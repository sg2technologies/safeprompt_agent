// Covers every provider that speaks OpenAI's wire format as-is: OpenAI
// itself, Grok, Perplexity, DeepSeek, Mistral, Cohere, Groq, OpenRouter,
// and Ollama's OpenAI-compatible endpoint. Only the base URL and auth style
// differ between them — no body reshaping needed.

use crate::{OutboundRequest, Provider};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStyle {
    /// `Authorization: Bearer <key>` — OpenAI, Grok, Perplexity, DeepSeek,
    /// Mistral, Cohere, Groq, OpenRouter.
    Bearer,
    /// No auth header at all — local Ollama.
    None,
}

pub struct OpenAiCompatibleProvider {
    name: String,
    base_url: String,
    api_key: Option<String>,
    auth_style: AuthStyle,
}

impl OpenAiCompatibleProvider {
    pub fn new(name: impl Into<String>, base_url: impl Into<String>, api_key: Option<String>, auth_style: AuthStyle) -> Self {
        Self {
            name: name.into(),
            base_url: base_url.into(),
            api_key,
            auth_style,
        }
    }
}

impl Provider for OpenAiCompatibleProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn translate_request(&self, path: &str, openai_body: &Value) -> anyhow::Result<OutboundRequest> {
        let url = format!("{}{}", self.base_url.trim_end_matches('/'), path);
        let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        if self.auth_style == AuthStyle::Bearer {
            let key = self
                .api_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("provider '{}' requires an API key but none is configured", self.name))?;
            headers.push(("Authorization".to_string(), format!("Bearer {key}")));
        }

        Ok(OutboundRequest {
            url,
            headers,
            body: serde_json::to_vec(openai_body)?,
        })
    }

    fn translate_response(&self, provider_body: &[u8]) -> anyhow::Result<Vec<u8>> {
        Ok(provider_body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_a_bearer_authenticated_request() {
        let provider = OpenAiCompatibleProvider::new("openai", "https://api.openai.com", Some("sk-test".to_string()), AuthStyle::Bearer);
        let body = serde_json::json!({"model": "gpt-4", "messages": []});
        let outbound = provider.translate_request("/v1/chat/completions", &body).unwrap();

        assert_eq!(outbound.url, "https://api.openai.com/v1/chat/completions");
        assert!(outbound.headers.contains(&("Authorization".to_string(), "Bearer sk-test".to_string())));
        assert_eq!(outbound.body, serde_json::to_vec(&body).unwrap());
    }

    #[test]
    fn builds_an_unauthenticated_request_for_local_ollama() {
        let provider = OpenAiCompatibleProvider::new("ollama", "http://localhost:11434", None, AuthStyle::None);
        let body = serde_json::json!({"model": "llama3", "messages": []});
        let outbound = provider.translate_request("/v1/chat/completions", &body).unwrap();

        assert_eq!(outbound.url, "http://localhost:11434/v1/chat/completions");
        assert!(!outbound.headers.iter().any(|(k, _)| k == "Authorization"));
    }

    #[test]
    fn fails_clearly_when_bearer_auth_is_required_but_no_key_configured() {
        let provider = OpenAiCompatibleProvider::new("openai", "https://api.openai.com", None, AuthStyle::Bearer);
        let body = serde_json::json!({"model": "gpt-4"});
        assert!(provider.translate_request("/v1/chat/completions", &body).is_err());
    }

    #[test]
    fn response_passes_through_unmodified() {
        let provider = OpenAiCompatibleProvider::new("openai", "https://api.openai.com", None, AuthStyle::None);
        let body = br#"{"choices":[{"message":{"content":"hi"}}]}"#;
        assert_eq!(provider.translate_response(body).unwrap(), body.to_vec());
    }
}
