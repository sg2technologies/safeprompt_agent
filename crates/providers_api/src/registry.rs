// Resolves which provider handles a request — exact port of
// `backend/gateway/providers/factory.py::ProviderFactory.resolve`'s logic
// (explicit header wins, otherwise match on model-name prefix).

use crate::Provider;
use std::collections::HashMap;
use std::sync::Arc;

/// `explicit_header` is the `X-Provider`/`X-LLM-Provider` header value, if
/// the client set one. Otherwise resolves from the model name prefix,
/// falling back to "openai" — matching the Python factory's default.
pub fn resolve_provider_name(explicit_header: Option<&str>, model: &str) -> String {
    if let Some(header) = explicit_header {
        return header.to_lowercase();
    }

    let model = model.to_lowercase();
    if model.starts_with("gpt") || model.starts_with("o1") || model.starts_with("o3") {
        "openai".to_string()
    } else if model.starts_with("claude") {
        "anthropic".to_string()
    } else if model.starts_with("gemini") {
        "gemini".to_string()
    } else if model.starts_with("grok") {
        "grok".to_string()
    } else if model.starts_with("sonar") || model.contains("perplexity") {
        "perplexity".to_string()
    } else if model.starts_with("deepseek") {
        "deepseek".to_string()
    } else if model.starts_with("mistral") || model.starts_with("pixtral") || model.starts_with("codestral") {
        "mistral".to_string()
    } else if model.starts_with("command") || model.starts_with("cohere") {
        "cohere".to_string()
    } else if model.contains("openrouter") {
        "openrouter".to_string()
    } else if model.starts_with("llama") || model.contains("ollama") {
        "ollama".to_string()
    } else {
        "openai".to_string()
    }
}

#[derive(Default)]
pub struct ProviderRegistry {
    providers: HashMap<String, Arc<dyn Provider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, key: impl Into<String>, provider: Arc<dyn Provider>) {
        self.providers.insert(key.into(), provider);
    }

    pub fn resolve(&self, explicit_header: Option<&str>, model: &str) -> Option<Arc<dyn Provider>> {
        let name = resolve_provider_name(explicit_header, model);
        self.providers.get(&name).cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openai_compatible::{AuthStyle, OpenAiCompatibleProvider};

    #[test]
    fn explicit_header_takes_precedence_over_model_name() {
        assert_eq!(resolve_provider_name(Some("anthropic"), "gpt-4"), "anthropic");
    }

    #[test]
    fn resolves_known_model_prefixes() {
        assert_eq!(resolve_provider_name(None, "gpt-4"), "openai");
        assert_eq!(resolve_provider_name(None, "o1-preview"), "openai");
        assert_eq!(resolve_provider_name(None, "claude-3-5-sonnet-20241022"), "anthropic");
        assert_eq!(resolve_provider_name(None, "gemini-1.5-pro"), "gemini");
        assert_eq!(resolve_provider_name(None, "grok-2"), "grok");
        assert_eq!(resolve_provider_name(None, "llama3"), "ollama");
    }

    #[test]
    fn falls_back_to_openai_for_unknown_models() {
        assert_eq!(resolve_provider_name(None, "some-unknown-model"), "openai");
    }

    #[test]
    fn registry_resolves_a_registered_provider_by_model_name() {
        let mut registry = ProviderRegistry::new();
        registry.register(
            "anthropic",
            Arc::new(OpenAiCompatibleProvider::new("anthropic", "https://api.anthropic.com", None, AuthStyle::None)),
        );

        let resolved = registry.resolve(None, "claude-3-5-sonnet-20241022");
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().name(), "anthropic");
    }

    #[test]
    fn registry_returns_none_for_an_unregistered_provider() {
        let registry = ProviderRegistry::new();
        assert!(registry.resolve(None, "gpt-4").is_none());
    }
}
