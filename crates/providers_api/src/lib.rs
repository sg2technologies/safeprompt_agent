// Provider plugin system: the Agent's local reverse-proxy always speaks
// OpenAI-compatible chat-completions to the *client* SDK; a `Provider`
// translates that into whatever the real backend actually needs and
// translates the response back. Port of the intent behind
// `backend/gateway/providers/*.py` + `ProviderFactory` — see
// docs/SafeGateway-Architecture-Review.md §5.
//
// 2026-08-27, open-core Phase 2: split out of the original
// `safeprompt-providers` crate. This crate (public, `agent/`) holds the
// `Provider`/`StreamTransformer` traits, the request/response data shapes,
// the generic provider-agnostic `ProviderRegistry` container, and the one
// concrete provider every edition ships — `OpenAiCompatibleProvider`,
// generic/unbranded, covering every backend that already speaks OpenAI's
// wire format as-is (OpenAI itself, Grok, Perplexity, DeepSeek, Mistral,
// Cohere, Groq, OpenRouter, Ollama). The branded translators that do real
// request+response reshaping — Anthropic (incl. streaming SSE reshaping),
// Azure OpenAI, Gemini — live in `agent-enterprise/crates/providers`
// instead (gated behind the `multi_provider` license feature), depending on
// this crate's `Provider` trait for the seam.

pub mod openai_compatible;
pub mod registry;
pub mod streaming;

pub use openai_compatible::OpenAiCompatibleProvider;
pub use registry::{resolve_provider_name, ProviderRegistry};
pub use streaming::StreamTransformer;

/// The request a `Provider` wants sent upstream, already fully formed:
/// exact target URL, exact headers, exact body bytes.
#[derive(Debug, Clone)]
pub struct OutboundRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// How a provider's streaming (SSE) responses relate to OpenAI's
/// `chat.completion.chunk` shape.
pub enum StreamingSupport {
    /// This provider's streaming responses already match OpenAI's SSE
    /// shape — no reshaping needed, forward the byte stream as-is.
    Identity,
    /// This provider's streaming responses need reshaping; a fresh
    /// transformer is constructed per streaming request (it holds
    /// per-connection state — partially-buffered events, the running
    /// finish reason, etc.).
    Translate(Box<dyn StreamTransformer>),
    /// Streaming isn't implemented for this provider yet — callers should
    /// reject a streaming request with a clear error rather than silently
    /// forwarding wrong-shaped output.
    Unsupported,
}

pub trait Provider: Send + Sync {
    /// Short identifier used for routing/logging, e.g. "openai", "anthropic".
    fn name(&self) -> &str;

    /// Translates an OpenAI-compatible chat-completions request (`path` is
    /// the client's original request path, e.g. "/v1/chat/completions";
    /// `openai_body` is that request's parsed JSON) into the request this
    /// provider actually expects.
    fn translate_request(&self, path: &str, openai_body: &serde_json::Value) -> anyhow::Result<OutboundRequest>;

    /// Translates this provider's raw (non-streaming) response bytes back
    /// into an OpenAI-compatible chat-completions response. Providers that
    /// already speak OpenAI shape (the generic provider, Azure) just return
    /// `provider_body` unchanged.
    fn translate_response(&self, provider_body: &[u8]) -> anyhow::Result<Vec<u8>>;

    /// See [`StreamingSupport`]. Defaults to `Identity`, correct for any
    /// provider whose `translate_response` is a no-op.
    fn streaming_support(&self) -> StreamingSupport {
        StreamingSupport::Identity
    }
}
