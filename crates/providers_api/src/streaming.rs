// Reshaping a provider's streaming (SSE) response into OpenAI's
// `chat.completion.chunk` shape. Unlike non-streaming translation (a single
// JSON blob in, a single JSON blob out), SSE events don't arrive aligned
// with network chunk boundaries — a `StreamTransformer` is a small state
// machine that buffers partial events and emits zero or more complete
// OpenAI-shaped SSE chunks per `push()`.

/// One transformer instance per streaming connection — it holds
/// per-connection state (partially-buffered bytes, whether the initial
/// role delta was already sent, the running finish reason).
pub trait StreamTransformer: Send {
    /// Feed raw upstream bytes in; returns zero or more complete
    /// OpenAI-shaped SSE bytes (`data: {...}\n\n`, possibly several
    /// concatenated, possibly empty if this push didn't complete an event).
    fn push(&mut self, upstream_bytes: &[u8]) -> Vec<u8>;

    /// Call once when the upstream stream ends, to flush any trailing
    /// state (e.g. a `data: [DONE]\n\n` the transformer hasn't sent yet).
    fn finish(&mut self) -> Vec<u8>;
}
