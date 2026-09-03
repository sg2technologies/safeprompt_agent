use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// SP-RISK-003's "real policy engine" ticket names this vocabulary as
/// Allow/Warn/Mask/Block/Audit/RequireApproval — `Redact` here IS that
/// "Mask" (see `safeprompt-policy::default_actions`'s own doc comment: this
/// codebase settled on "Redact" naming back on 2026-08-05 and every call
/// site already depends on it, so `RequireApproval`/`Audit` are added
/// alongside it rather than renaming). `Audit` and `RequireApproval` are new
/// as of 2026-08-10 (SP-RISK-003) — see `enforcement_action` below for the
/// one thing every enforcement point must do differently because of them.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Action {
    Allow,
    Warn,
    Redact,
    Block,
    /// Allow the request/response through unmodified, but the decision that
    /// produced it (a category or a rule) explicitly wanted elevated audit
    /// visibility -- e.g. a rule matching `RiskBandAtLeast(Medium)` that
    /// isn't severe enough to warn/block/mask but is worth a compliance
    /// trail entry distinct from ordinary `Allow`. Every enforcement point
    /// in this codebase already persists a `DlpEvent` for *every* action
    /// (see `agent/crates/proxy`'s unconditional `persist_event` call
    /// before any action-specific branching), so `Audit` needs no special
    /// enforcement handling at all -- it's mechanically identical to
    /// `Allow` at every check site that only ever asks "is this Block?" or
    /// "is this Redact?" (see `enforcement_action`), and the thing that
    /// makes it meaningfully different (the `DlpEvent.action_taken` field
    /// itself recording `Audit` instead of `Allow`) already happens for
    /// free.
    Audit,
    /// Hold the request/response for a human approve/deny decision rather
    /// than resolving it automatically. No approval queue/workflow exists
    /// yet -- that's SP-RISK-004, still open -- so every enforcement point
    /// must call `enforcement_action()` rather than compare against
    /// `Action::Block`/`Action::Redact` directly, or a `RequireApproval`
    /// decision would silently fall through and behave exactly like
    /// `Allow` (neither check would ever match it). Mirrors
    /// `safeprompt-mcp::McpAction::RequireApproval`, which already exists
    /// as a distinct variant in that crate's own decision enum and is
    /// already "treated as blocked... no approval workflow wired up yet"
    /// (see `agent/crates/proxy`'s MCP JSON-RPC handler) -- same interim
    /// reasoning, now generalized to the request/response scanning path.
    RequireApproval,
}

impl Action {
    /// What an enforcement point (a proxy/gateway that only knows how to
    /// Allow-through, mask-and-forward, or hard-deny) should actually *do*
    /// with this action today. `RequireApproval` fails closed to `Block`
    /// pending SP-RISK-004's real approval queue -- pausing a request
    /// indefinitely with no way to ever resume it would be worse than
    /// denying it outright, and silently treating it as `Allow` (what
    /// every existing `== Action::Block` / `== Action::Redact` comparison
    /// would otherwise do, since it matches neither) would defeat the
    /// entire point of a tenant/rule author choosing `RequireApproval` over
    /// `Allow` in the first place. Every other variant, including `Audit`,
    /// maps to itself -- `Audit` behaves exactly like `Allow` at every
    /// enforcement check (neither Block nor Redact), which is correct: see
    /// `Action::Audit`'s own doc comment for why that's sufficient.
    ///
    /// Deliberately NOT applied before persisting a `DlpEvent` -- the audit
    /// trail must record what was actually decided (`RequireApproval`), not
    /// the interim enforcement stand-in (`Block`), so every enforcement
    /// call site must call this only at the point it decides how to *act*,
    /// never before `persist_event`/`DlpEvent` construction.
    pub fn enforcement_action(&self) -> Action {
        match self {
            Action::RequireApproval => Action::Block,
            other => *other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FindingCategory {
    Pii,
    Secret,
    PromptInjection,
    CustomKeyword,
    /// Credit card / IBAN / ABA routing numbers — checksum-validated, not
    /// just pattern-matched. Mirrors the Python engine's "financial" category
    /// (`backend/detection/layer1_regex.py`).
    Financial,
    /// Internal-only URLs/hostnames (`*.internal`, `*.corp`, `*.company.*`).
    /// Mirrors the Python engine's "internal" category.
    Internal,
    /// Content-safety guardrail finding (profanity/harassment/threats-of-
    /// violence/self-harm ideation) — added 2026-08-12, `agent/crates/
    /// guardrails::ToxicityScanner`. Runs on both request and response text,
    /// same as every other category here, since either side of a
    /// conversation can contain unsafe content. Deliberately a request/
    /// response *content-safety* concern, distinct from `PromptInjection`
    /// (an *attack-on-the-system* concern) even though both currently
    /// default to `Block` — see that scanner's own module doc comment for
    /// what v1 does and does not cover (keyword/phrase-based, not a
    /// semantic classifier; hate-speech/slur detection explicitly deferred
    /// rather than shipped with a low-quality hand-rolled list).
    Toxicity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub category: FindingCategory,
    pub match_name: String,
    pub snippet: String,
    pub severity: String,
    pub redacted_replacement: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub action: Action,
    pub findings: Vec<Finding>,
    pub original_prompt: String,
    pub sanitized_prompt: String,
    /// Set only for a file/image upload whose detector verdict was Redact
    /// ("Mask it") but this file's format can't be safely masked in place
    /// (see `safeprompt_policy::SecurityPolicy::unmaskable_file_action`),
    /// so a different, policy-configured action was applied instead.
    /// Lets a caller (the extension's toast, the local console) explain
    /// exactly why the outcome doesn't match the configured "Mask it"
    /// action, rather than showing a bare Block/Warn that reads as a
    /// mismatch or a bug. `None` for every other scan -- most callers
    /// never set this and can ignore it entirely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unmaskable_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub action_taken: Action,
    pub app_name: String,
    pub domain: String,
    pub user_identity: String,
    pub findings: Vec<Finding>,
}

/// Common contract every detection backend implements — regex/checksum
/// (`safeprompt-pii`, `safeprompt-secrets`, `safeprompt-prompt`) today, an
/// IPC-backed Presidio/spaCy subprocess (`safeprompt-scanner`) next, an
/// in-process ONNX model later. `Inspector` (or whatever composes scanners)
/// can hold a `Vec<Box<dyn Scanner>>` and never care which is which —
/// decided 2026-07-31 so the Presidio->ONNX swap touches no call sites.
/// `Send + Sync` because a scanner may be shared across request-handling
/// threads/tasks (e.g. behind an `Arc`), same bound `Inspector` itself needs.
pub trait Scanner: Send + Sync {
    fn scan(&self, text: &str) -> Vec<Finding>;
}

/// Open-core Phase 2 (2026-08-27) seam for the real SIEM forwarder
/// (`safeprompt-siem`'s `SyslogForwarder`, private, `agent-enterprise/`):
/// `crates/proxy` holds this trait object (`Option<Arc<dyn SiemForwarder>>`)
/// instead of the concrete struct, so the public workspace never needs to
/// depend on the real RFC 5424 implementation. `DlpEvent` already lives
/// here, so this trait needed nowhere else to live.
#[async_trait::async_trait]
pub trait SiemForwarder: Send + Sync {
    async fn forward(&self, event: &DlpEvent);
}

/// Open-core Phase 2 (2026-08-27) seam for the real "redact-first-verify"
/// LLM second-opinion pass (`safeprompt-llm-verify`, private,
/// `agent-enterprise/`): `crates/local_api` holds this trait object
/// (`Option<Arc<dyn LlmVerifier>>`) instead of a concrete config struct plus
/// a free function, so the endpoint/model/API-key configuration is baked in
/// once at construction time in `apps/service` and `local_api` never needs
/// to know the shape of `LlmVerifyConfig` at all.
#[async_trait::async_trait]
pub trait LlmVerifier: Send + Sync {
    async fn verify(&self, text: &str) -> Vec<Finding>;
}

/// Applies every finding's `redacted_replacement` to `text`, safely,
/// without corrupting a JSON body's syntax. Real bug this exists to
/// prevent, found 2026-08-08 live-testing response scanning against a
/// real chat-completion response: naive whole-text substring replacement
/// (`text.replace(snippet, replacement)`, what every call site here used
/// to do directly) works fine for plain text, but a redaction replacement
/// string has no reason to itself be valid JSON -- splicing it into the
/// middle of a JSON string or number literal produces invalid JSON the
/// caller can no longer parse (exactly the "Unterminated fractional
/// number in JSON" class of failure, live-observed). This mirrors a fix
/// `browser-extension/`'s own JS layer already made for the same bug
/// class in a different code path (`main-world-interceptor.js`'s
/// `applyRedaction`, 2026-08-05) -- that fix never touched this Rust-side
/// logic at all, since it's a completely separate code path (the reverse-
/// proxy and CONNECT-proxy's own request/response scanning, not the
/// browser extension).
///
/// If `text` parses as JSON: redacts only inside String leaf values
/// (never object keys, JSON numbers, or structural syntax), then
/// re-serializes -- guaranteed syntactically valid JSON on the way out,
/// since serde_json always correctly escapes whatever ends up in a Rust
/// `String`. If `text` isn't JSON at all (plain text, SSE chunks,
/// markdown), falls back to the original whole-text substring
/// replacement -- unchanged behavior for that case.
///
/// Known, accepted scope limit: a finding whose snippet is itself a raw
/// JSON *number* (not a string) is not redacted in the JSON path -- e.g.
/// a document ID represented as `"id": 1901212` rather than `"id":
/// "1901212"`. Silently under-redacting that rare shape is safer than
/// corrupting the whole response; real-world PII/secrets in AI-generated
/// JSON responses are overwhelmingly string-typed in practice.
pub fn apply_redactions(text: &str, findings: &[Finding]) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text) {
        redact_json_strings(&mut value, findings);
        if let Ok(reserialized) = serde_json::to_string(&value) {
            return reserialized;
        }
    }

    let mut sanitized = text.to_string();
    for finding in findings {
        if let Some(replacement) = &finding.redacted_replacement {
            sanitized = sanitized.replace(&finding.snippet, replacement);
        }
    }
    sanitized
}

fn redact_json_strings(value: &mut serde_json::Value, findings: &[Finding]) {
    match value {
        serde_json::Value::String(s) => {
            for finding in findings {
                if let Some(replacement) = &finding.redacted_replacement {
                    *s = s.replace(finding.snippet.as_str(), replacement);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_strings(item, findings);
            }
        }
        serde_json::Value::Object(map) => {
            for v in map.values_mut() {
                redact_json_strings(v, findings);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::*;

    fn secret_finding(snippet: &str, replacement: &str) -> Finding {
        Finding {
            category: FindingCategory::Secret,
            match_name: "TEST_SECRET".to_string(),
            snippet: snippet.to_string(),
            severity: "HIGH".to_string(),
            redacted_replacement: Some(replacement.to_string()),
        }
    }

    #[test]
    fn redacts_inside_a_json_string_value_and_stays_valid_json() {
        let body = r#"{"choices":[{"message":{"content":"here is AKIAIOSFODNN7EXAMPLE for you"}}]}"#;
        let findings = vec![secret_finding("AKIAIOSFODNN7EXAMPLE", "[REDACTED_AWS_KEY]")];
        let sanitized = apply_redactions(body, &findings);

        // The critical regression check: the output must itself still
        // parse as JSON -- a plain string.replace() on the raw text would
        // have produced this exact malformed-JSON failure mode.
        let parsed: serde_json::Value = serde_json::from_str(&sanitized).expect("redacted response must still be valid JSON");
        assert_eq!(parsed["choices"][0]["message"]["content"], "here is [REDACTED_AWS_KEY] for you");
        assert!(!sanitized.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn redacts_inside_nested_arrays_and_objects() {
        let body = r#"{"records":[{"name":"Jane","passport":"A1234567"},{"name":"John","passport":"B7654321"}]}"#;
        let findings = vec![
            secret_finding("A1234567", "[REDACTED_PASSPORT]"),
            secret_finding("B7654321", "[REDACTED_PASSPORT]"),
        ];
        let sanitized = apply_redactions(body, &findings);
        let parsed: serde_json::Value = serde_json::from_str(&sanitized).expect("must still be valid JSON");
        assert_eq!(parsed["records"][0]["passport"], "[REDACTED_PASSPORT]");
        assert_eq!(parsed["records"][1]["passport"], "[REDACTED_PASSPORT]");
    }

    #[test]
    fn a_raw_json_number_is_left_unredacted_but_json_stays_valid() {
        // Documented scope limit: findings only match string content in
        // this codebase (every scanner extracts snippets as text), so a
        // value that happens to be a genuine JSON number type is never
        // walked into at all -- the important thing is this must not
        // corrupt the surrounding JSON, not that it gets redacted.
        let body = r#"{"document_number": 1901212, "note": "safe"}"#;
        let findings = vec![secret_finding("1901212", "[REDACTED]")];
        let sanitized = apply_redactions(body, &findings);
        let parsed: serde_json::Value = serde_json::from_str(&sanitized).expect("must still be valid JSON");
        assert_eq!(parsed["document_number"], 1901212);
    }

    #[test]
    fn non_json_plain_text_falls_back_to_whole_text_replacement() {
        let text = "my key is AKIAIOSFODNN7EXAMPLE, thanks";
        let findings = vec![secret_finding("AKIAIOSFODNN7EXAMPLE", "[REDACTED_AWS_KEY]")];
        let sanitized = apply_redactions(text, &findings);
        assert_eq!(sanitized, "my key is [REDACTED_AWS_KEY], thanks");
    }

    #[test]
    fn no_findings_leaves_json_unchanged_modulo_formatting() {
        let body = r#"{"a":"b"}"#;
        let sanitized = apply_redactions(body, &[]);
        let parsed: serde_json::Value = serde_json::from_str(&sanitized).unwrap();
        assert_eq!(parsed["a"], "b");
    }
}
