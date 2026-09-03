// MCP (Model Context Protocol) tool-call data shapes and the firewall trait
// seam -- open-core Phase 2 (2026-08-27) split of the original
// `safeprompt-mcp` crate. `agent/crates/proxy`'s live `/mcp` handler and
// `agent/crates/config`'s hot-reload loop both match/construct these types
// and hold a trait object (`Arc<Mutex<dyn McpToolFirewall>>`) instead of the
// concrete `McpFirewall` engine, whose real allow/deny-list evaluation,
// argument validation, and call-rate-limiting logic is private
// (`agent-enterprise/crates/mcp`) -- MCP firewalling is fully gated behind
// the `mcp` license feature, unlike e.g. OCR. See
// docs/SafeGateway-Architecture-Review.md §11 (Module 11/12/13 mapping) for
// the original design this data shape traces back to.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
    pub tool: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpAction {
    Allow,
    /// Not blocked outright, but flagged for a human to approve before it
    /// executes. There's no approval workflow UI yet (Control Plane work) —
    /// today this is enforced the same way as `Block`, just with a
    /// different reason surfaced to the caller.
    RequireApproval,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpDecision {
    pub action: McpAction,
    pub risk_score: u8,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolPolicyConfig {
    /// Exact tool names, or "prefix.*" globs, that are always blocked.
    pub denied_tools: Vec<String>,
    /// If non-empty, only these tools (or "prefix.*" globs) may run at all;
    /// anything else is blocked. Empty means no allowlist restriction.
    pub allowed_tools: Vec<String>,
    pub max_calls_per_window: u32,
    pub window_seconds: i64,
}

impl Default for ToolPolicyConfig {
    fn default() -> Self {
        Self {
            denied_tools: vec![
                "filesystem.delete".to_string(),
                "shell.*".to_string(),
                "ssh.*".to_string(),
                "powershell.*".to_string(),
            ],
            allowed_tools: vec![],
            max_calls_per_window: 20,
            window_seconds: 60,
        }
    }
}

/// The trait object `agent/crates/proxy` (`AppState`/`ProxyServer`) and
/// `agent/crates/config` (`spawn_hot_reload`) hold instead of the concrete
/// `McpFirewall` engine (`agent-enterprise/crates/mcp`, private). `&mut
/// self` because the real implementation tracks per-session call-rate state
/// across calls; callers wrap this in `Arc<Mutex<dyn McpToolFirewall>>`,
/// matching how the concrete type was already held before this split.
pub trait McpToolFirewall: Send + Sync {
    fn evaluate(&mut self, session_id: &str, call: &McpToolCall, now: DateTime<Utc>) -> McpDecision;

    /// Swaps in a new tool policy immediately -- every `evaluate` call after
    /// this returns uses `new_config`. Mirrors `Inspector::update_policy`'s
    /// hot-swap shape so `agent/crates/config`'s hot-reload loop can treat
    /// both the same way.
    fn update_config(&mut self, new_config: ToolPolicyConfig);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_policy_config_round_trips_through_json() {
        let config = ToolPolicyConfig {
            denied_tools: vec!["shell.*".to_string()],
            allowed_tools: vec!["notes.append".to_string()],
            max_calls_per_window: 5,
            window_seconds: 30,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: ToolPolicyConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.denied_tools, config.denied_tools);
        assert_eq!(parsed.max_calls_per_window, config.max_calls_per_window);
    }
}
