// Configuration Manager: layered config for Agent settings, rooted at
// `%ProgramData%\SafePrompt\config.json` by default (see
// `apps/service::default_path` — this crate itself stays install-location-
// agnostic and just takes whatever source string it's given).
//
// Two tiers, deliberately not treated the same way:
//   - Hot-reloadable: MCP tool policy (`safeprompt_mcp_api::ToolPolicyConfig`
//     — the firewall already supports swapping its config live via
//     `McpToolFirewall::update_config`, real implementation private as of
//     2026-08-27's open-core Phase 2) and audit retention days (the
//     retention-purge loop reads this from a shared atomic on every tick
//     rather than a value captured once at spawn time).
//   - Load-once-at-startup only: `tenant_id`, `upstream_base_url`/
//     `upstream_api_key`/`mcp_upstream_base_url`, and `providers` (API
//     keys/endpoints for the multi-provider registry). These used to be
//     `SAFEPROMPT_*`-env-var-only; they're real `AgentConfig` fields now so
//     a customer can configure a fresh install by dropping one
//     `config.json` into ProgramData instead of setting ~15 separate env
//     vars, but they're NOT wired into `spawn_hot_reload`'s apply step —
//     changing them still needs a restart, since live-swapping bind
//     addresses/upstream connections is a much bigger, riskier change than
//     this pass covers honestly (same reasoning that already applied to
//     the first two fields, just written down again because it's the
//     thing most likely to surprise someone editing this file live and
//     wondering why nothing happened).
//
// Layering: built-in `Default` < local file or http(s) URL (`source`,
// same "local vs cloud" convention `safeprompt_policy_sync` already uses
// for `SAFEPROMPT_POLICY_SOURCE`, so this doesn't invent a second way to
// say "read this from a file or a Control Plane URL") < env var overrides
// (applied by the caller, `apps/service` — every field here can still be
// overridden by its historical `SAFEPROMPT_*` env var, so nothing that
// worked before this existed stops working). Hot reload is
// `spawn_hot_reload` polling `source` on an interval and applying only
// the two fields listed as hot-reloadable above.

use safeprompt_mcp_api::{McpToolFirewall, ToolPolicyConfig};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn};

fn default_retention_days() -> i64 {
    90
}

fn default_upstream_base_url() -> String {
    "https://api.openai.com".to_string()
}

fn default_azure_api_version() -> String {
    "2024-06-01".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AzureOpenAiConfig {
    pub endpoint: String,
    pub api_key: String,
    #[serde(default = "default_azure_api_version")]
    pub api_version: String,
    /// Model name -> Azure deployment name (Azure deployment names are
    /// admin-chosen, never the model name itself).
    #[serde(default)]
    pub deployments: HashMap<String, String>,
}

/// Multi-provider registry configuration — one field per provider `apps/
/// service::build_provider_registry` already supported via env vars.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProviderConfig {
    #[serde(default)]
    pub openai_api_key: Option<String>,
    #[serde(default)]
    pub anthropic_api_key: Option<String>,
    #[serde(default)]
    pub gemini_api_key: Option<String>,
    #[serde(default)]
    pub groq_api_key: Option<String>,
    #[serde(default)]
    pub openrouter_api_key: Option<String>,
    #[serde(default)]
    pub ollama_base_url: Option<String>,
    #[serde(default)]
    pub azure_openai: Option<AzureOpenAiConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentConfig {
    #[serde(default)]
    pub mcp_tool_policy: ToolPolicyConfig,
    #[serde(default = "default_retention_days")]
    pub audit_retention_days: i64,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default = "default_upstream_base_url")]
    pub upstream_base_url: String,
    #[serde(default)]
    pub upstream_api_key: Option<String>,
    #[serde(default)]
    pub mcp_upstream_base_url: Option<String>,
    #[serde(default)]
    pub providers: ProviderConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            mcp_tool_policy: ToolPolicyConfig::default(),
            audit_retention_days: default_retention_days(),
            tenant_id: None,
            upstream_base_url: default_upstream_base_url(),
            upstream_api_key: None,
            mcp_upstream_base_url: None,
            providers: ProviderConfig::default(),
        }
    }
}

/// Loads an `AgentConfig` from a local file path or an http(s) URL. No
/// signing/verification here (unlike `safeprompt_policy_sync`'s signed
/// documents) — this is operational tuning, not a security-policy document
/// whose provenance matters as much as its content.
pub async fn fetch_config(source: &str) -> anyhow::Result<AgentConfig> {
    let content = if source.starts_with("http://") || source.starts_with("https://") {
        reqwest::get(source).await?.text().await?
    } else {
        tokio::fs::read_to_string(source).await?
    };
    Ok(serde_json::from_str(&content)?)
}

/// Polls `source` on `poll_interval` and hot-applies whatever changed since
/// `initial` — `mcp_tool_policy` into the running firewall (if one is
/// configured -- `None` on a Community build with no MCP firewall
/// implementation at all, see `safeprompt-mcp-api::McpToolFirewall`'s own
/// doc comment), `audit_retention_days` into the atomic the retention-purge
/// loop reads from. A fetch/parse failure just logs a warning and keeps the
/// last good config, same graceful-degradation posture as policy sync and
/// auto-update.
pub fn spawn_hot_reload(
    source: String,
    poll_interval: Duration,
    mcp_firewall: Option<Arc<Mutex<dyn McpToolFirewall>>>,
    retention_days: Arc<AtomicI64>,
    initial: AgentConfig,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut current = initial;
        loop {
            tokio::time::sleep(poll_interval).await;

            let fetched = match fetch_config(&source).await {
                Ok(c) => c,
                Err(e) => {
                    warn!("configuration hot-reload could not fetch {source}: {e}");
                    continue;
                }
            };

            if fetched == current {
                continue;
            }

            if fetched.mcp_tool_policy != current.mcp_tool_policy {
                if let Some(firewall) = &mcp_firewall {
                    firewall.lock().expect("mcp_firewall lock poisoned").update_config(fetched.mcp_tool_policy.clone());
                    info!("configuration hot-reload applied a new MCP tool policy");
                }
            }
            if fetched.audit_retention_days != current.audit_retention_days {
                retention_days.store(fetched.audit_retention_days, Ordering::Relaxed);
                info!(days = fetched.audit_retention_days, "configuration hot-reload applied a new audit retention period");
            }
            if fetched.tenant_id != current.tenant_id
                || fetched.upstream_base_url != current.upstream_base_url
                || fetched.upstream_api_key != current.upstream_api_key
                || fetched.mcp_upstream_base_url != current.mcp_upstream_base_url
                || fetched.providers != current.providers
            {
                warn!(
                    "configuration file changed tenant_id/upstream/provider settings — these are \
                     load-once-at-startup only and were NOT applied; restart the service to pick them up"
                );
            }

            current = fetched;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::Router;

    /// Test-only `McpToolFirewall`: since the real engine
    /// (`safeprompt-mcp::McpFirewall`) moved to the private
    /// `agent-enterprise/` workspace (2026-08-27, open-core Phase 2), this
    /// crate can no longer depend on it even in tests -- this crate's job
    /// is only to prove `spawn_hot_reload` calls `update_config` with the
    /// right value when the policy changes, not to re-prove the firewall's
    /// own allow/deny decision logic (already covered by that crate's own
    /// tests, unaffected by this move).
    #[derive(Default)]
    struct RecordingMcpFirewall {
        last_config: Option<ToolPolicyConfig>,
    }

    impl McpToolFirewall for RecordingMcpFirewall {
        fn evaluate(&mut self, _session_id: &str, _call: &safeprompt_mcp_api::McpToolCall, _now: chrono::DateTime<chrono::Utc>) -> safeprompt_mcp_api::McpDecision {
            safeprompt_mcp_api::McpDecision { action: safeprompt_mcp_api::McpAction::Allow, risk_score: 0, reasons: vec![] }
        }
        fn update_config(&mut self, new_config: ToolPolicyConfig) {
            self.last_config = Some(new_config);
        }
    }

    #[test]
    fn default_config_matches_the_individual_components_own_defaults() {
        let config = AgentConfig::default();
        assert_eq!(config.mcp_tool_policy, ToolPolicyConfig::default());
        assert_eq!(config.audit_retention_days, 90);
        assert_eq!(config.upstream_base_url, "https://api.openai.com");
        assert_eq!(config.tenant_id, None);
        assert_eq!(config.providers, ProviderConfig::default());
    }

    #[tokio::test]
    async fn fetch_config_reads_tenant_upstream_and_provider_settings_from_a_local_file() {
        let dir = std::env::temp_dir().join(format!("safeprompt-config-providers-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(
            &path,
            r#"{
                "tenant_id": "acme-corp",
                "upstream_base_url": "https://api.anthropic.com",
                "upstream_api_key": "sk-upstream",
                "providers": {
                    "openai_api_key": "sk-openai",
                    "azure_openai": {
                        "endpoint": "https://acme.openai.azure.com",
                        "api_key": "azure-key",
                        "deployments": {"gpt-4": "my-gpt4-deployment"}
                    }
                }
            }"#,
        )
        .unwrap();

        let config = fetch_config(path.to_str().unwrap()).await.unwrap();
        assert_eq!(config.tenant_id.as_deref(), Some("acme-corp"));
        assert_eq!(config.upstream_base_url, "https://api.anthropic.com");
        assert_eq!(config.upstream_api_key.as_deref(), Some("sk-upstream"));
        assert_eq!(config.providers.openai_api_key.as_deref(), Some("sk-openai"));
        assert_eq!(config.providers.anthropic_api_key, None, "unset provider fields should stay None, not error");
        let azure = config.providers.azure_openai.expect("azure_openai should be present");
        assert_eq!(azure.endpoint, "https://acme.openai.azure.com");
        assert_eq!(azure.api_version, "2024-06-01", "omitted api_version should fall back to its own default");
        assert_eq!(azure.deployments.get("gpt-4").map(String::as_str), Some("my-gpt4-deployment"));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn fetch_config_reads_a_local_file_and_fills_in_missing_fields_with_defaults() {
        let dir = std::env::temp_dir().join(format!("safeprompt-config-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        std::fs::write(&path, r#"{"audit_retention_days": 30}"#).unwrap();

        let config = fetch_config(path.to_str().unwrap()).await.unwrap();
        assert_eq!(config.audit_retention_days, 30);
        assert_eq!(config.mcp_tool_policy, ToolPolicyConfig::default(), "omitted field should fall back to its own default");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn fetch_config_reads_from_an_http_url() {
        let body = r#"{"mcp_tool_policy": {"denied_tools": ["shell.*"], "allowed_tools": [], "max_calls_per_window": 5, "window_seconds": 10}, "audit_retention_days": 45}"#;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/config", get(move || async move { body.to_string() }));
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let config = fetch_config(&format!("http://{addr}/config")).await.unwrap();
        assert_eq!(config.audit_retention_days, 45);
        assert_eq!(config.mcp_tool_policy.max_calls_per_window, 5);
    }

    #[tokio::test]
    async fn fetch_config_fails_on_a_missing_file_rather_than_panicking() {
        let result = fetch_config("C:\\does\\not\\exist\\config.json").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn hot_reload_applies_a_changed_mcp_policy_and_retention_period_without_restart() {
        let dir = std::env::temp_dir().join(format!("safeprompt-config-hotreload-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let initial = AgentConfig::default();
        std::fs::write(&path, serde_json::to_string(&initial).unwrap()).unwrap();

        // `concrete` and `mcp_firewall` (unsized-coerced from a clone of the
        // same `Arc`) point at the same underlying `Mutex` -- this test locks
        // `concrete` afterward to inspect `last_config`, something a plain
        // `Arc<Mutex<dyn McpToolFirewall>>` can't expose through the trait.
        let concrete: Arc<Mutex<RecordingMcpFirewall>> = Arc::new(Mutex::new(RecordingMcpFirewall::default()));
        let mcp_firewall: Arc<Mutex<dyn McpToolFirewall>> = concrete.clone();
        let retention_days = Arc::new(AtomicI64::new(initial.audit_retention_days));

        let handle = spawn_hot_reload(
            path.to_str().unwrap().to_string(),
            Duration::from_millis(100),
            Some(mcp_firewall),
            Arc::clone(&retention_days),
            initial.clone(),
        );

        // Write a new config denylisting a tool and bumping retention.
        let updated = AgentConfig {
            mcp_tool_policy: ToolPolicyConfig {
                denied_tools: vec!["notes.*".to_string()],
                ..ToolPolicyConfig::default()
            },
            audit_retention_days: 7,
            ..AgentConfig::default()
        };
        std::fs::write(&path, serde_json::to_string(&updated).unwrap()).unwrap();

        // Give the hot-reload loop a few poll cycles to pick it up.
        let mut applied = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if retention_days.load(Ordering::Relaxed) == 7 {
                applied = true;
                break;
            }
        }
        assert!(applied, "hot reload never applied the new retention_days within the poll window");
        assert_eq!(
            concrete.lock().unwrap().last_config.as_ref().map(|c| c.denied_tools.clone()),
            Some(vec!["notes.*".to_string()]),
            "hot reload should have applied the new MCP tool policy to the live firewall"
        );

        handle.abort();
        std::fs::remove_dir_all(&dir).ok();
    }
}
