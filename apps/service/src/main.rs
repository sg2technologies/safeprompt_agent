use safeprompt_connect_proxy::{CertificateAuthority, ConnectProxyServer};
use safeprompt_local_api::LocalApiServer;
use safeprompt_inspector::Inspector;
use safeprompt_integrity::{ManifestVerifier, SignedManifest};
use safeprompt_licensing::{
    compute_machine_fingerprint, features as license_features, grace_status, FeatureManager, GraceStatus,
    LicenseVerifier, SignedLicense,
};
use safeprompt_policy::PolicyConfig;
use safeprompt_providers_api::openai_compatible::AuthStyle;
use safeprompt_providers_api::{OpenAiCompatibleProvider, ProviderRegistry};
use safeprompt_proxy::{ProxyConfig, ProxyServer};
use safeprompt_storage::LocalDatabase;
use safeprompt_telemetry::collect_telemetry;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, warn};

// The local port registry (AGENT-COMM entries, EPIC 29 "Agent
// Connectivity & Data Plane"), formalized here rather than left scattered
// across each server's own env-var default. Every one of these is
// `127.0.0.1`-only by default; only SPOC's deliberately isn't (see its own
// bind-address handling below).
//
//   | Port | Service                          | Env var                              | Audience |
//   |------|-----------------------------------|---------------------------------------|----------|
//   | 8844 | `safeprompt-proxy` (DLP gateway)  | `SAFEPROMPT_PROXY_BIND_ADDR`          | OpenAI-compatible SDK clients pointed at this Agent as their base URL |
//   | 8845 | `connect_proxy` (TLS MITM)        | `SAFEPROMPT_CONNECT_PROXY_BIND_ADDR`  | The OS/browser's HTTPS proxy setting |
//   | 8846 | `safeprompt-metrics`              | `SAFEPROMPT_METRICS_BIND_ADDR`        | A Prometheus-compatible scraper |
//   | 8847 | `safeprompt-local-api`            | `SAFEPROMPT_LOCAL_API_BIND_ADDR`      | The browser extension + the local console (`GET /`) |
//   | 8850 | `safeprompt-spoc` (tenant relay)  | `SAFEPROMPT_SPOC_BIND_ADDR`           | Other workstations' Agents on the same LAN (deliberately `0.0.0.0` -- see `init_spoc` below) |
//
// Deliberately NOT consolidated behind one front-door port -- these five
// serve four genuinely different caller types (an SDK client configuring
// a base URL, an OS proxy setting, a metrics scraper, a browser
// extension, a peer Agent), each with its own existing protocol
// expectations a single shared port would have to multiplex or break.
//
// Final architecture (user-decided, 2026-08-10): one Rust Agent, one
// Agent API, two deployment modes -- no separate network-facing proxy
// component in front of either client-facing port. LOCAL mode
// (Community/Professional): both `SAFEPROMPT_LOCAL_API_BIND_ADDR` and
// `SAFEPROMPT_PROXY_BIND_ADDR` stay `127.0.0.1`, plain HTTP, nothing else
// needed. CENTRAL mode (Business/Enterprise): bind either or both to a
// real network address, and set that port's own
// `SAFEPROMPT_{LOCAL_API,PROXY}_TLS_CERT_PATH` +
// `SAFEPROMPT_{LOCAL_API,PROXY}_TLS_KEY_PATH` (a certificate/key the
// CUSTOMER provides -- this Agent is not a PKI system, see
// `LocalApiServer::with_tls`'s own doc comment) so that port terminates
// TLS directly, itself, rather than requiring a separate proxy in front
// of it. `SAFEPROMPT_LOCAL_API_SHARED_SECRET` (signed-request auth, see
// `with_shared_secret`) matters far more once CENTRAL mode means
// potentially every workstation in the tenant reaches port 8847; port
// 8844 (AGENT-COMM-016, 2026-08-14 -- previously TLS-less even though its
// own bind address was already overridable) has no equivalent
// shared-secret scheme yet, since its callers are SDK/app clients using
// their own upstream API key, not the browser extension.

/// Where every `SAFEPROMPT_*_PATH` env var defaults to when unset. A real
/// installed service (Windows Service or systemd unit) never runs with a
/// working directory this codebase controls — Windows Services always get
/// `C:\Windows\System32` (no per-service working directory exists in the
/// Win32 service model at all), and while systemd units *can* set
/// `WorkingDirectory=`, `agent/systemd/safeprompt-watchdog.service` (see
/// that file) deliberately doesn't rely on it either, for the same reason:
/// defaulting these to `./whatever` (relative to CWD) silently points an
/// installed service at nonexistent files, running unlicensed/unconfigured
/// with no error, which is worse than failing loudly. One well-known,
/// FHS-standard directory per OS, matching each platform's own installer's
/// data location:
///   - Windows: `%ProgramData%\SafePrompt` (installer/SafePrompt.wxs)
///   - Linux: `/var/lib/safeprompt` (a system service's own mutable state
///     directory, same FHS category systemd's own `StateDirectory=` and
///     e.g. `/var/lib/postgresql`, `/var/lib/docker` use — deliberately not
///     splitting config into `/etc` and state into `/var/lib` the way a
///     more mature Linux daemon might, since this codebase never had that
///     split even on Windows and inventing an asymmetric one here would be
///     surprising, not simpler)
///   - macOS: `/Library/Application Support/SafePrompt` (untested --
///     no macOS packaging/build has been attempted yet, this is a
///     documented-correct default, not a verified one)
/// Every env var below still overrides this for local dev/testing (all the
/// `test-*.ps1` scripts already set them explicitly).
fn default_data_dir() -> PathBuf {
    if cfg!(windows) {
        let program_data = env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        PathBuf::from(program_data).join("SafePrompt")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/SafePrompt")
    } else {
        PathBuf::from("/var/lib/safeprompt")
    }
}

fn default_path(filename: &str) -> String {
    default_data_dir().join(filename).to_string_lossy().into_owned()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting SafePrompt Agent Service...");
    // Only consumed by the agent-enterprise binary's init_fleet_reporting
    // (via DeviceHealth) -- still computed unconditionally here (uptime
    // tracking has no cost worth skipping), just unused in this
    // Community binary.
    #[allow(unused_variables)]
    let start_instant = Instant::now();

    if let Err(e) = fs::create_dir_all(default_data_dir()) {
        warn!("could not create default data directory {}: {e} — falls back to whatever each SAFEPROMPT_*_PATH env var (or CWD) resolves to", default_data_dir().display());
    }

    // Same reasoning as start_instant above -- verify_integrity()'s real
    // security value is in the check itself (it logs internally on
    // failure), not just this return value, so it still runs
    // unconditionally; only DeviceHealth's reporting of the result is
    // gated.
    #[allow(unused_variables)]
    let integrity_verified = verify_integrity();

    let telemetry = collect_telemetry();
    info!(
        "Host: {}, OS: {}, Agent Version: {}",
        telemetry.hostname, telemetry.os, telemetry.agent_version
    );

    let (features, signed_license) = load_license();
    info!(
        edition = ?features.edition(),
        tenant = features.tenant().unwrap_or("none"),
        "License loaded"
    );

    let ner_scanner = init_ner_scanner(&features);
    let inspector = Inspector::with_ner_scanner(
        PolicyConfig::default(),
        features.is_enabled(license_features::RESPONSE_SCANNING),
        ner_scanner,
    )
    // Shannon-entropy-based unknown-secret detection (2026-08-07,
    // Professional+ per the pricing matrix) -- see
    // safeprompt_secrets::EntropyScanner's own doc comment.
    .with_entropy_scanner(features.is_enabled(license_features::ENTROPY_DETECTION))
    // On-device OCR for image uploads and scanned PDF pages (2026-08-07,
    // Community+ since 2026-08-11) -- see init_ocr_engine's own doc comment.
    .with_ocr_engine(init_ocr_engine(&features))
    // AI Attack Guardian's gated tiers (2026-08-10) -- the basic tier
    // (plain-text jailbreak/injection) is always on regardless of these
    // flags, see license_features::ATTACK_ADVANCED/ATTACK_AGENTIC's own
    // doc comments and [[safeprompt-attack-gw-reconciliation]] for why
    // this call didn't exist until now. See init_attack_advanced_scanner's
    // own doc comment for why this Community build's result is always None.
    .with_attack_advanced_scanner(init_attack_advanced_scanner(&features));
    let inspector = Arc::new(inspector);

    let policy_sync_enabled = if features.is_enabled(license_features::POLICY_SYNC) {
        init_policy_sync(&inspector, features.tenant().unwrap_or("default"))
    } else {
        if env::var("SAFEPROMPT_POLICY_SOURCE").is_ok() {
            warn!(
                "SAFEPROMPT_POLICY_SOURCE is configured but policy sync is not enabled in this license \
                 (missing '{}' feature) — using the default local policy only",
                license_features::POLICY_SYNC
            );
        }
        false
    };

    // Configuration Manager (see `safeprompt_config`): local defaults <
    // local-file-or-http(s) source (`SAFEPROMPT_CONFIG_SOURCE`, defaulting
    // to `%ProgramData%\SafePrompt\config.json` if that file exists and no
    // source is explicitly set — same "look in ProgramData by default"
    // convention as license/policy/integrity/audit paths) < env var
    // overrides (every field below can still be set the old way) <
    // background hot reload for whatever is safe to change without a
    // restart today (MCP tool policy, audit retention — see the crate's
    // own doc comment for why tenant_id/upstream/provider settings are
    // load-once only). Not license-gated — this is operational
    // configuration, like Metrics, not a DLP capability.
    let agent_config_source = env::var("SAFEPROMPT_CONFIG_SOURCE").ok().or_else(|| {
        let default = default_path("config.json");
        Path::new(&default).exists().then_some(default)
    });
    let initial_agent_config = match &agent_config_source {
        Some(source) => match safeprompt_config::fetch_config(source).await {
            Ok(c) => c,
            Err(e) => {
                warn!("could not load initial configuration from {source}: {e} — using built-in defaults");
                safeprompt_config::AgentConfig::default()
            }
        },
        None => safeprompt_config::AgentConfig::default(),
    };
    let retention_days_override: Option<i64> = env::var("SAFEPROMPT_AUDIT_RETENTION_DAYS").ok().and_then(|s| s.parse().ok());
    let retention_days = Arc::new(AtomicI64::new(retention_days_override.unwrap_or(initial_agent_config.audit_retention_days)));
    // 2026-08-27, open-core Phase 2: no MCP firewall implementation exists
    // in this Community build at all -- the real `McpFirewall` engine is
    // private (`agent-enterprise/crates/mcp`). `mcp_tool_policy` in
    // `config.json`/hot-reload is accepted and parsed either way (see
    // `safeprompt_config::AgentConfig`) but has nothing to apply to here.
    let mcp_firewall: Option<Arc<std::sync::Mutex<dyn safeprompt_mcp_api::McpToolFirewall>>> = None;

    if let Some(source) = &agent_config_source {
        let poll_interval_secs: u64 = env::var("SAFEPROMPT_CONFIG_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        safeprompt_config::spawn_hot_reload(
            source.clone(),
            std::time::Duration::from_secs(poll_interval_secs),
            mcp_firewall.clone(),
            Arc::clone(&retention_days),
            initial_agent_config.clone(),
        );
        info!("configuration hot-reload enabled from {source} (polling every {poll_interval_secs}s)");
    } else {
        info!("no SAFEPROMPT_CONFIG_SOURCE configured and no config.json found in the default data directory — using built-in defaults for MCP tool policy and audit retention, no hot reload");
    }

    // Single-upstream fallback for whatever no registered provider resolves
    // to — TODO: replace with per-tenant policy synced from the SafePrompt
    // Control Plane once that exists. Each of these now has three sources,
    // in override order: the `config.json` loaded above, then the
    // historical env var (so nothing that worked before this existed stops
    // working), then a built-in default.
    let upstream_base_url = env::var("SAFEPROMPT_UPSTREAM_BASE_URL").unwrap_or(initial_agent_config.upstream_base_url.clone());
    let upstream_api_key = env::var("SAFEPROMPT_UPSTREAM_API_KEY").ok().or(initial_agent_config.upstream_api_key.clone());
    let mcp_upstream_base_url = env::var("SAFEPROMPT_MCP_UPSTREAM_BASE_URL").ok().or(initial_agent_config.mcp_upstream_base_url.clone());

    let providers = build_provider_registry(&initial_agent_config.providers);
    let providers = if features.is_enabled(license_features::MULTI_PROVIDER) {
        providers
    } else {
        if providers.is_some() {
            warn!(
                "provider configuration is present but multi-provider routing is not enabled in this \
                 license (missing '{}' feature) — falling back to single-upstream mode",
                license_features::MULTI_PROVIDER
            );
        }
        None
    };

    let tenant_id = env::var("SAFEPROMPT_TENANT_ID")
        .unwrap_or(initial_agent_config.tenant_id.clone().unwrap_or_else(|| "default".to_string()));
    // Local audit persistence is a baseline capability, not a licensed
    // feature -- the canonical pricing matrix lists "Local Audit ✅" for
    // every edition including Community, same as Prompt Scanner/Secret
    // Detection/PII Detection (none of which are behind an `is_enabled`
    // check either). Fixed 2026-08-08: this used to require the `siem`
    // feature, which only Business+ licenses ever carry -- meaning
    // Community/Professional got zero audit persistence at all, a real
    // access-control gap caught by a fresh audit across every edition, not
    // assumed correct just because the flag existed. `init_audit_storage`
    // already self-gates cleanly on whether
    // `SAFEPROMPT_AUDIT_ENCRYPTION_SECRET` is configured at all, so there's
    // nothing else to check here. `license_features::AUDIT_SIEM` now scopes
    // *only* to SIEM syslog export below, matching the matrix's separate
    // "SIEM Integration" row.
    let (storage, audit_encryption_secret) = match init_audit_storage(&tenant_id, Arc::clone(&retention_days)).await {
        Some((db, secret)) => (Some(db), Some(secret)),
        None => (None, None),
    };

    let siem_syslog = if features.is_enabled(license_features::AUDIT_SIEM) {
        build_siem_syslog_forwarder(&tenant_id)
    } else {
        if env::var("SAFEPROMPT_SIEM_SYSLOG_ADDR").is_ok() {
            warn!(
                "SAFEPROMPT_SIEM_SYSLOG_ADDR is configured but SIEM export is not enabled in this \
                 license (missing '{}' feature) — audit events will not be forwarded to a syslog collector",
                license_features::AUDIT_SIEM
            );
        }
        None
    };

    // Fleet Management: periodic self-reported checkins to the Control
    // Plane (device identity/edition/posture) — the fleet-wide view
    // `LicenseVerifier::verify` explicitly does *not* have (see its doc
    // comment on `max_devices`). Gated on the `fleet` feature (added
    // 2026-08-06, closing a real discrepancy against the canonical pricing
    // matrix — Fleet Management is Business+ only there, but this used to
    // run for any valid license regardless of features). Same path the
    // local API's /v1/extension-heartbeat writes to when browser coverage
    // is enabled below -- computed unconditionally here since a license
    // without that feature should just always report
    // extension_detected: false (no heartbeat file was ever going to
    // exist), not skip fleet reporting's own construction.
    let fleet_management_enabled = features.is_enabled(license_features::FLEET_MANAGEMENT);
    // Cloned before `init_fleet_reporting` below takes ownership of the
    // original -- the Audit Relay (Reconciled-P0 item #4) needs its own
    // copy of the same signed license as its identity proof, same reuse
    // rationale as everywhere else this license is attached to an outbound
    // request (see safeprompt_audit_relay's own doc comment). Still cloned
    // in a core-only build even though init_audit_relay's stub never uses
    // it -- keeping this line unconditional (rather than also `#[cfg]`-
    // gating it) means the two builds' surrounding code stays identical,
    // which is the whole point of the stub-function approach used
    // everywhere else in this cluster.
    let signed_license_for_audit_relay = signed_license.clone();

    // Tenant SPOC (Single Point of Coordination), item #1 of the
    // 2026-08-05 enterprise architecture backlog -- see
    // docs/SafeGateway-Tenant-SPOC-Architecture.md. Opt-in, off by default:
    // this is the *same* SafePrompt.msi/binaries every other workstation
    // runs, with one more role enabled by a single env var, so turning a
    // machine into the SPOC can never remove or overwrite another
    // machine's install (that doc's §4). Spawned independently (not part
    // of the `tokio::try_join!` blocks below) -- a SPOC misconfiguration
    // (bad bind address, etc.) must not be able to take down this
    // machine's own DLP proxy/browser coverage, which have nothing to do
    // with whether this machine also happens to relay for others. Gated
    // on the same `fleet` feature as Fleet Management above (added
    // 2026-08-06 — previously this had no license gate at all, so any
    // edition including Community could stand up a SPOC).
    init_spoc(fleet_management_enabled);

    // Audit Relay (Reconciled-P0 item #4, 2026-08-07): the agent -> SPOC ->
    // cloud upward hop for locally-persisted DlpEvents -- the last
    // remaining commercial-launch P0 blocker per task.md (real DLP audit
    // *search* in the Tenant Portal has had nothing to query without this).
    // Cloned `storage` (an `Arc`, cheap) rather than moved -- `ProxyConfig`
    // below still needs its own reference to the same database.
    init_audit_relay(fleet_management_enabled, storage.clone(), tenant_id.clone(), signed_license_for_audit_relay);
    // SP-AUD-004: same reasoning -- `local_api`'s `with_audit_export` (built
    // further below, inside the browser-coverage block) needs its own
    // clones of `storage`/`tenant_id`/`audit_encryption_secret` too, taken
    // here before `ProxyConfig` consumes the originals.
    let storage_for_audit_export = storage.clone();
    let tenant_id_for_audit_export = tenant_id.clone();
    let audit_export_licensed = features.is_enabled(license_features::AUDIT_EXPORT);

    // Overridable like every other listener in this file -- this one was
    // the sole holdout still hardcoded, which meant no test/dev setup could
    // run a second instance alongside a real installed Agent (or another
    // test run) on the same machine at all. Found and fixed while building
    // test-tenant-spoc.ps1, which needs exactly that.
    let proxy_bind_addr = env::var("SAFEPROMPT_PROXY_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8844".to_string())
        .parse()?;
    // AGENT-COMM-016 (2026-08-14) -- CENTRAL Agent mode's TLS termination
    // for this port, closing the gap local_api's own TLS wiring (below)
    // left open: SAFEPROMPT_PROXY_BIND_ADDR could already be pointed at a
    // real network address, but until now there was no way to terminate
    // TLS here, only plain HTTP -- see ProxyConfig::tls's own doc comment.
    // Same customer-provided-cert model, same both-or-neither validation,
    // as SAFEPROMPT_LOCAL_API_TLS_CERT_PATH/_KEY_PATH further below.
    let proxy_tls = match (env::var("SAFEPROMPT_PROXY_TLS_CERT_PATH"), env::var("SAFEPROMPT_PROXY_TLS_KEY_PATH")) {
        (Ok(cert), Ok(key)) => Some((PathBuf::from(cert), PathBuf::from(key))),
        (Err(_), Err(_)) => None, // unset -- ordinary LOCAL-mode install, plain HTTP, unchanged
        _ => {
            error!(
                "SAFEPROMPT_PROXY_TLS_CERT_PATH and SAFEPROMPT_PROXY_TLS_KEY_PATH must both be set together, \
                 or both left unset — only one was provided, so the API gateway is starting WITHOUT TLS. \
                 This is almost certainly not what you intended for a CENTRAL Agent deployment."
            );
            None
        }
    };
    let config = ProxyConfig {
        bind_addr: proxy_bind_addr,
        upstream_base_url,
        upstream_api_key,
        mcp_upstream_base_url,
        providers,
        storage,
        siem_syslog,
        tenant_id,
        mcp_enabled: features.is_enabled(license_features::MCP_FIREWALL),
        tls: proxy_tls,
    };
    let proxy = ProxyServer::new(config, Arc::clone(&inspector), mcp_firewall);

    // Prometheus text-exposition endpoint — its own port, deliberately not
    // sharing a listener with client-facing traffic (see
    // `safeprompt_metrics::serve`). Not license-gated: operational
    // observability, not a DLP capability tied to editions.
    let metrics_bind_addr = env::var("SAFEPROMPT_METRICS_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8846".to_string())
        .parse()?;
    let metrics_server = safeprompt_metrics::serve(metrics_bind_addr);

    info!("SafePrompt Agent Service initialization complete.");

    // Browser-AI coverage (chatgpt.com/claude.ai/... opened directly in a
    // browser, not just apps with a configurable base_url) — see
    // docs/SafeGateway-Architecture-Review.md §6b. License-gated: without
    // it, the Agent still runs the local reverse-proxy only.
    if features.is_enabled(license_features::BROWSER_COVERAGE) {
        let connect_proxy_bind_addr = env::var("SAFEPROMPT_CONNECT_PROXY_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8845".to_string())
            .parse()?;
        let ca = Arc::new(load_connect_proxy_ca()?);
        let root_cert_path =
            env::var("SAFEPROMPT_CA_ROOT_CERT_PATH").unwrap_or_else(|_| default_path("safeprompt-root-ca.pem"));
        fs::write(&root_cert_path, ca.root_cert_pem())?;
        info!("CONNECT-proxy root CA certificate available at {root_cert_path} — install this into the device's trust store (GPO/MDM) to enable browser interception");
        let connect_proxy = ConnectProxyServer::new(connect_proxy_bind_addr, ca, Arc::clone(&inspector));

        // Local API for browser-extension/ (see that crate's own doc
        // comment for why chatgpt.com/openai.com need this at all: the
        // CONNECT proxy's own outbound TLS handshake gets Cloudflare-
        // challenged there, live-confirmed 2026-08-04, so those two domains
        // rely on this instead; every other AI domain gets both this *and*
        // the CONNECT proxy, as defense-in-depth). Same Inspector instance
        // as the CONNECT proxy above -- one inspection engine, not two that
        // can drift apart. Default origin is browser-extension/manifest.json's
        // fixed key's derived ID; override via SAFEPROMPT_EXTENSION_ORIGINS
        // (comma-separated) for a differently-keyed or per-browser build.
        let local_api_bind_addr = env::var("SAFEPROMPT_LOCAL_API_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8847".to_string())
            .parse()?;
        let extension_origins = env::var("SAFEPROMPT_EXTENSION_ORIGINS")
            .unwrap_or_else(|_| "chrome-extension://lhlkjjdcbmnamgbmmahamcjnkpbpalmb".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        // apps/watchdog reads this same file back out (best-effort, same
        // convention as license.json/status.json) to fold "was the
        // extension seen recently" into the tray tooltip and, from there,
        // into DeviceHealth's fleet checkin -- see local_api's own doc
        // comment on with_heartbeat_path for why a file, not IPC.
        let mut local_api = LocalApiServer::new(local_api_bind_addr, inspector, extension_origins)
            .with_heartbeat_path(PathBuf::from(default_path("extension-status.json")))
            .with_max_ai_sites(features.max_ai_sites())
            // Display-only info for the local console (GET / on this same
            // port) -- see with_console_info's own doc comment.
            .with_console_info(
                format!("{:?}", features.edition()),
                features.tenant().map(str::to_string),
                policy_sync_enabled,
            )
            // Same Windows-installer marker as the agent-enterprise binary
            // -- see Install-ExtensionForceInstall.ps1 and
            // with_extension_manual_install_marker's own doc comments.
            .with_extension_manual_install_marker(PathBuf::from(default_path("extension-manual-install-needed.txt")));
        // Item #1 (2026-08-05, "extensions point to a central Agent"): only
        // meaningful once local_api is bound to something other than
        // 127.0.0.1 so other machines' extensions can reach it -- see
        // with_shared_secret's own doc comment for why the Origin check
        // alone isn't real authentication in that scenario. Unset (every
        // ordinary per-device install) leaves behavior unchanged.
        if let Ok(secret) = env::var("SAFEPROMPT_LOCAL_API_SHARED_SECRET") {
            local_api = local_api.with_shared_secret(secret);
        }
        // AGENT-FILE-003 (2026-08-11) -- redact-first-verify, only when
        // BOTH licensed and explicitly configured. See
        // init_llm_verifier's own doc comment.
        if let Some(verifier) = init_llm_verifier(&features) {
            local_api = local_api.with_llm_verifier(verifier);
        }
        // SP-AUD-004 -- `/ui/audit/export`, see with_audit_export's own doc
        // comment for why this route needs to exist at all. Only wired when
        // storage actually opened AND a secret was resolved (both, or
        // neither -- see `init_audit_storage`'s `Option<(Arc<LocalDatabase>,
        // String)>` return, they can't be Some/None independently);
        // `audit_export_licensed` still gates the route itself even when
        // both are present, matching the ticket's Professional+ tier.
        if let (Some(storage), Some(secret)) = (storage_for_audit_export, audit_encryption_secret) {
            local_api = local_api.with_audit_export(storage, tenant_id_for_audit_export, secret, audit_export_licensed);
        }
        // AGENT-COMM-014 (2026-08-10) -- CENTRAL Agent mode's TLS
        // termination, using a certificate/key the customer provides (see
        // LocalApiServer::with_tls's own doc comment: this Agent is
        // deliberately not a PKI system, user-directed 2026-08-10). Both
        // paths must be set together -- a cert with no key (or vice versa)
        // is a real misconfiguration, not something to silently ignore
        // half of.
        match (env::var("SAFEPROMPT_LOCAL_API_TLS_CERT_PATH"), env::var("SAFEPROMPT_LOCAL_API_TLS_KEY_PATH")) {
            (Ok(cert), Ok(key)) => {
                local_api = local_api.with_tls(PathBuf::from(cert), PathBuf::from(key));
            }
            (Err(_), Err(_)) => {} // unset -- ordinary LOCAL-mode install, plain HTTP, unchanged
            _ => {
                error!(
                    "SAFEPROMPT_LOCAL_API_TLS_CERT_PATH and SAFEPROMPT_LOCAL_API_TLS_KEY_PATH must both be set \
                     together, or both left unset — only one was provided, so local_api is starting WITHOUT TLS. \
                     This is almost certainly not what you intended for a CENTRAL Agent deployment."
                );
            }
        }

        tokio::try_join!(proxy.run(), connect_proxy.run(), local_api.run(), metrics_server)?;
    } else {
        info!(
            "browser coverage (CONNECT/TLS-interception proxy) is not enabled in this license \
             (missing '{}' feature) — running the local reverse-proxy only",
            license_features::BROWSER_COVERAGE
        );
        tokio::try_join!(proxy.run(), metrics_server)?;
    }

    Ok(())
}

/// Builds a real-time SIEM syslog forwarder if `SAFEPROMPT_SIEM_SYSLOG_ADDR`
/// (`host:port`) is configured, matching the enterprise binary's own
/// `build_siem_syslog_forwarder`. The real `safeprompt-siem::SyslogForwarder`
/// (RFC 5424 syslog implementation) lives in the sibling `agent-enterprise`
/// workspace only (2026-08-27, open-core Phase 2) -- this Community binary
/// has no SIEM export at all, regardless of `SAFEPROMPT_SIEM_SYSLOG_ADDR` or
/// license flags; `storage`'s own local Audit Pipeline persistence is
/// completely unaffected either way.
fn build_siem_syslog_forwarder(_tenant_id: &str) -> Option<Arc<dyn safeprompt_common::SiemForwarder>> {
    if env::var("SAFEPROMPT_SIEM_SYSLOG_ADDR").is_ok() {
        warn!("SAFEPROMPT_SIEM_SYSLOG_ADDR is configured, but this Community build has no SIEM export capability — see build_siem_syslog_forwarder's own doc comment");
    }
    None
}

/// Builds the multi-provider registry from `config.json`'s `providers`
/// block, with each field still overridable by its historical env var —
/// each provider is opt-in (registered only if its key/endpoint is
/// configured, from either source), so a deployment that sets none of
/// these gets exactly the old single-upstream behavior (`providers: None`).
/// See docs/SafeGateway-Architecture-Review.md §5 for the provider matrix.
///
/// 2026-08-27, open-core Phase 2: this Community binary only registers
/// providers backed by the generic, always-public
/// `OpenAiCompatibleProvider` (OpenAI itself, Groq, OpenRouter, Ollama —
/// all of which already speak OpenAI's wire format as-is). The branded
/// Anthropic/Gemini/Azure OpenAI translators (real request+response
/// reshaping, `multi_provider` license feature) live in the sibling
/// `agent-enterprise` workspace's own `build_provider_registry` only —
/// this build has no way to register them at all, regardless of any
/// `SAFEPROMPT_ANTHROPIC_API_KEY`/`SAFEPROMPT_GEMINI_API_KEY`/
/// `SAFEPROMPT_AZURE_OPENAI_*` env vars or `config.json` entries.
fn build_provider_registry(cfg: &safeprompt_config::ProviderConfig) -> Option<Arc<ProviderRegistry>> {
    let mut registry = ProviderRegistry::new();

    if let Some(key) = env::var("SAFEPROMPT_OPENAI_API_KEY").ok().or(cfg.openai_api_key.clone()) {
        registry.register("openai", Arc::new(OpenAiCompatibleProvider::new("openai", "https://api.openai.com", Some(key), AuthStyle::Bearer)));
    }
    for (env_var, cfg_present) in [
        ("SAFEPROMPT_ANTHROPIC_API_KEY", cfg.anthropic_api_key.is_some()),
        ("SAFEPROMPT_GEMINI_API_KEY", cfg.gemini_api_key.is_some()),
        ("SAFEPROMPT_AZURE_OPENAI_ENDPOINT", cfg.azure_openai.is_some()),
    ] {
        if env::var(env_var).is_ok() || cfg_present {
            warn!("{env_var} is configured, but this Community build has no branded (Anthropic/Gemini/Azure OpenAI) provider capability — see build_provider_registry's own doc comment");
        }
    }
    if let Some(key) = env::var("SAFEPROMPT_GROQ_API_KEY").ok().or(cfg.groq_api_key.clone()) {
        registry.register(
            "groq",
            Arc::new(OpenAiCompatibleProvider::new("groq", "https://api.groq.com/openai/v1", Some(key), AuthStyle::Bearer)),
        );
    }
    if let Some(key) = env::var("SAFEPROMPT_OPENROUTER_API_KEY").ok().or(cfg.openrouter_api_key.clone()) {
        registry.register(
            "openrouter",
            Arc::new(OpenAiCompatibleProvider::new("openrouter", "https://openrouter.ai/api/v1", Some(key), AuthStyle::Bearer)),
        );
    }
    if let Some(base_url) = env::var("SAFEPROMPT_OLLAMA_BASE_URL").ok().or(cfg.ollama_base_url.clone()) {
        registry.register("ollama", Arc::new(OpenAiCompatibleProvider::new("ollama", base_url, None, AuthStyle::None)));
    }

    if registry.is_empty() {
        info!("no provider configuration found (env vars or config.json) — using single-upstream fallback only (SAFEPROMPT_UPSTREAM_BASE_URL)");
        None
    } else {
        Some(Arc::new(registry))
    }
}

/// Opens the Audit Pipeline database, auto-provisioning an encryption
/// secret if `SAFEPROMPT_AUDIT_ENCRYPTION_SECRET` isn't set -- see
/// `resolve_audit_encryption_secret`'s own doc comment for why and its
/// full precedence (`SAFEPROMPT_AUDIT_DB_PATH` to override where the
/// database itself lives, default `./audit.db`).
/// `SAFEPROMPT_AUDIT_DB_PATH` does double duty (2026-08-01): a local
/// filesystem path (Community/Professional's embedded-SQLite default) OR a
/// `postgres://`/`postgresql://` connection URL, for Enterprise customers
/// running their own on-prem Postgres server and centralizing their whole
/// fleet's audit events there instead of one SQLite file per device --
/// `LocalDatabase::init` detects which by URL scheme. Config-driven, not
/// license-edition-gated: whoever sets a `postgres://` URL here gets it.
/// This is purely local Agent configuration, same as the encryption secret
/// above -- SG2 Cloud never sees this URL or the data behind it.
/// Not configured -> `None`, same graceful-degradation pattern
/// as everything else here: the Agent still scans and enforces policy, it
/// just doesn't keep a durable audit trail. When configured, also spawns
/// the retention-purge background loop (`SAFEPROMPT_AUDIT_RETENTION_DAYS`,
/// default 90) so the database doesn't grow forever.
/// `retention_days` is a shared atomic, not a plain value captured once at
/// spawn time, so `agent/crates/config`'s hot-reload loop can change it
/// while this loop keeps running — see `AgentConfig::audit_retention_days`.
/// Resolves the audit database's encryption secret, auto-provisioning one
/// if nothing was explicitly configured.
///
/// **Real bug fixed 2026-08-12**: this used to be a bare
/// `env::var("SAFEPROMPT_AUDIT_ENCRYPTION_SECRET")` — fine for the manual
/// dev-license test scripts (`installer/dev-license/editions/*/run.ps1`,
/// which set it explicitly) but the real MSI installer never sets this
/// var, so every actual Community/Professional customer who just ran the
/// installer got silent zero audit persistence despite Local Audit being
/// unconditional-by-design (see `init_audit_storage`'s own doc comment).
/// Found via a code-verified Agent-tier reconciliation, not a bug report.
///
/// Precedence, same "operational deployment secret" pattern the CONNECT
/// proxy's CA key already uses (`connect_proxy::ca::persistence`):
///   1. `SAFEPROMPT_AUDIT_ENCRYPTION_SECRET` env var, if set — an operator
///      (typically Enterprise, managing this via their own secrets
///      manager) explicitly owns and can rotate this secret.
///   2. A secret already auto-provisioned on a previous run
///      (`default_path("audit_encryption_secret.key")`) — read as-is, not
///      regenerated, since a mismatched secret can't decrypt an existing
///      database. A read failure here (corrupt/unreadable file) fails
///      closed (`None`, degrade to "not persisted") rather than silently
///      generating a new secret that would orphan the existing database.
///   3. Otherwise, generate a fresh random 32-byte secret (`OsRng`, same
///      RNG as the CA key) and persist it to that same path so it
///      survives a restart. A write failure here also fails closed rather
///      than proceeding with a secret that would vanish on next restart
///      and leave today's writes permanently undecryptable.
///
/// No per-file permission hardening (chmod/ACL) here, matching every
/// other secret this codebase already writes to the same directory
/// (`license.json`, `verifying_key.hex`, the CA key) — the trust boundary
/// is `default_data_dir()` itself, which the installer is responsible for
/// locking down, not each individual file.
fn resolve_audit_encryption_secret() -> Option<String> {
    if let Ok(secret) = env::var("SAFEPROMPT_AUDIT_ENCRYPTION_SECRET") {
        return Some(secret);
    }

    // Overridable like every other per-device state file (SAFEPROMPT_
    // LICENSE_PATH, SAFEPROMPT_SPOC_CHECKIN_CACHE_PATH, ...) both so tests
    // can isolate it instead of touching the real default_data_dir(), and
    // so an operator can relocate it deliberately.
    let secret_path =
        env::var("SAFEPROMPT_AUDIT_SECRET_PATH").unwrap_or_else(|_| default_path("audit_encryption_secret.key"));
    if Path::new(&secret_path).exists() {
        return match fs::read_to_string(&secret_path) {
            Ok(secret) if !secret.trim().is_empty() => Some(secret.trim().to_string()),
            Ok(_) => {
                warn!("audit encryption secret file at {secret_path} is empty — audit events will be logged but not persisted");
                None
            }
            Err(e) => {
                warn!("failed to read audit encryption secret at {secret_path}: {e} — audit events will be logged but not persisted");
                None
            }
        };
    }

    // First run with nothing configured: provision one and persist it so
    // every future run (and today's writes) can still decrypt this
    // database.
    use rand_core::{OsRng, RngCore};
    let mut key_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut key_bytes);
    let secret = hex::encode(key_bytes);

    if let Some(parent) = Path::new(&secret_path).parent() {
        if let Err(e) = fs::create_dir_all(parent) {
            warn!("failed to create {} for the audit encryption secret: {e} — audit events will be logged but not persisted", parent.display());
            return None;
        }
    }
    match fs::write(&secret_path, &secret) {
        Ok(()) => {
            info!("auto-provisioned a new audit encryption secret at {secret_path} (no SAFEPROMPT_AUDIT_ENCRYPTION_SECRET configured)");
            Some(secret)
        }
        Err(e) => {
            warn!("failed to persist an auto-provisioned audit encryption secret to {secret_path}: {e} — audit events will be logged but not persisted");
            None
        }
    }
}

/// Returns the opened database alongside the encryption secret that opened
/// it -- SP-AUD-004 needs the same secret again later (`with_audit_export`'s
/// `format=signed` HMAC key), and re-deriving it via a second
/// `resolve_audit_encryption_secret()` call would mean two redundant file
/// reads/writes for what is otherwise the exact same value; returning it
/// here once is simpler and can't drift.
async fn init_audit_storage(tenant_id: &str, retention_days: Arc<AtomicI64>) -> Option<(Arc<LocalDatabase>, String)> {
    let secret = resolve_audit_encryption_secret()?;
    let db_path = env::var("SAFEPROMPT_AUDIT_DB_PATH").unwrap_or_else(|_| default_path("audit.db"));
    let db_path_for_log = safeprompt_storage::redact_location(&db_path);

    let db = match LocalDatabase::init(&db_path, &secret).await {
        Ok(db) => Arc::new(db),
        Err(e) => {
            // `{e:?}` (the full anyhow chain), not `{e}` (only the top-level
            // context) -- found live 2026-08-07 debugging a real
            // SQLITE_CANTOPEN bug (see safeprompt_storage::sqlite_url_for_path's
            // doc comment): `{e}` was silently swallowing the actual
            // underlying cause, printing nothing but the same context
            // string twice and making the real failure look opaque.
            error!("failed to open audit database at {db_path_for_log}: {e:?} — audit events will not be persisted");
            return None;
        }
    };
    info!("audit database opened at {db_path_for_log} (tenant={tenant_id})");

    // SP-AUD-002 "max size": a per-tenant event-count cap, enforced in the
    // same daily loop as the day-based purge above -- see
    // `LocalDatabase::enforce_max_events`'s own doc comment for why an
    // event count (not a byte-size figure) is the backend-portable stand-in
    // used here. Generous default (500k events/tenant -- normal DLP volume
    // for one workstation is a tiny fraction of that even over a 90-day
    // window) since this exists to stop runaway growth from a misbehaving
    // app generating findings in a loop, not to be a routine trim.
    let max_events: i64 = env::var("SAFEPROMPT_AUDIT_MAX_EVENTS").ok().and_then(|s| s.parse().ok()).unwrap_or(500_000);
    let purge_db = Arc::clone(&db);
    let tenant_id_for_purge = tenant_id.to_string();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(24 * 60 * 60)).await;
            let retention_days = retention_days.load(Ordering::Relaxed);
            let cutoff = chrono::Utc::now() - chrono::Duration::days(retention_days);
            match purge_db.purge_older_than(cutoff).await {
                Ok(count) if count > 0 => info!("audit retention purge removed {count} events older than {retention_days} days"),
                Ok(_) => {}
                Err(e) => warn!("audit retention purge failed: {e}"),
            }
            match purge_db.enforce_max_events(&tenant_id_for_purge, max_events).await {
                Ok(count) if count > 0 => info!("audit retention purge removed {count} events over the {max_events}-event cap"),
                Ok(_) => {}
                Err(e) => warn!("audit max-events retention purge failed: {e}"),
            }
        }
    });

    Some((db, secret))
}

/// Builds the Layer-2 NER scanner (`safeprompt_scanner::PresidioScanner`) if
/// the `advanced_ner` license feature is present *and* a scanner command can
/// be resolved (`SAFEPROMPT_NER_SCANNER_PATH` (a raw `python.exe` with
/// `SAFEPROMPT_NER_SCANNER_ARGS` pointing at `agent/scripts/presidio_scanner.py`
/// during development, or a PyInstaller-frozen `presidio-scanner.exe` with no
/// args once packaged; `PresidioScanner` doesn't care which), or -- 2026-08-11,
/// same real gap this comment used to require an env var for at all --
/// `presidio-scanner.exe` sitting next to this process's own executable,
/// which `installer/SafePrompt.wxs` now actually installs there. Mirrors
/// `init_ocr_engine`'s `resolve_and_init_dylib`: an explicit env var always
/// wins, the installed-next-to-the-exe file is the default a real customer
/// never has to configure by hand. Spawns and health-checks it right here at
/// startup (rather than lazily on first request) so a slow/broken scanner is
/// a clear log line at boot, not a silent multi-second delay on whichever
/// request happens to arrive first. Not resolvable, not licensed, or fails
/// its health check -> `None`, same graceful-degradation posture as
/// everything else in this file: Layer-1 regex/checksum scanning
/// (`Inspector`'s always-on scanners) is completely unaffected either way.
fn init_ner_scanner(_features: &FeatureManager) -> Option<Box<dyn safeprompt_common::Scanner>> {
    // The Presidio/spaCy NER subprocess (`safeprompt-scanner`) lives in
    // the sibling `agent-enterprise` workspace's own apps/service binary
    // only -- this Community binary has no Layer 2 NER at all; Layer 1
    // regex/checksum scanning (`Inspector`'s always-on scanners) is
    // completely unaffected.
    None
}

/// AI Attack Guardian's advanced/agentic tiers (`license_features::
/// ATTACK_ADVANCED`/`ATTACK_AGENTIC`) -- the real
/// `safeprompt-attack-advanced::AdvancedAttackScanner` lives in the sibling
/// `agent-enterprise` workspace's own apps/service binary only (2026-08-27,
/// open-core Phase 3) -- this Community binary has no advanced/agentic
/// tier at all, regardless of license flags; `crates/prompt`'s basic tier
/// (`Inspector`'s always-on `prompt` field) is completely unaffected.
fn init_attack_advanced_scanner(_features: &FeatureManager) -> Option<Box<dyn safeprompt_common::Scanner>> {
    None
}

/// Redact-first-verify (2026-08-11, `license_features::LLM_VERIFY`,
/// Business+) -- an optional second-opinion LLM pass over text that
/// already scanned clean locally, wired into `local_api`'s `/v1/inspect`
/// and `/v1/inspect-file` (see `apply_llm_verify` there). The real
/// `safeprompt-llm-verify::HttpLlmVerifier` implementation lives in the
/// sibling `agent-enterprise` workspace only (2026-08-27, open-core Phase
/// 2) -- this Community binary has no verify pass at all, regardless of
/// `SAFEPROMPT_LLM_VERIFY_BASE_URL` or license flags; local (regex/NER/
/// entropy) scanning is completely unaffected either way.
fn init_llm_verifier(_features: &FeatureManager) -> Option<Arc<dyn safeprompt_common::LlmVerifier>> {
    if env::var("SAFEPROMPT_LLM_VERIFY_BASE_URL").is_ok() {
        warn!("SAFEPROMPT_LLM_VERIFY_BASE_URL is configured, but this Community build has no redact-first-verify capability — see init_llm_verifier's own doc comment");
    }
    None
}

/// On-device OCR engine (2026-08-07, `license_features::OCR`, Community+
/// since 2026-08-11 -- see `license_features::OCR`'s own doc comment for
/// the full tier history) -- same graceful-degradation shape as
/// `init_ner_scanner` above: unlicensed,
/// or the underlying model load fails for any reason (no network for the
/// first-run model download, no compatible ONNX Runtime dylib resolvable --
/// see `safeprompt_ocr`'s own doc comment for that resolution order), logs
/// a warning and returns `None` rather than failing Agent startup. Image
/// uploads then come back `Unsupported` (not silently "scanned clean") and
/// scanned PDFs fall back to whatever `pdf-extract` alone found -- both
/// documented in `safeprompt-file-inspector`'s own doc comment.
///
/// **Startup cost, stated plainly**: building `OarOcrEngine` loads real
/// ONNX models into memory and, on a machine that has never run OCR
/// before, downloads them first (~12MB total, cached under `$OAR_HOME`
/// afterward -- see `safeprompt_ocr`'s module doc comment). For any
/// licensed Agent with the `ocr` feature this happens once per process
/// start, not per request.
fn init_ocr_engine(features: &FeatureManager) -> Option<Arc<dyn safeprompt_ocr::OcrEngine>> {
    if !features.is_enabled(license_features::OCR) {
        return None;
    }
    match safeprompt_ocr::OarOcrEngine::new_with_auto_download() {
        Ok(engine) => {
            info!("on-device OCR ready (image uploads + scanned-PDF pages will be scanned)");
            Some(Arc::new(engine))
        }
        Err(e) => {
            warn!(
                "OCR is licensed but the pipeline failed to initialize ({e}) -- image uploads and \
                 scanned PDF pages will come back Unsupported until this is resolved"
            );
            None
        }
    }
}

/// `safeprompt-policy-sync` lives in the sibling `agent-enterprise`
/// workspace's own apps/service binary only -- this Community binary
/// has nothing to sync from (no signed-policy-document verifier at
/// all); `Inspector` keeps whatever policy it's given locally, same
/// graceful-degradation posture as every other optional subsystem
/// here.
fn init_policy_sync(_inspector: &Arc<Inspector>, _tenant: &str) -> bool {
    false
}

/// Starts the Tenant SPOC role if `SAFEPROMPT_SPOC_ENABLED=1` -- off unless
/// explicitly opted into, same posture as every other optional subsystem
/// here. Reuses the exact same verifying keys every ordinary workstation
/// already loads (`SAFEPROMPT_LICENSE_PUBLIC_KEY`/`SAFEPROMPT_POLICY_PUBLIC_KEY`)
/// rather than inventing a new trust root just for this role. Bound to
/// `SAFEPROMPT_SPOC_BIND_ADDR` (default `0.0.0.0:8850`) -- deliberately
/// LAN-reachable, unlike `local_api`'s hardcoded 127.0.0.1-only bind, since
/// the entire point of this role is that *other machines* reach it.
/// Misconfigured (can't load either verifying key) -> logs an error and
/// stays disabled rather than silently doing nothing, same as
/// `init_policy_sync`'s posture for the same class of mistake. Gated on the
/// `fleet` feature (added 2026-08-06 — this role is "centralized
/// management," which the canonical pricing matrix scopes to Business+; it
/// previously had no license gate at all, so any edition including
/// Community could stand up a SPOC).
/// `safeprompt-spoc` lives in the sibling `agent-enterprise` workspace's
/// own apps/service binary only -- this Community binary simply cannot
/// be told to take on this role (`SAFEPROMPT_SPOC_ENABLED` has nothing
/// to enable here).
fn init_spoc(_fleet_management_enabled: bool) {}

/// Starts the Audit Relay background loop (Reconciled-P0 item #4,
/// 2026-08-07, see task.md's enterprise-architecture-backlog #9) if a live
/// Audit Pipeline database exists (`storage.is_some()` -- gated on the
/// `siem` feature one level up, same as local persistence itself: there is
/// nothing to relay without it), a valid license was loaded (the batch's
/// own identity proof, same reuse as fleet reporting), and
/// `SAFEPROMPT_AUDIT_RELAY_ENDPOINT` is configured, explicitly (a SPOC's
/// `/audit/relay` route -- a LAN address, never derivable) or implicitly
/// via `SAFEPROMPT_CONTROL_PLANE_URL` (the cloud's own ingestion endpoint
/// directly, for a deployment with no SPOC in between). Any of the three
/// missing -> no relay, same graceful-degradation posture as everything
/// else in this file: the local database keeps every event regardless,
/// this only affects whether a copy also reaches the cloud for the Tenant
/// Portal's audit search.
/// Returns whether the relay loop was actually started -- makes the gating
/// decision itself observable/testable (see the `#[cfg(test)]` coverage
/// below) rather than a fire-and-forget `()` nobody outside a log line
/// could verify. `safeprompt-audit-relay` is an open-core Phase 1
/// candidate for the private workspace -- see this crate's Cargo.toml
/// `enterprise` feature doc comment. A core-only build has nowhere to
/// relay to; the local database still keeps every event regardless (audit
/// *persistence* is unconditional, only the cloud copy is affected).
fn init_audit_relay(_fleet_management_enabled: bool, _storage: Option<Arc<LocalDatabase>>, _tenant_id: String, _signed_license: Option<SignedLicense>) -> bool {
    false
}

/// Loads the CONNECT-proxy root CA from `SAFEPROMPT_CA_KEY_PATH` (default
/// `./ca_signing_key.enc`), decrypting with `SAFEPROMPT_CA_KEY_ENCRYPTION_SECRET`,
/// generating and saving a new one if none exists yet — this is what keeps
/// the same root CA (and thus the same device trust) across restarts.
/// Without the secret configured, falls back to an ephemeral CA regenerated
/// every restart (fine for local dev; browser interception won't be usable
/// in a real deployment until the secret is set, since no device would
/// trust a CA that changes on every restart).
fn load_connect_proxy_ca() -> anyhow::Result<CertificateAuthority> {
    match env::var("SAFEPROMPT_CA_KEY_ENCRYPTION_SECRET") {
        Ok(secret) => {
            let key_path =
                env::var("SAFEPROMPT_CA_KEY_PATH").unwrap_or_else(|_| default_path("ca_signing_key.enc"));
            let ca = CertificateAuthority::load_or_generate(Path::new(&key_path), &secret)?;
            info!("loaded CONNECT-proxy root CA key from {key_path} (persists across restarts)");
            Ok(ca)
        }
        Err(_) => {
            warn!(
                "SAFEPROMPT_CA_KEY_ENCRYPTION_SECRET not set — using an ephemeral CONNECT-proxy root CA \
                 regenerated on every restart. Fine for local dev; set this for any real deployment, or \
                 devices won't keep trusting the root cert across restarts."
            );
            Ok(CertificateAuthority::generate()?)
        }
    }
}

/// Loads and verifies a license from `SAFEPROMPT_LICENSE_PATH` /
/// `SAFEPROMPT_LICENSE_PUBLIC_KEY` (both default to `./license.json` /
/// `./verifying_key.hex`). Missing or invalid license -> unlicensed
/// (Community edition, no gated features) rather than refusing to start —
/// per docs/SafeGateway-Architecture-Review.md §9, Community still ships
/// core scanning. Feature-gating individual scanners on `features` is not
/// wired up yet; this currently only affects the "License loaded" log line.
/// Also returns the `SignedLicense` itself (not just the `FeatureManager`
/// derived from its claims) — Fleet Management's checkin embeds it whole so
/// the Control Plane can independently re-verify "this checkin really came
/// from a device holding a real license," not just trust whatever fields a
/// checkin payload happens to claim.
fn load_license() -> (FeatureManager, Option<SignedLicense>) {
    let license_path = env::var("SAFEPROMPT_LICENSE_PATH").unwrap_or_else(|_| default_path("license.json"));
    let public_key_path =
        env::var("SAFEPROMPT_LICENSE_PUBLIC_KEY").unwrap_or_else(|_| default_path("verifying_key.hex"));

    let result = (|| -> anyhow::Result<SignedLicense> {
        let public_hex = fs::read_to_string(&public_key_path)?;
        let public_bytes: [u8; 32] = hex::decode(public_hex.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key file must contain exactly 32 bytes hex-encoded"))?;
        let verifier = LicenseVerifier::from_public_key_bytes(&public_bytes)
            .map_err(|e| anyhow::anyhow!("bad public key: {e}"))?;

        let signed: SignedLicense = serde_json::from_str(&fs::read_to_string(&license_path)?)?;
        let fingerprint = compute_machine_fingerprint();
        verifier
            .verify(&signed, &fingerprint)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        Ok(signed)
    })();

    match result {
        Ok(signed) => {
            // Grace period is real (verify() above already tolerated it,
            // that's why this branch is reached at all), but silent unless
            // something logs it -- a customer running past nominal expiry
            // on borrowed time should see *why* it still works, not
            // discover it only once the grace window itself elapses and
            // features suddenly disappear with no warning.
            if let GraceStatus::InGrace { days_remaining } = grace_status(&signed.claims) {
                warn!(
                    tenant = %signed.claims.tenant,
                    expiry = %signed.claims.expiry,
                    days_remaining,
                    "license is past its nominal expiry but still inside its grace period — renew soon, \
                     features will stop working once the grace window elapses"
                );
            }
            (FeatureManager::from_verified(signed.claims.clone()), Some(signed))
        }
        Err(e) => {
            warn!("no valid license found ({e}) — running as unlicensed Community edition");
            (FeatureManager::unlicensed(), None)
        }
    }
}

/// Verifies the running binary against a signed integrity manifest from
/// `SAFEPROMPT_INTEGRITY_MANIFEST_PATH` / `SAFEPROMPT_INTEGRITY_PUBLIC_KEY`
/// (default `./integrity_manifest.json` / `./integrity_public_key.hex`).
/// Unlike licensing, this fails *closed*: no manifest configured is treated
/// as "integrity checking isn't set up for this deployment" (fine for dev —
/// logs a warning and continues), but a manifest that's present and doesn't
/// verify means the binary on disk doesn't match what the vendor signed —
/// that's exactly the tampering this exists to catch, so the process exits
/// rather than starting a service that might not be trustworthy.
/// Returns whether a manifest was present *and* verified — `false` means
/// "not configured for this deployment," not "failed," since a failure
/// exits the process outright rather than returning. Fleet checkins report
/// this so the Control Plane can distinguish devices with tamper-detection
/// actually turned on from ones just running with it unconfigured.
fn verify_integrity() -> bool {
    let manifest_path =
        env::var("SAFEPROMPT_INTEGRITY_MANIFEST_PATH").unwrap_or_else(|_| default_path("integrity_manifest.json"));
    let public_key_path =
        env::var("SAFEPROMPT_INTEGRITY_PUBLIC_KEY").unwrap_or_else(|_| default_path("integrity_public_key.hex"));

    if !Path::new(&manifest_path).exists() {
        warn!("no integrity manifest at {manifest_path} — skipping self-integrity check (fine for dev; configure this for production)");
        return false;
    }

    let result = (|| -> anyhow::Result<()> {
        let public_hex = fs::read_to_string(&public_key_path)?;
        let public_bytes: [u8; 32] = hex::decode(public_hex.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key file must contain exactly 32 bytes hex-encoded"))?;
        let verifier = ManifestVerifier::from_public_key_bytes(&public_bytes)
            .map_err(|e| anyhow::anyhow!("bad public key: {e}"))?;

        let signed: SignedManifest = serde_json::from_str(&fs::read_to_string(&manifest_path)?)?;
        safeprompt_integrity::verify_self(&verifier, &signed).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    })();

    match result {
        Ok(()) => {
            info!("self-integrity check passed");
            true
        }
        Err(e) => {
            error!("SELF-INTEGRITY CHECK FAILED: {e} — refusing to start");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod audit_secret_provisioning_tests {
    use super::*;

    /// Regression coverage for the 2026-08-12 fix: real MSI installs never
    /// set `SAFEPROMPT_AUDIT_ENCRYPTION_SECRET`, so `init_audit_storage`
    /// silently persisted nothing for every real Community/Professional
    /// customer despite Local Audit being unconditional-by-design. All
    /// scenarios live in one test function, run sequentially, not split
    /// across multiple `#[test]`s -- both env vars this touches
    /// (`SAFEPROMPT_AUDIT_ENCRYPTION_SECRET`, `SAFEPROMPT_AUDIT_SECRET_PATH`)
    /// are process-global, and cargo runs different `#[test]` fns
    /// concurrently by default, so separate tests touching the same two
    /// var names would race each other -- same reasoning
    /// `license_clock_sync_tests` documents for `SAFEPROMPT_LICENSE_PATH`.
    #[test]
    fn resolves_and_persists_the_audit_secret_correctly_in_every_scenario() {
        let dir = std::env::temp_dir().join(format!("sp_audit_secret_test_{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let secret_path = dir.join("audit_encryption_secret.key");
        env::set_var("SAFEPROMPT_AUDIT_SECRET_PATH", secret_path.to_str().unwrap());
        env::remove_var("SAFEPROMPT_AUDIT_ENCRYPTION_SECRET");

        // Branch 1: explicit env var always wins, even if a persisted file
        // exists at the same path (it doesn't here, but the ordering is
        // what's under test).
        env::set_var("SAFEPROMPT_AUDIT_ENCRYPTION_SECRET", "operator-managed-secret");
        assert_eq!(resolve_audit_encryption_secret().as_deref(), Some("operator-managed-secret"));
        env::remove_var("SAFEPROMPT_AUDIT_ENCRYPTION_SECRET");

        // Branch 2: nothing in the env, nothing on disk yet -> a fresh
        // secret is generated AND persisted (not just returned once).
        assert!(!secret_path.exists());
        let provisioned = resolve_audit_encryption_secret().expect("should auto-provision when nothing is configured");
        assert_eq!(provisioned.len(), 64, "expected 32 bytes hex-encoded");
        assert!(secret_path.exists(), "the provisioned secret must be persisted so it survives a restart");

        // Branch 3: a persisted secret from a prior run is reused as-is,
        // not regenerated -- a mismatched secret would orphan whatever was
        // already encrypted with the first one.
        let reloaded = resolve_audit_encryption_secret().expect("should reload the already-persisted secret");
        assert_eq!(reloaded, provisioned, "must reuse the persisted secret, not silently rotate it");

        // Branch 4: a corrupted/empty persisted-secret file must fail
        // closed (None, degrade to "not persisted this run") rather than
        // silently generating a replacement that can't decrypt whatever
        // was already written with the original secret.
        fs::write(&secret_path, "").unwrap();
        assert!(resolve_audit_encryption_secret().is_none());

        env::remove_var("SAFEPROMPT_AUDIT_SECRET_PATH");
        let _ = fs::remove_dir_all(&dir);
    }
}
