// Local HTTP API for the browser extension (browser-extension/) — the
// counterpart to connect_proxy's TLS-interception MITM path, for the domains
// that can't be MITM'd at all (chatgpt.com/openai.com/gemini.google.com:
// the upstream's own bot detection fingerprints our own outbound TLS
// handshake and blocks/challenges it, see connect_proxy::sni_gate's doc
// comment) and, per architecture review 2026-08-04, as a second,
// defense-in-depth layer for every other AI domain too — since the
// extension runs inside the real browser, patching fetch/XHR before a
// request ever leaves the page, it's immune to that entire class of problem
// regardless of which site it's covering.
//
// Deliberately the *same* Inspector the CONNECT proxy uses (constructed
// once in apps/service and passed to both) — one inspection engine, not two
// codebases that can drift, matching the review's "single inspection
// engine" principle.
//
// Auth: 127.0.0.1-only bind by default (never LAN, see ConnectProxyServer's
// own doc comment on the same principle) plus an Origin-header allow-list.
// The browser extension's *background service worker* — not a content
// script — is what actually calls this API: with `host_permissions`
// covering this origin, a service worker's fetch bypasses CORS entirely (no
// preflight, no Access-Control-* response headers needed here) while still
// sending a genuine `Origin: chrome-extension://<id>` request header that a
// non-extension local process can't forge. That's why there's no CORS
// middleware in this file — it would be solving a problem that doesn't
// apply to this caller.
//
// Item #1 (2026-08-05, "extensions point to a central Agent"): the bind
// address was already just a config value (`SAFEPROMPT_LOCAL_API_BIND_ADDR`
// in apps/service), so one Agent's local_api can serve every workstation's
// extension on a LAN today — but the Origin check above is only real
// protection against a *browser-context* caller; a general LAN attacker
// running curl can set an arbitrary `Origin` header too. `with_shared_secret`
// adds a real second factor (an exact-match shared header) for exactly that
// scenario, opt-in and additive — every 127.0.0.1-only install is
// completely unaffected by its existence.

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use hmac::{Hmac, Mac};
use safeprompt_common::{Action, LlmVerifier, ScanResult};
use safeprompt_inspector::Inspector;
use safeprompt_policy::PolicyConfig;
use safeprompt_storage::LocalDatabase;
use serde::Deserialize;
use sha2::Sha256;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{info, warn};

/// The local console (`GET /`) -- a single self-contained HTML/CSS/JS file
/// compiled straight into this binary via `include_str!`, the same "one
/// exe, no separate runtime files" pattern as the sibling SG2 project this
/// was modeled on (ThreatVantage's Go `//go:embed`). Lets an end user (or a
/// tester) actually see and drive the Agent -- test what gets flagged, view
/// and edit the live policy -- through a browser instead of hand-editing
/// signed JSON via CLI, closing the gap flagged in
/// `safeprompt-tray-first-run-notice`'s "explicitly not fixed" note.
const CONSOLE_HTML: &str = include_str!("console.html");

#[derive(Clone)]
struct ApiState {
    inspector: Arc<Inspector>,
    allowed_origins: Arc<Vec<String>>,
    /// Where `/v1/extension-heartbeat` writes its last-seen timestamp.
    /// `None` disables the endpoint entirely (returns 404) rather than
    /// writing somewhere nobody reads it back from — callers that don't
    /// care about extension health (e.g. most test setups) just omit it.
    heartbeat_path: Option<Arc<PathBuf>>,
    /// Where the Windows installer leaves `extension-manual-install-needed.txt`
    /// -- see `with_extension_manual_install_marker`'s doc comment. `None`
    /// disables the console's manual-install banner entirely (non-Windows,
    /// or a build that never wires this in), same "omit it, feature just
    /// isn't there" posture as `heartbeat_path`.
    extension_manual_install_marker: Option<Arc<PathBuf>>,
    /// License cap on `/v1/policy/applications`' response (item #6 -- see
    /// `LicenseClaims::max_ai_sites`). `None` means uncapped, not zero.
    max_ai_sites: Option<u32>,
    /// Second authentication factor, item #1 (2026-08-05) -- see
    /// `with_shared_secret`'s doc comment. `None` (the default, every
    /// 127.0.0.1-only install) means the Origin check alone still gates
    /// every route, unchanged from before this existed.
    shared_secret: Option<Arc<String>>,
    /// AGENT-COMM-004 -- replay tracking for the signed-request scheme
    /// above. Constructed once per server (in `router()`), not per-request
    /// -- it must be the same instance across every request for the
    /// "have we seen this nonce before" check to mean anything. Allocated
    /// unconditionally (cheap, empty) rather than behind an `Option`
    /// alongside `shared_secret` -- simpler than threading an `Option`
    /// through `verify_signed_request` for a struct that costs nothing
    /// when unused.
    nonce_cache: Arc<NonceCache>,
    /// AGENT-COMM-009 -- see `RateLimiter`'s own doc comment. Same
    /// per-server (not per-request) construction reasoning as
    /// `nonce_cache` above.
    rate_limiter: Arc<RateLimiter>,
    /// Display-only fields for the local console's Status tab -- see
    /// `with_console_info`'s doc comment.
    edition: Arc<String>,
    tenant: Option<Arc<String>>,
    policy_sync_active: bool,
    /// AGENT-FILE-003 -- see `LocalApiServer::with_llm_verifier`'s doc
    /// comment. `None` unless both licensed and explicitly configured. A
    /// trait object (2026-08-27, open-core Phase 2) rather than a config
    /// struct + free function -- the real `safeprompt-llm-verify`
    /// implementation is private (`agent-enterprise/`); this crate only
    /// depends on the seam and never sees `LlmVerifyConfig`'s shape.
    llm_verifier: Option<Arc<dyn LlmVerifier>>,
    /// SP-AUD-004 -- see `LocalApiServer::with_audit_export`'s doc comment.
    audit_export: Option<AuditExportState>,
}

/// Bundles what `/ui/audit/export` needs: the same database local audit
/// persistence already writes to, the tenant id to scope the query to (a
/// single-device local export has no cross-tenant concept), and whether the
/// `audit_export` license feature is actually present -- kept together
/// rather than three separate `Option`s on `ApiState` since all three only
/// ever matter as a unit.
#[derive(Clone)]
struct AuditExportState {
    storage: Arc<LocalDatabase>,
    tenant_id: Arc<String>,
    /// Needed only for `format=signed` (`export_signed_archive`'s HMAC key)
    /// -- the same secret `apps/service` already resolved to open `storage`
    /// in the first place (see `resolve_audit_encryption_secret`), passed
    /// through rather than re-derived here.
    encryption_secret: Arc<String>,
    licensed: bool,
}

#[derive(Deserialize)]
struct InspectRequest {
    text: String,
    /// 2026-09-03: the AI site's hostname (`window.location.hostname`,
    /// read by `bridge-content-script.js` -- the same content script that
    /// relays this call from the page's MAIN world, so it always knows
    /// its own page's origin). Optional and defaulted, not required: an
    /// older extension build, or any other caller of this endpoint, won't
    /// send it, and persisting "unknown" is still strictly better than
    /// rejecting the request outright over a cosmetic audit-log field.
    /// Previously every persisted DlpEvent showed "unknown" here
    /// unconditionally (real user report) -- see `persist_inspect_event`.
    #[serde(default)]
    domain: Option<String>,
}

/// AGENT-FILE-002: the browser extension's file/image-upload interceptor
/// (main-world-interceptor.js) can't cleanly relay a `multipart/form-data`
/// body through `chrome.runtime.sendMessage`'s structured-clone message
/// channel the way it relays a plain JSON string for text -- so a file
/// upload is sent here instead, as raw bytes base64-encoded into an
/// ordinary JSON envelope, symmetric with `InspectRequest` above rather
/// than adding a second body format this API has to parse.
#[derive(Deserialize)]
struct InspectFileRequest {
    filename: String,
    data_base64: String,
    /// See `InspectRequest::domain`'s doc comment -- same field, same
    /// reasoning, just for the file-upload path.
    #[serde(default)]
    domain: Option<String>,
}

fn blocked_file_result() -> ScanResult {
    ScanResult { action: Action::Block, findings: Vec::new(), original_prompt: String::new(), sanitized_prompt: String::new(), unmaskable_reason: None }
}

fn allowed_file_result() -> ScanResult {
    ScanResult { action: Action::Allow, findings: Vec::new(), original_prompt: String::new(), sanitized_prompt: String::new(), unmaskable_reason: None }
}

/// rustls 0.23 refuses to guess a default `CryptoProvider` if more than one
/// backend (`ring`, `aws-lc-rs`) ends up linked into the same binary --
/// which `cargo test --workspace` (and, in production, a build that also
/// pulls in `connect_proxy`'s own TLS) can trigger by unifying different
/// crates' default features into one binary. Same fix, same reasoning as
/// `connect_proxy::ca`'s own `ensure_crypto_provider_installed` -- pinned
/// here too (not shared between the two crates: each crate that
/// constructs a `rustls::ServerConfig` needs its own idempotent call at
/// its own entry point, not a cross-crate dependency just for this).
fn ensure_crypto_provider_installed() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

pub struct LocalApiServer {
    bind_addr: SocketAddr,
    inspector: Arc<Inspector>,
    /// Exact `Origin` header values to accept, e.g.
    /// `chrome-extension://<32-char-id>` — one per browser build of
    /// browser-extension/, since each gets a different extension ID even
    /// with a fixed manifest `key` (Chrome/Edge/Firefox each mint their own).
    allowed_origins: Vec<String>,
    heartbeat_path: Option<PathBuf>,
    extension_manual_install_marker: Option<PathBuf>,
    max_ai_sites: Option<u32>,
    shared_secret: Option<String>,
    edition: String,
    tenant: Option<String>,
    policy_sync_active: bool,
    /// AGENT-COMM-003 -- see `with_tls`'s own doc comment.
    tls: Option<(PathBuf, PathBuf)>,
    /// AGENT-FILE-003 -- see `with_llm_verifier`'s own doc comment.
    llm_verifier: Option<Arc<dyn LlmVerifier>>,
    /// SP-AUD-004 -- see `with_audit_export`'s own doc comment.
    audit_export: Option<AuditExportState>,
}

impl LocalApiServer {
    pub fn new(bind_addr: SocketAddr, inspector: Arc<Inspector>, allowed_origins: Vec<String>) -> Self {
        Self {
            bind_addr,
            inspector,
            allowed_origins,
            heartbeat_path: None,
            extension_manual_install_marker: None,
            max_ai_sites: None,
            shared_secret: None,
            edition: "unknown".to_string(),
            tenant: None,
            policy_sync_active: false,
            tls: None,
            llm_verifier: None,
            audit_export: None,
        }
    }

    /// AGENT-FILE-003 (2026-08-11) -- redact-first-verify. `apps/service`
    /// only calls this when BOTH the `llm_verify` license feature is
    /// present AND a tenant has explicitly configured a verify endpoint
    /// (env vars, see that init function's own doc comment) -- this
    /// crate has no opinion of its own about whether it should be on, it
    /// just carries whatever verifier it's given. `None` (the default)
    /// means `/v1/inspect` and `/v1/inspect-file` behave exactly as before
    /// this existed. Takes the trait object directly (2026-08-27, open-core
    /// Phase 2) rather than a config struct -- the real HTTP-calling
    /// implementation and its endpoint/model/API-key configuration are both
    /// private (`agent-enterprise/`); this crate never constructs either.
    pub fn with_llm_verifier(mut self, verifier: Arc<dyn LlmVerifier>) -> Self {
        self.llm_verifier = Some(verifier);
        self
    }

    /// SP-AUD-004 (2026-08-12) -- exposes `/ui/audit/export` on the local
    /// console. Real, live gap this closes: `safeprompt-storage`'s
    /// `export_csv`/`export_json`/`export_signed_archive` already existed
    /// and worked, but the only caller was `license-tool audit-export` --
    /// and `license-tool.exe` is deliberately never shipped to a customer
    /// (`installer/SafePrompt.wxs`'s own top-of-file comment: "vendor-side
    /// issuer"), meaning no real Community/Professional install has ever
    /// had a reachable way to export its own audit log at all. `storage` is
    /// the same `LocalDatabase` handle `apps/service` already opened for
    /// persistence -- this doesn't open a second connection to the file.
    /// `licensed` is the `audit_export` feature check (Professional+ per
    /// SP-AUD-004's own ticket tier); `storage` can still be `Some` on
    /// Community (persistence itself is unconditional, see
    /// `AUDIT_SIEM`'s doc comment) while `licensed` is `false` -- the route
    /// checks both independently, see `ui_audit_export`.
    pub fn with_audit_export(mut self, storage: Arc<LocalDatabase>, tenant_id: String, encryption_secret: String, licensed: bool) -> Self {
        self.audit_export = Some(AuditExportState { storage, tenant_id: Arc::new(tenant_id), encryption_secret: Arc::new(encryption_secret), licensed });
        self
    }

    /// AGENT-COMM-014 (2026-08-10) -- TLS termination for CENTRAL Agent
    /// mode, using a certificate and private key the CUSTOMER provides
    /// (their own internal CA, or a public CA cert for an internal
    /// hostname). This Agent never generates, issues, rotates, or manages
    /// certificates of its own -- deliberately not a PKI system
    /// (user-directed decision, 2026-08-10: "I'd strongly support
    /// customer-provided CA/certificate rather than forcing SafePrompt's
    /// installer to become a PKI system"). One Rust Agent, one Agent API,
    /// two deployment modes -- no separate network-facing proxy component
    /// in front of it; this server terminates TLS directly.
    ///
    /// Cert/key rotation is the customer's own responsibility: replace the
    /// files and restart the Agent. A signal-driven hot-reload (matching
    /// how `apply_synced_policy` hot-swaps policy without a restart) is a
    /// reasonable future addition, not attempted here -- the failure mode
    /// of getting that wrong (serving a stale/expired cert silently) is
    /// worse than requiring a restart for now.
    ///
    /// `None` (the default -- every LOCAL-mode install): plain HTTP on
    /// loopback, matching every install today. Only meaningful once
    /// `bind_addr` is non-loopback anyway (CENTRAL mode) -- LOCAL mode's
    /// loopback-only traffic never leaves the machine, so it has nothing
    /// to protect against a network observer that TLS would add.
    pub fn with_tls(mut self, cert_path: PathBuf, key_path: PathBuf) -> Self {
        self.tls = Some((cert_path, key_path));
        self
    }

    /// Display-only info for the local console's Status tab (`GET /ui/status`)
    /// -- purely informational, not a security boundary the way license
    /// gating elsewhere in this codebase is. `policy_sync_active` lets the
    /// console warn a user editing policy from `/ui/policy` that their
    /// change is an in-memory-only override of *this* process and can be
    /// overwritten by the next sync tick, rather than that happening
    /// silently.
    pub fn with_console_info(mut self, edition: String, tenant: Option<String>, policy_sync_active: bool) -> Self {
        self.edition = edition;
        self.tenant = tenant;
        self.policy_sync_active = policy_sync_active;
        self
    }

    /// Enables `/v1/extension-heartbeat`, writing its last-seen timestamp to
    /// `path` on every call — the caller (apps/service) is expected to pass
    /// `%ProgramData%\SafePrompt\extension-status.json`, the same
    /// file-polling convention apps/watchdog already uses for
    /// license.json/status.json rather than an IPC channel (see
    /// apps/watchdog's own doc comment on why: permissive-enough ProgramData
    /// ACLs beat hand-rolling a named-pipe SECURITY_ATTRIBUTES DACL). This
    /// crate deliberately doesn't know or care *why* the path is that one —
    /// path resolution stays apps/service's job, matching every other
    /// dependency-injected config in this server.
    pub fn with_heartbeat_path(mut self, path: PathBuf) -> Self {
        self.heartbeat_path = Some(path);
        self
    }

    /// `path` is `%ProgramData%\SafePrompt\extension-manual-install-needed.txt`
    /// -- written by the Windows installer's `Install-ExtensionForceInstall.ps1`
    /// when it detects the machine isn't domain/Intune-managed and so skips
    /// the silent `ExtensionInstallForcelist` policy (Chrome refuses that on
    /// an unmanaged PC -- confirmed live 2026-08-31, see that script's own
    /// doc comment). `GET /ui/status` reports whether the marker currently
    /// exists so the local console can show a manual "Add to Chrome"
    /// prompt instead of a customer silently never getting the extension.
    /// Existence is checked per-request, not cached at startup -- this file
    /// is small, local, and rarely read, so there's no reason to risk
    /// showing a stale banner after a customer follows the instructions.
    pub fn with_extension_manual_install_marker(mut self, path: PathBuf) -> Self {
        self.extension_manual_install_marker = Some(path);
        self
    }

    /// Caps `/v1/policy/applications`' response to at most `cap` domains --
    /// the license-side enforcement point for item #6's "customize the AI
    /// site list" (Community defaults to 5 via `license-tool issue`, paid
    /// editions get `None`/uncapped). Omitting this call (or passing `None`)
    /// leaves the endpoint uncapped, matching a license with no
    /// `max_ai_sites` claim at all.
    pub fn with_max_ai_sites(mut self, cap: Option<u32>) -> Self {
        self.max_ai_sites = cap;
        self
    }

    /// Second authentication factor for every scan/policy/heartbeat route
    /// (not `/v1/status`, unchanged -- see that handler's own comment).
    /// Item #1 (2026-08-05, "extensions point to a central Agent"): this
    /// server's `Origin`-header allow-list is real protection against a
    /// *browser-context* caller (a web page's own `fetch` can't forge that
    /// header), but it is NOT real authentication against a general caller
    /// on the same network -- headers are just text, trivially set by any
    /// non-browser HTTP client -- which only starts to matter once this
    /// server is bound to something other than 127.0.0.1
    /// (`SAFEPROMPT_LOCAL_API_BIND_ADDR`) so that *other* machines'
    /// extensions can reach it. Omitting this call (every existing
    /// 127.0.0.1-only install) leaves behavior completely unchanged: the
    /// Origin check alone still gates every route, exactly as before this
    /// existed.
    ///
    /// AGENT-COMM-004 (2026-08-10): checked via a signed-request scheme
    /// now, not a bare `X-SafePrompt-Shared-Secret` header match -- see
    /// `verify_signed_request`'s own doc comment for the full reasoning
    /// (replay protection matters more once this stops being a same-
    /// machine-only feature). The caller must send `X-SafePrompt-
    /// Timestamp` (Unix seconds), `X-SafePrompt-Nonce` (any unique string
    /// per request), and `X-SafePrompt-Signature`
    /// (`hex(HMAC-SHA256(secret, "{timestamp}.{nonce}"))`) -- `browser-
    /// extension/src/background.js`'s `localApiHeaders` computes all three
    /// via the Web Crypto API when a shared secret is configured.
    pub fn with_shared_secret(mut self, secret: String) -> Self {
        self.shared_secret = Some(secret);
        self
    }

    fn router(&self) -> Router {
        let state = ApiState {
            inspector: Arc::clone(&self.inspector),
            allowed_origins: Arc::new(self.allowed_origins.clone()),
            heartbeat_path: self.heartbeat_path.clone().map(Arc::new),
            extension_manual_install_marker: self.extension_manual_install_marker.clone().map(Arc::new),
            max_ai_sites: self.max_ai_sites,
            shared_secret: self.shared_secret.clone().map(Arc::new),
            nonce_cache: Arc::new(NonceCache::new()),
            rate_limiter: Arc::new(RateLimiter::new(RATE_LIMIT_MAX_REQUESTS, RATE_LIMIT_WINDOW)),
            edition: Arc::new(self.edition.clone()),
            tenant: self.tenant.clone().map(Arc::new),
            policy_sync_active: self.policy_sync_active,
            llm_verifier: self.llm_verifier.clone(),
            audit_export: self.audit_export.clone(),
        };
        Router::new()
            .route("/v1/status", get(status))
            .route("/v1/inspect", post(inspect_request))
            .route("/v1/inspect-file", post(inspect_file_request))
            .route("/v1/inspect-response", post(inspect_response))
            .route("/v1/extension-heartbeat", post(extension_heartbeat))
            .route("/v1/policy/applications", get(policy_applications))
            // The local console -- see CONSOLE_HTML's doc comment. Deliberately
            // separate `/ui/*` endpoints rather than reusing the `/v1/*` routes
            // above: the console page's own same-origin `fetch()` calls send
            // `Origin: http://127.0.0.1:<port>`, which `request_authorized`
            // would reject outright (only `chrome-extension://...` origins are
            // allow-listed there). These stay unauthenticated on the same
            // "reaching 127.0.0.1 at all is the real boundary" basis `/v1/status`
            // already established, not a new, weaker posture.
            .route("/", get(console_page))
            .route("/ui/status", get(ui_status))
            .route("/ui/inspect", post(ui_inspect))
            .route("/ui/inspect-response", post(ui_inspect_response))
            .route("/ui/policy", get(ui_get_policy).post(ui_apply_policy))
            .route("/ui/audit/recent", get(ui_audit_recent))
            .route("/ui/audit/export", get(ui_audit_export))
            // AGENT-COMM-009 -- explicit, not relying on axum's implicit
            // 2MB default. Raised from the original 1MB (fine for a
            // prompt/response/policy document) to 25MB with AGENT-FILE-002:
            // /v1/inspect-file's base64-encoded file bytes inflate ~33%
            // over the raw file, so this now matches connect_proxy/proxy's
            // own MAX_BODY_BYTES precedent for "a real uploaded
            // file/image, comfortably bounded" rather than a text-only cap.
            .layer(DefaultBodyLimit::max(25 * 1024 * 1024))
            .with_state(state)
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        if let Some((cert_path, key_path)) = &self.tls {
            ensure_crypto_provider_installed();
            let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "failed to load TLS cert/key from {}/{}: {e}",
                        cert_path.display(),
                        key_path.display()
                    )
                })?;
            info!("SafePrompt local extension API listening on {} (TLS)", self.bind_addr);
            axum_server::bind_rustls(self.bind_addr, config)
                .serve(self.router().into_make_service())
                .await?;
        } else {
            let listener = tokio::net::TcpListener::bind(self.bind_addr).await?;
            info!("SafePrompt local extension API listening on {}", self.bind_addr);
            axum::serve(listener, self.router()).await?;
        }
        Ok(())
    }
}

fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let Some(origin) = headers.get(axum::http::header::ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    allowed.iter().any(|a| a == origin)
}

type HmacSha256 = Hmac<Sha256>;

/// AGENT-COMM-004 (2026-08-10) — how long a signed request stays acceptable
/// after it was generated, and how long a nonce is remembered to block a
/// verbatim replay within that window. 60s is generous for normal clock
/// skew between the extension's machine and the Agent (the same machine,
/// in every case today -- `with_shared_secret` only matters once
/// `SAFEPROMPT_LOCAL_API_BIND_ADDR` is a LAN address, at which point it's
/// still the same local network, not cross-region) while still closing the
/// door on a request captured once and replayed minutes/hours later.
const REPLAY_WINDOW: Duration = Duration::from_secs(60);

/// AGENT-COMM-009 -- see `RateLimiter`'s own doc comment for the reasoning
/// behind these numbers (300 requests/60s = 5/s sustained, far above any
/// legitimate single-extension traffic pattern).
const RATE_LIMIT_MAX_REQUESTS: u32 = 300;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Tracks nonces seen within `REPLAY_WINDOW` so a signature-valid request
/// can still be rejected if it's a verbatim replay of one already seen --
/// the timestamp check alone only bounds *how old* a request can be, not
/// whether it's been used before within that window. Purges stale entries
/// on every check rather than running a background sweep task -- local
/// API request volume is low enough that this is cheap, and it means no
/// extra task to manage the lifetime of.
struct NonceCache {
    seen: Mutex<HashMap<String, Instant>>,
}

impl NonceCache {
    fn new() -> Self {
        Self { seen: Mutex::new(HashMap::new()) }
    }

    /// Returns `true` (and records the nonce) the first time it's seen
    /// within the window; `false` -- a replay -- every time after.
    fn check_and_record(&self, nonce: &str) -> bool {
        let mut seen = self.seen.lock().expect("nonce cache lock poisoned");
        let now = Instant::now();
        seen.retain(|_, first_seen| now.duration_since(*first_seen) < REPLAY_WINDOW);
        if seen.contains_key(nonce) {
            false
        } else {
            seen.insert(nonce.to_string(), now);
            true
        }
    }
}

/// AGENT-COMM-009 (2026-08-10) — a coarse, in-process request budget for
/// the `/v1/*` routes. A single global fixed window, not per-caller: this
/// Agent's local_api serves a small, known set of callers (this machine's
/// own browser extension in the overwhelming majority of installs; a
/// handful of workstations sharing one Agent in the opt-in LAN/shared-
/// secret scenario), so there's no meaningful per-identity axis to key on
/// the way the Control Plane's Redis-backed limiter
/// (`backend/core/security.py::check_rate_limit`) needs for many
/// unrelated internet-facing tenants -- a very different threat model.
/// Sized generously against every real traffic pattern here (a scan per
/// prompt, a heartbeat every ~60s, a policy poll every ~15min) -- this
/// exists to bound a runaway or malicious local caller, not to throttle
/// normal use.
struct RateLimiter {
    window: Mutex<(Instant, u32)>,
    max_requests: u32,
    window_duration: Duration,
}

impl RateLimiter {
    fn new(max_requests: u32, window_duration: Duration) -> Self {
        Self { window: Mutex::new((Instant::now(), 0)), max_requests, window_duration }
    }

    /// `true` if this request is within budget (and counts it against the
    /// current window); `false` if the window's budget is already spent.
    fn allow(&self) -> bool {
        let mut window = self.window.lock().expect("rate limiter lock poisoned");
        let (window_start, count) = &mut *window;
        let now = Instant::now();
        if now.duration_since(*window_start) >= self.window_duration {
            *window_start = now;
            *count = 0;
        }
        if *count >= self.max_requests {
            false
        } else {
            *count += 1;
            true
        }
    }
}

fn compute_signature(secret: &str, timestamp: &str, nonce: &str) -> String {
    // HMAC accepts any key length (it hashes down a too-long key, pads a
    // too-short one) -- `new_from_slice` only fails for algorithms with a
    // fixed key size, which SHA-256-based HMAC isn't.
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(nonce.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Not `==` -- an early-exit string/slice comparison leaks how many
/// leading bytes matched via response timing, which matters for something
/// an attacker could otherwise brute-force byte-by-byte. Every byte is
/// compared regardless of earlier mismatches.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// The signed-request scheme `with_shared_secret` upgraded to (AGENT-COMM-
/// 004, 2026-08-10) -- signature over `{timestamp}.{nonce}`, not the raw
/// secret sent in cleartext (the old scheme, replaced rather than kept as
/// a fallback: keeping both would let a captured plaintext-secret request
/// bypass replay protection entirely by just using the old header instead
/// of the new ones). Requires all three headers; missing any one fails
/// closed rather than falling back to "unauthenticated."
fn verify_signed_request(headers: &HeaderMap, secret: &str, nonce_cache: &NonceCache) -> bool {
    let header_str = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let (Some(timestamp_str), Some(nonce), Some(presented_signature)) =
        (header_str("X-SafePrompt-Timestamp"), header_str("X-SafePrompt-Nonce"), header_str("X-SafePrompt-Signature"))
    else {
        return false;
    };

    let Ok(timestamp) = timestamp_str.parse::<i64>() else { return false };
    let now = chrono::Utc::now().timestamp();
    if (now - timestamp).abs() > REPLAY_WINDOW.as_secs() as i64 {
        return false; // too old (or clock skew too large) either way
    }

    let expected_signature = compute_signature(secret, timestamp_str, nonce);
    if !constant_time_eq(expected_signature.as_bytes(), presented_signature.as_bytes()) {
        return false;
    }

    // Signature alone doesn't stop a verbatim replay within the window --
    // that's what the nonce check is for, checked last since it's the one
    // check with a side effect (recording the nonce), and only worth
    // paying for once the request has already proven it knows the secret.
    nonce_cache.check_and_record(nonce)
}

/// The Origin allow-list, plus (when configured) a signed-request check --
/// see `with_shared_secret`'s doc comment for why both checks stay
/// layered rather than one replacing the other, and `verify_signed_request`
/// for the signature scheme itself. Every route below except `/v1/status`
/// goes through this instead of calling `origin_allowed` directly.
fn request_authorized(headers: &HeaderMap, state: &ApiState) -> bool {
    if !origin_allowed(headers, &state.allowed_origins) {
        return false;
    }
    match &state.shared_secret {
        None => true,
        Some(expected) => verify_signed_request(headers, expected, &state.nonce_cache),
    }
}

/// Deliberately includes `edition` here (not just on `/ui/status`) --
/// display-only, same "not a security boundary" posture as
/// `with_console_info`'s doc comment, and the popup added to
/// browser-extension/ needs a plan label ("Community"/"Professional"/
/// "Business"/"Enterprise") to show the user without introducing a second
/// authenticated round-trip just for that. `tenant` is deliberately left
/// off this route (unlike `/ui/status`): a tenant name is closer to
/// identifying information than a plan tier, and the console page it's
/// shown on is already same-origin/local-only, whereas this route stays
/// reachable pre-auth by design.
async fn status(State(state): State<ApiState>) -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "edition": state.edition.as_str() }))
}

/// AGENT-FILE-003 (2026-08-11): redact-first-verify. Only ever called with
/// a `scan` that's already `Action::Allow` -- if local detection found
/// anything at all, that's already the answer, and this never gets a
/// chance to see whatever text local detection redacted/blocked (see
/// `safeprompt-llm-verify`'s own doc comment for exactly why that
/// ordering is the entire point). A no-op when `verifier` is `None` --
/// every existing caller/behavior is unchanged unless a tenant has both
/// the license feature and an explicit endpoint configured.
async fn apply_llm_verify(
    mut scan: ScanResult,
    original_text: &str,
    verifier: &Option<Arc<dyn LlmVerifier>>,
    upgrade_redact_to_block: bool,
) -> ScanResult {
    let Some(verifier) = verifier else { return scan };
    if scan.action != Action::Allow {
        return scan;
    }
    let findings = verifier.verify(original_text).await;
    if findings.is_empty() {
        return scan;
    }

    let mut sanitized = original_text.to_string();
    for f in &findings {
        if let Some(replacement) = &f.redacted_replacement {
            sanitized = sanitized.replace(&f.snippet, replacement);
        }
    }
    scan.action = if upgrade_redact_to_block { Action::Block } else { Action::Redact };
    scan.findings = findings;
    scan.original_prompt = original_text.to_string();
    scan.sanitized_prompt = sanitized;
    scan
}

/// Persists one extension-driven scan decision to the local Audit Pipeline
/// -- the counterpart to `connect_proxy`'s own `persist_event` for the
/// domains that go through the CONNECT proxy's MITM path instead. Found
/// missing 2026-09-03: `/v1/inspect`, `/v1/inspect-file` and
/// `/v1/inspect-response` are what the shipped `browser-extension/` calls
/// for *every* scan (the CONNECT proxy MITMs nothing by default -- see this
/// file's own top-of-file doc comment), so until this call existed, no
/// event from the extension's normal operation ever reached
/// `LocalDatabase::save_event` at all. That silently broke two downstream
/// consumers that both read the exact same table: the local console's
/// History tab (`/ui/audit/recent`) and `init_audit_relay`'s agent-to-SPOC-
/// to-cloud forwarder (see that function's own doc comment) -- which is why
/// the SaaS Activity dashboard went quiet too, not just the local one; both
/// were downstream of a table nothing was writing into.
///
/// `domain` is the best identifier each call site actually has -- the AI
/// site for `/v1/inspect`/`/v1/inspect-response` (not yet threaded through
/// from `background.js`, so "unknown" like the CONNECT-proxy path's own
/// `app_name` until that's wired up), the filename for `/v1/inspect-file`
/// (more useful than "unknown" and costs nothing since it's already in
/// hand). No-op when local audit persistence isn't configured for this
/// install (`with_audit_export` never called, e.g. the encryption secret
/// failed to resolve) -- same fail-open posture as `persist_event`, a sink
/// failure never blocks the scan result already computed.
async fn persist_inspect_event(state: &ApiState, event_type: &str, domain: &str, scan: &ScanResult) {
    let Some(export) = &state.audit_export else {
        return;
    };

    let event = safeprompt_common::DlpEvent {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        event_type: event_type.to_string(),
        action_taken: scan.action.clone(),
        app_name: "unknown".to_string(), // process attribution not implemented yet, matches connect_proxy::persist_event
        domain: domain.to_string(),
        user_identity: "unknown".to_string(), // Identity/RBAC not implemented yet
        findings: scan.findings.clone(),
    };

    if let Err(e) = export.storage.save_event(&export.tenant_id, &event).await {
        warn!("local API: failed to persist audit event for '{event_type}': {e}");
    }
}

async fn inspect_request(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<InspectRequest>,
) -> Result<Json<ScanResult>, StatusCode> {
    if !request_authorized(&headers, &state) {
        warn!("local API: rejected /v1/inspect from an unrecognized or missing Origin");
        return Err(StatusCode::FORBIDDEN);
    }
    if !state.rate_limiter.allow() {
        warn!("local API: rate limit exceeded on /v1/inspect");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let scan = state.inspector.inspect(&req.text);
    let scan = apply_llm_verify(scan, &req.text, &state.llm_verifier, false).await;
    persist_inspect_event(&state, "request", req.domain.as_deref().unwrap_or("unknown"), &scan).await;
    Ok(Json(scan))
}

/// AGENT-FILE-002: closes the real gap found 2026-08-11 -- a file/image the
/// user attaches directly in the ChatGPT/Claude web UI never went through
/// either the extension (no file-handling code existed before this) or the
/// CONNECT-proxy (never intercepts those domains at all, see
/// `connect_proxy::sni_gate`'s doc comment) -- so it reached the AI
/// provider completely unscanned regardless of plan. Same extract-then-OCR-
/// then-scan pipeline `connect_proxy::server::scan_multipart_request`
/// already uses for the domains it *does* MITM, same "Redact upgrades to
/// Block" reasoning (no safe way to splice sanitized text back into a
/// binary file), same policy-driven `upload_action()` pre-check, same
/// fail-open posture for a file type `safeprompt-file-inspector` can't
/// parse. OCR extraction specifically still respects the license's `ocr`
/// feature via `Inspector::ocr_engine()` returning `None` when absent --
/// unrelated to this endpoint's own auth, which is unconditional like every
/// other `/v1/*` scan route.
async fn inspect_file_request(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<InspectFileRequest>,
) -> Result<Json<ScanResult>, StatusCode> {
    if !request_authorized(&headers, &state) {
        warn!("local API: rejected /v1/inspect-file from an unrecognized or missing Origin");
        return Err(StatusCode::FORBIDDEN);
    }
    if !state.rate_limiter.allow() {
        warn!("local API: rate limit exceeded on /v1/inspect-file");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // 2026-09-03: fold the real AI site in alongside the filename when
    // it's known -- both are useful for a file upload (which site AND
    // which file), and DlpEvent only has one "domain" column
    // (`app_name` stays "unknown", same as every other call site --
    // process attribution isn't implemented yet). Falls back to just the
    // filename, matching the only thing this event label carried before
    // `domain` existed at all.
    let event_label = match &req.domain {
        Some(domain) if !domain.is_empty() => format!("{domain} ({})", req.filename),
        _ => req.filename.clone(),
    };

    let extension = req.filename.rsplit('.').next().unwrap_or("");
    match state.inspector.upload_action(extension) {
        safeprompt_policy::UploadAction::Block => {
            warn!("upload '{}' blocked by policy for extension '.{extension}'", req.filename);
            let scan = blocked_file_result();
            persist_inspect_event(&state, "file", &event_label, &scan).await;
            return Ok(Json(scan));
        }
        safeprompt_policy::UploadAction::Allow => {
            info!("upload '{}' allowed unscanned per policy for extension '.{extension}'", req.filename);
            let scan = allowed_file_result();
            persist_inspect_event(&state, "file", &event_label, &scan).await;
            return Ok(Json(scan));
        }
        safeprompt_policy::UploadAction::Inspect => {}
    }

    let file_bytes = match BASE64.decode(&req.data_base64) {
        Ok(b) => b,
        Err(e) => {
            warn!("inspect-file: invalid base64 payload for '{}': {e}", req.filename);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let text = match safeprompt_file_inspector::extract_text(&req.filename, &file_bytes, state.inspector.ocr_engine()) {
        safeprompt_file_inspector::ExtractionOutcome::Text(t) => t,
        safeprompt_file_inspector::ExtractionOutcome::Unsupported { filename, reason } => {
            warn!("inspect-file: '{filename}' could not be scanned ({reason}) — allowed through unscanned");
            let scan = allowed_file_result();
            persist_inspect_event(&state, "file", &event_label, &scan).await;
            return Ok(Json(scan));
        }
    };

    let mut scan = state.inspector.inspect(&text);
    if scan.action == Action::Redact {
        if is_text_redactable_extension(extension) {
            // `scan.sanitized_prompt` is already the masked plain text --
            // for these formats that IS a valid replacement for the
            // file's own bytes (a .txt/.csv/.md/.json file's content *is*
            // its plain-text extraction, nothing lost round-tripping it
            // back), so the Redact verdict stands and the caller
            // (background.js/main-world-interceptor.js) substitutes the
            // upload's bytes with `sanitized_prompt` re-encoded as UTF-8,
            // the same way it already substitutes a redacted chat message.
        } else {
            // Anything with real internal structure (.docx/.pdf) or that
            // isn't text at all (images) can't be safely masked in place --
            // apply the admin-configured fallback instead of a hardcoded
            // Block, and say why so the caller can show a clear message
            // rather than one that looks like it ignored "Mask it".
            let mut fallback = state.inspector.current_policy().security.unmaskable_file_action.enforcement_action();
            // `unmaskable_file_action` is admin-configurable, and nothing
            // stops someone from setting it to Redact itself -- which
            // would defeat the entire point of this branch: we're here
            // specifically because `sanitized_prompt` for this format is
            // NOT a safe file replacement (a lossy structural extraction,
            // not the file's real bytes). Force Block instead of letting
            // a misconfigured policy round-trip back into the exact
            // corruption this code exists to prevent.
            if fallback == Action::Redact {
                fallback = Action::Block;
            }
            scan.unmaskable_reason = Some(format!(
                "'.{extension}' files can't be masked in place, so the policy's unmaskable-file fallback ({fallback:?}) was applied to this upload instead of Mask it."
            ));
            scan.action = fallback;
        }
    }
    let scan = apply_llm_verify(scan, &text, &state.llm_verifier, true).await;
    persist_inspect_event(&state, "file", &event_label, &scan).await;
    Ok(Json(scan))
}

/// Plain-text formats where `Inspector::inspect`'s `sanitized_prompt`
/// (the masked text) is itself a safe, complete replacement for the
/// file's own bytes -- these formats' entire content already *is* what
/// `safeprompt_file_inspector::extract_text` returns (a lossless read, not
/// a structural extraction), so nothing is lost re-encoding the masked
/// text as UTF-8 bytes. Deliberately kept in exact sync with
/// `extract_text`'s own plain-text dispatch list (see that function) --
/// every extension it treats as "just decode the bytes as text" belongs
/// here too, for the same reason. A `.docx`/`.pdf`, by contrast, has real
/// internal structure (styles, layout, embedded objects) `extract_text`
/// throws away to get plain text out, so writing that plain text back as
/// the file wouldn't just mask the secret, it would silently destroy the
/// rest of the document. Images aren't text at all. Both of those instead
/// fall back to `SecurityPolicy::unmaskable_file_action` (see
/// `inspect_file_request`).
fn is_text_redactable_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "txt" | "md" | "csv" | "json" | "log" | "yaml" | "yml" | "xml" | "html" | "htm"
    )
}

/// `background.js` pings this on a `chrome.alarms` timer (default ~60s —
/// MV3 service workers get suspended between events, so a plain
/// `setInterval` in the extension wouldn't reliably keep firing). apps/
/// watchdog reads the file this writes back out and folds "was the
/// extension seen recently" into status.json/DeviceHealth — see
/// `with_heartbeat_path`'s doc comment for why a file, not IPC. Origin-
/// checked the same as the scan endpoints: an unrecognized caller
/// shouldn't be able to make the tray/fleet report "extension healthy"
/// for an extension that was never actually installed.
/// Profile-based license segregation (2026-09-01): `profile_id` is
/// `background.js`'s `getProfileId()` -- a `crypto.randomUUID()` cached in
/// that Chrome/Edge profile's own isolated `chrome.storage.local`. A
/// machine-wide `ExtensionInstallForcelist` policy installs this extension
/// into every profile on a machine, but until now the Agent had no way to
/// tell those profiles apart -- `backend/models/device.py`'s
/// `device_fingerprint` hashes browser/OS/screen attributes that are
/// identical across every profile on the same machine, so two profiles
/// collapsed into one identity. Plain `Bytes`, not `Json<...>`: an older
/// extension build (or a body lost to a transient error) sends an empty
/// POST body, which a required `Json<T>` extractor would reject outright
/// with a 400 before this handler ever runs -- best-effort parsing here
/// keeps the existing bare-heartbeat behavior working during a staged
/// rollout instead of breaking it.
#[derive(Deserialize, Default)]
struct ExtensionHeartbeatRequest {
    #[serde(default)]
    profile_id: Option<String>,
}

async fn extension_heartbeat(State(state): State<ApiState>, headers: HeaderMap, body: Bytes) -> StatusCode {
    if !request_authorized(&headers, &state) {
        warn!("local API: rejected /v1/extension-heartbeat from an unrecognized or missing Origin");
        return StatusCode::FORBIDDEN;
    }
    if !state.rate_limiter.allow() {
        warn!("local API: rate limit exceeded on /v1/extension-heartbeat");
        return StatusCode::TOO_MANY_REQUESTS;
    }
    let Some(path) = &state.heartbeat_path else {
        return StatusCode::NOT_FOUND;
    };
    let profile_id = serde_json::from_slice::<ExtensionHeartbeatRequest>(&body)
        .ok()
        .and_then(|r| r.profile_id)
        .filter(|s| !s.is_empty());
    let now = chrono::Utc::now().to_rfc3339();

    // Read-modify-write, not overwrite: multiple profiles on this machine
    // each send their own heartbeat independently, so clobbering the whole
    // file on every tick would leave only the most-recently-seen profile
    // visible. Best-effort read -- a missing/corrupt file just starts a
    // fresh map, same "never fail the caller over this" posture as the
    // write below.
    let mut profiles: serde_json::Map<String, serde_json::Value> = std::fs::read_to_string(path.as_path())
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|v| v.get("profiles").cloned())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();
    if let Some(id) = &profile_id {
        profiles.insert(id.clone(), serde_json::json!(now));
    }

    // Top-level "last_seen" stays a bare string -- apps/watchdog's
    // read_extension_detected() parses exactly that field and must keep
    // working unchanged. "profiles" is new, additive.
    let body = serde_json::json!({ "last_seen": now, "profiles": profiles });
    // Best-effort: a write failure here (e.g. ProgramData briefly locked)
    // must not surface as an error to the extension -- there's nothing
    // useful it could do in response, and background.js's own fail-open
    // posture already means a heartbeat failure never blocks scanning.
    if let Err(e) = std::fs::write(path.as_path(), body.to_string()) {
        warn!("failed to write extension heartbeat file at {}: {e}", path.display());
    }
    StatusCode::NO_CONTENT
}

async fn inspect_response(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Json(req): Json<InspectRequest>,
) -> Result<Json<ScanResult>, StatusCode> {
    if !request_authorized(&headers, &state) {
        warn!("local API: rejected /v1/inspect-response from an unrecognized or missing Origin");
        return Err(StatusCode::FORBIDDEN);
    }
    if !state.rate_limiter.allow() {
        warn!("local API: rate limit exceeded on /v1/inspect-response");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let scan = state.inspector.inspect_response(&req.text);
    persist_inspect_event(&state, "response", req.domain.as_deref().unwrap_or("unknown"), &scan).await;
    Ok(Json(scan))
}

/// `background.js` polls this to build its dynamic site list (item #6 --
/// "any llm websites, not limited to chatgpt/gemini/claude, customize the
/// sites it's looking for"), rather than the extension's static
/// `manifest.json` `content_scripts` list being the only source of truth.
/// Domains come straight from the live policy's enabled `applications`
/// entries -- a policy-document change, not a code change, already adds a
/// new site to what this returns -- truncated to the license's
/// `max_ai_sites` cap (enforced here, agent-side, rather than trusting the
/// Control Plane's policy document to never exceed it: the same
/// defense-in-depth posture as every other license check in this codebase).
/// Origin-checked like every other endpoint here: an unrecognized caller
/// has no legitimate reason to learn which internal AI domains a tenant
/// governs.
async fn policy_applications(State(state): State<ApiState>, headers: HeaderMap) -> Result<Json<serde_json::Value>, StatusCode> {
    if !request_authorized(&headers, &state) {
        warn!("local API: rejected /v1/policy/applications from an unrecognized or missing Origin");
        return Err(StatusCode::FORBIDDEN);
    }
    if !state.rate_limiter.allow() {
        warn!("local API: rate limit exceeded on /v1/policy/applications");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let mut domains = state.inspector.enabled_application_domains();
    if let Some(cap) = state.max_ai_sites {
        domains.truncate(cap as usize);
    }
    Ok(Json(serde_json::json!({ "domains": domains })))
}

/// Serves the local console page itself -- no auth, same reasoning as
/// `/v1/status`: a page that just *displays* a login-free local tool isn't
/// the thing worth protecting; the `/ui/*` data endpoints it calls are the
/// ones that matter, and they're unauthenticated for the same "127.0.0.1 is
/// the boundary" reason, not because this route made them safe.
async fn console_page() -> impl IntoResponse {
    Html(CONSOLE_HTML)
}

async fn ui_status(State(state): State<ApiState>) -> Json<serde_json::Value> {
    let policy = state.inspector.current_policy();
    // ONB-008/SP-CONF-003: persistent, queryable-any-time provenance --
    // not just the one-shot `warning` string POST /ui/policy's own
    // response carries. A console UI can poll this to show "you have an
    // unsynced local override" indefinitely, not just at the moment of
    // the edit.
    let provenance = state.inspector.policy_provenance();
    let extension_manual_install_needed = state
        .extension_manual_install_marker
        .as_deref()
        .is_some_and(|p| p.exists());
    // Profile-based license segregation (2026-09-01): surfaces every
    // distinct chrome.storage.local profile_id extension_heartbeat has seen
    // recently, so a customer on this machine can see "2 browser profiles
    // detected" -- read fresh per request, same "small local file, no
    // reason to cache and risk a stale view" posture as
    // extension_manual_install_marker above. Community/Professional have no
    // backend fleet checkin to forward this to yet (see that endpoint's own
    // doc comment on why Fleet Management is Business+ only); this is
    // purely local visibility until that's built.
    let heartbeat_value = state
        .heartbeat_path
        .as_deref()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok());
    let extension_profiles = heartbeat_value
        .as_ref()
        .and_then(|v| v.get("profiles").cloned())
        .unwrap_or_else(|| serde_json::json!({}));
    // Same freshness window apps/watchdog's `read_extension_detected` uses
    // (2.5x background.js's ~60s heartbeat) -- so the console's "Browser
    // Extension" tab and the tray tooltip never disagree about whether the
    // extension is live. A missing/old/unparseable file is just "not
    // detected," not an error.
    let extension_detected = heartbeat_value
        .as_ref()
        .and_then(|v| v.get("last_seen").and_then(|s| s.as_str()))
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .is_some_and(|seen| {
            chrono::Utc::now().signed_duration_since(seen.with_timezone(&chrono::Utc))
                < chrono::Duration::seconds(150)
        });
    Json(serde_json::json!({
        "edition": state.edition.as_str(),
        "tenant": state.tenant.as_deref(),
        "applications_count": policy.applications.len(),
        "custom_keywords_count": policy.custom_keywords.len(),
        "max_ai_sites": state.max_ai_sites,
        "policy_sync_active": state.policy_sync_active,
        "policy_source": provenance.source,
        "policy_version": provenance.version,
        "policy_local_override": provenance.local_override,
        "extension_manual_install_needed": extension_manual_install_needed,
        "extension_detected": extension_detected,
        "extension_profiles": extension_profiles,
    }))
}

async fn ui_inspect(State(state): State<ApiState>, Json(req): Json<InspectRequest>) -> Json<ScanResult> {
    Json(state.inspector.inspect(&req.text))
}

async fn ui_inspect_response(State(state): State<ApiState>, Json(req): Json<InspectRequest>) -> Json<ScanResult> {
    Json(state.inspector.inspect_response(&req.text))
}

async fn ui_get_policy(State(state): State<ApiState>) -> Json<PolicyConfig> {
    Json(state.inspector.current_policy())
}

#[derive(Deserialize)]
struct AuditExportQuery {
    /// `json` (default), `csv`, or `signed` (`SignedAuditArchive`, see
    /// `safeprompt-storage::export_signed_archive`'s doc comment).
    #[serde(default = "default_export_format")]
    format: String,
    /// How many days back to include -- 30 by default, matching
    /// `license-tool audit-export`'s own default so behavior is at least
    /// consistent between the two callers of the same query.
    #[serde(default = "default_export_days")]
    days: i64,
}
fn default_export_format() -> String {
    "json".to_string()
}
fn default_export_days() -> i64 {
    30
}

#[derive(Deserialize)]
struct AuditRecentQuery {
    /// Page size, capped at 200 -- this is a "glance at what just
    /// happened" view for the local console, not the bulk export path
    /// (`/ui/audit/export`).
    #[serde(default = "default_recent_limit")]
    limit: usize,
    #[serde(default = "default_recent_days")]
    days: i64,
    /// 2026-09-03: pagination -- how many (already filtered, newest-first)
    /// events to skip before taking `limit`. In-memory skip/take, same as
    /// `limit` always was -- proportionate to what this endpoint already
    /// is (a single device's own local log, not a cloud-scale query), not
    /// a real cursor/offset at the storage layer.
    #[serde(default)]
    offset: usize,
    /// Exact match against the `Action` debug name (`"Block"`, `"Redact"`,
    /// `"Allow"`, `"Warn"`, `"Audit"`, `"RequireApproval"`) -- same
    /// strings `/ui/audit/recent`'s own JSON already renders, so the
    /// console can feed a selected option straight back without an
    /// extra translation table on either side.
    #[serde(default)]
    action: Option<String>,
    /// Case-insensitive substring match against the event's `domain`
    /// field (the AI site, or `"<site> (<filename>)"` for a file upload
    /// -- see `inspect_file_request`'s `event_label`). Substring, not
    /// exact, so filtering by "chatgpt" also catches a file-upload event
    /// on chatgpt.com without the admin needing to know the exact string
    /// this endpoint happens to compose.
    #[serde(default)]
    domain: Option<String>,
}
fn default_recent_limit() -> usize {
    50
}
fn default_recent_days() -> i64 {
    7
}

/// Recent DLP events from THIS device's own local audit database, for the
/// local console's History tab. Deliberately NOT gated on the
/// `audit_export` license feature: the events are captured on every edition
/// (see `apps/service::init_audit_storage`, unconditional by design), and
/// showing a user their own device's activity is baseline transparency, not
/// a premium capability -- the Professional+ gate stays on
/// `/ui/audit/export` (bulk download, signed archive, the SIEM-shaped
/// artifact), which is the actual monetized surface.
///
/// Returns `{"available": false, "events": []}` (200, not an error) when no
/// local audit DB is configured, so the console renders a calm empty state.
/// `snippet` is omitted from each finding on purpose -- the raw matched
/// text can be the secret itself; category/name/severity is enough to say
/// "an AWS key was redacted here" without re-surfacing it in a second
/// place. No `request_authorized` origin check -- same "127.0.0.1 is the
/// boundary" posture as every other `/ui/*` route.
async fn ui_audit_recent(State(state): State<ApiState>, Query(query): Query<AuditRecentQuery>) -> Json<serde_json::Value> {
    let Some(export) = &state.audit_export else {
        return Json(serde_json::json!({ "available": false, "events": [] }));
    };

    let until = chrono::Utc::now();
    let since = until - chrono::Duration::days(query.days.max(1));
    let events = match export.storage.query_events(&export.tenant_id, since, until).await {
        Ok(events) => events,
        Err(e) => {
            warn!("local API: /ui/audit/recent query failed: {e}");
            return Json(serde_json::json!({ "available": true, "events": [], "error": "failed to read local audit history" }));
        }
    };

    let limit = query.limit.clamp(1, 200);
    let domain_filter = query.domain.as_ref().map(|d| d.to_ascii_lowercase()).filter(|d| !d.is_empty());
    let action_filter = query.action.as_ref().filter(|a| !a.is_empty());

    // Newest-first (query_events returns oldest-first), then filter,
    // THEN paginate -- offset/limit must apply to the filtered set, not
    // the raw one, or "page 2" would silently skip matching events that
    // happened to sit behind non-matching ones in the raw window.
    let matching: Vec<&safeprompt_common::DlpEvent> = events
        .iter()
        .rev()
        .filter(|e| action_filter.map(|a| format!("{:?}", e.action_taken) == *a).unwrap_or(true))
        .filter(|e| domain_filter.as_ref().map(|d| e.domain.to_ascii_lowercase().contains(d.as_str())).unwrap_or(true))
        .collect();

    let total_matching = matching.len();
    let rows: Vec<serde_json::Value> = matching
        .into_iter()
        .skip(query.offset)
        .take(limit)
        .map(|e| {
            serde_json::json!({
                "timestamp": e.timestamp.to_rfc3339(),
                "event_type": e.event_type,
                "action": format!("{:?}", e.action_taken),
                "app": e.app_name,
                "domain": e.domain,
                "findings": e.findings.iter().map(|f| serde_json::json!({
                    "category": format!("{:?}", f.category),
                    "match_name": f.match_name,
                    "severity": f.severity,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    Json(serde_json::json!({
        "available": true,
        "returned": rows.len(),
        "total_matching": total_matching,
        "offset": query.offset,
        "has_more": query.offset + rows.len() < total_matching,
        "window_days": query.days.max(1),
        "events": rows,
    }))
}

/// SP-AUD-004 (Professional+): lets a user download their own device's
/// audit log straight from the local console -- see
/// `LocalApiServer::with_audit_export`'s doc comment for why this route
/// exists at all (the only prior export path, `license-tool audit-export`,
/// is a binary that's deliberately never installed on a customer machine).
/// No `request_authorized` origin check -- same "127.0.0.1 is the
/// boundary" posture as every other `/ui/*` route, not a new, weaker one.
async fn ui_audit_export(State(state): State<ApiState>, Query(query): Query<AuditExportQuery>) -> impl IntoResponse {
    let Some(export) = &state.audit_export else {
        return (StatusCode::NOT_FOUND, "audit export is unavailable: no local audit database is configured on this Agent").into_response();
    };
    if !export.licensed {
        return (StatusCode::FORBIDDEN, "audit export requires a Professional (or higher) license").into_response();
    }

    let until = chrono::Utc::now();
    let since = until - chrono::Duration::days(query.days.max(1));
    let events = match export.storage.query_events(&export.tenant_id, since, until).await {
        Ok(events) => events,
        Err(e) => {
            warn!("local API: audit export query failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "failed to read audit events").into_response();
        }
    };

    let (content_type, extension, body) = match query.format.as_str() {
        "csv" => ("text/csv", "csv", safeprompt_storage::export_csv(&events)),
        "signed" => match safeprompt_storage::export_signed_archive(&events, &export.encryption_secret) {
            Ok(archive) => ("application/json", "signed.json", archive),
            Err(e) => {
                warn!("local API: signed audit archive export failed: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "failed to build signed audit archive").into_response();
            }
        },
        "json" => match safeprompt_storage::export_json(&events) {
            Ok(json) => ("application/json", "json", json),
            Err(e) => {
                warn!("local API: JSON audit export failed: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "failed to build JSON audit export").into_response();
            }
        },
        other => return (StatusCode::BAD_REQUEST, format!("unknown export format '{other}' (expected json|csv|signed)")).into_response(),
    };

    let filename = format!("safeprompt-audit-export.{extension}");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, content_type.to_string()), (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\""))],
        body,
    )
        .into_response()
}

/// Applies an edited policy immediately, in-memory, to *this* running
/// process -- not a signed, distributed policy document. That's a
/// deliberate scope decision, not an oversight: the Ed25519 signing dance
/// (`safeprompt-policy-sync`) exists to protect a Control-Plane-to-Agent
/// network hop this local console never crosses (the console's own request
/// already has to reach 127.0.0.1 on this exact machine). Layering a local
/// signing key on top here would add real complexity for a boundary that
/// doesn't exist in this path.
///
/// The one honest caveat: if central policy sync IS active
/// (`policy_sync_active`), its background loop polls its own source on a
/// timer and will overwrite this in-memory edit the next time it ticks --
/// flagged back to the caller as a `warning` in the response body rather
/// than left to surprise them later, rather than silently applying and
/// letting the user believe the change is durable.
async fn ui_apply_policy(State(state): State<ApiState>, Json(new_policy): Json<PolicyConfig>) -> Json<serde_json::Value> {
    // ONB-008/SP-CONF-003: apply_local_policy_edit (not update_policy) so
    // this marks local_override -- see Inspector::policy_provenance,
    // surfaced on GET /ui/status, for the persistent (not just this
    // response's one-shot `warning`) record of that.
    state.inspector.apply_local_policy_edit(new_policy);
    let mut body = serde_json::json!({ "applied": true });
    if state.policy_sync_active {
        body["warning"] = serde_json::json!(
            "Central policy sync is active on this Agent. This change is in-memory only and \
             may be overwritten the next time a signed policy is synced from its configured source."
        );
    }
    Json(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use safeprompt_policy::{ApplicationPolicy, PolicyConfig};

    const TEST_ORIGIN: &str = "chrome-extension://testextensionid0000000000000000";

    async fn spawn_test_server() -> SocketAddr {
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    /// Test-only `LlmVerifier`: since the real HTTP-calling implementation
    /// (`safeprompt-llm-verify::HttpLlmVerifier`) moved to the private
    /// `agent-enterprise/` workspace (2026-08-27, open-core Phase 2), this
    /// crate can no longer depend on it even in tests -- this crate's job
    /// is only to prove `apply_llm_verify`'s ordering/wiring is correct
    /// (called only when local scanning found nothing, findings correctly
    /// merged into the response), not to re-prove the real crate's own
    /// HTTP/provider-translation correctness (that end-to-end coverage,
    /// including a real mock HTTP upstream, moved to
    /// `agent-enterprise/crates/llm_verify`'s own integration tests).
    struct MockLlmVerifier {
        findings: Vec<safeprompt_common::Finding>,
    }

    #[async_trait::async_trait]
    impl LlmVerifier for MockLlmVerifier {
        async fn verify(&self, _text: &str) -> Vec<safeprompt_common::Finding> {
            self.findings.clone()
        }
    }

    /// AGENT-FILE-003: same as `spawn_test_server`, wired with a verifier
    /// that always returns `findings` regardless of input -- proves
    /// `apply_llm_verify`'s wiring/ordering, not the real crate's own HTTP
    /// call (see `MockLlmVerifier`'s own doc comment for where that moved).
    async fn spawn_test_server_with_llm_verify(findings: Vec<safeprompt_common::Finding>) -> SocketAddr {
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_llm_verifier(Arc::new(MockLlmVerifier { findings }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn llm_verify_flags_something_local_scanning_alone_misses() {
        let findings = vec![safeprompt_common::Finding {
            category: safeprompt_common::FindingCategory::Pii,
            match_name: "LLM_VERIFY_PII".to_string(),
            snippet: "Rajesh Kumar".to_string(),
            severity: "HIGH".to_string(),
            redacted_replacement: Some("[REDACTED_PII]".to_string()),
        }];
        let addr = spawn_test_server_with_llm_verify(findings).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "contact Rajesh Kumar about this" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let result: ScanResult = resp.json().await.unwrap();
        assert_eq!(result.action, safeprompt_common::Action::Redact, "the verify pass caught what local scanning alone would have let through");
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].match_name, "LLM_VERIFY_PII");
        assert!(result.sanitized_prompt.contains("[REDACTED_PII]"));
    }

    #[tokio::test]
    async fn llm_verify_never_runs_when_local_scanning_already_found_something() {
        // The mock upstream would flag ANYTHING it's asked about (see its
        // fixed verdict_body) -- if this test's AWS key comes back as a
        // plain local-detection Redact (not something the mock's PII
        // category would produce), that proves the verify pass was never
        // even called, which is the whole point of the ordering.
        let findings = vec![safeprompt_common::Finding {
            category: safeprompt_common::FindingCategory::Pii,
            match_name: "LLM_VERIFY_PII".to_string(),
            snippet: "anything".to_string(),
            severity: "HIGH".to_string(),
            redacted_replacement: Some("[REDACTED_PII]".to_string()),
        }];
        let addr = spawn_test_server_with_llm_verify(findings).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "my key is AKIAIOSFODNN7EXAMPLE" }))
            .send()
            .await
            .unwrap();
        let result: ScanResult = resp.json().await.unwrap();
        assert_eq!(result.action, safeprompt_common::Action::Redact);
        assert_eq!(result.findings[0].category, safeprompt_common::FindingCategory::Secret, "must be the real local AWS-key finding, not the mock LLM's fixed PII verdict");
        assert!(!result.findings.iter().any(|f| f.match_name.starts_with("LLM_VERIFY")));
    }

    #[tokio::test]
    async fn llm_verify_is_a_no_op_when_not_configured() {
        // spawn_test_server (no llm_verify_config at all) -- proves every
        // existing behavior is completely unchanged for the common case.
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "an entirely ordinary sentence" }))
            .send()
            .await
            .unwrap();
        let result: ScanResult = resp.json().await.unwrap();
        assert_eq!(result.action, safeprompt_common::Action::Allow);
        assert!(result.findings.is_empty());
    }

    #[tokio::test]
    async fn rejects_a_request_with_no_origin_header() {
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .json(&serde_json::json!({ "text": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn rejects_a_request_from_an_unrecognized_origin() {
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", "chrome-extension://some-other-extension")
            .json(&serde_json::json!({ "text": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn allows_and_scans_a_request_from_the_allow_listed_origin() {
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "my key is AKIAIOSFODNN7EXAMPLE" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let result: ScanResult = resp.json().await.unwrap();
        // Changed 2026-08-05: Secret now masks by default rather than
        // blocking the whole message.
        assert_eq!(result.action, safeprompt_common::Action::Redact);
        assert!(!result.findings.is_empty());
    }

    #[tokio::test]
    async fn inspect_file_masks_a_secret_found_in_a_plain_text_file() {
        // AGENT-FILE-002 regression: a .txt file needs no OCR to prove the
        // extract-then-scan wiring is correct end to end -- OCR-specific
        // extraction is covered by safeprompt-file-inspector's own tests.
        //
        // 2026-09-03: this used to assert Block -- every Redact verdict on
        // a file used to be unconditionally upgraded to Block, with no way
        // to configure otherwise. Real user report: "i defined mask it, it
        // works block" -- a .txt is one of the formats
        // `is_text_redactable_extension` now actually masks in place
        // (`sanitized_prompt` round-trips losslessly for plain text), so
        // the configured "Mask it" (Redact) action is honored for real now.
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        let data_base64 = BASE64.encode("here is my key AKIAIOSFODNN7EXAMPLE");
        let resp = client
            .post(format!("http://{addr}/v1/inspect-file"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "filename": "secret.txt", "data_base64": data_base64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let result: ScanResult = resp.json().await.unwrap();
        assert_eq!(result.action, safeprompt_common::Action::Redact);
        assert!(!result.sanitized_prompt.contains("AKIAIOSFODNN7EXAMPLE"), "the key should be masked out of the sanitized text");
        assert!(result.unmaskable_reason.is_none(), "a genuinely maskable format shouldn't carry an 'unmaskable' explanation");
    }

    #[tokio::test]
    async fn inspect_file_falls_back_to_block_for_a_secret_in_an_unmaskable_format() {
        // .rtf goes through anydoc's structural extraction (see
        // file_inspector::extract_text), so writing the plain-text
        // extraction back as "the file" would destroy the RTF formatting
        // -- not in `is_text_redactable_extension`'s list. Default
        // `unmaskable_file_action` is Block, so this is what the actual
        // user report's "it works block" behavior should still look like
        // for a format where masking genuinely isn't safe -- but now WITH
        // a clear explanation instead of a bare, confusing Block.
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        let rtf = br"{\rtf1\ansi\deff0 here is my key AKIAIOSFODNN7EXAMPLE\par}";
        let data_base64 = BASE64.encode(rtf);
        let resp = client
            .post(format!("http://{addr}/v1/inspect-file"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "filename": "secret.rtf", "data_base64": data_base64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let result: ScanResult = resp.json().await.unwrap();
        assert_eq!(result.action, safeprompt_common::Action::Block);
        let reason = result.unmaskable_reason.expect("should explain why Mask it wasn't honored");
        assert!(reason.contains("rtf"), "the explanation should name the actual file extension: {reason}");
    }

    #[tokio::test]
    async fn inspect_file_respects_a_configured_unmaskable_file_action() {
        // An admin can choose Warn instead of the Block default for
        // formats that can't be masked -- proves the policy's
        // `unmaskable_file_action` is actually consulted, not just the
        // hardcoded default.
        use safeprompt_policy::PolicyConfig;
        let mut policy = PolicyConfig::default();
        policy.security.unmaskable_file_action = Action::Warn;
        let inspector = Arc::new(Inspector::new(policy));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });

        let client = reqwest::Client::new();
        let rtf = br"{\rtf1\ansi\deff0 here is my key AKIAIOSFODNN7EXAMPLE\par}";
        let resp = client
            .post(format!("http://{addr}/v1/inspect-file"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "filename": "secret.rtf", "data_base64": BASE64.encode(rtf) }))
            .send()
            .await
            .unwrap();
        let result: ScanResult = resp.json().await.unwrap();
        assert_eq!(result.action, safeprompt_common::Action::Warn);
        assert!(result.unmaskable_reason.is_some());
    }

    #[tokio::test]
    async fn inspect_file_never_lets_unmaskable_file_action_resolve_to_redact() {
        // Defensive: an admin configuring `unmaskable_file_action: Redact`
        // itself would defeat the entire point of the fallback -- we only
        // reach it because `sanitized_prompt` is NOT a safe byte-for-byte
        // replacement for this format. Must still resolve to Block, not
        // round-trip back into the exact corruption this feature exists
        // to prevent.
        use safeprompt_policy::PolicyConfig;
        let mut policy = PolicyConfig::default();
        policy.security.unmaskable_file_action = Action::Redact;
        let inspector = Arc::new(Inspector::new(policy));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });

        let client = reqwest::Client::new();
        let rtf = br"{\rtf1\ansi\deff0 here is my key AKIAIOSFODNN7EXAMPLE\par}";
        let resp = client
            .post(format!("http://{addr}/v1/inspect-file"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "filename": "secret.rtf", "data_base64": BASE64.encode(rtf) }))
            .send()
            .await
            .unwrap();
        let result: ScanResult = resp.json().await.unwrap();
        assert_eq!(result.action, safeprompt_common::Action::Block, "must never resolve to Redact for an unmaskable format regardless of policy config");
    }

    #[tokio::test]
    async fn inspect_file_allows_a_clean_plain_text_file() {
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        let data_base64 = BASE64.encode("just a normal agenda, nothing sensitive here");
        let resp = client
            .post(format!("http://{addr}/v1/inspect-file"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "filename": "notes.txt", "data_base64": data_base64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let result: ScanResult = resp.json().await.unwrap();
        assert_eq!(result.action, safeprompt_common::Action::Allow);
    }

    #[tokio::test]
    async fn inspect_file_needs_a_recognized_origin() {
        let addr = spawn_test_server().await;
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/v1/inspect-file"))
            .json(&serde_json::json!({ "filename": "secret.txt", "data_base64": BASE64.encode("hello") }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn status_endpoint_needs_no_origin() {
        // Deliberately unauthenticated -- lets the extension's background
        // worker sanity-check connectivity to a *running* agent before it
        // has anything sensitive to send.
        let addr = spawn_test_server().await;
        let resp = reqwest::get(format!("http://{addr}/v1/status")).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn status_endpoint_reports_edition_for_the_extension_popup() {
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_console_info("Professional".to_string(), Some("SG2 Technologies".to_string()), false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let resp = reqwest::get(format!("http://{addr}/v1/status")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["edition"], "Professional");
        // Tenant name deliberately does NOT leak through this unauthenticated
        // route -- see status()'s own doc comment.
        assert!(body.get("tenant").is_none());
    }

    async fn spawn_test_server_with_shared_secret(secret: &str) -> SocketAddr {
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_shared_secret(secret.to_string());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    /// Test-side stand-in for what `background.js`'s `localApiHeaders`
    /// computes via the Web Crypto API -- reuses the real
    /// `compute_signature` so these tests exercise the actual production
    /// signing logic, not a reimplementation of it.
    fn sign_request(secret: &str, nonce: &str) -> (String, String, String) {
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let signature = compute_signature(secret, &timestamp, nonce);
        (timestamp, nonce.to_string(), signature)
    }

    #[tokio::test]
    async fn a_correct_origin_alone_is_not_enough_once_a_shared_secret_is_configured() {
        let addr = spawn_test_server_with_shared_secret("tenant-secret").await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN) // correct Origin, but no signature headers at all
            .json(&serde_json::json!({ "text": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "Origin alone must not be sufficient once a shared secret is configured");
    }

    #[tokio::test]
    async fn rejects_a_signature_computed_with_the_wrong_secret() {
        let addr = spawn_test_server_with_shared_secret("tenant-secret").await;
        let (timestamp, nonce, wrong_signature) = sign_request("wrong-secret", "nonce-1");
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .header("X-SafePrompt-Timestamp", timestamp)
            .header("X-SafePrompt-Nonce", nonce)
            .header("X-SafePrompt-Signature", wrong_signature)
            .json(&serde_json::json!({ "text": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn accepts_a_correct_origin_and_a_correctly_signed_request_together() {
        let addr = spawn_test_server_with_shared_secret("tenant-secret").await;
        let (timestamp, nonce, signature) = sign_request("tenant-secret", "nonce-1");
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .header("X-SafePrompt-Timestamp", timestamp)
            .header("X-SafePrompt-Nonce", nonce)
            .header("X-SafePrompt-Signature", signature)
            .json(&serde_json::json!({ "text": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn a_correct_signature_does_not_bypass_the_origin_check() {
        let addr = spawn_test_server_with_shared_secret("tenant-secret").await;
        let (timestamp, nonce, signature) = sign_request("tenant-secret", "nonce-1");
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            // no Origin header at all
            .header("X-SafePrompt-Timestamp", timestamp)
            .header("X-SafePrompt-Nonce", nonce)
            .header("X-SafePrompt-Signature", signature)
            .json(&serde_json::json!({ "text": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "a correct signature must not substitute for a valid Origin");
    }

    #[tokio::test]
    async fn a_stale_timestamp_is_rejected_even_with_a_correct_signature() {
        let addr = spawn_test_server_with_shared_secret("tenant-secret").await;
        let stale_timestamp = (chrono::Utc::now().timestamp() - 3600).to_string(); // 1 hour old
        let signature = compute_signature("tenant-secret", &stale_timestamp, "nonce-1");
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .header("X-SafePrompt-Timestamp", stale_timestamp)
            .header("X-SafePrompt-Nonce", "nonce-1")
            .header("X-SafePrompt-Signature", signature)
            .json(&serde_json::json!({ "text": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403, "a well-signed but stale (outside the replay window) request must still be rejected");
    }

    #[tokio::test]
    async fn a_verbatim_replay_of_the_same_signed_request_is_rejected_the_second_time() {
        let addr = spawn_test_server_with_shared_secret("tenant-secret").await;
        let (timestamp, nonce, signature) = sign_request("tenant-secret", "nonce-replay-test");
        let client = reqwest::Client::new();

        let send = || {
            let (timestamp, nonce, signature) = (timestamp.clone(), nonce.clone(), signature.clone());
            let client = client.clone();
            let addr = addr;
            async move {
                client
                    .post(format!("http://{addr}/v1/inspect"))
                    .header("Origin", TEST_ORIGIN)
                    .header("X-SafePrompt-Timestamp", timestamp)
                    .header("X-SafePrompt-Nonce", nonce)
                    .header("X-SafePrompt-Signature", signature)
                    .json(&serde_json::json!({ "text": "hello" }))
                    .send()
                    .await
                    .unwrap()
            }
        };

        let first = send().await;
        assert_eq!(first.status(), 200, "the first use of a fresh, correctly-signed request must succeed");
        let second = send().await;
        assert_eq!(second.status(), 403, "a verbatim replay of the exact same signed request must be rejected the second time");
    }

    #[tokio::test]
    async fn a_partial_set_of_signature_headers_is_rejected() {
        // Timestamp and nonce present, signature missing -- must fail
        // closed, not fall back to some weaker check.
        let addr = spawn_test_server_with_shared_secret("tenant-secret").await;
        let (timestamp, nonce, _signature) = sign_request("tenant-secret", "nonce-1");
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .header("X-SafePrompt-Timestamp", timestamp)
            .header("X-SafePrompt-Nonce", nonce)
            .json(&serde_json::json!({ "text": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn status_endpoint_still_needs_no_shared_secret() {
        // The whole point of /v1/status staying unauthenticated (connectivity
        // sanity-check before anything sensitive is sent) must not regress
        // just because a shared secret is now configured for every other route.
        let addr = spawn_test_server_with_shared_secret("tenant-secret").await;
        let resp = reqwest::get(format!("http://{addr}/v1/status")).await.unwrap();
        assert_eq!(resp.status(), 200);
    }

    async fn spawn_test_server_with_heartbeat(path: std::path::PathBuf) -> SocketAddr {
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_heartbeat_path(path);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn extension_heartbeat_is_404_when_no_path_is_configured() {
        // spawn_test_server() -> LocalApiServer::new() with no
        // with_heartbeat_path() call -- callers that don't care about
        // extension health (most of this test file) shouldn't need to
        // wire up a temp file just to hit an unrelated endpoint.
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/extension-heartbeat"))
            .header("Origin", TEST_ORIGIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn extension_heartbeat_rejects_an_unrecognized_origin() {
        let dir = tempfile_dir();
        let addr = spawn_test_server_with_heartbeat(dir.join("extension-status.json")).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/extension-heartbeat"))
            .header("Origin", "chrome-extension://some-other-extension")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
        assert!(!dir.join("extension-status.json").exists(), "a rejected heartbeat must not write the file");
    }

    #[tokio::test]
    async fn extension_heartbeat_writes_a_parseable_last_seen_timestamp() {
        let dir = tempfile_dir();
        let heartbeat_path = dir.join("extension-status.json");
        let addr = spawn_test_server_with_heartbeat(heartbeat_path.clone()).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/extension-heartbeat"))
            .header("Origin", TEST_ORIGIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);

        let written = std::fs::read_to_string(&heartbeat_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&written).unwrap();
        let last_seen = value["last_seen"].as_str().expect("last_seen field should be a string");
        chrono::DateTime::parse_from_rfc3339(last_seen).expect("last_seen should be a valid RFC3339 timestamp");
    }

    #[tokio::test]
    async fn ui_status_reports_extension_detected_after_a_fresh_heartbeat() {
        // Drives the same field the console's "Browser Extension" tab and
        // the tray tooltip both read -- a real heartbeat POST must flip
        // /ui/status's `extension_detected` to true, and a server with no
        // heartbeat path wired at all must report false, not error.
        let no_hb = spawn_test_server().await;
        let body: serde_json::Value =
            reqwest::get(format!("http://{no_hb}/ui/status")).await.unwrap().json().await.unwrap();
        assert_eq!(body["extension_detected"], false, "no heartbeat path configured -> not detected");

        let dir = tempfile_dir();
        let addr = spawn_test_server_with_heartbeat(dir.join("extension-status.json")).await;
        let before: serde_json::Value =
            reqwest::get(format!("http://{addr}/ui/status")).await.unwrap().json().await.unwrap();
        assert_eq!(before["extension_detected"], false, "no heartbeat sent yet");

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/extension-heartbeat"))
            .header("Origin", TEST_ORIGIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);

        let after: serde_json::Value =
            reqwest::get(format!("http://{addr}/ui/status")).await.unwrap().json().await.unwrap();
        assert_eq!(after["extension_detected"], true, "a fresh heartbeat -> detected");
    }

    #[tokio::test]
    async fn extension_heartbeat_records_a_sent_profile_id() {
        let dir = tempfile_dir();
        let heartbeat_path = dir.join("extension-status.json");
        let addr = spawn_test_server_with_heartbeat(heartbeat_path.clone()).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/extension-heartbeat"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "profile_id": "profile-a" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);

        let written = std::fs::read_to_string(&heartbeat_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&written).unwrap();
        let profile_last_seen = value["profiles"]["profile-a"]
            .as_str()
            .expect("profile-a should have a recorded last_seen entry");
        chrono::DateTime::parse_from_rfc3339(profile_last_seen).expect("profile last_seen should be a valid RFC3339 timestamp");
    }

    #[tokio::test]
    async fn extension_heartbeat_accumulates_multiple_distinct_profiles() {
        // The real scenario this feature exists for: two Chrome profiles on
        // one machine, each independently ticking their own heartbeat --
        // must not clobber each other's entry (a naive overwrite-the-file
        // approach would only ever show whichever profile ticked last).
        let dir = tempfile_dir();
        let heartbeat_path = dir.join("extension-status.json");
        let addr = spawn_test_server_with_heartbeat(heartbeat_path.clone()).await;
        let client = reqwest::Client::new();
        for profile_id in ["profile-a", "profile-b"] {
            let resp = client
                .post(format!("http://{addr}/v1/extension-heartbeat"))
                .header("Origin", TEST_ORIGIN)
                .json(&serde_json::json!({ "profile_id": profile_id }))
                .send()
                .await
                .unwrap();
            assert_eq!(resp.status(), 204);
        }

        let written = std::fs::read_to_string(&heartbeat_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&written).unwrap();
        let profiles = value["profiles"].as_object().expect("profiles should be an object");
        assert_eq!(profiles.len(), 2, "both profiles must have their own surviving entry, got {profiles:?}");
        assert!(profiles.contains_key("profile-a"));
        assert!(profiles.contains_key("profile-b"));
    }

    #[tokio::test]
    async fn extension_heartbeat_with_no_body_still_works_and_leaves_profiles_untouched() {
        // Backward compatibility during a staged rollout: an extension build
        // older than this feature sends a bare POST with no body at all --
        // must not 400/500 just because Bytes couldn't parse as the new
        // request shape.
        let dir = tempfile_dir();
        let heartbeat_path = dir.join("extension-status.json");
        let addr = spawn_test_server_with_heartbeat(heartbeat_path.clone()).await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/extension-heartbeat"))
            .header("Origin", TEST_ORIGIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 204);

        let written = std::fs::read_to_string(&heartbeat_path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert!(value["last_seen"].is_string());
        assert_eq!(value["profiles"].as_object().expect("profiles should still be an (empty) object"), &serde_json::Map::new());
    }

    /// A fresh temp directory per test -- avoids two heartbeat tests racing
    /// on the same file path (tests run concurrently by default).
    fn tempfile_dir() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("safeprompt-local-api-test-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn uuid_like() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        format!("{}-{:?}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos(), std::thread::current().id())
    }

    fn app(id: &str, domain: &str, enabled: bool) -> ApplicationPolicy {
        ApplicationPolicy {
            id: id.to_string(),
            match_domains: vec![domain.to_string()],
            enabled,
            upload: true,
            prompt_scan: true,
            response_scan: true,
            connect_proxy: false,
        }
    }

    async fn spawn_test_server_with_applications(applications: Vec<ApplicationPolicy>, max_ai_sites: Option<u32>) -> SocketAddr {
        let inspector = Arc::new(Inspector::new(PolicyConfig { applications, ..PolicyConfig::default() }));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_max_ai_sites(max_ai_sites);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn policy_applications_rejects_an_unrecognized_origin() {
        let addr = spawn_test_server_with_applications(vec![app("chatgpt", "chatgpt.com", true)], None).await;
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{addr}/v1/policy/applications"))
            .header("Origin", "chrome-extension://some-other-extension")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 403);
    }

    #[tokio::test]
    async fn policy_applications_returns_only_enabled_domains_uncapped() {
        let addr = spawn_test_server_with_applications(
            vec![
                app("chatgpt", "chatgpt.com", true),
                app("claude", "claude.ai", true),
                app("disabled-site", "internal-llm.example.com", false),
            ],
            None,
        )
        .await;
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{addr}/v1/policy/applications"))
            .header("Origin", TEST_ORIGIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let domains: Vec<String> = body["domains"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert_eq!(domains, vec!["chatgpt.com".to_string(), "claude.ai".to_string()]);
    }

    #[tokio::test]
    async fn console_page_needs_no_origin_and_no_auth() {
        let addr = spawn_test_server().await;
        let resp = reqwest::get(format!("http://{addr}/")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        assert!(body.contains("SafePrompt Local Console"), "the embedded console page should actually be served");
    }

    #[tokio::test]
    async fn ui_inspect_needs_no_origin_and_scans_for_real() {
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/ui/inspect"))
            .json(&serde_json::json!({ "text": "my key is AKIAIOSFODNN7EXAMPLE" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let result: ScanResult = resp.json().await.unwrap();
        assert!(!result.findings.is_empty(), "the console's test tool must hit the real Inspector, not a stub");
    }

    #[tokio::test]
    async fn ui_status_reports_policy_shape_with_no_auth_required() {
        let addr = spawn_test_server_with_applications(vec![app("chatgpt", "chatgpt.com", true)], Some(3)).await;
        let resp = reqwest::get(format!("http://{addr}/ui/status")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["applications_count"], 1);
        assert_eq!(body["max_ai_sites"], 3);
    }

    #[tokio::test]
    async fn ui_status_reports_no_manual_install_needed_when_no_marker_is_configured() {
        // The plain spawn_test_server() -> LocalApiServer::new() never calls
        // with_extension_manual_install_marker at all -- same "feature just
        // isn't wired in" absence as extension_heartbeat_is_404_when_no_path_is_configured.
        let addr = spawn_test_server().await;
        let resp = reqwest::get(format!("http://{addr}/ui/status")).await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["extension_manual_install_needed"], false);
    }

    #[tokio::test]
    async fn ui_status_reflects_the_extension_manual_install_marker_file() {
        // Install-ExtensionForceInstall.ps1's real contract: the marker's
        // mere existence (empty or not) means "this machine wasn't detected
        // as managed, Chrome would reject the silent force-install" -- see
        // that script's own doc comment. Covers both states from one file
        // rather than two servers, since the check is per-request (no
        // caching to worry about) -- see with_extension_manual_install_marker's
        // own doc comment on why.
        let dir = std::env::temp_dir().join(format!("safeprompt-ext-marker-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker_path = dir.join("extension-manual-install-needed.txt");

        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_extension_manual_install_marker(marker_path.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let before: serde_json::Value = reqwest::get(format!("http://{addr}/ui/status")).await.unwrap().json().await.unwrap();
        assert_eq!(before["extension_manual_install_needed"], false, "no marker file on disk yet");

        std::fs::write(&marker_path, "2026-08-31T00:00:00Z").unwrap();
        let after: serde_json::Value = reqwest::get(format!("http://{addr}/ui/status")).await.unwrap().json().await.unwrap();
        assert_eq!(after["extension_manual_install_needed"], true, "marker file now exists");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ui_policy_round_trips_get_then_apply_then_get_again() {
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();

        let current: PolicyConfig = client.get(format!("http://{addr}/ui/policy")).send().await.unwrap().json().await.unwrap();
        assert!(current.applications.is_empty(), "a fresh default policy should start with no applications");

        let mut edited = current.clone();
        edited.applications.push(app("internal-tool", "internal-llm.example.com", true));
        let apply_resp = client.post(format!("http://{addr}/ui/policy")).json(&edited).send().await.unwrap();
        assert_eq!(apply_resp.status(), 200);
        let apply_body: serde_json::Value = apply_resp.json().await.unwrap();
        assert_eq!(apply_body["applied"], true);
        assert!(apply_body.get("warning").is_none(), "no warning expected when policy sync isn't active");

        let after: PolicyConfig = client.get(format!("http://{addr}/ui/policy")).send().await.unwrap().json().await.unwrap();
        assert_eq!(after.applications.len(), 1, "the edited policy applied via /ui/policy must actually take effect on this Agent");
    }

    #[tokio::test]
    async fn ui_apply_policy_warns_when_central_sync_is_active() {
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_console_info("Business".to_string(), Some("Acme Corp".to_string()), true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = reqwest::Client::new();
        let resp = client.post(format!("http://{addr}/ui/policy")).json(&PolicyConfig::default()).send().await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert!(body["warning"].as_str().unwrap().contains("sync"), "an active-sync warning should tell the user their edit may not stick");

        let status_resp = client.get(format!("http://{addr}/ui/status")).send().await.unwrap();
        let status: serde_json::Value = status_resp.json().await.unwrap();
        assert_eq!(status["edition"], "Business");
        assert_eq!(status["tenant"], "Acme Corp");
        assert_eq!(status["policy_sync_active"], true);
    }

    #[tokio::test]
    async fn ui_status_exposes_persistent_policy_provenance_across_the_local_central_local_lifecycle() {
        // ONB-008/SP-CONF-003: unlike the one-shot `warning` string the test
        // above checks, this must stay correct on GET /ui/status at ANY
        // later point, not just in the response to the edit itself.
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let inspector_handle = Arc::clone(&inspector);
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()]);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        let client = reqwest::Client::new();

        // Fresh Agent: never edited locally, never synced.
        let fresh: serde_json::Value = client.get(format!("http://{addr}/ui/status")).send().await.unwrap().json().await.unwrap();
        assert_eq!(fresh["policy_version"], 0);
        assert_eq!(fresh["policy_local_override"], false);

        // A local console edit, via the real HTTP endpoint.
        client.post(format!("http://{addr}/ui/policy")).json(&PolicyConfig::default()).send().await.unwrap();
        let after_local: serde_json::Value = client.get(format!("http://{addr}/ui/status")).send().await.unwrap().json().await.unwrap();
        assert_eq!(after_local["policy_source"], "local");
        assert_eq!(after_local["policy_version"], 1);
        assert_eq!(after_local["policy_local_override"], true);

        // A central sync tick (driven directly on the same Inspector, same
        // as apps/service's policy_sync loop would) supersedes it.
        inspector_handle.apply_synced_policy(PolicyConfig::default(), 99);
        let after_central: serde_json::Value = client.get(format!("http://{addr}/ui/status")).send().await.unwrap().json().await.unwrap();
        assert_eq!(after_central["policy_source"], "central");
        assert_eq!(after_central["policy_version"], 99, "the signed document's real version, not a continuation of the local counter");
        assert_eq!(after_central["policy_local_override"], false, "central sync must clear the override flag, not just overwrite the policy silently");
    }

    #[tokio::test]
    async fn policy_applications_truncates_to_the_license_cap() {
        let addr = spawn_test_server_with_applications(
            vec![
                app("chatgpt", "chatgpt.com", true),
                app("claude", "claude.ai", true),
                app("gemini", "gemini.google.com", true),
            ],
            Some(2),
        )
        .await;
        let client = reqwest::Client::new();
        let resp = client
            .get(format!("http://{addr}/v1/policy/applications"))
            .header("Origin", TEST_ORIGIN)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        let domains = body["domains"].as_array().unwrap();
        assert_eq!(domains.len(), 2, "a Community-tier cap of 2 must never let a 3rd site through");
    }

    // ── AGENT-COMM-009: request limits ──────────────────────────────────────

    #[test]
    fn rate_limiter_allows_up_to_the_configured_max_then_blocks() {
        let limiter = RateLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow(), "the 4th request within the window must be blocked");
    }

    #[test]
    fn rate_limiter_resets_once_the_window_rolls_over() {
        let limiter = RateLimiter::new(1, Duration::from_millis(20));
        assert!(limiter.allow());
        assert!(!limiter.allow(), "still within the first window");
        std::thread::sleep(Duration::from_millis(30));
        assert!(limiter.allow(), "a new window must have its own budget");
    }

    #[tokio::test]
    async fn the_real_v1_inspect_endpoint_enforces_the_configured_rate_limit() {
        // Exercises the actual production constants (RATE_LIMIT_MAX_REQUESTS/
        // _WINDOW), not a test-only smaller limit -- proves the real numbers
        // in use, not just the RateLimiter type in isolation.
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();

        let mut last_status = StatusCode::OK;
        for _ in 0..RATE_LIMIT_MAX_REQUESTS {
            let resp = client
                .post(format!("http://{addr}/v1/inspect"))
                .header("Origin", TEST_ORIGIN)
                .json(&serde_json::json!({ "text": "hello" }))
                .send()
                .await
                .unwrap();
            last_status = resp.status();
        }
        assert_eq!(last_status, StatusCode::OK, "every request up to the configured max should succeed");

        let over_budget = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "hello" }))
            .send()
            .await
            .unwrap();
        assert_eq!(over_budget.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_request_body_over_the_size_cap_is_rejected() {
        let addr = spawn_test_server().await;
        let client = reqwest::Client::new();
        // Just over the 25MB cap (AGENT-FILE-002 raised this from 1MB so
        // /v1/inspect-file's base64-inflated file bytes fit -- see the
        // DefaultBodyLimit layer's own doc comment) -- a real prompt/policy
        // document never gets remotely this large, so this is exercising
        // the cap, not a realistic payload.
        let oversized_text = "a".repeat(25 * 1024 * 1024 + 100_000);
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": oversized_text }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ── AGENT-COMM-014: Central Agent TLS ───────────────────────────────────

    #[tokio::test]
    async fn tls_termination_serves_https_using_a_provided_cert_and_key() {
        // Generates a throwaway self-signed cert/key -- production TLS
        // always loads a customer-provided pair (with_tls's own doc
        // comment: this Agent never generates certs itself); this proves
        // with_tls's loading + axum-server's rustls wiring actually serve
        // real HTTPS traffic through the real router, not where the cert
        // came from.
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "safeprompt-local-api-tls-test-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

        // A fixed, high, non-default port -- axum-server's bind_rustls
        // doesn't expose the bound address the way tokio::net::TcpListener
        // does before serving starts, so port 0 (the pattern every other
        // test in this file uses) isn't available here. High and specific
        // enough that it's very unlikely to collide with anything else
        // this test suite (or a real running Agent, default port 8847) uses.
        let addr: SocketAddr = "127.0.0.1:18943".parse().unwrap();
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let server = LocalApiServer::new(addr, inspector, vec![TEST_ORIGIN.to_string()]).with_tls(cert_path, key_path);
        tokio::spawn(async move {
            server.run().await.unwrap();
        });
        // Give the TLS listener a moment to actually start accepting --
        // unlike the plain-HTTP tests, there's no listener handle to bind
        // synchronously before spawning here (see the port-0 comment above).
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Self-signed, so the test client must skip cert validation --
        // a real central-Agent deployment uses a customer-trusted cert,
        // where a real client (the browser extension) would NOT skip this.
        let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build().unwrap();
        let resp = client
            .post(format!("https://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "AKIAIOSFODNN7EXAMPLE" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200, "a request over real HTTPS (not HTTP) must reach and be handled by the real router");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["action"], "Redact", "the real Inspector must have actually run behind the TLS termination");

        // Plain HTTP to the same port must NOT work once TLS is configured
        // -- proves this isn't silently still speaking HTTP alongside TLS.
        let http_attempt = reqwest::Client::new().post(format!("http://{addr}/v1/inspect")).header("Origin", TEST_ORIGIN).json(&serde_json::json!({ "text": "hi" })).send().await;
        assert!(http_attempt.is_err(), "plain HTTP to a TLS-configured port should fail (protocol mismatch), not silently succeed");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── SP-AUD-004: /ui/audit/export ──────────────────────────────────────

    async fn sample_audit_event(app_name: &str) -> safeprompt_common::DlpEvent {
        safeprompt_common::DlpEvent {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            event_type: "request".to_string(),
            action_taken: Action::Block,
            app_name: app_name.to_string(),
            domain: "api.openai.com".to_string(),
            user_identity: "alice@example.com".to_string(),
            findings: vec![],
        }
    }

    async fn spawn_test_server_with_audit_export(licensed: bool) -> SocketAddr {
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let storage = Arc::new(LocalDatabase::init_in_memory("test-audit-secret").await.unwrap());
        storage.save_event("test-tenant", &sample_audit_event("chrome.exe").await).await.unwrap();
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_audit_export(storage, "test-tenant".to_string(), "test-audit-secret".to_string(), licensed);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    /// Same as `spawn_test_server_with_audit_export`, but with no event
    /// pre-seeded -- for tests proving a *live* `/v1/*` scan call is what
    /// puts an event in the table, not the test fixture itself.
    async fn spawn_test_server_with_empty_audit_export() -> SocketAddr {
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let storage = Arc::new(LocalDatabase::init_in_memory("test-audit-secret").await.unwrap());
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_audit_export(storage, "test-tenant".to_string(), "test-audit-secret".to_string(), true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        addr
    }

    /// Regression for the 2026-09-03 fix: `/v1/inspect`, `/v1/inspect-file`
    /// and `/v1/inspect-response` -- what the shipped `browser-extension/`
    /// actually calls for every scan decision -- used to return a result
    /// without ever writing to the local Audit Pipeline. Both the local
    /// console's History tab and `init_audit_relay`'s agent-to-SPOC-to-cloud
    /// forwarder read that exact same table, so neither the local nor the
    /// SaaS activity log ever had anything to show, no matter how much the
    /// extension actually blocked or redacted -- one missing write broke
    /// both consumers.
    #[tokio::test]
    async fn v1_inspect_persists_a_dlp_event_the_local_console_history_tab_can_see() {
        let addr = spawn_test_server_with_empty_audit_export().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "my key is AKIAIOSFODNN7EXAMPLE" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let history: serde_json::Value = client
            .get(format!("http://{addr}/ui/audit/recent"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(history["returned"], 1);
        assert_eq!(history["events"][0]["event_type"], "request");
    }

    #[tokio::test]
    async fn v1_inspect_file_persists_a_dlp_event_using_the_filename_as_domain() {
        let addr = spawn_test_server_with_empty_audit_export().await;
        let client = reqwest::Client::new();
        let data_base64 = BASE64.encode("here is my key AKIAIOSFODNN7EXAMPLE");
        let resp = client
            .post(format!("http://{addr}/v1/inspect-file"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "filename": "secret.txt", "data_base64": data_base64 }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let history: serde_json::Value = client
            .get(format!("http://{addr}/ui/audit/recent"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(history["returned"], 1);
        assert_eq!(history["events"][0]["domain"], "secret.txt");
    }

    #[tokio::test]
    async fn v1_inspect_uses_the_real_domain_when_the_extension_sends_one() {
        // Real user report: the local console's History tab showed
        // "unknown" for App/site on every single row. `domain` comes from
        // bridge-content-script.js's own `window.location.hostname` now
        // (see InspectRequest::domain's doc comment) -- proves it actually
        // lands in the persisted DlpEvent instead of the "unknown" fallback.
        let addr = spawn_test_server_with_empty_audit_export().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "just an ordinary prompt", "domain": "chatgpt.com" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let history: serde_json::Value = client.get(format!("http://{addr}/ui/audit/recent")).send().await.unwrap().json().await.unwrap();
        assert_eq!(history["events"][0]["domain"], "chatgpt.com");
    }

    #[tokio::test]
    async fn v1_inspect_file_combines_the_real_domain_and_the_filename() {
        let addr = spawn_test_server_with_empty_audit_export().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect-file"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({
                "filename": "notes.txt",
                "data_base64": BASE64.encode("nothing sensitive here"),
                "domain": "claude.ai",
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let history: serde_json::Value = client.get(format!("http://{addr}/ui/audit/recent")).send().await.unwrap().json().await.unwrap();
        assert_eq!(history["events"][0]["domain"], "claude.ai (notes.txt)");
    }

    #[tokio::test]
    async fn v1_inspect_response_persists_a_dlp_event_too() {
        let addr = spawn_test_server_with_empty_audit_export().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect-response"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "a perfectly ordinary AI reply" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);

        let history: serde_json::Value = client
            .get(format!("http://{addr}/ui/audit/recent"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(history["returned"], 1);
        assert_eq!(history["events"][0]["event_type"], "response");
    }

    /// A scan that returns `Allow` still needs to land in the audit trail --
    /// same "log every decision, not just the interesting ones" posture
    /// `connect_proxy::persist_event` already has -- because a *complete*
    /// activity log (not just a blocked-events log) is the actual point of
    /// the Audit Pipeline: proving nothing slipped through unscanned.
    #[tokio::test]
    async fn v1_inspect_persists_an_allow_event_too_not_just_blocks() {
        let addr = spawn_test_server_with_empty_audit_export().await;
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .json(&serde_json::json!({ "text": "just a normal question, nothing sensitive" }))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.json::<ScanResult>().await.unwrap().action, safeprompt_common::Action::Allow);

        let history: serde_json::Value = client
            .get(format!("http://{addr}/ui/audit/recent"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(history["returned"], 1);
    }

    #[tokio::test]
    async fn audit_export_returns_404_when_not_configured() {
        let addr = spawn_test_server().await; // no with_audit_export at all
        let resp = reqwest::get(format!("http://{addr}/ui/audit/export")).await.unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn audit_export_returns_403_when_storage_exists_but_not_licensed() {
        let addr = spawn_test_server_with_audit_export(false).await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/export")).await.unwrap();
        assert_eq!(resp.status(), 403, "Community (storage present, feature not licensed) must not be able to export");
    }

    #[tokio::test]
    async fn audit_export_json_format_returns_the_saved_event() {
        let addr = spawn_test_server_with_audit_export(true).await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/export?format=json")).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
        let body = resp.text().await.unwrap();
        let events: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["app_name"], "chrome.exe");
    }

    #[tokio::test]
    async fn audit_export_csv_format_returns_csv() {
        let addr = spawn_test_server_with_audit_export(true).await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/export?format=csv")).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "text/csv");
        let body = resp.text().await.unwrap();
        assert!(body.starts_with("id,timestamp,event_type"));
        assert!(body.contains("chrome.exe"));
    }

    #[tokio::test]
    async fn audit_export_signed_format_verifies_with_the_right_secret() {
        let addr = spawn_test_server_with_audit_export(true).await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/export?format=signed")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.text().await.unwrap();
        let verified = safeprompt_storage::verify_signed_archive(&body, "test-audit-secret").expect("the exported archive must verify against the Agent's own audit encryption secret");
        assert_eq!(verified.len(), 1);
        assert_eq!(verified[0].app_name, "chrome.exe");
    }

    #[tokio::test]
    async fn audit_export_rejects_an_unknown_format() {
        let addr = spawn_test_server_with_audit_export(true).await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/export?format=xml")).await.unwrap();
        assert_eq!(resp.status(), 400);
    }

    #[tokio::test]
    async fn audit_export_defaults_to_json_when_no_query_params_given() {
        let addr = spawn_test_server_with_audit_export(true).await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/export")).await.unwrap();
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.headers().get(header::CONTENT_TYPE).unwrap(), "application/json");
    }

    // ── /ui/audit/recent (local-console History tab) ─────────────────────

    #[tokio::test]
    async fn audit_recent_reports_unavailable_when_no_storage_is_configured() {
        let addr = spawn_test_server().await; // no with_audit_export at all
        let resp = reqwest::get(format!("http://{addr}/ui/audit/recent")).await.unwrap();
        assert_eq!(resp.status(), 200, "an absent local DB is a calm empty state here, not an error (unlike /export's 404)");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["available"], false);
        assert_eq!(body["events"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn audit_recent_returns_this_devices_events_regardless_of_export_license() {
        // licensed=false == Community: /export is 403 for them, but seeing
        // your own device's activity in the console is not gated.
        let addr = spawn_test_server_with_audit_export(false).await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/recent")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["available"], true);
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["app"], "chrome.exe");
        assert_eq!(events[0]["action"], "Block");
        assert!(events[0].get("timestamp").is_some());
        // The raw matched text must never be echoed back here.
        assert!(events[0].to_string().to_lowercase().find("snippet").is_none());
    }

    #[tokio::test]
    async fn audit_recent_honors_the_limit() {
        let addr = spawn_test_server_with_audit_export(true).await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/recent?limit=0")).await.unwrap();
        assert_eq!(resp.status(), 200);
        let body: serde_json::Value = resp.json().await.unwrap();
        // limit is clamped to at least 1, so the single saved event still
        // comes back rather than 400ing on a nonsense value.
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
    }

    /// Seeds a fresh in-memory audit DB with a handful of distinct events
    /// (different domains and actions) for the filter/pagination tests
    /// below -- `sample_audit_event` always produces the same fixed
    /// domain/action, not useful for proving a filter actually filters.
    async fn spawn_test_server_with_varied_events() -> SocketAddr {
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let storage = Arc::new(LocalDatabase::init_in_memory("test-audit-secret").await.unwrap());
        let fixtures: &[(&str, &str, Action)] = &[
            ("chatgpt.com", "request", Action::Allow),
            ("chatgpt.com", "response", Action::Block),
            ("claude.ai", "request", Action::Redact),
            ("claude.ai (secret.txt)", "file", Action::Redact),
            ("gemini.google.com", "request", Action::Allow),
        ];
        for (domain, event_type, action) in fixtures {
            let event = safeprompt_common::DlpEvent {
                id: uuid::Uuid::new_v4(),
                timestamp: chrono::Utc::now(),
                event_type: event_type.to_string(),
                action_taken: *action,
                app_name: "unknown".to_string(),
                domain: domain.to_string(),
                user_identity: "unknown".to_string(),
                findings: vec![],
            };
            storage.save_event("test-tenant", &event).await.unwrap();
        }
        let server = LocalApiServer::new("127.0.0.1:0".parse().unwrap(), inspector, vec![TEST_ORIGIN.to_string()])
            .with_audit_export(storage, "test-tenant".to_string(), "test-audit-secret".to_string(), true);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        addr
    }

    #[tokio::test]
    async fn audit_recent_filters_by_action() {
        let addr = spawn_test_server_with_varied_events().await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/recent?action=Redact")).await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 2, "only the two Redact fixtures should match");
        assert!(events.iter().all(|e| e["action"] == "Redact"));
    }

    #[tokio::test]
    async fn audit_recent_filters_by_domain_substring_case_insensitively() {
        let addr = spawn_test_server_with_varied_events().await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/recent?domain=CLAUDE")).await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        let events = body["events"].as_array().unwrap();
        assert_eq!(events.len(), 2, "both claude.ai fixtures (request + file) should match a case-insensitive substring");
    }

    #[tokio::test]
    async fn audit_recent_combines_action_and_domain_filters() {
        let addr = spawn_test_server_with_varied_events().await;
        let resp = reqwest::get(format!("http://{addr}/ui/audit/recent?domain=claude&action=Redact")).await.unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["events"].as_array().unwrap().len(), 2, "both claude.ai fixtures happen to be Redact, so combining filters keeps both");

        let resp2 = reqwest::get(format!("http://{addr}/ui/audit/recent?domain=chatgpt&action=Redact")).await.unwrap();
        let body2: serde_json::Value = resp2.json().await.unwrap();
        assert_eq!(body2["events"].as_array().unwrap().len(), 0, "no chatgpt.com fixture is Redact, so this combination matches nothing");
    }

    #[tokio::test]
    async fn audit_recent_paginates_with_offset_and_reports_has_more() {
        let addr = spawn_test_server_with_varied_events().await;
        let page1: serde_json::Value = reqwest::get(format!("http://{addr}/ui/audit/recent?limit=2&offset=0")).await.unwrap().json().await.unwrap();
        assert_eq!(page1["events"].as_array().unwrap().len(), 2);
        assert_eq!(page1["total_matching"], 5);
        assert_eq!(page1["has_more"], true);

        let page3: serde_json::Value = reqwest::get(format!("http://{addr}/ui/audit/recent?limit=2&offset=4")).await.unwrap().json().await.unwrap();
        assert_eq!(page3["events"].as_array().unwrap().len(), 1, "only one event left on the last page of 5 total at page size 2");
        assert_eq!(page3["has_more"], false);
    }

    /// Diagnostic sweep, not a correctness-assertion suite: runs every real
    /// file in `D:\Safeprompt\samples` (docx/pdf/plain-text, plus the
    /// `passport/` subfolder of real-looking passport images) through the
    /// exact pipeline `inspect_file_request` uses -- `extract_text` with a
    /// real, auto-downloaded OCR engine, `Inspector::inspect`, then the
    /// same text-vs-unmaskable masking decision this crate's own handler
    /// applies -- and prints one line per file. `#[ignore]`d: needs a
    /// real, machine-specific sample directory and a live OCR model
    /// download, neither appropriate for the ordinary `cargo test` run
    /// every other dev machine/CI executes. Run explicitly with:
    ///   cargo test -p safeprompt-local-api sample_directory_sweep -- --ignored --nocapture
    #[test]
    #[ignore]
    fn sample_directory_sweep() {
        use std::path::{Path, PathBuf};

        fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else { return };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_files(&path, out);
                } else if path.extension().and_then(|e| e.to_str()).map(|e| e != "py").unwrap_or(true) {
                    out.push(path);
                }
            }
        }

        let root = Path::new(r"D:\Safeprompt\samples");
        if !root.exists() {
            eprintln!("skipping sample_directory_sweep -- {root:?} doesn't exist on this machine");
            return;
        }

        let ocr: Option<Arc<dyn safeprompt_ocr::OcrEngine>> = match safeprompt_ocr::OarOcrEngine::new_with_auto_download() {
            Ok(engine) => Some(Arc::new(engine)),
            Err(e) => {
                eprintln!("OCR engine unavailable ({e}) -- image files will come back Unsupported/allowed-through");
                None
            }
        };
        let inspector = Inspector::new(PolicyConfig::default()).with_ocr_engine(ocr);

        let mut files = Vec::new();
        collect_files(root, &mut files);
        files.sort();
        assert!(!files.is_empty(), "expected real sample files under {root:?}");

        println!("\n{:<70} {:<12} {:<10} {}", "file", "extracted", "action", "note");
        for path in &files {
            let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("?").to_string();
            let extension = filename.rsplit('.').next().unwrap_or("");
            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    println!("{filename:<70} {:<12} {:<10} read error: {e}", "-", "-");
                    continue;
                }
            };

            match safeprompt_file_inspector::extract_text(&filename, &bytes, inspector.ocr_engine()) {
                safeprompt_file_inspector::ExtractionOutcome::Unsupported { reason, .. } => {
                    println!("{filename:<70} {:<12} {:<10} unsupported: {reason}", "no", "allow");
                }
                safeprompt_file_inspector::ExtractionOutcome::Text(text) => {
                    let mut scan = inspector.inspect(&text);
                    let mut note = format!("{} finding(s)", scan.findings.len());
                    if scan.action == Action::Redact {
                        if is_text_redactable_extension(extension) {
                            note.push_str(" -- masked in place");
                        } else {
                            let fallback = inspector.current_policy().security.unmaskable_file_action.enforcement_action();
                            let fallback = if fallback == Action::Redact { Action::Block } else { fallback };
                            scan.action = fallback;
                            note = format!("{note} -- unmaskable format, fell back to {fallback:?}");
                        }
                    }
                    let extracted_len = text.chars().count();
                    println!("{filename:<70} {:<12} {:<10} {note} ({extracted_len} chars extracted)", "yes", format!("{:?}", scan.action));
                    if scan.findings.is_empty() && extension != "txt" && extension != "docx" && extension != "pdf" {
                        println!("    OCR text: {:?}", text.chars().take(600).collect::<String>());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod live_tests {
    //! AGENT-COMM-002 (2026-08-10) -- proves the CENTRAL Agent mode
    //! (browser-extension/schema.json's `agentMode: "central"`) actually
    //! works end to end over a *real* routable network address, not just
    //! 127.0.0.1 -- the one thing every other test in this crate exercises.
    //! Same self-skip convention as `safeprompt-scanner`'s own
    //! `live_tests` module: if this machine genuinely has no non-loopback
    //! interface (some sandboxes don't), the test skips rather than fails
    //! -- this crate has no hard dependency on one existing.
    use super::*;
    use std::net::UdpSocket;

    const TEST_ORIGIN: &str = "chrome-extension://testextensionid0000000000000000";

    /// This machine's real outbound-facing IPv4 address, if it has one.
    /// The classic "connect a UDP socket, never actually send anything"
    /// trick -- `connect()` on a UDP socket just asks the OS routing table
    /// which local interface *would* be used to reach that destination, no
    /// packet is sent and no network access is required, so this works
    /// fully offline too (8.8.8.8 is never actually contacted).
    fn real_local_ipv4() -> Option<std::net::IpAddr> {
        let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        let addr = socket.local_addr().ok()?.ip();
        (!addr.is_loopback()).then_some(addr)
    }

    #[tokio::test]
    async fn central_mode_signed_requests_work_over_a_real_routable_address_not_just_loopback() {
        let Some(ip) = real_local_ipv4() else {
            eprintln!("skipping: no non-loopback IPv4 interface on this machine");
            return;
        };

        // A real central-Agent deployment binds beyond 127.0.0.1
        // (SAFEPROMPT_LOCAL_API_BIND_ADDR) and requires a shared secret --
        // exactly what with_shared_secret configures here.
        let inspector = Arc::new(Inspector::new(PolicyConfig::default()));
        let server = LocalApiServer::new(SocketAddr::new(ip, 0), inspector, vec![TEST_ORIGIN.to_string()])
            .with_shared_secret("central-tenant-secret".to_string());
        let listener = match tokio::net::TcpListener::bind(SocketAddr::new(ip, 0)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("skipping: could not bind {ip}:0 in this environment: {e}");
                return;
            }
        };
        let addr = listener.local_addr().unwrap();
        let router = server.router();
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });

        // The client deliberately connects via the real IP, not
        // "localhost"/127.0.0.1 -- simulating a different workstation's
        // extension reaching this Agent over the network, the actual
        // CENTRAL-mode scenario, not a loopback shortcut.
        let nonce = "central-live-test-nonce";
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let signature = compute_signature("central-tenant-secret", &timestamp, nonce);
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("http://{addr}/v1/inspect"))
            .header("Origin", TEST_ORIGIN)
            .header("X-SafePrompt-Timestamp", timestamp)
            .header("X-SafePrompt-Nonce", nonce)
            .header("X-SafePrompt-Signature", signature)
            .json(&serde_json::json!({ "text": "AKIAIOSFODNN7EXAMPLE" }))
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), 200, "a correctly signed request over a real routable address (not loopback) must succeed, proving CENTRAL mode works end to end");
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["action"], "Redact", "the real Inspector must have actually run, not just the auth layer");
    }
}
