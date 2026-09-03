// Agent tamper protection, part 2: process supervision. Spawns the
// SafePrompt Agent service as a child process and restarts it if it exits
// unexpectedly (crashed, killed via Task Manager/`taskkill`, etc). Honest
// scope note: this is a userspace watchdog, not a protected/critical
// process — someone with local admin rights who kills the watchdog *and*
// the service in quick succession (or kills both faster than the restart
// loop reacts) isn't stopped by this. Real tamper-resistance against a
// privileged local attacker needs OS-level protected-process support,
// which is out of scope for this pass. What this does provide: the service
// survives a crash, an accidental kill, or a single `taskkill` — the common
// cases, not the adversarial worst case.

use safeprompt_integrity::ManifestVerifier;
use safeprompt_updater::Updater;
use std::collections::VecDeque;
use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tracing::{error, info, warn};

struct RestartLimiter {
    history: VecDeque<Instant>,
    max_restarts: usize,
    window: Duration,
    normal_delay: Duration,
    backoff_delay: Duration,
}

impl RestartLimiter {
    fn new(max_restarts: usize, window: Duration, normal_delay: Duration, backoff_delay: Duration) -> Self {
        Self {
            history: VecDeque::new(),
            max_restarts,
            window,
            normal_delay,
            backoff_delay,
        }
    }

    /// Records a restart at `now` and returns how long to wait before
    /// actually respawning — `normal_delay` under the limit, `backoff_delay`
    /// once restarts are happening faster than `max_restarts` per `window`
    /// (a crash loop, not a one-off kill).
    fn record_and_next_delay(&mut self, now: Instant) -> Duration {
        self.history.push_back(now);
        let cutoff = now.checked_sub(self.window).unwrap_or(now);
        while self.history.front().is_some_and(|t| *t < cutoff) {
            self.history.pop_front();
        }
        if self.history.len() > self.max_restarts {
            self.backoff_delay
        } else {
            self.normal_delay
        }
    }
}

fn resolve_service_path() -> anyhow::Result<PathBuf> {
    if let Ok(p) = env::var("SAFEPROMPT_SERVICE_PATH") {
        return Ok(PathBuf::from(p));
    }
    let mut path = env::current_exe()?;
    path.pop();
    let name = if cfg!(windows) { "safeprompt-service.exe" } else { "safeprompt-service" };
    path.push(name);
    Ok(path)
}

/// Same per-OS data directory convention `apps/service::default_data_dir`
/// uses (see that function's doc comment for the full reasoning) — kept as
/// its own small copy here rather than a shared crate just for this,
/// matching how each binary's startup logic is already tailored rather
/// than centralized.
fn default_path(filename: &str) -> String {
    let dir = if cfg!(windows) {
        let program_data = env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
        PathBuf::from(program_data).join("SafePrompt")
    } else if cfg!(target_os = "macos") {
        PathBuf::from("/Library/Application Support/SafePrompt")
    } else {
        PathBuf::from("/var/lib/safeprompt")
    };
    dir.join(filename).to_string_lossy().into_owned()
}

/// The mutual-trust half of tamper protection the vendor's own signature
/// pipeline (installer/sign.ps1) makes possible: rather than the service
/// only ever checking *itself* at its own startup (which a maliciously
/// modified binary could simply skip — it controls whether it runs its own
/// check at all), the watchdog checks the service binary from *outside*
/// it, before every spawn, not just once at watchdog startup — so a binary
/// swapped in while the watchdog is already running gets caught on the very
/// next restart attempt, not only on a fresh boot.
///
/// Same graceful-degradation posture as every other opt-in check in this
/// codebase: no manifest configured at all -> skip (dev-friendly), a
/// manifest that's present and doesn't verify -> refuse to spawn (fail
/// closed, this is exactly the tampering the check exists to catch).
fn verify_service_binary_before_spawn(service_path: &Path) -> bool {
    let manifest_path = env::var("SAFEPROMPT_INTEGRITY_MANIFEST_PATH").unwrap_or_else(|_| default_path("integrity_manifest.json"));
    let public_key_path = env::var("SAFEPROMPT_INTEGRITY_PUBLIC_KEY").unwrap_or_else(|_| default_path("integrity_public_key.hex"));

    if !Path::new(&manifest_path).exists() {
        return true;
    }

    let result = (|| -> anyhow::Result<()> {
        let public_hex = std::fs::read_to_string(&public_key_path)?;
        let public_bytes: [u8; 32] = hex::decode(public_hex.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("public key file must contain exactly 32 bytes hex-encoded"))?;
        let verifier = ManifestVerifier::from_public_key_bytes(&public_bytes).map_err(|e| anyhow::anyhow!("{e}"))?;

        let signed: safeprompt_integrity::SignedManifest = serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
        verifier.verify_binary_at(&signed, service_path).map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(())
    })();

    match result {
        Ok(()) => true,
        Err(e) => {
            error!(
                "REFUSING TO START {}: pre-spawn integrity check failed: {e} — the binary on disk does not \
                 match what the vendor signed, or its Authenticode signature doesn't match the pinned signer",
                service_path.display()
            );
            false
        }
    }
}

/// This machine's platform, as the Release Registry (backend/api/updates.py)
/// spells it in its `platform` query param / stored records — must match
/// exactly what .github/workflows/release.yml's publish-updates job POSTs
/// (see that job for the "windows"/"linux" literals). macOS isn't a real
/// release-pipeline target yet (Phase 2/3, see the release-pipeline memory)
/// but is named correctly here anyway rather than mis-reporting "linux" the
/// day it does become one.
fn current_platform() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

/// SP-UPD-006 (2026-08-13): same idea as apps/service's own
/// `control_plane_endpoint` — derives a Release Registry URL from
/// `SAFEPROMPT_CONTROL_PLANE_URL` + this machine's platform, so a fleet
/// only needs one control-plane URL configured (already true for
/// fleet/policy/audit) rather than a fourth/fifth update-specific env var
/// on every install. `kind` is "latest" or "latest/binary" — the two
/// backend/api/updates.py routes. Individual
/// SAFEPROMPT_UPDATE_MANIFEST_URL/_BINARY_URL env vars still win if set
/// explicitly (checked by the caller before this ever runs) — this is only
/// the fallback. Fails safe to `None` on an unset or malformed base URL,
/// same posture as every other derived endpoint in this codebase.
fn control_plane_update_endpoint(kind: &str) -> Option<String> {
    let base = env::var("SAFEPROMPT_CONTROL_PLANE_URL").ok()?;
    let mut url = reqwest::Url::parse(&base).ok()?;
    url.path_segments_mut().ok()?.extend(&["api", "v1", "updates"]).extend(kind.split('/'));
    url.query_pairs_mut().append_pair("platform", current_platform()).append_pair("channel", "stable");
    Some(url.to_string())
}

/// Secure auto-update — opt-in via `SAFEPROMPT_UPDATE_PUBLIC_KEY` (no
/// sensible derived default for a local file path); the manifest/binary
/// URLs are each either set explicitly or derived from
/// `SAFEPROMPT_CONTROL_PLANE_URL` (see `control_plane_update_endpoint`). If
/// none of these resolve, the watchdog only supervises (its original job),
/// it doesn't update. See `safeprompt-updater`'s module doc for why
/// replacing the service's binary happens *here* (the watchdog, supervising
/// a child process) and not in the service updating itself.
fn build_updater() -> Option<(Updater, String, String, Duration)> {
    let public_key_path = env::var("SAFEPROMPT_UPDATE_PUBLIC_KEY").ok()?;
    let manifest_url = env::var("SAFEPROMPT_UPDATE_MANIFEST_URL")
        .ok()
        .or_else(|| control_plane_update_endpoint("latest"))?;
    let binary_url = env::var("SAFEPROMPT_UPDATE_BINARY_URL")
        .ok()
        .or_else(|| control_plane_update_endpoint("latest/binary"))?;
    let check_interval = Duration::from_secs(
        env::var("SAFEPROMPT_UPDATE_CHECK_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3600),
    );

    let public_hex = match std::fs::read_to_string(&public_key_path) {
        Ok(h) => h,
        Err(e) => {
            error!("auto-update configured but couldn't read verifier key at {public_key_path}: {e} — auto-update disabled");
            return None;
        }
    };
    let public_bytes: [u8; 32] = match hex::decode(public_hex.trim()).ok().and_then(|v| v.try_into().ok()) {
        Some(b) => b,
        None => {
            error!("verifier key at {public_key_path} is not 32 bytes hex-encoded — auto-update disabled");
            return None;
        }
    };
    let verifier = match ManifestVerifier::from_public_key_bytes(&public_bytes) {
        Ok(v) => v,
        Err(e) => {
            error!("bad verifier key at {public_key_path}: {e} — auto-update disabled");
            return None;
        }
    };

    Some((Updater::new(verifier), manifest_url, binary_url, check_interval))
}

/// Runs forever, checking for and applying updates to `service_path` on
/// `check_interval`. Signals `notify` after a successful `apply_update` so
/// the main supervision loop knows to restart the child and pick up the
/// new binary — the checker never touches the running child itself.
fn spawn_update_checker(
    updater: Updater,
    manifest_url: String,
    binary_url: String,
    service_path: PathBuf,
    check_interval: Duration,
    notify: Arc<tokio::sync::Notify>,
) {
    tokio::spawn(async move {
        let mut current_version = env!("CARGO_PKG_VERSION").to_string();
        info!("auto-update checker started (checking every {check_interval:?}, current version {current_version})");

        loop {
            tokio::time::sleep(check_interval).await;

            let signed = match updater.check_for_update(&manifest_url, &current_version).await {
                Ok(Some(signed)) => signed,
                Ok(None) => continue, // steady state — already up to date
                Err(e) => {
                    warn!("update check failed: {e}");
                    continue;
                }
            };

            info!(new_version = signed.manifest.version, current_version, "update available — downloading");
            let new_binary = match updater.download_and_verify(&binary_url, &signed).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("failed to download/verify update binary: {e}");
                    continue;
                }
            };

            match updater.apply_update(&service_path, &new_binary) {
                Ok(()) => {
                    info!(version = signed.manifest.version, "update applied to {} — restarting to pick it up", service_path.display());
                    current_version = signed.manifest.version;
                    notify.notify_one();
                }
                Err(e) => error!("failed to apply downloaded update: {e}"),
            }
        }
    });
}

/// Status the tray app (apps/tray, a separate per-user process — a Windows
/// Service can't show UI directly, Session 0 isolation) polls to know
/// whether the user is actually protected right now. Written here, not by
/// the service itself, because the watchdog is the one thing that actually
/// knows the supervised child's real running state moment to moment (that's
/// its whole job) — the tray app never talks to the service directly.
#[derive(serde::Serialize)]
struct AgentStatus {
    protected: bool,
    updated_at: String,
    edition: Option<String>,
    expiry: Option<String>,
    extension_detected: bool,
}

/// 2.5x background.js's ~60s heartbeat period -- same constant and same
/// reasoning as apps/service's own copy of this (see that one's doc
/// comment); duplicated rather than shared, matching how this file already
/// keeps its own copy of `default_path`/`ProgramData` resolution instead of
/// pulling in apps/service as a dependency for one constant.
const EXTENSION_HEARTBEAT_FRESHNESS: Duration = Duration::from_secs(150);

/// Best-effort read of `extension-status.json` (written by apps/service's
/// local API on every `/v1/extension-heartbeat` call) -- missing/
/// unparseable/stale just means "not detected," not an error worth
/// surfacing, same posture as `read_license_summary` below.
fn read_extension_detected() -> bool {
    let path = default_path("extension-status.json");
    let Ok(text) = std::fs::read_to_string(&path) else { return false };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else { return false };
    let Some(last_seen) = value["last_seen"].as_str() else { return false };
    let Ok(last_seen) = chrono::DateTime::parse_from_rfc3339(last_seen) else { return false };
    let age = chrono::Utc::now().signed_duration_since(last_seen.with_timezone(&chrono::Utc));
    age >= chrono::Duration::zero() && age <= chrono::Duration::from_std(EXTENSION_HEARTBEAT_FRESHNESS).unwrap_or_default()
}

/// Best-effort read of the two fields the tray tooltip cares about out of
/// license.json -- missing/unparseable file just means an unlicensed
/// Community install, not an error worth surfacing here.
fn read_license_summary() -> (Option<String>, Option<String>) {
    let path = default_path("license.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return (None, None);
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
        return (None, None);
    };
    let claims = &v["claims"];
    (
        claims["edition"].as_str().map(String::from),
        claims["expiry"].as_str().map(String::from),
    )
}

/// Writes %ProgramData%\SafePrompt\status.json every 2s reflecting
/// `service_running`'s current value. Polling rather than push (a named
/// pipe/IPC channel) is a deliberate simplification: ProgramData already has
/// permissive-enough default ACLs for any logged-on user to read a file
/// SYSTEM wrote there (unlike a named pipe, which would need a hand-built
/// SECURITY_ATTRIBUTES DACL to be reachable from a non-elevated tray
/// process — real Windows IPC security attributes are a notorious source of
/// subtle over/under-permissioning bugs). A 2s-stale tray icon is an
/// acceptable tradeoff for not hand-rolling that.
fn spawn_status_writer(service_running: Arc<AtomicBool>) {
    tokio::spawn(async move {
        let path = default_path("status.json");
        loop {
            let (edition, expiry) = read_license_summary();
            let status = AgentStatus {
                protected: service_running.load(Ordering::Relaxed),
                updated_at: chrono::Utc::now().to_rfc3339(),
                edition,
                expiry,
                extension_detected: read_extension_detected(),
            };
            if let Ok(json) = serde_json::to_string(&status) {
                if let Err(e) = std::fs::write(&path, json) {
                    warn!("failed to write status file at {path}: {e}");
                }
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// Logs to `SAFEPROMPT_WATCHDOG_LOG_PATH` if set (append mode), falling
/// back to stdout otherwise. Matters more than it would for a normal CLI:
/// a real Windows Service has no attached console, so `tracing_subscriber`'s
/// default stdout writer has nowhere useful to go once this actually runs
/// under the Service Control Manager rather than a dev console. ProgramData-
/// rooted config/log paths are a deliberately later piece (see the
/// Configuration Manager rework in the productization plan) — this is the
/// minimal real thing needed right now, an explicit env var with a stdout
/// fallback for local/dev runs, not a stub.
fn init_tracing() {
    if let Ok(path) = env::var("SAFEPROMPT_WATCHDOG_LOG_PATH") {
        match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                tracing_subscriber::fmt()
                    .with_writer(move || file.try_clone().expect("failed to clone watchdog log file handle"))
                    .with_ansi(false)
                    .init();
                return;
            }
            Err(e) => {
                eprintln!("could not open SAFEPROMPT_WATCHDOG_LOG_PATH ({path}): {e} — logging to stdout instead");
            }
        }
    }
    tracing_subscriber::fmt::init();
}

/// The actual supervision loop, unchanged in behavior from before this was
/// extracted — only the shutdown trigger is now generic (`shutdown_rx`)
/// instead of hardcoding `tokio::signal::ctrl_c()`, so the exact same loop
/// serves both the console/dev entry point (fed by Ctrl+C) and the real
/// Windows Service entry point (fed by the SCM's Stop/Shutdown control,
/// which has no notion of a console Ctrl+C signal at all).
async fn run_watchdog(service_path: PathBuf, mut shutdown_rx: watch::Receiver<bool>) -> anyhow::Result<()> {
    info!("SafePrompt watchdog supervising {}", service_path.display());

    let mut limiter = RestartLimiter::new(
        5,
        Duration::from_secs(60),
        Duration::from_secs(1),
        Duration::from_secs(30),
    );

    let update_ready = Arc::new(tokio::sync::Notify::new());
    match build_updater() {
        Some((updater, manifest_url, binary_url, check_interval)) => {
            spawn_update_checker(updater, manifest_url, binary_url, service_path.clone(), check_interval, Arc::clone(&update_ready));
        }
        None => info!(
            "auto-update not configured (SAFEPROMPT_UPDATE_PUBLIC_KEY missing, or neither SAFEPROMPT_UPDATE_MANIFEST_URL/_BINARY_URL nor SAFEPROMPT_CONTROL_PLANE_URL is set) — supervising only"
        ),
    }

    let service_running = Arc::new(AtomicBool::new(false));
    spawn_status_writer(Arc::clone(&service_running));

    loop {
        if !verify_service_binary_before_spawn(&service_path) {
            service_running.store(false, Ordering::Relaxed);
            let delay = limiter.record_and_next_delay(Instant::now());
            warn!("not spawning this cycle — retrying the integrity check in {delay:?}");
            tokio::time::sleep(delay).await;
            continue;
        }

        info!("Starting supervised service process...");
        let mut child = match tokio::process::Command::new(&service_path).spawn() {
            Ok(c) => c,
            Err(e) => {
                error!("failed to spawn service process at {}: {e}", service_path.display());
                service_running.store(false, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        let child_pid = child.id();
        service_running.store(true, Ordering::Relaxed);

        tokio::select! {
            status = child.wait() => {
                match status {
                    Ok(s) => warn!("supervised service (pid {:?}) exited with {s}", child_pid),
                    Err(e) => error!("error waiting on supervised service: {e}"),
                }
            }
            _ = shutdown_rx.changed() => {
                info!("watchdog received shutdown signal — stopping supervised service and exiting");
                service_running.store(false, Ordering::Relaxed);
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Ok(());
            }
            _ = update_ready.notified() => {
                info!("update was applied to disk — stopping current service to restart on the new version");
                let _ = child.kill().await;
                let _ = child.wait().await;
            }
        }

        service_running.store(false, Ordering::Relaxed);
        let delay = limiter.record_and_next_delay(Instant::now());
        warn!("restarting supervised service in {delay:?}");
        tokio::time::sleep(delay).await;
    }
}

/// Runs the watchdog directly in the current process/console — the
/// dev/debug path (and the only path at all on non-Windows, until
/// systemd/launchd integration exists). Shutdown is triggered by Ctrl+C,
/// same as before this file gained real Windows Service support.
fn run_console_mode() -> anyhow::Result<()> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let service_path = resolve_service_path()?;
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            let _ = shutdown_tx.send(true);
        });
        run_watchdog(service_path, shutdown_rx).await
    })
}

fn main() -> anyhow::Result<()> {
    init_tracing();

    #[cfg(windows)]
    {
        let args: Vec<String> = env::args().collect();
        match args.get(1).map(String::as_str) {
            Some("install") => return windows_svc::install_service(),
            Some("uninstall") => return windows_svc::uninstall_service(),
            _ => {}
        }

        // Launched by the Service Control Manager -> this call blocks for
        // the service's whole lifetime and returns only after it stops.
        // Launched any other way (a dev console, cargo run, double-click)
        // -> the SCM handshake fails immediately (there's no control pipe
        // to connect to), and we fall through to the plain console path
        // below unchanged from before this file had service support at all.
        if windows_svc::try_run_as_service().is_ok() {
            return Ok(());
        }
    }

    run_console_mode()
}

/// Real Windows Service Control Manager integration: `install`/`uninstall`
/// register/remove `safeprompt-watchdog.exe` as an actual auto-start
/// service, and `try_run_as_service` is how the binary behaves when the SCM
/// itself launches it (as opposed to a human running it from a console).
/// This is genuinely new capability, not a config toggle — before this, the
/// only way to keep the watchdog (and therefore the whole Agent) running
/// across a reboot was a human (or some other launcher entirely outside
/// this codebase) starting it by hand every time.
#[cfg(windows)]
mod windows_svc {
    use super::{resolve_service_path, run_watchdog};
    use std::ffi::OsString;
    use std::time::Duration;
    use tokio::sync::watch;
    use tracing::error;
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    pub const SERVICE_NAME: &str = "SafePromptWatchdog";
    const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

    pub fn install_service() -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CREATE_SERVICE)?;
        let executable_path = std::env::current_exe()?;
        let service_info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("SafePrompt Watchdog"),
            service_type: SERVICE_TYPE,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path,
            launch_arguments: vec![],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;
        service.set_description(
            "Supervises and auto-restarts the SafePrompt Agent service; applies signed auto-updates to it.",
        )?;
        println!("Installed service '{SERVICE_NAME}' (start type: Automatic). Start it with: sc start {SERVICE_NAME}");
        Ok(())
    }

    pub fn uninstall_service() -> anyhow::Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let service = manager.open_service(
            SERVICE_NAME,
            ServiceAccess::DELETE | ServiceAccess::STOP | ServiceAccess::QUERY_STATUS,
        )?;
        // Best-effort: stop it first so a running service doesn't linger
        // "marked for deletion" until the next reboot.
        let _ = service.stop();
        service.delete()?;
        println!("Removed service '{SERVICE_NAME}'.");
        Ok(())
    }

    pub fn try_run_as_service() -> anyhow::Result<()> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| anyhow::anyhow!("{e}"))
    }

    define_windows_service!(ffi_service_main, service_main);

    fn service_main(_arguments: Vec<OsString>) {
        if let Err(e) = run_service() {
            error!("SafePrompt Watchdog service_main failed: {e}");
        }
    }

    fn run_service() -> anyhow::Result<()> {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let status_handle = service_control_handler::register(SERVICE_NAME, move |control_event| match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        })?;

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        let runtime = tokio::runtime::Runtime::new()?;
        let result = runtime.block_on(async {
            let service_path = resolve_service_path()?;
            run_watchdog(service_path, shutdown_rx).await
        });

        if let Err(e) = &result {
            error!("watchdog loop exited with an error: {e}");
        }

        status_handle.set_service_status(ServiceStatus {
            service_type: SERVICE_TYPE,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })?;

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_normal_restarts_under_the_limit() {
        let mut limiter = RestartLimiter::new(3, Duration::from_secs(60), Duration::from_secs(1), Duration::from_secs(30));
        let base = Instant::now();
        for i in 0..3 {
            let delay = limiter.record_and_next_delay(base + Duration::from_millis(i));
            assert_eq!(delay, Duration::from_secs(1), "restart {i} should still be under the limit");
        }
    }

    #[test]
    fn backs_off_after_exceeding_restart_limit_within_window() {
        let mut limiter = RestartLimiter::new(3, Duration::from_secs(60), Duration::from_secs(1), Duration::from_secs(30));
        let base = Instant::now();
        for i in 0..3 {
            limiter.record_and_next_delay(base + Duration::from_millis(i));
        }
        // The 4th restart within the same 60s window exceeds max_restarts=3.
        let delay = limiter.record_and_next_delay(base + Duration::from_millis(4));
        assert_eq!(delay, Duration::from_secs(30));
    }

    #[test]
    fn window_forgets_old_restarts() {
        let mut limiter = RestartLimiter::new(1, Duration::from_secs(10), Duration::from_secs(1), Duration::from_secs(30));
        let base = Instant::now();
        limiter.record_and_next_delay(base);
        // Second restart is well outside the 10s window, so it shouldn't trip the limit.
        let delay = limiter.record_and_next_delay(base + Duration::from_secs(30));
        assert_eq!(delay, Duration::from_secs(1));
    }

    // Combined into one test rather than two: `std::env::set_var`/
    // `remove_var` mutate whole-process state, and Rust's default test
    // harness runs tests in the same binary on separate threads — two
    // tests each touching SAFEPROMPT_SERVICE_PATH independently is a real
    // data race (intermittently observed under `cargo test --workspace`,
    // not just a theoretical concern), not just a style nit.
    #[test]
    fn resolves_service_path_with_and_without_the_env_var_override() {
        env::remove_var("SAFEPROMPT_SERVICE_PATH");
        let default_path = resolve_service_path().unwrap();
        let expected_name = if cfg!(windows) { "safeprompt-service.exe" } else { "safeprompt-service" };
        assert_eq!(default_path.file_name().unwrap().to_str().unwrap(), expected_name);

        env::set_var("SAFEPROMPT_SERVICE_PATH", "/custom/path/to/service");
        let overridden_path = resolve_service_path().unwrap();
        assert_eq!(overridden_path, PathBuf::from("/custom/path/to/service"));

        env::remove_var("SAFEPROMPT_SERVICE_PATH");
    }

    // Same reasoning as `resolves_service_path_with_and_without_the_env_var_
    // override` above — SAFEPROMPT_CONTROL_PLANE_URL is process-global state,
    // so every case lives in one test rather than racing across threads.
    #[test]
    fn control_plane_update_endpoint_covers_every_case() {
        env::remove_var("SAFEPROMPT_CONTROL_PLANE_URL");
        assert_eq!(control_plane_update_endpoint("latest"), None, "unset base URL must fail safe, not panic or guess");

        env::set_var("SAFEPROMPT_CONTROL_PLANE_URL", "https://control.safeprompt.ai");
        let manifest_url = control_plane_update_endpoint("latest").unwrap();
        assert!(manifest_url.starts_with("https://control.safeprompt.ai/api/v1/updates/latest?"), "{manifest_url}");
        assert!(manifest_url.contains(&format!("platform={}", current_platform())), "{manifest_url}");
        assert!(manifest_url.contains("channel=stable"), "{manifest_url}");

        let binary_url = control_plane_update_endpoint("latest/binary").unwrap();
        assert!(binary_url.starts_with("https://control.safeprompt.ai/api/v1/updates/latest/binary?"), "{binary_url}");

        // Trailing slash on the base must not produce a doubled slash before
        // the appended path segments.
        env::set_var("SAFEPROMPT_CONTROL_PLANE_URL", "https://control.safeprompt.ai/");
        assert!(control_plane_update_endpoint("latest").unwrap().starts_with("https://control.safeprompt.ai/api/v1/updates/latest?"));

        env::set_var("SAFEPROMPT_CONTROL_PLANE_URL", "not a url");
        assert_eq!(control_plane_update_endpoint("latest"), None, "a malformed base URL must fail safe, never panic");

        env::remove_var("SAFEPROMPT_CONTROL_PLANE_URL");
    }
}
