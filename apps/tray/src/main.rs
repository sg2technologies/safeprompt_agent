// SafePrompt Agent tray icon.
//
// Runs as a per-user process (auto-started via an HKLM Run key at login --
// see SafePrompt.wxs), NOT as part of the Windows Service. A Service lives
// in Session 0 and cannot show any UI in a user's desktop session -- that's
// a Windows security boundary, not a limitation of this code. So this is a
// deliberately separate, lightweight binary whose only job is to reflect
// what the watchdog already knows.
//
// Status comes from polling %ProgramData%\SafePrompt\status.json (written
// every 2s by apps/watchdog's spawn_status_writer), not a live IPC channel.
// A named pipe would need a hand-built Windows SECURITY_ATTRIBUTES DACL to
// be reachable by this non-elevated process from a SYSTEM-owned pipe --
// getting that wrong either over-permissions the pipe or makes it
// unreachable, and it's a notorious source of subtle bugs. Polling a file
// under ProgramData's already-permissive-enough default ACLs is a
// deliberate simplification: the tray can be up to ~2s stale, which is an
// acceptable tradeoff here.

use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

const DEFAULT_DASHBOARD_URL: &str = "https://safeprompt.pro/dashboard";
/// Same default apps/service binds local_api to (`SAFEPROMPT_LOCAL_API_BIND_ADDR`,
/// see that binary's port table) -- kept as its own copy, matching how every
/// other path/port in this dependency-light binary is duplicated rather than
/// shared.
const DEFAULT_LOCAL_API_ADDR: &str = "127.0.0.1:8847";
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The local console -- `GET /` on local_api (see that crate's
/// `console.html`): protection status, live policy view/edit, and a
/// test-a-message detection tool, served straight off this device with no
/// login. Honors `SAFEPROMPT_LOCAL_API_BIND_ADDR` (the same var
/// `apps/service` binds local_api from), defaulting to the same
/// `127.0.0.1:8847`. A `0.0.0.0` bind (CENTRAL-mode LAN exposure) isn't
/// browsable as-is, so it's normalised back to loopback for this link.
fn local_console_url() -> String {
    let addr = std::env::var("SAFEPROMPT_LOCAL_API_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_LOCAL_API_ADDR.to_string());
    let addr = addr.trim();
    let host_port = match addr.strip_prefix("0.0.0.0") {
        Some(rest) => format!("127.0.0.1{rest}"),
        None => addr.to_string(),
    };
    format!("http://{host_port}/")
}

/// Resolves the URL the tray's "Open Dashboard" item opens -- always the
/// cloud account portal now, on every edition including Community (a
/// Community user has a real cloud workspace behind the safeprompt.pro
/// login: it's where they manage their account, download, and license).
/// The device-local view (policy, status, detection testing, browser
/// extension setup) is a SEPARATE always-present "Open Local Console" menu
/// item -- this used to double as that for Community, which is why the
/// old Community special-case existed; it doesn't any more.
///
/// Priority:
/// 1. `SAFEPROMPT_DASHBOARD_URL` -- explicit override, verbatim.
/// 2. `SAFEPROMPT_CONTROL_PLANE_URL` + `/dashboard` -- a private Control
///    Plane deployment's own dashboard.
/// 3. The public SaaS (`https://safeprompt.pro/dashboard`).
///
/// A malformed value in either env var falls through to the next level
/// rather than opening garbage -- the result only ever goes to
/// `cmd /C start`, so a plain scheme-prefix check is enough.
fn resolve_dashboard_url(_edition: Option<&str>) -> String {
    fn is_plausible_url(s: &str) -> bool {
        s.starts_with("http://") || s.starts_with("https://")
    }

    if let Ok(explicit) = std::env::var("SAFEPROMPT_DASHBOARD_URL") {
        if is_plausible_url(&explicit) {
            return explicit;
        }
    }

    if let Ok(control_plane) = std::env::var("SAFEPROMPT_CONTROL_PLANE_URL") {
        if is_plausible_url(&control_plane) {
            return format!("{}/dashboard", control_plane.trim_end_matches('/'));
        }
    }
    DEFAULT_DASHBOARD_URL.to_string()
}

#[derive(Deserialize)]
struct AgentStatus {
    protected: bool,
    #[allow(dead_code)]
    updated_at: String,
    edition: Option<String>,
    #[allow(dead_code)]
    expiry: Option<String>,
    #[serde(default)] // absent on a status.json written by an older watchdog build -- default false, not a parse error
    extension_detected: bool,
}

/// Same %ProgramData%\SafePrompt convention every other Agent binary uses
/// (apps/service::default_data_dir, apps/watchdog::default_path) -- kept as
/// its own copy rather than a shared crate just for this one path, matching
/// how each binary here already tailors its own startup logic.
fn status_file_path() -> PathBuf {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(program_data).join("SafePrompt").join("status.json")
}

/// Same convention as `status_file_path` -- a marker so the first-run popup
/// below only ever shows once per machine, not on every login.
fn onboarding_marker_path() -> PathBuf {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(program_data).join("SafePrompt").join("tray-onboarded.marker")
}

/// Real end-user problem this exists to fix, not a hypothetical one:
/// live-caught 2026-08-08 -- the tray auto-starts via a registry Run key
/// with zero indication to the person sitting at the machine that anything
/// happened at all, and Windows hides new tray icons in the collapsed
/// overflow ("hidden icons") area by default. A toast/balloon notification
/// was considered first and deliberately rejected: Windows Focus Assist can
/// silently suppress those, and a missed one just recreates the exact same
/// "how would I know" problem this is supposed to solve. A blocking modal
/// dialog cannot be silently missed -- it's the bluntest tool available,
/// which is the point. Shown once ever (see `onboarding_marker_path`), not
/// on every login -- a returning user who already knows what SafePrompt is
/// does not need to be interrupted again.
fn show_first_run_notice_if_needed() {
    let marker = onboarding_marker_path();
    if marker.exists() {
        return;
    }

    let message = "SafePrompt is now protecting this device.\n\n\
        Look for the SafePrompt icon in your system tray (bottom-right of \
        the screen, near the clock). If you don't see it right away, click \
        the ^ arrow to show hidden icons -- Windows tucks new tray icons \
        away by default.\n\n\
        Right-click (or click) the icon any time to check protection \
        status or open your dashboard.";

    unsafe {
        use windows_sys::core::PCWSTR;
        use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONINFORMATION, MB_OK};

        fn to_wide(s: &str) -> Vec<u16> {
            s.encode_utf16().chain(std::iter::once(0)).collect()
        }
        let title = to_wide("SafePrompt");
        let body = to_wide(message);
        MessageBoxW(std::ptr::null_mut(), body.as_ptr() as PCWSTR, title.as_ptr() as PCWSTR, MB_OK | MB_ICONINFORMATION);
    }

    // Written AFTER the dialog closes, not before -- if the process were
    // killed mid-dialog (e.g. a forced logoff) the marker shouldn't exist
    // for a notice the user never actually saw.
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, b"shown");
}

enum Status {
    Protected(Option<String>, bool), // edition (if known), extension_detected
    NotRunning,
    Unknown, // status.json missing/unreadable -- e.g. moments after a fresh install
}

/// The licensed edition string from status.json, when the Agent is running
/// and reported one. `None` for a not-running / not-yet-readable Agent, in
/// which case callers treat the install as standalone (see
/// `resolve_dashboard_url`).
fn status_edition(status: &Status) -> Option<&str> {
    match status {
        Status::Protected(edition, _) => edition.as_deref(),
        Status::NotRunning | Status::Unknown => None,
    }
}

fn read_status() -> Status {
    let Ok(text) = std::fs::read_to_string(status_file_path()) else {
        return Status::Unknown;
    };
    let Ok(status) = serde_json::from_str::<AgentStatus>(&text) else {
        return Status::Unknown;
    };
    if status.protected {
        Status::Protected(status.edition, status.extension_detected)
    } else {
        Status::NotRunning
    }
}

/// Extension health is only worth mentioning when this install's license
/// could actually use one at all -- appending "Extension: Not detected" to
/// a Community/core-only install (where nothing was ever going to send a
/// heartbeat) would just be confusing noise, not a real signal.
fn status_label(status: &Status) -> String {
    match status {
        Status::Protected(edition, extension_detected) => {
            let base = match edition {
                Some(edition) => format!("Protected ({edition})"),
                None => "Protected".to_string(),
            };
            if browser_coverage_active() {
                let ext = if *extension_detected { "Extension: detected" } else { "Extension: not detected" };
                format!("{base} · {ext}")
            } else {
                base
            }
        }
        Status::NotRunning => "Not running".to_string(),
        Status::Unknown => "Status unknown".to_string(),
    }
}

fn status_tooltip(status: &Status) -> String {
    format!("SafePrompt Agent - {}", status_label(status))
}

fn load_icon() -> Icon {
    // Embedded at build time from this crate's own assets/ (not reaching
    // across into frontend/public/ at build time, which would make the
    // agent workspace's build fragile/dependent on the frontend tree being
    // checked out in the same place) -- copied from there once, see
    // assets/icon-32.png's sibling icon-192.png for the source.
    let bytes = include_bytes!("../assets/icon-32.png");
    let img = image::load_from_memory(bytes)
        .expect("bundled tray icon PNG must decode")
        .into_rgba8();
    let (width, height) = img.dimensions();
    Icon::from_rgba(img.into_raw(), width, height).expect("bundled tray icon must have valid dimensions")
}

const PROXY_SERVER: &str = "127.0.0.1:8845";

/// %ProgramData%\SafePrompt\safeprompt-root-ca.pem existing is the same
/// signal installer/scripts/Install-TrustAndProxy.ps1 already gates on: it's
/// only written by apps/service when the license includes "browser_coverage"
/// (see that binary's load_connect_proxy_ca). Mirroring the gate here avoids
/// routing an unlicensed/core-only install's browser traffic through a
/// proxy with no CA trust behind it, which would just break their internet.
fn browser_coverage_active() -> bool {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(program_data).join("SafePrompt").join("safeprompt-root-ca.pem").exists()
}

/// `%ProgramData%\SafePrompt\extension-manual-install-needed.txt` -- dropped
/// by installer/scripts/Install-ExtensionForceInstall.ps1 when the machine
/// isn't domain/Intune-managed, so Chrome/Edge refuse the silent
/// force-install and the browser extension has to be loaded by hand once.
/// The local console already surfaces a full how-to banner keyed off the
/// same marker (see local_api's `/ui/status` -> console.html
/// `#extension-banner`); this is just so a user who only ever sees the tray
/// icon still finds out there's a step left -- live-caught 2026-09-02, a
/// free install where the extension simply never appeared and nothing said
/// why.
fn extension_manual_install_needed() -> bool {
    let program_data = std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(program_data).join("SafePrompt").join("extension-manual-install-needed.txt").exists()
}

/// What, if anything, already owns this user's browser proxy before
/// SafePrompt touches it. Distinguishing these matters: blindly overwriting
/// `ProxyServer` -- the original behavior -- would silently replace an
/// enterprise's existing proxy/DLP/CASB stack for *all* browser traffic, not
/// just AI domains, breaking auth or violating policy on a real managed
/// endpoint. Live-flagged in review 2026-08-04.
enum ExistingProxy {
    /// No proxy configured (or it's already pointed at us -- idempotent
    /// re-run). Safe to enable SafePrompt's own proxy exactly as before.
    None,
    /// A GPO/Intune "Policies\...\Internet Settings" key exists. Per-user
    /// Internet Settings under a policy like this are either read-only or
    /// get silently reasserted on the next policy refresh -- writing our own
    /// values would either no-op or fight the policy engine. We back off
    /// entirely rather than guess; an admin needs to point the managed
    /// proxy/PAC at SafePrompt (or update the policy to chain through it)
    /// for AI-domain coverage to take effect here.
    ManagedByPolicy,
    /// A PAC (AutoConfigURL) is configured. PAC-aware chaining -- evaluating
    /// FindProxyForURL ourselves to decide the real upstream per request --
    /// isn't implemented yet, so we leave it alone rather than overwrite it
    /// with a static proxy that ignores whatever routing the PAC encoded.
    Pac(String),
    /// A manual proxy is already configured and it isn't us. We still take
    /// over `ProxyServer` (SafePrompt has to be in the path to inspect
    /// anything at all), but record this address so the CONNECT proxy
    /// chains every connection -- AI and non-AI alike -- through it instead
    /// of dialing the internet directly, preserving whatever that existing
    /// proxy was doing (auth, egress policy, logging) for the other 99% of
    /// traffic this agent doesn't even inspect.
    Manual(String),
}

const UPSTREAM_PROXY_ENV: &str = "ProgramData";

fn upstream_proxy_chain_file() -> PathBuf {
    let program_data = std::env::var(UPSTREAM_PROXY_ENV).unwrap_or_else(|_| "C:\\ProgramData".to_string());
    PathBuf::from(program_data).join("SafePrompt").join("upstream-proxy.txt")
}

/// A per-protocol `ProxyServer` value looks like `"http=10.0.0.1:80;https=10.0.0.1:8080"`;
/// a flat one is just `"10.0.0.1:8080"` used for every protocol. Only the
/// HTTPS entry matters here -- the CONNECT proxy only ever chains TLS
/// (port-443-style) destinations.
fn extract_https_proxy(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if !raw.contains('=') {
        return Some(raw.to_string());
    }
    raw.split(';').find_map(|part| part.trim().strip_prefix("https=")).map(|s| s.to_string())
}

fn detect_existing_proxy() -> ExistingProxy {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;

    if let Ok(policy_key) =
        RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey("SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
    {
        let manages_proxy = policy_key.get_value::<u32, _>("ProxySettingsPerUser").is_ok()
            || policy_key.get_value::<String, _>("ProxyServer").is_ok()
            || policy_key.get_value::<String, _>("AutoConfigURL").is_ok()
            || policy_key.get_value::<u32, _>("ProxyEnable").is_ok();
        if manages_proxy {
            return ExistingProxy::ManagedByPolicy;
        }
    }

    let Ok(settings) = RegKey::predef(HKEY_CURRENT_USER).open_subkey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings")
    else {
        return ExistingProxy::None;
    };

    if let Ok(pac_url) = settings.get_value::<String, _>("AutoConfigURL") {
        if !pac_url.trim().is_empty() {
            return ExistingProxy::Pac(pac_url);
        }
    }

    let proxy_enabled = settings.get_value::<u32, _>("ProxyEnable").unwrap_or(0) == 1;
    if proxy_enabled {
        if let Ok(raw) = settings.get_value::<String, _>("ProxyServer") {
            if let Some(https_proxy) = extract_https_proxy(&raw) {
                if https_proxy != PROXY_SERVER {
                    return ExistingProxy::Manual(https_proxy);
                }
            }
        }
    }

    ExistingProxy::None
}

/// Ensures Chrome/Edge/Firefox (which read the per-user WinINet proxy
/// setting under HKCU, not the machine-wide WinHTTP default the installer
/// also sets) are routed through the CONNECT proxy -- chaining through
/// whatever proxy already owned this connection rather than replacing it,
/// see `ExistingProxy`.
///
/// Run once at every tray startup -- i.e. every login -- rather than only at
/// install time. The installer's own SYSTEM-context attempt at this
/// (WTSQueryUserToken/CreateProcessAsUser impersonating the logged-on user,
/// see installer/scripts/Invoke-AsLoggedOnUser.ps1) proved unreliable in
/// practice: live-confirmed 2026-08-04, ERROR_INVALID_NAME on every install
/// across several different Win32 API variants (CreateProcessAsUser with and
/// without lpDesktop, CreateProcessWithTokenW), despite the token/privilege/
/// environment-block setup all being individually correct. This process, in
/// contrast, already runs natively as the real logged-on user (launched via
/// the HKLM Run key), so it writes its own HKCU directly -- no cross-session
/// token dance at all. As a side effect this also covers the installer's
/// pre-existing known gap of someone logging in *after* install, since this
/// now runs at every login rather than only once during setup.
fn ensure_user_proxy_enabled() {
    if !browser_coverage_active() {
        return;
    }

    match detect_existing_proxy() {
        ExistingProxy::ManagedByPolicy => {
            tracing::warn!(
                "browser proxy is managed by Group Policy/Intune -- leaving it alone; AI-domain traffic won't route \
                 through SafePrompt until the managed policy itself points at SafePrompt or chains through it"
            );
            return;
        }
        ExistingProxy::Pac(pac_url) => {
            tracing::warn!(pac_url, "a PAC script is already configured -- leaving it alone; PAC-aware chaining isn't implemented yet");
            return;
        }
        ExistingProxy::Manual(existing) => {
            tracing::info!(existing_proxy = %existing, "existing manual proxy detected -- SafePrompt will chain every connection through it");
            let _ = std::fs::create_dir_all(upstream_proxy_chain_file().parent().expect("chain file always has a parent"));
            let _ = std::fs::write(upstream_proxy_chain_file(), &existing);
        }
        ExistingProxy::None => {
            let _ = std::fs::remove_file(upstream_proxy_chain_file());
        }
    }

    use winreg::enums::{HKEY_CURRENT_USER, KEY_SET_VALUE};
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let Ok((key, _)) = hkcu.create_subkey_with_flags(
        "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
        KEY_SET_VALUE,
    ) else {
        return;
    };
    let _ = key.set_value("ProxyServer", &PROXY_SERVER);
    let _ = key.set_value("ProxyOverride", &"<local>");
    let _ = key.set_value("ProxyEnable", &1u32);

    // WinINet-based apps only pick up a registry-only change on their next
    // restart without these -- same InternetSetOption dance
    // installer/scripts/Set-UserProxy.ps1 already does.
    unsafe {
        notify_wininet_settings_changed();
    }
}

#[link(name = "wininet")]
extern "system" {
    fn InternetSetOptionW(h_internet: *mut std::ffi::c_void, dw_option: u32, lp_buffer: *mut std::ffi::c_void, dw_buffer_length: u32) -> i32;
}

unsafe fn notify_wininet_settings_changed() {
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const INTERNET_OPTION_REFRESH: u32 = 37;
    InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null_mut(), 0);
    InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null_mut(), 0);
}

fn open_url(url: &str) {
    // Shelling out to `cmd /C start` rather than adding the `open` crate --
    // this binary only ever ships on Windows (see SafePrompt.wxs), so a
    // cross-platform crate would be dead weight here.
    let _ = std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn();
}

/// Whether the "⚠ Finish setup" call-to-action belongs in the menu right
/// now: browser coverage is licensed, the installer left the manual-install
/// marker (unmanaged machine, Chrome won't silently force-install), AND the
/// extension hasn't checked in yet. The moment it does -- `status.json`'s
/// `extension_detected` flips true -- this goes false and the menu is
/// rebuilt without the item, so it "vanishes" once setup is actually done.
fn show_finish_setup(status: &Status) -> bool {
    let detected = matches!(status, Status::Protected(_, true));
    browser_coverage_active() && extension_manual_install_needed() && !detected
}

/// The structural inputs that decide the menu's shape. Rebuilt only when
/// one of these changes (not every 2s poll) -- the status *line text* is
/// refreshed in place via `status_item` regardless.
#[derive(PartialEq, Clone)]
struct MenuShape {
    finish_setup: bool,
}

impl MenuShape {
    fn of(status: &Status) -> Self {
        Self { finish_setup: show_finish_setup(status) }
    }
}

struct TrayMenu {
    menu: Menu,
    status_item: MenuItem,
    console_id: MenuId,
    dashboard_id: MenuId,
    quit_id: MenuId,
}

fn build_menu(status: &Status) -> TrayMenu {
    let menu = Menu::new();

    let status_item = MenuItem::new(status_tooltip(status), false, None);
    let _ = menu.append(&status_item);
    let _ = menu.append(&PredefinedMenuItem::separator());

    // "Open Local Console" is always present -- the device-local view
    // (policy toggles, on-device history, detection testing, browser
    // extension setup) lives only there. While the one-time manual
    // extension step is still pending it takes on a call-to-action label
    // instead; same destination, the console carries the walkthrough.
    let console_label = if status.finish_setup_pending() {
        "\u{26a0} Finish setup: install browser extension"
    } else {
        "Open Local Console"
    };
    let console_item = MenuItem::new(console_label, true, None);

    // "Open Dashboard" is always present too and always points at the cloud
    // account portal (safeprompt.pro), on every edition -- see
    // `resolve_dashboard_url`.
    let dashboard_item = MenuItem::new("Open Dashboard", true, None);

    let quit_item = MenuItem::new("Exit", true, None);

    let _ = menu.append(&console_item);
    let _ = menu.append(&dashboard_item);
    let _ = menu.append(&PredefinedMenuItem::separator());
    let _ = menu.append(&quit_item);

    TrayMenu {
        console_id: console_item.id().clone(),
        dashboard_id: dashboard_item.id().clone(),
        quit_id: quit_item.id().clone(),
        status_item,
        menu,
    }
}

impl Status {
    fn finish_setup_pending(&self) -> bool {
        show_finish_setup(self)
    }
}

fn main() {
    tracing_subscriber::fmt::init();

    ensure_user_proxy_enabled();
    show_first_run_notice_if_needed();

    let initial_status = read_status();
    let mut shape = MenuShape::of(&initial_status);
    let mut tray_menu = build_menu(&initial_status);

    // tao's own event loop, not tokio -- tray-icon needs a native Win32
    // message pump to receive menu-click/tray events, which is exactly what
    // tao provides (the same crate Tauri's own tray support is built on).
    let event_loop = EventLoopBuilder::new().build();

    let mut tray_icon = Some(
        TrayIconBuilder::new()
            .with_menu(Box::new(tray_menu.menu.clone()))
            .with_tooltip(status_tooltip(&initial_status))
            .with_icon(load_icon())
            .build()
            .expect("failed to create tray icon"),
    );

    let mut last_poll = Instant::now() - POLL_INTERVAL;

    event_loop.run(move |_event, _, control_flow| {
        // Poll on a timer rather than reacting to filesystem events -- the
        // status file changes every 2s regardless (see apps/watchdog), so a
        // filesystem watcher would be strictly more complexity for the same
        // observed latency.
        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(250));

        if last_poll.elapsed() >= POLL_INTERVAL {
            last_poll = Instant::now();
            let status = read_status();

            // Rebuild the whole menu only when its shape changes -- e.g. the
            // browser extension finally checks in, so "⚠ Finish setup"
            // should disappear and become plain "Open Local Console".
            let new_shape = MenuShape::of(&status);
            if new_shape != shape {
                shape = new_shape;
                tray_menu = build_menu(&status);
                if let Some(tray) = &tray_icon {
                    let _ = tray.set_menu(Some(Box::new(tray_menu.menu.clone())));
                }
            }

            tray_menu.status_item.set_text(status_tooltip(&status));
            if let Some(tray) = &tray_icon {
                let _ = tray.set_tooltip(Some(status_tooltip(&status)));
            }
        }

        if let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == tray_menu.quit_id {
                tray_icon.take(); // drop it explicitly so the icon disappears immediately, not on process exit
                *control_flow = ControlFlow::Exit;
            } else if event.id == tray_menu.dashboard_id {
                open_url(&resolve_dashboard_url(status_edition(&read_status())));
            } else if event.id == tray_menu.console_id {
                // Always the local console -- its "Browser Extension" tab
                // carries the full "load unpacked from C:\Program Files\
                // SafePrompt\extension\unpacked" walkthrough plus live
                // detection status.
                open_url(&local_console_url());
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_https_entry_from_a_per_protocol_proxy_string() {
        assert_eq!(
            extract_https_proxy("http=10.0.0.1:80;https=10.0.0.1:8080;ftp=10.0.0.1:21"),
            Some("10.0.0.1:8080".to_string())
        );
    }

    #[test]
    fn treats_a_flat_proxy_string_as_covering_every_protocol() {
        assert_eq!(extract_https_proxy("10.0.0.1:8080"), Some("10.0.0.1:8080".to_string()));
    }

    #[test]
    fn finds_nothing_when_the_per_protocol_string_has_no_https_entry() {
        assert_eq!(extract_https_proxy("http=10.0.0.1:80;ftp=10.0.0.1:21"), None);
    }

    #[test]
    fn treats_an_empty_proxy_string_as_none() {
        assert_eq!(extract_https_proxy(""), None);
        assert_eq!(extract_https_proxy("   "), None);
    }

    /// All scenarios in one test, same reasoning as apps/service's own
    /// `control_plane_url_tests`: this reads/writes process-global env
    /// vars, which would race across parallel test threads if split into
    /// separate `#[test]` fns.
    #[test]
    fn dashboard_url_resolution_covers_every_case() {
        std::env::remove_var("SAFEPROMPT_DASHBOARD_URL");
        std::env::remove_var("SAFEPROMPT_CONTROL_PLANE_URL");
        std::env::remove_var("SAFEPROMPT_LOCAL_API_BIND_ADDR");

        let paid = Some("Business");

        // Nothing configured -> the public SaaS default, on EVERY edition.
        // "Open Dashboard" is the cloud account portal for Community too now
        // (a Community user has a real safeprompt.pro workspace); the
        // device-local view is a separate "Open Local Console" menu item.
        assert_eq!(resolve_dashboard_url(paid), DEFAULT_DASHBOARD_URL);
        assert_eq!(resolve_dashboard_url(Some("community")), DEFAULT_DASHBOARD_URL);
        assert_eq!(resolve_dashboard_url(Some("Community")), DEFAULT_DASHBOARD_URL);
        assert_eq!(resolve_dashboard_url(None), DEFAULT_DASHBOARD_URL);

        // Control Plane configured, paid edition, no explicit dashboard
        // override -> derived from it (the on-prem/private-deployment case).
        std::env::set_var("SAFEPROMPT_CONTROL_PLANE_URL", "http://localhost:8000");
        assert_eq!(resolve_dashboard_url(paid), "http://localhost:8000/dashboard");

        // A trailing slash on the Control Plane URL must not produce a
        // doubled slash in the derived dashboard URL.
        std::env::set_var("SAFEPROMPT_CONTROL_PLANE_URL", "http://localhost:8000/");
        assert_eq!(resolve_dashboard_url(paid), "http://localhost:8000/dashboard");

        // Explicit SAFEPROMPT_DASHBOARD_URL wins outright, even with a
        // Control Plane also configured; used verbatim, no path appended.
        std::env::set_var("SAFEPROMPT_DASHBOARD_URL", "https://dash.mycompany.internal/agent-portal");
        assert_eq!(resolve_dashboard_url(paid), "https://dash.mycompany.internal/agent-portal");
        assert_eq!(resolve_dashboard_url(Some("community")), "https://dash.mycompany.internal/agent-portal");

        // A malformed override (no scheme) falls through to the next
        // priority level rather than opening garbage.
        std::env::set_var("SAFEPROMPT_DASHBOARD_URL", "not a url");
        assert_eq!(resolve_dashboard_url(paid), "http://localhost:8000/dashboard", "a malformed SAFEPROMPT_DASHBOARD_URL must fall through, not open garbage");

        // A malformed Control Plane URL too -> a paid edition falls all the
        // way back to the public SaaS default, never a panic or an empty
        // string.
        std::env::set_var("SAFEPROMPT_CONTROL_PLANE_URL", "not a url either");
        assert_eq!(resolve_dashboard_url(paid), DEFAULT_DASHBOARD_URL);

        std::env::remove_var("SAFEPROMPT_DASHBOARD_URL");
        std::env::remove_var("SAFEPROMPT_CONTROL_PLANE_URL");
    }
}
