// MV3 service worker -- the only context in this extension with a real
// chrome-extension:// origin and a fetch that bypasses CORS entirely (given
// host_permissions), which is exactly what safeprompt-local-api relies on
// for auth (checking the Origin header). Everything here is a thin relay:
// receive {kind, text} from bridge-content-script.js, forward to the local
// agent, return its verdict.
const DEFAULT_AGENT_ENDPOINT = "http://127.0.0.1:8847";

// AGENT-COMM-001/002 (2026-08-10, renamed from the original "Item #1"
// 2026-08-05 localApiBase/localApiSharedSecret fields -- see schema.json's
// own doc comments for the full agentMode/agentEndpoint/agentSharedSecret
// story): SafePrompt has two real Agent deployment modes. 'local'
// (default, no managed policy configured at all -- the common, non-
// enterprise case): this device's own Agent at 127.0.0.1:8847. As of
// 2026-08-31 this still needs a shared secret -- the installer now writes
// one into managed storage itself (Install-ExtensionSharedSecret.ps1),
// same mechanism as an admin's GPO push, just self-configured for an
// unmanaged per-device install. 'central' (Business/Enterprise, configured
// via Chrome/
// Edge managed storage / GPO / Intune): every workstation's extension in
// the tenant points at ONE shared Agent elsewhere on the customer's own
// network instead -- agentSharedSecret is the real authentication that
// matters here, since local_api's Origin-header check alone isn't enough
// once a general network caller (not just this browser) can reach it. See
// agent/crates/local_api's with_shared_secret doc comment for the full
// signed-request scheme this now uses.
async function getAgentConfig() {
  try {
    const managed = await chrome.storage.managed.get(["agentMode", "agentEndpoint", "agentSharedSecret"]);
    const mode = managed.agentMode === "central" ? "central" : "local";
    const endpoint = (managed.agentEndpoint && managed.agentEndpoint.trim()) || DEFAULT_AGENT_ENDPOINT;
    return { mode, base: endpoint.replace(/\/+$/, ""), sharedSecret: managed.agentSharedSecret || null };
  } catch {
    // No managed policy schema configured for this extension at all -- the
    // common, non-enterprise case. Some browsers reject rather than just
    // returning {} in that situation, so this isn't just defensive filler.
    return { mode: "local", base: DEFAULT_AGENT_ENDPOINT, sharedSecret: null };
  }
}

// AGENT-COMM-004 (2026-08-10): signs the request instead of sending the
// shared secret itself in cleartext -- HMAC-SHA256 over "{timestamp}.
// {nonce}", matching agent/crates/local_api's compute_signature exactly
// (see that function's own doc comment for the full replay-protection
// reasoning). Web Crypto's sign() is Promise-based, so this is async --
// every call site below already awaits it.
async function signLocalApiRequest(secret, timestamp, nonce) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sigBytes = await crypto.subtle.sign("HMAC", key, enc.encode(`${timestamp}.${nonce}`));
  return Array.from(new Uint8Array(sigBytes))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// Merges the signed-request headers (when a shared secret is configured)
// into whatever headers a call site already needs -- every fetch to
// local_api goes through this so they can never be forgotten on just one
// of them, or drift out of sync with each other.
async function localApiHeaders(config, extra) {
  const headers = extra ? { ...extra } : {};
  if (config.sharedSecret) {
    const timestamp = Math.floor(Date.now() / 1000).toString();
    // crypto.randomUUID() is available in every MV3 service worker
    // (Chrome 92+/Edge 92+) -- no extra permission or dependency needed.
    const nonce = crypto.randomUUID();
    headers["X-SafePrompt-Timestamp"] = timestamp;
    headers["X-SafePrompt-Nonce"] = nonce;
    headers["X-SafePrompt-Signature"] = await signLocalApiRequest(config.sharedSecret, timestamp, nonce);
  }
  return headers;
}

// Profile-based license segregation (2026-09-01): a machine-wide
// ExtensionInstallForcelist policy installs this extension into EVERY
// Chrome/Edge profile on a machine, but until now the Agent had no way to
// tell those profiles apart -- device_fingerprint in backend/models/device.py
// hashes browser_name/os_name/os_version/screen_resolution, which are
// identical across every profile on the same machine, so two profiles
// collapsed into one identity. chrome.storage.local IS already isolated
// per profile (a separate instance of this service worker runs per
// profile even under a shared machine-wide install), so it's the right
// place for a stable per-profile id -- no new permission, works whether or
// not the profile is signed into a Google account. Generated once and
// cached in a module-level variable since storage.local's own read is
// itself async and every heartbeat tick would otherwise re-read it.
let cachedProfileId = null;

async function getProfileId() {
  if (cachedProfileId) return cachedProfileId;
  const stored = await chrome.storage.local.get(["profileId"]);
  if (stored.profileId) {
    cachedProfileId = stored.profileId;
    return cachedProfileId;
  }
  const id = crypto.randomUUID();
  await chrome.storage.local.set({ profileId: id });
  cachedProfileId = id;
  return id;
}

// Lets the Agent (and, from there, the tray icon and fleet checkins --
// see agent/crates/fleet::DeviceHealth::extension_detected) tell "extension
// installed and running" apart from "license permits browser coverage but
// nothing's actually there" -- the exact gap the 2026-08-05 Gemini/ChatGPT
// bug turned out to be. chrome.alarms, not setInterval: an MV3 service
// worker gets torn down after ~30s idle, so a plain interval timer would
// just stop firing silently once the worker is suspended; alarms wake it
// back up. 1 minute is the shortest period Chrome allows a packed/published
// extension to request (finer-grained periods are silently clamped to this
// in production, even if requested).
const HEARTBEAT_ALARM = "safeprompt-heartbeat";
const HEARTBEAT_PERIOD_MINUTES = 1;

async function sendHeartbeat() {
  const config = await getAgentConfig();
  const profileId = await getProfileId();
  const headers = await localApiHeaders(config, { "Content-Type": "application/json" });
  fetch(`${config.base}/v1/extension-heartbeat`, {
    method: "POST",
    headers,
    body: JSON.stringify({ profile_id: profileId }),
  })
    .then((resp) => {
      // 2026-09-04: this used to have no .then() at all -- a non-2xx
      // response (e.g. a 403 from an extension-origin mismatch) was
      // completely indistinguishable from success, since only a
      // network-level failure reaches .catch() below. Same loud-on-403
      // treatment as the inspect-request handler above, for the same
      // reason: "Extension not detected" in the console with no visible
      // cause is a much worse debugging experience than a named 403.
      if (!resp.ok && resp.status === 403) {
        console.error(
          `[SafePrompt] Heartbeat rejected (403) — the console will keep showing "not detected." ` +
          `This extension's ID is ${chrome.runtime.id}; make sure the Agent's ` +
          `SAFEPROMPT_EXTENSION_ORIGINS includes chrome-extension://${chrome.runtime.id}.`
        );
      }
    })
    .catch(() => {
      // Agent not installed/not running -- nothing to do here; the tray/fleet
      // side already treats a stale-or-missing heartbeat file as "not
      // detected" on its own, so silently skipping this tick is enough.
    });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === HEARTBEAT_ALARM) sendHeartbeat();
});

// Both fire on a normal browser start; onInstalled additionally covers a
// fresh install/update where onStartup never runs in the same session.
// create() with a periodInMinutes replaces any existing alarm of the same
// name, so this is safe to call from both without double-scheduling.
chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: HEARTBEAT_PERIOD_MINUTES });
  sendHeartbeat(); // don't make the tray wait a full minute for the first signal
});
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(HEARTBEAT_ALARM, { periodInMinutes: HEARTBEAT_PERIOD_MINUTES });
  sendHeartbeat();
});

// ── Dynamic AI-site coverage (item #6, 2026-08-05) ──────────────────────
// manifest.json's static content_scripts already cover the 5 built-in
// platforms (chatgpt/openai, claude/anthropic, gemini, perplexity, grok/
// x.ai) that main-world-interceptor.js's PLATFORMS list knows about -- that
// alone already satisfies Community's default max_ai_sites=5 cap, with no
// extra permission needed from anyone. This section handles domains BEYOND
// those 5: a tenant admin adds one to the signed policy's `applications`
// list (a policy-document change, not a code change -- see
// agent/crates/policy's own doc comment), the Agent serves the resulting
// list back capped to the license's max_ai_sites via
// GET /v1/policy/applications, and this reconciles that list against
// Chrome's dynamic `chrome.scripting` content-script registry so a new
// site lights up without a new extension build.
//
// This can only ever cover a domain the extension actually has host
// permission for. For an enterprise-managed install that's silent -- IT
// pushes the domain into `runtime_allowed_hosts` via a GPO/Intune policy
// (Business/Enterprise deployment tooling, not part of this repository),
// which grants permission regardless of what's in this manifest. Everyone
// else (BYOD/Community, no MDM) simply doesn't get custom domains covered
// yet: `chrome.permissions.contains` below comes back false, syncOneDomain
// quietly skips it, and nothing breaks. Self-service "add my own site"
// needs a popup UI + a user gesture (chrome.permissions.request can't run
// headless) -- not built yet.
const SITE_SYNC_ALARM = "safeprompt-site-sync";
const SITE_SYNC_PERIOD_MINUTES = 15;
const DYNAMIC_SCRIPT_ID_PREFIX = "safeprompt-dynamic-";
const STATIC_BUILTIN_DOMAINS = new Set([
  "chatgpt.com",
  "openai.com",
  "claude.ai",
  "anthropic.com",
  "gemini.google.com",
  "perplexity.ai",
  "grok.com",
  "x.ai",
]);

function dynamicScriptIds(domain) {
  return [`${DYNAMIC_SCRIPT_ID_PREFIX}${domain}-main`, `${DYNAMIC_SCRIPT_ID_PREFIX}${domain}-bridge`];
}

async function fetchPolicyDomains() {
  const config = await getAgentConfig();
  const headers = await localApiHeaders(config);
  const resp = await fetch(`${config.base}/v1/policy/applications`, { headers });
  if (!resp.ok) return []; // agent not running, or browser_coverage isn't licensed at all
  const body = await resp.json();
  return Array.isArray(body.domains) ? body.domains : [];
}

async function syncDynamicSites() {
  let domains;
  try {
    domains = await fetchPolicyDomains();
  } catch {
    return; // agent unreachable this tick -- leave whatever's already registered alone
  }

  const customDomains = domains.filter((d) => !STATIC_BUILTIN_DOMAINS.has(d));

  const existing = await chrome.scripting.getRegisteredContentScripts();
  const mainSuffix = "-main";
  const registeredDomains = new Set(
    existing
      .filter((s) => s.id.startsWith(DYNAMIC_SCRIPT_ID_PREFIX) && s.id.endsWith(mainSuffix))
      .map((s) => s.id.slice(DYNAMIC_SCRIPT_ID_PREFIX.length, -mainSuffix.length))
  );

  // Tenant admin removed a site from policy -- stop covering it.
  const toRemove = [...registeredDomains].filter((d) => !customDomains.includes(d));
  if (toRemove.length > 0) {
    const ids = toRemove.flatMap(dynamicScriptIds);
    await chrome.scripting.unregisterContentScripts({ ids }).catch(() => {});
  }

  // New domains from policy -- register anything we have permission for.
  for (const domain of customDomains) {
    if (registeredDomains.has(domain)) continue;
    const matches = [`https://${domain}/*`, `https://*.${domain}/*`];
    const hasPermission = await chrome.permissions.contains({ origins: matches }).catch(() => false);
    if (!hasPermission) continue; // not granted (no GPO/Intune push, no user consent) -- skip quietly

    const [mainId, bridgeId] = dynamicScriptIds(domain);
    try {
      await chrome.scripting.registerContentScripts([
        { id: mainId, matches, js: ["src/main-world-interceptor.js"], world: "MAIN", runAt: "document_start" },
        { id: bridgeId, matches, js: ["src/bridge-content-script.js"], runAt: "document_start" },
      ]);
    } catch (e) {
      // One malformed/duplicate entry shouldn't stop the rest of the sync.
      console.log("[SafePrompt] could not register dynamic content scripts for", domain, e);
    }
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === SITE_SYNC_ALARM) syncDynamicSites();
});
chrome.runtime.onStartup.addListener(() => {
  chrome.alarms.create(SITE_SYNC_ALARM, { periodInMinutes: SITE_SYNC_PERIOD_MINUTES });
  syncDynamicSites();
});
chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create(SITE_SYNC_ALARM, { periodInMinutes: SITE_SYNC_PERIOD_MINUTES });
  syncDynamicSites();
});

const INSPECT_MESSAGE_KINDS = new Set(["inspect", "inspect-response", "inspect-file"]);

function inspectRequestPath(kind) {
  if (kind === "inspect") return "/v1/inspect";
  if (kind === "inspect-response") return "/v1/inspect-response";
  return "/v1/inspect-file"; // AGENT-FILE-002
}

// AGENT-FILE-002: "inspect-file" carries { filename, dataBase64 } instead of
// { text } -- main-world-interceptor.js reads a File/Blob's bytes as an
// ArrayBuffer and base64-encodes them there (before this message channel),
// since chrome.runtime.sendMessage's structured-clone payload can carry an
// ArrayBuffer fine on its own, but keeping one small JSON shape for every
// inspect-* kind here (rather than branching on ArrayBuffer vs string) is
// simpler and mirrors safeprompt-local-api's own InspectFileRequest shape.
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (!message || !INSPECT_MESSAGE_KINDS.has(message.kind)) {
    return false; // not a message this extension sent to itself -- ignore
  }

  const path = inspectRequestPath(message.kind);
  // 2026-09-03: `domain` -- bridge-content-script.js reads its own page's
  // `window.location.hostname` and passes it straight through here, so
  // persisted DlpEvents (local console History tab, SaaS activity log)
  // show the real AI site instead of "unknown" for every single row.
  const body =
    message.kind === "inspect-file"
      ? { filename: message.filename, data_base64: message.dataBase64, domain: message.domain }
      : { text: message.text, domain: message.domain };

  (async () => {
    const config = await getAgentConfig();
    const headers = await localApiHeaders(config, { "Content-Type": "application/json" });
    fetch(`${config.base}${path}`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    })
      .then((resp) => {
        if (resp.ok) return resp.json();
        // 2026-09-04: a 403 here used to be silently indistinguishable
        // from "Agent not running" -- both just returned null and failed
        // open, which is correct behavior (a broken/unreachable Agent
        // shouldn't break browsing), but left a real, common
        // misconfiguration (SAFEPROMPT_EXTENSION_ORIGINS on the Agent not
        // including THIS extension's actual ID -- the default only
        // matches SG2's own signed build, not a from-source `Load
        // unpacked` install) completely invisible: the popup still shows
        // "Connected" (that check doesn't require the origin match), so
        // nothing ever looked wrong even though every single scan was
        // being silently skipped. Still fails open -- this only makes the
        // 403 case loud in the service worker console instead of mute.
        if (resp.status === 403) {
          console.error(
            `[SafePrompt] Agent rejected this request (403) — every prompt/file is currently going through UNSCANNED. ` +
            `Most likely cause: SAFEPROMPT_EXTENSION_ORIGINS on the Agent doesn't include this extension's real ID. ` +
            `This extension's ID is ${chrome.runtime.id}. Restart the Agent with ` +
            `SAFEPROMPT_EXTENSION_ORIGINS=chrome-extension://${chrome.runtime.id} — see the README's ` +
            `"Using it with your browser" section, step 4.`
          );
        }
        return null;
      })
      .then((result) => sendResponse(result))
      // Agent not installed or not running -- fail open, same posture as
      // everywhere else in this extension.
      .catch(() => sendResponse(null));
  })();

  return true; // keep the message channel open for the async sendResponse above
});
