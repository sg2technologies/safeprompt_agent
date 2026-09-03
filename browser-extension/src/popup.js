// Popup for the browser action icon. Deliberately thin -- it does not
// authenticate to anything or hold its own session; it just asks whatever
// Agent this device/extension already points at (LOCAL 127.0.0.1:8847, or a
// CENTRAL Agent under managed policy -- same agentMode/agentEndpoint config
// background.js reads, duplicated here rather than imported since a popup
// page and an MV3 service worker can't share a module without a bundler)
// what plan it's licensed for, via the unauthenticated GET /v1/status route
// (see agent/crates/local_api's status() -- edition is display-only, not a
// security boundary, same reasoning as the local console's /ui/status).
const DEFAULT_AGENT_ENDPOINT = "http://127.0.0.1:8847";

const PLAN_LABELS = {
  community: "Community",
  professional: "Professional",
  business: "Business",
  enterprise: "Enterprise",
};

async function getAgentBase() {
  try {
    const managed = await chrome.storage.managed.get(["agentEndpoint"]);
    const endpoint = (managed.agentEndpoint && managed.agentEndpoint.trim()) || DEFAULT_AGENT_ENDPOINT;
    return endpoint.replace(/\/+$/, "");
  } catch {
    // No managed schema configured -- the common, non-enterprise case.
    return DEFAULT_AGENT_ENDPOINT;
  }
}

function renderConnected(edition) {
  const dot = document.getElementById("agent-dot");
  const status = document.getElementById("agent-status");
  dot.className = "dot on";
  status.lastChild.textContent = "Connected";

  const key = (edition || "").toLowerCase();
  const label = PLAN_LABELS[key] || edition || "Unknown";
  document.getElementById("plan-row").style.display = "flex";
  document.getElementById("plan-pill").textContent = label;

  // Upsell for every edition except the one that already has everything.
  const upsell = document.getElementById("upsell");
  if (upsell && key !== "enterprise") upsell.style.display = "block";
}

function renderDisconnected() {
  const dot = document.getElementById("agent-dot");
  const status = document.getElementById("agent-status");
  dot.className = "dot off";
  status.lastChild.textContent = "Not found";
  document.getElementById("offline-help").style.display = "block";
}

// The local console (GET / on the same local_api port). Points at whatever
// Agent this extension already talks to -- the local one for an ordinary
// per-device install, or a CENTRAL Agent under managed policy. This is the
// only "dashboard" a Community / standalone user needs: status, live policy,
// and their own device's history are all served here with no login. (The
// cloud portal at safeprompt.pro is for fleet/team/license management on
// paid editions -- deliberately not linked from here.)
function wireConsoleLink(base) {
  const link = document.getElementById("console-link");
  if (!link) return;
  link.href = `${base.replace(/\/+$/, "")}/`;
  link.style.display = "block";
}

(async function init() {
  const base = await getAgentBase();
  try {
    const resp = await fetch(`${base}/v1/status`, { method: "GET" });
    if (!resp.ok) throw new Error(`status ${resp.status}`);
    const body = await resp.json();
    renderConnected(body.edition);
    wireConsoleLink(base);
  } catch {
    renderDisconnected();
  }
})();
