// Functional checks for background.js's dynamic AI-site sync logic (item
// #6, 2026-08-05) -- run with: node scripts/test-site-sync-logic.mjs
//
// Same marker-extraction approach as test-extraction-logic.mjs: pulls the
// real syncDynamicSites()/dynamicScriptIds()/fetchPolicyDomains() functions
// out of background.js by locating stable markers, not a hand-copied
// duplicate. chrome.scripting/chrome.permissions/fetch are mocked here
// since background.js only runs inside a real extension service worker --
// the mocks record calls so each check can assert on exactly what the real
// logic decided to do.
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";
import vm from "vm";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = readFileSync(path.join(root, "src", "background.js"), "utf8");

const START_MARKER = "const SITE_SYNC_ALARM";
const END_MARKER = "chrome.alarms.onAlarm.addListener((alarm) => {\n  if (alarm.name === SITE_SYNC_ALARM)";
const start = src.indexOf(START_MARKER);
const end = src.indexOf(END_MARKER);
if (start === -1 || end === -1 || end <= start) {
  throw new Error(
    `Could not locate the site-sync logic block in background.js ` +
      `(markers "${START_MARKER}" / "${END_MARKER}" not found in the expected order) -- ` +
      `the file was restructured; update these markers to match.`
  );
}
const logicSource = src.slice(start, end);

let failures = 0;
function assert(cond, msg) {
  if (cond) {
    console.log("ok - " + msg);
  } else {
    failures++;
    console.error("FAIL - " + msg);
  }
}

// Builds a fresh sandbox per check -- registered/permission state must not
// leak between checks the way it wouldn't between real service-worker ticks.
function makeSandbox({ policyDomains, registered = [], grantedOrigins = [], fetchThrows = false }) {
  const registeredScripts = registered.map((id) => ({ id }));
  const calls = { registered: [], unregistered: [] };

  const sandbox = {
    // Real background.js defines these above the extracted block (shared
    // with the heartbeat/inspect logic too) -- the marker slice below
    // intentionally starts after that, so the test has to supply them.
    getAgentConfig: async () => ({ mode: "local", base: "http://127.0.0.1:8847", sharedSecret: null }),
    localApiHeaders: (config, extra) => ({ ...(extra || {}), ...(config.sharedSecret ? { "X-SafePrompt-Shared-Secret": config.sharedSecret } : {}) }),
    fetch: async (url) => {
      if (fetchThrows) throw new Error("agent unreachable");
      if (url.endsWith("/v1/policy/applications")) {
        return { ok: true, json: async () => ({ domains: policyDomains }) };
      }
      throw new Error("unexpected fetch: " + url);
    },
    chrome: {
      scripting: {
        getRegisteredContentScripts: async () => registeredScripts,
        registerContentScripts: async (defs) => {
          calls.registered.push(...defs);
          registeredScripts.push(...defs.map((d) => ({ id: d.id })));
        },
        unregisterContentScripts: async ({ ids }) => {
          calls.unregistered.push(...ids);
        },
      },
      permissions: {
        contains: async ({ origins }) => origins.every((o) => grantedOrigins.includes(o)),
      },
    },
    console,
  };
  vm.createContext(sandbox);
  vm.runInContext(logicSource + "\nglobalThis.syncDynamicSites = syncDynamicSites;", sandbox);
  return { sandbox, calls };
}

// --- Static built-in domains never generate a dynamic registration ---
{
  const { sandbox, calls } = makeSandbox({ policyDomains: ["chatgpt.com", "claude.ai", "gemini.google.com"] });
  await sandbox.syncDynamicSites();
  assert(calls.registered.length === 0, "the 5 built-in platforms never get dynamically (re-)registered");
}

// --- A custom domain WITH granted permission gets registered (main + bridge) ---
{
  const { sandbox, calls } = makeSandbox({
    policyDomains: ["chatgpt.com", "llm.internal.example.com"],
    grantedOrigins: ["https://llm.internal.example.com/*", "https://*.llm.internal.example.com/*"],
  });
  await sandbox.syncDynamicSites();
  assert(calls.registered.length === 2, "a granted custom domain registers exactly 2 content scripts (main + bridge)");
  const mainEntry = calls.registered.find((d) => d.world === "MAIN");
  assert(!!mainEntry && mainEntry.js[0] === "src/main-world-interceptor.js", "the MAIN-world entry points at main-world-interceptor.js");
  const bridgeEntry = calls.registered.find((d) => d.world !== "MAIN");
  assert(!!bridgeEntry && bridgeEntry.js[0] === "src/bridge-content-script.js", "the isolated-world entry points at bridge-content-script.js");
  assert(
    mainEntry.matches.includes("https://llm.internal.example.com/*") && mainEntry.matches.includes("https://*.llm.internal.example.com/*"),
    "both the exact domain and its subdomains are covered by the match pattern"
  );
}

// --- A custom domain WITHOUT granted permission is skipped quietly, not thrown ---
{
  const { sandbox, calls } = makeSandbox({
    policyDomains: ["chatgpt.com", "llm.internal.example.com"],
    grantedOrigins: [], // no GPO/Intune push, no user consent
  });
  await sandbox.syncDynamicSites(); // must not throw
  assert(calls.registered.length === 0, "an ungranted custom domain is skipped, not registered");
}

// --- A domain the tenant admin removed from policy gets unregistered ---
{
  const { sandbox, calls } = makeSandbox({
    policyDomains: ["chatgpt.com"], // no longer includes the custom domain
    registered: ["safeprompt-dynamic-llm.internal.example.com-main", "safeprompt-dynamic-llm.internal.example.com-bridge"],
  });
  await sandbox.syncDynamicSites();
  assert(
    calls.unregistered.includes("safeprompt-dynamic-llm.internal.example.com-main") &&
      calls.unregistered.includes("safeprompt-dynamic-llm.internal.example.com-bridge"),
    "a domain dropped from policy has both its content scripts unregistered"
  );
}

// --- An already-registered custom domain is not re-registered every tick ---
{
  const { sandbox, calls } = makeSandbox({
    policyDomains: ["chatgpt.com", "llm.internal.example.com"],
    grantedOrigins: ["https://llm.internal.example.com/*", "https://*.llm.internal.example.com/*"],
    registered: ["safeprompt-dynamic-llm.internal.example.com-main", "safeprompt-dynamic-llm.internal.example.com-bridge"],
  });
  await sandbox.syncDynamicSites();
  assert(calls.registered.length === 0, "a domain already registered on a prior tick is left alone, not duplicated");
  assert(calls.unregistered.length === 0, "a domain still present in policy is not unregistered");
}

// --- Agent unreachable: must not throw, must not touch existing registrations ---
{
  const { sandbox, calls } = makeSandbox({
    policyDomains: [],
    fetchThrows: true,
    registered: ["safeprompt-dynamic-llm.internal.example.com-main", "safeprompt-dynamic-llm.internal.example.com-bridge"],
  });
  await sandbox.syncDynamicSites(); // must not throw
  assert(calls.registered.length === 0 && calls.unregistered.length === 0, "an unreachable agent leaves existing registrations untouched");
}

if (failures > 0) {
  console.error(`\n${failures} check(s) FAILED`);
  process.exit(1);
} else {
  console.log("\nAll site-sync logic checks passed.");
}
