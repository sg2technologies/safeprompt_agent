// Isolated-world content script (default world -- deliberately NOT "MAIN",
// unlike main-world-interceptor.js). Its only job is relaying scan requests
// from the MAIN-world interceptor (which can't call chrome.runtime.*) to
// background.js (which can) and back, via window.postMessage on one side
// and chrome.runtime.sendMessage on the other.
(function () {
  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== "safeprompt-main-world") return;

    // filename/dataBase64 (AGENT-FILE-002) are only present for a
    // "inspect-file" message -- forwarded alongside text/requestId rather
    // than branching here, so this relay stays a dumb pass-through and
    // doesn't need updating again the next time a new inspect-* kind shows
    // up on either side of it.
    //
    // 2026-09-03: `domain` -- real user report, the local console's
    // History tab and every persisted DlpEvent showed "unknown" for
    // app/site on every single row. main-world-interceptor.js runs in the
    // page's own MAIN world and can't call chrome.runtime.* to look this
    // up itself, but THIS script (isolated world, same page/tab) shares
    // the exact same `window.location` as the page it's injected into --
    // simplest to read it here rather than threading it through the
    // MAIN-world postMessage payload too.
    try {
      chrome.runtime.sendMessage({ kind: data.kind, text: data.text, filename: data.filename, dataBase64: data.dataBase64, domain: window.location.hostname }, (response) => {
        // chrome.runtime.lastError fires if the background worker is
        // unreachable (e.g. the extension is reloading) -- same fail-open
        // posture as a timeout in the MAIN-world interceptor.
        const result = chrome.runtime.lastError ? null : response;
        window.postMessage({ source: "safeprompt-bridge-response", requestId: data.requestId, result }, "*");
      });
    } catch (_e) {
      // Fixed 2026-09-05 (live-caught: "Uncaught Error: Extension context
      // invalidated" on chatgpt.com): chrome.runtime.sendMessage can also
      // throw SYNCHRONOUSLY, not just set chrome.runtime.lastError -- this
      // happens when the extension's own context is invalidated (e.g. this
      // content script is still alive in a tab that was already open when
      // the extension got reloaded/updated/disabled). Same fail-open
      // posture as the lastError branch above, just reached via the
      // synchronous path -- without this catch, the exception stopped
      // execution before the response postMessage ever fired, so the
      // waiting askAgent()/askAgentFile() promise in
      // main-world-interceptor.js sat until its own 5s/20s timeout instead
      // of failing open immediately, on every scan attempt from a stale
      // tab.
      window.postMessage({ source: "safeprompt-bridge-response", requestId: data.requestId, result: null }, "*");
    }
  });
})();
