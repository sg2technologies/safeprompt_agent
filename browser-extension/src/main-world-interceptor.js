// Runs in the page's own JS context ("world": "MAIN" in manifest.json) --
// not the isolated content-script world -- because it has to patch the
// REAL window.fetch/XMLHttpRequest the page's own code calls, before the
// page has a chance to grab a reference to the originals. This is the piece
// that makes network-level bot detection (Cloudflare et al.) irrelevant:
// the actual outgoing request still leaves the real browser with the real
// browser's TLS fingerprint -- we only inspect the body before it's sent,
// nothing about the connection itself changes.
//
// MAIN-world code can't call chrome.runtime.* directly (no extension APIs
// there), so scan requests are relayed via window.postMessage to
// bridge-content-script.js (isolated world, same page) -> background.js
// (service worker, real chrome-extension:// origin) -> the local agent API.
// See safeprompt-local-api's own doc comment for why that hop matters for
// auth (a service worker's fetch, unlike a page-context one, isn't subject
// to CORS and carries an unforgeable Origin header).
(function () {
  const RESPONSE_TIMEOUT_MS = 5000;
  // File/image scanning runs OCR + document extraction, which is far slower
  // than a text scan -- a passport photo alone is a couple of seconds. A
  // longer wait here is well worth it: the alternative on timeout is the
  // file leaving the machine unscanned.
  const FILE_RESPONSE_TIMEOUT_MS = 20000;
  let requestCounter = 0;
  const pending = new Map();

  window.addEventListener("message", (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== "safeprompt-bridge-response") return;
    const entry = pending.get(data.requestId);
    if (!entry) return;
    pending.delete(data.requestId);
    entry.resolve(data.result);
  });

  // Fail OPEN (resolve null -> caller passes the request through
  // unmodified) rather than closed when the agent is slow/unreachable --
  // e.g. not installed, not running, or unlicensed for browser_coverage.
  // Deliberate tradeoff: a security scanner that's temporarily unreachable
  // should degrade to "unprotected, same as before this extension existed"
  // rather than "the user's AI chat site stops working entirely." Revisit
  // if a stricter deployment posture is ever needed.
  function askAgent(kind, text) {
    return new Promise((resolve) => {
      const requestId = `sp-${Date.now()}-${requestCounter++}`;
      const timeout = setTimeout(() => {
        pending.delete(requestId);
        log(`askAgent(${kind}) timed out after ${RESPONSE_TIMEOUT_MS}ms -- failing open (request/response passes through unscanned). Check: is the agent running? Is something (a CSP, an ad blocker) blocking this page from reaching http://127.0.0.1:8847?`);
        resolve(null);
      }, RESPONSE_TIMEOUT_MS);
      pending.set(requestId, {
        resolve: (result) => {
          clearTimeout(timeout);
          resolve(result);
        },
      });
      window.postMessage({ source: "safeprompt-main-world", kind, text, requestId }, "*");
    });
  }

  // AGENT-FILE-002 (2026-08-11): a file/image attached directly in the
  // ChatGPT/Claude web UI is sent as multipart/form-data, i.e. `init.body`
  // is a FormData instance, never a string -- which is exactly what the
  // "not a POST-with-string-body" bail-out below this used to skip
  // entirely, before this fix existed. Same fail-open posture and 5s
  // timeout as askAgent above, just carrying file bytes instead of text.
  function askAgentFile(filename, dataBase64) {
    return new Promise((resolve) => {
      const requestId = `sp-${Date.now()}-${requestCounter++}`;
      const timeout = setTimeout(() => {
        pending.delete(requestId);
        log(`askAgentFile(${filename}) timed out after ${FILE_RESPONSE_TIMEOUT_MS}ms -- failing open (file passes through unscanned)`);
        resolve(null);
      }, FILE_RESPONSE_TIMEOUT_MS);
      pending.set(requestId, {
        resolve: (result) => {
          clearTimeout(timeout);
          resolve(result);
        },
      });
      window.postMessage({ source: "safeprompt-main-world", kind: "inspect-file", filename, dataBase64, requestId }, "*");
    });
  }

  // readAsDataURL does the binary->base64 conversion natively rather than
  // building a giant string with String.fromCharCode(...bytes) here, which
  // risks blowing the call stack on anything beyond a few hundred KB.
  function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result; // "data:<mime>;base64,<data>"
        const commaIdx = typeof result === "string" ? result.indexOf(",") : -1;
        resolve(commaIdx >= 0 ? result.slice(commaIdx + 1) : result);
      };
      reader.onerror = () => reject(reader.error);
      reader.readAsDataURL(file);
    });
  }

  // Keep in step with safeprompt-local-api's own 25MB post-base64-inflation
  // body cap -- 20MB of raw file comes to ~27MB base64, so this stays
  // comfortably under that rather than discovering the mismatch as a
  // confusing 413 at request time.
  const MAX_SCANNED_FILE_BYTES = 20 * 1024 * 1024;

  // AGENT-FILE-003 (2026-09-02, user-reported: a passport image uploaded to
  // ChatGPT went straight through). ChatGPT and Claude no longer upload an
  // attached image as `multipart/form-data` -- they POST to get a
  // pre-signed URL, then `PUT` the RAW bytes (a Blob/ArrayBuffer body) to
  // blob storage. That PUT is a `fetch`, so this interceptor sees it, but
  // the old code only ever handled a FormData body or a string body and let
  // everything else fall straight through. `scanBinaryUpload` covers the
  // raw-bytes case: guess the file type from the Blob's `.type` / the
  // request's Content-Type, base64 it, and run it through the same
  // /v1/inspect-file path the FormData scanner already uses.
  const MIME_TO_EXT = {
    "image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg", "image/webp": "webp",
    "image/gif": "gif", "image/bmp": "bmp", "image/tiff": "tif", "image/tif": "tif",
    "application/pdf": "pdf", "text/plain": "txt", "text/csv": "csv",
    "text/markdown": "md", "application/json": "json",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "docx",
    "application/msword": "doc",
  };

  function isBinaryBody(body) {
    return (
      body instanceof Blob ||
      body instanceof ArrayBuffer ||
      (typeof ArrayBuffer !== "undefined" && ArrayBuffer.isView && ArrayBuffer.isView(body))
    );
  }

  function headerValue(headers, name) {
    if (!headers) return null;
    try {
      if (typeof headers.get === "function") return headers.get(name);
      const lower = name.toLowerCase();
      for (const k of Object.keys(headers)) if (k.toLowerCase() === lower) return headers[k];
    } catch (_e) { /* fall through */ }
    return null;
  }

  function guessUploadExt(body, contentType) {
    const ct = ((body && body.type) || contentType || "").split(";")[0].trim().toLowerCase();
    return MIME_TO_EXT[ct] || (ct.startsWith("image/") ? "png" : "bin");
  }

  async function bodyToBase64(body) {
    const blob = body instanceof Blob ? body : new Blob([body]);
    return readFileAsBase64(blob);
  }

  function bodyByteLength(body) {
    if (body instanceof Blob) return body.size;
    if (body instanceof ArrayBuffer) return body.byteLength;
    if (ArrayBuffer.isView && ArrayBuffer.isView(body)) return body.byteLength;
    return 0;
  }

  /// 2026-09-03: a Redact verdict on a file is no longer always upgraded
  /// to Block server-side -- for plain-text formats (see local_api's
  /// `is_text_redactable_extension`) the agent now returns a real masked
  /// version in `sanitized_prompt`, safe to send in place of the original
  /// bytes (the file's whole content IS its text, nothing else to lose).
  /// For anything it can't safely mask (docx/pdf/images/...), the agent
  /// applies the policy's `unmaskable_file_action` instead and sets
  /// `unmaskable_reason` explaining why "Mask it" wasn't honored --
  /// surfaced in the toast so this doesn't look like a policy mismatch or
  /// a bug (real user report: "i defined mask it, it works block").
  function redactedFileFromVerdict(verdict, filename, mimeType) {
    if (!verdict || verdict.action !== "Redact" || typeof verdict.sanitized_prompt !== "string") return null;
    return new File([verdict.sanitized_prompt], filename, { type: mimeType || "text/plain" });
  }

  function fileToastMessage(verdict, findings) {
    if (verdict && verdict.unmaskable_reason) {
      return [outcomeStyleFor(verdict.action), `SafePrompt: ${verdict.unmaskable_reason}`];
    }
    if (verdict && verdict.action === "Redact") {
      return ["redact", `SafePrompt masked ${describeFindings(findings)} in an uploaded file before sending`];
    }
    return ["block", `Blocked by SafePrompt: ${describeFindings(findings)} detected in an uploaded file`];
  }

  function outcomeStyleFor(action) {
    if (action === "Block" || action === "RequireApproval") return "block";
    if (action === "Redact") return "redact";
    if (action === "Audit") return "audit";
    return "warn"; // Warn, or an unrecognized/missing action
  }

  /// Returns { blocked, redactedFile, toast, findings }. `redactedFile`
  /// (a `File`) is set only when a plain-text upload was actually masked
  /// in place -- the caller substitutes it for the original body before
  /// letting the request through. Fail-open on anything unexpected
  /// (oversized, unreadable, timed-out verdict) -- same posture as the
  /// FormData scanner.
  async function scanBinaryUpload(body, contentType, url) {
    try {
      const size = bodyByteLength(body);
      if (size === 0 || size > MAX_SCANNED_FILE_BYTES) {
        log("binary upload not scanned", { url, size, reason: size ? "over cap" : "empty" });
        return { blocked: false };
      }
      const ext = guessUploadExt(body, contentType);
      const filename = `upload.${ext}`;
      log("binary upload -> inspecting", { url, filename, size });
      const dataBase64 = await bodyToBase64(body);
      const verdict = await askAgentFile(filename, dataBase64);
      log("binary upload <- verdict", { url, filename, action: verdict && verdict.action, findings: safeFindings(verdict && verdict.findings), unmaskable_reason: verdict && verdict.unmaskable_reason });
      const outcome = verdictOutcome(verdict);
      if (outcome.stop) {
        return { blocked: true, findings: (verdict && verdict.findings) || [], toast: fileToastMessage(verdict, verdict && verdict.findings) };
      }
      const redactedFile = redactedFileFromVerdict(verdict, filename, contentType);
      if (redactedFile) {
        return { blocked: false, redactedFile, toast: fileToastMessage(verdict, verdict.findings) };
      }
      if (verdict && verdict.unmaskable_reason) {
        // Fallback action resolved to something non-blocking (Warn/Audit/
        // Allow) -- still worth telling the user why "Mask it" didn't
        // actually mask this particular upload.
        return { blocked: false, toast: fileToastMessage(verdict, verdict.findings) };
      }
      return { blocked: false };
    } catch (e) {
      log("binary upload scan errored -- failing open", { url, error: String(e) });
      return { blocked: false };
    }
  }

  // Scans every File a FormData body carries, one at a time -- not
  // reassembled into a single multipart parse here, that's local_api's
  // job on the other end. ANY file triggering Block cancels the whole
  // request (mirrors scan_multipart_request's "Redact upgrades to Block":
  // there's no safe way to pull just one file back out of a FormData and
  // still represent what the user actually tried to send). A Redact
  // verdict on a plain-text file, in contrast, replaces just that one
  // entry in place and keeps scanning the rest -- masking is expected to
  // coexist with other clean files in the same upload.
  async function scanFormDataFiles(formData) {
    let toast = null;
    for (const [key, value] of Array.from(formData.entries())) {
      if (!(value instanceof File) || value.size === 0) continue;
      if (value.size > MAX_SCANNED_FILE_BYTES) {
        log("fetch (file) skipped -- larger than the scannable cap", { name: value.name, size: value.size });
        continue; // fail open on an oversized file rather than block on size alone
      }
      let dataBase64;
      try {
        dataBase64 = await readFileAsBase64(value);
      } catch (e) {
        log("fetch (file) skipped -- could not read file bytes", { name: value.name, error: String(e) });
        continue;
      }
      log("fetch (file) -> inspecting", { name: value.name, size: value.size });
      const verdict = await askAgentFile(value.name, dataBase64);
      log("fetch (file) <- verdict", { name: value.name, action: verdict && verdict.action, findings: safeFindings(verdict && verdict.findings), unmaskable_reason: verdict && verdict.unmaskable_reason });
      if (verdict && (verdict.action === "Block" || verdict.action === "RequireApproval")) {
        return { blocked: true, findings: verdict.findings, toast: fileToastMessage(verdict, verdict.findings) };
      }
      const redactedFile = redactedFileFromVerdict(verdict, value.name, value.type);
      if (redactedFile) {
        formData.set(key, redactedFile); // replaces just this entry -- other clean files/fields are untouched
        toast = fileToastMessage(verdict, verdict.findings);
      } else if (verdict && verdict.unmaskable_reason) {
        toast = fileToastMessage(verdict, verdict.findings);
      }
    }
    return { blocked: false, toast };
  }

  // A blocked/redacted request used to be indistinguishable from the AI
  // site just being broken -- e.g. a raw "Failed to fetch" makes ChatGPT
  // show its own generic "Something went wrong" error, with nothing
  // anywhere saying SafePrompt did that on purpose. This renders a small,
  // self-contained toast so the user (and anyone screen-sharing/support-
  // ticketing over their shoulder) can tell "blocked by policy" apart from
  // "the site is down." Shadow DOM, closed off from the page: an AI chat
  // site's own CSS can't accidentally hide/restyle it, and its own JS can't
  // easily query into it either. Deliberately built with DOM APIs + one
  // `.textContent` assignment for the dynamic part, not string-concatenated
  // innerHTML, so there's no HTML-injection surface even though today's
  // `match_name` values are always static scanner-authored strings.
  const FRIENDLY_FINDING_NAMES = {
    AWS_ACCESS_KEY: "AWS access key",
    OPENAI_API_KEY: "OpenAI API key",
    ANTHROPIC_API_KEY: "Anthropic API key",
    GCP_API_KEY: "GCP API key",
    AZURE_SECRET: "Azure secret",
    PASSWORD_CONTEXT: "password",
    DB_CONNECTION_STRING: "database connection string",
    JWT_BEARER_TOKEN: "JWT / bearer token",
    PRIVATE_RSA_KEY: "private key",
    CRYPTO_WALLET: "crypto wallet address",
  };

  function describeFindings(findings) {
    if (!findings || findings.length === 0) return "sensitive content";
    const names = [...new Set(findings.map((f) => FRIENDLY_FINDING_NAMES[f.match_name] || f.match_name.replace(/_/g, " ").toLowerCase()))];
    return names.join(", ");
  }

  let toastHost = null;
  let toastShadow = null; // kept explicitly -- mode:"closed" makes toastHost.shadowRoot null even to this same script
  let toastHideTimer = null;

  function removeToast() {
    if (toastHost) toastHost.remove();
    toastHost = null;
    toastShadow = null;
  }

  // Positioned bottom-center, hovering just above where every one of
  // these sites' own message input box sits -- ported from the old
  // extension/'s `.sp-overlay` (`position: fixed; bottom: 90px; left: 50%;
  // transform: translateX(-50%)`), ADOPTED 2026-08-05 per direct user
  // feedback after two earlier attempts (a small corner toast, then a
  // full-width top banner) that this same old extension's placement --
  // right where the user is already looking immediately after hitting
  // send -- read as "part of the chat" instead of a generic browser
  // notification, and that's what actually made it feel unmistakably
  // intentional rather than the site being broken. Block does not
  // auto-dismiss (the user must close it) since the whole point is not
  // being missed; Redact keeps a short auto-dismiss since it's
  // informational, not a "did my message go through" moment.
  // Built entirely with createElement/textContent -- deliberately NOT
  // `shadow.innerHTML = ...templateString...`, even though a closed shadow
  // root already isolates it from the page's own styles/scripts. Live-
  // caught 2026-08-05: Gemini (and evidently Claude) enforce a Trusted
  // Types CSP (`require-trusted-types-for 'script'`), which blocks *any*
  // direct `.innerHTML` assignment page-wide, including inside a shadow
  // root attached to that same document -- Trusted Types is a document-
  // level policy, not scoped away by shadow DOM boundaries. That silently
  // threw "This document requires 'TrustedHTML' assignment" and killed the
  // toast entirely on those sites, with no visible symptom other than
  // "nothing appeared" -- the user only ever saw the site's own error.
  // `textContent`/attribute/style-property assignment are exempt from
  // Trusted Types (only innerHTML/outerHTML/document.write require a
  // TrustedHTML value), so building the DOM programmatically sidesteps the
  // whole restriction rather than registering a TrustedTypes policy (which
  // a strict site could itself refuse to allow via its own CSP anyway).
  function showToast(kind, message) {
    try {
      const root = (document.body || document.documentElement);
      if (!root) return; // document_start on a document with no root yet -- nothing to attach to
      if (!toastHost) {
        toastHost = document.createElement("div");
        toastShadow = toastHost.attachShadow({ mode: "closed" });
        root.appendChild(toastHost);
      }
      const shadow = toastShadow;
      shadow.textContent = ""; // clear any previous render
      // block   -> the message was stopped (Block, and RequireApproval which
      //            has no approval queue yet so it fails closed the same way)
      // redact  -> values were masked before sending
      // warn    -> sent unchanged, but flagged (Warn)
      // audit   -> sent unchanged, recorded for audit (Audit)
      const KIND_STYLE = {
        block:  { accent: "#dc2626", icon: "⛔", sticky: true },
        redact: { accent: "#d97706", icon: "✏️", sticky: false },
        warn:   { accent: "#d97706", icon: "⚠️", sticky: false },
        audit:  { accent: "#6b7280", icon: "👁️", sticky: false },
      };
      const style = KIND_STYLE[kind] || KIND_STYLE.redact;
      const isBlock = kind === "block";
      const accent = style.accent;
      const icon = style.icon;

      const toast = document.createElement("div");
      toast.setAttribute("role", "alert");
      Object.assign(toast.style, {
        all: "initial",
        position: "fixed",
        bottom: "90px",
        left: "50%",
        transform: "translateX(-50%)",
        zIndex: "2147483647",
        width: "min(480px, 92vw)",
        display: "flex",
        alignItems: "flex-start",
        gap: "10px",
        padding: "14px 16px",
        font: '14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
        background: "#1f2937",
        color: "#f9fafb",
        borderLeft: `4px solid ${accent}`,
        borderRadius: "12px",
        boxShadow: "0 12px 40px rgba(0,0,0,0.3), 0 0 0 1px rgba(0,0,0,0.05)",
      });

      const iconEl = document.createElement("span");
      Object.assign(iconEl.style, { fontSize: "18px", flex: "none", lineHeight: "1.4" });
      iconEl.textContent = icon;

      const textCol = document.createElement("span");
      textCol.style.flex = "1";

      const title = document.createElement("div");
      title.style.fontWeight = "700";
      title.textContent = message;
      textCol.appendChild(title);

      if (isBlock) {
        const subtext = document.createElement("div");
        Object.assign(subtext.style, { color: "#d1d5db", fontWeight: "400", marginTop: "4px", fontSize: "12px" });
        subtext.textContent = "Nothing was sent. Any error shown by the site is expected — it just means the request never went out.";
        textCol.appendChild(subtext);
      }

      const closeBtn = document.createElement("button");
      closeBtn.setAttribute("aria-label", "Dismiss");
      Object.assign(closeBtn.style, {
        all: "unset",
        cursor: "pointer",
        color: "#9ca3af",
        fontSize: "18px",
        lineHeight: "1",
        padding: "0 4px",
        flex: "none",
      });
      closeBtn.textContent = "×";
      closeBtn.addEventListener("click", () => removeToast());
      closeBtn.addEventListener("mouseenter", () => { closeBtn.style.color = "#f9fafb"; });
      closeBtn.addEventListener("mouseleave", () => { closeBtn.style.color = "#9ca3af"; });

      toast.append(iconEl, textCol, closeBtn);
      shadow.appendChild(toast);

      clearTimeout(toastHideTimer);
      if (!style.sticky) {
        toastHideTimer = setTimeout(removeToast, 8000);
      }
    } catch (_e) {
      // Never let the notification UI itself break the actual block/redact
      // decision above/below it -- that's already been enforced by the time
      // this runs.
    }
  }

  // These chat sites' actual network payload is a JSON envelope, not just
  // the message you typed -- ChatGPT's alone includes message/conversation
  // UUIDs, timezone offsets, screen dimensions, and other client telemetry
  // alongside the real text. Scanning that whole raw body (what this did
  // before 2026-08-05) means any long token in that metadata can trip a
  // loose heuristic -- confirmed live: a plain "my aws key is
  // AKIA...EXAMPLE" message produced a false "crypto wallet address, phone
  // number detected" block, from fields that were never anything the user
  // typed. The pre-network-interception extension/ avoided this entirely by
  // reading the visible input box directly via a hardcoded per-site CSS
  // selector map -- precise, but brittle (breaks every time a site changes
  // its DOM) and exactly what moving to fetch/XHR interception was meant to
  // get away from. This keeps the network-level approach (site-agnostic,
  // catches programmatic sends too) but only trusts well-known
  // content-bearing key names within the JSON -- covers ChatGPT's
  // messages[].content.parts[] and the {role, content} shape most other
  // providers use -- rather than the raw serialized blob. Falls back to
  // scanning (and, for redaction, replacing) the whole body when the shape
  // isn't recognized, which is exactly today's pre-fix behavior, so an
  // unrecognized site is no worse off than before.
  const CONTENT_KEY_NAMES = new Set(["parts", "prompt", "text", "message", "query", "input", "content"]);

  // `inArrayContentKey`: whether the array *containing* `node` was itself
  // reached via a content key name (e.g. "parts"). Array elements have no
  // key of their own (only a numeric index, never a member of
  // CONTENT_KEY_NAMES), so that "content-ness" has to be threaded through
  // from the array's own key rather than re-derived per element -- without
  // this, `parts: ["the actual message"]` is silently never matched at all,
  // since the string's `key` parameter would be its array index, not
  // "parts". Object traversal deliberately does NOT inherit this the same
  // way: a content-object's own sub-keys (e.g. ChatGPT's `content:
  // {content_type, parts}`) must be re-evaluated on their own key names,
  // not swept in wholesale just because their parent object's key matched.
  function collectContentLocations(node, parent, key, inArrayContentKey, out) {
    if (typeof node === "string") {
      const isContent = (key !== null && CONTENT_KEY_NAMES.has(key)) || inArrayContentKey;
      if (isContent) out.push({ parent, key });
      return;
    }
    if (Array.isArray(node)) {
      const arrayIsContent = key !== null && CONTENT_KEY_NAMES.has(key);
      node.forEach((item, i) => collectContentLocations(item, node, i, arrayIsContent, out));
      return;
    }
    if (node && typeof node === "object") {
      for (const k of Object.keys(node)) collectContentLocations(node[k], node, k, false, out);
    }
  }

  /// URL-decodes defensively before falling back to whole-body scanning --
  /// added 2026-08-05 after live-confirming Gemini's actual request body is
  /// `application/x-www-form-urlencoded` (`f.req=<url-encoded-JSON>&at=...`),
  /// not JSON. A percent-encoded space ("%20") is three literal characters
  /// -- '%', '2', '0' -- and '0' is a word character, so an AWS key sitting
  /// right after "...s%20AKIA..." never matched `\bAKIA...`: there's no
  /// actual word/non-word transition for `\b` to fire on, just a digit
  /// touching a letter. Decoding first restores real spaces/quotes so word
  /// boundaries mean what they're supposed to. Safe to apply unconditionally:
  /// text with no '%' sequences round-trips through decodeURIComponent
  /// unchanged, and a malformed sequence (a literal '%' in real content)
  /// throws, caught here, falling back to the original un-decoded text
  /// rather than losing the scan entirely.
  function safeUrlDecode(s) {
    try {
      return decodeURIComponent(s);
    } catch (_e) {
      return s;
    }
  }

  /// Returns { text, parsed, locations }. `parsed` is set whenever the
  /// body is valid JSON at all -- even with zero recognized content
  /// fields -- specifically so applyRedaction below can tell "valid JSON,
  /// nothing recognized" apart from "not JSON at all" and never corrupt a
  /// real API call's structure just because it can't cleanly redact it.
  function extractScannable(rawBody) {
    let parsed;
    try {
      parsed = JSON.parse(rawBody);
    } catch (_e) {
      return { text: safeUrlDecode(rawBody), parsed: null, locations: [] }; // not JSON (form/plain-text body)
    }
    const locations = [];
    collectContentLocations(parsed, null, null, false, locations);
    const text = locations.length > 0 ? locations.map((loc) => loc.parent[loc.key]).join("\n") : safeUrlDecode(rawBody);
    return { text, parsed, locations };
  }

  /// Substituting a single combined `sanitizedPrompt` back into the JSON is
  /// only unambiguous when exactly one content field was found (the
  /// overwhelmingly common case: one message per request).
  ///
  /// Live-caught 2026-08-05, and this is the important part: zero or
  /// multiple recognized fields used to fall back to replacing the *entire*
  /// body with the plain sanitized string -- fine for a real chat message,
  /// but this whole-body-fallback path is what *every* unrecognized JSON
  /// shape hits, which in practice turned out to be overwhelmingly a
  /// site's own first-party/analytics telemetry (Segment/Amplitude relay
  /// endpoints, Datadog RUM, etc.), not user content at all. Silently
  /// replacing a well-formed analytics payload with a bare string broke
  /// those calls outright -- live-confirmed on claude.ai as repeated
  /// "TypeError: Failed to fetch" from the site's *own* telemetry/query
  /// client, not the block path, cascading into "We couldn't connect to
  /// Claude" because enough of the app's own plumbing depends on those
  /// calls succeeding.
  ///
  /// Fixed: if the body parsed as JSON at all, always return valid JSON
  /// back -- either the one field substituted, or (0/2+ recognized fields)
  /// the parsed object re-serialized completely unmodified, i.e. redaction
  /// is skipped rather than risking corruption. This is a deliberate
  /// trade-off, not an oversight: a genuine secret sitting in a multi-field
  /// request we can't safely rewrite now passes through unredacted instead
  /// of corrupting the request. Only a non-JSON body (no structure to
  /// preserve either way -- e.g. Gemini's form-urlencoded shape) still
  /// gets the whole-body string replace, the same pre-existing, stated
  /// scope limit as before.
  function applyRedaction(extracted, sanitizedPrompt) {
    if (extracted.locations.length === 1) {
      const { parent, key } = extracted.locations[0];
      parent[key] = sanitizedPrompt;
      return JSON.stringify(extracted.parsed);
    }
    if (extracted.parsed !== null) {
      return JSON.stringify(extracted.parsed); // valid JSON, nothing safely redactable -- pass through unmodified rather than corrupt it
    }
    return sanitizedPrompt;
  }

  /// Whether applyRedaction(extracted, ...) actually changes anything --
  /// callers use this to decide whether "SafePrompt redacted ..." is a true
  /// statement (single-location JSON substitution, or a non-JSON whole-body
  /// replace) versus a silent unmodified pass-through (valid JSON, nothing
  /// safely redactable) that must NOT claim to have redacted anything.
  function wasRedactionApplied(extracted) {
    return extracted.locations.length === 1 || extracted.parsed === null;
  }

  /// Turn the agent's ScanResult into what this interception site should do.
  /// The agent reports the policy DECISION; each enforcement point decides
  /// how to act on it -- mirroring agent/crates/common
  /// Action::enforcement_action. Before this, only "Block" and "Redact"
  /// were handled and Warn / Audit / RequireApproval all fell through as a
  /// silent allow (live-reported 2026-09-02: "hold for approval passes the
  /// email", "warn shows no message"). RequireApproval has no approval
  /// queue yet (SP-RISK-004) so it fails closed to a stop, exactly like
  /// Block.
  function verdictOutcome(verdict) {
    const action = verdict && verdict.action;
    const what = describeFindings(verdict && verdict.findings);
    switch (action) {
      case "Block":
        return { stop: true, redact: false, toast: ["block", `Blocked by SafePrompt: ${what} detected`] };
      case "RequireApproval":
        return { stop: true, redact: false, toast: ["block", `Held by SafePrompt for approval: ${what} — not sent`] };
      case "Redact":
        return { stop: false, redact: true, toast: ["redact", `SafePrompt redacted ${what} before sending`] };
      case "Warn":
        return { stop: false, redact: false, toast: ["warn", `SafePrompt flagged ${what} — sent anyway`] };
      case "Audit":
        return { stop: false, redact: false, toast: ["audit", `SafePrompt logged ${what} for audit`] };
      default: // Allow, or a null / timed-out verdict
        return { stop: false, redact: false, toast: null };
    }
  }

  // Visible-by-default console.log (not console.debug, which Chrome hides
  // unless "Verbose" level is explicitly enabled) at every real decision
  // point -- added 2026-08-05 after several rounds of remote debugging
  // where "is this even running, and on what" turned out to be the actual
  // open question, not the scanning logic itself. Never passed scanned
  // text or a raw Finding here (see safeFindings below) -- this is a DLP
  // tool, logging the exact secrets it's supposed to protect to a console
  // anyone with devtools access can read would be its own leak.
  //
  // Fixed 2026-09-05: this used to call a `truncate(text, 200)` helper and
  // log the first 200 chars of the scanned body directly, plus the raw
  // `verdict.findings` array untouched. Both were real leaks -- 200 chars
  // is plenty to carry a full password or API key, and each Finding's
  // `snippet` field (agent/crates/common::Finding) is the complete,
  // untruncated matched text, not a masked preview. Callers now pass only
  // counts (extractedLocations, characterCount) and safeFindings(...)
  // output instead of the text/findings themselves.
  function log(...args) {
    console.log("[SafePrompt]", ...args);
  }
  // Strips a ScanResult's findings down to what's safe to print: the
  // detector category/label and severity (e.g. "AWS_SECRET_KEY" / "HIGH"),
  // never `snippet` (the raw matched secret/PII value) or
  // `redacted_replacement` (still derived from it).
  //
  // Fixed 2026-09-05 (code review, same day as the fix above): `match_name`
  // is a safe static label for every category EXCEPT CustomKeyword, where
  // the agent sets it to the literal tenant-configured keyword/codename
  // itself (agent/crates/inspector::scan_custom_keywords --
  // `match_name: rule.pattern.clone()`, e.g. a confidential project name).
  // Logging that would leak exactly the term this category exists to
  // catch, so it's dropped for that one category.
  function safeFindings(findings) {
    return Array.isArray(findings)
      ? findings.map((f) => ({
          category: f && f.category,
          match_name: f && f.category === "CustomKeyword" ? undefined : f.match_name,
          severity: f && f.severity,
        }))
      : findings;
  }

  const originalFetch = window.fetch.bind(window);

  window.fetch = async function safePromptFetch(input, init) {
    const isRequestObj = typeof Request !== "undefined" && input instanceof Request;
    const method = ((init && init.method) || (isRequestObj && input.method) || "GET").toUpperCase();
    const url = typeof input === "string" ? input : input && input.url;

    // A `fetch(new Request(url, { method:"PUT", body: blob }))` -- the body
    // lives on the Request, not `init`. Read it (via a clone, so the real
    // request still has its body) and scan the same way.
    if (isRequestObj && !init && (method === "PUT" || method === "POST")) {
      try {
        const buf = await input.clone().arrayBuffer();
        if (buf && buf.byteLength > 0 && buf.byteLength <= MAX_SCANNED_FILE_BYTES) {
          const ct = headerValue(input.headers, "content-type") || "";
          // Only treat it as a file if it isn't obviously JSON/text/form.
          if (!/json|x-www-form-urlencoded|multipart/i.test(ct)) {
            const result = await scanBinaryUpload(buf, ct, url);
            if (result.blocked) {
              showToast(result.toast[0], result.toast[1]);
              throw new TypeError("Failed to fetch");
            }
            if (result.toast) showToast(result.toast[0], result.toast[1]);
            if (result.redactedFile) {
              // A masked file was produced -- rebuild the Request with the
              // redacted body in place of the original; every other
              // property (method, headers, ...) carries over unchanged.
              input = new Request(input, { body: result.redactedFile });
            }
          }
        }
      } catch (e) {
        if (e instanceof TypeError && e.message === "Failed to fetch") throw e;
        log("Request-object upload scan errored -- failing open", { url, error: String(e) });
      }
      return originalFetch(input, init);
    }

    if (method === "POST" && init && init.body instanceof FormData) {
      const result = await scanFormDataFiles(init.body);
      if (result.blocked) {
        showToast(result.toast[0], result.toast[1]);
        throw new TypeError("Failed to fetch");
      }
      if (result.toast) showToast(result.toast[0], result.toast[1]);
      // Clean, or a plain-text entry was masked in place above -- either
      // way `init.body` is already what should go out; no attempt to
      // redact bytes inside a non-text file and still have it decode as
      // that file type, same call scan_multipart_request already makes on
      // the connect_proxy side.
      const response = await originalFetch(input, init);
      return maybeScanResponse(response, askAgent);
    }

    // Raw-bytes upload (ChatGPT/Claude pre-signed-URL flow -- see
    // scanBinaryUpload's own comment). Either method; the body is a
    // Blob/ArrayBuffer, never FormData or a string.
    if ((method === "PUT" || method === "POST") && init && isBinaryBody(init.body)) {
      const ct = ((init.body && init.body.type) || headerValue(init.headers, "content-type") || "").toLowerCase();
      if (!/json|x-www-form-urlencoded|multipart/i.test(ct)) {
        const result = await scanBinaryUpload(init.body, ct, url);
        if (result.blocked) {
          showToast(result.toast[0], result.toast[1]);
          throw new TypeError("Failed to fetch");
        }
        if (result.toast) showToast(result.toast[0], result.toast[1]);
        if (result.redactedFile) {
          init = { ...init, body: result.redactedFile };
        }
      }
      return originalFetch(input, init);
    }

    if (method !== "POST" || !init || typeof init.body !== "string") {
      log("fetch skipped (not a POST-with-string-body)", { url, method, bodyType: init && typeof init.body });
      return originalFetch(input, init);
    }

    const extracted = extractScannable(init.body);
    log("fetch -> inspecting", { url, extractedLocations: extracted.locations.length, characterCount: extracted.text.length });
    const verdict = await askAgent("inspect", extracted.text);
    log("fetch <- verdict", { url, action: verdict && verdict.action, findings: safeFindings(verdict && verdict.findings) });
    const outcome = verdictOutcome(verdict);
    if (outcome.stop) {
      showToast(outcome.toast[0], outcome.toast[1]);
      // Mirrors a real network failure -- the page's own error handling
      // (already built to cope with dropped connections) takes it from
      // there, rather than us inventing a bespoke error UI per site.
      throw new TypeError("Failed to fetch");
    }

    let outgoingInit = init;
    if (outcome.redact && verdict.sanitized_prompt) {
      outgoingInit = { ...init, body: applyRedaction(extracted, verdict.sanitized_prompt) };
      if (wasRedactionApplied(extracted)) {
        showToast(outcome.toast[0], outcome.toast[1]);
      }
    } else if (outcome.toast) {
      showToast(outcome.toast[0], outcome.toast[1]); // Warn / Audit -- sent, but flagged
    }

    const response = await originalFetch(input, outgoingInit);
    return maybeScanResponse(response, askAgent);
  };

  async function maybeScanResponse(response, ask) {
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("json") && !contentType.includes("text/")) {
      return response; // binary/streaming/unknown -- don't buffer it
    }
    let text;
    try {
      text = await response.clone().text();
    } catch (_e) {
      return response; // not actually buffer-able (e.g. a streamed body) -- pass through
    }
    if (!text) return response;

    const extracted = extractScannable(text);
    const verdict = await ask("inspect-response", extracted.text);
    const outcome = verdictOutcome(verdict);
    if (outcome.stop) {
      showToast(outcome.toast[0], `${outcome.toast[1]} (in the AI response)`);
      return new Response(JSON.stringify({ error: { message: "Response blocked by SafePrompt policy" } }), {
        status: 403,
        headers: { "content-type": "application/json" },
      });
    }
    if (outcome.redact && verdict.sanitized_prompt) {
      if (wasRedactionApplied(extracted)) {
        showToast("redact", `SafePrompt redacted ${describeFindings(verdict.findings)} from the response`);
      }
      return new Response(applyRedaction(extracted, verdict.sanitized_prompt), {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
    }
    if (outcome.toast) {
      showToast(outcome.toast[0], `${outcome.toast[1]} (in the AI response)`); // Warn / Audit
    }
    return response;
  }

  // XHR: best-effort, request-side only. The AI sites this ships for today
  // (ChatGPT, Claude, Gemini, Perplexity, Grok) all predominantly use fetch
  // for their chat calls -- this covers older/incidental XHR usage without
  // the added complexity of rewriting response getters, which fetch's
  // Response object already gives us for free above.
  const OriginalXHR = window.XMLHttpRequest;

  function SafePromptXHR() {
    const xhr = new OriginalXHR();
    let method = "GET";

    const originalOpen = xhr.open.bind(xhr);
    xhr.open = function (m, ...rest) {
      method = m;
      return originalOpen(m, ...rest);
    };

    const originalSend = xhr.send.bind(xhr);
    xhr.send = function (body) {
      if (method.toUpperCase() === "POST" && body instanceof FormData) {
        scanFormDataFiles(body).then((result) => {
          if (result.blocked) {
            showToast(result.toast[0], result.toast[1]);
            xhr.dispatchEvent(new Event("error"));
            return;
          }
          if (result.toast) showToast(result.toast[0], result.toast[1]);
          originalSend(body); // masked entries (if any) are already set in place on `body`
        });
        return;
      }
      const m = method.toUpperCase();
      if ((m === "PUT" || m === "POST") && isBinaryBody(body)) {
        scanBinaryUpload(body, body && body.type, "(xhr)").then((result) => {
          if (result.blocked) {
            showToast(result.toast[0], result.toast[1]);
            xhr.dispatchEvent(new Event("error"));
            return;
          }
          if (result.toast) showToast(result.toast[0], result.toast[1]);
          originalSend(result.redactedFile || body);
        });
        return;
      }
      if (m !== "POST" || typeof body !== "string") {
        log("XHR skipped (not a POST-with-string-body)", { method, bodyType: typeof body });
        return originalSend(body);
      }
      const extracted = extractScannable(body);
      log("XHR -> inspecting", { extractedLocations: extracted.locations.length, characterCount: extracted.text.length });
      askAgent("inspect", extracted.text).then((verdict) => {
        log("XHR <- verdict", { action: verdict && verdict.action, findings: safeFindings(verdict && verdict.findings) });
        const outcome = verdictOutcome(verdict);
        if (outcome.stop) {
          showToast(outcome.toast[0], outcome.toast[1]);
          xhr.dispatchEvent(new Event("error"));
          return;
        }
        let outgoing = body;
        if (outcome.redact && verdict.sanitized_prompt) {
          outgoing = applyRedaction(extracted, verdict.sanitized_prompt);
          if (wasRedactionApplied(extracted)) {
            showToast(outcome.toast[0], outcome.toast[1]);
          }
        } else if (outcome.toast) {
          showToast(outcome.toast[0], outcome.toast[1]); // Warn / Audit
        }
        originalSend(outgoing);
      });
    };

    return xhr;
  }
  SafePromptXHR.prototype = OriginalXHR.prototype;
  window.XMLHttpRequest = SafePromptXHR;

  // Second, earlier layer, added 2026-08-05 in direct response to user
  // feedback: a Block via the network layer above still means the site's
  // own JS *attempted* the send and had to handle a thrown "Failed to
  // fetch" itself -- which is where ChatGPT's "Something went wrong" /
  // Gemini's/Claude's own generic errors came from. That's cosmetic (the
  // block itself was always correct), but it reads as "the tool is
  // broken." The pre-network-interception extension/ never had this
  // problem: it intercepted the Enter keydown / Send-button click itself,
  // in the capture phase, before the site's own handler ever ran -- so on
  // a block, the site never attempts a network call at all, and therefore
  // never has anything to show an error about. Ported that same pattern
  // here, calling into the exact same askAgent/showToast/local-agent
  // pipeline as the network layer (not a separate detection path). This
  // is intentionally a second, imperfect layer on top of the first, not a
  // replacement for it: per-site CSS selectors are inherently fragile
  // (break when a site redesigns its input UI) in a way network
  // interception isn't, so the fetch/XHR patching above stays as the
  // reliable backstop -- if this layer's selectors go stale for a site,
  // that site simply falls back to today's behavior (network-level block,
  // site's own error visible) instead of silently going unprotected.
  const PLATFORMS = [
    { hostnames: ["chatgpt.com", "openai.com"], inputSelector: "#prompt-textarea", submitSelector: '[data-testid="send-button"]', isContentEditable: true },
    {
      hostnames: ["claude.ai"],
      inputSelector: 'div[contenteditable="true"].ProseMirror, div[contenteditable="true"][data-placeholder]',
      submitSelector: 'button[aria-label="Send message"], button[aria-label="Send Message"]',
      isContentEditable: true,
    },
    { hostnames: ["gemini.google.com"], inputSelector: ".ql-editor, rich-textarea .ql-editor", submitSelector: 'button[aria-label="Send message"], button.send-button', isContentEditable: true },
    { hostnames: ["perplexity.ai"], inputSelector: 'textarea[placeholder], textarea.overflow-auto, textarea, [role="textbox"]', submitSelector: 'button[aria-label="Submit"]', isContentEditable: false },
    { hostnames: ["grok.com", "x.ai"], inputSelector: 'textarea, [role="textbox"], [contenteditable="true"]', submitSelector: "button", isContentEditable: false },
  ];

  function currentPlatform() {
    const host = location.hostname;
    return PLATFORMS.find((p) => p.hostnames.some((h) => host === h || host.endsWith("." + h))) || null;
  }

  function findActiveInput(platform, eventTarget) {
    for (const selector of platform.inputSelector.split(",").map((s) => s.trim())) {
      const el = document.querySelector(selector);
      if (el && (eventTarget === el || el.contains(eventTarget))) return el;
    }
    return null;
  }

  function getText(el, platform) {
    return (platform.isContentEditable ? el.textContent : el.value) || "";
  }

  // Sets text via the native value setter (bypassing React's own tracked
  // setter, same reason the old extension did this) so the site's own
  // framework actually notices the change, then fires a real "input"
  // event so it re-renders/re-validates -- a raw `.value = ...` assignment
  // alone is invisible to React-controlled inputs.
  function setText(el, platform, text) {
    if (!platform.isContentEditable) {
      const setter = Object.getOwnPropertyDescriptor(
        el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype,
        "value"
      )?.set;
      if (setter) {
        setter.call(el, text);
        el.dispatchEvent(new Event("input", { bubbles: true }));
      } else {
        el.value = text;
      }
      return;
    }
    el.focus();
    const range = document.createRange();
    range.selectNodeContents(el);
    const sel = window.getSelection();
    sel?.removeAllRanges();
    sel?.addRange(range);
    document.execCommand("insertText", false, text);
  }

  let bypassNextSubmit = false;

  function resubmit(el, platform) {
    bypassNextSubmit = true;
    const btn = platform.submitSelector ? document.querySelector(platform.submitSelector) : null;
    if (btn) {
      btn.click();
    } else {
      el.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", code: "Enter", keyCode: 13, which: 13, bubbles: true, cancelable: true }));
    }
  }

  async function interceptSubmit(e, el, platform) {
    e.preventDefault();
    e.stopImmediatePropagation();
    const text = getText(el, platform).trim();
    if (!text) return;
    log("UI intercept -> inspecting", { characterCount: text.length });
    const verdict = await askAgent("inspect", text);
    log("UI intercept <- verdict", { action: verdict && verdict.action, findings: safeFindings(verdict && verdict.findings) });
    const outcome = verdictOutcome(verdict);
    if (outcome.stop) {
      showToast(outcome.toast[0], outcome.toast[1]);
      return; // no resubmit -- the site's own send handler never runs, so it never has a failed request to show an error about
    }
    if (outcome.redact && verdict.sanitized_prompt) {
      setText(el, platform, verdict.sanitized_prompt);
      showToast(outcome.toast[0], outcome.toast[1]);
    } else if (outcome.toast) {
      showToast(outcome.toast[0], outcome.toast[1]); // Warn / Audit -- sent, but flagged
    }
    // Allow, Redact (text already replaced), Warn/Audit (flagged), or a
    // timed-out null verdict (fail open, same posture as askAgent's own doc
    // comment) all resubmit -- the network layer above scans it again
    // regardless, so a stale selector or a missed case here is never the
    // only check.
    resubmit(el, platform);
  }

  function attachSubmitInterceptor() {
    const platform = currentPlatform();
    if (!platform) return;

    document.addEventListener(
      "keydown",
      (e) => {
        if (e.key !== "Enter" || e.shiftKey) return;
        const el = findActiveInput(platform, e.target);
        if (!el) return;
        if (bypassNextSubmit) {
          bypassNextSubmit = false;
          return;
        }
        interceptSubmit(e, el, platform);
      },
      true // capture phase -- must run before the site's own listener
    );

    if (platform.submitSelector) {
      document.addEventListener(
        "click",
        (e) => {
          const btn = document.querySelector(platform.submitSelector);
          if (!btn || (e.target !== btn && !btn.contains(e.target))) return;
          if (bypassNextSubmit) {
            bypassNextSubmit = false;
            return;
          }
          const el = document.querySelector(platform.inputSelector.split(",")[0].trim());
          if (!el) return;
          interceptSubmit(e, el, platform);
        },
        true
      );
    }
  }

  attachSubmitInterceptor();
})();
