// Functional checks for the request/response scanning-extraction logic in
// main-world-interceptor.js -- run with: node scripts/test-extraction-logic.mjs
//
// That file is a browser-only IIFE (MAIN-world content script, no module
// exports, uses window/document) with no bundler/test framework in this
// project, so this pulls the pure-logic functions out of the real source
// by locating them between two stable markers and eval()s that slice --
// NOT a hand-copied duplicate, so a future edit to the real file is what
// this actually tests, not a snapshot that can drift out of sync with it.
// If the markers below ever stop matching (the surrounding code was
// restructured), this fails loudly with a clear error rather than silently
// testing stale logic.
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import path from "path";
import vm from "vm";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = readFileSync(path.join(root, "src", "main-world-interceptor.js"), "utf8");

const START_MARKER = "const CONTENT_KEY_NAMES";
const END_MARKER = "const originalFetch";
const start = src.indexOf(START_MARKER);
const end = src.indexOf(END_MARKER);
if (start === -1 || end === -1 || end <= start) {
  throw new Error(
    `Could not locate the extraction-logic block in main-world-interceptor.js ` +
      `(markers "${START_MARKER}" / "${END_MARKER}" not found in the expected order) -- ` +
      `the file was restructured; update these markers to match.`
  );
}
const logicSource = src.slice(start, end);

const sandbox = {};
vm.createContext(sandbox);
vm.runInContext(
  logicSource +
    "\nglobalThis.extractScannable = extractScannable; globalThis.applyRedaction = applyRedaction; globalThis.wasRedactionApplied = wasRedactionApplied;",
  sandbox
);
const { extractScannable, applyRedaction, wasRedactionApplied } = sandbox;

let failures = 0;
function assert(cond, msg) {
  if (cond) {
    console.log("ok - " + msg);
  } else {
    failures++;
    console.error("FAIL - " + msg);
  }
}

// --- ChatGPT-shaped JSON body: extraction excludes metadata, includes the secret ---
{
  const body = JSON.stringify({
    action: "next",
    messages: [
      {
        id: "c1a2b3c4-d5e6-4f78-9a0b-1c2d3e4f5678",
        author: { role: "user" },
        content: { content_type: "text", parts: ["my aws key is AKIAIOSFODNN7EXAMPLE"] },
      },
    ],
    parent_message_id: "9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0",
    conversation_id: "583aa39a-95c1-4f59-aa79-afffd1d73857",
    model: "auto",
    timezone_offset_min: -330,
    timezone: "Asia/Calcutta",
  });
  const extracted = extractScannable(body);
  assert(extracted.text.includes("AKIAIOSFODNN7EXAMPLE"), "ChatGPT shape: extracted text includes the actual AWS key");
  assert(!extracted.text.includes("583aa39a-95c1"), "ChatGPT shape: excludes the conversation_id UUID");
  assert(!extracted.text.includes("9f8e7d6c-5b4a"), "ChatGPT shape: excludes the parent_message_id UUID");
  assert(!extracted.text.includes("Asia/Calcutta"), "ChatGPT shape: excludes timezone metadata");
  assert(extracted.locations.length === 1, "ChatGPT shape: exactly one content location found");

  const redacted = JSON.parse(applyRedaction(extracted, "my aws key is [REDACTED_AWS_KEY]"));
  assert(redacted.messages[0].content.parts[0] === "my aws key is [REDACTED_AWS_KEY]", "ChatGPT shape: redaction hits the exact original field");
  assert(redacted.conversation_id === "583aa39a-95c1-4f59-aa79-afffd1d73857", "ChatGPT shape: redaction leaves conversation_id untouched");
}

// --- OpenAI-compatible {role, content} shape ---
{
  const body = JSON.stringify({
    model: "gpt-4",
    messages: [{ role: "user", content: "sk-ant-api03-abcdefghijklmnopqrstuvwx here" }],
    request_id: "req_1a2b3c4d5e6f7g8h9i0j",
  });
  const extracted = extractScannable(body);
  assert(extracted.text.includes("sk-ant-api03"), "OpenAI-compatible shape: content string captured");
  assert(!extracted.text.includes("req_1a2b3c4d5e6f7g8h9i0j"), "OpenAI-compatible shape: request_id excluded");
}

// --- Unrecognized JSON shape: still scans the whole body, but redaction ---
// --- must NOT corrupt the JSON structure (see next block for why) ---
{
  const body = JSON.stringify({ weirdField: "my aws key is AKIAIOSFODNN7EXAMPLE" });
  const extracted = extractScannable(body);
  assert(extracted.text === body, "unrecognized shape: falls back to scanning the whole raw body");
  assert(extracted.locations.length === 0, "unrecognized shape: reports zero locations");
  assert(!wasRedactionApplied(extracted), "unrecognized JSON shape: redaction is correctly reported as not applied");
  const result = JSON.parse(applyRedaction(extracted, "[REDACTED]"));
  assert(result.weirdField === "my aws key is AKIAIOSFODNN7EXAMPLE", "unrecognized JSON shape: redact is skipped, original JSON passed through unmodified rather than corrupted");
}

// --- Regression: valid JSON telemetry payload must never be corrupted by redact ---
// Live-confirmed 2026-08-05 on claude.ai: a Segment/Amplitude analytics
// relay call (a-api.anthropic.com/v1/b) and Datadog RUM telemetry got
// Redact verdicts (from an unrelated false-positive finding elsewhere in
// the payload); the old whole-body-replace behavior turned their
// well-formed JSON bodies into a bare string, breaking those first-party
// API calls outright and cascading into "We couldn't connect to Claude."
{
  const telemetryBody = JSON.stringify({
    writeKey: "LKJN8LsLERHEOXkw487o7qCTFOrGPimI",
    batch: [{ type: "track", event: "page_view", properties: { path: "/chat" } }],
    sentAt: "2026-08-05T08:33:24.113Z",
  });
  const extracted = extractScannable(telemetryBody);
  assert(extracted.locations.length === 0, "telemetry payload: no recognized content field (as expected -- it's not a chat message)");
  const result = JSON.parse(applyRedaction(extracted, "[REDACTED]"));
  assert(result.writeKey === "LKJN8LsLERHEOXkw487o7qCTFOrGPimI", "telemetry payload: redaction does not corrupt the writeKey field");
  assert(Array.isArray(result.batch), "telemetry payload: redaction does not corrupt the batch array structure");
}

// --- Plain non-JSON body is unaffected ---
{
  const body = "just plain text with AKIAIOSFODNN7EXAMPLE in it";
  const extracted = extractScannable(body);
  assert(extracted.text === body, "plain text body: passed through unchanged");
}

// --- Regression: Gemini's real application/x-www-form-urlencoded body ---
// Live-confirmed 2026-08-05: a percent-encoded space ("%20") is three
// literal characters, and the last one ('0') is a word character, so
// "...s%20AKIA..." has no real word/non-word transition for `\b` to match
// on -- the AWS-key regex silently failed to match on Gemini even though
// the key was plainly present in the scanned text. Fixed by URL-decoding
// before falling back to whole-body scanning.
{
  const body =
    "f.req=%5Bnull%2C%22%5B%5B%5C%22my%20aws%20key%20is%20AKIAIOSFODNN7EXAMPLE%5C%22%2Cnull%2Cnull%5D%5D%22%5D&at=ADR5zaqWAJCt3yuYREZriYjJkXMm%3A1785917881718";
  const extracted = extractScannable(body);
  assert(extracted.text.includes('"my aws key is AKIAIOSFODNN7EXAMPLE"'.replace(/"/g, '\\"')) || extracted.text.includes("my aws key is AKIAIOSFODNN7EXAMPLE"),
    "Gemini form-urlencoded body: decodes to real spaces (AWS key readable as plain text, not %20-separated)");
  const awsKeyRegex = /\b(AKIA[0-9A-Z]{16})\b/;
  assert(awsKeyRegex.test(extracted.text), "Gemini form-urlencoded body: AWS key regex now matches after decoding (this is the actual bug that shipped)");
}

// --- decodeURIComponent safety: malformed sequences don't throw/crash ---
{
  const body = "100% guaranteed, not a % encoding sequence at all";
  const extracted = extractScannable(body);
  assert(extracted.text === body, "malformed %-sequence: falls back to the original text instead of throwing");
}

console.log(failures === 0 ? "\nAll extraction/redaction logic checks passed." : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
