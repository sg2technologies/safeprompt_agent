# SafePrompt Agent

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Open-source, on-device data-loss-prevention scanning for AI chat tools.**

SafePrompt inspects text and files *before* they reach ChatGPT, Claude, Gemini, Copilot, or any other AI tool — catching secrets, personal data, financial information, and prompt-injection attempts, and masking or blocking them as you configure. Nothing is scanned in the cloud; detection runs entirely on-device.

This repository is the **Community edition**: the Rust Agent (`agent/` at the repo root) *and* the browser extension (`browser-extension/`) that actually intercepts and scans prompts and uploads on AI chat sites — the same components used across every SafePrompt edition, published together so the piece that sees your traffic is just as inspectable as the engine behind it. Both are licensed under Apache 2.0: use them, modify them, self-host them, or build on them, commercially or not — see [License](#license) below.

---

## Features

- **On-device detection** — API keys & credentials, PII (names, emails, phone numbers, government IDs), financial data (cards, account numbers), internal hostnames, prompt-injection attempts, and custom keyword rules
- **File & image scanning** — `.txt`, `.docx`, `.pdf`, and scanned/photographed documents via on-device OCR
- **In-place masking** — plain-text file uploads (`.txt`, `.csv`, `.json`, `.md`, `.log`, `.yaml`, `.xml`, `.html`) are redacted and still sent, instead of being blocked outright
- **Configurable policy** — turn detectors on or off, choose Allow / Warn / Mask / Block / Require-approval per category
- **Pause protection** — a one-button, auto-expiring pause (15 min / 1 hour / 4 hours) for the rare "let me send this one thing" case, instead of hand-editing per-category settings and having to remember to revert them
- **Local console** — a browser-based dashboard at `http://127.0.0.1:8847`, reachable only from your own machine, with live policy editing, a message tester, and an activity log
- **Local audit log** — every scan decision recorded on-device; nothing leaves the machine unless you explicitly enable it
- **Browser extension integration** — works alongside the SafePrompt browser extension to cover chat prompts and uploads directly on AI sites

## Installation

### Option A — Pre-built installer (recommended for Windows) - Download the exe

The simplest way to get started on Windows: download the signed installer from [safeprompt.pro](https://www.safeprompt.pro/). It bundles the agent, the browser extension, and on-device OCR support in one package — no build tools required. There's no pre-built package for Linux or macOS yet — use Option B below on those platforms.

### Option B — Build from source (Windows, Linux, macOS)

**Requirements:**
- [Rust toolchain](https://rustup.rs/), stable channel
- Git
- Windows only: MSVC Build Tools (the "Desktop development with C++" workload in Visual Studio Build Tools, or a full Visual Studio install) — the standard native-linking prerequisite for any Rust project on Windows with dependencies that aren't pure Rust; rustup's installer offers to install this for you if it's missing
- Chrome or Edge, if you want the browser-extension integration below (the Agent itself doesn't need a browser to run)
- Two extra runtime libraries if you want on-device OCR (image/scanned-PDF scanning) — see [OCR support](#ocr-support) below; everything else works without them

The Community binary (`apps/service`) has no Windows-only code — it builds and runs the same way on Linux and macOS.

```bash
git clone https://github.com/sg2technologies/safeprompt_agent.git
cd safeprompt_agent
cargo build --release -p safeprompt-service
```

Run it:

```bash
./target/release/safeprompt-service
```

Then open **http://127.0.0.1:8847** in your browser for the local console — no account or sign-in needed.

> **Windows Firewall**: the first time you run it, Windows will likely show a "Windows Defender Firewall has blocked some features of this app" prompt — this is normal for any freshly built, unsigned binary that opens a listening socket, not something specific to SafePrompt. SafePrompt's local console and browser-extension API bind to `127.0.0.1` only by default, meaning they're reachable exclusively from this same machine — no firewall rule changes that. For ordinary local use, it's safe to click **Cancel**/dismiss the prompt entirely; nothing on `127.0.0.1` needs a firewall exception to work. Only click **Allow access** if you've deliberately reconfigured the Agent to bind to a real network interface for a role that genuinely needs to be reached from other devices (e.g. a fleet's Tenant SPOC) — and if you have, treat that as a real network service to secure, not a default posture.

> **macOS note**: `platform/macos` (system-proxy auto-configuration) is currently a stub — it compiles but doesn't actually route traffic through the Agent yet. The detection engine, local console, and browser-extension integration below all work; only that one piece of automatic setup is still pending. Linux has no such gap — the same source this repo ships also produces the real, tested `.deb`/`.rpm` packages used by paid editions (see `apps/watchdog` and `systemd/`).

## Verify installation

Before relying on it, confirm the Agent is actually detecting things:

1. Start the Agent (`./target/release/safeprompt-service` or the installed service) and open **http://127.0.0.1:8847**.
2. Open the **Policy** tab and confirm the detectors you care about are toggled on.
3. Open the **Test a Message** tab and paste in a synthetic test secret — e.g. `AKIAIOSFODNN7EXAMPLE` (a documented AWS example key, not a real credential) — and confirm it comes back Redact/Block, not Allow.
4. If you're using the browser extension, follow [Using it with your browser](#using-it-with-your-browser) below, then repeat the same synthetic-secret test *inside an actual AI chat prompt* — a green "Connected" status on its own is not proof scanning works (see the warning in that section).

If step 3 doesn't flag the test secret, check the Policy tab before anything else — a detector toggled off, or a category set to Allow, means exactly that.

What step 4 looks like when it's actually working — the browser extension intercepting a synthetic AWS key and a synthetic password before either one reaches ChatGPT:

<img src="docs/images/verify-secret-redacted.png" alt="ChatGPT prompt showing a synthetic AWS key replaced with [REDACTED_AWS_KEY] before sending, with a SafePrompt toast confirming the redaction" width="600">
<img src="docs/images/verify-password-redacted.png" alt="ChatGPT prompt showing a synthetic password replaced with [REDACTED_PASSWORD] before sending, with a SafePrompt toast confirming the redaction" width="600">

(Both values above are made-up test data, not real credentials.)

## Using it with your browser

The extension (`browser-extension/` in this repo) is what actually sees your prompts and file uploads on ChatGPT, Claude, Gemini, and Copilot, and sends them to the Agent above to be scanned before they leave your machine. Once it's set up, the local console's **Browser extension** tab looks like this:

<img src="docs/images/browser-extension-tab.png" alt="SafePrompt local console's Browser extension tab, showing it detected and checking in, plus the Load unpacked install steps" width="700">

1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
2. Click **Load unpacked** and select this repo's `browser-extension/` folder directly — no build step needed.
3. Chrome assigns the unpacked extension a local extension ID (derived from how it was loaded, not something SafePrompt controls) — copy it from the extension's card:

   <img src="docs/images/chrome-extension-id.png" alt="Chrome extensions page for SafePrompt, with the extension ID field circled" width="700">
4. **Configure the extension origin — do not skip this step.** The Agent only accepts requests from an extension origin it recognizes, and by default that's SG2's own official build's ID, not yours. Start the Agent with your ID set instead:

   ```bash
   SAFEPROMPT_EXTENSION_ORIGINS=chrome-extension://<your-extension-id> ./target/release/safeprompt-service
   ```
   Windows PowerShell:
   ```powershell
   $env:SAFEPROMPT_EXTENSION_ORIGINS="chrome-extension://<your-extension-id>"; .\target\release\safeprompt-service.exe
   ```
   Windows cmd.exe:
   ```cmd
   set SAFEPROMPT_EXTENSION_ORIGINS=chrome-extension://<your-extension-id>
   target\release\safeprompt-service.exe
   ```

   **⚠️ Important:** skipping this doesn't produce an error — the popup and local console still show **"Connected"** even with the wrong ID configured, since that check doesn't require the ID to match. Every prompt and file upload then goes through **completely unscanned**, silently, because a rejected request fails open by design (a broken/unreachable Agent shouldn't break your browsing) rather than blocking your traffic. Always verify with a real test (see [Verify installation](#verify-installation) above), never just the "Connected" status. If it looks connected but isn't catching anything, check the extension's own service worker console (`chrome://extensions` → SafePrompt → **service worker** → Inspect) for a `403` error naming the mismatch.
5. Reload the tab on whichever AI site you're using. The local console's **Browser extension** tab (`http://127.0.0.1:8847`) confirms once it's detected — then actually test it (paste the synthetic test secret `AKIAIOSFODNN7EXAMPLE` into a prompt and confirm it gets masked/blocked before send), don't just trust the "Connected" status.

To produce a stable ID and a real, installable `.crx` instead (e.g. for your own team's force-install policy) rather than repeating step 4 on every machine, generate your own signing key with `node browser-extension/gen-key.mjs` and pack it with `browser-extension/scripts/pack-crx.ps1` — **never reuse SG2's production key**, which isn't part of this repository, precisely so a community build's identity and an official SafePrompt build's identity are never the same thing.

## Configuring policy

Everything is controlled from the local console's **Policy** tab, or by editing the underlying JSON policy document directly — no cloud account required to change what's detected or how it's handled. The **Pause protection** buttons at the top handle the "just this once" case without touching the detector settings below them:

<img src="docs/images/pause-protection.png" alt="SafePrompt local console's Policy tab, showing Pause 15 minutes / 1 hour / 4 hours buttons above the per-category detector toggles" width="700">

## OCR support

On-device OCR (image and scanned-PDF scanning) needs two extra runtime libraries placed next to the built binary — they're loaded dynamically at startup, not statically linked in, so the Agent runs fine without them; OCR-dependent uploads just pass through unscanned instead. On Windows that means:

```
target/release/
├── safeprompt-service.exe
├── onnxruntime.dll
└── pdfium.dll
```

**[crates/ocr/README.md](crates/ocr/README.md)** has the exact download links, pinned versions, SHA-256 hashes to verify against, and a copy-pasteable PowerShell script that fetches and places both files for you. Linux/macOS use the platform-appropriate filename (`libonnxruntime.so`/`libonnxruntime.dylib`, etc.) — the same doc has what's known so far for those.

## Security & privacy

- Detection (secrets, PII, financial data, prompt injection, ...) runs **entirely on-device** — nothing is sent to a cloud service to be scanned.
- The local console and browser-extension API bind to `127.0.0.1` by default — reachable only from this machine, not your network.
- The audit log of scan decisions is stored locally; nothing leaves the machine unless you explicitly configure that.
- No account, sign-in, or license is required to build, run, or use Community edition scanning.
- The browser extension only ever talks to an Agent on the machine it's configured with an explicit origin for (see [Using it with your browser](#using-it-with-your-browser) above) — it doesn't phone home anywhere else.

## Project layout

```
apps/service/           the Agent binary (local API, policy engine, scan pipeline)
apps/watchdog/          supervises and restarts the service; applies signed updates
apps/tray/              system-tray companion app
crates/                 the detection engine, split by concern (pii, secrets, policy, ocr, ...)
browser-extension/      the browser extension source (Chrome/Edge + Firefox manifests)
browser-extension/src/  content scripts: intercepts fetch/XHR, relays to the Agent for scanning
```

## Enterprise edition

Need centralized policy management across a fleet, SIEM/syslog export, advanced attack detection, or SSO? SafePrompt Enterprise builds on this same detection engine with fleet management, cloud audit sync, and priority support.

Enterprise is a **separate, proprietary product** — its fleet management, SSO/RBAC, SIEM integration, compliance reporting, and GPO/Intune deployment tooling are not included in this repository (see [License](#license) below).

**→ [www.safeprompt.pro](https://www.safeprompt.pro/)**

## Contact

**info@sg2technologies.com**

## License

Copyright © 2026 SG2 Technologies.

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, modify, and redistribute this code — including commercially — under the terms of that license.

This applies to everything in this repository: the Agent (`apps/`, `crates/`) and the browser extension (`browser-extension/`). SafePrompt Enterprise (fleet management, SSO/RBAC, SIEM integration, compliance reporting, GPO/Intune deployment tooling, and related enterprise tooling) is separate, proprietary software licensed by SG2 Technologies, and is not part of this repository — see [Enterprise edition](#enterprise-edition) above.

## Author

**Gopi Narayanaswamy** — [github.com/ngopi37](https://github.com/ngopi37)
