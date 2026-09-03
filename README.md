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
- **Local console** — a browser-based dashboard at `http://127.0.0.1:8847`, reachable only from your own machine, with live policy editing, a message tester, and an activity log
- **Local audit log** — every scan decision recorded on-device; nothing leaves the machine unless you explicitly enable it
- **Browser extension integration** — works alongside the SafePrompt browser extension to cover chat prompts and uploads directly on AI sites

## Installation

### Option A — Pre-built installer (recommended) - Download the exe

The simplest way to get started on Windows: download the signed installer from [safeprompt.pro](https://www.safeprompt.pro/). It bundles the agent, the browser extension, and on-device OCR support in one package — no build tools required.

### Option B — Build from source

Requires the [Rust toolchain](https://rustup.rs/) (stable channel).

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

> On-device OCR (image and scanned-PDF scanning) needs two additional runtime libraries — `onnxruntime` and `pdfium` — placed next to the built binary. See `crates/ocr`'s documentation for download links; everything else works out of the box.

## Using it with your browser

The extension (`browser-extension/` in this repo) is what actually sees your prompts and file uploads on ChatGPT, Claude, Gemini, and Copilot, and sends them to the Agent above to be scanned before they leave your machine.

1. Open `chrome://extensions` (or `edge://extensions`) and turn on **Developer mode**.
2. Click **Load unpacked** and select this repo's `browser-extension/` folder directly — no build step needed.
3. Chrome assigns the unpacked extension a random local ID — copy it from the extension's card.
4. **Point the Agent at that ID**: the Agent only accepts requests from an extension origin it recognizes, and by default that's SG2's own official build's ID, not yours. Start the Agent with
   ```bash
   SAFEPROMPT_EXTENSION_ORIGINS=chrome-extension://<your-extension-id> ./target/release/safeprompt-service
   ```
   (On Windows PowerShell: `$env:SAFEPROMPT_EXTENSION_ORIGINS="chrome-extension://<your-extension-id>"` before running it.)
5. Reload the tab on whichever AI site you're using. The local console's **Browser extension** tab (`http://127.0.0.1:8847`) confirms once it's detected.

To produce a stable ID and a real, installable `.crx` instead (e.g. for your own team's force-install policy) rather than repeating step 4 on every machine, generate your own signing key with `node browser-extension/gen-key.mjs` and pack it with `browser-extension/scripts/pack-crx.ps1` — **never reuse SG2's production key**, which isn't part of this repository, precisely so a community build's identity and an official SafePrompt build's identity are never the same thing.

## Configuring policy

Everything is controlled from the local console's **Policy** tab, or by editing the underlying JSON policy document directly — no cloud account required to change what's detected or how it's handled.

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

Need centralized policy management across a fleet, SIEM/syslog export, advanced attack detection, or SSO? SafePrompt Enterprise builds on this same engine with fleet management, cloud audit sync, and priority support.

**→ [www.safeprompt.pro](https://www.safeprompt.pro/)**

## Contact

**info@sg2technologies.com**

## License

Copyright © 2026 SG2 Technologies.

Licensed under the [Apache License, Version 2.0](LICENSE). You may use, modify, and redistribute this code — including commercially — under the terms of that license.

This applies to everything in this repository: the Agent (`apps/`, `crates/`) and the browser extension (`browser-extension/`). SafePrompt Enterprise (fleet management, SSO/RBAC, SIEM integration, compliance reporting, GPO/Intune deployment tooling, and related enterprise tooling) is separate, proprietary software licensed by SG2 Technologies, and is not part of this repository — see [Enterprise edition](#enterprise-edition) above.

## Author

**Gopi Narayanaswamy** — [github.com/ngopi37](https://github.com/ngopi37)
