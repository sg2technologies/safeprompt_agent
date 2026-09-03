# SafePrompt Agent

**On-device data-loss-prevention scanning for AI chat tools — Community edition.**

SafePrompt Agent runs locally on your machine and inspects text and files *before* they reach ChatGPT, Claude, Gemini, Copilot, or any other AI tool — catching secrets, personal data, financial information, and prompt-injection attempts, and masking or blocking them as you configure. Nothing is scanned in the cloud; detection runs entirely on-device.

This repository is the **Community edition engine**, written in Rust — the same detection core used across every SafePrompt edition.

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

### Option A — Pre-built installer (recommended)

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

> On-device OCR (image and scanned-PDF scanning) needs two additional runtime libraries — `onnxruntime` and `pdfium` — placed next to the built binary. See `agent/crates/ocr`'s documentation for download links; everything else works out of the box.

## Using it with your browser

Point the SafePrompt browser extension at this agent (it talks to `http://127.0.0.1:8847` by default) to have prompts and file uploads on AI chat sites scanned automatically. The local console's **Browser extension** tab has step-by-step setup instructions once the agent is running.

## Configuring policy

Everything is controlled from the local console's **Policy** tab, or by editing the underlying JSON policy document directly — no cloud account required to change what's detected or how it's handled.

## Project layout

```
apps/service/     the Agent binary (local API, policy engine, scan pipeline)
apps/watchdog/     supervises and restarts the service; applies signed updates
apps/tray/         system-tray companion app
crates/            the detection engine, split by concern (pii, secrets, policy, ocr, ...)
```

## Enterprise edition

Need centralized policy management across a fleet, SIEM/syslog export, advanced attack detection, or SSO? SafePrompt Enterprise builds on this same engine with fleet management, cloud audit sync, and priority support.

**→ [www.safeprompt.pro](https://www.safeprompt.pro/)**

## Contact

**info@sg2technologies.com**

## License

© SG2 Technologies. All rights reserved.

## Author

**Gopi Narayanaswamy** — [github.com/ngopi37](https://github.com/ngopi37)
