# On-device OCR runtime setup

`safeprompt-service` scans images and scanned (image-only) PDF pages using
[oar-ocr](https://github.com/GreatV/oar-ocr) on top of two runtime
libraries this crate loads dynamically at startup, not statically linked
into the binary. If they're missing, the Agent still runs — OCR-dependent
uploads just come back `Unsupported` and pass through unscanned, logged
as a warning, not a crash.

This file exists because the main README's build-from-source
instructions point here for exact download links — those links didn't
actually exist anywhere until this file was added (2026-09-04, found
live: a from-source build had no OCR at all and no path to fix it beyond
guessing).

## What you need (Windows)

Two DLLs, placed in the **same folder as `safeprompt-service.exe`**
(e.g. `target\release\`) — exactly what `release.yml`'s CI pipeline
downloads and SHA256-verifies for the official installer, pinned to the
versions actually tested against this codebase, not "latest":

| File | Source | SHA-256 |
|---|---|---|
| `onnxruntime.dll` | [microsoft/onnxruntime v1.28.0](https://github.com/microsoft/onnxruntime/releases/download/v1.28.0/onnxruntime-win-x64-1.28.0.zip) (`lib/onnxruntime.dll` inside the zip) | `18370C375F07357FA5874344A9D9AC17E6B6FE1EB18B1DD209D79483B4470257` |
| `pdfium.dll` | [bblanchon/pdfium-binaries chromium/7999](https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/7999/pdfium-win-x64.tgz) (`bin/pdfium.dll` inside the tarball) | `FB898A1F5ACE57805834F390407500BDB6EF93EFF326A252AD334A8AAE809D8E` |

PowerShell, from the repo root, to fetch/verify/place both in one go
(same commands `release.yml` itself runs):

```powershell
function Assert-Sha256($Path, $Expected) {
    $actual = (Get-FileHash $Path -Algorithm SHA256).Hash
    if ($actual -ne $Expected) { throw "$Path SHA256 mismatch: expected $Expected, got $actual" }
}

Invoke-WebRequest -Uri "https://github.com/microsoft/onnxruntime/releases/download/v1.28.0/onnxruntime-win-x64-1.28.0.zip" -OutFile "$env:TEMP\onnxruntime.zip"
Expand-Archive -Path "$env:TEMP\onnxruntime.zip" -DestinationPath "$env:TEMP\onnxruntime" -Force
Copy-Item "$env:TEMP\onnxruntime\onnxruntime-win-x64-1.28.0\lib\onnxruntime.dll" target\release\onnxruntime.dll -Force
Assert-Sha256 target\release\onnxruntime.dll "18370C375F07357FA5874344A9D9AC17E6B6FE1EB18B1DD209D79483B4470257"

Invoke-WebRequest -Uri "https://github.com/bblanchon/pdfium-binaries/releases/download/chromium/7999/pdfium-win-x64.tgz" -OutFile "$env:TEMP\pdfium-win-x64.tgz"
New-Item -ItemType Directory -Force -Path "$env:TEMP\pdfium" | Out-Null
tar -xzf "$env:TEMP\pdfium-win-x64.tgz" -C "$env:TEMP\pdfium"
Copy-Item "$env:TEMP\pdfium\bin\pdfium.dll" target\release\pdfium.dll -Force
Assert-Sha256 target\release\pdfium.dll "FB898A1F5ACE57805834F390407500BDB6EF93EFF326A252AD334A8AAE809D8E"
```

(Building a debug binary instead of `--release`? Copy to `target\debug\`
instead.)

## Linux / macOS

This crate resolves the platform-appropriate filename automatically
(`libonnxruntime.so` on Linux, `libonnxruntime.dylib` on macOS — see
`ORT_DYLIB_FILENAME` in `src/lib.rs`), but **only the Windows DLLs above
have actually been vendored, pinned, and tested** against this codebase
so far — no verified download link/SHA-256 exists yet for the other two
platforms. onnxruntime publishes official Linux/macOS release archives on
the same [GitHub releases page](https://github.com/microsoft/onnxruntime/releases)
as the Windows build above; pdfium-binaries does the same for
[Linux](https://github.com/bblanchon/pdfium-binaries/releases) and macOS.
Same idea (download the matching archive for your OS/arch, extract the
shared library, place it next to the built binary) should work, just
without this project having verified an exact version pin for you yet.

## Auto-download alternative

`OarOcrEngine::new_with_auto_download()` (what `apps/service` actually
calls) can fetch its own ONNX *model* files on first run via `oar-ocr`'s
own registry, cached under `OAR_HOME` (defaults to `~/.oar`) — that part
already works out of the box. It's the *runtime* library (onnxruntime/
pdfium themselves) this file's steps are for; those aren't part of that
auto-download path.
