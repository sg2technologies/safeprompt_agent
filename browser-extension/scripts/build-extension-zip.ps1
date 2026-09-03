<#
.SYNOPSIS
    Packs browser-extension/'s runtime files into a plain, unsigned .zip for
    either the Chromium family (Chrome/Edge/Brave, one shared package -- they
    all consume the same MV3 manifest.json) or Firefox (manifest.firefox.json,
    which differs in the ways Firefox actually requires -- see below).

.DESCRIPTION
    This is a SEPARATE artifact from safeprompt-extension.crx
    (scripts/pack-crx.ps1). The .crx is signed and is what a self-hosted
    force-install path uses (update manifest + Chrome's own
    ExtensionInstallForcelist policy). The .zip this script produces is
    the plain, unsigned distributable a person loads via
    chrome://extensions "Load unpacked" (after extracting) or side-loads,
    matching the "here's a zip per browser family" pattern used by e.g.
    novincode/dlman's release pipeline. Both artifacts are built from the
    exact same source files -- this script doesn't fork the extension logic,
    only the manifest and the packaging format.

    Firefox needs a different manifest than Chrome/Edge/Brave, not just a
    different package:
      - `key` (Chrome's CRX-signing pubkey, also used to derive a stable
        extension ID) means nothing to Firefox -- it uses
        `browser_specific_settings.gecko.id` for a stable ID instead.
      - Firefox's MV3 implementation runs background scripts as an event
        page, not a true service worker -- `background.service_worker`
        (Chrome) becomes `background.scripts` (Firefox).
      - The MAIN-world content script (main-world-interceptor.js, needed to
        intercept page-context fetch/XHR before the page's own JS runs)
        needs Firefox 128+ (shipped 2024) -- `strict_min_version` in the
        Firefox manifest documents that floor rather than silently
        producing a package that only half-works on older Firefox.
    These live as two committed manifest files (manifest.json,
    manifest.firefox.json) rather than being templated at build time, so a
    manifest change is a visible diff in both places, not a hidden
    generation step.

    NOT done by this script or covered by any testing in this repo: actual
    functional verification of the extension running inside real Firefox.
    Packaging correctness (valid manifest, right files, loads without
    manifest-parse errors) is the whole scope here -- if Firefox needs its
    own QA pass, that's separate work.

    Self-hosted Firefox distribution (outside addons.mozilla.org) still
    needs either AMO signing or a policies.json ExtensionSettings
    force-install entry, same shape as Chrome's own ExtensionInstallForcelist
    policy -- this script only produces the .zip, it doesn't attempt
    either of those.

.PARAMETER Browser
    "chrome" (default) or "firefox".

.PARAMETER Version
    Version string to stamp into the packaged manifest.json's "version"
    field and the output filename (e.g. "1.2.3", typically derived from a
    release tag in CI). Defaults to whatever's already in the source
    manifest if omitted -- local/manual runs don't need to pass this.

.PARAMETER OutDir
    Where to write the .zip. Defaults to the repo's browser-extension/
    directory itself.

.EXAMPLE
    powershell -File scripts\build-extension-zip.ps1 -Browser chrome -Version 1.2.3
.EXAMPLE
    powershell -File scripts\build-extension-zip.ps1 -Browser firefox -Version 1.2.3 -OutDir C:\out
#>

param(
    [ValidateSet("chrome", "firefox")]
    [string]$Browser = "chrome",
    [string]$Version,
    [string]$OutDir
)

$ErrorActionPreference = "Stop"
$extRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutDir) { $OutDir = $extRoot }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$sourceManifest = if ($Browser -eq "firefox") {
    Join-Path $extRoot "manifest.firefox.json"
} else {
    Join-Path $extRoot "manifest.json"
}
if (-not (Test-Path $sourceManifest)) { throw "missing $sourceManifest" }

$stageDir = Join-Path ([System.IO.Path]::GetTempPath()) "safeprompt-extension-zip-stage-$Browser"
Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stageDir | Out-Null

# Same runtime-file set as pack-crx.ps1 stages -- manifest.json, icons/,
# src/, schema.json. Deliberately not key.pem/gen-key.mjs/scripts/enterprise/
# -- key.pem is the CRX-signing private key and has no meaning to a plain
# zip, and shipping it inside a distributable package would leak it.
#
# Read/write explicitly as UTF-8 without a BOM: the source manifests contain
# a real em-dash (SafePrompt — AI Security Gateway), which Windows
# PowerShell 5.1's default Get-Content/Set-Content encoding (system ANSI
# codepage, not UTF-8) would mangle; a BOM on the other end can make some
# JSON parsers choke on manifest.json specifically.
$manifest = (Get-Content $sourceManifest -Raw -Encoding UTF8) | ConvertFrom-Json
if ($Version) { $manifest.version = $Version }
$manifestJson = $manifest | ConvertTo-Json -Depth 20
[System.IO.File]::WriteAllText((Join-Path $stageDir "manifest.json"), $manifestJson, (New-Object System.Text.UTF8Encoding $false))
Copy-Item (Join-Path $extRoot "icons") (Join-Path $stageDir "icons") -Recurse
Copy-Item (Join-Path $extRoot "src") (Join-Path $stageDir "src") -Recurse
Copy-Item (Join-Path $extRoot "schema.json") $stageDir

$zipVersion = if ($Version) { $Version } else { $manifest.version }
$zipName = "safeprompt-extension-$Browser-v$zipVersion.zip"
$zipPath = Join-Path $OutDir $zipName
Remove-Item -Force $zipPath -ErrorAction SilentlyContinue

Compress-Archive -Path (Join-Path $stageDir "*") -DestinationPath $zipPath -CompressionLevel Optimal
Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue

if (-not (Test-Path $zipPath)) { throw "failed to produce $zipPath" }
Write-Host "Built: $zipPath"
