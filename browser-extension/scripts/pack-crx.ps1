# Packs browser-extension/'s actual runtime files (manifest.json, icons/,
# src/) into a signed .crx for self-hosted enterprise distribution -- no
# Chrome Web Store listing (and no Web Store developer registration fee)
# required. Ported from extension/scripts/pack-crx.ps1; adapted since
# browser-extension/ has no dist/ build step of its own.
#
# Stages those files into a throwaway temp directory before packing --
# NOT packing browser-extension/ directly, unlike the first version of this
# script. Chrome's --pack-extension actively refuses to pack a directory
# that contains the *private* key.pem alongside the extension it's signing
# ("This extension includes the key file... You probably don't want to do
# that") -- rightly so, since that would ship the private signing key
# inside the extension package itself. The old extension/ never hit this
# because it packed a dist/ build subdirectory that never contained
# key.pem; this one has no build step, so staging is done explicitly here
# instead.
#
# Usage:
#   1. node gen-key.mjs               (already done -- key.pem exists)
#   2. .\scripts\pack-crx.ps1         (produces safeprompt-extension.crx)
#   3. node scripts\gen-update-manifest.mjs <https://your-host/safeprompt-extension.crx>
#
# Then host the resulting .crx and update_manifest.xml on any HTTPS server
# you control, and point ExtensionInstallForcelist at that
# update_manifest.xml URL (see enterprise/gpo_windows_sample.reg and
# enterprise/intune_chrome_policy.json).

param(
    [string]$ChromePath
)

$ErrorActionPreference = "Stop"
$extRoot = Split-Path -Parent $PSScriptRoot
$keyPath = Join-Path $extRoot "key.pem"
$crxPath = Join-Path $extRoot "safeprompt-extension.crx"

if (-not (Test-Path $keyPath)) {
    Write-Host "key.pem not found - generating it first." -ForegroundColor Yellow
    node (Join-Path $extRoot "gen-key.mjs")
}

$stageDir = Join-Path ([System.IO.Path]::GetTempPath()) "safeprompt-extension-pack-stage"
Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stageDir | Out-Null
Copy-Item (Join-Path $extRoot "manifest.json") $stageDir
Copy-Item (Join-Path $extRoot "icons") (Join-Path $stageDir "icons") -Recurse
Copy-Item (Join-Path $extRoot "src") (Join-Path $stageDir "src") -Recurse
# manifest.json's storage.managed_schema (item #1, 2026-08-05) points at
# this -- Chrome needs schema.json bundled *inside* the package for
# chrome.storage.managed to have anything to validate incoming managed
# policy against; without it in the CRX, chrome.storage.managed.get()
# silently returns nothing at all no matter what an admin pushes.
Copy-Item (Join-Path $extRoot "schema.json") $stageDir
Write-Host "Staged runtime files (manifest.json, schema.json, icons/, src/ -- no key.pem/scripts/enterprise/) at $stageDir"

if (-not $ChromePath) {
    $chromeCandidates = @(
        "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
        "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
        "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
    )
    $ChromePath = $chromeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
}
if (-not $ChromePath) {
    throw "Could not find chrome.exe. Pass its path with -ChromePath 'C:\path\to\chrome.exe'"
}

Write-Host "Packing with $ChromePath ..."
# Chrome writes the .crx next to the target directory, named after it, not
# inside it -- packing $stageDir (named "safeprompt-extension-pack-stage")
# means the produced file lands one level up (in the temp root), named
# after that directory.
$producedCrx = Join-Path ([System.IO.Path]::GetTempPath()) "safeprompt-extension-pack-stage.crx"
Remove-Item -Force $producedCrx -ErrorAction SilentlyContinue
& $ChromePath --pack-extension="$stageDir" --pack-extension-key="$keyPath"

# Chrome re-execs into a background process, so the .crx may not exist yet
# by the time the call above returns. Poll briefly for it.
$waited = 0
while (-not (Test-Path $producedCrx) -and $waited -lt 15) {
    Start-Sleep -Seconds 1
    $waited++
}

if (Test-Path $producedCrx) {
    Move-Item -Force $producedCrx $crxPath
}
Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue

if (-not (Test-Path $crxPath)) {
    throw "Packing failed - chrome did not produce a .crx file. Check that no other Chrome window has this profile open (packing can silently no-op if Chrome is already running)."
}

$manifest = Get-Content (Join-Path $extRoot "manifest.json") | ConvertFrom-Json
$extensionId = node (Join-Path $extRoot "scripts\get-extension-id.mjs")

Write-Host ""
Write-Host "Packed: $crxPath"
Write-Host "Extension ID: $extensionId"
Write-Host "Version: $($manifest.version)"
Write-Host ""
Write-Host "Next: host this .crx on an HTTPS URL you control, then run:"
Write-Host "  node scripts\gen-update-manifest.mjs https://your-host/safeprompt-extension.crx"
