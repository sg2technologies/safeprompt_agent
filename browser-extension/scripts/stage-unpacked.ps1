# Stages browser-extension/'s actual runtime files (manifest.json, icons/,
# schema.json, src/) into dist-unpacked/ for Chrome's "Load unpacked" --
# NOT the extension root itself, unlike an earlier version of the local
# testing guide. Loading the root directly puts key.pem (the private CRX-
# signing key) in the same folder Chrome inspects, which trips
# "This extension includes the key file '...\key.pem'. You probably don't
# want to do that." -- harmless for Load-unpacked specifically (unlike
# --pack-extension, which refuses outright to pack a directory containing
# it -- see pack-crx.ps1's own doc comment), but there's no reason to make
# a private key's on-disk location part of a normal test flow, or show a
# security-sounding warning to someone just trying to load the extension.
#
# Deliberately a *stable* output directory (dist-unpacked/), not a
# throwaway temp dir like pack-crx.ps1 uses for its own staging -- Chrome
# remembers the path an unpacked extension was loaded from and re-reads it
# on every "reload", so this needs to still exist (and be up to date) at
# the same path across dev-loop iterations, not just for one pack.
#
# Usage:
#   .\scripts\stage-unpacked.ps1
#   Then in Chrome/Edge: chrome://extensions -> Developer mode -> Load
#   unpacked -> select browser-extension\dist-unpacked
#
# Re-run this after any change under src/, manifest.json, icons/, or
# schema.json, then click the reload icon on the extension's tile.

$ErrorActionPreference = "Stop"
$extRoot = Split-Path -Parent $PSScriptRoot
$stageDir = Join-Path $extRoot "dist-unpacked"

Remove-Item -Recurse -Force $stageDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stageDir | Out-Null

Copy-Item (Join-Path $extRoot "manifest.json") $stageDir
Copy-Item (Join-Path $extRoot "icons") (Join-Path $stageDir "icons") -Recurse
Copy-Item (Join-Path $extRoot "src") (Join-Path $stageDir "src") -Recurse
# manifest.json's storage.managed_schema points at this -- Chrome needs it
# bundled alongside manifest.json for chrome.storage.managed to have
# anything to validate incoming managed policy against.
Copy-Item (Join-Path $extRoot "schema.json") $stageDir

Write-Host "Staged runtime files (no key.pem, no scripts/, no enterprise/) at $stageDir" -ForegroundColor Green
