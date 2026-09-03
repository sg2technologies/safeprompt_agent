<#
.SYNOPSIS
    End-to-end validation of the SafePrompt Agent licensing pipeline.

.DESCRIPTION
    Exercises the full flow described in docs/SafeGateway-Architecture-Review.md §9:
    keygen -> activation request -> issue -> verify, plus the rejection paths a
    real license system has to get right (tampering, expiry, device lock,
    forged signer). Finishes with a live smoke test: starts the actual Agent
    service with a valid license present and confirms it logs the right
    tenant/edition at startup.

    Run from anywhere — paths are resolved relative to this script's location.
    Exits 0 if every check passes, 1 otherwise (safe to wire into CI).

.EXAMPLE
    powershell -File agent\scripts\test-licensing.ps1
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
$agentEnterpriseDir = Join-Path (Split-Path -Parent $agentDir) "agent-enterprise"
$workDir = Join-Path $env:TEMP "safeprompt-license-validation"

if (Test-Path $workDir) { Remove-Item -Recurse -Force $workDir }
New-Item -ItemType Directory -Path $workDir | Out-Null

$results = New-Object System.Collections.ArrayList

function Record-Result([string]$name, [bool]$passed, [string]$detail) {
    $results.Add([PSCustomObject]@{ Name = $name; Passed = $passed; Detail = $detail }) | Out-Null
    if ($passed) {
        Write-Host "[PASS] $name" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $name" -ForegroundColor Red
        Write-Host "       $detail" -ForegroundColor DarkGray
    }
}

function Invoke-Tool([string]$binPath, [string[]]$toolArgs) {
    $output = & $binPath @toolArgs
    return @{ Output = ($output -join "`n"); ExitCode = $LASTEXITCODE }
}

Write-Host "== Building license-tool and the Agent service (agent-enterprise) ==" -ForegroundColor Cyan
Push-Location $agentEnterpriseDir
try {
    cargo build -p safeprompt-license-tool -p safeprompt-service
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
    # 2026-08-14, open-core Phase 5: license-tool/safeprompt-service now
    # live in agent-enterprise/, whose target-dir is resolved via `cargo
    # metadata` (not a hardcoded "agent-enterprise\target" guess) so this
    # keeps working the day that workspace also gets a target-dir
    # override, same reasoning as installer/build.ps1's own fix for the
    # identical class of bug against agent/.cargo/config.toml's existing
    # D:\ redirect.
    $enterpriseCargoMetadata = cargo metadata --no-deps --format-version=1 | ConvertFrom-Json
    $enterpriseTargetDir = $enterpriseCargoMetadata.target_directory
} finally {
    Pop-Location
}

$bin = Join-Path $enterpriseTargetDir "debug\license-tool.exe"
$serviceBin = Join-Path $enterpriseTargetDir "debug\safeprompt-service.exe"
if (-not (Test-Path $bin)) { throw "license-tool binary not found at $bin" }
if (-not (Test-Path $serviceBin)) { throw "safeprompt-service binary not found at $serviceBin" }

Write-Host "`n== Running licensing checks ==" -ForegroundColor Cyan

# 1. keygen: produces a signing key (issuer-only) + verifying key (ships in the Agent)
$r = Invoke-Tool $bin @("keygen", "--out-dir", $workDir)
$signingKey = Join-Path $workDir "signing_key.hex"
$publicKey = Join-Path $workDir "verifying_key.hex"
Record-Result "keygen produces a signing + verifying key" `
    ($r.ExitCode -eq 0 -and (Test-Path $signingKey) -and (Test-Path $publicKey)) $r.Output

# 2. request: simulates a device generating an offline activation request
$requestPath = Join-Path $workDir "request.json"
$r = Invoke-Tool $bin @("request", "--out", $requestPath)
Record-Result "request produces an activation-request file with a machine fingerprint" `
    ($r.ExitCode -eq 0 -and (Test-Path $requestPath) -and (Get-Content $requestPath -Raw) -match "machine_fingerprint") $r.Output

# 3. issue: signs a license for the requesting device (the "portal signs it" step)
$licensePath = Join-Path $workDir "license.json"
$r = Invoke-Tool $bin @(
    "issue", "--signing-key", $signingKey, "--tenant", "Acme Corp", "--edition", "professional",
    "--devices", "25", "--days", "365", "--features", "gateway,firewall,pii,mcp",
    "--fingerprint-file", $requestPath, "--out", $licensePath
)
Record-Result "issue signs a license bound to the requesting device" `
    ($r.ExitCode -eq 0 -and (Test-Path $licensePath)) $r.Output

# 4. verify (happy path): the Agent accepts its own valid, unexpired, node-locked license
$r = Invoke-Tool $bin @("verify", "--public-key", $publicKey, "--license", $licensePath)
Record-Result "verify accepts a validly-signed, node-locked, unexpired license" `
    ($r.ExitCode -eq 0 -and $r.Output -match "VALID") $r.Output

# 5. tamper test: editing the claims after signing must invalidate the signature
$tamperedPath = Join-Path $workDir "tampered.json"
# -Encoding ascii deliberately, not utf8: Windows PowerShell 5.1's utf8
# encoding always writes a BOM, which corrupts the JSON (serde_json chokes
# on a leading BOM) and would make this "fail" for the wrong reason.
(Get-Content $licensePath -Raw) -replace "Professional", "Enterprise" |
    Set-Content -Path $tamperedPath -Encoding ascii -NoNewline
$r = Invoke-Tool $bin @("verify", "--public-key", $publicKey, "--license", $tamperedPath)
Record-Result "verify rejects a license tampered with after signing" `
    ($r.ExitCode -ne 0 -and $r.Output -match "signature is invalid") $r.Output

# 6. expiry test
$expiredPath = Join-Path $workDir "expired.json"
$issueExpired = Invoke-Tool $bin @(
    "issue", "--signing-key", $signingKey, "--tenant", "Acme Corp", "--edition", "professional",
    "--devices", "25", "--days", "-1", "--features", "gateway", "--out", $expiredPath
)
$r = Invoke-Tool $bin @("verify", "--public-key", $publicKey, "--license", $expiredPath)
Record-Result "verify rejects an expired license" `
    ($issueExpired.ExitCode -eq 0 -and $r.ExitCode -ne 0 -and $r.Output -match "expired") $r.Output

# 7. wrong-device test: a license node-locked to someone else's machine must not validate here
$wrongFpPath = Join-Path $workDir "wrongfp.json"
$issueWrongFp = Invoke-Tool $bin @(
    "issue", "--signing-key", $signingKey, "--tenant", "Acme Corp", "--edition", "professional",
    "--devices", "25", "--days", "30", "--features", "gateway",
    "--fingerprint", "AAAA-BBBB-CCCC-DDDD", "--out", $wrongFpPath
)
$r = Invoke-Tool $bin @("verify", "--public-key", $publicKey, "--license", $wrongFpPath)
Record-Result "verify rejects a license node-locked to a different device" `
    ($issueWrongFp.ExitCode -eq 0 -and $r.ExitCode -ne 0 -and $r.Output -match "different device") $r.Output

# 8. forged-signer test: nobody without the vendor's private key can mint an accepted license
$forgedDir = Join-Path $workDir "forged-issuer"
New-Item -ItemType Directory -Path $forgedDir | Out-Null
Invoke-Tool $bin @("keygen", "--out-dir", $forgedDir) | Out-Null
$forgedSigningKey = Join-Path $forgedDir "signing_key.hex"
$forgedLicensePath = Join-Path $workDir "forged_license.json"
$issueForged = Invoke-Tool $bin @(
    "issue", "--signing-key", $forgedSigningKey, "--tenant", "Acme Corp", "--edition", "enterprise",
    "--devices", "99999", "--days", "3650", "--features", "gateway,firewall,pii,mcp,siem",
    "--out", $forgedLicensePath
)
$r = Invoke-Tool $bin @("verify", "--public-key", $publicKey, "--license", $forgedLicensePath)
Record-Result "verify rejects a license signed by a non-vendor key" `
    ($issueForged.ExitCode -eq 0 -and $r.ExitCode -ne 0 -and $r.Output -match "signature is invalid") $r.Output

# 9. live smoke test: the actual Agent binary loads the license at startup
Write-Host "`n== Live Agent service smoke test ==" -ForegroundColor Cyan
$serviceWorkDir = Join-Path $workDir "service-run"
New-Item -ItemType Directory -Path $serviceWorkDir | Out-Null
Copy-Item $licensePath (Join-Path $serviceWorkDir "license.json")
Copy-Item $publicKey (Join-Path $serviceWorkDir "verifying_key.hex")

$env:RUST_LOG = "info"
$stdoutLog = Join-Path $serviceWorkDir "service.out.log"
$stderrLog = Join-Path $serviceWorkDir "service.err.log"
$proc = Start-Process -FilePath $serviceBin -WorkingDirectory $serviceWorkDir `
    -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2
$logContent = ""
if (Test-Path $stdoutLog) { $logContent += (Get-Content $stdoutLog -Raw) }
if (Test-Path $stderrLog) { $logContent += (Get-Content $stderrLog -Raw) }
if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Record-Result "running Agent service loads the license (logs Professional / Acme Corp)" `
    ($logContent -match "Professional" -and $logContent -match "Acme Corp") $logContent

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
foreach ($r in $results) {
    $status = if ($r.Passed) { "PASS" } else { "FAIL" }
    Write-Host ("{0,-70} {1}" -f $r.Name, $status)
}

$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    Write-Host "`n$($failed.Count) of $($results.Count) checks FAILED." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll $($results.Count) checks passed." -ForegroundColor Green
    exit 0
}
