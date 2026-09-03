<#
.SYNOPSIS
    Live validation of Authenticode-based mutual binary trust: the watchdog
    verifies safeprompt-service.exe's signed hash *and* its Authenticode
    signer before spawning it, not just once at the service's own startup.

.DESCRIPTION
    Generates a disposable self-signed code-signing certificate (never
    trusted or used outside this script's own temp scope), signs a copy of
    the real service binary with it via installer/sign.ps1, and proves
    three real scenarios against the real watchdog binary:
      1. A correctly signed binary + a manifest pinning its real hash and
         real signer thumbprint -> the watchdog spawns it (port 8844 opens).
      2. The exact same correctly signed binary, but a manifest pinning a
         *different* (wrong) expected signer thumbprint -> the watchdog
         refuses to spawn it at all (port never opens) -- proves the signer
         check is independent of the hash check, not just "hash passed so
         everything passed."
      3. The signed binary tampered with afterward (bytes appended, breaking
         both the pinned hash and the Authenticode signature) -> the
         watchdog refuses to spawn it -- proves the *pre-spawn* check
         (external, done by the watchdog before the child even runs) catches
         tampering, not only the existing self-check (internal, done by the
         service at its own startup, which a modified binary could simply
         choose not to run).

    Requires signtool.exe (Windows SDK) and admin rights are NOT needed for
    New-SelfSignedCertificate/CurrentUser cert store operations used here.

.EXAMPLE
    powershell -File agent\scripts\test-authenticode-verification.ps1
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
$repoRoot = Split-Path -Parent $agentDir
$installerDir = Join-Path $repoRoot "installer"
$workDir = Join-Path $env:TEMP "safeprompt-authenticode-validation"

if (Test-Path $workDir) { Remove-Item -Recurse -Force $workDir }
New-Item -ItemType Directory -Path $workDir | Out-Null

$results = New-Object System.Collections.ArrayList
$spawnedProcs = New-Object System.Collections.ArrayList
$testCert = $null

function Record-Result([string]$name, [bool]$passed, [string]$detail) {
    $results.Add([PSCustomObject]@{ Name = $name; Passed = $passed; Detail = $detail }) | Out-Null
    if ($passed) {
        Write-Host "[PASS] $name" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $name" -ForegroundColor Red
        Write-Host "       $detail" -ForegroundColor DarkGray
    }
}

function Test-Port8844Opens([int]$maxWaitMs) {
    $elapsed = 0
    while ($elapsed -lt $maxWaitMs) {
        try {
            $conn = Test-NetConnection -ComputerName 127.0.0.1 -Port 8844 -WarningAction SilentlyContinue
            if ($conn.TcpTestSucceeded) { return $true }
        } catch {}
        Start-Sleep -Milliseconds 300
        $elapsed += 300
    }
    return $false
}

function Stop-WatchdogTree($proc) {
    if ($proc -and -not $proc.HasExited) {
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$($proc.Id)" -ErrorAction SilentlyContinue |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
}

try {
    Write-Host "== Building license-tool + service (agent-enterprise) ==" -ForegroundColor Cyan
    # 2026-08-14, open-core Phase 5: license-tool/safeprompt-service now live
    # in agent-enterprise/; safeprompt-watchdog stays in agent/ -- built
    # separately below, same split installer/build.ps1 and this codebase's
    # other test-*.ps1 scripts already apply.
    $agentEnterpriseDir = Join-Path $repoRoot "agent-enterprise"
    Push-Location $agentEnterpriseDir
    try {
        cargo build -p safeprompt-license-tool -p safeprompt-service
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
        $enterpriseCargoMetadata = cargo metadata --no-deps --format-version=1 | ConvertFrom-Json
        $enterpriseTargetDir = $enterpriseCargoMetadata.target_directory
    } finally {
        Pop-Location
    }

    Write-Host "== Building watchdog (agent) ==" -ForegroundColor Cyan
    Push-Location $agentDir
    try {
        cargo build -p safeprompt-watchdog
        if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
        $agentCargoMetadata = cargo metadata --no-deps --format-version=1 | ConvertFrom-Json
        $agentTargetDir = $agentCargoMetadata.target_directory
    } finally {
        Pop-Location
    }

    $runDir = Join-Path $workDir "run"
    New-Item -ItemType Directory -Path $runDir | Out-Null
    Copy-Item (Join-Path $enterpriseTargetDir "debug\safeprompt-service.exe") (Join-Path $runDir "safeprompt-service.exe")
    Copy-Item (Join-Path $agentTargetDir "debug\safeprompt-watchdog.exe") (Join-Path $runDir "safeprompt-watchdog.exe")
    $serviceExe = Join-Path $runDir "safeprompt-service.exe"
    $watchdogExe = Join-Path $runDir "safeprompt-watchdog.exe"

    Write-Host "`n== Generating a disposable test code-signing certificate ==" -ForegroundColor Cyan
    # X.500 Subject strings can't contain ':' unescaped, so a colon-free
    # unique suffix (a GUID) is used rather than a raw ISO-8601 timestamp.
    $testCert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject "CN=SafePrompt Authenticode Test (disposable, $([guid]::NewGuid()))" `
        -KeyUsage DigitalSignature -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddDays(1)
    $thumbprint = $testCert.Thumbprint
    Write-Host "Test certificate thumbprint: $thumbprint"

    # Trust it in CurrentUser Root -- simulates what a real deployment does
    # via GPO-pushed trusted-root distribution for an enterprise-internal CA.
    # Deliberately NOT the raw X509Store.Add() .NET API here: adding to the
    # Root store that way triggers a native "you are about to install a
    # certificate..." confirmation dialog that blocks forever with no user
    # present to click it (a real hang hit while writing this script).
    # `certutil -addstore -f` is the standard non-interactive workaround.
    $certFile = Join-Path $workDir "test-cert.cer"
    Export-Certificate -Cert $testCert -FilePath $certFile | Out-Null
    certutil -addstore -f -user Root $certFile | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "certutil -addstore failed with exit code $LASTEXITCODE" }

    Write-Host "`n== Signing the service binary ==" -ForegroundColor Cyan
    powershell -File (Join-Path $installerDir "sign.ps1") -Files @($serviceExe) -CertThumbprint $thumbprint
    if ($LASTEXITCODE -ne 0) { throw "signing failed" }

    $licenseTool = Join-Path $enterpriseTargetDir "debug\license-tool.exe"
    $keysDir = Join-Path $workDir "keys"
    New-Item -ItemType Directory -Path $keysDir | Out-Null
    & $licenseTool keygen --out-dir $keysDir | Out-Null
    Copy-Item (Join-Path $keysDir "verifying_key.hex") (Join-Path $runDir "integrity_public_key.hex")

    $env:SAFEPROMPT_SERVICE_PATH = $serviceExe
    $env:SAFEPROMPT_INTEGRITY_PUBLIC_KEY = Join-Path $runDir "integrity_public_key.hex"
    $env:RUST_LOG = "info"

    function Start-Watchdog([string]$manifestPath, [string]$label) {
        $env:SAFEPROMPT_INTEGRITY_MANIFEST_PATH = $manifestPath
        $stdout = Join-Path $runDir "watchdog-$label.out.log"
        $stderr = Join-Path $runDir "watchdog-$label.err.log"
        $proc = Start-Process -FilePath $watchdogExe -WorkingDirectory $runDir `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru -WindowStyle Hidden
        $spawnedProcs.Add($proc) | Out-Null
        # .GetNewClosure() is required here -- a plain scriptblock does NOT
        # capture this function's local $stdout/$stderr the way a lambda
        # would in most other languages; without it, `& $result.Log`
        # evaluates those names in the *caller's* scope later, where they
        # don't exist, and Get-Content fails with a null path. A real bug
        # hit while writing this script, not a hypothetical one.
        $logGetter = { (Get-Content $stdout -Raw -ErrorAction SilentlyContinue) + (Get-Content $stderr -Raw -ErrorAction SilentlyContinue) }.GetNewClosure()
        return @{ Proc = $proc; Log = $logGetter }
    }

    # ---- Scenario 1: correct hash + correct signer -> spawns successfully ----
    Write-Host "`n== Scenario 1: correctly signed binary, manifest pins the real signer ==" -ForegroundColor Cyan
    $manifestOk = Join-Path $runDir "manifest-ok.json"
    & $licenseTool manifest --signing-key (Join-Path $keysDir "signing_key.hex") --binary $serviceExe `
        --signer-thumbprint $thumbprint --version "1.0.0" --out $manifestOk | Out-Null

    $w1 = Start-Watchdog $manifestOk "ok"
    $opened1 = Test-Port8844Opens 8000
    Record-Result "correctly signed binary + matching manifest: watchdog spawns it (port 8844 opens)" $opened1 (& $w1.Log)
    Stop-WatchdogTree $w1.Proc

    # ---- Scenario 2: correct hash, WRONG expected signer -> refused ----
    Write-Host "`n== Scenario 2: same binary, manifest pins the WRONG signer thumbprint ==" -ForegroundColor Cyan
    $manifestWrongSigner = Join-Path $runDir "manifest-wrong-signer.json"
    & $licenseTool manifest --signing-key (Join-Path $keysDir "signing_key.hex") --binary $serviceExe `
        --signer-thumbprint "0000000000000000000000000000000000000000" --version "1.0.0" --out $manifestWrongSigner | Out-Null

    $w2 = Start-Watchdog $manifestWrongSigner "wrongsigner"
    $opened2 = Test-Port8844Opens 5000
    Record-Result "manifest pinning the wrong signer: watchdog refuses to spawn (port never opens)" (-not $opened2) (& $w2.Log)
    Record-Result "log names the signer mismatch specifically, not just a generic failure" ((& $w2.Log) -match "(?i)signer|thumbprint") (& $w2.Log)
    Stop-WatchdogTree $w2.Proc

    # ---- Scenario 3: tampered binary (breaks hash AND signature) -> refused ----
    Write-Host "`n== Scenario 3: tampering the signed binary after the manifest was issued ==" -ForegroundColor Cyan
    [System.IO.File]::AppendAllText($serviceExe, "TAMPERED-BYTES-APPENDED-AFTER-SIGNING")

    $w3 = Start-Watchdog $manifestOk "tampered"
    $opened3 = Test-Port8844Opens 5000
    Record-Result "tampered binary (correct manifest): watchdog refuses to spawn it (port never opens)" (-not $opened3) (& $w3.Log)
    Stop-WatchdogTree $w3.Proc
} finally {
    foreach ($p in $spawnedProcs) {
        try { if (-not $p.HasExited) { Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" -ErrorAction SilentlyContinue | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }; Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch {}
    }
    Remove-Item Env:\SAFEPROMPT_SERVICE_PATH, Env:\SAFEPROMPT_INTEGRITY_PUBLIC_KEY, Env:\SAFEPROMPT_INTEGRITY_MANIFEST_PATH, Env:\RUST_LOG -ErrorAction SilentlyContinue

    if ($testCert) {
        Write-Host "`n== Removing the disposable test certificate from CurrentUser stores ==" -ForegroundColor Yellow
        # certutil -delstore, not Remove-Item, for the same non-interactive-hang reason -addstore needed it above.
        certutil -delstore -user Root $testCert.Thumbprint 2>&1 | Out-Null
        Get-ChildItem "Cert:\CurrentUser\Root" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $testCert.Thumbprint } | Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem "Cert:\CurrentUser\My" -ErrorAction SilentlyContinue | Where-Object { $_.Thumbprint -eq $testCert.Thumbprint } | Remove-Item -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
foreach ($r in $results) {
    $status = if ($r.Passed) { "PASS" } else { "FAIL" }
    Write-Host ("{0,-95} {1}" -f $r.Name, $status)
}

$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    Write-Host "`n$($failed.Count) of $($results.Count) checks FAILED." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll $($results.Count) checks passed." -ForegroundColor Green
    exit 0
}
