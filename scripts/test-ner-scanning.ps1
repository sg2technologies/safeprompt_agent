<#
.SYNOPSIS
    End-to-end validation of Layer-2 NER scanning (PresidioScanner) wired
    into the real Agent service.

.DESCRIPTION
    Proves the full chain works against the real running service binary, not
    just the crate-level unit/live-subprocess tests: license-gates the
    `advanced_ner` feature, points SAFEPROMPT_NER_SCANNER_PATH at a real
    scanner backend, and sends a request containing a person's name with NO
    other PII/secret/injection pattern in it -- something Layer 1
    (regex/checksum) genuinely cannot catch, so a PERSON finding reaching
    the audit log is proof the whole pipeline actually ran inside the real
    service, not just in an isolated test. Also proves the negative: the
    same text produces no PERSON finding when the license lacks the
    `advanced_ner` feature.

    Two backends, same protocol, same test:
      - Default (dev mode): the real `backend/venv` Python running the real
        `presidio_scanner.py` directly.
      - `-UseFrozenExe`: the PyInstaller-frozen `dist\presidio-scanner.exe`
        with no Python/venv involved at all -- this is what actually ships
        to a customer, so it's the one that matters for "does the
        installer's NER story work," not just "does Presidio work."

    Skips itself (not a failure) if the selected backend isn't present on
    this machine -- same self-skip posture as the `safeprompt-scanner`
    crate's own live tests.

.EXAMPLE
    powershell -File agent\scripts\test-ner-scanning.ps1
    powershell -File agent\scripts\test-ner-scanning.ps1 -UseFrozenExe
#>

param(
    [switch]$UseFrozenExe
)

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
$agentEnterpriseDir = Join-Path (Split-Path -Parent $agentDir) "agent-enterprise"
$repoDir = Split-Path -Parent $agentDir

if ($UseFrozenExe) {
    $nerScannerPath = Join-Path $scriptDir "dist\presidio-scanner.exe"
    $nerScannerArgs = ""
    $backendLabel = "frozen exe (dist\presidio-scanner.exe)"
} else {
    $nerScannerPath = Join-Path $repoDir "backend\venv\Scripts\python.exe"
    $nerScannerArgs = Join-Path $agentDir "scripts\presidio_scanner.py"
    $backendLabel = "backend/venv Python + presidio_scanner.py"
}

if (-not (Test-Path $nerScannerPath)) {
    Write-Host "SKIP: NER scanner backend not present at $nerScannerPath -- nothing to validate against." -ForegroundColor Yellow
    Write-Host "      (backend selected: $backendLabel)" -ForegroundColor Yellow
    exit 0
}
Write-Host "Testing NER scanner backend: $backendLabel" -ForegroundColor Cyan

$workDir = Join-Path $env:TEMP "safeprompt-ner-scanning-validation"
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

$licenseTool = Join-Path $enterpriseTargetDir "debug\license-tool.exe"
$serviceBin = Join-Path $enterpriseTargetDir "debug\safeprompt-service.exe"

# --- Local mock upstream (no real API key needed) ---------------------------
$mockUpstreamPort = 18847
$mockJob = Start-Job -ScriptBlock {
    param($port)
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    $listener.Start()
    while ($listener.IsListening) {
        try { $context = $listener.GetContext() } catch { break }
        $responseBody = '{"id":"mock-1","choices":[{"message":{"role":"assistant","content":"noted, thanks"}}]}'
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
        $context.Response.ContentType = "application/json"
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.OutputStream.Close()
    }
} -ArgumentList $mockUpstreamPort
Start-Sleep -Milliseconds 500

# Text containing a PERSON entity only spaCy/Presidio NER can catch — no
# email/phone/secret/injection pattern anywhere in it, so any PERSON finding
# reaching the audit log can only have come from Layer 2, not Layer 1.
$nerOnlyText = "Please loop in Jane Doe on this project before Friday."

function Start-Agent([string]$runDir, [hashtable]$envOverrides) {
    New-Item -ItemType Directory -Path $runDir -Force | Out-Null
    foreach ($key in $envOverrides.Keys) { Set-Item -Path "Env:\$key" -Value $envOverrides[$key] }
    $stdoutLog = Join-Path $runDir "service.out.log"
    $stderrLog = Join-Path $runDir "service.err.log"
    $proc = Start-Process -FilePath $serviceBin -WorkingDirectory $runDir `
        -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru -WindowStyle Hidden
    return [PSCustomObject]@{ Proc = $proc; StdoutLog = $stdoutLog; StderrLog = $stderrLog }
}

function Get-RunLog($run) {
    $content = ""
    if (Test-Path $run.StdoutLog) { $content += (Get-Content $run.StdoutLog -Raw) }
    if (Test-Path $run.StderrLog) { $content += (Get-Content $run.StderrLog -Raw) }
    return $content
}

function Wait-ForLogMatch($run, [string]$literalText, [int]$maxWaitMs) {
    $elapsed = 0
    while ($elapsed -lt $maxWaitMs) {
        if ((Get-RunLog $run).Contains($literalText)) { return $true }
        Start-Sleep -Milliseconds 300
        $elapsed += 300
    }
    return $false
}

# ============================================================================
# Run 1: licensed for advanced_ner + siem — the PERSON finding should reach
# the real audit log through the real subprocess.
# ============================================================================
Write-Host "`n== Run 1: licensed for 'advanced_ner' ==" -ForegroundColor Cyan
$run1Dir = Join-Path $workDir "run-licensed"
New-Item -ItemType Directory -Path $run1Dir | Out-Null
$keysDir = Join-Path $run1Dir "keys"
New-Item -ItemType Directory -Path $keysDir | Out-Null
& $licenseTool keygen --out-dir $keysDir | Out-Null
$licensePath = Join-Path $run1Dir "license.json"
& $licenseTool issue --signing-key (Join-Path $keysDir "signing_key.hex") --tenant "Acme Corp" --edition enterprise `
    --devices 25 --days 365 --features "advanced_ner,siem" --out $licensePath | Out-Null

$auditDbPath = Join-Path $run1Dir "audit.db"
$auditSecret = "ner-scanning-validation-secret-do-not-use-in-prod"
$tenantId = "acme-ner-validation-tenant"

$run1 = Start-Agent $run1Dir @{
    SAFEPROMPT_UPSTREAM_BASE_URL      = "http://127.0.0.1:$mockUpstreamPort"
    SAFEPROMPT_LICENSE_PATH           = $licensePath
    SAFEPROMPT_LICENSE_PUBLIC_KEY     = (Join-Path $keysDir "verifying_key.hex")
    SAFEPROMPT_NER_SCANNER_PATH       = $nerScannerPath
    SAFEPROMPT_NER_SCANNER_ARGS       = $nerScannerArgs
    SAFEPROMPT_AUDIT_ENCRYPTION_SECRET = $auditSecret
    SAFEPROMPT_AUDIT_DB_PATH          = $auditDbPath
    SAFEPROMPT_TENANT_ID              = $tenantId
    RUST_LOG                          = "info"
}

# Generous timeout: this is the run where the subprocess has to cold-spawn
# and spaCy has to cold-load a model, which is the slow path by design.
$startedUp = Wait-ForLogMatch $run1 "advanced NER scanning ready" 30000
Record-Result "licensed startup logs that advanced NER scanning is ready (real subprocess health-checked)" $startedUp (Get-RunLog $run1)

Write-Host "`n== Sending NER-only text (no regex-catchable pattern) ==" -ForegroundColor Cyan
$body = @{ model = "gpt-4"; messages = @(@{ role = "user"; content = $nerOnlyText }) } | ConvertTo-Json -Compress
$response = Invoke-WebRequest -Uri "http://127.0.0.1:8844/v1/chat/completions" -Method Post -Body $body -ContentType "application/json" -UseBasicParsing
Record-Result "request is allowed through (Redact, not Block -- a name alone isn't a secret)" ($response.StatusCode -eq 200) "got status $($response.StatusCode)"

Start-Sleep -Milliseconds 500
if (-not $run1.Proc.HasExited) { Stop-Process -Id $run1.Proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 500

$export1Path = Join-Path $run1Dir "export.json"
& $licenseTool audit-export --db $auditDbPath --secret $auditSecret --tenant $tenantId --format json --since-days 1 --out $export1Path | Out-Null
if (Test-Path $export1Path) {
    $events1 = Get-Content $export1Path -Raw | ConvertFrom-Json
    $personFindings = @($events1 | ForEach-Object { $_.findings } | Where-Object { $_.match_name -eq "PERSON" })
    Record-Result "a real PERSON finding (from real spaCy NER, not regex) reached the audit log" `
        ($personFindings.Count -ge 1) "findings seen: $((@($events1 | ForEach-Object { $_.findings } | ForEach-Object { $_.match_name })) -join ', ')"
    if ($personFindings.Count -ge 1) {
        Record-Result "the PERSON finding's snippet is the actual name from the request" `
            ($personFindings[0].snippet -eq "Jane Doe") "got snippet: '$($personFindings[0].snippet)'"
    }
} else {
    Record-Result "audit-export produced an output file" $false "expected file at $export1Path"
}

# ============================================================================
# Run 2: same text, no 'advanced_ner' feature — must NOT see a PERSON
# finding, proving the license gate actually gates Layer 2 (Layer 1 is
# unaffected either way, since this text has nothing for Layer 1 to catch).
# ============================================================================
Write-Host "`n== Run 2: unlicensed for 'advanced_ner' (gate must hold) ==" -ForegroundColor Cyan
$run2Dir = Join-Path $workDir "run-unlicensed"
$licensePath2 = Join-Path $run1Dir "license-no-ner.json"
& $licenseTool issue --signing-key (Join-Path $keysDir "signing_key.hex") --tenant "Acme Corp" --edition enterprise `
    --devices 25 --days 365 --features "siem" --out $licensePath2 | Out-Null
$auditDbPath2 = Join-Path $run2Dir "audit.db"

$run2 = Start-Agent $run2Dir @{
    SAFEPROMPT_UPSTREAM_BASE_URL      = "http://127.0.0.1:$mockUpstreamPort"
    SAFEPROMPT_LICENSE_PATH           = $licensePath2
    SAFEPROMPT_LICENSE_PUBLIC_KEY     = (Join-Path $keysDir "verifying_key.hex")
    SAFEPROMPT_NER_SCANNER_PATH       = $nerScannerPath
    SAFEPROMPT_NER_SCANNER_ARGS       = $nerScannerArgs
    SAFEPROMPT_AUDIT_ENCRYPTION_SECRET = $auditSecret
    SAFEPROMPT_AUDIT_DB_PATH          = $auditDbPath2
    SAFEPROMPT_TENANT_ID              = $tenantId
    RUST_LOG                          = "info"
}
Wait-ForLogMatch $run2 "initialization complete" 8000 | Out-Null
Record-Result "unlicensed startup logs that advanced NER is not enabled (missing 'advanced_ner' feature)" `
    ((Get-RunLog $run2).Contains("advanced NER scanning is not enabled") -and (Get-RunLog $run2).Contains("advanced_ner")) (Get-RunLog $run2)

Invoke-WebRequest -Uri "http://127.0.0.1:8844/v1/chat/completions" -Method Post -Body $body -ContentType "application/json" -UseBasicParsing | Out-Null
Start-Sleep -Milliseconds 500
if (-not $run2.Proc.HasExited) { Stop-Process -Id $run2.Proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 500

$export2Path = Join-Path $run2Dir "export.json"
& $licenseTool audit-export --db $auditDbPath2 --secret $auditSecret --tenant $tenantId --format json --since-days 1 --out $export2Path | Out-Null
if (Test-Path $export2Path) {
    $events2 = Get-Content $export2Path -Raw | ConvertFrom-Json
    $personFindings2 = @($events2 | ForEach-Object { $_.findings } | Where-Object { $_.match_name -eq "PERSON" })
    Record-Result "no PERSON finding appears without the 'advanced_ner' feature (gate actually gates)" `
        ($personFindings2.Count -eq 0) "found $($personFindings2.Count) PERSON findings"
} else {
    Record-Result "audit-export produced an output file (unlicensed run)" $false "expected file at $export2Path"
}

Stop-Job -Job $mockJob -ErrorAction SilentlyContinue | Out-Null
Remove-Job -Job $mockJob -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item Env:\SAFEPROMPT_UPSTREAM_BASE_URL, Env:\SAFEPROMPT_LICENSE_PATH, Env:\SAFEPROMPT_LICENSE_PUBLIC_KEY, `
    Env:\SAFEPROMPT_NER_SCANNER_PATH, Env:\SAFEPROMPT_NER_SCANNER_ARGS, Env:\SAFEPROMPT_AUDIT_ENCRYPTION_SECRET, `
    Env:\SAFEPROMPT_AUDIT_DB_PATH, Env:\SAFEPROMPT_TENANT_ID -ErrorAction SilentlyContinue

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
foreach ($r in $results) {
    $status = if ($r.Passed) { "PASS" } else { "FAIL" }
    Write-Host ("{0,-85} {1}" -f $r.Name, $status)
}

$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    Write-Host "`n$($failed.Count) of $($results.Count) checks FAILED." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll $($results.Count) checks passed." -ForegroundColor Green
    exit 0
}
