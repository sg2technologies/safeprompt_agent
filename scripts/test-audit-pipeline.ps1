<#
.SYNOPSIS
    End-to-end validation of the SafePrompt Agent Audit Pipeline.

.DESCRIPTION
    Proves the audit pipeline works against the real service binary, not
    just in unit tests: starts the service with a real encrypted SQLite
    audit database and a local mock upstream (so no external API key is
    needed), sends one request containing a secret (blocked -> 1 audit
    event) and one clean request (allowed -> request+response = 2 audit
    events), stops the service, then uses `license-tool audit-export` to
    pull the events back out and checks: the right total count, the right
    action_taken values, and that the raw .db file on disk never contains
    the plaintext secret (proving findings are actually encrypted at rest,
    not just in the storage crate's own unit tests).

.EXAMPLE
    powershell -File agent\scripts\test-audit-pipeline.ps1
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
$agentEnterpriseDir = Join-Path (Split-Path -Parent $agentDir) "agent-enterprise"
$workDir = Join-Path $env:TEMP "safeprompt-audit-pipeline-validation"

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

$runDir = Join-Path $workDir "run"
New-Item -ItemType Directory -Path $runDir | Out-Null

# Feature gating is strict (see safeprompt-licensing::features): the Audit
# Pipeline only persists events at all if the running license includes
# "siem". Same stand-in "vendor" issuer keypair pattern as the other scripts.
$keysDir = Join-Path $runDir "keys"
New-Item -ItemType Directory -Path $keysDir | Out-Null
& $licenseTool keygen --out-dir $keysDir | Out-Null
$signingKey = Join-Path $keysDir "signing_key.hex"
$licensePath = Join-Path $runDir "license.json"
& $licenseTool issue --signing-key $signingKey --tenant "Acme Corp" --edition enterprise `
    --devices 25 --days 365 --features "siem" --out $licensePath | Out-Null

# --- Local mock upstream (no real API key needed) ---------------------------
# A minimal HttpListener standing in for "https://api.openai.com": returns a
# fixed, secret-free JSON body so the clean request produces a real
# request+response round trip without depending on external network/creds.
$mockUpstreamPort = 18844
$mockJob = Start-Job -ScriptBlock {
    param($port)
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    $listener.Start()
    while ($listener.IsListening) {
        try {
            $context = $listener.GetContext()
        } catch {
            break
        }
        $responseBody = '{"id":"mock-1","choices":[{"message":{"role":"assistant","content":"hello, nothing sensitive here"}}]}'
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
        $context.Response.ContentType = "application/json"
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.OutputStream.Close()
    }
} -ArgumentList $mockUpstreamPort

Start-Sleep -Milliseconds 500

$auditDbPath = Join-Path $runDir "audit.db"
$auditSecret = "audit-pipeline-validation-secret-do-not-use-in-prod"
$tenantId = "acme-validation-tenant"

$env:SAFEPROMPT_UPSTREAM_BASE_URL = "http://127.0.0.1:$mockUpstreamPort"
$env:SAFEPROMPT_AUDIT_ENCRYPTION_SECRET = $auditSecret
$env:SAFEPROMPT_AUDIT_DB_PATH = $auditDbPath
$env:SAFEPROMPT_TENANT_ID = $tenantId
$env:SAFEPROMPT_LICENSE_PATH = $licensePath
$env:SAFEPROMPT_LICENSE_PUBLIC_KEY = Join-Path $keysDir "verifying_key.hex"
$env:RUST_LOG = "info"

$stdoutLog = Join-Path $runDir "service.out.log"
$stderrLog = Join-Path $runDir "service.err.log"
$proc = Start-Process -FilePath $serviceBin -WorkingDirectory $runDir `
    -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru -WindowStyle Hidden

function Get-ServiceLog {
    $content = ""
    if (Test-Path $stdoutLog) { $content += (Get-Content $stdoutLog -Raw) }
    if (Test-Path $stderrLog) { $content += (Get-Content $stderrLog -Raw) }
    return $content
}

function Wait-ForLogMatch([string]$literalText, [int]$maxWaitMs) {
    $elapsed = 0
    while ($elapsed -lt $maxWaitMs) {
        if ((Get-ServiceLog).Contains($literalText)) { return $true }
        Start-Sleep -Milliseconds 300
        $elapsed += 300
    }
    return $false
}

Write-Host "`n== Waiting for service startup ==" -ForegroundColor Cyan
$startedUp = Wait-ForLogMatch "initialization complete" 8000
Record-Result "service starts up and opens the audit database" $startedUp (Get-ServiceLog)
Record-Result "log confirms the audit database was opened at the configured path" ((Get-ServiceLog).Contains("audit database opened at")) (Get-ServiceLog)

$secretValue = "AKIAIOSFODNN7EXAMPLE"

Write-Host "`n== Sending a request containing a secret (must be blocked) ==" -ForegroundColor Cyan
$blockedBody = @{ model = "gpt-4"; messages = @(@{ role = "user"; content = "here is my AWS key: $secretValue" }) } | ConvertTo-Json -Compress
try {
    Invoke-WebRequest -Uri "http://127.0.0.1:8844/v1/chat/completions" -Method Post -Body $blockedBody -ContentType "application/json" -UseBasicParsing | Out-Null
    $blockedStatus = 200
} catch {
    $blockedStatus = $_.Exception.Response.StatusCode.value__
}
Record-Result "request containing a secret is blocked with 403" ($blockedStatus -eq 403) "got status $blockedStatus"

Write-Host "`n== Sending a clean request (must be allowed and forwarded) ==" -ForegroundColor Cyan
$cleanBody = @{ model = "gpt-4"; messages = @(@{ role = "user"; content = "what is the capital of France?" }) } | ConvertTo-Json -Compress
$cleanResponse = Invoke-WebRequest -Uri "http://127.0.0.1:8844/v1/chat/completions" -Method Post -Body $cleanBody -ContentType "application/json" -UseBasicParsing
Record-Result "clean request is allowed and forwarded to upstream (200)" ($cleanResponse.StatusCode -eq 200) "got status $($cleanResponse.StatusCode)"

Start-Sleep -Milliseconds 500 # let the async persist_event() writes land

if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 500 # let port 8844 release before starting the second instance

Write-Host "`n== Confirming the gate itself: an unlicensed Agent must NOT persist audit events ==" -ForegroundColor Cyan
$unlicensedRunDir = Join-Path $workDir "run-unlicensed"
New-Item -ItemType Directory -Path $unlicensedRunDir | Out-Null
$unlicensedDbPath = Join-Path $unlicensedRunDir "audit.db"

Remove-Item Env:\SAFEPROMPT_LICENSE_PATH, Env:\SAFEPROMPT_LICENSE_PUBLIC_KEY -ErrorAction SilentlyContinue
$env:SAFEPROMPT_AUDIT_DB_PATH = $unlicensedDbPath

$unlicensedOut = Join-Path $unlicensedRunDir "service.out.log"
$unlicensedErr = Join-Path $unlicensedRunDir "service.err.log"
$unlicensedProc = Start-Process -FilePath $serviceBin -WorkingDirectory $unlicensedRunDir `
    -RedirectStandardOutput $unlicensedOut -RedirectStandardError $unlicensedErr -PassThru -WindowStyle Hidden

$unlicensedElapsed = 0
$unlicensedLog = ""
while ($unlicensedElapsed -lt 8000) {
    $unlicensedLog = ""
    if (Test-Path $unlicensedOut) { $unlicensedLog += Get-Content $unlicensedOut -Raw }
    if (Test-Path $unlicensedErr) { $unlicensedLog += Get-Content $unlicensedErr -Raw }
    if ($unlicensedLog.Contains("initialization complete")) { break }
    Start-Sleep -Milliseconds 300
    $unlicensedElapsed += 300
}
Record-Result "unlicensed startup logs that the Audit Pipeline is not enabled (missing 'siem' feature)" `
    ($unlicensedLog.Contains("Audit Pipeline is not enabled") -and $unlicensedLog.Contains("siem")) $unlicensedLog

$unlicensedCleanBody = @{ model = "gpt-4"; messages = @(@{ role = "user"; content = "what is the capital of Germany?" }) } | ConvertTo-Json -Compress
Invoke-WebRequest -Uri "http://127.0.0.1:8844/v1/chat/completions" -Method Post -Body $unlicensedCleanBody -ContentType "application/json" -UseBasicParsing | Out-Null
Start-Sleep -Milliseconds 500

if (-not $unlicensedProc.HasExited) { Stop-Process -Id $unlicensedProc.Id -Force -ErrorAction SilentlyContinue }
Record-Result "no audit database file is even created without the 'siem' license feature" (-not (Test-Path $unlicensedDbPath)) "expected no file at $unlicensedDbPath"

Stop-Job -Job $mockJob -ErrorAction SilentlyContinue | Out-Null
Remove-Job -Job $mockJob -Force -ErrorAction SilentlyContinue | Out-Null

Write-Host "`n== Exporting audit events via license-tool ==" -ForegroundColor Cyan
$exportPath = Join-Path $runDir "export.json"
& $licenseTool audit-export --db $auditDbPath --secret $auditSecret --tenant $tenantId --format json --since-days 1 --out $exportPath | Out-Null

$exportExists = Test-Path $exportPath
Record-Result "audit-export produces an output file" $exportExists "expected file at $exportPath"

if ($exportExists) {
    $events = Get-Content $exportPath -Raw | ConvertFrom-Json
    Record-Result "exactly 3 audit events were persisted (1 blocked request + 1 allowed request + 1 allowed response)" ($events.Count -eq 3) "got $($events.Count) events"

    $blockedEvents = @($events | Where-Object { $_.action_taken -eq "Block" })
    $allowedEvents = @($events | Where-Object { $_.action_taken -eq "Allow" })
    Record-Result "1 event recorded with action_taken = Block" ($blockedEvents.Count -eq 1) "got $($blockedEvents.Count)"
    Record-Result "2 events recorded with action_taken = Allow" ($allowedEvents.Count -eq 2) "got $($allowedEvents.Count)"

    $requestEvents = @($events | Where-Object { $_.event_type -eq "request" })
    $responseEvents = @($events | Where-Object { $_.event_type -eq "response" })
    Record-Result "2 request-scan events and 1 response-scan event recorded" ($requestEvents.Count -eq 2 -and $responseEvents.Count -eq 1) "requests=$($requestEvents.Count) responses=$($responseEvents.Count)"

    $blockedFindingSnippets = ($blockedEvents | ForEach-Object { $_.findings } | ForEach-Object { $_.snippet }) -join " "
    Record-Result "the blocked event's decrypted findings actually reference the AWS-key finding" ($blockedFindingSnippets -match "AKIA") "snippets: $blockedFindingSnippets"
}

Write-Host "`n== Confirming findings are encrypted at rest (raw .db file has no plaintext secret) ==" -ForegroundColor Cyan
$latin1 = [System.Text.Encoding]::GetEncoding(28591) # ISO-8859-1: byte-for-byte, unlike UTF8 (Encoding.Latin1 doesn't exist in PowerShell 5.1's .NET Framework)
$rawDbBytes = [System.IO.File]::ReadAllText($auditDbPath, $latin1)
$secretLeaked = $rawDbBytes.Contains($secretValue)
Record-Result "the plaintext AWS key does not appear anywhere in the raw .db file bytes" (-not $secretLeaked) "Contains(secret) = $secretLeaked"

Remove-Item Env:\SAFEPROMPT_UPSTREAM_BASE_URL, Env:\SAFEPROMPT_AUDIT_ENCRYPTION_SECRET, Env:\SAFEPROMPT_AUDIT_DB_PATH, `
    Env:\SAFEPROMPT_TENANT_ID, Env:\SAFEPROMPT_LICENSE_PATH, Env:\SAFEPROMPT_LICENSE_PUBLIC_KEY -ErrorAction SilentlyContinue

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
