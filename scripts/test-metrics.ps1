<#
.SYNOPSIS
    End-to-end validation of the SafePrompt Agent's Prometheus metrics endpoint.

.DESCRIPTION
    Proves the Metrics exporter works against the real service binary, not
    just in unit tests: starts the service pointed at a local mock upstream
    (no external API key needed), sends a secret-bearing request (blocked)
    and a clean request (allowed), then scrapes the real `GET /metrics`
    endpoint on its own port and checks the real Prometheus text output:
    request counts by event_type/action, provider usage, and a non-zero
    latency histogram — not just that the crate's own unit tests pass in
    isolation.

.EXAMPLE
    powershell -File agent\scripts\test-metrics.ps1
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
$workDir = Join-Path $env:TEMP "safeprompt-metrics-validation"

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

Write-Host "== Building the Agent service ==" -ForegroundColor Cyan
Push-Location $agentDir
try {
    cargo build -p safeprompt-service
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

$serviceBin = Join-Path $agentDir "target\debug\safeprompt-service.exe"
$runDir = Join-Path $workDir "run"
New-Item -ItemType Directory -Path $runDir | Out-Null

# --- Local mock upstream (no real API key needed) ---------------------------
$mockUpstreamPort = 18845
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
        $responseBody = '{"id":"mock-1","choices":[{"message":{"role":"assistant","content":"nothing sensitive here"}}]}'
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
        $context.Response.ContentType = "application/json"
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.OutputStream.Close()
    }
} -ArgumentList $mockUpstreamPort

Start-Sleep -Milliseconds 500

$env:SAFEPROMPT_UPSTREAM_BASE_URL = "http://127.0.0.1:$mockUpstreamPort"
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
$startedUp = Wait-ForLogMatch "metrics endpoint listening" 8000
Record-Result "service starts up and opens the metrics endpoint (not license-gated)" $startedUp (Get-ServiceLog)

Write-Host "`n== Sending a request containing a secret (must be blocked) ==" -ForegroundColor Cyan
$blockedBody = @{ model = "gpt-4"; messages = @(@{ role = "user"; content = "here is my AWS key: AKIAIOSFODNN7EXAMPLE" }) } | ConvertTo-Json -Compress
try {
    Invoke-WebRequest -Uri "http://127.0.0.1:8844/v1/chat/completions" -Method Post -Body $blockedBody -ContentType "application/json" -UseBasicParsing | Out-Null
} catch {
    # expected: 403
}

Write-Host "`n== Sending a clean request (must be allowed and forwarded) ==" -ForegroundColor Cyan
$cleanBody = @{ model = "gpt-4"; messages = @(@{ role = "user"; content = "what is the capital of Italy?" }) } | ConvertTo-Json -Compress
Invoke-WebRequest -Uri "http://127.0.0.1:8844/v1/chat/completions" -Method Post -Body $cleanBody -ContentType "application/json" -UseBasicParsing | Out-Null

Start-Sleep -Milliseconds 500

Write-Host "`n== Scraping GET /metrics on its own port (8846) ==" -ForegroundColor Cyan
$metricsResponse = Invoke-WebRequest -Uri "http://127.0.0.1:8846/metrics" -UseBasicParsing
Record-Result "metrics endpoint responds 200 on its own port" ($metricsResponse.StatusCode -eq 200) "got status $($metricsResponse.StatusCode)"
$metricsText = $metricsResponse.Content

Record-Result "metrics text is valid Prometheus exposition format (HELP/TYPE lines present)" `
    ($metricsText -match "# HELP safeprompt_requests_total" -and $metricsText -match "# TYPE safeprompt_requests_total counter") $metricsText

Record-Result "blocked request is counted (event_type=request, action=Block)" `
    ($metricsText -match 'safeprompt_requests_total\{event_type="request",action="Block"\} [1-9]') $metricsText
Record-Result "allowed request is counted (event_type=request, action=Allow)" `
    ($metricsText -match 'safeprompt_requests_total\{event_type="request",action="Allow"\} [1-9]') $metricsText
Record-Result "allowed request's response scan is also counted (event_type=response, action=Allow)" `
    ($metricsText -match 'safeprompt_requests_total\{event_type="response",action="Allow"\} [1-9]') $metricsText

Record-Result "provider usage is counted for the single-upstream fallback (legacy_upstream)" `
    ($metricsText -match 'safeprompt_provider_requests_total\{provider="legacy_upstream"\} [1-9]') $metricsText

Record-Result "latency histogram recorded at least 2 observations (both requests)" `
    ($metricsText -match 'safeprompt_request_duration_seconds_count 2') $metricsText

if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
Stop-Job -Job $mockJob -ErrorAction SilentlyContinue | Out-Null
Remove-Job -Job $mockJob -Force -ErrorAction SilentlyContinue | Out-Null
Remove-Item Env:\SAFEPROMPT_UPSTREAM_BASE_URL -ErrorAction SilentlyContinue

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
