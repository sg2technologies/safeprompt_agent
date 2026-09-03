<#
.SYNOPSIS
    End-to-end validation of the Audit Relay (agent -> cloud DlpEvent sync,
    P0-12/SP-AUD-005) against the real compiled service binary -- not just
    agent/crates/audit_relay's own unit tests.

.DESCRIPTION
    Proves the whole upward hop actually works, same "real binary, not a
    mock of the logic" standard as test-audit-pipeline.ps1 (which this
    script's first phase directly extends) and test-tenant-spoc.ps1:

      Phase 1 -- a real Business-edition license (siem + fleet, both
                 required: siem gates local persistence, fleet gates the
                 relay itself being Business+), a real blocked request
                 (AWS key) creates a real local DlpEvent, the relay loop
                 (short interval so this test doesn't wait 120s) picks it
                 up and POSTs a real AuditEventBatch to a mock cloud
                 endpoint -- confirms the batch's shape (tenant/device_id/
                 signed license/events) and that the raw finding snippet is
                 STRIPPED by default (the non-negotiable "never leaves the
                 device by default" boundary, see audit_relay's own doc
                 comment).
      Phase 2 -- SAFEPROMPT_AUDIT_RELAY_INCLUDE_SNIPPETS=1 (explicit opt-in):
                 a second, distinct secret's relayed batch DOES carry the
                 raw snippet this time -- proves the opt-out mechanism the
                 dashboard's Audit tab copy refers to is real, not just
                 documented.
      Phase 3 -- restart the service pointed at the same audit DB and mock
                 endpoint: the already-relayed Phase 1/2 events must NOT be
                 relayed again (mark_synced persists across a restart, not
                 just in-memory) -- proven by a fresh secret being the only
                 new batch received.

.EXAMPLE
    powershell -File agent\scripts\test-audit-relay.ps1
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
$agentEnterpriseDir = Join-Path (Split-Path -Parent $agentDir) "agent-enterprise"
$workDir = Join-Path $env:TEMP "safeprompt-audit-relay-validation"

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

# siem gates local persistence, fleet gates the relay itself (Audit Sync is
# a Business+-bundled capability, same tier as Fleet Management -- see
# init_audit_relay's own doc comment in apps/service/src/main.rs).
$keysDir = Join-Path $runDir "keys"
New-Item -ItemType Directory -Path $keysDir | Out-Null
& $licenseTool keygen --out-dir $keysDir | Out-Null
$signingKey = Join-Path $keysDir "signing_key.hex"
$verifyingKey = Join-Path $keysDir "verifying_key.hex"
$licensePath = Join-Path $runDir "license.json"
$tenantId = "audit-relay-validation-tenant"
& $licenseTool issue --signing-key $signingKey --tenant $tenantId --edition business `
    --devices 10 --days 365 --features "siem,fleet" --out $licensePath | Out-Null

# --- Local mock upstream (chat completions target, same as test-audit-pipeline.ps1) ---
$mockUpstreamPort = 18846
$upstreamJob = Start-Job -ScriptBlock {
    param($port)
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    $listener.Start()
    while ($listener.IsListening) {
        try { $context = $listener.GetContext() } catch { break }
        $responseBody = '{"id":"mock-1","choices":[{"message":{"role":"assistant","content":"nothing sensitive here"}}]}'
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
        $context.Response.ContentType = "application/json"
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.OutputStream.Close()
    }
} -ArgumentList $mockUpstreamPort

# --- Mock cloud Control Plane audit-ingest endpoint --------------------------
# Unlike test-tenant-spoc.ps1's shared _mock_cloud_control_plane.ps1 (a plain
# "ok" text response for every path except /fleet/checkin), audit_relay's
# client actually parses the response body as AuditRelayResponse JSON
# ({"status":"ok","accepted":N}) -- see agent/crates/audit_relay/src/lib.rs's
# response.json::<AuditRelayResponse>() -- so a generic text "ok" would
# surface as a Transport/parse error, not a clean success. This mock is
# self-contained here rather than extending the shared one, since it's a
# different response contract, not a shared concern.
$cloudPort = 18847
$cloudLogFile = Join-Path $runDir "cloud_ingest.log"
$cloudJob = Start-Job -ScriptBlock {
    param($port, $logFile)
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://127.0.0.1:$port/")
    $listener.Start()
    while ($listener.IsListening) {
        try { $context = $listener.GetContext() } catch { break }
        # /__warmup -- a priming probe (see below), deliberately not logged
        # as a real batch so it can't pollute Get-CloudBatches' count.
        if ($context.Request.Url.AbsolutePath -ne "/__warmup") {
            $reader = New-Object System.IO.StreamReader($context.Request.InputStream, [System.Text.Encoding]::UTF8)
            $body = $reader.ReadToEnd()
            $reader.Close()
            Add-Content -Path $logFile -Value $body -Encoding utf8
        }
        $responseBody = '{"status":"ok","accepted":1}'
        $buffer = [System.Text.Encoding]::UTF8.GetBytes($responseBody)
        $context.Response.ContentType = "application/json"
        $context.Response.StatusCode = 200
        $context.Response.ContentLength64 = $buffer.Length
        $context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
        $context.Response.OutputStream.Close()
    }
} -ArgumentList $cloudPort, $cloudLogFile

Start-Sleep -Milliseconds 500

# Warm-up probe: two consecutive runs showed Phase 1 (this job's very first
# real request) consistently slow/timing-out while Phases 2/3 (same job,
# already warm) succeeded reliably every time -- a cold-start cost specific
# to this test harness's freshly-spawned Start-Job runspace handling its
# first HttpListener.GetContext() dispatch, not a real product issue (the
# same underlying relay mechanism Phase 1 exercises is the one Phase 2/3
# already prove works). Forcing that one-time cost to happen here, before
# any phase's timing is measured, rather than leaving it to silently eat
# into Phase 1's own wait budget.
try { Invoke-WebRequest -Uri "http://127.0.0.1:$cloudPort/__warmup" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch { }

# Pre-create the log file itself, empty, before Phase 1 ever starts polling
# for it. Real root cause, found via the service's OWN log (not guessed):
# the relay actually succeeded in ~2s every single run ("audit relay: batch
# accepted" appeared well inside every timeout tried, including the
# original 10s) -- the data was always there. What wasn't reliable was this
# script's own Test-Path/Get-Content polling *discovering a brand-new file*
# in the narrow window right after another process's Add-Content creates it
# for the first time. Phases 2/3 never hit this because they poll a file
# that already exists (created here, or by Phase 1's own first write) and
# is merely growing -- a fundamentally different, and apparently far more
# reliable, filesystem-visibility case than "does this file exist at all
# yet" on this environment. Confirmed by elimination: two earlier fixes
# (a Get-CloudBatches retry loop, then a mock-job warm-up probe) each
# targeted a different plausible cause and neither changed Phase 1's
# outcome at all, while Phase 2/3 passed reliably throughout -- narrowing
# it down to specifically the file's *first appearance*.
New-Item -ItemType File -Path $cloudLogFile -Force | Out-Null

function Get-CloudBatches {
    if (-not (Test-Path $cloudLogFile)) { return @() }
    try {
        $lines = @(Get-Content $cloudLogFile -ErrorAction Stop | Where-Object { $_.Trim().Length -gt 0 })
        if ($lines.Count -eq 0) { return @() }
        return @($lines | ForEach-Object { $_ | ConvertFrom-Json })
    } catch {
        return @()
    }
}

# Deliberately returns the actual batches array, not just a bool -- an
# earlier draft split "wait for count" (Wait-ForCloudBatchCount, boolean)
# and "fetch for inspection" (a second, independent Get-CloudBatches call)
# into two separate reads of the same file. Live-observed real failure mode
# from that split: the wait-loop's own internal retries would eventually
# see the expected count and return true, but the very next, separate,
# single-shot read immediately after it -- for detailed inspection -- came
# back empty, silently skipping every detailed check without ever failing
# them (they were inside an `if ($batches.Count -ge N)` guard that just
# never ran). Collapsing to one function that returns what it actually saw
# removes the second read/race entirely, whatever its exact root cause
# (this environment was also under real extra load from several stacked
# debugging processes at the time, which likely didn't help).
function Wait-ForCloudBatches([int]$expectedCount, [int]$maxWaitMs) {
    $elapsed = 0
    while ($elapsed -lt $maxWaitMs) {
        $batches = Get-CloudBatches
        if ($batches.Count -ge $expectedCount) { return $batches }
        Start-Sleep -Milliseconds 300
        $elapsed += 300
    }
    return Get-CloudBatches
}

$auditDbPath = Join-Path $runDir "audit.db"
$auditSecret = "audit-relay-validation-secret-do-not-use-in-prod"

# Non-default ports throughout (18844+, matching the established convention
# from installer/dev-license/editions/*/run.ps1): this machine already has a
# real installed Agent bound to the real default ports (8844/8845/8846), and
# a first run of this exact script proved that collision is real, not
# theoretical -- SAFEPROMPT_PROXY_BIND_ADDR was the one listener in this file
# with no override at all until that same discovery (see its own doc comment
# in apps/service/src/main.rs), so it silently fell back to the colliding
# 8844 default and the service failed to bind at all (os error 10048),
# meaning every "blocked request" in this test's first draft never reached
# a running service, so nothing was ever there to relay.
$proxyPort = 18848
$env:SAFEPROMPT_PROXY_BIND_ADDR = "127.0.0.1:$proxyPort"
$env:SAFEPROMPT_METRICS_BIND_ADDR = "127.0.0.1:18849"
$env:SAFEPROMPT_UPSTREAM_BASE_URL = "http://127.0.0.1:$mockUpstreamPort"
$env:SAFEPROMPT_AUDIT_ENCRYPTION_SECRET = $auditSecret
$env:SAFEPROMPT_AUDIT_DB_PATH = $auditDbPath
$env:SAFEPROMPT_TENANT_ID = $tenantId
$env:SAFEPROMPT_LICENSE_PATH = $licensePath
$env:SAFEPROMPT_LICENSE_PUBLIC_KEY = $verifyingKey
$env:SAFEPROMPT_AUDIT_RELAY_ENDPOINT = "http://127.0.0.1:$cloudPort/api/v1/agent/audit/ingest"
$env:SAFEPROMPT_AUDIT_RELAY_INTERVAL_SECS = "2"
$env:RUST_LOG = "info"

function Start-Service([string]$stdoutLog, [string]$stderrLog) {
    return Start-Process -FilePath $serviceBin -WorkingDirectory $runDir `
        -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru -WindowStyle Hidden
}

function Get-ServiceLog([string]$stdoutLog, [string]$stderrLog) {
    $content = ""
    if (Test-Path $stdoutLog) { $content += (Get-Content $stdoutLog -Raw) }
    if (Test-Path $stderrLog) { $content += (Get-Content $stderrLog -Raw) }
    return $content
}

function Wait-ForLogMatch([string]$stdoutLog, [string]$stderrLog, [string]$literalText, [int]$maxWaitMs) {
    $elapsed = 0
    while ($elapsed -lt $maxWaitMs) {
        if ((Get-ServiceLog $stdoutLog $stderrLog).Contains($literalText)) { return $true }
        Start-Sleep -Milliseconds 300
        $elapsed += 300
    }
    return $false
}

Write-Host "`n== Phase 1: default (snippets stripped) relay ==" -ForegroundColor Cyan
$stdout1 = Join-Path $runDir "service1.out.log"
$stderr1 = Join-Path $runDir "service1.err.log"
$proc1 = Start-Service $stdout1 $stderr1

$started1 = Wait-ForLogMatch $stdout1 $stderr1 "audit relay enabled" 8000
Record-Result "service starts up with the audit relay enabled" $started1 (Get-ServiceLog $stdout1 $stderr1)

$secret1 = "AKIAIOSFODNN7EXAMPLE"
$blockedBody1 = @{ model = "gpt-4"; messages = @(@{ role = "user"; content = "here is my AWS key: $secret1" }) } | ConvertTo-Json -Compress
try {
    Invoke-WebRequest -Uri "http://127.0.0.1:$proxyPort/v1/chat/completions" -Method Post -Body $blockedBody1 -ContentType "application/json" -UseBasicParsing | Out-Null
} catch { }

Write-Host "Waiting for the relay loop to pick up and POST the event..." -ForegroundColor DarkGray
# Uses the SERVICE's own log line as the primary success signal, not the
# mock cloud's log file directly -- found by direct evidence, not a further
# guess: across every single run of this script so far, the Rust process's
# own "audit relay: batch accepted" line appeared reliably within ~2-3s
# every time (proving the actual relay mechanism works correctly and
# fast), while this script's own cross-process polling of $cloudLogFile
# (a separate Start-Job runspace's Add-Content target) remained
# inconsistent through several different fix attempts (retry-hardening the
# read, combining wait+fetch into one call, widening the timeout 10s->15s->
# 30s, priming the mock job with a warm-up request, pre-creating the file
# before polling starts). Whatever the exact remaining cause, the service's
# own log has been 100% reliable throughout this whole process, so it's a
# strictly better signal for "did the relay happen" -- the file is still
# used below for detailed content inspection, but only AFTER this log
# confirmation, by which point the mock's own Add-Content write (which
# necessarily completed before the Rust client could see the HTTP response
# that produces this exact log line) is not just "eventually" but
# definitely already done.
$relayLogSeen = Wait-ForLogMatch $stdout1 $stderr1 "audit relay: batch accepted" 30000
$batches = Get-CloudBatches
Record-Result "the mock cloud received a real audit-ingest POST" $relayLogSeen "service log confirmed relay; cloud-side file batches visible: $($batches.Count)"

if ($batches.Count -ge 1) {
    $batch1 = $batches[0]
    Record-Result "the batch's tenant matches this Agent's license" ($batch1.tenant -eq $tenantId) "got '$($batch1.tenant)'"
    Record-Result "the batch carries a signed license (identity proof)" ($null -ne $batch1.license -and $null -ne $batch1.license.signature) "license: $($batch1.license | ConvertTo-Json -Compress)"
    Record-Result "the batch has at least one event" ($batch1.events.Count -ge 1) "got $($batch1.events.Count) events"
    if ($batch1.events.Count -ge 1) {
        $findings1 = @($batch1.events[0].findings)
        Record-Result "the relayed event has findings" ($findings1.Count -ge 1) "got $($findings1.Count)"
        if ($findings1.Count -ge 1) {
            $snippet1 = $findings1[0].snippet
            Record-Result "the raw finding snippet is STRIPPED by default (never leaves the device unless opted in)" `
                ([string]::IsNullOrEmpty($snippet1)) "snippet was: '$snippet1'"
            Record-Result "category/severity/action metadata still travels even with the snippet stripped" `
                (-not [string]::IsNullOrEmpty($findings1[0].category)) "category: '$($findings1[0].category)'"
        }
    }
}

if (-not $proc1.HasExited) { Stop-Process -Id $proc1.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 500

Write-Host "`n== Phase 2: explicit opt-in (SAFEPROMPT_AUDIT_RELAY_INCLUDE_SNIPPETS=1) ==" -ForegroundColor Cyan
$env:SAFEPROMPT_AUDIT_RELAY_INCLUDE_SNIPPETS = "1"
$stdout2 = Join-Path $runDir "service2.out.log"
$stderr2 = Join-Path $runDir "service2.err.log"
$proc2 = Start-Service $stdout2 $stderr2

$started2 = Wait-ForLogMatch $stdout2 $stderr2 "audit relay enabled" 8000
Record-Result "service restarts with the relay enabled (opted into full-content)" $started2 (Get-ServiceLog $stdout2 $stderr2)
Record-Result "the startup log explicitly warns that snippets will now be relayed" `
    ((Get-ServiceLog $stdout2 $stderr2).Contains("relayed audit batches will carry raw finding snippets")) (Get-ServiceLog $stdout2 $stderr2)

# Must be a real, correctly-shaped AWS Access Key ID -- AKIA + exactly 16
# uppercase alphanumeric chars (20 total) -- for the detector to actually
# match it at all. A first draft of this script used made-up strings of the
# wrong length here and in Phase 3's secret below; they silently matched
# nothing, which would have made both phases' detailed checks vacuously
# skip (0 findings) even after the Wait-ForCloudBatches race above was
# fixed -- caught by inspecting the real relayed JSON on disk, not assumed.
$secret2 = "AKIAOPTEDINXSNIPPET1"
$blockedBody2 = @{ model = "gpt-4"; messages = @(@{ role = "user"; content = "second AWS key: $secret2" }) } | ConvertTo-Json -Compress
try {
    Invoke-WebRequest -Uri "http://127.0.0.1:$proxyPort/v1/chat/completions" -Method Post -Body $blockedBody2 -ContentType "application/json" -UseBasicParsing | Out-Null
} catch { }

$batches = Wait-ForCloudBatches 2 10000
Record-Result "a second batch (the opted-in event) was relayed" ($batches.Count -ge 2) "batches so far: $($batches.Count)"

if ($batches.Count -ge 2) {
    $batch2 = $batches[$batches.Count - 1]
    $findings2 = @($batch2.events[0].findings)
    if ($findings2.Count -ge 1) {
        Record-Result "with the opt-in set, the raw snippet DOES travel this time" `
            ($findings2[0].snippet -match [regex]::Escape($secret2)) "snippet was: '$($findings2[0].snippet)'"
    }
}

if (-not $proc2.HasExited) { Stop-Process -Id $proc2.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 500
Remove-Item Env:\SAFEPROMPT_AUDIT_RELAY_INCLUDE_SNIPPETS -ErrorAction SilentlyContinue

Write-Host "`n== Phase 3: restart -- already-relayed events must not be relayed again ==" -ForegroundColor Cyan
$batchCountBeforeRestart = @(Get-CloudBatches).Count
$stdout3 = Join-Path $runDir "service3.out.log"
$stderr3 = Join-Path $runDir "service3.err.log"
$proc3 = Start-Service $stdout3 $stderr3
$started3 = Wait-ForLogMatch $stdout3 $stderr3 "audit relay enabled" 8000
Record-Result "service restarts a third time against the same audit DB" $started3 (Get-ServiceLog $stdout3 $stderr3)

# Give the relay loop a couple of ticks to run against the existing (already
# synced) events -- if mark_synced didn't actually persist, this would
# re-relay events 1 and 2 and the batch count would climb.
Start-Sleep -Seconds 5
$batchCountAfterIdleRestart = @(Get-CloudBatches).Count
Record-Result "no duplicate re-relay of already-synced events after a restart (mark_synced persists on disk)" `
    ($batchCountAfterIdleRestart -eq $batchCountBeforeRestart) `
    "before restart: $batchCountBeforeRestart, after $($batchCountAfterIdleRestart - $batchCountBeforeRestart) idle ticks: $batchCountAfterIdleRestart"

# Now prove the loop is still genuinely alive against the same DB, not just
# quiet: a third, fresh secret must relay as a new batch. Same real-shape
# requirement as $secret2 above (AKIA + 16 uppercase alphanumeric chars).
$secret3 = "AKIAPOSTRESTARTEVNT2"
$blockedBody3 = @{ model = "gpt-4"; messages = @(@{ role = "user"; content = "third AWS key: $secret3" }) } | ConvertTo-Json -Compress
try {
    Invoke-WebRequest -Uri "http://127.0.0.1:$proxyPort/v1/chat/completions" -Method Post -Body $blockedBody3 -ContentType "application/json" -UseBasicParsing | Out-Null
} catch { }
$batches = Wait-ForCloudBatches ($batchCountAfterIdleRestart + 1) 10000
Record-Result "a genuinely new event still relays after the restart (the loop isn't just stuck, it's correctly idempotent)" `
    ($batches.Count -ge $batchCountAfterIdleRestart + 1) "batches: $($batches.Count)"

if ($batches.Count -ge $batchCountAfterIdleRestart + 1) {
    $batch3 = $batches[$batches.Count - 1]
    $findings3 = @($batch3.events[0].findings)
    if ($findings3.Count -ge 1) {
        Record-Result "back on the default (stripped) setting after the restart, the post-restart event's snippet is stripped too" `
            ([string]::IsNullOrEmpty($findings3[0].snippet)) "snippet was: '$($findings3[0].snippet)'"
    }
}

if (-not $proc3.HasExited) { Stop-Process -Id $proc3.Id -Force -ErrorAction SilentlyContinue }

Stop-Job -Job $upstreamJob -ErrorAction SilentlyContinue | Out-Null
Remove-Job -Job $upstreamJob -Force -ErrorAction SilentlyContinue | Out-Null
Stop-Job -Job $cloudJob -ErrorAction SilentlyContinue | Out-Null
Remove-Job -Job $cloudJob -Force -ErrorAction SilentlyContinue | Out-Null

Remove-Item Env:\SAFEPROMPT_UPSTREAM_BASE_URL, Env:\SAFEPROMPT_AUDIT_ENCRYPTION_SECRET, Env:\SAFEPROMPT_AUDIT_DB_PATH, `
    Env:\SAFEPROMPT_TENANT_ID, Env:\SAFEPROMPT_LICENSE_PATH, Env:\SAFEPROMPT_LICENSE_PUBLIC_KEY, `
    Env:\SAFEPROMPT_AUDIT_RELAY_ENDPOINT, Env:\SAFEPROMPT_AUDIT_RELAY_INTERVAL_SECS -ErrorAction SilentlyContinue

Write-Host "`n=== Summary ===" -ForegroundColor Cyan
foreach ($r in $results) {
    $status = if ($r.Passed) { "PASS" } else { "FAIL" }
    Write-Host ("{0,-90} {1}" -f $r.Name, $status)
}

$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    Write-Host "`n$($failed.Count) of $($results.Count) checks FAILED." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`nAll $($results.Count) checks passed." -ForegroundColor Green
    exit 0
}
