<#
.SYNOPSIS
    End-to-end validation of the SafePrompt Agent's Configuration Manager.

.DESCRIPTION
    Proves the hot-reloadable configuration layer works against the real
    service binary, not just in unit tests: starts the service pointed at
    a local JSON config file (SAFEPROMPT_CONFIG_SOURCE) containing an MCP
    tool policy that allows a given tool, confirms a call to that tool is
    allowed, then rewrites the config file to deny that same tool and
    confirms the running service picks up the change and blocks the next
    call — all without restarting.

.EXAMPLE
    powershell -File agent\scripts\test-config-hot-reload.ps1
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
$agentEnterpriseDir = Join-Path (Split-Path -Parent $agentDir) "agent-enterprise"
$workDir = Join-Path $env:TEMP "safeprompt-config-hot-reload-validation"

if (Test-Path $workDir) { Remove-Item -Recurse -Force $workDir }
New-Item -ItemType Directory -Path $workDir | Out-Null

$results = New-Object System.Collections.ArrayList
$spawnedProcs = New-Object System.Collections.ArrayList

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

try {
    # The MCP route is license-gated (see safeprompt-licensing::features) —
    # needs the "mcp" feature to accept any /mcp traffic at all, otherwise
    # this test would just be exercising the "not licensed" refusal path.
    $keysDir = Join-Path $runDir "keys"
    New-Item -ItemType Directory -Path $keysDir | Out-Null
    & $licenseTool keygen --out-dir $keysDir | Out-Null
    $signingKey = Join-Path $keysDir "signing_key.hex"
    $licensePath = Join-Path $runDir "license.json"
    & $licenseTool issue --signing-key $signingKey --tenant "Acme Corp" --edition enterprise `
        --devices 25 --days 365 --features "mcp" --out $licensePath | Out-Null

    # Mock MCP tool server the proxy forwards allowed calls to.
    $mcpUpstreamPort = 18847
    $mcpScript = Join-Path $scriptDir "_mock_mcp_upstream.ps1"
    $mcpProc = Start-Process -FilePath "powershell.exe" `
        -ArgumentList @("-NoProfile", "-NonInteractive", "-File", "`"$mcpScript`"", "-Port", $mcpUpstreamPort) `
        -PassThru -WindowStyle Hidden
    $spawnedProcs.Add($mcpProc) | Out-Null

    $configPath = Join-Path $runDir "config.json"
    # Initial config: notes.append is NOT denied.
    @{ mcp_tool_policy = @{ denied_tools = @(); allowed_tools = @(); max_calls_per_window = 20; window_seconds = 60 }; audit_retention_days = 90 } |
        ConvertTo-Json | Set-Content -Path $configPath -Encoding ascii

    $env:SAFEPROMPT_CONFIG_SOURCE = $configPath
    $env:SAFEPROMPT_CONFIG_POLL_INTERVAL_SECS = "1"
    $env:SAFEPROMPT_MCP_UPSTREAM_BASE_URL = "http://127.0.0.1:$mcpUpstreamPort/mcp"
    $env:SAFEPROMPT_LICENSE_PATH = $licensePath
    $env:SAFEPROMPT_LICENSE_PUBLIC_KEY = Join-Path $keysDir "verifying_key.hex"
    $env:RUST_LOG = "info"

    $stdoutLog = Join-Path $runDir "service.out.log"
    $stderrLog = Join-Path $runDir "service.err.log"
    $proc = Start-Process -FilePath $serviceBin -WorkingDirectory $runDir `
        -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru -WindowStyle Hidden
    $spawnedProcs.Add($proc) | Out-Null

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
    $startedUp = Wait-ForLogMatch "configuration hot-reload enabled" 8000
    Record-Result "service starts up with configuration hot-reload enabled from the local file" $startedUp (Get-ServiceLog)

    Write-Host "`n== Calling notes.append under the initial policy (must be allowed) ==" -ForegroundColor Cyan
    $mcpCall = @{ jsonrpc = "2.0"; id = 1; method = "tools/call"; params = @{ name = "notes.append"; arguments = @{ text = "hello" } } } | ConvertTo-Json -Compress
    $resp1 = Invoke-RestMethod -Uri "http://127.0.0.1:8844/mcp" -Method Post -Body $mcpCall -ContentType "application/json"
    Record-Result "notes.append is allowed under the initial (empty denylist) policy" ($null -ne $resp1.result) ($resp1 | ConvertTo-Json -Compress)

    Write-Host "`n== Rewriting the config to deny notes.* ==" -ForegroundColor Cyan
    @{ mcp_tool_policy = @{ denied_tools = @("notes.*"); allowed_tools = @(); max_calls_per_window = 20; window_seconds = 60 }; audit_retention_days = 30 } |
        ConvertTo-Json | Set-Content -Path $configPath -Encoding ascii

    $appliedHotReload = Wait-ForLogMatch "configuration hot-reload applied a new MCP tool policy" 6000
    Record-Result "running service picks up the new MCP tool policy without restarting" $appliedHotReload (Get-ServiceLog)

    Write-Host "`n== Calling notes.append again (must now be blocked) ==" -ForegroundColor Cyan
    $resp2 = Invoke-RestMethod -Uri "http://127.0.0.1:8844/mcp" -Method Post -Body $mcpCall -ContentType "application/json"
    Record-Result "notes.append is blocked after the hot-reloaded denylist takes effect" `
        ($null -ne $resp2.error -and $resp2.error.message -match "blocked") ($resp2 | ConvertTo-Json -Compress)

    Record-Result "log confirms the new audit retention period (30 days) was also hot-applied" `
        ((Get-ServiceLog) -match "audit retention period") (Get-ServiceLog)

    Record-Result "service is still running after the hot reload (didn't crash)" (-not $proc.HasExited) (Get-ServiceLog)
} finally {
    foreach ($p in $spawnedProcs) {
        try {
            if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
        } catch {}
    }
    Remove-Item Env:\SAFEPROMPT_CONFIG_SOURCE, Env:\SAFEPROMPT_CONFIG_POLL_INTERVAL_SECS, Env:\SAFEPROMPT_MCP_UPSTREAM_BASE_URL, `
        Env:\SAFEPROMPT_LICENSE_PATH, Env:\SAFEPROMPT_LICENSE_PUBLIC_KEY -ErrorAction SilentlyContinue
}

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
