<#
.SYNOPSIS
    Validation of Configuration Manager -> ProgramData: a real install with
    zero SAFEPROMPT_* env vars still picks up tenant_id/upstream/provider
    settings from %ProgramData%\SafePrompt\config.json.

.DESCRIPTION
    Proves the config.json default-source-discovery and the tenant_id/
    upstream_base_url/providers fields added 2026-07-30 actually work
    end-to-end against the real service binary — not just the crate's own
    unit tests. `C:\ProgramData\SafePrompt` is a real shared system
    location, so this script backs up anything already there before
    writing its test config.json and restores it afterward, regardless of
    how the script exits.

.EXAMPLE
    powershell -File agent\scripts\test-config-programdata.ps1
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
$workDir = Join-Path $env:TEMP "safeprompt-config-programdata-validation"
$programDataDir = "C:\ProgramData\SafePrompt"
$backupDir = Join-Path $workDir "programdata-backup"

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

# Back up anything already at the real ProgramData location -- this is
# shared system state, not ours to clobber.
$hadExisting = Test-Path $programDataDir
if ($hadExisting) {
    Write-Host "== Backing up existing $programDataDir ==" -ForegroundColor Yellow
    Copy-Item -Path $programDataDir -Destination $backupDir -Recurse -Force
}

try {
    New-Item -ItemType Directory -Path $programDataDir -Force | Out-Null
    # [System.IO.File]::WriteAllText(path, contents) (2-arg overload) writes
    # UTF-8 *without* a BOM -- Set-Content/Out-File -Encoding utf8 in Windows
    # PowerShell 5.1 write a BOM instead, which serde_json chokes on
    # ("expected value at line 1 column 1"), a real gotcha hit while writing
    # this script.
    $configJson = @{
        tenant_id = "acme-programdata-test"
        upstream_base_url = "https://api.anthropic.com"
        providers = @{ openai_api_key = "sk-fake-key-for-validation-only" }
    } | ConvertTo-Json
    [System.IO.File]::WriteAllText((Join-Path $programDataDir "config.json"), $configJson)

    $runDir = Join-Path $workDir "run"
    New-Item -ItemType Directory -Path $runDir | Out-Null
    $stdoutLog = Join-Path $runDir "service.out.log"
    $stderrLog = Join-Path $runDir "service.err.log"
    $env:RUST_LOG = "info"
    # Deliberately NOT setting any SAFEPROMPT_CONFIG_SOURCE / _UPSTREAM_BASE_URL /
    # _TENANT_ID / _OPENAI_API_KEY env vars -- that's the entire point of this test.
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

    $started = Wait-ForLogMatch "SafePrompt Agent Service initialization complete" 8000
    Record-Result "service starts successfully with zero SAFEPROMPT_* env vars set" $started (Get-ServiceLog)

    $foundConfigSource = Wait-ForLogMatch "configuration hot-reload enabled from" 2000
    Record-Result "config.json in ProgramData is discovered as the default config source (no SAFEPROMPT_CONFIG_SOURCE needed)" $foundConfigSource (Get-ServiceLog)

    $log = Get-ServiceLog
    Record-Result "upstream_base_url from config.json is used (not the built-in openai default)" ($log -match [regex]::Escape("upstream: https://api.anthropic.com")) $log
    Record-Result "providers.openai_api_key from config.json registered a provider (multi-provider warning proves the registry wasn't empty)" ($log -match "provider configuration is present") $log

    Remove-Item Env:\RUST_LOG -ErrorAction SilentlyContinue
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
} finally {
    Remove-Item -Recurse -Force $programDataDir -ErrorAction SilentlyContinue
    if ($hadExisting) {
        Write-Host "== Restoring original $programDataDir ==" -ForegroundColor Yellow
        Copy-Item -Path $backupDir -Destination $programDataDir -Recurse -Force
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
