<#
.SYNOPSIS
    Validation of real Windows Service Control Manager integration for
    safeprompt-watchdog.exe (install/uninstall/run-as-a-real-service).

.DESCRIPTION
    Registering, starting, and stopping an actual Windows Service requires
    administrator privileges — a real, unavoidable OS requirement, not a
    limitation of this script. Run from a non-elevated session, this script
    still proves something real: that `watchdog.exe install` reaches the
    genuine Service Control Manager API and is rejected for the correct
    reason (access denied), rather than silently doing nothing or crashing.
    Run elevated, it does the full lifecycle: install, start (confirms the
    supervised Agent service actually comes up under SCM launch, not just a
    console), stop, uninstall — and cleans up the real service it registered
    either way.

.EXAMPLE
    powershell -File agent\scripts\test-windows-service.ps1
    # From an elevated (Run as Administrator) PowerShell for full coverage:
    powershell -File agent\scripts\test-windows-service.ps1
#>

$ErrorActionPreference = "Stop"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentDir = Split-Path -Parent $scriptDir
$workDir = Join-Path $env:TEMP "safeprompt-windows-service-validation"

if (Test-Path $workDir) { Remove-Item -Recurse -Force $workDir }
New-Item -ItemType Directory -Path $workDir | Out-Null

$results = New-Object System.Collections.ArrayList
$serviceName = "SafePromptWatchdog"

function Record-Result([string]$name, [bool]$passed, [string]$detail) {
    $results.Add([PSCustomObject]@{ Name = $name; Passed = $passed; Detail = $detail }) | Out-Null
    if ($passed) {
        Write-Host "[PASS] $name" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] $name" -ForegroundColor Red
        Write-Host "       $detail" -ForegroundColor DarkGray
    }
}

Write-Host "== Building the Agent service and watchdog ==" -ForegroundColor Cyan
Push-Location $agentDir
try {
    cargo build -p safeprompt-service -p safeprompt-watchdog
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE" }
} finally {
    Pop-Location
}

$watchdogBin = Join-Path $agentDir "target\debug\safeprompt-watchdog.exe"
$runDir = Join-Path $workDir "run"
New-Item -ItemType Directory -Path $runDir | Out-Null

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# A plain `& exe args 2>&1` merges the native command's stderr into
# PowerShell's object pipeline as ErrorRecords in Windows PowerShell 5.1,
# which then aborts the whole script under $ErrorActionPreference = "Stop"
# even when the exe's exit code is exactly what we expect and are testing
# for. Start-Process with file-redirected output sidesteps that entirely.
function Invoke-WatchdogCommand([string]$commandArg) {
    $outFile = Join-Path $runDir "watchdog-$commandArg-out.log"
    $errFile = Join-Path $runDir "watchdog-$commandArg-err.log"
    $proc = Start-Process -FilePath $watchdogBin -ArgumentList @($commandArg) `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile -PassThru -Wait -WindowStyle Hidden
    $combined = ""
    if (Test-Path $outFile) { $combined += Get-Content $outFile -Raw -ErrorAction SilentlyContinue }
    if (Test-Path $errFile) { $combined += Get-Content $errFile -Raw -ErrorAction SilentlyContinue }
    return [PSCustomObject]@{ ExitCode = $proc.ExitCode; Output = $combined }
}

function Get-ScQueryOutput([string]$name) {
    $outFile = Join-Path $runDir "sc-query-out.log"
    $errFile = Join-Path $runDir "sc-query-err.log"
    $proc = Start-Process -FilePath "sc.exe" -ArgumentList @("query", $name) `
        -RedirectStandardOutput $outFile -RedirectStandardError $errFile -PassThru -Wait -WindowStyle Hidden
    $text = ""
    if (Test-Path $outFile) { $text += Get-Content $outFile -Raw -ErrorAction SilentlyContinue }
    if (Test-Path $errFile) { $text += Get-Content $errFile -Raw -ErrorAction SilentlyContinue }
    return [PSCustomObject]@{ ExitCode = $proc.ExitCode; Output = $text }
}

# Always clean up any leftover registration from a previous run of this
# script, elevated or not, before testing.
if ((Get-ScQueryOutput $serviceName).ExitCode -eq 0) {
    Start-Process -FilePath "sc.exe" -ArgumentList @("stop", $serviceName) -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Milliseconds 500
    Start-Process -FilePath "sc.exe" -ArgumentList @("delete", $serviceName) -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
    Start-Sleep -Milliseconds 500
}

if (-not $isAdmin) {
    Write-Host "`n== Not running elevated: verifying the real-SCM-call path only ==" -ForegroundColor Yellow
    Write-Host "    (Re-run this script from an elevated PowerShell session for the full install/start/stop/uninstall lifecycle.)" -ForegroundColor Yellow

    $installResult = Invoke-WatchdogCommand "install"
    Record-Result "non-elevated 'install' reaches the real SCM API and is rejected (not a silent no-op)" `
        (($installResult.ExitCode -ne 0) -and ($installResult.Output -match "(?i)access is denied")) $installResult.Output

    $svcAfter = Get-ScQueryOutput $serviceName
    Record-Result "no service was actually registered by the rejected install attempt" ($svcAfter.ExitCode -ne 0) $svcAfter.Output

    Write-Host "`n=== Summary (PARTIAL -- re-run elevated for full coverage) ===" -ForegroundColor Cyan
} else {
    Write-Host "`n== Running elevated: full install/start/stop/uninstall lifecycle ==" -ForegroundColor Cyan
    try {
        $installResult = Invoke-WatchdogCommand "install"
        Record-Result "'install' registers the service successfully" ($installResult.ExitCode -eq 0) $installResult.Output

        $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        Record-Result "the registered service is visible via Get-Service" ($null -ne $svc) "Get-Service returned nothing for '$serviceName'"
        if ($svc) {
            Record-Result "the registered service has StartType Automatic" ($svc.StartType -eq "Automatic") "StartType was $($svc.StartType)"
        }

        Start-Service -Name $serviceName
        Start-Sleep -Seconds 2
        $running = (Get-Service -Name $serviceName).Status -eq "Running"
        Record-Result "the service starts and reports Running" $running "status: $((Get-Service -Name $serviceName).Status)"

        # The watchdog resolves its supervised service path from its own
        # exe's directory (env::current_exe(), not CWD) — so it should find
        # and launch safeprompt-service.exe next to it even though the SCM
        # runs the watchdog with System32 as its working directory. Port
        # 8844 opening proves the *supervised child* really came up under a
        # real SCM-launched parent, not just a console-launched one (already
        # covered by test-tamper-protection.ps1).
        $portOpen = $false
        for ($i = 0; $i -lt 15; $i++) {
            try {
                $conn = Test-NetConnection -ComputerName 127.0.0.1 -Port 8844 -WarningAction SilentlyContinue
                if ($conn.TcpTestSucceeded) { $portOpen = $true; break }
            } catch {}
            Start-Sleep -Milliseconds 500
        }
        Record-Result "the supervised Agent service (port 8844) comes up under an SCM-launched watchdog" $portOpen "port 8844 never opened"

        Stop-Service -Name $serviceName -Force
        Start-Sleep -Seconds 1
        $stopped = (Get-Service -Name $serviceName).Status -eq "Stopped"
        Record-Result "the service stops cleanly" $stopped "status: $((Get-Service -Name $serviceName).Status)"
    } finally {
        Start-Process -FilePath "sc.exe" -ArgumentList @("stop", $serviceName) -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue | Out-Null
        Start-Sleep -Milliseconds 500
        $uninstallResult = Invoke-WatchdogCommand "uninstall"
        Record-Result "'uninstall' removes the service" (-not (Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) $uninstallResult.Output
    }

    Write-Host "`n=== Summary ===" -ForegroundColor Cyan
}

foreach ($r in $results) {
    $status = if ($r.Passed) { "PASS" } else { "FAIL" }
    Write-Host ("{0,-90} {1}" -f $r.Name, $status)
}

$failed = @($results | Where-Object { -not $_.Passed })
if ($failed.Count -gt 0) {
    Write-Host "`n$($failed.Count) of $($results.Count) checks FAILED." -ForegroundColor Red
    exit 1
} else {
    if (-not $isAdmin) {
        Write-Host "`nAll $($results.Count) checks passed (partial coverage -- not elevated). Re-run elevated for the full lifecycle." -ForegroundColor Yellow
    } else {
        Write-Host "`nAll $($results.Count) checks passed." -ForegroundColor Green
    }
    exit 0
}
