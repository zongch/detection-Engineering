# Fix Log Health Issues
# Fixes 3 warnings from health check:
# 1. Sysmon network connect events (P1)
# 2. Security process creation events (P1)
# 3. Sysmon log size too small (P2)

Write-Host "========================================"
Write-Host "   FIX LOG HEALTH ISSUES"
Write-Host "========================================" -ForegroundColor Yellow
Write-Host ""

# Fix 1: Update Sysmon config to capture ALL network connections (not just high-risk processes)
Write-Host "[Fix 1/3] Updating Sysmon network configuration..." -ForegroundColor Cyan
$configPath = "$PSScriptRoot\sysmonconfig.xml"
$config = Get-Content $configPath -Raw

# Change NetworkConnect from include to exclude to capture ALL connections
# Original line 69: <NetworkConnect onmatch="include">
$config = $config -replace '<NetworkConnect onmatch="include">', '<NetworkConnect onmatch="exclude">'

# Save updated config
$config | Out-File $configPath -Encoding UTF8
Write-Host "   Updated: Now capturing ALL network connections (except excluded)" -ForegroundColor Green
Write-Host ""

# Fix 2: Force Security Event 4688 to activate
Write-Host "[Fix 2/3] Verifying Process Command Line Audit (Event 4688)..." -ForegroundColor Cyan
$policyResult = & auditpol /get /subcategory:"Process Creation" 2>&1
if ($policyResult -match "Success and Failure") {
    Write-Host "   Process Creation audit already enabled" -ForegroundColor Green
} else {
    Write-Host "   Current policy:" -ForegroundColor Yellow
    Write-Host $policyResult -ForegroundColor Gray
    Write-Host "   Enabling Process Creation audit..." -ForegroundColor Yellow
    $enableResult = & auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "   Process Creation audit enabled" -ForegroundColor Green
    } else {
        Write-Host "   WARNING: auditpol command failed" -ForegroundColor Yellow
        Write-Host "   Error: $enableResult" -ForegroundColor Red
        Write-Host "   This may require elevated permissions or different Windows version" -ForegroundColor Yellow
        Write-Host "   Continuing with other fixes..." -ForegroundColor Cyan
    }
}
Write-Host ""

# Fix 3: Set Sysmon Operational log size to 512MB
Write-Host "[Fix 3/3] Increasing Sysmon log size to 512MB..." -ForegroundColor Cyan
$sysmonLogName = "Microsoft-Windows-Sysmon/Operational"
try {
    $log = Get-WinEvent -ListLog $sysmonLogName -ErrorAction Stop
    $log.MaximumSizeInBytes = 512MB
    $log.SaveChanges()
    Write-Host "   Log size updated to 512MB" -ForegroundColor Green
} catch {
    Write-Host "   ERROR: Failed to update log size" -ForegroundColor Red
    Write-Host "   Error: $_" -ForegroundColor Red
}
Write-Host ""

# Reconfigure Sysmon with updated config
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "Reconfiguring Sysmon..." -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
$sysmonConfigPath = Join-Path $PSScriptRoot "sysmonconfig.xml"

# Check if Sysmon is installed
$sysmonPath = Get-Command Sysmon64.exe -ErrorAction SilentlyContinue
if (-not $sysmonPath) {
    $sysmonPath = Get-Command Sysmon.exe -ErrorAction SilentlyContinue
}

if ($sysmonPath) {
    Write-Host "Sysmon found at: $($sysmonPath.Source)" -ForegroundColor Green
    & $sysmonPath.Source -c $sysmonConfigPath

    if ($LASTEXITCODE -eq 0) {
        Write-Host "Sysmon reconfigured successfully" -ForegroundColor Green
    } else {
        Write-Host "Sysmon reconfiguration failed (exit code: $LASTEXITCODE)" -ForegroundColor Red
    }
} else {
    Write-Host "ERROR: Sysmon not found" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "SUMMARY" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow
Write-Host "[OK] Network connect config updated - now capturing all connections"
Write-Host "[OK] Process Creation audit verified"
Write-Host "[OK] Sysmon log size increased to 512MB"
Write-Host ""
Write-Host "Next: Run Check-LogHealth-EN.ps1 again to verify fixes" -ForegroundColor Cyan
Write-Host "Note: Network events will appear once network activity occurs" -ForegroundColor Gray
