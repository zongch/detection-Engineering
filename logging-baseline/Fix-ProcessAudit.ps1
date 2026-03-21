# Alternative method to enable Process Creation audit
# Uses PowerShell instead of auditpol command

Write-Host "Enabling Process Creation audit via PowerShell..." -ForegroundColor Cyan

# Try method 1: Set-AuditPolicy (Windows 10/11 with Security Auditing module)
try {
    Import-Module SecurityPolicy 2>$null
    $result = Set-AuditPolicy -Subcategory "Process Creation" -Success Enable -Failure Enable -ErrorAction Stop
    Write-Host "Process Creation audit enabled via SecurityPolicy module" -ForegroundColor Green
} catch {
    Write-Host "SecurityPolicy module not available, trying alternative..." -ForegroundColor Yellow
    
    # Try method 2: Direct registry modification (Process Command Line Logging)
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        # Enable command line process creation tracking
        Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
        Write-Host "Process command line logging enabled via registry" -ForegroundColor Green
        Write-Host "This enables Event ID 4688 with command line information" -ForegroundColor Cyan
    } catch {
        Write-Host "Registry method failed: $_" -ForegroundColor Yellow
        
        # Try method 3: Suggested manual action
        Write-Host ""
        Write-Host "================================================" -ForegroundColor Yellow
        Write-Host "MANUAL CONFIGURATION REQUIRED" -ForegroundColor Yellow
        Write-Host "================================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Please run the following steps manually:" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. Open Local Security Policy:" -ForegroundColor White
        Write-Host "   Press Win+R, type: secpol.msc" -ForegroundColor Gray
        Write-Host ""
        Write-Host "2. Navigate to:" -ForegroundColor White
        Write-Host "   Security Settings -> Advanced Audit Policy Configuration" -ForegroundColor Gray
        Write-Host "   -> Object Access -> Audit process creation" -ForegroundColor Gray
        Write-Host ""
        Write-Host "3. Configure:" -ForegroundColor White
        Write-Host "   Check both Success and Failure boxes" -ForegroundColor Gray
        Write-Host ""
        Write-Host "4. Apply and OK" -ForegroundColor White
        Write-Host ""
        Write-Host "5. Run: gpupdate /force" -ForegroundColor Gray
        Write-Host ""
    }
}

Write-Host ""
Write-Host "Checking current status..." -ForegroundColor Cyan

# Check if Event 4688 command line logging is enabled
$cmdLineEnabled = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled

if ($cmdLineEnabled -eq 1) {
    Write-Host "[OK] Command line process tracking is enabled" -ForegroundColor Green
    Write-Host "    This will capture Event ID 4688 with full command line" -ForegroundColor Cyan
} else {
    Write-Host "[WARN] Command line process tracking may not be enabled" -ForegroundColor Yellow
    Write-Host "    Event 4688 may still work but without detailed command line info" -ForegroundColor Cyan
}

# Try to check recent 4688 events
Write-Host ""
Write-Host "Checking for recent Event 4688 events..." -ForegroundColor Cyan
try {
    $events = Get-WinEvent -LogName Security -FilterXPath "*[System[(EventID=4688)]]" -MaxEvents 1 -ErrorAction Stop
    $time = $events.TimeCreated
    $minutesAgo = ((Get-Date) - $time).TotalMinutes
    Write-Host "[OK] Found Event 4688 from $([math]::Round($minutesAgo)) minutes ago" -ForegroundColor Green
} catch {
    Write-Host "[INFO] No Event 4688 found in Security log (may be normal if system is idle)" -ForegroundColor Gray
}
