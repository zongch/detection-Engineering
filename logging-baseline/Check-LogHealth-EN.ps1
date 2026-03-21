# Log Source Health Check (English)
$checkTime = Get-Date
$thresholdTime = $checkTime.AddMinutes(-60)

$healthChecks = @(
    @{ Name="Sysmon_Service";   Description="Sysmon Service Status";            Severity="Critical"; CheckType="Service";        Target="Sysmon64" },
    @{ Name="Sysmon_ProcCreate"; Description="Sysmon Process Creation Events";   Severity="Critical"; CheckType="EventLog";      LogName="Microsoft-Windows-Sysmon/Operational"; EventID=1; MinCount=5 },
    @{ Name="Sysmon_NetConn";   Description="Sysmon Network Connect Events";     Severity="High";      CheckType="EventLog";      LogName="Microsoft-Windows-Sysmon/Operational"; EventID=3; MinCount=1 },
    @{ Name="Sysmon_ProcAccess"; Description="Sysmon Process Access Events";     Severity="Critical"; CheckType="EventLog";      LogName="Microsoft-Windows-Sysmon/Operational"; EventID=10; MinCount=0 },
    @{ Name="WinSec_Logon";     Description="Windows Security Logon Events";     Severity="Critical"; CheckType="EventLog";      LogName="Security"; EventID=4624; MinCount=1 },
    @{ Name="WinSec_ProcCreate"; Description="Windows Security Process Creation"; Severity="High";      CheckType="EventLog";      LogName="Security"; EventID=4688; MinCount=1 },
    @{ Name="PS_ScriptBlock";   Description="PowerShell ScriptBlock Events";    Severity="Critical"; CheckType="EventLog";      LogName="Microsoft-Windows-PowerShell/Operational"; EventID=4104; MinCount=0 },
    @{ Name="PS_SB_Enabled";    Description="PS ScriptBlock Logging Enabled";    Severity="Critical"; CheckType="Registry";      RegPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"; RegName="EnableScriptBlockLogging"; Expected=1 },
    @{ Name="PS_Module_Enabled"; Description="PS Module Logging Enabled";         Severity="High";      CheckType="Registry";      RegPath="HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"; RegName="EnableModuleLogging"; Expected=1 },
    @{ Name="CmdLine_Enabled";  Description="Process CmdLine Audit Enabled";     Severity="Critical"; CheckType="Registry";      RegPath="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"; RegName="ProcessCreationIncludeCmdLine_Enabled"; Expected=1 },
    @{ Name="SecLog_Size";      Description="Security Event Log Size";            Severity="Medium";     CheckType="LogSize";       LogName="Security"; MinSizeMB=512 },
    @{ Name="PSLog_Size";       Description="PowerShell Operational Log Size";    Severity="Medium";     CheckType="LogSize";       LogName="Microsoft-Windows-PowerShell/Operational"; MinSizeMB=256 },
    @{ Name="SysLog_Size";      Description="Sysmon Operational Log Size";       Severity="High";      CheckType="LogSize";       LogName="Microsoft-Windows-Sysmon/Operational"; MinSizeMB=512 }
)

function Invoke-HealthCheck {
    param($Check, [string]$Computer = "LOCAL")
    
    $result = @{
        Computer = $Computer
        Name = $Check.Name
        Description = $Check.Description
        Severity = $Check.Severity
        Status = "Unknown"
        Detail = ""
        CheckTime = $checkTime.ToString("yyyy-MM-dd HH:mm:ss")
    }
    
    try {
        switch ($Check.CheckType) {
            "Service" {
                $svc = Get-Service -Name $Check.Target -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq "Running") {
                    $result.Status = "Healthy"
                    $result.Detail = "Service Running"
                } elseif ($svc) {
                    $result.Status = "Warning"
                    $result.Detail = "Service: $($svc.Status)"
                } else {
                    $result.Status = "Critical"
                    $result.Detail = "Service Not Installed"
                }
            }
            "EventLog" {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName = $Check.LogName
                    Id = $Check.EventID
                    StartTime = $thresholdTime
                } -ErrorAction SilentlyContinue -MaxEvents 100
                $count = if ($events) { $events.Count } else { 0 }
                if ($count -ge $Check.MinCount) {
                    $result.Status = "Healthy"
                    $result.Detail = "$count events in last 60min"
                } elseif ($Check.MinCount -eq 0) {
                    $result.Status = "Healthy"
                    $result.Detail = "Log OK (no activity)"
                } else {
                    $result.Status = "Warning"
                    $result.Detail = "Only $count events in last 60min (expected >=$($Check.MinCount))"
                }
            }
            "EventLogExists" {
                $log = Get-WinEvent -ListLog $Check.LogName -ErrorAction SilentlyContinue
                if ($log -and $log.IsEnabled) {
                    $result.Status = "Healthy"
                    $result.Detail = "Log Enabled, $($log.RecordCount) total events"
                } else {
                    $result.Status = "Critical"
                    $result.Detail = "Log Not Enabled or Not Exists"
                }
            }
            "Registry" {
                if (Test-Path $Check.RegPath) {
                    $val = Get-ItemProperty -Path $Check.RegPath -Name $Check.RegName -ErrorAction SilentlyContinue
                    if ($val -and $val.$($Check.RegName) -eq $Check.Expected) {
                        $result.Status = "Healthy"
                        $result.Detail = "Registry Value Correct: $($Check.Expected)"
                    } else {
                        $result.Status = "Critical"
                        $actualVal = if ($val) { $val.$($Check.RegName) } else { "Not Set" }
                        $result.Detail = "Value Mismatch: expected $($Check.Expected), got $actualVal"
                    }
                } else {
                    $result.Status = "Critical"
                    $result.Detail = "Registry Path Not Found"
                }
            }
            "LogSize" {
                $log = Get-WinEvent -ListLog $Check.LogName -ErrorAction SilentlyContinue
                if ($log) {
                    $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB)
                    if ($sizeMB -ge $Check.MinSizeMB) {
                        $result.Status = "Healthy"
                        $result.Detail = "Log Size: ${sizeMB}MB (min: $($Check.MinSizeMB)MB)"
                    } else {
                        $result.Status = "Warning"
                        $result.Detail = "Log Size Too Small: ${sizeMB}MB (min: $($Check.MinSizeMB)MB)"
                    }
                } else {
                    $result.Status = "Warning"
                    $result.Detail = "Cannot Read Log Config"
                }
            }
        }
    } catch {
        $result.Status = "Error"
        $result.Detail = "Check Failed: $_"
    }
    
    return [PSCustomObject]$result
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   LOG SOURCE HEALTH CHECK" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$allResults = [System.Collections.ArrayList]@()

foreach ($check in $healthChecks) {
    $result = Invoke-HealthCheck -Check $check -Computer (hostname)
    [void]$allResults.Add($result)
    
    $icon = switch ($result.Status) {
        "Healthy"  { "[OK]" }
        "Warning"  { "[WARN]" }
        "Critical" { "[CRIT]" }
        default    { "[?]" }
    }
    $color = switch ($result.Status) {
        "Healthy"  { "Green"  }
        "Warning"  { "Yellow" }
        "Critical" { "Red"    }
        default    { "Gray"   }
    }
    
    Write-Host "$icon [$($result.Severity.PadRight(8))] $($result.Description)" -ForegroundColor $color
    if ($result.Status -ne "Healthy") {
        Write-Host "     -> $($result.Detail)" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "          SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$criticalCount = ($allResults | Where-Object { $_.Status -in @("Critical","Error") }).Count
$warningCount  = ($allResults | Where-Object { $_.Status -eq "Warning" }).Count
$healthyCount  = ($allResults | Where-Object { $_.Status -eq "Healthy" }).Count
$totalCount    = $allResults.Count

Write-Host "  Total Checks: $totalCount"
Write-Host "  [OK] Healthy:   $healthyCount" -ForegroundColor Green
Write-Host "  [WARN] Warning:  $warningCount" -ForegroundColor Yellow
Write-Host "  [CRIT] Critical: $criticalCount" -ForegroundColor Red

$healthScore = [math]::Round(($healthyCount / $totalCount) * 100)
$scoreColor = if ($healthScore -ge 90) { "Green" } elseif ($healthScore -ge 70) { "Yellow" } else { "Red" }
Write-Host ""
Write-Host "  HEALTH SCORE: $healthScore / 100" -ForegroundColor $scoreColor

if ($criticalCount -gt 0) {
    Write-Host ""
    Write-Host "  CRITICAL ISSUES FOUND - FIX IMMEDIATELY:" -ForegroundColor Red
    $allResults | Where-Object { $_.Status -in @("Critical","Error") } | ForEach-Object {
        Write-Host "    -> [$($_.Name)] $($_.Description): $($_.Detail)" -ForegroundColor Red
    }
}

Write-Host ""
if ($criticalCount -eq 0) {
    Write-Host "  [SUCCESS] No critical issues found!" -ForegroundColor Green
    Write-Host "  Your logging baseline is properly deployed." -ForegroundColor Green
} else {
    Write-Host "  [ACTION REQUIRED] Fix the critical issues above." -ForegroundColor Yellow
}

if ($criticalCount -gt 0) { exit 1 } else { exit 0 }
