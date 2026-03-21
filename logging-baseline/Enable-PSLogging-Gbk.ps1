# PowerShell Logging Deployment (GBK Compatible)
$ErrorActionPreference = "Stop"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SUCCESS" { "Green" }
        "WARN"    { "Yellow" }
        "ERROR"   { "Red" }
    }
    Write-Host "[$timestamp][$Level] $Message" -ForegroundColor $color
}

$PSEngineKey     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$ScriptBlockKey  = "$PSEngineKey\ScriptBlockLogging"
$ModuleLogKey    = "$PSEngineKey\ModuleLogging"
$TranscriptKey   = "$PSEngineKey\Transcription"

Write-Log "========================================"
Write-Log "  PowerShell Audit Logging Deployment"
Write-Log "========================================"

Write-Log "Configuring ScriptBlock Logging (EventID 4104)..."
if (-not (Test-Path $ScriptBlockKey)) {
    New-Item -Path $ScriptBlockKey -Force | Out-Null
}
Set-ItemProperty -Path $ScriptBlockKey -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
Set-ItemProperty -Path $ScriptBlockKey -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord
Write-Log "ScriptBlock Logging: ENABLED" "SUCCESS"

Write-Log "Configuring Module Logging (EventID 4103)..."
if (-not (Test-Path $ModuleLogKey)) {
    New-Item -Path $ModuleLogKey -Force | Out-Null
}
Set-ItemProperty -Path $ModuleLogKey -Name "EnableModuleLogging" -Value 1 -Type DWord
$ModuleNamesKey = "$ModuleLogKey\ModuleNames"
if (-not (Test-Path $ModuleNamesKey)) {
    New-Item -Path $ModuleNamesKey -Force | Out-Null
}
Set-ItemProperty -Path $ModuleNamesKey -Name "*" -Value "*" -Type String
Write-Log "Module Logging: ENABLED (all modules)" "SUCCESS"

Write-Log "Configuring Transcription..."
$TranscriptPath = "C:\Windows\Temp\PSTranscripts"
if (-not (Test-Path $TranscriptPath)) {
    New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null
}
if (-not (Test-Path $TranscriptKey)) {
    New-Item -Path $TranscriptKey -Force | Out-Null
}
Set-ItemProperty -Path $TranscriptKey -Name "EnableTranscripting"     -Value 1 -Type DWord
Set-ItemProperty -Path $TranscriptKey -Name "EnableInvocationHeader"  -Value 1 -Type DWord
Set-ItemProperty -Path $TranscriptKey -Name "OutputDirectory"         -Value $TranscriptPath -Type String
Write-Log "Transcription: ENABLED to $TranscriptPath" "SUCCESS"

Write-Log "Configuring PowerShell Event Log Sizes..."
$LogConfigs = @(
    @{ Name = "Windows PowerShell";                              MaxSize = 524288000 },
    @{ Name = "Microsoft-Windows-PowerShell/Operational";        MaxSize = 524288000 },
    @{ Name = "Microsoft-Windows-PowerShell/Admin";              MaxSize = 104857600 }
)
foreach ($log in $LogConfigs) {
    try {
        $logObj = Get-WinEvent -ListLog $log.Name -ErrorAction SilentlyContinue
        if ($logObj) {
            $logObj.MaximumSizeInBytes = $log.MaxSize
            $logObj.IsEnabled = $true
            $logObj.SaveChanges()
            Write-Log "  $($log.Name): Set to $([math]::Round($log.MaxSize/1MB))MB" "SUCCESS"
        }
    } catch {
        Write-Log "  Failed to configure $($log.Name): $_" "WARN"
    }
}

Write-Log "Configuring Windows Advanced Audit Policies..."
$AuditPolicies = @(
    @{ Category = "Detailed Tracking"; SubCategory = "Process Creation";         Success = "enable"; Failure = "enable" },
    @{ Category = "Detailed Tracking"; SubCategory = "Process Termination";      Success = "enable"; Failure = "disable" },
    @{ Category = "Logon/Logoff";      SubCategory = "Logon";                    Success = "enable"; Failure = "enable" },
    @{ Category = "Logon/Logoff";      SubCategory = "Logoff";                   Success = "enable"; Failure = "disable" },
    @{ Category = "Logon/Logoff";      SubCategory = "Special Logon";            Success = "enable"; Failure = "disable" },
    @{ Category = "Account Management"; SubCategory = "User Account Management"; Success = "enable"; Failure = "enable" },
    @{ Category = "Account Management"; SubCategory = "Security Group Management"; Success = "enable"; Failure = "enable" },
    @{ Category = "Object Access";     SubCategory = "Registry";                 Success = "enable"; Failure = "enable" },
    @{ Category = "Policy Change";     SubCategory = "Audit Policy Change";      Success = "enable"; Failure = "enable" },
    @{ Category = "Policy Change";     SubCategory = "Authentication Policy Change"; Success = "enable"; Failure = "enable" },
    @{ Category = "Privilege Use";     SubCategory = "Sensitive Privilege Use";  Success = "enable"; Failure = "enable" },
    @{ Category = "System";            SubCategory = "Security System Extension"; Success = "enable"; Failure = "enable" },
    @{ Category = "System";            SubCategory = "System Integrity";         Success = "enable"; Failure = "enable" }
)
foreach ($policy in $AuditPolicies) {
    try {
        $cmd = "auditpol /set /subcategory:`"$($policy.SubCategory)`" /success:$($policy.Success) /failure:$($policy.Failure)"
        Invoke-Expression $cmd 2>&1 | Out-Null
        Write-Log "  Enabled audit: $($policy.SubCategory)" "SUCCESS"
    } catch {
        Write-Log "  Failed to set audit policy $($policy.SubCategory): $_" "WARN"
    }
}

Write-Log "Enabling Process Command Line Audit..."
$AuditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $AuditKey)) {
    New-Item -Path $AuditKey -Force | Out-Null
}
Set-ItemProperty -Path $AuditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
Write-Log "Process Command Line Audit: ENABLED (Event 4688)" "SUCCESS"

Write-Log "Configuring Security Event Log Size..."
try {
    $secLog = Get-WinEvent -ListLog "Security" -ErrorAction Stop
    $secLog.MaximumSizeInBytes = 1073741824  # 1GB
    $secLog.SaveChanges()
    Write-Log "Security Event Log: Set to 1GB" "SUCCESS"
} catch {
    Write-Log "Failed to configure Security log size: $_" "WARN"
}

Write-Log ""
Write-Log "========================================"
Write-Log "           Verification Results"
Write-Log "========================================"

$verificationItems = @(
    @{ Name = "ScriptBlock Log";   Path = $ScriptBlockKey; Value = "EnableScriptBlockLogging"; Expected = 1 },
    @{ Name = "Module Log";        Path = $ModuleLogKey;   Value = "EnableModuleLogging";      Expected = 1 },
    @{ Name = "Transcription";     Path = $TranscriptKey;  Value = "EnableTranscripting";      Expected = 1 },
    @{ Name = "CmdLine Audit";     Path = $AuditKey;       Value = "ProcessCreationIncludeCmdLine_Enabled"; Expected = 1 }
)

$allPassed = $true
foreach ($item in $verificationItems) {
    try {
        $val = Get-ItemPropertyValue -Path $item.Path -Name $item.Value -ErrorAction Stop
        if ($val -eq $item.Expected) {
            Write-Log "  $($item.Name): ENABLED" "SUCCESS"
        } else {
            Write-Log "  $($item.Name): FAILED (expected $($item.Expected), got $val)" "ERROR"
            $allPassed = $false
        }
    } catch {
        Write-Log "  $($item.Name): NOT FOUND" "ERROR"
        $allPassed = $false
    }
}

if ($allPassed) {
    Write-Log ""
    Write-Log "ALL PowerShell audit policies configured successfully!" "SUCCESS"
    Write-Log ""
    Write-Log "Next Steps:"
    Write-Log "  1. Confirm SIEM is collecting Event ID 4103, 4104"
    Write-Log "  2. Run Check-LogHealth.ps1 to verify log sources"
} else {
    Write-Log "Some configurations failed, check errors above" "WARN"
    exit 1
}
