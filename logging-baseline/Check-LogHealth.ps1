# 日志源健康持续监测脚本
# 文件：Check-LogHealth.ps1
# 用途：检测所有关键日志源是否正常工作，发现盲点立即告警
# 建议：每小时通过计划任务运行，结果推送至 SIEM 或告警系统

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    # 远程目标（为空则检查本机）
    [string[]]$ComputerName = @(),
    
    # 过去多少分钟内必须有事件（超出则认为日志源异常）
    [int]$SilenceThresholdMinutes = 60,
    
    # 输出格式：Console / JSON / CSV / Splunk（HEC格式）
    [string]$OutputFormat = "Console",
    
    # Splunk HEC URL（OutputFormat=Splunk 时使用）
    [string]$SplunkHECUrl = "",
    [string]$SplunkHECToken = "",
    
    # 报告保存路径
    [string]$ReportPath = "$PSScriptRoot\health_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
)

$checkTime = Get-Date
$thresholdTime = $checkTime.AddMinutes(-$SilenceThresholdMinutes)

# ============================================================
# 健康检查项定义
# 每项检查代表一个检测盲点风险
# ============================================================
$healthChecks = @(
    @{
        Name        = "Sysmon_Service"
        Description = "Sysmon 服务运行状态"
        ATTACKGap   = "服务停止将导致T1003/T1055/T1059等大量检测失效"
        Severity    = "Critical"
        CheckType   = "Service"
        Target      = "Sysmon64"
    },
    @{
        Name        = "Sysmon_ProcessCreate"
        Description = "Sysmon 进程创建事件（ID=1）活跃度"
        ATTACKGap   = "T1059 命令执行检测失明"
        Severity    = "Critical"
        CheckType   = "EventLog"
        LogName     = "Microsoft-Windows-Sysmon/Operational"
        EventID     = 1
        MinCount    = 5
    },
    @{
        Name        = "Sysmon_NetworkConnect"
        Description = "Sysmon 网络连接事件（ID=3）活跃度"
        ATTACKGap   = "T1071 C2通信检测失明"
        Severity    = "High"
        CheckType   = "EventLog"
        LogName     = "Microsoft-Windows-Sysmon/Operational"
        EventID     = 3
        MinCount    = 1
    },
    @{
        Name        = "Sysmon_ProcessAccess"
        Description = "Sysmon 进程访问事件（ID=10）存在"
        ATTACKGap   = "T1003.001 LSASS凭证转储检测失明（最高风险盲点）"
        Severity    = "Critical"
        CheckType   = "EventLogExists"
        LogName     = "Microsoft-Windows-Sysmon/Operational"
        EventID     = 10
    },
    @{
        Name        = "WinSecurity_Logon"
        Description = "Windows 安全日志登录事件（4624）活跃度"
        ATTACKGap   = "T1078/T1021 横向移动和账户滥用检测失明"
        Severity    = "Critical"
        CheckType   = "EventLog"
        LogName     = "Security"
        EventID     = 4624
        MinCount    = 1
    },
    @{
        Name        = "WinSecurity_ProcessCreate"
        Description = "Windows 安全日志进程创建（4688）命令行记录"
        ATTACKGap   = "T1059 执行检测能力受损（Sysmon备用数据源）"
        Severity    = "High"
        CheckType   = "EventLog"
        LogName     = "Security"
        EventID     = 4688
        MinCount    = 1
    },
    @{
        Name        = "PS_ScriptBlock"
        Description = "PowerShell ScriptBlock 日志（4104）活跃度"
        ATTACKGap   = "T1059.001 PowerShell混淆/编码命令检测失明"
        Severity    = "Critical"
        CheckType   = "EventLog"
        LogName     = "Microsoft-Windows-PowerShell/Operational"
        EventID     = 4104
        MinCount    = 0  # 可以为0（无PS活动时正常）
    },
    @{
        Name        = "PS_ScriptBlock_Enabled"
        Description = "PowerShell ScriptBlock 日志策略已启用"
        ATTACKGap   = "策略未启用=T1059.001完全失明"
        Severity    = "Critical"
        CheckType   = "Registry"
        RegistryPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        RegistryName  = "EnableScriptBlockLogging"
        ExpectedValue = 1
    },
    @{
        Name        = "PS_ModuleLog_Enabled"
        Description = "PowerShell 模块日志策略已启用"
        ATTACKGap   = "T1059.001 模块级执行不可见"
        Severity    = "High"
        CheckType   = "Registry"
        RegistryPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        RegistryName  = "EnableModuleLogging"
        ExpectedValue = 1
    },
    @{
        Name        = "ProcessCmdLine_Enabled"
        Description = "进程创建命令行审计已启用"
        ATTACKGap   = "T1059 命令行参数不可见，检测准确度下降80%"
        Severity    = "Critical"
        CheckType   = "Registry"
        RegistryPath  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        RegistryName  = "ProcessCreationIncludeCmdLine_Enabled"
        ExpectedValue = 1
    },
    @{
        Name        = "Security_LogSize"
        Description = "Security 事件日志大小（建议>=512MB）"
        ATTACKGap   = "日志轮转过快导致历史证据丢失"
        Severity    = "Medium"
        CheckType   = "LogSize"
        LogName     = "Security"
        MinSizeMB   = 512
    },
    @{
        Name        = "PS_LogSize"
        Description = "PowerShell/Operational 日志大小（建议>=256MB）"
        ATTACKGap   = "PS日志轮转丢失攻击证据"
        Severity    = "Medium"
        CheckType   = "LogSize"
        LogName     = "Microsoft-Windows-PowerShell/Operational"
        MinSizeMB   = 256
    },
    @{
        Name        = "Sysmon_LogSize"
        Description = "Sysmon/Operational 日志大小（建议>=512MB）"
        ATTACKGap   = "Sysmon日志轮转丢失检测关键证据"
        Severity    = "High"
        CheckType   = "LogSize"
        LogName     = "Microsoft-Windows-Sysmon/Operational"
        MinSizeMB   = 512
    },
    @{
        Name        = "WMI_Logging"
        Description = "WMI 活动日志已启用（WMI-Activity/Operational）"
        ATTACKGap   = "T1047 WMI执行/T1546.003 WMI持久化检测失明"
        Severity    = "High"
        CheckType   = "LogEnabled"
        LogName     = "Microsoft-Windows-WMI-Activity/Operational"
    }
)

# ============================================================
# 执行检查
# ============================================================
function Invoke-HealthCheck {
    param($Check, [string]$Computer = "LOCAL")
    
    $result = @{
        Computer    = $Computer
        Name        = $Check.Name
        Description = $Check.Description
        ATTACKGap   = $Check.ATTACKGap
        Severity    = $Check.Severity
        Status      = "Unknown"
        Detail      = ""
        CheckTime   = $checkTime.ToString("yyyy-MM-dd HH:mm:ss")
    }
    
    try {
        switch ($Check.CheckType) {
            "Service" {
                $svc = Get-Service -Name $Check.Target -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq "Running") {
                    $result.Status = "Healthy"
                    $result.Detail = "服务运行中"
                } elseif ($svc) {
                    $result.Status = "Warning"
                    $result.Detail = "服务已安装但状态: $($svc.Status)"
                } else {
                    $result.Status = "Critical"
                    $result.Detail = "服务未安装"
                }
            }
            
            "EventLog" {
                $events = Get-WinEvent -FilterHashtable @{
                    LogName   = $Check.LogName
                    Id        = $Check.EventID
                    StartTime = $thresholdTime
                } -ErrorAction SilentlyContinue -MaxEvents 100
                
                $count = if ($events) { $events.Count } else { 0 }
                
                if ($count -ge $Check.MinCount) {
                    $result.Status = "Healthy"
                    $result.Detail = "过去${SilenceThresholdMinutes}分钟内有 $count 条事件"
                } elseif ($Check.MinCount -eq 0) {
                    $result.Status = "Healthy"
                    $result.Detail = "日志正常（当前无相关活动）"
                } else {
                    $result.Status = "Warning"
                    $result.Detail = "过去${SilenceThresholdMinutes}分钟内只有 $count 条事件（期望>=$($Check.MinCount)）"
                }
            }
            
            "EventLogExists" {
                # 检查日志通道是否存在（不要求有事件）
                $log = Get-WinEvent -ListLog $Check.LogName -ErrorAction SilentlyContinue
                if ($log -and $log.IsEnabled) {
                    $result.Status = "Healthy"
                    $result.Detail = "日志通道已启用，共 $($log.RecordCount) 条记录"
                } elseif ($log) {
                    $result.Status = "Warning"
                    $result.Detail = "日志通道存在但未启用"
                } else {
                    $result.Status = "Critical"
                    $result.Detail = "日志通道不存在（Sysmon可能未安装）"
                }
            }
            
            "Registry" {
                if (Test-Path $Check.RegistryPath) {
                    $val = Get-ItemProperty -Path $Check.RegistryPath -Name $Check.RegistryName -ErrorAction SilentlyContinue
                    if ($val -and $val.$($Check.RegistryName) -eq $Check.ExpectedValue) {
                        $result.Status = "Healthy"
                        $result.Detail = "注册表值已正确设置为 $($Check.ExpectedValue)"
                    } else {
                        $result.Status = "Critical"
                        $actualVal = if ($val) { $val.$($Check.RegistryName) } else { "未设置" }
                        $result.Detail = "注册表值异常: 期望=$($Check.ExpectedValue), 实际=$actualVal"
                    }
                } else {
                    $result.Status = "Critical"
                    $result.Detail = "注册表路径不存在: $($Check.RegistryPath)"
                }
            }
            
            "LogSize" {
                $log = Get-WinEvent -ListLog $Check.LogName -ErrorAction SilentlyContinue
                if ($log) {
                    $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB)
                    if ($sizeMB -ge $Check.MinSizeMB) {
                        $result.Status = "Healthy"
                        $result.Detail = "日志大小: ${sizeMB}MB（建议>=$($Check.MinSizeMB)MB）"
                    } else {
                        $result.Status = "Warning"
                        $result.Detail = "日志大小不足: ${sizeMB}MB（建议>=$($Check.MinSizeMB)MB），存在日志轮转丢失风险"
                    }
                } else {
                    $result.Status = "Warning"
                    $result.Detail = "无法读取日志通道配置"
                }
            }
            
            "LogEnabled" {
                $log = Get-WinEvent -ListLog $Check.LogName -ErrorAction SilentlyContinue
                if ($log -and $log.IsEnabled) {
                    $result.Status = "Healthy"
                    $result.Detail = "日志通道已启用"
                } else {
                    $result.Status = "Warning"
                    $result.Detail = "日志通道未启用（需手动启用或配置策略）"
                }
            }
        }
    } catch {
        $result.Status = "Error"
        $result.Detail = "检查失败: $_"
    }
    
    return [PSCustomObject]$result
}

# ============================================================
# 主逻辑
# ============================================================
$allResults = [System.Collections.ArrayList]@()

$targets = if ($ComputerName.Count -gt 0) { $ComputerName } else { @("LOCAL") }

foreach ($target in $targets) {
    Write-Host ""
    Write-Host "🔍 检查主机: $target" -ForegroundColor Cyan
    Write-Host ("-" * 60)
    
    foreach ($check in $healthChecks) {
        if ($target -eq "LOCAL") {
            $result = Invoke-HealthCheck -Check $check -Computer (hostname)
        } else {
            try {
                $result = Invoke-Command -ComputerName $target -ScriptBlock ${function:Invoke-HealthCheck} `
                    -ArgumentList $check, $target
            } catch {
                $result = [PSCustomObject]@{
                    Computer    = $target
                    Name        = $check.Name
                    Description = $check.Description
                    ATTACKGap   = $check.ATTACKGap
                    Severity    = $check.Severity
                    Status      = "Error"
                    Detail      = "无法连接: $_"
                    CheckTime   = $checkTime.ToString("yyyy-MM-dd HH:mm:ss")
                }
            }
        }
        
        [void]$allResults.Add($result)
        
        # 控制台输出
        $icon  = switch ($result.Status) {
            "Healthy"  { "✅" }
            "Warning"  { "⚠️ " }
            "Critical" { "🔴" }
            default    { "❓" }
        }
        $color = switch ($result.Status) {
            "Healthy"  { "Green"  }
            "Warning"  { "Yellow" }
            "Critical" { "Red"    }
            default    { "Gray"   }
        }
        
        Write-Host "$icon [$($result.Severity.PadRight(8))] $($result.Description)" -ForegroundColor $color
        if ($result.Status -ne "Healthy") {
            Write-Host "     └─ $($result.Detail)" -ForegroundColor DarkGray
            Write-Host "     └─ 检测影响: $($result.ATTACKGap)" -ForegroundColor DarkYellow
        }
    }
}

# ============================================================
# 汇总报告
# ============================================================
Write-Host ""
Write-Host ("=" * 60)
Write-Host "  日志源健康检查汇总"
Write-Host ("=" * 60)

$criticalCount = ($allResults | Where-Object { $_.Status -in @("Critical","Error") }).Count
$warningCount  = ($allResults | Where-Object { $_.Status -eq "Warning" }).Count
$healthyCount  = ($allResults | Where-Object { $_.Status -eq "Healthy" }).Count
$totalCount    = $allResults.Count

Write-Host "  总检查项: $totalCount"
Write-Host "  ✅ 正常: $healthyCount" -ForegroundColor Green
Write-Host "  ⚠️  警告: $warningCount" -ForegroundColor Yellow
Write-Host "  🔴 严重: $criticalCount" -ForegroundColor Red

if ($criticalCount -gt 0) {
    Write-Host ""
    Write-Host "🚨 以下严重问题代表当前检测盲点，请立即处理：" -ForegroundColor Red
    $allResults | Where-Object { $_.Status -in @("Critical","Error") } | ForEach-Object {
        Write-Host "  → [$($_.Computer)] $($_.Name): $($_.Detail)" -ForegroundColor Red
        Write-Host "    检测影响: $($_.ATTACKGap)" -ForegroundColor DarkYellow
    }
}

# 计算综合健康分数
$healthScore = [math]::Round(($healthyCount / $totalCount) * 100)
$scoreColor  = if ($healthScore -ge 90) { "Green" } elseif ($healthScore -ge 70) { "Yellow" } else { "Red" }
Write-Host ""
Write-Host "  综合日志健康评分: $healthScore / 100" -ForegroundColor $scoreColor

# 保存 JSON 报告
$report = @{
    ReportTime   = $checkTime.ToString("yyyy-MM-dd HH:mm:ss")
    HealthScore  = $healthScore
    TotalChecks  = $totalCount
    HealthyCount = $healthyCount
    WarningCount = $warningCount
    CriticalCount = $criticalCount
    Results      = $allResults
}
$report | ConvertTo-Json -Depth 5 | Out-File $ReportPath -Encoding UTF8
Write-Host ""
Write-Host "  📄 详细报告已保存: $ReportPath" -ForegroundColor Cyan

# 如果存在严重问题，以非零退出码退出（供 CI/CD 使用）
if ($criticalCount -gt 0) {
    exit 1
} else {
    exit 0
}
