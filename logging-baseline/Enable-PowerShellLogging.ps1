# PowerShell 详细日志审计策略
# 文件：Enable-PowerShellLogging.ps1
# 用途：在 Windows 主机上启用完整的 PowerShell 日志审计
# 覆盖：T1059.001 - PowerShell 执行检测
# 部署方式：本地运行 或 通过 GPO 分发（推荐）
# 需要管理员权限

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Rollback  # 传入此参数可回滚所有更改
)

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

# ============================================================
# 注册表路径定义
# ============================================================
$PSEngineKey     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$ScriptBlockKey  = "$PSEngineKey\ScriptBlockLogging"
$ModuleLogKey    = "$PSEngineKey\ModuleLogging"
$TranscriptKey   = "$PSEngineKey\Transcription"

if ($Rollback) {
    Write-Log "开始回滚 PowerShell 日志策略..." "WARN"
    @($ScriptBlockKey, $ModuleLogKey, $TranscriptKey, $PSEngineKey) | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item $_ -Recurse -Force
            Write-Log "已删除: $_" "SUCCESS"
        }
    }
    Write-Log "回滚完成。" "SUCCESS"
    exit 0
}

Write-Log "========================================"
Write-Log "  PowerShell 安全审计日志部署脚本"
Write-Log "  检测覆盖: T1059.001, T1027, T1562"
Write-Log "========================================"

# ============================================================
# 1. 启用 ScriptBlock 日志（最关键）
#    事件 ID 4104 - 记录所有执行的脚本内容（含混淆代码）
#    注意：此设置会记录明文脚本内容，包含解码后的实际代码
# ============================================================
Write-Log "配置 ScriptBlock 日志（事件ID 4104）..."

if (-not (Test-Path $ScriptBlockKey)) {
    New-Item -Path $ScriptBlockKey -Force | Out-Null
}
# EnableScriptBlockLogging = 1 : 记录所有脚本块
Set-ItemProperty -Path $ScriptBlockKey -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
# EnableScriptBlockInvocationLogging = 1 : 记录每次调用（含Start/Stop）
Set-ItemProperty -Path $ScriptBlockKey -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord

Write-Log "✅ ScriptBlock 日志已启用" "SUCCESS"

# ============================================================
# 2. 启用模块日志（记录所有模块调用的管道执行信息）
#    事件 ID 4103 - 记录模块级别的执行细节
# ============================================================
Write-Log "配置模块日志（事件ID 4103）..."

if (-not (Test-Path $ModuleLogKey)) {
    New-Item -Path $ModuleLogKey -Force | Out-Null
}
Set-ItemProperty -Path $ModuleLogKey -Name "EnableModuleLogging" -Value 1 -Type DWord

# 指定记录所有模块（* 通配符）
$ModuleNamesKey = "$ModuleLogKey\ModuleNames"
if (-not (Test-Path $ModuleNamesKey)) {
    New-Item -Path $ModuleNamesKey -Force | Out-Null
}
Set-ItemProperty -Path $ModuleNamesKey -Name "*" -Value "*" -Type String

Write-Log "✅ 模块日志已启用（记录所有模块）" "SUCCESS"

# ============================================================
# 3. 启用 PowerShell Transcription（完整会话记录）
#    记录完整的输入/输出到文本文件，便于取证分析
# ============================================================
Write-Log "配置 Transcription 记录..."

# 创建安全的转录目录（只有 System 和管理员可访问）
$TranscriptPath = "C:\Windows\Temp\PSTranscripts"
if (-not (Test-Path $TranscriptPath)) {
    New-Item -Path $TranscriptPath -ItemType Directory -Force | Out-Null
    
    # 设置 ACL：只允许 SYSTEM 和 Administrators 读取
    $acl = Get-Acl $TranscriptPath
    $acl.SetAccessRuleProtection($true, $false)  # 断开继承
    
    $adminRule  = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
    )
    
    $acl.AddAccessRule($adminRule)
    $acl.AddAccessRule($systemRule)
    Set-Acl $TranscriptPath $acl
    Write-Log "  转录目录已创建并设置安全 ACL: $TranscriptPath" "SUCCESS"
}

if (-not (Test-Path $TranscriptKey)) {
    New-Item -Path $TranscriptKey -Force | Out-Null
}
Set-ItemProperty -Path $TranscriptKey -Name "EnableTranscripting"     -Value 1 -Type DWord
Set-ItemProperty -Path $TranscriptKey -Name "EnableInvocationHeader"  -Value 1 -Type DWord
Set-ItemProperty -Path $TranscriptKey -Name "OutputDirectory"         -Value $TranscriptPath -Type String

Write-Log "✅ Transcription 已启用，输出路径: $TranscriptPath" "SUCCESS"

# ============================================================
# 4. 配置 Windows PowerShell 事件日志大小
#    默认 15MB 会在活跃环境中几分钟内轮转，导致证据丢失
# ============================================================
Write-Log "配置 PowerShell 事件日志大小..."

$LogConfigs = @(
    @{ Name = "Windows PowerShell";                              MaxSize = 524288000 },  # 500MB
    @{ Name = "Microsoft-Windows-PowerShell/Operational";        MaxSize = 524288000 },  # 500MB
    @{ Name = "Microsoft-Windows-PowerShell/Admin";              MaxSize = 104857600 }   # 100MB
)

foreach ($log in $LogConfigs) {
    try {
        $logObj = Get-WinEvent -ListLog $log.Name -ErrorAction SilentlyContinue
        if ($logObj) {
            $logObj.MaximumSizeInBytes = $log.MaxSize
            $logObj.IsEnabled = $true
            $logObj.SaveChanges()
            Write-Log "  ✅ $($log.Name): 日志大小已设为 $([math]::Round($log.MaxSize/1MB))MB" "SUCCESS"
        }
    } catch {
        Write-Log "  ⚠️  无法配置日志 $($log.Name): $_" "WARN"
    }
}

# ============================================================
# 5. 配置 Windows 安全审计策略（关键事件开关）
#    这些是 Sysmon 之外必须启用的 Windows 原生审计
# ============================================================
Write-Log "配置 Windows 高级安全审计策略..."

$AuditPolicies = @(
    # 进程追踪（4688 进程创建，含命令行）
    @{ Category = "Detailed Tracking"; SubCategory = "Process Creation";         Success = "enable"; Failure = "enable" },
    @{ Category = "Detailed Tracking"; SubCategory = "Process Termination";      Success = "enable"; Failure = "disable" },
    # 账户登录（4624/4625/4648）
    @{ Category = "Logon/Logoff";      SubCategory = "Logon";                    Success = "enable"; Failure = "enable" },
    @{ Category = "Logon/Logoff";      SubCategory = "Logoff";                   Success = "enable"; Failure = "disable" },
    @{ Category = "Logon/Logoff";      SubCategory = "Special Logon";            Success = "enable"; Failure = "disable" },
    # 账户管理（4720/4726 创建/删除用户，4732/4733 组成员变更）
    @{ Category = "Account Management"; SubCategory = "User Account Management"; Success = "enable"; Failure = "enable" },
    @{ Category = "Account Management"; SubCategory = "Security Group Management"; Success = "enable"; Failure = "enable" },
    # 对象访问（文件、注册表）
    @{ Category = "Object Access";     SubCategory = "Registry";                 Success = "enable"; Failure = "enable" },
    # 策略变更（4719 审计策略变更，攻击者常修改此项）
    @{ Category = "Policy Change";     SubCategory = "Audit Policy Change";      Success = "enable"; Failure = "enable" },
    @{ Category = "Policy Change";     SubCategory = "Authentication Policy Change"; Success = "enable"; Failure = "enable" },
    # 权限使用（4673/4674 特权服务调用）
    @{ Category = "Privilege Use";     SubCategory = "Sensitive Privilege Use";  Success = "enable"; Failure = "enable" },
    # 系统事件（4616 时钟修改，4657 注册表修改）
    @{ Category = "System";            SubCategory = "Security System Extension"; Success = "enable"; Failure = "enable" },
    @{ Category = "System";            SubCategory = "System Integrity";         Success = "enable"; Failure = "enable" }
)

foreach ($policy in $AuditPolicies) {
    try {
        $cmd = "auditpol /set /subcategory:`"$($policy.SubCategory)`" /success:$($policy.Success) /failure:$($policy.Failure)"
        Invoke-Expression $cmd 2>&1 | Out-Null
        Write-Log "  ✅ 已启用审计: $($policy.SubCategory)" "SUCCESS"
    } catch {
        Write-Log "  ⚠️  无法设置审计策略 $($policy.SubCategory): $_" "WARN"
    }
}

# ============================================================
# 6. 启用进程创建命令行记录（4688 事件含完整命令行）
# ============================================================
Write-Log "启用进程创建命令行审计..."

$AuditKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $AuditKey)) {
    New-Item -Path $AuditKey -Force | Out-Null
}
Set-ItemProperty -Path $AuditKey -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

Write-Log "✅ 进程命令行审计已启用（Windows 事件 4688）" "SUCCESS"

# ============================================================
# 7. 配置 Security 事件日志大小
# ============================================================
Write-Log "配置 Security 事件日志大小..."
try {
    $secLog = Get-WinEvent -ListLog "Security" -ErrorAction Stop
    $secLog.MaximumSizeInBytes = 1073741824  # 1GB
    $secLog.SaveChanges()
    Write-Log "✅ Security 事件日志: 已设为 1GB" "SUCCESS"
} catch {
    Write-Log "⚠️  无法配置 Security 日志大小: $_" "WARN"
}

# ============================================================
# 8. 验证配置
# ============================================================
Write-Log ""
Write-Log "========================================"
Write-Log "           配置验证结果"
Write-Log "========================================"

$verificationItems = @(
    @{ Name = "ScriptBlock 日志";   Path = $ScriptBlockKey; Value = "EnableScriptBlockLogging"; Expected = 1 },
    @{ Name = "模块日志";           Path = $ModuleLogKey;   Value = "EnableModuleLogging";      Expected = 1 },
    @{ Name = "Transcription";      Path = $TranscriptKey;  Value = "EnableTranscripting";      Expected = 1 },
    @{ Name = "进程命令行审计";      Path = $AuditKey;       Value = "ProcessCreationIncludeCmdLine_Enabled"; Expected = 1 }
)

$allPassed = $true
foreach ($item in $verificationItems) {
    try {
        $val = Get-ItemPropertyValue -Path $item.Path -Name $item.Value -ErrorAction Stop
        if ($val -eq $item.Expected) {
            Write-Log "  ✅ $($item.Name): 已启用" "SUCCESS"
        } else {
            Write-Log "  ❌ $($item.Name): 值异常（期望 $($item.Expected)，实际 $val）" "ERROR"
            $allPassed = $false
        }
    } catch {
        Write-Log "  ❌ $($item.Name): 注册表键未找到" "ERROR"
        $allPassed = $false
    }
}

if ($allPassed) {
    Write-Log ""
    Write-Log "✅ 所有 PowerShell 审计策略已成功配置！" "SUCCESS"
    Write-Log ""
    Write-Log "【后续步骤】"
    Write-Log "  1. 通过 GPO 将此脚本分发至所有域内主机"
    Write-Log "  2. 确认 SIEM 正在收集事件 ID 4103, 4104"
    Write-Log "  3. 运行 Check-LogHealth.ps1 验证全域日志源状态"
} else {
    Write-Log "⚠️  部分配置未成功，请检查上方错误信息" "WARN"
    exit 1
}
