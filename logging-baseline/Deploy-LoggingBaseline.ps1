# Sysmon + 日志基线 一键部署脚本
# 文件：Deploy-LoggingBaseline.ps1
# 用途：在单台主机或通过 PSRemoting 批量部署 Sysmon + 日志审计基线
# 需要：管理员权限，Sysmon.exe 和 sysmonconfig.xml 位于同目录或指定路径

#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    # 远程部署：目标计算机列表（为空则部署本机）
    [string[]]$ComputerName = @(),
    
    # Sysmon 安装包路径（需提前从 Sysinternals 下载）
    [string]$SysmonPath = "$PSScriptRoot\Sysmon64.exe",
    
    # Sysmon 配置文件路径
    [string]$SysmonConfig = "$PSScriptRoot\sysmonconfig.xml",
    
    # 是否同时部署 PowerShell 日志策略
    [switch]$SkipPowerShellLogging,
    
    # 部署报告输出路径
    [string]$ReportPath = "$PSScriptRoot\deployment_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

$ErrorActionPreference = "Continue"

# ============================================================
# 工具函数
# ============================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO", [string]$Computer = "LOCAL")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan"    }
        "SUCCESS" { "Green"   }
        "WARN"    { "Yellow"  }
        "ERROR"   { "Red"     }
    }
    Write-Host "[$timestamp][$Computer][$Level] $Message" -ForegroundColor $color
}

function Test-Prerequisites {
    param([string]$Computer = "LOCAL")
    
    $checks = @{
        SysmonExeExists   = Test-Path $SysmonPath
        SysmonConfigExists = Test-Path $SysmonConfig
        PS5orHigher       = $PSVersionTable.PSVersion.Major -ge 5
    }
    
    $failed = $checks.GetEnumerator() | Where-Object { -not $_.Value }
    if ($failed) {
        foreach ($f in $failed) {
            Write-Log "前置条件失败: $($f.Key)" "ERROR" $Computer
        }
        return $false
    }
    return $true
}

function Install-SysmonLocal {
    param([string]$Computer = "LOCAL")
    
    try {
        # 检查 Sysmon 是否已安装
        $sysmonService = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
        
        if ($sysmonService) {
            Write-Log "Sysmon 已安装，更新配置..." "INFO" $Computer
            & $SysmonPath -c $SysmonConfig -accepteula 2>&1 | Out-Null
            Write-Log "✅ Sysmon 配置已更新" "SUCCESS" $Computer
        } else {
            Write-Log "安装 Sysmon..." "INFO" $Computer
            & $SysmonPath -i $SysmonConfig -accepteula 2>&1 | Out-Null
            
            # 验证安装
            Start-Sleep -Seconds 3
            $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq "Running") {
                Write-Log "✅ Sysmon 安装并运行成功" "SUCCESS" $Computer
                return $true
            } else {
                Write-Log "❌ Sysmon 安装后服务未运行" "ERROR" $Computer
                return $false
            }
        }
        return $true
    } catch {
        Write-Log "❌ Sysmon 安装失败: $_" "ERROR" $Computer
        return $false
    }
}

function Install-SysmonRemote {
    param([string]$Computer)
    
    Write-Log "开始远程部署..." "INFO" $Computer
    
    try {
        # 创建远程临时目录
        $remoteTempPath = "\\$Computer\C$\Windows\Temp\SysmonDeploy"
        if (-not (Test-Path $remoteTempPath)) {
            New-Item -Path $remoteTempPath -ItemType Directory -Force | Out-Null
        }
        
        # 复制文件到目标主机
        Write-Log "  复制 Sysmon 文件..." "INFO" $Computer
        Copy-Item $SysmonPath "$remoteTempPath\Sysmon64.exe" -Force
        Copy-Item $SysmonConfig "$remoteTempPath\sysmonconfig.xml" -Force
        
        # 远程执行安装
        $result = Invoke-Command -ComputerName $Computer -ScriptBlock {
            param($TempPath)
            
            $sysmonExe    = "$TempPath\Sysmon64.exe"
            $sysmonConfig = "$TempPath\sysmonconfig.xml"
            
            $svc = Get-Service "Sysmon64" -ErrorAction SilentlyContinue
            if ($svc) {
                & $sysmonExe -c $sysmonConfig -accepteula 2>&1
                return @{ Success = $true; Action = "Updated" }
            } else {
                & $sysmonExe -i $sysmonConfig -accepteula 2>&1
                Start-Sleep -Seconds 3
                $svc = Get-Service "Sysmon64" -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq "Running") {
                    return @{ Success = $true; Action = "Installed" }
                } else {
                    return @{ Success = $false; Action = "Failed" }
                }
            }
        } -ArgumentList "C:\Windows\Temp\SysmonDeploy"
        
        if ($result.Success) {
            Write-Log "✅ Sysmon $($result.Action) 成功" "SUCCESS" $Computer
            return $true
        } else {
            Write-Log "❌ Sysmon 部署失败" "ERROR" $Computer
            return $false
        }
    } catch {
        Write-Log "❌ 远程部署异常: $_" "ERROR" $Computer
        return $false
    }
}

function Deploy-PSLoggingRemote {
    param([string]$Computer)
    
    try {
        $psLoggingScript = "$PSScriptRoot\Enable-PowerShellLogging.ps1"
        if (-not (Test-Path $psLoggingScript)) {
            Write-Log "  ⚠️  未找到 Enable-PowerShellLogging.ps1，跳过 PS 日志配置" "WARN" $Computer
            return $false
        }
        
        $scriptContent = Get-Content $psLoggingScript -Raw
        Invoke-Command -ComputerName $Computer -ScriptBlock {
            param($Script)
            Invoke-Expression $Script
        } -ArgumentList $scriptContent
        
        Write-Log "✅ PowerShell 日志策略部署成功" "SUCCESS" $Computer
        return $true
    } catch {
        Write-Log "❌ PowerShell 日志部署失败: $_" "ERROR" $Computer
        return $false
    }
}

function Get-DeploymentStatus {
    param([string]$Computer = "LOCAL")
    
    $status = @{
        Computer         = $Computer
        SysmonInstalled  = $false
        SysmonRunning    = $false
        SysmonVersion    = "N/A"
        PSScriptBlock    = $false
        PSModuleLog      = $false
        PSTranscription  = $false
        SecurityLogSize  = 0
        PSLogSize        = 0
        DeployTime       = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Status           = "Unknown"
    }
    
    if ($Computer -eq "LOCAL") {
        # 检查 Sysmon
        $svc = Get-Service "Sysmon64" -ErrorAction SilentlyContinue
        $status.SysmonInstalled = ($null -ne $svc)
        $status.SysmonRunning   = ($svc -and $svc.Status -eq "Running")
        
        if ($status.SysmonRunning) {
            $sysmonBin = Get-Process "Sysmon64" -ErrorAction SilentlyContinue
            if ($sysmonBin) { $status.SysmonVersion = $sysmonBin.FileVersion }
        }
        
        # 检查 PS 日志策略
        $sbKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        $mlKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
        $trKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
        
        $status.PSScriptBlock   = (Test-Path $sbKey) -and ((Get-ItemProperty $sbKey -EA SilentlyContinue).EnableScriptBlockLogging -eq 1)
        $status.PSModuleLog     = (Test-Path $mlKey) -and ((Get-ItemProperty $mlKey -EA SilentlyContinue).EnableModuleLogging -eq 1)
        $status.PSTranscription = (Test-Path $trKey) -and ((Get-ItemProperty $trKey -EA SilentlyContinue).EnableTranscripting -eq 1)
        
        # 检查日志大小
        $secLog = Get-WinEvent -ListLog "Security" -EA SilentlyContinue
        $psLog  = Get-WinEvent -ListLog "Microsoft-Windows-PowerShell/Operational" -EA SilentlyContinue
        $status.SecurityLogSize = if ($secLog) { [math]::Round($secLog.MaximumSizeInBytes / 1MB) } else { 0 }
        $status.PSLogSize       = if ($psLog)  { [math]::Round($psLog.MaximumSizeInBytes / 1MB)  } else { 0 }
        
    } else {
        try {
            $remoteStatus = Invoke-Command -ComputerName $Computer -ScriptBlock {
                $svc = Get-Service "Sysmon64" -ErrorAction SilentlyContinue
                $sbKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                $mlKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
                $trKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
                @{
                    SysmonInstalled  = ($null -ne $svc)
                    SysmonRunning    = ($svc -and $svc.Status -eq "Running")
                    PSScriptBlock    = (Test-Path $sbKey) -and ((Get-ItemProperty $sbKey -EA SilentlyContinue).EnableScriptBlockLogging -eq 1)
                    PSModuleLog      = (Test-Path $mlKey) -and ((Get-ItemProperty $mlKey -EA SilentlyContinue).EnableModuleLogging -eq 1)
                    PSTranscription  = (Test-Path $trKey) -and ((Get-ItemProperty $trKey -EA SilentlyContinue).EnableTranscripting -eq 1)
                }
            }
            foreach ($key in $remoteStatus.Keys) {
                $status[$key] = $remoteStatus[$key]
            }
        } catch {
            $status.Status = "ConnectionFailed"
        }
    }
    
    # 计算综合状态
    if ($status.SysmonRunning -and $status.PSScriptBlock -and $status.PSModuleLog) {
        $status.Status = "Healthy"
    } elseif ($status.SysmonRunning -or $status.PSScriptBlock) {
        $status.Status = "Partial"
    } else {
        $status.Status = "NotDeployed"
    }
    
    return $status
}

# ============================================================
# 主部署逻辑
# ============================================================
Write-Log "=================================================="
Write-Log "  日志基线部署脚本 v1.0"
Write-Log "  Sysmon + PowerShell 审计策略"
Write-Log "=================================================="

# 前置检查
if (-not (Test-Prerequisites)) {
    Write-Log "前置条件检查失败，请确认:" "ERROR"
    Write-Log "  1. Sysmon64.exe 存在于: $SysmonPath" "ERROR"
    Write-Log "  2. sysmonconfig.xml 存在于: $SysmonConfig" "ERROR"
    Write-Log "  下载 Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" "INFO"
    exit 1
}

$deploymentResults = [System.Collections.ArrayList]@()

# 确定部署目标
$targets = if ($ComputerName.Count -gt 0) { $ComputerName } else { @("LOCAL") }

Write-Log "部署目标: $($targets.Count) 台主机"
Write-Log ""

foreach ($target in $targets) {
    Write-Log "-------- 开始处理: $target --------"
    
    $sysmonResult = $false
    $psLogResult  = $false
    
    if ($target -eq "LOCAL") {
        # 本地部署
        $sysmonResult = Install-SysmonLocal -Computer $target
        if (-not $SkipPowerShellLogging) {
            # 直接调用 PS 日志脚本
            $psScript = "$PSScriptRoot\Enable-PowerShellLogging.ps1"
            if (Test-Path $psScript) {
                & $psScript
                $psLogResult = ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $null)
            }
        }
    } else {
        # 远程部署
        $sysmonResult = Install-SysmonRemote -Computer $target
        if (-not $SkipPowerShellLogging) {
            $psLogResult = Deploy-PSLoggingRemote -Computer $target
        }
    }
    
    # 验证部署结果
    Start-Sleep -Seconds 2
    $status = if ($target -eq "LOCAL") { 
        Get-DeploymentStatus -Computer "LOCAL" 
    } else { 
        Get-DeploymentStatus -Computer $target 
    }
    $status.Computer = $target
    
    [void]$deploymentResults.Add([PSCustomObject]$status)
    
    Write-Log ""
    Write-Log "  部署状态: $($status.Status)" $(if ($status.Status -eq "Healthy") { "SUCCESS" } else { "WARN" })
    Write-Log "  Sysmon 运行中: $($status.SysmonRunning)"
    Write-Log "  ScriptBlock 日志: $($status.PSScriptBlock)"
    Write-Log "  模块日志: $($status.PSModuleLog)"
    Write-Log "  Transcription: $($status.PSTranscription)"
    Write-Log ""
}

# ============================================================
# 生成部署报告
# ============================================================
Write-Log "=================================================="
Write-Log "              部署汇总报告"
Write-Log "=================================================="

$healthy = $deploymentResults | Where-Object { $_.Status -eq "Healthy" }
$partial = $deploymentResults | Where-Object { $_.Status -eq "Partial" }
$failed  = $deploymentResults | Where-Object { $_.Status -in @("NotDeployed", "ConnectionFailed") }

Write-Log "✅ 成功 (Healthy): $($healthy.Count) 台" "SUCCESS"
if ($partial.Count -gt 0) {
    Write-Log "⚠️  部分完成 (Partial): $($partial.Count) 台" "WARN"
    $partial | ForEach-Object { Write-Log "   - $($_.Computer)" "WARN" }
}
if ($failed.Count -gt 0) {
    Write-Log "❌ 失败: $($failed.Count) 台" "ERROR"
    $failed | ForEach-Object { Write-Log "   - $($_.Computer): $($_.Status)" "ERROR" }
}

# 导出 CSV 报告
$deploymentResults | Export-Csv $ReportPath -NoTypeInformation -Encoding UTF8
Write-Log ""
Write-Log "📄 详细报告已保存至: $ReportPath" "INFO"

Write-Log ""
Write-Log "【下一步操作】"
Write-Log "  1. 在 SIEM 中验证 Sysmon 事件是否正常摄入（查询 EventCode=1）"
Write-Log "  2. 在 SIEM 中验证 PowerShell 事件 4104 是否出现"
Write-Log "  3. 运行 Check-LogHealth.ps1 进行日志源持续健康监测"
Write-Log "  4. 完成后继续执行第二步：部署5条关键检测规则"
