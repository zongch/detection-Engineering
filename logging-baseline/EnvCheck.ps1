Write-Host "===== 环境检查报告 =====" -ForegroundColor Cyan

# 1. Sysmon 状态
Write-Host "`n[1] Sysmon 服务状态" -ForegroundColor Yellow
$svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
if ($svc) {
    Write-Host "  已安装: $($svc.Name) - $($svc.Status)" -ForegroundColor Green
} else {
    Write-Host "  未安装" -ForegroundColor Red
}

# 2. PS 审计策略
Write-Host "`n[2] PowerShell 审计策略" -ForegroundColor Yellow
$sbKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
$mlKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
$trKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
$sb = if (Test-Path $sbKey) { (Get-ItemProperty $sbKey -EA SilentlyContinue).EnableScriptBlockLogging } else { 0 }
$ml = if (Test-Path $mlKey) { (Get-ItemProperty $mlKey -EA SilentlyContinue).EnableModuleLogging } else { 0 }
$tr = if (Test-Path $trKey) { (Get-ItemProperty $trKey -EA SilentlyContinue).EnableTranscripting } else { 0 }
Write-Host "  ScriptBlock日志(4104): $(if($sb -eq 1){'[OK] 已启用'}else{'[!!] 未启用'})"
Write-Host "  模块日志(4103):        $(if($ml -eq 1){'[OK] 已启用'}else{'[!!] 未启用'})"
Write-Host "  Transcription:         $(if($tr -eq 1){'[OK] 已启用'}else{'[!!] 未启用'})"

# 3. 进程命令行审计
Write-Host "`n[3] 进程命令行审计" -ForegroundColor Yellow
$cmdKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
$cmdVal = if (Test-Path $cmdKey) { (Get-ItemProperty $cmdKey -EA SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled } else { 0 }
Write-Host "  命令行记录(4688): $(if($cmdVal -eq 1){'[OK] 已启用'}else{'[!!] 未启用'})"

# 4. 日志大小
Write-Host "`n[4] 关键事件日志大小" -ForegroundColor Yellow
$logNames = @("Security","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-Sysmon/Operational")
foreach ($logName in $logNames) {
    $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
    if ($log) {
        $sizeMB = [math]::Round($log.MaximumSizeInBytes / 1MB)
        $status = if ($sizeMB -ge 256) { "[OK]" } else { "[偏小]" }
        Write-Host "  $($logName.Split('/')[-1]): ${sizeMB}MB $status"
    } else {
        Write-Host "  $logName : [!!] 不存在" -ForegroundColor Red
    }
}

# 5. 管理员权限
Write-Host "`n[5] 当前权限" -ForegroundColor Yellow
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "  管理员权限: $(if($isAdmin){'[OK] 是'}else{'[!!] 否 - 部署需要管理员权限'})"

# 6. Sysmon 安装包
Write-Host "`n[6] Sysmon 安装包" -ForegroundColor Yellow
$sysmonExe = "C:\Users\zongc\WorkBuddy\20260320164613\detection-engineering\logging-baseline\Sysmon64.exe"
if (Test-Path $sysmonExe) {
    Write-Host "  Sysmon64.exe: [OK] 已就绪" -ForegroundColor Green
} else {
    Write-Host "  Sysmon64.exe: [!!] 未找到，需要先下载" -ForegroundColor Red
}

Write-Host "`n===== 检查完成 =====" -ForegroundColor Cyan
