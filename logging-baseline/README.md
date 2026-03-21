# 日志基线部署包
## 第一步：确保日志完整性

---

### 文件清单

| 文件 | 用途 | 执行顺序 |
|------|------|----------|
| `sysmonconfig.xml` | 生产级 Sysmon 配置（25项事件规则） | Step 1 |
| `Enable-PowerShellLogging.ps1` | PowerShell 详细审计策略 | Step 2 |
| `Deploy-LoggingBaseline.ps1` | 一键部署 Sysmon + PS 日志（含远程批量部署） | Step 1+2 合并 |
| `Check-LogHealth.ps1` | 日志源健康持续监测，发现盲点告警 | 每小时运行 |

---

### 快速部署（推荐）

#### 1. 下载 Sysmon
从微软官方下载 Sysmon64.exe，放到本目录：
```
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
```

#### 2. 一键部署本机
```powershell
# 以管理员身份运行 PowerShell
cd detection-engineering\logging-baseline
.\Deploy-LoggingBaseline.ps1
```

#### 3. 批量部署多台主机
```powershell
# 需要目标主机开启 PSRemoting（WinRM）
.\Deploy-LoggingBaseline.ps1 -ComputerName "PC001","PC002","SERVER01"

# 从文件读取主机列表
$hosts = Get-Content .\hosts.txt
.\Deploy-LoggingBaseline.ps1 -ComputerName $hosts
```

#### 4. 验证部署结果
```powershell
# 运行健康检查
.\Check-LogHealth.ps1

# 健康分数 >= 90 表示日志基线已完整部署
```

---

### sysmonconfig.xml 覆盖的事件 ID

| 事件 ID | 名称 | ATT&CK 覆盖 |
|---------|------|------------|
| 1 | 进程创建 | T1059, T1053, T1203 |
| 2 | 文件时间戳修改 | T1070.006 |
| 3 | 网络连接 | T1071, T1043 |
| 5 | 进程终止 | T1562.001（安全工具被杀） |
| 6 | 驱动加载 | T1014, T1068 |
| 7 | 镜像加载（DLL） | T1574, T1055 |
| 8 | 远程线程创建 | T1055（进程注入） |
| 9 | 原始磁盘读取 | T1003.002 |
| **10** | **进程访问** | **T1003.001（LSASS凭证转储）** |
| 11 | 文件创建 | T1105, T1486（勒索软件） |
| 12/13 | 注册表操作 | T1547.001, T1112 |
| 15 | 文件流哈希（ADS） | T1564.004 |
| 17/18 | 命名管道 | T1021.002, T1559 |
| 22 | DNS 查询 | T1071.004 |
| 23 | 文件删除 | T1070.004 |
| 25 | 进程篡改 | T1055.012（进程镂空） |

---

### PowerShell 审计启用后的关键事件

| 事件 ID | 来源 | 内容 | 检测价值 |
|---------|------|------|----------|
| **4104** | PS/Operational | ScriptBlock 内容（**含解码后的明文**） | 最高——可见所有 PS 执行内容 |
| 4103 | PS/Operational | 模块调用管道详情 | 高 |
| 4688 | Security | 进程创建（含命令行） | 高——不依赖 Sysmon 的备份 |

---

### 部署后在 SIEM 中验证

**Splunk 验证查询：**
```spl
# 确认 Sysmon 事件到达
index=windows sourcetype=WinEventLog:Sysmon
| stats count by EventCode host
| sort - count

# 确认 PS ScriptBlock 日志到达
index=windows EventCode=4104
| stats count by host
| sort - count
```

**Sentinel KQL 验证：**
```kql
// 确认 Sysmon 数据
SecurityEvent
| where EventID == 1
| summarize count() by Computer
| order by count_ desc

// 确认 PS ScriptBlock
SecurityEvent  
| where EventID == 4104
| summarize count() by Computer
```

---

### 设置定时健康检查（计划任务）

```powershell
# 每小时运行一次健康检查，写入 Windows 事件日志
$action  = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-NonInteractive -File `"$PWD\Check-LogHealth.ps1`" -OutputFormat JSON"
$trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Hours 1) -Once -At (Get-Date)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

Register-ScheduledTask -TaskName "LogSourceHealthCheck" `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description "每小时检查安全日志源健康状态，发现盲点"
```

---

### 完成第一步后的检查清单

```
□ Sysmon 服务在所有 Windows 主机上运行（Get-Service Sysmon64）
□ PowerShell ScriptBlock 日志已启用（事件 4104 出现在日志中）
□ 进程命令行审计已启用（事件 4688 包含 CommandLine 字段）
□ SIEM 正在收集 Sysmon 和 Security 事件
□ Check-LogHealth.ps1 运行返回健康分数 >= 90
□ 计划任务已配置每小时监控日志源健康
```

完成以上所有项目后，继续执行 **第二步：部署5条关键检测规则**。
