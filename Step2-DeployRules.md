# Step 2: Deploy Critical Detection Rules

## Overview
Deploy 5 critical detection rules to start capturing actual threat signals based on the logging baseline deployed in Step 1.

## Prerequisites
- [x] Sysmon installed and configured (16 event types)
- [x] PowerShell ScriptBlock logging enabled
- [x] Log sources collecting data (Health Score: 85/100)

## Detection Rules to Deploy

### Rule 1: Suspicious PowerShell Encoded Commands
- **ATT&CK**: T1059.001 (PowerShell), T1027.010 (Command Obfuscation)
- **Detection Logic**: PowerShell execution with -enc/-EncodedCommand flags, launched from suspicious parent processes
- **Data Source**: Sysmon Event 1 + PowerShell Event 4104
- **Priority**: CRITICAL - High-confidence attack indicator
- **False Positives**: SCCM, Intune, some IT automation tools

### Rule 2: LSASS Memory Dumping Attempt
- **ATT&ACK**: T1003.001 (OS Credential Dumping: LSASS Memory)
- **Detection Logic**: Non-system process accessing lsass.exe with high privilege access masks (0x1010, 0x1410, 0x1fffff)
- **Data Source**: Sysmon Event 10 (ProcessAccess)
- **Priority**: CRITICAL - Direct credential theft attempt
- **False Positives**: EDR/AV agents, legitimate credential providers (rare)

### Rule 3: Process Hollowing/Injection
- **ATT&CK**: T1055.012 (Process Hollowing), T1055 (Process Injection)
- **Detection Logic**: Remote thread creation (CreateRemoteThread) targeting non-system processes
- **Data Source**: Sysmon Event 8
- **Priority**: HIGH - Sophisticated evasion technique
- **False Positives**: Debuggers, certain legitimate inter-process communication

### Rule 4: Registry Persistence via Run Keys
- **ATT&CK**: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys)
- **Detection Logic**: Modifications to Run/RunOnce registry keys with executables from non-standard locations
- **Data Source**: Sysmon Event 12/13/14 (RegistryEvent)
- **Priority**: MEDIUM - Common persistence mechanism
- **False Positives**: Software installation, legitimate admin tools

### Rule 5: Suspicious Script Network Connection
- **ATT&ACK**: T1071 (Application Layer Protocol: C2 Communications)
- **Detection Logic**: Script interpreters (powershell.exe, wscript.exe, etc.) making outbound network connections
- **Data Source**: Sysmon Event 3 (NetworkConnect)
- **Priority**: HIGH - Strong C2 indicator
- **False Positives**: Legitimate script-based software updates (rare)

## Implementation Steps

### Step 2.1: Create Detection Rules Directory
```
detection-engineering/
├── sigma-rules/
│   ├── suspicious_powershell_encoded.yml
│   ├── lsass_memory_dump.yml
│   ├── process_hollowing.yml
│   ├── registry_persistence.yml
│   └── script_network_connection.yml
```

### Step 2.2: Write Sigma Rules
Create 5 production-ready Sigma rules with:
- Complete metadata (title, id, status, level, author, date, tags)
- ATT&CK mapping (tactics + techniques)
- Detection logic optimized for Sysmon data
- False positive documentation
- Required log sources specified

### Step 2.3: Compile to Target SIEM
Convert Sigma rules to query languages:
- **Splunk SPL** - For Splunk environments
- **Microsoft Sentinel KQL** - For Azure Sentinel/M365 Defender
- **Elastic EQL** - For Elastic Security

### Step 2.4: Validate Against Local Logs
Test each rule against actual log data:
```powershell
# Validate rule produces matches
# Validate rule doesn't flood with false positives
# Document actual behavior in this environment
```

### Step 2.5: Deploy to SIEM (Optional)
If you have a SIEM instance, import the compiled rules and enable alerts.

## Expected Outcomes

### Detection Coverage After Step 2
| ATT&CK Technique | Data Source | Rule Status |
|-----------------|-------------|------------|
| T1059.001 (PowerShell) | Sysmon 1 + PS 4104 | ✅ Rule 1 |
| T1003.001 (LSASS Dump) | Sysmon 10 | ✅ Rule 2 |
| T1055.012 (Process Hollowing) | Sysmon 8 | ✅ Rule 3 |
| T1547.001 (Run Keys) | Sysmon 12/13/14 | ✅ Rule 4 |
| T1071 (Script C2) | Sysmon 3 | ✅ Rule 5 |

### MITRE ATT&CK Coverage Estimate
- Before Step 2: ~0% (log collection only, no detection logic)
- After Step 2: ~5% of critical techniques covered
- Target by Step 3: ~15% (with additional rules)

## Success Criteria
- [ ] 5 Sigma rules created with complete metadata
- [ ] Rules compiled to at least one SIEM query language
- [ ] Each rule validated against local log data
- [ ] False positive expectations documented
- [ ] Rules stored in Git (if available)

## Next Steps (After Step 2)
1. Step 3: Set up Git repository + CI/CD pipeline
2. Add more rules based on threat intelligence
3. Purple team validation of detection effectiveness
4. MITRE ATT&CK coverage assessment
