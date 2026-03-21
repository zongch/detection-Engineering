# MITRE ATT&CK Coverage Gap Analysis

## Current Coverage (After Step 2)

### Already Covered (5 techniques)

| ID | Technique | Tactic | Rule | Priority |
|----|-----------|--------|------|----------|
| T1059.001 | PowerShell | Execution | suspicious_powershell_encoded.yml | ✅ Critical |
| T1003.001 | LSASS Memory | Credential Access | lsass_memory_dump.yml | ✅ Critical |
| T1055.012 | Process Hollowing | Priv Esc/Def Evasion | process_hollowing.yml | ✅ High |
| T1547.001 | Registry Run Keys | Persistence | registry_persistence.yml | ✅ Medium |
| T1071 | App Layer Protocol C2 | C2 | script_network_connection.yml | ✅ High |

**Total Covered**: 5 techniques
**Coverage**: ~5% of critical techniques

---

## Priority Gaps to Address

### P1: Critical - High Impact + High Prevalence

| ID | Technique | Tactic | Rationale | Difficulty |
|----|-----------|--------|-----------|------------|
| **T1562.001** | Disable Security Tools | Defense Evasion | Used by 80%+ ransomware | Medium |
| **T1562.004** | Disable Windows Event Logging | Defense Evasion | Logs = evidence, attackers always disable | Low |
| **T1003.002** | SAM Database Dump | Credential Access | Alternative to LSASS, easier to detect | Low |
| **T1018** | Remote System Discovery | Discovery | Attackers need to know what to target | Low |
| **T1087.002** | Domain Account Discovery | Discovery | Lateral movement prep | Low |

### P2: High - Industry-Specific Threats

| ID | Technique | Tactic | Rationale | Difficulty |
|----|-----------|--------|-----------|------------|
| **T1021.002** | SMB/Windows Admin Shares | Lateral Movement | PsExec, WMI execution | Medium |
| **T1021.006** | Windows Remote Management | Lateral Movement | WinRM lateral movement | Medium |
| **T1053.005** | Scheduled Task | Persistence | Common in APT campaigns | Low |
| **T1569.002** | Service Execution | Execution | Windows Service abuse | Low |
| **T1548.002** | Bypass UAC | Privilege Escalation | Elevation without admin password | Medium |

### P3: Medium - Advanced Techniques

| ID | Technique | Tactic | Rationale | Difficulty |
|----|-----------|--------|-----------|------------|
| **T1486** | Data Encrypted for Impact | Impact | Ransomware payload delivery | Medium |
| **T1105** | Ingress Tool Transfer | Command and Control | Downloading malware | Low |
| **T1564.001** | Hidden Files and Directories | Defense Evasion | Malware stealth | Low |
| **T1136.001** | Local Account Creation | Persistence | Backdoor creation | Low |
| **T1552.004** | Private Keys | Credential Access | SSH/HTTPS credential theft | Medium |

---

## Proposed Rule Expansion (Target: +20 rules)

### Batch 1: Defense Evasion (5 rules) - PRIORITY
1. **T1562.001** - Disable Windows Defender
2. **T1562.004** - Disable/Impair Windows Event Logs
3. **T1564.001** - Hidden Files Creation (attrib +h +s)
4. **T1014** - Rootkit (unsigned driver loading)
5. **T1574.002** - DLL Side-Loading

### Batch 2: Credential Access (4 rules) - HIGH
6. **T1003.002** - SAM Database Dumping
7. **T1003.003** - NTDS.dit Extraction
8. **T1552.004** - Private Key Theft
9. **T1003.005** - Cached Domain Credentials

### Batch 3: Discovery/Recon (4 rules) - HIGH
10. **T1018** - Remote System Discovery (ping/sweep)
11. **T1087.002** - Domain Account Discovery (net user/domain)
12. **T1135** - Network Share Discovery (net view)
13. **T1069.002** - Domain Group Discovery (net group)

### Batch 4: Lateral Movement (3 rules) - HIGH
14. **T1021.002** - SMB/Windows Admin Shares
15. **T1021.006** - Windows Remote Management (WinRM)
16. **T1569.002** - Service Execution

### Batch 5: Persistence/Execution (4 rules) - MEDIUM
17. **T1053.005** - Scheduled Task Creation
18. **T1548.002** - Bypass UAC
19. **T1546.015** - Component Object Model Hijacking
20. **T1105** - Ingress Tool Transfer

---

## Expected Coverage After Expansion

| Metric | Current | After Expansion | Improvement |
|--------|---------|-----------------|-------------|
| Total Rules | 5 | 25 | +20 |
| Techniques Covered | 5 | 25 | +20 |
| ATT&CK Coverage | 5% | 15-20% | +10-15% |
| Tactics Covered | 3 | 7 | +4 |

### Tactic Coverage After Expansion

| Tactic | Before | After | Coverage |
|---------|--------|-------|----------|
| Execution | 1 | 4 | 4 techniques |
| Persistence | 1 | 5 | 5 techniques |
| Privilege Escalation | 0 | 2 | 2 techniques |
| Defense Evasion | 1 | 6 | 6 techniques |
| Credential Access | 1 | 5 | 5 techniques |
| Discovery | 0 | 4 | 4 techniques |
| Lateral Movement | 0 | 3 | 3 techniques |
| Command and Control | 1 | 2 | 2 techniques |
| Impact | 0 | 0 | 0 techniques |

---

## Data Source Requirements

All proposed rules are compatible with current logging baseline:
- ✅ Sysmon Events: 1, 3, 5, 6, 7, 8, 10, 11, 12, 13, 14, 22, 23
- ✅ PowerShell Events: 4104 (ScriptBlock)
- ✅ Security Events: 4688, 4624, 4625

No additional log sources required.

---

## Implementation Priority

### Phase 1 (Now): High-Impact Rules (10 rules)
- Defense Evasion: T1562.001, T1562.004, T1564.001
- Credential Access: T1003.002, T1003.003, T1552.004
- Discovery: T1018, T1087.002

### Phase 2 (Next): Movement & Persistence (7 rules)
- Lateral Movement: T1021.002, T1021.006
- Persistence: T1053.005, T1548.002, T1546.015
- Execution: T1569.002, T1105

### Phase 3 (Later): Advanced Techniques (3 rules)
- Rootkits: T1014
- DLL Side-Loading: T1574.002
- Other: As needed based on threat intel

---

## Success Criteria

By end of Option C (Rule Expansion):

- [ ] 20+ new Sigma rules created
- [ ] Rules compiled to Splunk SPL
- [ ] Rules compiled to Sentinel KQL
- [ ] All rules validated with Validate-Rules.ps1
- [ ] MITRE ATT&CK coverage increased to 15%+
- [ ] Coverage report generated
- [ ] Deployment documentation updated

---

**Document Version**: 1.0
**Last Updated**: 2026-03-21
**Author**: Detection Engineering Team
