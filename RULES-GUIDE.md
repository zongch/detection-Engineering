# Detection Rules Deployment Guide

## Overview
This guide covers the 5 critical detection rules deployed in Step 2 of the threat detection system implementation.

**Deployment Date**: 2026-03-21
**Total Rules**: 5
**Coverage**: 5 MITRE ATT&CK techniques
**Log Sources Required**: Sysmon (16 event types), PowerShell ScriptBlock Logging

---

## Directory Structure

```
detection-engineering/
├── sigma-rules/                    # Original Sigma rules (vendor-agnostic)
│   ├── suspicious_powershell_encoded.yml
│   ├── lsass_memory_dump.yml
│   ├── process_hollowing.yml
│   ├── registry_persistence.yml
│   └── script_network_connection.yml
├── compiled/
│   ├── splunk/
│   │   └── rules.conf             # Splunk SPL queries
│   └── sentinel/
│       └── rules.kql               # Microsoft Sentinel KQL queries
├── logging-baseline/
│   ├── sysmonconfig.xml
│   └── Check-LogHealth-EN.ps1
└── Validate-Rules.ps1              # Validation script
```

---

## Rule Summary

### Rule 1: Suspicious PowerShell Encoded Command
| Attribute | Value |
|-----------|-------|
| **Sigma ID** | a1b2c3d4-e5f6-7890-abcd-ef1234567890 |
| **Level** | Critical |
| **ATT&CK** | T1059.001, T1027.010 |
| **Data Source** | Sysmon Event 1 + PS Event 4104 |
| **Description** | Detects PowerShell with -enc/-EncodedCommand flags from suspicious parent processes |
| **False Positives** | SCCM, Intune, IT automation tools |

### Rule 2: LSASS Memory Dumping Attempt
| Attribute | Value |
|-----------|-------|
| **Sigma ID** | b3c4d5e6-f7g8-9012-cdef-1234567890ab |
| **Level** | Critical |
| **ATT&CK** | T1003.001, T1003.003 |
| **Data Source** | Sysmon Event 10 (ProcessAccess) |
| **Description** | Non-system processes accessing lsass.exe with high privilege masks |
| **False Positives** | EDR/AV agents, credential providers |

### Rule 3: Process Hollowing / Injection
| Attribute | Value |
|-----------|-------|
| **Sigma ID** | d4e5f6g7-h8i9-1234-efab-345678901cde |
| **Level** | High |
| **ATT&CK** | T1055.012, T1055 |
| **Data Source** | Sysmon Event 8 (CreateRemoteThread) |
| **Description** | Remote thread creation in non-system processes |
| **False Positives** | Debuggers, some IPC applications |

### Rule 4: Registry Persistence via Run Keys
| Attribute | Value |
|-----------|-------|
| **Sigma ID** | f5g6h7i8-j9k0-3456-bcde-567890123ef0 |
| **Level** | Medium |
| **ATT&CK** | T1547.001 |
| **Data Source** | Sysmon Event 12/13/14 (Registry) |
| **Description** | Modifications to Run/RunOnce/Winlogon keys with suspicious executables |
| **False Positives** | Software installation, admin tools |

### Rule 5: Suspicious Script Network Connection
| Attribute | Value |
|-----------|-------|
| **Sigma ID** | g7h8i9j0-k1l2-5678-defa-789012345012 |
| **Level** | High |
| **ATT&CK** | T1071, T1059.001, T1059.005 |
| **Data Source** | Sysmon Event 3 (NetworkConnect) |
| **Description** | Script interpreters making outbound network connections |
| **False Positives** | Rare: script-based software updates |

---

## Deployment Options

### Option A: Local Windows Event Viewer (Immediate Testing)

```powershell
# Run validation script to test against local logs
.\Validate-Rules.ps1
```

This validates rules work against your current event logs without requiring a SIEM.

### Option B: Splunk Deployment

**Prerequisites**:
- Splunk Enterprise installed with Windows Add-on for Splunk
- Sysmon data ingested via Splunk Universal Forwarder

**Steps**:
1. Copy `compiled/splunk/rules.conf` to Splunk server
2. Create saved searches in Splunk Web UI:
   - Navigate to Search & Reporting → Searches, reports, and alerts
   - Create new saved search for each rule
   - Paste the corresponding SPL query
   - Set alert conditions (e.g., trigger on >0 results)
3. Configure alert actions (email, webhook, etc.)

**Recommended Alert Settings**:
- **Critical rules**: Real-time alerts, email immediately
- **High rules**: Every 5 minutes, batch email
- **Medium rules**: Every 15 minutes, daily summary

### Option C: Microsoft Sentinel Deployment

**Prerequisites**:
- Microsoft Sentinel enabled on Azure subscription
- Microsoft Defender for Endpoint data connector configured
- Sysmon data ingested via Log Analytics agent

**Steps**:
1. Copy `compiled/sentinel/rules.kql` to Sentinel
2. Create custom analytics rules:
   - Navigate to Configuration → Analytics
   - Create new scheduled rule
   - Paste the KQL query
   - Set alert rule details (name, description, tactics)
   - Configure incident creation
3. Set automated response actions (SOAR playbooks)

**Recommended Schedule**:
- **Critical rules**: Run every 5 minutes, 10 lookback
- **High rules**: Run every 15 minutes, 1 hour lookback
- **Medium rules**: Run every hour, 24 hour lookback

### Option D: Elastic Security Deployment

**Prerequisites**:
- Elastic Stack with Security app
- Elastic Agent or Winlogbeat configured
- Sysmon data ingested

**Steps**:
1. Install `sigma-cli` with Elastic backend
2. Compile Sigma rules:
   ```bash
   sigma convert -t elasticsearch -p sysmon sigma-rules/*.yml
   ```
3. Import compiled rules into Elastic Security → Rules → New rule
4. Configure detection alerts

---

## Validation Checklist

Before deploying to production:

- [x] All 5 Sigma rules created with complete metadata
- [x] Rules compiled to Splunk SPL
- [x] Rules compiled to Sentinel KQL
- [ ] Validation script run successfully (`Validate-Rules.ps1`)
- [ ] False positive expectations documented for each rule
- [ ] Allowlist updated with environment-specific benign sources
- [ ] Alert recipients configured
- [ ] Incident response playbooks documented
- [ ] Rules committed to Git repository (if available)
- [ ] SOC team trained on new alerts

---

## Tuning Guidelines

### Reducing False Positives

1. **Review Alert History**
   ```powershell
   # Run rules and examine results
   .\Validate-Rules.ps1
   ```

2. **Update Allowlists**
   - Edit Sigma rule `allowlist:` section
   - Add specific parent processes, file paths, or domains
   - Re-compile to target SIEM

3. **Add Context Filters**
   - Include user context (e.g., exclude service accounts)
   - Include time-based filters (e.g., exclude maintenance windows)
   - Include location-based filters (e.g., exclude trusted subnets)

### Increasing Sensitivity

1. **Remove Allowlist Entries**
   - Remove overly broad exclusions
   - Keep specific, verified exclusions only

2. **Add Correlation Rules**
   - Combine multiple weak signals for higher confidence
   - Example: PowerShell encoded + network connection = critical

3. **Reduce Time Thresholds**
   - Decrease lookback windows for faster detection
   - Balance between detection speed and false positive rate

---

## Monitoring & Maintenance

### Monthly Review Tasks

1. **Alert Volume Analysis**
   - Track daily/weekly alert count per rule
   - Investigate rules with >20 alerts/day (likely need tuning)

2. **True Positive Rate Calculation**
   - Document confirmed incidents from alerts
   - Calculate TP rate: TP / (TP + FP)
   - Target: TP rate >70% for production rules

3. **False Positive Updates**
   - Review FP alerts with SOC team
   - Update allowlists quarterly

4. **Rule Effectiveness**
   - Compare MITRE ATT&CK coverage before/after
   - Track which rules actually detected threats
   - Retire rules with 0 value after 3 months

### Quarterly Tasks

1. **Purple Team Validation**
   - Run Atomic Red Team tests for each covered technique
   - Verify rules trigger as expected
   - Document gaps and improvements

2. **ATT&CK Coverage Assessment**
   - Re-evaluate coverage gaps
   - Prioritize new rules based on threat intelligence

3. **Rule Archive Review**
   - Review deprecated or unused rules
   - Archive or remove stale detection logic

---

## Next Steps (Step 3)

After validating these 5 rules, proceed to Step 3:

1. **Set up Git Repository**
   - Initialize Git repo in `detection-engineering/`
   - Commit all Sigma rules and compiled queries
   - Set up GitHub/Azure DevOps repository

2. **Implement CI/CD Pipeline**
   - GitHub Actions or Azure DevOps Pipelines
   - Automated Sigma validation
   - Automated compilation to SIEM queries
   - Automated testing against sample log data

3. **Expand Rule Coverage**
   - Add 15-20 more rules based on MITRE ATT&CK gaps
   - Focus on techniques used by threat actors in your industry
   - Target 15% ATT&CK coverage by end of Step 3

---

## Support & Troubleshooting

### Common Issues

**Issue: No events found when running validation**
- **Cause**: System idle, no recent activity
- **Solution**: Generate test events or wait for normal activity

**Issue: Too many false positives**
- **Cause**: Allowlist too generic or missing
- **Solution**: Review specific FPs, add to rule allowlist

**Issue: Splunk query syntax errors**
- **Cause**: Splunk version incompatible with syntax
- **Solution**: Review Splunk docs, adjust regex patterns

**Issue: Sentinel KQL errors**
- **Cause**: Schema mismatch or column name changes
- **Solution**: Check DeviceProcessEvents schema, adjust field names

### Getting Help

- Review Sigma specification: https://github.com/SigmaHQ/sigma-specification
- MITRE ATT&CK techniques: https://attack.mitre.org/
- Sysmon documentation: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

---

## Appendix: Rule Statistics

| Metric | Value |
|--------|-------|
| Total Rules | 5 |
| Critical Severity | 2 |
| High Severity | 2 |
| Medium Severity | 1 |
| ATT&CK Tactics Covered | 3 |
| ATT&CK Techniques Covered | 5 |
| Avg False Positive Rate (Expected) | 10-15% |
| Avg True Positive Rate (Expected) | 85-90% |
| Maintenance Cadence | Quarterly |

---

**Document Version**: 1.0
**Last Updated**: 2026-03-21
**Author**: Detection Engineering Team
