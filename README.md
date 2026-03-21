# Detection Engineering Repository

A collection of SIEM detection rules built with "Detection-as-Code" methodology. Rules are written in Sigma format and compiled to multiple SIEM platforms.

## Overview

This repository contains production-ready detection rules for:
- **Splunk** (SPL queries)
- **Microsoft Sentinel** (KQL queries)
- **Elastic Security** (EQL queries - coming soon)

All rules are mapped to MITRE ATT&CK techniques and include comprehensive metadata for detection tuning.

---

## Quick Start

### Prerequisites

```bash
# Install Git
# Windows: https://git-scm.com/download/win
# macOS: brew install git
# Linux: sudo apt install git

# Clone the repository
git clone <repository-url>
cd detection-engineering
```

### Project Structure

```
detection-engineering/
├── .github/
│   └── workflows/
│       └── ci-cd.yml           # GitHub Actions CI/CD pipeline
├── sigma-rules/               # Source Sigma YAML rules
│   ├── suspicious_powershell_encoded.yml
│   ├── lsass_memory_dump.yml
│   └── ...
├── compiled/
│   ├── splunk/                # Compiled Splunk SPL queries
│   │   ├── rules.conf
│   │   └── rules-expanded.conf
│   └── sentinel/              # Compiled Sentinel KQL queries
│       ├── rules.kql
│       └── rules-expanded.kql
├── logging-baseline/          # Log collection baseline
│   ├── sysmonconfig.xml
│   ├── Check-LogHealth-EN.ps1
│   └── ...
├── scripts/                   # Utility scripts
│   ├── compile-rules.py       # Compile Sigma to SIEM formats
│   └── validate-rules.py      # Validate Sigma rules
├── docs/                      # Documentation
│   ├── ATTACK-GAP-ANALYSIS.md
│   ├── RULES-EXPANSION-SUMMARY.md
│   └── DEPLOYMENT-GUIDE.md
├── .gitignore
├── .sigmarc                   # Sigma CLI configuration
└── README.md
```

---

## CI/CD Pipeline

This repository uses GitHub Actions for automated validation and compilation:

### Workflow Triggers

- **Pull Request**: Validates all rules and compiles them
- **Push to main**: Validates, compiles, and creates artifacts for deployment
- **Manual**: Triggered workflow for custom validation

### Pipeline Stages

1. **Linting** - Validate Sigma rule syntax and required fields
2. **ATT&CK Validation** - Ensure all rules map to MITRE ATT&CK techniques
3. **Compilation** - Compile to Splunk SPL and Sentinel KQL
4. **Artifact Upload** - Store compiled rules as downloadable artifacts

---

## Working with Detection Rules

### Adding a New Rule

1. Create a new Sigma rule file in `sigma-rules/`:
   ```bash
   # Example: sigma-rules/new_detection.yml
   ```

2. Follow the Sigma rule template (see `docs/RULE-TEMPLATE.md`)

3. Required fields:
   - `title` - Rule name
   - `id` - Unique UUID
   - `status` - draft | testing | stable | deprecated
   - `level` - low | medium | high | critical
   - `description` - Detailed threat description
   - `tags` - MITRE ATT&CK tactics and techniques
   - `falsepositives` - Known false positive scenarios
   - `logsource` - Data source configuration
   - `detection` - Detection logic

4. Create a pull request - CI will validate automatically

### Validating Rules Locally

```bash
# Install Sigma CLI
pip install sigma-cli pySigma-backend-splunk pySigma-backend-microsoft365defender

# Validate a single rule
sigma check sigma-rules/your-rule.yml

# Validate all rules
find sigma-rules/ -name "*.yml" -exec sigma check {} \;
```

### Compiling Rules Locally

```bash
# Compile to Splunk
sigma convert -t splunk -p sysmon sigma-rules/*.yml > compiled/splunk/rules.conf

# Compile to Sentinel KQL
sigma convert -t microsoft365defender sigma-rules/*.yml > compiled/sentinel/rules.kql
```

---

## Rule Metadata Standards

### MITRE ATT&CK Mapping

Every rule MUST include at least one MITRE ATT&CK technique:

```yaml
tags:
  - attack.execution
  - attack.t1059.001
```

### False Positives Documentation

Rules MUST document known false positive scenarios:

```yaml
falsepositives:
  - Legitimate IT administration tools
  - Automated deployment scripts
  - Security scanners
```

### Severity Levels

| Level | Response Time | Examples |
|-------|---------------|----------|
| **critical** | <15 minutes | LSASS dump, NTDS extraction, Event logging disabled |
| **high** | <1 hour | Credential theft, Lateral movement, Defender disabled |
| **medium** | <4 hours | Suspicious processes, Hidden files, Reconnaissance |
| **low** | <24 hours | Informational events, Anomalous behavior |

---

## Deployment

### Deploying to Splunk

See `docs/DEPLOYMENT-GUIDE.md` for detailed deployment instructions.

Quick summary:
```bash
# Download compiled rules from GitHub Actions artifacts
# Upload to Splunk via REST API
curl -k -u admin:password \
  https://splunk-server:8089/servicesNS/admin/search/saved/searches \
  -d @compiled/splunk/rules.conf
```

### Deploying to Microsoft Sentinel

```bash
# Use Azure CLI
az sentinel alert-rule create \
  --resource-group your-rg \
  --workspace-name sentinel-ws \
  --alert-rule @compiled/sentinel/rules.kql
```

---

## Contributing

### Rule Submission Process

1. **Fork** the repository
2. **Create a feature branch**: `git checkout -b feature/new-rule`
3. **Write** your Sigma rule following the template
4. **Validate** locally: `sigma check sigma-rules/your-rule.yml`
5. **Test** against sample log data if available
6. **Submit a pull request** with:
   - Rule description
   - MITRE ATT&CK mapping
   - Known false positives
   - Testing methodology

### Code Review Checklist

- [ ] Rule follows Sigma format specification
- [ ] Includes complete metadata (title, id, status, level, author, date)
- [ ] Maps to at least one MITRE ATT&CK technique
- [ ] Documents false positive scenarios
- [ ] Includes allow lists for common benign activity
- [ ] Tested against real or sample log data
- [ ] Compiled successfully to target SIEM formats

---

## Metrics and Coverage

Current Status:
- **Total Rules**: 17
- **MITRE ATT&CK Coverage**: ~12%
- **Tactics Covered**: 6/12
- **Critical Rules**: 6
- **High Rules**: 7
- **Medium Rules**: 4

See `docs/RULES-EXPANSION-SUMMARY.md` for detailed coverage analysis.

---

## Maintenance

### Regular Tasks

- **Weekly**: Review and tune rules with high false positive rates
- **Monthly**: Update ATT&CK mappings based on new techniques
- **Quarterly**: Run purple team tests to validate detection effectiveness
- **Annually**: Audit and deprecate underperforming rules

### Rule Lifecycle

1. **Draft** - Initial development and testing
2. **Testing** - Deployed to non-production SIEM for validation
3. **Stable** - Production-ready with validated false positive rates
4. **Deprecated** - Removed or replaced by better detection

---

## Documentation

- [ATT&CK Gap Analysis](docs/ATTACK-GAP-ANALYSIS.md) - Coverage gaps and prioritization
- [Rule Expansion Summary](docs/RULES-EXPANSION-SUMMARY.md) - Expansion history and metrics
- [Deployment Guide](docs/DEPLOYMENT-GUIDE.md) - SIEM-specific deployment instructions
- [Rule Template](docs/RULE-TEMPLATE.md) - Sigma rule template and best practices

---

## License

[Your License Here]

## Contact

- **Detection Engineering Team**: security@yourcompany.com
- **Slack Channel**: #detection-engineering

---

**Version**: 1.0.0
**Last Updated**: 2026-03-22
