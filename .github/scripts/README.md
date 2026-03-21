# CI/CD Scripts

This directory contains Python scripts used in the GitHub Actions CI/CD pipeline for validating and analyzing Sigma rules.

## Scripts

### Validation Scripts

#### `check-required-fields.py`
Validates that all Sigma rules have required fields:
- title, id, status, level, description, tags, falsepositives, logsource, detection
- UUID format validation for `id` field
- Valid status and level values
- ATT&CK technique tags in `tags`

**Usage**: `python check-required-fields.py`

#### `check-attack-mappings.py`
Validates MITRE ATT&CK mappings:
- Every rule has at least one ATT&CK technique tag
- Technique format is correct (`attack.tXXXX` or `attack.tXXXX.YYY`)
- Tactics are correctly formatted (`attack.tactic_name`)
- Generates coverage report

**Usage**: `python check-attack-mappings.py`

#### `check-duplicates.py`
Checks for duplicate rule IDs:
- Ensures each rule has a unique identifier
- Prevents conflicts when compiling to SIEM formats

**Usage**: `python check-duplicates.py`

#### `check-yaml-formatting.py`
Validates YAML file formatting:
- Valid YAML syntax
- Proper indentation
- No trailing whitespace
- Unix line endings (LF) preferred

**Usage**: `python check-yaml-formatting.py`

### Reporting Scripts

#### `generate-coverage-report.py`
Generates comprehensive ATT&CK coverage report:
- Total rules and coverage percentage
- Rules by severity and status
- Top covered techniques
- Covered tactics
- Complete rule list

**Usage**: `python generate-coverage-report.py`

**Output**: Markdown-formatted coverage report

## Local Testing

You can run these scripts locally before pushing changes:

```bash
# Install dependencies
pip install pyyaml

# Run all checks
cd .github/scripts
python check-required-fields.py
python check-attack-mappings.py
python check-duplicates.py
python check-yaml-formatting.py

# Generate coverage report
python generate-coverage-report.py > ../../docs/COVERAGE-REPORT.md
```

## Adding New Scripts

When adding a new validation script:

1. Make it executable (`chmod +x script-name.py` on Unix)
2. Add usage documentation to this README
3. Update `.github/workflows/ci-cd.yml` to call the new script
4. Test locally before committing

## Error Handling

All scripts follow these conventions:
- Exit code 0: Success
- Exit code 1: Validation failed with errors
- Print errors to stderr
- Use consistent formatting for error messages
- Provide helpful error messages for debugging

## Dependencies

All scripts require:
- Python 3.7+
- PyYAML (`pip install pyyaml`)

These dependencies are automatically installed in the CI/CD pipeline.
