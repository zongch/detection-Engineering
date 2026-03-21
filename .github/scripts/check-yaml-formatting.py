#!/usr/bin/env python3
"""
Validate YAML formatting in Sigma rules.

Checks:
- Valid YAML syntax
- Proper indentation
- No trailing whitespace
- Unix line endings (LF) preferred
"""

import sys
import yaml
from pathlib import Path


def validate_yaml_formatting(rule_file):
    """Validate YAML file formatting."""
    errors = []
    warnings = []

    try:
        # Read file as text to check line endings and whitespace
        with open(rule_file, 'r', encoding='utf-8') as f:
            content = f.read()
            lines = content.splitlines(keepends=True)

        # Check for Windows line endings (CRLF)
        if '\r\n' in content:
            warnings.append("Contains Windows line endings (CRLF). Prefer Unix line endings (LF).")

        # Check for trailing whitespace
        for i, line in enumerate(lines, 1):
            if line.rstrip('\r\n') != line.rstrip():
                errors.append(f"Line {i}: Trailing whitespace")

        # Parse YAML to check syntax
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                yaml.safe_load(f)
        except yaml.YAMLError as e:
            errors.append(f"Invalid YAML syntax: {e}")

    except Exception as e:
        errors.append(f"Failed to read file: {e}")

    return errors, warnings


def main():
    """Main validation function."""
    sigma_rules_dir = Path('sigma-rules')
    rule_files = list(sigma_rules_dir.glob('*.yml'))

    if not rule_files:
        print(f"No Sigma rules found in {sigma_rules_dir}")
        sys.exit(1)

    print(f"Validating YAML formatting in {len(rule_files)} rules...")

    total_errors = 0
    total_warnings = 0

    for rule_file in sorted(rule_files):
        errors, warnings = validate_yaml_formatting(rule_file)

        if errors or warnings:
            print(f"\n{rule_file.name}:")
            for error in errors:
                print(f"  ❌ ERROR: {error}")
                total_errors += 1
            for warning in warnings:
                print(f"  ⚠️  WARNING: {warning}")
                total_warnings += 1
        else:
            print(f"  ✓ {rule_file.name}")

    print(f"\n{'='*60}")
    print(f"Formatting check complete:")
    print(f"  Files checked: {len(rule_files)}")
    print(f"  Errors: {total_errors}")
    print(f"  Warnings: {total_warnings}")

    if total_errors > 0:
        print(f"\n❌ Formatting check failed with {total_errors} error(s)")
        sys.exit(1)
    else:
        print(f"\n✓ All YAML files properly formatted")
        sys.exit(0)


if __name__ == '__main__':
    main()
