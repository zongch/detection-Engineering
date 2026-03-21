#!/usr/bin/env python3
"""
Check required fields in Sigma rules.

Required fields:
- title
- id (UUID format)
- status
- level
- description
- tags (at least one ATT&CK technique)
- falsepositives
- logsource
- detection
"""

import sys
import yaml
import re
from pathlib import Path

# Required fields for Sigma rules
REQUIRED_FIELDS = [
    'title',
    'id',
    'status',
    'level',
    'description',
    'tags',
    'falsepositives',
    'logsource',
    'detection'
]

# Valid status values
VALID_STATUSES = ['draft', 'testing', 'stable', 'deprecated']

# Valid level values
VALID_LEVELS = ['low', 'medium', 'high', 'critical']

# UUID pattern
UUID_PATTERN = re.compile(
    r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    re.IGNORECASE
)


def validate_uuid(uuid_str):
    """Validate UUID format."""
    return bool(UUID_PATTERN.match(uuid_str))


def validate_tags(tags):
    """Validate tags contain at least one ATT&CK technique."""
    if not tags or not isinstance(tags, list):
        return False, "Tags must be a non-empty list"

    attack_techniques = [t for t in tags if t.startswith('attack.t')]
    if not attack_techniques:
        return False, "No ATT&CK technique tags found (must contain at least one 'attack.tXXXX')"

    return True, ""


def validate_rule(rule_file):
    """Validate a single Sigma rule file."""
    errors = []
    warnings = []

    try:
        with open(rule_file, 'r', encoding='utf-8') as f:
            rule = yaml.safe_load(f)
    except Exception as e:
        return [f"Failed to parse YAML: {e}"], []

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in rule:
            errors.append(f"Missing required field: {field}")

    # Validate UUID format
    if 'id' in rule:
        if not validate_uuid(rule['id']):
            errors.append(f"Invalid UUID format for field 'id': {rule['id']}")

    # Validate status
    if 'status' in rule:
        if rule['status'] not in VALID_STATUSES:
            errors.append(
                f"Invalid status '{rule['status']}'. "
                f"Must be one of: {', '.join(VALID_STATUSES)}"
            )

    # Validate level
    if 'level' in rule:
        if rule['level'] not in VALID_LEVELS:
            errors.append(
                f"Invalid level '{rule['level']}'. "
                f"Must be one of: {', '.join(VALID_LEVELS)}"
            )

    # Validate tags
    if 'tags' in rule:
        is_valid, message = validate_tags(rule['tags'])
        if not is_valid:
            errors.append(f"Invalid tags: {message}")

    # Check for deprecated status
    if rule.get('status') == 'deprecated':
        warnings.append(f"Rule '{rule.get('title', 'Unknown')}' is deprecated")

    return errors, warnings


def main():
    """Main validation function."""
    sigma_rules_dir = Path('sigma-rules')
    rule_files = list(sigma_rules_dir.glob('*.yml'))

    if not rule_files:
        print(f"No Sigma rules found in {sigma_rules_dir}")
        sys.exit(1)

    total_errors = 0
    total_warnings = 0

    print(f"Checking {len(rule_files)} Sigma rules...")

    for rule_file in sorted(rule_files):
        errors, warnings = validate_rule(rule_file)

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
    print(f"Validation complete:")
    print(f"  Rules checked: {len(rule_files)}")
    print(f"  Errors: {total_errors}")
    print(f"  Warnings: {total_warnings}")

    if total_errors > 0:
        print(f"\n❌ Validation failed with {total_errors} error(s)")
        sys.exit(1)
    else:
        print(f"\n✓ All rules validated successfully")
        sys.exit(0)


if __name__ == '__main__':
    main()
