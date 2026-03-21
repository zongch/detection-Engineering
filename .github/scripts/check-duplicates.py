#!/usr/bin/env python3
"""
Check for duplicate rule IDs in Sigma repository.

Ensures each rule has a unique identifier.
"""

import sys
import yaml
from pathlib import Path
from collections import defaultdict


def extract_rule_ids():
    """Extract all rule IDs from Sigma files."""
    sigma_rules_dir = Path('sigma-rules')
    rule_files = list(sigma_rules_dir.glob('*.yml'))

    id_to_files = defaultdict(list)

    for rule_file in rule_files:
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)

            if 'id' in rule:
                rule_id = rule['id']
                id_to_files[rule_id].append(rule_file.name)
            else:
                print(f"  ⚠️  {rule_file.name}: Missing rule ID")

        except Exception as e:
            print(f"  ❌ {rule_file.name}: Failed to parse - {e}")

    return id_to_files


def main():
    """Main duplicate check function."""
    print("Checking for duplicate rule IDs...")

    id_to_files = extract_rule_ids()

    duplicates = {
        rule_id: files
        for rule_id, files in id_to_files.items()
        if len(files) > 1
    }

    if duplicates:
        print(f"\n❌ Found {len(duplicates)} duplicate rule ID(s):\n")
        for rule_id, files in duplicates.items():
            print(f"  {rule_id}:")
            for file in files:
                print(f"    - {file}")
        sys.exit(1)
    else:
        print(f"  ✓ {len(id_to_files)} unique rule IDs found")
        print(f"✓ No duplicates detected")
        sys.exit(0)


if __name__ == '__main__':
    main()
