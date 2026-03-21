#!/usr/bin/env python3
"""
Validate MITRE ATT&CK mappings in Sigma rules.

Checks:
- Every rule has at least one ATT&CK technique tag
- Technique format is correct (attack.tXXXX or attack.tXXXX.YYY)
- Tactics are correctly formatted (attack.tactic_name)
"""

import sys
import yaml
import re
from pathlib import Path
from collections import defaultdict

# ATT&CK tag patterns
TECHNIQUE_PATTERN = re.compile(r'^attack\.t\d{4}(?:\.\d{3})?$', re.IGNORECASE)
TACTIC_PATTERN = re.compile(r'^attack\.[a-z_]+$', re.IGNORECASE)


def analyze_attack_mappings(rule_file):
    """Analyze ATT&CK mappings in a rule."""
    try:
        with open(rule_file, 'r', encoding='utf-8') as f:
            rule = yaml.safe_load(f)
    except Exception as e:
        return None, f"Failed to parse YAML: {e}"

    if 'tags' not in rule:
        return None, "No tags found"

    tags = rule['tags']
    techniques = []
    tactics = []
    invalid_tags = []

    for tag in tags:
        if TECHNIQUE_PATTERN.match(tag):
            techniques.append(tag.lower())
        elif TACTIC_PATTERN.match(tag):
            tactics.append(tag.lower())
        else:
            # Check if it looks like a malformed attack tag
            if tag.lower().startswith('attack.'):
                invalid_tags.append(tag)

    if not techniques:
        return None, f"No valid ATT&CK technique tags found. Invalid tags: {invalid_tags}"

    return {
        'title': rule.get('title', 'Unknown'),
        'techniques': list(set(techniques)),  # Deduplicate
        'tactics': list(set(tactics)),
        'invalid_tags': invalid_tags
    }, None


def generate_coverage_report():
    """Generate ATT&CK coverage report."""
    sigma_rules_dir = Path('sigma-rules')
    rule_files = list(sigma_rules_dir.glob('*.yml'))

    if not rule_files:
        print(f"No Sigma rules found in {sigma_rules_dir}")
        return

    all_analysis = []
    technique_counts = defaultdict(int)
    tactic_counts = defaultdict(int)

    for rule_file in sorted(rule_files):
        analysis, error = analyze_attack_mappings(rule_file)

        if error:
            print(f"  ❌ {rule_file.name}: {error}")
            continue

        all_analysis.append(analysis)

        # Count techniques and tactics
        for technique in analysis['techniques']:
            technique_counts[technique] += 1
        for tactic in analysis['tactics']:
            tactic_counts[tactic] += 1

        print(f"  ✓ {rule_file.name}")

    # Print summary
    print(f"\n{'='*60}")
    print(f"ATT&CK Coverage Summary:")
    print(f"  Rules analyzed: {len(all_analysis)}")
    print(f"  Unique techniques: {len(technique_counts)}")
    print(f"  Unique tactics: {len(tactic_counts)}")

    print(f"\nTop 10 Techniques:")
    for technique, count in sorted(technique_counts.items(),
                                   key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {technique}: {count} rule(s)")

    print(f"\nTactics:")
    for tactic in sorted(tactic_counts.keys()):
        print(f"  {tactic}: {tactic_counts[tactic]} rule(s)")


def main():
    """Main validation function."""
    sigma_rules_dir = Path('sigma-rules')
    rule_files = list(sigma_rules_dir.glob('*.yml'))

    if not rule_files:
        print(f"No Sigma rules found in {sigma_rules_dir}")
        sys.exit(1)

    print(f"Validating ATT&CK mappings in {len(rule_files)} rules...")

    total_errors = 0

    for rule_file in sorted(rule_files):
        analysis, error = analyze_attack_mappings(rule_file)

        if error:
            print(f"❌ {rule_file.name}: {error}")
            total_errors += 1
            continue

        # Check for invalid tags
        if analysis['invalid_tags']:
            print(f"⚠️  {rule_file.name}: Invalid ATT&CK tags: {analysis['invalid_tags']}")
            total_errors += 1
        else:
            print(f"  ✓ {rule_file.name}: {len(analysis['techniques'])} technique(s), "
                  f"{len(analysis['tactics'])} tactic(s)")

    print(f"\n{'='*60}")

    if total_errors > 0:
        print(f"❌ Validation failed with {total_errors} error(s)")
        sys.exit(1)
    else:
        print(f"✓ All rules have valid ATT&CK mappings")
        print()

        # Generate coverage report
        generate_coverage_report()
        sys.exit(0)


if __name__ == '__main__':
    main()
