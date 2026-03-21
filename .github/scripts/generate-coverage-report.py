#!/usr/bin/env python3
"""
Generate MITRE ATT&CK coverage report.

Analyzes all Sigma rules and produces a coverage report showing:
- Total rules
- Techniques covered
- Tactics covered
- Coverage percentage
- Rules by severity
"""

import sys
import yaml
from pathlib import Path
from collections import defaultdict
from datetime import datetime


def analyze_rules():
    """Analyze all Sigma rules."""
    sigma_rules_dir = Path('sigma-rules')
    rule_files = list(sigma_rules_dir.glob('*.yml'))

    rules = []
    technique_counts = defaultdict(int)
    tactic_counts = defaultdict(int)
    severity_counts = defaultdict(int)
    status_counts = defaultdict(int)

    for rule_file in rule_files:
        try:
            with open(rule_file, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)

            rules.append(rule)

            # Count techniques
            tags = rule.get('tags', [])
            techniques = [t.lower() for t in tags if t.startswith('attack.t')]
            tactics = [t.lower() for t in tags if t.startswith('attack.') and '.' not in t[6:]]

            for technique in techniques:
                technique_counts[technique] += 1

            for tactic in tactics:
                tactic_counts[tactic] += 1

            # Count severity
            level = rule.get('level', 'unknown')
            severity_counts[level] += 1

            # Count status
            status = rule.get('status', 'unknown')
            status_counts[status] += 1

        except Exception as e:
            print(f"Warning: Failed to parse {rule_file.name}: {e}")

    return rules, technique_counts, tactic_counts, severity_counts, status_counts


def generate_report():
    """Generate coverage report."""
    rules, technique_counts, tactic_counts, severity_counts, status_counts = analyze_rules()

    total_rules = len(rules)
    unique_techniques = len(technique_counts)
    unique_tactics = len(tactic_counts)

    # Approximate ATT&CK coverage (201 Enterprise techniques)
    coverage_percent = round((unique_techniques / 201) * 100, 1)

    report = f"""# MITRE ATT&CK Coverage Report

**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Total Rules**: {total_rules}
**Coverage**: {unique_techniques}/201 techniques ({coverage_percent}%)

---

## Summary Metrics

| Metric | Count |
|--------|-------|
| Total Rules | {total_rules} |
| Unique Techniques | {unique_techniques} |
| Unique Tactics | {unique_tactics} |
| ATT&CK Coverage | {coverage_percent}% |

---

## Rules by Severity

| Severity | Count | Percentage |
|----------|-------|------------|
| Critical | {severity_counts.get('critical', 0)} | {round(severity_counts.get('critical', 0)/total_rules*100, 1)}% |
| High | {severity_counts.get('high', 0)} | {round(severity_counts.get('high', 0)/total_rules*100, 1)}% |
| Medium | {severity_counts.get('medium', 0)} | {round(severity_counts.get('medium', 0)/total_rules*100, 1)}% |
| Low | {severity_counts.get('low', 0)} | {round(severity_counts.get('low', 0)/total_rules*100, 1)}% |

---

## Rules by Status

| Status | Count |
|--------|-------|
| Stable | {status_counts.get('stable', 0)} |
| Testing | {status_counts.get('testing', 0)} |
| Draft | {status_counts.get('draft', 0)} |
| Deprecated | {status_counts.get('deprecated', 0)} |

---

## Top 15 Covered Techniques

| Technique | Rules |
|-----------|-------|
"""

    # Sort techniques by count
    sorted_techniques = sorted(technique_counts.items(),
                              key=lambda x: x[1], reverse=True)[:15]

    for technique, count in sorted_techniques:
        report += f"| {technique.upper()} | {count} |\n"

    report += f"""
---

## Covered Tactics

| Tactic | Rules |
|--------|-------|
"""

    sorted_tactics = sorted(tactic_counts.items(),
                           key=lambda x: x[0])

    for tactic, count in sorted_tactics:
        report += f"| {tactic.replace('attack.', '').title()} | {count} |\n"

    report += f"""

---

## Rule List

| Rule | Technique | Severity | Status |
|------|-----------|----------|--------|
"""

    # Sort rules by title
    sorted_rules = sorted(rules, key=lambda r: r.get('title', ''))

    for rule in sorted_rules:
        title = rule.get('title', 'Unknown')
        tags = rule.get('tags', [])
        techniques = [t.upper() for t in tags if t.startswith('attack.t')]
        level = rule.get('level', 'unknown')
        status = rule.get('status', 'unknown')

        technique_str = ', '.join(techniques[:2])  # Show first 2 techniques
        if len(techniques) > 2:
            technique_str += f' (+{len(techniques)-2})'

        report += f"| {title[:50]} | {technique_str} | {level} | {status} |\n"

    return report


def main():
    """Main function."""
    report = generate_report()
    print(report)
    return 0


if __name__ == '__main__':
    sys.exit(main())
