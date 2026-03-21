# Sigma Rule Template

Use this template when creating new Sigma detection rules.

---

## Complete Template

```yaml
title: [Rule Title - Clear, Descriptive]
id: [UUID v4 - Generate with: python -c "import uuid; print(uuid.uuid4())"]
status: [draft | testing | stable | deprecated]
level: [low | medium | high | critical]
description: |
  [Detailed description of the threat being detected.
   Explain what the attacker is doing and why it's suspicious.
   Include context about when this technique is used.]

references:
  - [ATT&CK Technique URL - https://attack.mitre.org/techniques/TXXXX/]
  - [Additional reference URLs]
author: [Your Name / Team]
date: [YYYY/MM/DD]
modified: [YYYY/MM/DD]

tags:
  - attack.[tactic_name]           # e.g., attack.execution
  - attack.tXXXX                   # Main technique
  - attack.tXXXX.YYY               # Sub-technique (if applicable)

logsource:
  category: [process_creation | registry_set | file_access | network_connection | driver_load | image_load | etc.]
  product: [windows | linux | macos]

detection:
  selection_[component]:
    [Field]: [Value or Pattern]
    [Field|endswith]: [Pattern]
    [Field|contains]: [Pattern]
    [Field|re]: [Regex Pattern]
  condition: [Logic combining selections]
    # Examples:
    # - selection_a and selection_b
    # - 1 of selection_*
    # - all of selection_*

falsepositives:
  - [Known legitimate scenario 1]
  - [Known legitimate scenario 2]
  - [Known legitimate scenario 3]

fields:
  - [Field 1 for investigation]
  - [Field 2 for investigation]
  - [Field 3 for investigation]

allowlist:
  - [Field]: [Pattern]
    Reason: [Why this is benign]
  - [Field]: [Pattern]
    User: [Specific user if relevant]
    Reason: [Why this is benign]

related:
  - id: [UUID of related rule]
    type: [derived | correlated | obsoletes | merged]
```

---

## Required Fields Explained

### `title`
- Clear, descriptive name
- Start with what is being detected
- Example: "PowerShell Encoded Command Execution"

### `id`
- Unique UUID v4
- Generate with: `python -c "import uuid; print(uuid.uuid4())"`
- Never reuse IDs

### `status`
- `draft`: Initial development, not ready for production
- `testing`: Deployed to non-production for validation
- `stable`: Production-ready with validated false positive rates
- `deprecated`: Removed or replaced by better detection

### `level`
- `low`: Informational, requires no immediate action
- `medium`: Suspicious, investigate within hours
- `high`: Threatening, investigate immediately
- `critical`: Imminent threat, respond within minutes

### `description`
- What threat is being detected
- Why it's suspicious
- When attackers use this technique
- What data sources are needed

### `tags`
- Format: `attack.tactic_name` and `attack.tXXXX`
- At least one technique tag required
- Multiple tactics/techniques allowed
- Example:
  ```yaml
  tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027.010
  ```

### `logsource`
- `category`: Event type
  - `process_creation`
  - `registry_set`
  - `file_access`
  - `file_create`
  - `network_connection`
  - `driver_load`
  - `image_load`
  - `pipe_created`
  - `process_access`
- `product`: Operating system
  - `windows`
  - `linux`
  - `macos`

### `detection`
- Define selections with meaningful names
- Use operators:
  - `|contains`: Contains substring
  - `|endswith`: Ends with pattern
  - `|startswith`: Starts with pattern
  - `|re`: Regular expression match
  - `|contains|all`: Contains all patterns
  - `|contains|any`: Contains any pattern
- Combine with logical operators:
  - `and`: All conditions must match
  - `or`: Any condition can match
  - `not`: Condition must not match
  - `1 of selection_*`: At least one selection matches
  - `all of selection_*`: All selections must match

### `falsepositives`
- Document all known benign scenarios
- Be specific about what triggers the rule legitimately
- This helps SOC analysts investigate alerts

### `fields`
- List fields to display in SIEM alerts
- Include context for investigation:
  - `User` - Who triggered the event
  - `Computer` - Where it happened
  - `CommandLine` - What command was run
  - `ParentImage` - Parent process
  - `TargetObject` - What was modified
  - `Details` - What changed

### `allowlist`
- Known benign patterns that should not alert
- Document the reason
- Include user or system context if relevant

### `related`
- Link to related rules
- Types:
  - `derived`: This rule was derived from another
  - `correlated`: Correlates with another rule
  - `obsoletes`: This rule replaces another
  - `merged`: This rule merged multiple rules

---

## Example Rule

```yaml
title: Suspicious PowerShell Encoded Command Execution
id: a1b2c3d4-e5f6-7890-abcd-123456789012
status: stable
level: high
description: |
  Detects PowerShell execution with encoded commands. Attackers use
  Base64-encoded PowerShell commands to obfuscate malicious payloads
  and bypass simple command-line log detection. This technique is
  commonly used in malware delivery and post-exploitation.

references:
  - https://attack.mitre.org/techniques/T1059/001/
  - https://attack.mitre.org/techniques/T1027/010/
author: Detection Engineering Team
date: 2026/03/15
modified: 2026/03/22

tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027.010

logsource:
  category: process_creation
  product: windows

detection:
  selection_parent:
    ParentImage|endswith:
      - '\cmd.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\wmiprvse.exe'
  selection_powershell:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - '-enc '
      - '-EncodedCommand'
      - '-ec '
      - 'FromBase64String'
  condition: selection_parent and selection_powershell

falsepositives:
  - Legitimate IT automation tools using encoded commands for deployment
  - SCCM and Intune software distribution
  - PowerShell Remoting scripts

fields:
  - ParentImage
  - Image
  - CommandLine
  - User
  - Computer
  - ProcessId

allowlist:
  - Image: 'C:\Windows\System32\powershell.exe'
    CommandLine: '*SCCM*'
    Reason: 'SCCM software deployment'
  - Image: 'C:\Windows\System32\powershell.exe'
    User: 'DOMAIN\ServiceAccount'
    Reason: 'Automated deployment script'

related:
  - id: b2c3d4e5-f6a7-8901-bcde-234567890123
    type: derived
```

---

## Best Practices

### 1. Detection Logic
- Keep detection logic simple and performant
- Avoid complex regex when possible
- Use multiple weak signals instead of one strong signal
- Correlate events when appropriate

### 2. Field Selection
- Include context for investigation
- Don't include sensitive data (passwords, tokens)
- Use consistent field names across rules

### 3. False Positives
- Be honest about false positive potential
- Document all known benign scenarios
- Provide guidance on tuning thresholds

### 4. ATT&CK Mapping
- Map to the most specific technique
- Include both tactic and technique tags
- Use sub-techniques when applicable

### 5. Description Quality
- Explain the threat clearly
- Provide context about attacker motivations
- Reference threat intelligence when available

### 6. Rule Status
- Start as `draft`
- Move to `testing` after initial validation
- Promote to `stable` after production testing
- Deprecate obsolete rules

---

## Validation Checklist

Before submitting a new rule:

- [ ] Rule follows Sigma format specification
- [ ] All required fields present
- [ ] UUID is unique
- [ ] At least one ATT&CK technique tag
- [ ] False positives documented
- [ ] Allow lists included for common benign activity
- [ ] Detection logic tested against sample data
- [ ] Description is clear and informative
- [ ] References are accurate and up-to-date
- [ ] Status is appropriate (draft for new rules)

---

## Common Mistakes

### ❌ Bad: Too Generic
```yaml
detection:
  selection:
    Image|endswith: '\powershell.exe'
  condition: selection
```
**Issue**: Will fire on all PowerShell execution (too many false positives)

### ✅ Good: Specific and Context-Aware
```yaml
detection:
  selection_parent:
    ParentImage|endswith: '\cmd.exe'
  selection_powershell:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc '
  condition: selection_parent and selection_powershell
```
**Better**: Only fires when encoded PowerShell runs from cmd.exe

### ❌ Bad: Missing ATT&CK Mapping
```yaml
tags:
  - powershell
  - suspicious
```
**Issue**: Non-standard tags, won't work with ATT&CK analysis

### ✅ Good: Proper ATT&CK Mapping
```yaml
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1027.010
```
**Better**: Uses standard ATT&CK taxonomy

---

## Testing Your Rule

### 1. Validate Sigma Syntax
```bash
sigma check your-rule.yml
```

### 2. Test Against Sample Logs
```bash
# Compile to Splunk
sigma convert -t splunk your-rule.yml > test-rule.conf

# Test in Splunk with sample data
# Verify it matches expected events
# Check for false positives
```

### 3. Run Local Validation Scripts
```bash
python .github/scripts/check-required-fields.py
python .github/scripts/check-attack-mappings.py
```

### 4. Create Pull Request
- Describe the threat being detected
- Include testing methodology
- Document false positive tuning
- Reference related rules

---

**Template Version**: 1.0.0
**Last Updated**: 2026-03-22
