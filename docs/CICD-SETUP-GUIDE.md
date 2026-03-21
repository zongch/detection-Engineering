# CI/CD Setup Guide

Complete guide for setting up the Detection Engineering CI/CD pipeline using GitHub Actions.

---

## Prerequisites

1. **GitHub Account**
   - Create a GitHub account if you don't have one
   - Have repository admin permissions

2. **Git Installed**
   ```bash
   # Windows: Download from https://git-scm.com/download/win
   # macOS: brew install git
   # Linux: sudo apt install git
   ```

3. **GitHub CLI (optional but recommended)**
   ```bash
   # Install from https://cli.github.com/
   # Windows: winget install --id GitHub.cli
   # macOS: brew install gh
   ```

---

## Step 1: Initialize Git Repository

```bash
# Navigate to project directory
cd detection-engineering

# Initialize Git repository
git init

# Add all files
git add .

# Make initial commit
git commit -m "Initial commit: Detection Engineering setup

- 17 Sigma detection rules
- CI/CD pipeline configuration
- Documentation"
```

---

## Step 2: Create GitHub Repository

### Option A: Using GitHub CLI (Recommended)

```bash
# Create repository on GitHub
gh repo create detection-engineering \
  --public \
  --source=. \
  --push \
  --description="SIEM Detection Rules with Detection-as-Code methodology"

# Enable GitHub Actions
gh repo edit detection-engineering --enable-actions=true
```

### Option B: Using GitHub Web UI

1. Go to https://github.com/new
2. Repository name: `detection-engineering`
3. Description: `SIEM Detection Rules with Detection-as-Code methodology`
4. Set visibility (Public or Private)
5. **Do not** initialize with README, .gitignore, or license (we already have them)
6. Click "Create repository"
7. Follow instructions to push existing repository

```bash
# After creating repository on GitHub
git remote add origin https://github.com/YOUR_USERNAME/detection-engineering.git
git branch -M main
git push -u origin main
```

---

## Step 3: Configure GitHub Actions

### Workflow Triggers

The CI/CD pipeline (`.github/workflows/ci-cd.yml`) runs on:

1. **Pull Requests**: Validates all changed rules
2. **Push to main**: Validates, compiles, and creates deployment artifacts
3. **Manual Dispatch**: Trigger via GitHub Actions UI

### Workflow Stages

1. **validate-rules**: Validates Sigma syntax and required fields
2. **compile-rules**: Compiles to Splunk SPL and Sentinel KQL
3. **generate-report**: Creates ATT&CK coverage report
4. **deploy-artifacts**: Packages rules for SIEM deployment
5. **security-scan**: Runs Trivy security scanner

### Required Secrets

Currently, no secrets are required. When you add automatic deployment to SIEM, add:

- `SPLUNK_HOST` - Splunk server hostname
- `SPLUNK_USER` - Splunk username
- `SPLUNK_PASS` - Splunk password
- `AZURE_RG` - Azure resource group (for Sentinel)
- `SENTINEL_WORKSPACE` - Sentinel workspace name

Add secrets in GitHub: **Settings → Secrets and variables → Actions**

---

## Step 4: Test CI/CD Pipeline

### Test on Pull Request

```bash
# Create a new branch
git checkout -b test-ci-cd

# Make a trivial change to a rule file
echo "# Test CI/CD" >> sigma-rules/README.md

# Commit and push
git add sigma-rules/README.md
git commit -m "Test: CI/CD pipeline validation"
git push -u origin test-ci-cd

# Create pull request via GitHub CLI
gh pr create --title "Test CI/CD Pipeline" --body "Testing the pipeline"

# Or create PR manually on GitHub
```

### Verify Pipeline Status

1. Go to your repository on GitHub
2. Click the **Actions** tab
3. Find the workflow run for your PR
4. Check that all jobs passed:
   - ✓ validate-rules
   - ✓ compile-rules (Splunk)
   - ✓ compile-rules (Sentinel)
   - ✓ generate-report
   - ✓ deploy-artifacts
   - ✓ security-scan

### Download Artifacts

1. Scroll to the bottom of the workflow run
2. Expand **Artifacts** section
3. Download:
   - `compiled-splunk` - Splunk rules
   - `compiled-microsoft365defender` - Sentinel rules
   - `deployment-package` - Complete deployment package

---

## Step 5: Merge to Main

After testing:

```bash
# Merge pull request
gh pr merge test-ci-cd --merge

# Delete branch
git checkout main
git pull
git branch -d test-ci-cd
gh repo delete-branch test-ci-cd
```

The pipeline will run again on `main` and create final deployment artifacts.

---

## Step 6: Set Up Branch Protection (Recommended)

Require pull requests and CI checks before merging:

1. Go to **Settings → Branches**
2. Click **Add rule**
3. Branch name: `main`
4. Enable:
   - ✅ Require a pull request before merging
   - ✅ Require status checks to pass before merging
   - Select all CI/CD jobs: `validate-rules`, `compile-rules`, etc.
   - ✅ Require branches to be up to date before merging
5. Click **Create**

---

## Step 7: Configure Notifications

Get notified when CI/CD runs fail:

1. Go to **Settings → Notifications**
2. Add email for:
   - Workflow run failures
   - Pull request reviews
   - Deployment events

---

## Troubleshooting

### Pipeline Fails with "sigma: command not found"

The workflow installs Sigma CLI automatically. If this fails:

1. Check Python version (3.7+ required)
2. Verify pip installation works
3. Check workflow logs for specific error

### Validation Fails with "Missing required field"

Review the error output and fix the specific rule file:

```bash
# Run validation locally to see exact errors
python .github/scripts/check-required-fields.py
```

### Compilation Fails

Check the Sigma rule syntax:

```bash
# Validate specific rule
sigma check sigma-rules/your-rule.yml
```

### Artifacts Not Generated

Ensure the `compile-rules` job completed successfully. Check:
- Job status (green checkmark)
- Job logs for errors

---

## Advanced Configuration

### Customizing Workflow Triggers

Edit `.github/workflows/ci-cd.yml`:

```yaml
on:
  push:
    branches:
      - main
      - development  # Add more branches
  pull_request:
    paths:
      - 'sigma-rules/**/*.yml'
      - '.github/workflows/*.yml'
  schedule:
    # Run every Sunday at 2 AM
    - cron: '0 2 * * 0'
```

### Adding More SIEM Backends

Install additional backends:

```yaml
- name: Install Sigma CLI and Backends
  run: |
    pip install sigma-cli
    pip install pySigma-backend-splunk
    pip install pySigma-backend-microsoft365defender
    pip install pySigma-backend-elasticsearch  # Add Elastic
    pip install pySigma-backend-qradar        # Add QRadar
```

### Adding Automated Deployment

Enable automatic deployment to SIEM:

```yaml
deploy-splunk:
  needs: compile-rules
  runs-on: ubuntu-latest
  steps:
    - uses: actions/download-artifact@v4
      with:
        name: compiled-splunk
    - name: Deploy to Splunk
      run: |
        curl -k -u "${{ secrets.SPLUNK_USER }}:${{ secrets.SPLUNK_PASS }}" \
          https://${{ secrets.SPLUNK_HOST }}:8089/servicesNS/admin/search/saved/searches \
          -d @rules-all.conf
```

---

## Best Practices

1. **Always Test on Branch**: Never push directly to `main`
2. **Review Pipeline Logs**: Check logs even when pipeline passes
3. **Keep Workflow Fast**: Avoid long-running steps
4. **Document Changes**: Update README.md with new rules
5. **Version Rules**: Use semantic versioning for rule changes
6. **Monitor Artifacts**: Regularly download and review compiled rules

---

## Next Steps

After setting up CI/CD:

1. **Add Team Members**: Invite collaborators to the repository
2. **Set Up Code Review**: Require at least one approval before merging
3. **Create Issues**: Use GitHub Issues for rule requests and bug reports
4. **Add Labels**: Create labels like `bug`, `enhancement`, `urgent`
5. **Set Milestones**: Track progress with milestones

---

## Support

For issues with:
- **GitHub Actions**: https://docs.github.com/en/actions
- **Sigma CLI**: https://github.com/SigmaHQ/sigma-cli
- **Detection Rules**: Create an issue in this repository

---

**Last Updated**: 2026-03-22
**Version**: 1.0.0
