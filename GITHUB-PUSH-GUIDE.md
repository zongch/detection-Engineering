# GitHub Push Guide

Git repository has been initialized locally! Follow these steps to push to GitHub.

---

## ✅ What's Done

- ✅ Git installed (v2.53.0.windows.2)
- ✅ Git repository initialized
- ✅ All 55 files staged
- ✅ Initial commit created (ae1d16a)

---

## 📤 Next Steps: Push to GitHub

### Step 1: Create GitHub Repository

1. Go to: **https://github.com/new**
2. **Repository name**: `detection-engineering`
3. **Description**: `SIEM Detection Rules with Detection-as-Code methodology`
4. **Visibility**: Choose Public or Private
5. **IMPORTANT**: Do NOT initialize with:
   - ❌ README.md (we already have one)
   - ❌ .gitignore (we already have one)
   - ❌ License (we'll add one later)
6. Click **Create repository**

### Step 2: Connect Local Repo to GitHub

Open a **new PowerShell terminal** (not the current one) and run:

```powershell
cd C:\Users\zongc\WorkBuddy\20260320164613\detection-engineering

# Replace YOUR_USERNAME with your actual GitHub username
& "C:\Program Files\Git\cmd\git.exe" remote add origin https://github.com/YOUR_USERNAME/detection-engineering.git

# Rename branch to main
& "C:\Program Files\Git\cmd\git.exe" branch -M main
```

### Step 3: Push to GitHub

```powershell
# Push to GitHub (you'll be prompted for username/password)
& "C:\Program Files\Git\cmd\git.exe" push -u origin main
```

**Note**: If you use 2FA (Two-Factor Authentication), you need a Personal Access Token:
1. Go to GitHub Settings → Developer Settings → Personal Access Tokens
2. Generate new token with `repo` scope
3. Use token as password (not your GitHub password)

---

## 🔐 Using Personal Access Token (Recommended)

If you have 2FA enabled (which you should!):

1. **Create Personal Access Token**:
   - Go to: https://github.com/settings/tokens
   - Click **Generate new token** (classic)
   - Note: "Detection Engineering Repo"
   - Expiration: 90 days
   - Scopes: Check **repo**
   - Click **Generate token**
   - **Copy the token** (you won't see it again!)

2. **Push with token**:
   ```powershell
   & "C:\Program Files\Git\cmd\git.exe" push -u origin main
   ```
   - Username: Your GitHub username
   - Password: The token you just copied

---

## ✨ After Push

Once you successfully push, GitHub will automatically:

1. **Run CI/CD Pipeline** (Actions tab)
   - Validate all rules (2-3 minutes)
   - Compile to Splunk and Sentinel
   - Generate coverage report

2. **Repository will show**:
   - 17 Sigma rules
   - Complete CI/CD workflow
   - Documentation and guides

3. **Download compiled rules** from Actions artifacts:
   - `compiled-splunk` - Splunk queries
   - `compiled-microsoft365defender` - Sentinel queries
   - `deployment-package` - Complete deployment bundle

---

## 🐛 Troubleshooting

### Error: "fatal: repository not found"
**Cause**: Repository URL is incorrect or doesn't exist
**Fix**:
- Check GitHub username in URL
- Verify repository exists on GitHub
- Try: `git remote -v` to see current remote

### Error: "fatal: authentication failed"
**Cause**: Wrong username/password or 2FA issue
**Fix**:
- Use Personal Access Token instead of password
- Check username spelling
- Verify token has `repo` scope

### Error: "Updates were rejected"
**Cause**: GitHub repository has commits (e.g., you created with README)
**Fix**:
```powershell
# Force push (only do this if you're sure!)
& "C:\Program Files\Git\cmd\git.exe" push -u origin main --force
```

### CI/CD Pipeline doesn't run
**Cause**: GitHub Actions not enabled
**Fix**:
1. Go to repository **Settings → Actions → General**
2. Check **Allow all actions and reusable workflows**
3. Click **Save**

---

## 📊 What You'll Have After Push

```
GitHub Repository: detection-engineering
├── Actions Tab          # CI/CD pipeline runs
├── Code Tab              # All source files
├── Insights Tab          # Commits, contributors
├── Settings Tab          # Branch protection, secrets
└── Security Tab          # Dependabot alerts
```

### Actions Tab Shows:
- ✅ validate-rules (5 checks)
- ✅ compile-rules (Splunk + Sentinel)
- ✅ generate-report (Coverage)
- ✅ deploy-artifacts (Package)
- ✅ security-scan (Trivy)

### Download Artifacts:
1. Click **Actions** tab
2. Find latest workflow run
3. Scroll to **Artifacts**
4. Download:
   - `compiled-splunk` (for Splunk SIEM)
   - `compiled-microsoft365defender` (for Sentinel SIEM)
   - `deployment-package` (everything bundled)

---

## 🚀 Next Steps After Push

1. **Enable Branch Protection**:
   - Settings → Branches → Add rule
   - Require PR before merging
   - Require status checks to pass

2. **Add Collaborators**:
   - Settings → Collaborators
   - Add team members

3. **Set Up Deployment**:
   - Download artifacts
   - Deploy to your SIEM (Splunk/Sentinel)
   - See `docs/CICD-SETUP-GUIDE.md` for details

4. **Start Detecting**:
   - Monitor alerts in your SIEM
   - Tune false positives
   - Document findings

---

## 📞 Quick Reference

| Command | Purpose |
|---------|-----------|
| `git status` | See changes |
| `git add .` | Stage all files |
| `git commit -m "message"` | Create commit |
| `git push -u origin main` | Push to GitHub |
| `git pull` | Update from GitHub |
| `git checkout -b feature/new-rule` | Create feature branch |
| `git checkout main` | Switch to main |

---

**Ready to push?** Open a new PowerShell terminal and follow the steps above! 🚀

---

**Created**: 2026-03-22
**Git Version**: 2.53.0.windows.2
