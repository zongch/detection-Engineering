# Git Repository Initialization Script
# This script initializes the Git repository and prepares it for push to GitHub

$ErrorActionPreference = "Stop"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Git Repository Initialization" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if we're in the right directory
$currentDir = Get-Location
Write-Host "Current directory: $currentDir" -ForegroundColor Yellow
Write-Host ""

# Check for .gitignore
if (-not (Test-Path ".gitignore")) {
    Write-Host "Error: .gitignore not found. Please run this script from the detection-engineering directory." -ForegroundColor Red
    exit 1
}

# Initialize Git repository
Write-Host "[1/5] Initializing Git repository..." -ForegroundColor Cyan
git init

# Configure Git
Write-Host "[2/5] Configuring Git..." -ForegroundColor Cyan
git config user.name "Detection Engineering Team"
git config user.email "security@yourcompany.com"

# Add all files
Write-Host "[3/5] Staging files..." -ForegroundColor Cyan
git add .

# Check what will be committed
Write-Host "`nFiles staged for commit:" -ForegroundColor Yellow
git status --short
Write-Host ""

# Create initial commit
Write-Host "[4/5] Creating initial commit..." -ForegroundColor Cyan
git commit -m "Initial commit: Detection Engineering Setup

🎯 Detection Engineering Repository with Detection-as-Code methodology

📦 Content:
- 17 Sigma detection rules (MITRE ATT&CK mapped)
- Complete CI/CD pipeline with GitHub Actions
- Automated validation and compilation to Splunk & Sentinel
- Comprehensive documentation and guides

🚀 Features:
- Rule validation (syntax, fields, ATT&CK mappings)
- Automatic compilation to multiple SIEM formats
- Coverage reporting and metrics
- Security scanning with Trivy

📚 Documentation:
- CI/CD setup guide
- Sigma rule template
- Deployment guides for Splunk/Sentinel
- ATT&CK gap analysis

📊 Current Coverage:
- Total Rules: 17
- ATT&CK Coverage: ~12%
- Tactics: 6/12

🔍 Security:
- Critical rules: 6
- High rules: 7
- Medium rules: 4"

Write-Host "[5/5] Repository initialized successfully!" -ForegroundColor Green
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Next Steps" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Create a GitHub repository:" -ForegroundColor Yellow
Write-Host "   - Go to: https://github.com/new" -ForegroundColor White
Write-Host "   - Repository name: detection-engineering" -ForegroundColor White
Write-Host "   - Description: SIEM Detection Rules with Detection-as-Code methodology" -ForegroundColor White
Write-Host "   - Set visibility (Public or Private)" -ForegroundColor White
Write-Host "   - IMPORTANT: Do NOT initialize with README, .gitignore, or license" -ForegroundColor Red
Write-Host ""

Write-Host "2. Connect to GitHub:" -ForegroundColor Yellow
Write-Host "   Replace YOUR_USERNAME with your actual GitHub username:" -ForegroundColor White
Write-Host "   git remote add origin https://github.com/YOUR_USERNAME/detection-engineering.git" -ForegroundColor Cyan
Write-Host ""

Write-Host "3. Push to GitHub:" -ForegroundColor Yellow
Write-Host "   git branch -M main" -ForegroundColor Cyan
Write-Host "   git push -u origin main" -ForegroundColor Cyan
Write-Host ""

Write-Host "4. Enable GitHub Actions:" -ForegroundColor Yellow
Write-Host "   - Go to repository Settings → Actions" -ForegroundColor White
Write-Host "   - Click 'General'" -ForegroundColor White
Write-Host "   - Enable 'Allow all actions and reusable workflows'" -ForegroundColor White
Write-Host ""

Write-Host "========================================" -ForegroundColor Green
Write-Host "  ✅ Initialization Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Repository is ready for push to GitHub!" -ForegroundColor Green
