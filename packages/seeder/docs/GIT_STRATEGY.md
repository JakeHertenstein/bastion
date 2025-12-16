# Git Strategy for Seed Card Project

## 🎯 Overview

This document outlines a comprehensive git strategy for managing multiple variants of the Seed Card project while maintaining security and enabling selective file sharing.

## 🏗️ Repository Structure

### Multi-Repository Strategy

We use **git worktrees** to manage three repository variants:

1. **🌍 Public Repository** (`seed-card-public`)
   - Sanitized version without sensitive integrations
   - Open source, community contributions welcome
   - Excludes: 1Password integration, private configs, real test data

2. **🔒 Private Repository** (`seed-card-private`) 
   - Full-featured version with all integrations
   - Development and testing with real configurations
   - Includes: All features, 1Password integration, private configs

3. **🏢 Enterprise Repository** (`seed-card-enterprise`)
   - Enterprise features and compliance tools
   - Audit logging, advanced security features
   - Includes: All features + enterprise extensions

## 🔧 Setup Instructions

### 1. Initial Setup

```bash
# Run the automated setup script
chmod +x scripts/setup_git_strategy.sh
./scripts/setup_git_strategy.sh
```

### 2. Manual Repository Creation

After running the setup script:

```bash
# Create GitHub repositories (public)
gh repo create seed-card-public --public

# Create GitHub repositories (private)
gh repo create seed-card-private --private
gh repo create seed-card-enterprise --private
```

### 3. Configure Remotes

```bash
# Navigate to each worktree and add remotes
cd ../seed-card-public
git remote add origin git@github.com:username/seed-card-public.git
git push -u origin main

cd ../seed-card-private  
git remote add origin git@github.com:username/seed-card-private.git
git push -u origin main

cd ../seed-card-enterprise
git remote add origin git@github.com:username/seed-card-enterprise.git
git push -u origin main
```

## 🔄 Workflow Patterns

### Feature Development Workflow

```bash
# 1. Start in main repository
git checkout -b feature/new-crypto-function

# 2. Develop and test
git add src/seeder/core/crypto.py
git commit -m "feat: add new cryptographic function"

# 3. Sync to appropriate repositories
cd ../seed-card-public && git cherry-pick feature/new-crypto-function
cd ../seed-card-private && git cherry-pick feature/new-crypto-function  
cd ../seed-card-enterprise && git cherry-pick feature/new-crypto-function
```

### Integration-Specific Development

```bash
# Work directly in private repository for 1Password features
cd ../seed-card-private
git checkout -b feature/1password-enhancements

# Make changes to integration
git add src/seeder/integrations/onepassword_integration.py
git commit -m "feat: enhance 1Password vault management"

# Push only to private repository
git push origin feature/1password-enhancements
```

### Enterprise Feature Development

```bash
# Work in enterprise repository for compliance features
cd ../seed-card-enterprise
git checkout -b feature/audit-logging

# Add enterprise features
git add src/seeder/enterprise/compliance.py
git commit -m "feat: add compliance audit logging"

# Push only to enterprise repository
git push origin feature/audit-logging
```

## 📋 File Organization Strategy

### Shared Files (All Repositories)
- `src/seeder/core/` - Core cryptographic functions
- `src/seeder/cli/` - Command-line interface
- `tests/` - Unit tests (sanitized)
- `docs/` - Public documentation
- `pyproject.toml` - Basic package configuration

### Private Repository Only
- `src/seeder/integrations/onepassword_integration.py`
- `config/private/` - Private configuration files
- `real_test_data/` - Test data with real mnemonics
- `.env` files with API keys

### Enterprise Repository Only  
- `src/seeder/enterprise/` - Enterprise-specific features
- `compliance/` - Audit and compliance tools
- `deployment/` - Enterprise deployment configurations

## 🛡️ Security Considerations

### .gitignore Strategy

Each repository has tailored `.gitignore` rules:

```bash
# Public repository - basic ignores
__pycache__/
*.pyc
venv/
build/
dist/

# Private repository - additional ignores  
config/private/.env
real_test_data/
*.key
*.pem

# Enterprise repository - comprehensive ignores
audit_logs/
deployment_keys/
production_configs/
```

### Sensitive Data Handling

1. **Never commit real mnemonics or API keys**
2. **Use environment variables for sensitive configuration**
3. **Sanitize commit messages and documentation**
4. **Regular security audits with `git-secrets`**

### Branch Protection

Configure branch protection rules:

```bash
# Public repository
gh api repos/username/seed-card-public/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":[]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":1}'

# Private/Enterprise repositories  
gh api repos/username/seed-card-private/branches/main/protection \
  --method PUT \
  --field required_status_checks='{"strict":true,"contexts":["test","security-scan"]}' \
  --field enforce_admins=true \
  --field required_pull_request_reviews='{"required_approving_review_count":2}'
```

## 🔄 Synchronization Workflows

### Core Updates (Propagate to All)

```bash
# Script: scripts/sync_core_changes.sh
#!/bin/bash
FEATURE_BRANCH=$1

cd ../seed-card-public
git cherry-pick $FEATURE_BRANCH
git push origin main

cd ../seed-card-private  
git cherry-pick $FEATURE_BRANCH
git push origin main

cd ../seed-card-enterprise
git cherry-pick $FEATURE_BRANCH  
git push origin main
```

### Selective Updates (Integration-Specific)

```bash
# Update only private and enterprise with integration changes
cd ../seed-card-private
git cherry-pick integration/new-feature

cd ../seed-card-enterprise  
git cherry-pick integration/new-feature
# Skip public repository
```

## 🧪 Testing Strategy

### Repository-Specific CI/CD

Each repository has tailored GitHub Actions:

**Public Repository:**
```yaml
# .github/workflows/public-ci.yml
- name: Test Core Functions
  run: pytest tests/core/ -v
  
- name: Test CLI Interface  
  run: pytest tests/cli/ -v
  
- name: Security Scan
  run: bandit -r src/
```

**Private Repository:**
```yaml  
# .github/workflows/private-ci.yml
- name: Test All Functions
  run: pytest tests/ -v
  
- name: Test 1Password Integration
  run: pytest tests/integrations/ -v
  env:
    OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_TOKEN }}
```

**Enterprise Repository:**
```yaml
# .github/workflows/enterprise-ci.yml  
- name: Test Enterprise Features
  run: pytest tests/enterprise/ -v
  
- name: Compliance Check
  run: python -m seeder.enterprise.compliance --verify
```

## 📊 Release Management

### Versioning Strategy

- **Public:** Standard semantic versioning (1.0.0)
- **Private:** Includes pre-release identifiers (1.0.0-private.1)  
- **Enterprise:** Enterprise suffix (1.0.0-enterprise.1)

### Release Process

```bash
# 1. Tag main repository
git tag v1.0.0
git push origin v1.0.0

# 2. Create releases in each variant
cd ../seed-card-public && git tag v1.0.0-public && git push origin v1.0.0-public
cd ../seed-card-private && git tag v1.0.0-private && git push origin v1.0.0-private  
cd ../seed-card-enterprise && git tag v1.0.0-enterprise && git push origin v1.0.0-enterprise
```

## 🛠️ Tools and Automation

### Recommended Tools

- **Git Worktree Manager:** For managing multiple worktrees
- **GitHub CLI:** For repository management  
- **Pre-commit Hooks:** For code quality and security
- **Git Secrets:** For preventing credential commits

### Automation Scripts

1. `scripts/setup_git_strategy.sh` - Initial repository setup
2. `scripts/sync_core_changes.sh` - Propagate core changes
3. `scripts/selective_sync.sh` - Selective repository updates  
4. `scripts/release_all.sh` - Multi-repository releases

## 📈 Monitoring and Maintenance

### Regular Tasks

1. **Weekly:** Sync core changes across repositories
2. **Monthly:** Security audit and dependency updates
3. **Quarterly:** Review access permissions and branch protection
4. **Annually:** Complete security review and strategy update

### Health Checks

```bash
# Check repository synchronization
scripts/check_repo_sync.sh

# Verify security configurations
scripts/security_audit.sh

# Test all integrations
scripts/integration_test.sh
```

This strategy provides robust separation of concerns while maintaining synchronization and security across multiple repository variants.
