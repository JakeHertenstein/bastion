#!/bin/bash
# Git Strategy Setup Script for Seed Card Project
# Creates multiple repository variants with selective file sharing

set -e

# Configuration
PUBLIC_REPO="seed-card-public"
PRIVATE_REPO="seed-card-private"
ENTERPRISE_REPO="seed-card-enterprise"

echo "🔧 Setting up multi-repository git strategy..."

# 1. Create public repository (sanitized version)
setup_public_repo() {
    echo "📁 Setting up public repository..."
    
    git worktree add "../${PUBLIC_REPO}" HEAD
    cd "../${PUBLIC_REPO}"
    
    # Remove sensitive files and configurations
    rm -rf src/seeder/integrations/onepassword_integration.py
    rm -rf private/
    rm -rf config/private/
    rm -f .env*
    rm -f *.csv
    
    # Create sanitized README
    cat > README.md << 'EOF'
# Seed Card - Cryptographic Token Generator

> **Note**: This is the public version. Enterprise features and integrations are available separately.

A deterministic cryptographic token generator for offline password creation using BIP-39 mnemonics and SLIP-39 shares.

## Features
- ✅ BIP-39 mnemonic support
- ✅ SLIP-39 Shamir's Secret Sharing
- ✅ Deterministic token generation
- ✅ CLI interface with rich formatting
- ✅ CSV export functionality
- ❌ Enterprise integrations (1Password, etc.)

## Installation
```bash
pip install -e .
```

## Usage
```bash
# Generate token grid from BIP-39 mnemonic
seeder generate grid --bip39 "your mnemonic words here"

# Export to CSV
seeder export csv --simple "test phrase" --id "SYS.01.02"
```

For enterprise features and integrations, contact the maintainer.
EOF
    
    # Commit public version
    git add .
    git commit -m "feat: public version without sensitive integrations"
    
    echo "✅ Public repository ready at ../${PUBLIC_REPO}"
    cd -
}

# 2. Create private repository (full featured)
setup_private_repo() {
    echo "🔒 Setting up private repository..."
    
    git worktree add "../${PRIVATE_REPO}" HEAD
    cd "../${PRIVATE_REPO}"
    
    # Add private configuration template
    mkdir -p config/private
    cat > config/private/example.env << 'EOF'
# Private Configuration Template
# Copy to config/private/.env and customize

# 1Password Integration
OP_SERVICE_ACCOUNT_TOKEN=your_token_here
OP_VAULT_ID=your_vault_id_here

# Development Settings
DEBUG_MODE=true
LOG_LEVEL=DEBUG

# Testing
USE_TEST_MNEMONICS=true
SKIP_ENTROPY_WARNINGS=true
EOF
    
    # Enhanced gitignore for private repo
    cat >> .gitignore << 'EOF'

# Private repository specific
config/private/.env
config/private/*.json
real_test_data/
production_configs/
deployment_keys/
EOF
    
    git add .
    git commit -m "feat: private repository with full integrations"
    
    echo "✅ Private repository ready at ../${PRIVATE_REPO}"
    cd -
}

# 3. Create enterprise repository (additional features)
setup_enterprise_repo() {
    echo "🏢 Setting up enterprise repository..."
    
    git worktree add "../${ENTERPRISE_REPO}" HEAD
    cd "../${ENTERPRISE_REPO}"
    
    # Add enterprise-specific features
    mkdir -p src/seeder/enterprise
    cat > src/seeder/enterprise/__init__.py << 'EOF'
"""Enterprise features for Seed Card system."""
EOF
    
    cat > src/seeder/enterprise/compliance.py << 'EOF'
"""Compliance and audit features for enterprise deployments."""

import logging
from typing import Dict, List, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class ComplianceLogger:
    """Audit logging for enterprise compliance."""
    
    def __init__(self, audit_file: str = "audit.log"):
        self.audit_file = audit_file
    
    def log_seed_generation(self, user_id: str, seed_type: str, grid_id: str):
        """Log seed generation events for compliance."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "seed_generation",
            "user_id": user_id,
            "seed_type": seed_type,
            "grid_id": grid_id,
            "source": "seeder_cli"
        }
        logger.info(f"AUDIT: {event}")
    
    def log_export_operation(self, user_id: str, export_format: str, destination: str):
        """Log export operations for compliance."""
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event": "data_export",
            "user_id": user_id,
            "format": export_format,
            "destination": destination
        }
        logger.info(f"AUDIT: {event}")
EOF
    
    # Update pyproject.toml for enterprise
    cat >> pyproject.toml << 'EOF'

[project.optional-dependencies]
enterprise = [
    "pydantic>=2.0.0",
    "sqlalchemy>=2.0.0",
    "alembic>=1.11.0",
    "fastapi>=0.100.0",
    "uvicorn>=0.20.0"
]
EOF
    
    git add .
    git commit -m "feat: enterprise features with compliance and audit logging"
    
    echo "✅ Enterprise repository ready at ../${ENTERPRISE_REPO}"
    cd -
}

# 4. Setup remote repositories
setup_remotes() {
    echo "🌐 Setting up remote repositories..."
    
    # Instructions for setting up remotes
    cat > git_remotes_setup.md << 'EOF'
# Git Remotes Setup Instructions

## 1. Create GitHub/GitLab repositories:
- `username/seed-card-public` (public)
- `username/seed-card-private` (private)
- `username/seed-card-enterprise` (private)

## 2. Add remotes to each worktree:

### Public Repository
```bash
cd ../seed-card-public
git remote add origin git@github.com:username/seed-card-public.git
git push -u origin main
```

### Private Repository
```bash
cd ../seed-card-private
git remote add origin git@github.com:username/seed-card-private.git
git push -u origin main
```

### Enterprise Repository
```bash
cd ../seed-card-enterprise
git remote add origin git@github.com:username/seed-card-enterprise.git
git push -u origin main
```

## 3. Cross-repository synchronization:

### Sync core changes to all repositories:
```bash
# In main repository
git add src/seeder/core/
git commit -m "feat: update core functionality"

# Push to all variants
cd ../seed-card-public && git cherry-pick main
cd ../seed-card-private && git cherry-pick main
cd ../seed-card-enterprise && git cherry-pick main
```
EOF
    
    echo "📋 See git_remotes_setup.md for remote configuration instructions"
}

# Main execution
main() {
    if [ ! -d ".git" ]; then
        echo "❌ Not a git repository. Run 'git init' first."
        exit 1
    fi
    
    echo "This will create multiple repository variants. Continue? (y/N)"
    read -r response
    
    if [[ "$response" =~ ^[Yy]$ ]]; then
        setup_public_repo
        setup_private_repo
        setup_enterprise_repo
        setup_remotes
        
        echo ""
        echo "🎉 Multi-repository strategy setup complete!"
        echo ""
        echo "📁 Repository variants created:"
        echo "   • ../${PUBLIC_REPO} (public, sanitized)"
        echo "   • ../${PRIVATE_REPO} (private, full features)"
        echo "   • ../${ENTERPRISE_REPO} (private, enterprise features)"
        echo ""
        echo "📋 Next steps:"
        echo "   1. Review git_remotes_setup.md"
        echo "   2. Create remote repositories"
        echo "   3. Configure VS Code workspace"
    else
        echo "Setup cancelled."
    fi
}

main "$@"
