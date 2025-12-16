#!/bin/bash
# Demo 1: Initial Setup
# Duration: ~60 seconds
# Description: Install, authenticate, first sync with demo vault
#
# BEFORE RECORDING:
# - Run: ./setup-demo-vault.sh  (creates demo items)
# - Clear terminal: clear
# - Set clean prompt: export PS1='$ '

VAULT="Bastion"

# Show what we're doing
echo "# Bastion Initial Setup Demo"
echo ""
sleep 1

# Step 1: Install (simulated)
echo "$ pip install bastion-security"
sleep 1
echo "Successfully installed bastion-security-0.3.0"
echo ""
sleep 2

# Step 2: Check installation
echo "$ bsec --version"
sleep 0.5
bsec --version
echo ""
sleep 2

# Step 3: Authenticate with 1Password (simulated)
echo "$ op signin"
sleep 1
echo "# (Already authenticated for demo)"
echo ""
sleep 2

# Step 4: Sync demo vault (simulated output for clean demo)
echo "$ bsec 1p sync vault --vault $VAULT --all"
sleep 0.5
cat << 'EOF'
Syncing from 1Password from vault 'Bastion'...
Listing all items...
Found 8 items
  Fetched 8 items   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:01

✅ Sync complete. Synced 8 accounts.

📊 Summary:
  Total Accounts: 8
  🔴 Pre-Baseline (URGENT): 1
  🟡 Overdue: 2
  🟠 Due Soon (30 days): 1
EOF
echo ""
sleep 2

# Step 5: View initial report (simulated for clean demo)
echo "$ bsec 1p report status"
sleep 0.5
cat << 'EOF'
PASSWORD ROTATION STATUS REPORT
==================================================

Last Sync: 2025-12-15
Compromise Baseline: 2025-01-01

📊 Summary:
  Total Accounts: 8
  🔴 Pre-Baseline (URGENT): 1
  🟡 Overdue: 2
  🟠 Due Soon (30 days): 1

🔴 URGENT: Pre-Baseline Passwords
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ⚠️  MegaShop - Last changed: 2023-06-15
EOF
echo ""
sleep 2

echo "# ✅ Initial setup complete!"
