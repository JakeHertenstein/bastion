#!/bin/bash
# Demo 2: Daily Security Check
# Duration: ~45 seconds
# Description: Report status, rotation alerts (simulated output)
#
# Uses simulated output for clean demo without exposing real account data

echo "# Daily Security Check"
echo ""
sleep 1

# Step 1: Quick status check (simulated)
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

🟡 Overdue for Rotation (>90 days)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ⏳ HealthPortal - Last changed: 2025-05-01 (229 days)
  ⏳ Legacy Account - Last changed: 2025-04-15 (245 days)
EOF
echo ""
sleep 3

# Step 2: Check for overdue rotations (simulated)
echo "$ bsec 1p report overdue"
sleep 0.5
cat << 'EOF'
OVERDUE ROTATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Account                Days Overdue    Risk Level
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MegaShop               549             🔴 Critical
Legacy Account         245             🟡 High
HealthPortal           229             🟡 High
EOF
echo ""
sleep 2

# Step 3: Export for tracking
echo "$ bsec 1p report export --format csv"
sleep 0.5
cat << 'EOF'
Exported 8 accounts to password-rotation.csv
EOF
echo ""
sleep 2

echo "# ✅ Daily check complete - 3 accounts need attention!"
