#!/bin/bash
# Demo 3: YubiKey Management
# Duration: ~45 seconds
# Description: List, scan, sync YubiKeys (simulated output)
#
# Uses simulated output for clean demo

echo "# YubiKey Management"
echo ""
sleep 1

# Step 1: List YubiKeys from 1Password (simulated)
echo "$ bsec 1p yubikey list"
sleep 0.5
cat << 'EOF'
YubiKey Items from 1Password:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Serial       Model          OATH Slots
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  12345678     YubiKey 5 NFC  3 accounts
EOF
echo ""
sleep 2

# Step 2: Scan connected YubiKey (simulated)
echo "$ bsec 1p yubikey scan"
sleep 0.5
cat << 'EOF'
Scanning connected YubiKeys...

Found YubiKey: 12345678 (YubiKey 5 NFC)

OATH Slots Comparison:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Account             Device    1Password   Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ACME Bank           ✓         ✓           ✅ Synced
  CloudStore AWS      ✓         ✓           ✅ Synced
  DevHub GitHub       ✓         ✓           ✅ Synced
EOF
echo ""
sleep 3

# Step 3: Show status overview (simulated)
echo "$ bsec 1p yubikey status"
sleep 0.5
cat << 'EOF'
YubiKey Sync Status:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Serial       Connected   1Password   Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  12345678     ✓           ✓           ✅ In sync
EOF
echo ""
sleep 2

echo "# ✅ YubiKey OATH accounts tracked in 1Password!"
