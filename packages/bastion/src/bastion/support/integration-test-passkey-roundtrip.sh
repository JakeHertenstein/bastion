#!/bin/bash
# integration-test-passkey-roundtrip.sh
# Demonstrates passkey data loss during JSON round-trip editing
#
# PREREQUISITES:
# - 1Password CLI (op) installed and authenticated
# - A LOGIN item with a passkey (create one at autofill.me for testing)
# - jq installed for JSON parsing
#
# WARNING: This test WILL destroy the passkey on the test item!
#
# Bug report: bastion/support/1PASSWORD-CLI-PASSKEY-BUG.md

set -e

# Configuration - UPDATE THIS with your test item UUID or pass as argument
TEST_UUID="${1:-hqguqsaovlalodxkabkzujska4}"

echo "=========================================="
echo "1Password CLI Passkey Round-Trip Test"
echo "=========================================="
echo ""
echo "Test UUID: $TEST_UUID"
echo "CLI Version: $(op --version)"
echo ""

# Step 1: Verify item exists and get initial state
echo "Step 1: Checking initial state..."
INITIAL_VERSION=$(op item get "$TEST_UUID" --format json | jq -r '.version')
INITIAL_TITLE=$(op item get "$TEST_UUID" --format json | jq -r '.title')
echo "  Title: $INITIAL_TITLE"
echo "  Initial version: $INITIAL_VERSION"
echo ""

# Step 2: Prompt user to export from UI to verify passkey exists
echo "Step 2: MANUAL VERIFICATION REQUIRED"
echo "  1. Open 1Password app"
echo "  2. Find item: $INITIAL_TITLE ($TEST_UUID)"
echo "  3. Right-click → Export → Copy as JSON"
echo "  4. Verify 'details.passkey.privateKey' exists in the export"
echo ""
read -p "Press Enter when you've verified the passkey exists (or Ctrl+C to abort)..."
echo ""

# Step 3: Show what the CLI sees (no passkey data)
echo "Step 3: CLI view of item (note: NO passkey data visible)..."
echo ""
op item get "$TEST_UUID" --format json | jq '{id, title, category, fields: [.fields[].id]}'
echo ""
echo "  ⚠️  The CLI output does NOT include passkey data!"
echo ""

# Step 4: Perform the round-trip (THIS DESTROYS THE PASSKEY)
echo "Step 4: Performing round-trip edit..."
echo "  Command: op item get $TEST_UUID --format json | op item edit $TEST_UUID"
echo ""
echo "  ⚠️  WARNING: This will DESTROY the passkey private key!"
read -p "Press Enter to proceed (or Ctrl+C to abort)..."
echo ""

op item get "$TEST_UUID" --format json | op item edit "$TEST_UUID"

echo "  ✅ Round-trip complete (no errors reported by CLI)"
echo ""

# Step 5: Check new version
echo "Step 5: Checking final state..."
FINAL_VERSION=$(op item get "$TEST_UUID" --format json | jq -r '.version')
echo "  Final version: $FINAL_VERSION"
echo "  Version changed: $INITIAL_VERSION → $FINAL_VERSION"
echo ""

# Step 6: Prompt user to verify damage
echo "Step 6: VERIFY THE DAMAGE"
echo ""
echo "  1. Open 1Password app"
echo "  2. Find item: $INITIAL_TITLE ($TEST_UUID)"
echo "  3. Right-click → Export → Copy as JSON"
echo "  4. Check for 'details.passkey' - IT SHOULD BE MISSING!"
echo ""
echo "  Expected corrupted state:"
echo "    ✅ overview.passkey: EXISTS (orphaned public metadata)"
echo "    ❌ details.passkey:  DELETED (private key destroyed)"
echo ""
echo "  Observable symptoms:"
echo "    • Safari will still offer to use the passkey"
echo "    • Authentication will FAIL (private key missing)"
echo "    • User has no indication passkey is corrupted"
echo ""
echo "=========================================="
echo "TEST COMPLETE"
echo "=========================================="
echo ""
echo "The passkey private key has been permanently destroyed."
echo "The item is now in a corrupted state."
echo "To fix: Delete the passkey in 1Password UI and re-register."
