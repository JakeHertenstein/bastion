# 🚨 CRITICAL BUG: Passkey Data Loss During JSON Round-Trip

**Reported**: 2025-12-07  
**CLI Version**: 2.32.0  
**Severity**: CRITICAL - Irreversible data loss  
**Status**: Acknowledged by 1Password Support (behavior "expected" but creates corrupted state)

---

## Summary

**A pure JSON round-trip (`op item get --format json | op item edit <uuid>`) permanently deletes passkey data from LOGIN items.**

The WebAuthn/FIDO2 private key is destroyed and cannot be recovered.

---

## 1Password Support Response

> "Technically, this behavior is expected, but I completely understand why it feels like a bug."

### Why "Expected Behavior" Is Still a Bug

This is not merely "feeling like a bug" - it creates a **corrupted data state** that causes downstream failures. A round-trip edit (get → edit with no changes) should be **idempotent** and safe. Instead:

| Issue | Impact |
|-------|--------|
| **Silent data destruction** | No warning, no confirmation, no error message |
| **Orphaned metadata** | `overview.passkey` remains while `details.passkey` is deleted |
| **Authentication failures** | Safari offers the passkey, user attempts to use it, auth fails |
| **Violated expectations** | The documented workflow implies all data is preserved |
| **No recovery path** | The private key is permanently lost |

### Required Fix

If the CLI cannot preserve passkey data during editing, it should either:

1. **Refuse** to edit items with passkeys via JSON stdin (with clear error message)
2. **Warn** before proceeding with destructive operation
3. **Preserve** fields not present in input (merge semantics instead of replace)

The current behavior is a **data integrity violation**, not a feature.

---

## Integration Test Script

Save as `integration-test-passkey-roundtrip.sh` and run to demonstrate the bug:

```bash
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

set -e

# Configuration - UPDATE THIS with your test item UUID
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
```

### Running the Test

```bash
# Make executable
chmod +x integration-test-passkey-roundtrip.sh

# Run with default test UUID
./integration-test-passkey-roundtrip.sh

# Or specify a different UUID
./integration-test-passkey-roundtrip.sh "your-item-uuid-here"
```

---

## Reproduction Steps

```bash
# 1. Start with a LOGIN item that has a passkey
op item get <uuid-with-passkey> --format json > /tmp/before.json

# 2. Pure round-trip - NO modifications to the JSON
cat /tmp/before.json | op item edit <uuid-with-passkey>

# 3. Result: Passkey is DELETED from the item
```

Note: Both `op item edit <uuid>` and `op item edit <uuid>` produce identical results when piping JSON.

---

## Evidence

### Test Item

- **UUID**: `hqguqsaovlalodxkabkzujska4`
- **Title**: Autofill
- **URL**: autofill.me
- **Had passkey**: Yes (FIDO2/WebAuthn)

### Before Round-Trip (exported from 1Password UI)

```json
{
  "overview": {
    "passkey": {
      "credentialId": "bC_HcuI8JIieZedDG-zn1UlAJQhtVSaNGILKcJ1M",
      "userHandle": "e7f8Z0OqKitOV_yf-Z1V8Q8yiGbHdWWhVsmV8uW0hfI",
      "rpId": "autofill.me"
    }
  },
  "details": {
    "passkey": {
      "type": "webauthn",
      "createdAt": 1765121634,
      "privateKey": "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwiZCI6InJtRmd...<EC P-256 PRIVATE KEY>",
      "userHandle": "e7f8Z0OqKitOV_yf-Z1V8Q8yiGbHdWWhVsmV8uW0hfI"
    },
    "fields": [
      {
        "value": "1@email.com",
        "id": "identifier",
        "name": "",
        "type": "T",
        "designation": "username"
      }
    ]
  }
}
```

### CLI Output (`op item get --format json`)

```json
{
  "id": "hqguqsaovlalodxkabkzujska4",
  "title": "Autofill",
  "category": "LOGIN",
  "fields": [
    {"id": "username", "type": "STRING", "purpose": "USERNAME", "value": "1@email.com"},
    {"id": "password", "type": "CONCEALED", "purpose": "PASSWORD"},
    {"id": "notesPlain", "type": "STRING", "purpose": "NOTES"}
  ]
}
```

**⚠️ NOTE: No passkey data anywhere in CLI JSON output!**

### After Round-Trip (exported from 1Password UI)

```json
{
  "overview": {
    "passkey": {
      "credentialId": "bC_HcuI8JIieZedDG-zn1UlAJQhtVSaNGILKcJ1M",
      "rpId": "autofill.me",
      "userHandle": "e7f8Z0OqKitOV_yf-Z1V8Q8yiGbHdWWhVsmV8uW0hfI"
    }
  },
  "details": {
    "fields": [...],
    "notesPlain": "",
    "passwordHistory": [],
    "sections": []
  }
}
```

**❌ The `details.passkey` object is GONE - the WebAuthn private key has been permanently deleted!**

---

## Root Cause Analysis

1. `op item get --format json` does **NOT** include passkey data in its output
2. `op item edit <uuid>` interprets missing data as "delete this field"
3. Result: The passkey's WebAuthn private key is permanently destroyed

This is a **replace** semantic rather than a **merge** semantic. The CLI treats the input JSON as the complete desired state, not as a partial update.

### Official Documentation Conflict

The 1Password CLI documentation explicitly supports this workflow:

```
EDIT AN ITEM USING A TEMPLATE

1. Get the item you want to edit in JSON format and save it to a file:
        op item get oldLogin --format=json > updatedLogin.json

2. Edit the file.

3. Use the '--template' flag to specify the path to the edited file:
        op item edit oldLogin --template=updatedLogin.json

You can also edit an item using piped input:
        cat updatedLogin.json | op item edit oldLogin
```

**The documented workflow assumes `op item get --format=json` returns all item data.** Since passkey data is omitted from the output, the workflow silently destroys it.

### No Recovery Options

- `op item get` has no `--include-passkey` or similar flag
- CLI does not expose item version history
- No way to recover deleted passkey data via CLI

---

## Impact

| Aspect | Details |
|--------|---------|
| **Severity** | CRITICAL |
| **Data Lost** | WebAuthn/FIDO2 EC P-256 private keys |
| **Reversible** | NO - private key is destroyed, CLI has no history access |
| **User Impact** | Must re-register passkey with each affected service |
| **Scope** | Any LOGIN item with passkey edited via `op item edit -` |

### Broken State Created

The bug creates a **corrupt/orphaned passkey state**:

| Location | Data | Status |
|----------|------|--------|
| `overview.passkey` | Metadata (credentialId, rpId) | ✅ Preserved |
| `details.passkey` | Private key (EC P-256) | ❌ **DELETED** |

**Observed Behavior**:

| Component | Shows Passkey? | Authentication Works? |
|-----------|----------------|----------------------|
| macOS 1Password app | ❌ No | N/A |
| Safari extension | ✅ Yes (offers to use) | ❌ **Fails** |

This is **worse than complete deletion** because:
1. User sees passkey offered in Safari autofill
2. User attempts to authenticate with it
3. Authentication fails (private key missing)
4. User has no indication the passkey is corrupted
5. User doesn't know to re-register

---

## Workaround

### DO NOT USE `op item edit <uuid>` ON ITEMS WITH PASSKEYS

For items with passkeys, use only field assignment syntax:

```bash
# ✅ SAFE - only modifies the specific field
op item edit <uuid> "Section.Field[text]=value"
op item edit <uuid> --tags "new-tag"

# ❌ UNSAFE - deletes passkey!
cat item.json | op item edit <uuid>
op item get <uuid> --format json | op item edit <uuid>
```

### Detection

Before editing, check if item has a passkey:

```bash
# This will NOT show passkey (that's the bug), but you can check UI
# or maintain a list of items known to have passkeys
```

---

## Requested Fix Options

### Option A: Merge semantics instead of replace (Preferred)
`op item edit` with piped/template JSON should preserve fields not present in input JSON, rather than deleting them. This is the safest fix as it:
- Prevents accidental deletion of any data not in CLI output
- Maintains backward compatibility for existing workflows
- Doesn't require exposing sensitive passkey private keys in CLI output

### Option B: Add explicit delete syntax
Require explicit `"fieldName": null` or similar syntax to delete fields. Missing fields should be left unchanged.

### Option C: Add safety flag
Add `--preserve-passkey` or `--no-delete-missing` flag to prevent accidental deletion of data not in the input JSON.

### Option D: Warning/confirmation
When `op item edit -` would delete a passkey, prompt for confirmation or show a warning.

---

## Questions for 1Password Support

1. Is this behavior intentional or a bug?

2. Is there a way to include passkey data in the CLI JSON output?

3. Is there a safe way to add fields (like REFERENCE links) to items with passkeys via CLI?

4. Are there other item types/fields that are similarly excluded from CLI output and would be deleted on round-trip?

5. Can passkey data be restored from 1Password's item history via UI or API?

---

## Investigation Notes

### CLI Flags Checked

```bash
$ op item get --help
# No --include-passkey, --full, or similar flag exists
# Available: --fields, --otp, --reveal, --share-link, --vault

$ op item --help
# Subcommands: create, get, edit, delete, list, move, share, template
# No "history" or "restore" command
```

### Version History

```bash
$ op item get <uuid> --format json | jq '.version'
4  # Item is at version 4, but no way to access previous versions via CLI
```

### Passkey Data Location

The passkey private key is stored in `details.passkey.privateKey` (Base64-encoded JWK):
```json
{
  "details": {
    "passkey": {
      "type": "webauthn",
      "createdAt": 1765121634,
      "privateKey": "eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwiZCI6Ii4uLiJ9",
      "userHandle": "..."
    }
  }
}
```

This entire object is missing from `op item get --format json` output.

---

## Related Files

- `test - before.json` - Full item export before round-trip (with passkey)
- `test - after.json` - Full item export after round-trip (passkey deleted)
