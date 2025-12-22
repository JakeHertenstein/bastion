# YubiKey Password Retrieval Debugging Guide

## Overview

This guide helps debug YubiKey OATH password retrieval issues using the Bastion CLI with verbose logging and VS Code debugger.

## Issue: "Scan failed" with Password-Protected YubiKeys

When running `bsec 1p yubikey scan`, you may encounter:
- `[yellow]⚠ Scan failed[/yellow]` status
- OATH accounts not retrieved even though password exists in 1Password
- `ykman` failing with "password required" error

### Root Cause

The `get_oath_password()` method searches for a password field in the 1Password YubiKey item but may not find it if:
1. **Field name mismatch**: The password field has an unexpected label (not exactly "password")
2. **Missing field ID**: The field lacks the "password" ID or "PASSWORD" purpose attribute
3. **Wrong account**: The serial number doesn't match the YubiKey item in 1Password
4. **Cache stale**: The synced account data is outdated

## Quick Debugging with Verbose Output

### Level 1: Info-level logging (shows key steps)

```bash
bsec 1p yubikey scan -v
```

Output shows:
- Whether 1Password item was found for the serial
- If password field was located
- Number of OATH accounts found

### Level 2: Debug-level logging (field-by-field inspection)

```bash
bsec 1p yubikey scan -vv
```

Output includes:
- **Every field** in the YubiKey item with its id, purpose, and label
- Which field matched the password pattern
- Count of fields scanned
- Full error messages from `ykman`

### Example Debug Output

```
[YubiKey 24014076] Searching for OATH password in 1Password
[YubiKey 24014076] Found item: My Security Key (UUID: XXXXXXXXXXXX)
[YubiKey 24014076] Scanning 45 fields...
  Field: id=username, purpose=USERNAME, label=Email
  Field: id=password, purpose=PASSWORD, label=OATH Password
[YubiKey 24014076] Found password via ID/purpose match (label: OATH Password)
[YubiKey 24014076] Scanning OATH accounts with password...
[YubiKey 24014076] Found 8 OATH accounts
  - GitHub:jane.doe
  - GitLab:jane.doe
  ...
```

## VS Code Debugger Configurations

Pre-configured launch configurations are available in `.vscode/launch.json`.

### 1. YubiKey Scan with Debugger

**Command**: `F5` or Run > Debug > "YubiKey Scan (Debug)"

Sets breakpoints in:
- `YubiKeyService.get_oath_password()` to inspect field lookup
- `YubiKeyService.scan_oath_accounts()` to verify password is passed to `ykman`
- `yubikey_commands._yubikey_scan()` to see full flow

### 2. YubiKey Status with Debugger

**Command**: `F5` or Run > Debug > "YubiKey Status (Debug)"

Useful for checking all connected YubiKeys simultaneously.

### 3. Scan Specific Serial

**Command**: `F5` or Run > Debug > "YubiKey Scan (Specific Serial)"

Prompts for serial number (defaults to 24014076) and starts debugging.

### 4. YubiKey Scan + Update

**Command**: `F5` or Run > Debug > "YubiKey Scan + Update (Debug)"

Includes the `--update` flag to also update 1Password after scan.

### 5. Run Tests

**Command**: `F5` or Run > Debug > "Test Suite (YubiKey)"

Runs YubiKey-related tests with verbose output for test failures.

## Manual Debugging Steps

### Step 1: Check if item exists in 1Password

```bash
# List all YubiKey items
bsec 1p yubikey list

# If your serial is not there, sync and try again
bsec 1p yubikey scan --force-sync
```

### Step 2: Inspect fields in 1Password item

Run with debug output and copy the output. Look for:
- Does a field have `id=password` or `purpose=PASSWORD`?
- What is the exact `label=` value?
- Is the value shown or masked?

### Step 3: Set a breakpoint in the debugger

In VS Code:
1. Open `packages/bastion/src/bastion/yubikey_service.py`
2. Go to the `get_oath_password()` method
3. Click left margin to set breakpoint at line that checks `field_id == "password"`
4. Start debug session: `F5` > "YubiKey Scan (Debug)"
5. When breakpoint hits, inspect `field` variable:
   - Hover over `field` to see all attributes
   - Use Debug Console to run: `field.get("label")`, `field.get("id")`, etc.

### Step 4: Trace through the password lookup

Fields in `account.fields_cache` have this structure:

```python
{
  "id": "password",              # Field ID in 1Password schema
  "purpose": "PASSWORD",         # Field purpose (if set)
  "label": "OATH Password",      # Display label
  "value": "my-secret-password", # The actual password (hidden in logs)
  "section": {                   # Section info
    "id": "details",
    "label": "Details"
  }
}
```

**Common issues:**
- `id` is not "password" (check actual value in debugger)
- `label` contains spaces or special characters
- `value` is empty even though field exists
- Field is in a section that's not being iterated

## Fixing the Issue

Once you identify the problem using verbose logging:

### Issue: Wrong field label

If the password field has `label="Account Password"` instead of containing "password":

**Solution**: Update the search pattern in `get_oath_password()`:

```python
# In yubikey_service.py, in get_oath_password():
if "password" in field_label.lower():  # Already handles case-insensitive
    # This should match "Account Password", "OATH Password", etc.
```

If it's not matching, add more flexible matching:

```python
if field_label.lower() in ["account password", "oath password", "password"]:
    password = field.get("value")
    if password:
        return password
```

### Issue: Password field in wrong section

If the password is in a section that's not being indexed:

Debug output will show which section. Update 1Password item to move password field to main "Details" section.

### Issue: Serial doesn't match

If `[YubiKey {serial}] No 1Password item found`, the serial in 1Password doesn't match your physical YubiKey:

```bash
# Check connected serials
ykman list --serials

# Verify the SN field value in the 1Password item matches exactly
bsec 1p yubikey scan -vv
```

## Logging Output Analysis Checklist

When running `bsec 1p yubikey scan -vv`, look for:

- [ ] `Found item: {title}` — Item exists and serial matched
- [ ] `Scanning N fields` — How many fields are in the item
- [ ] `Found password via...` — Password was located
- [ ] `Found X OATH accounts` — Device scan succeeded
- [ ] No `[red]✗ Error` messages — No crashes

If any step is missing, the issue is at that point.

## Running Manual Commands

To verify the pieces independently:

```bash
# Check if device requires password
ykman --device 24014076 oath info

# Test password manually
ykman --device 24014076 oath accounts list --password "my-password"

# Get raw item from 1Password (to inspect fields)
op item get <UUID> --format json | jq '.fields'
```

## Environment Variables

For advanced debugging:

```bash
# Enable Python verbose mode
PYTHONVERBOSE=1 bsec 1p yubikey scan -vv

# Enable debug logging from dependencies
DEBUG=bastion.* bsec 1p yubikey scan -vv
```

## Related Files

- [`packages/bastion/src/bastion/yubikey_service.py`](https://github.com/jakehertenstein/bastion/blob/main/packages/bastion/src/bastion/yubikey_service.py) — Core password retrieval logic
- [`packages/bastion/src/bastion/cli/commands/yubikey_commands.py`](https://github.com/jakehertenstein/bastion/blob/main/packages/bastion/src/bastion/cli/commands/yubikey_commands.py) — CLI integration
- [`.vscode/launch.json`](https://github.com/jakehertenstein/bastion/blob/main/.vscode/launch.json) — Debugger configurations
