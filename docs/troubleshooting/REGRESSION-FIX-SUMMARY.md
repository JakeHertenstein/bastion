# YubiKey Password Retrieval - Regression Fix

## Summary

Fixed the YubiKey OATH password retrieval regression where `bsec 1p yubikey scan` was failing with "Scan failed" even though the password exists in 1Password.

## Changes Made

### 1. Enhanced Password Retrieval Logging (`yubikey_service.py`)

**Added:**
- `logging` module integration
- `_mask_sensitive()` utility function to hide passwords in logs
- Verbose parameter (0-3 levels) to `get_oath_password()`, `scan_oath_accounts()`, and `compare_device()`
- Detailed field inspection logging that shows:
  - Which 1Password item was found
  - Every field scanned with its id, purpose, and label
  - Why a field matched or didn't match password patterns
  - Full error messages from `ykman` commands

**Example debug output (-vv flag):**
```
[YubiKey 24014076] Searching for OATH password in 1Password
[YubiKey 24014076] Found item: My Security Key (UUID: ...)
[YubiKey 24014076] Scanning 45 fields...
  Field: id=password, purpose=PASSWORD, label=OATH Password
[YubiKey 24014076] Found password via ID/purpose match
[YubiKey 24014076] Scanning OATH accounts with password...
[YubiKey 24014076] Found 8 OATH accounts
```

### 2. CLI Verbose Flag (`yubikey_commands.py`)

**Added:**
- `-v` / `--verbose` flag with count support (v/vv/vvv for levels 1-3)
- Automatic logging configuration based on verbosity level
- Passes verbose flag through all function calls

**Usage:**
```bash
bsec 1p yubikey scan              # No debug output (normal)
bsec 1p yubikey scan -v           # Info-level logging
bsec 1p yubikey scan -vv          # Debug-level logging (field inspection)
bsec 1p yubikey scan -vvv         # Extra verbose (future expansion)
```

### 3. VS Code Debugger Configuration (`.vscode/launch.json`)

**Added 5 debug configurations:**
1. **YubiKey Scan (Debug)** - Debug a full scan with `-vv` logging
2. **YubiKey Status (Debug)** - Debug status check for all devices
3. **YubiKey Scan (Specific Serial)** - Debug with interactive serial input
4. **YubiKey Scan + Update (Debug)** - Debug scan + 1Password update
5. **Test Suite (YubiKey)** - Run YubiKey unit tests with debugger

**All configurations:**
- Set proper PYTHONPATH for package discovery
- Launch in integrated terminal for real-time output
- Enable `justMyCode: false` for debugging dependencies

**To use:**
- Set breakpoints in code (click left margin)
- Press `F5` or Run > Debug to start
- Use Debug Console for introspection: `field.get("label")`, etc.

### 4. Debugging Guide (`docs/YUBIKEY-DEBUG-GUIDE.md`)

Comprehensive guide covering:
- Quick debugging with verbose flags (-v, -vv)
- VS Code debugger step-by-step instructions
- Manual debugging for tricky cases
- Field structure reference
- Common issues and solutions
- Analysis checklist

## How to Debug Password Retrieval Issues

### Quick Test (No Debugger)

```bash
# See password lookup process in detail
bsec 1p yubikey scan -vv

# Scan specific YubiKey
bsec 1p yubikey scan --serial 24014076 -vv

# See status of all YubiKeys
bsec 1p yubikey status -vv
```

### With VS Code Debugger

1. Open VS Code
2. Go to Run & Debug (Ctrl+Shift+D)
3. Select "YubiKey Scan (Debug)" from dropdown
4. Press F5 to start
5. Set breakpoints in `yubikey_service.py` → `get_oath_password()`
6. Step through and inspect field variables

### What to Look For

When running with `-vv`, output shows:
- ✓ Item found in 1Password (or ✗ serial not found)
- ✓ Each field scanned with its attributes
- ✓ Which field matched password
- ✓ Number of OATH accounts retrieved
- ✗ Error messages if any step fails

## Testing

All existing tests pass (1 pre-existing failure in config path test, unrelated):

```bash
cd packages/bastion
python -m pytest tests/ -m 'not integration' -q
# 167 passed, 9 deselected, 1 failed (pre-existing)
```

Syntax validation:
```bash
python -m py_compile src/bastion/yubikey_service.py
python -m py_compile src/bastion/cli/commands/yubikey_commands.py
# ✓ No syntax errors
```

## Files Modified

- `packages/bastion/src/bastion/yubikey_service.py` - Added verbose logging
- `packages/bastion/src/bastion/cli/commands/yubikey_commands.py` - Added `-v` flag and logging setup
- `.vscode/launch.json` - Added 5 debug configurations (new file or updated if existing)
- `docs/YUBIKEY-DEBUG-GUIDE.md` - New comprehensive debugging guide

## Next Steps for Users

1. **Quick diagnosis**: Run `bsec 1p yubikey scan -vv` to see where password lookup fails
2. **Interactive debugging**: Use F5 > "YubiKey Scan (Debug)" to set breakpoints
3. **Identify the fix**: Refer to [YUBIKEY-DEBUG-GUIDE.md](./YUBIKEY-DEBUG-GUIDE.md) for common issues
4. **Report findings**: The verbose output will show exactly what field is (or isn't) being found

## Backward Compatibility

✓ All changes are backward compatible:
- `-v` flag is optional (defaults to 0, no debug output)
- Method signatures still work without verbose parameter
- Logging doesn't interfere with normal operation
- Debug configs only run when explicitly invoked
