# YubiKey Debugging Quick Reference

## One-Liners

```bash
# Check if password field exists in 1Password
bsec 1p yubikey scan --serial 24014076 -vv | grep -i "password"

# See all fields in the YubiKey item
bsec 1p yubikey scan -vv | grep "Field:"

# Test specific serial with debug
bsec 1p yubikey status -vv

# Manually verify password with ykman
ykman --device 24014076 oath info
ykman --device 24014076 oath accounts list --password "YOUR_PASSWORD"
```

## Verbosity Levels

| Flag | Output | Best For |
|------|--------|----------|
| (none) | Colored summary only | Normal operation |
| `-v` | Info: "Found password", item title, count | Quick diagnostics |
| `-vv` | Debug: All fields scanned, field attributes | Troubleshooting |
| `-vvv` | Extra verbose: Future use | Unknown issues |

## Key Log Messages to Look For

✓ **Success indicators:**
```
[YubiKey 24014076] Found item: My Security Key
[YubiKey 24014076] Found password via ID/purpose match
[YubiKey 24014076] Found 8 OATH accounts
```

✗ **Failure indicators:**
```
[YubiKey 24014076] No 1Password item found with serial
[YubiKey 24014076] OATH password field not found in 1Password item
[YubiKey 24014076] ykman command failed
[YubiKey 24014076] OATH password required but not provided or incorrect
```

## Field Structure (What to Expect)

```python
{
    "id": "password",                    # Could be missing!
    "purpose": "PASSWORD",               # Check this
    "label": "OATH Password",            # Common values:
                                         #   "OATH Password"
                                         #   "Account Password"  
                                         #   "Password"
    "value": "secret",                   # Hidden in logs
    "section": {
        "id": "details",
        "label": "Details"
    }
}
```

## Debugging Flowchart

```
bsec 1p yubikey scan -vv
        ↓
    Found item?
    ├─ NO → Serial in 1Password doesn't match (check with `ykman list --serials`)
    └─ YES
        ↓
    Found password?
    ├─ NO → Field name mismatch (check "Field:" lines for password patterns)
    └─ YES
        ↓
    Found OATH accounts?
    ├─ NO → Password incorrect or `ykman` not installed
    └─ YES → ✓ All working!
```

## Common Fixes

| Problem | Solution |
|---------|----------|
| "No 1Password item found" | `ykman list --serials` to get correct serial |
| "Password field not found" | Check 1Password item for password field, note exact label |
| "ykman command failed" | Verify `ykman` installed: `which ykman` |
| "OATH accounts: 0" | Password may be incorrect in 1Password |

## VS Code Debugger Hotkeys

| Action | Key |
|--------|-----|
| Start debug | F5 |
| Step over | F10 |
| Step into | F11 |
| Step out | Shift+F11 |
| Toggle breakpoint | Ctrl+K Ctrl+B or click margin |
| Evaluate expression | Ctrl+Shift+D then click "Debug Console" |
| View variables | Hover over variable |

## Debug Console Commands

In VS Code Debug Console, while paused at breakpoint:

```python
# View current field being examined
field

# Get specific attribute
field.get("label")
field.get("id")
field.get("value")

# Check if substring matches
"password" in field.get("label", "").lower()

# View all fields in account
account.fields_cache
```

## When to Use Each Tool

| Tool | When to Use |
|------|------------|
| `-v` flag | "I want to see what's happening at a high level" |
| `-vv` flag | "I want to see every field scanned" |
| VS Code Debugger | "I need to inspect variables step-by-step" |
| Manual ykman commands | "I want to verify the password works" |
| `op` CLI | "I want to see raw 1Password data" |

## Related Documentation

- Full guide: [YUBIKEY-DEBUG-GUIDE.md](./YUBIKEY-DEBUG-GUIDE.md)
 - Field format spec: [LABEL-FORMAT-SPECIFICATION.md](../reference/LABEL-FORMAT-SPECIFICATION.md)
 - 1Password integration: [1PASSWORD-DATA-MODEL-DECISIONS.md](../integration/1PASSWORD-DATA-MODEL-DECISIONS.md)
