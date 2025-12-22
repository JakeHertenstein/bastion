# Next Steps: Debugging Your YubiKey Issue

## Start Here

You mentioned getting "Scan failed" even though the OATH password exists in 1Password. Here's how to diagnose:

### Step 1: Run with Debug Output (30 seconds)

```bash
bsec 1p yubikey scan -vv
```

This will show:
- Whether the 1Password item was found for your YubiKey
- Every field in that item (with its id, purpose, and label)
- Whether a password field was found and matched
- Any error messages from the `ykman` command

**Look for these lines in output:**
```
[YubiKey 24014076] Found item: ...
[YubiKey 24014076] Found password via ...
[YubiKey 24014076] Found X OATH accounts
```

### Step 2: Screenshot the Output

Copy the full output from `-vv`. This will show exactly:
- Which fields exist in the 1Password item
- What labels/IDs they have
- Why the password lookup succeeded or failed

### Step 3: If Still Failing, Use the Debugger (VS Code)

1. Open the workspace in VS Code
2. Go to Run & Debug (Ctrl+Shift+D or Cmd+Shift+D on Mac)
3. From the dropdown, select **"YubiKey Scan (Debug)"**
4. Press **F5** or click the green play button
5. When it pauses at a breakpoint, inspect the `field` variable (hover over it)

This lets you see exactly what 1Password fields are available.

## What the Fix Provides

✓ **Verbose logging** - See the password lookup process step-by-step
✓ **Debug configurations** - One-click debugging in VS Code  
✓ **Comprehensive guide** - [YUBIKEY-DEBUG-GUIDE.md](../troubleshooting/YUBIKEY-DEBUG-GUIDE.md) for reference

## Common Issues (From the Debug Output)

### Issue 1: "No 1Password item found with serial"
```bash
# Verify your serial matches
ykman list --serials

# Sync 1Password
bsec 1p yubikey scan --force-sync -vv
```

### Issue 2: "Password field not found in 1Password"
The field exists but its name doesn't match patterns. Look at the `-vv` output for a field with `label="..."` that contains "password". Then check 1Password directly:
```bash
op item get <item-uuid> --format json | jq '.fields[] | select(.label | contains("password"; "i"))'
```

### Issue 3: "ykman command failed"
Ensure ykman is installed and the YubiKey is connected:
```bash
which ykman
ykman --device <your-serial> oath info
```

## Documentation

- **Quick reference**: [YUBIKEY-DEBUG-QUICK-REF.md](../troubleshooting/YUBIKEY-DEBUG-QUICK-REF.md) - One-page cheat sheet
- **Full guide**: [YUBIKEY-DEBUG-GUIDE.md](../troubleshooting/YUBIKEY-DEBUG-GUIDE.md) - Complete troubleshooting guide
- **Summary**: [REGRESSION-FIX-SUMMARY.md](../troubleshooting/REGRESSION-FIX-SUMMARY.md) - What was fixed

## Examples

### Debugging a specific YubiKey
```bash
bsec 1p yubikey scan --serial 24014076 -vv
```

### Checking all YubiKeys at once
```bash
bsec 1p yubikey status -vv
```

### Scan and update with debug info
```bash
bsec 1p yubikey scan --update -vv
```

## Need More Help?

1. Run `bsec 1p yubikey scan -vv` and note the output
2. Open [YUBIKEY-DEBUG-GUIDE.md](../troubleshooting/YUBIKEY-DEBUG-GUIDE.md) and follow the "Manual Debugging Steps" section
3. Use VS Code debugger to inspect the `get_oath_password()` method
4. Check if the password field exists in your 1Password YubiKey item (may need to add it if missing)

## Success Indicators

When everything works, you'll see:
```
[YubiKey 24014076] Found item: My YubiKey
[YubiKey 24014076] Found password via ID/purpose match (label: OATH Password)
[YubiKey 24014076] Scanning OATH accounts with password...
[YubiKey 24014076] Found 8 OATH accounts
  - GitHub:username
  - GitLab:username
  ...
✓ In sync (8 accounts)
```

---

**TL;DR**: Run `bsec 1p yubikey scan -vv` to see exactly where password retrieval fails, then refer to [YUBIKEY-DEBUG-GUIDE](../troubleshooting/YUBIKEY-DEBUG-GUIDE.md) for solutions.
