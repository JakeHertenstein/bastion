# YubiKey TOTP Provisioning: Quick Reference Card

**Version**: 0.3.2+

## One-Minute Setup

```bash
# 1. Open YubiKey item in 1Password, add section:
[TOTP Configuration]
  Profile: Daily
  Capacity: 32

# 2. Tag accounts to include:
Bastion/2FA/TOTP/YubiKey/Include/Daily

# 3. Preview provisioning:
bsec 1p yubikey provision --serial 12345678 --dry-run

# 4. Provision (or add --no-touch for backup devices):
bsec 1p yubikey provision --serial 12345678

# 5. Verify:
bsec 1p yubikey scan --serial 12345678 --update
```

---

## Command Syntax

```bash
bsec 1p yubikey provision --serial <SN> [OPTIONS]

OPTIONS:
  --profile <NAME>    # Override profile from 1Password
  --dry-run          # Preview only (default)
  --no-touch         # Disable touch requirement
```

---

## Tag Format

| Tag | Meaning |
|-----|---------|
| `Bastion/2FA/TOTP/YubiKey/Include/Daily` | Include in Daily profile |
| `Bastion/2FA/TOTP/YubiKey/Include/Backup` | Include in Backup profile |
| `Bastion/2FA/TOTP/YubiKey/Exclude/Travel` | Exclude from Travel profile |

**Rules:**
- Accounts require `Include` tag (explicit opt-in)
- `Exclude` takes precedence
- Multiple profiles per account allowed

---

## Profile Examples

### Daily Carry
- All personal + work accounts
- Touch enabled
- 32 slots

### Backup Device
- Same as daily
- Touch disabled
- Kept in safe

### Travel Device
- Only critical accounts (Gmail, 2FA recovery)
- Touch enabled
- Tag others with: `Bastion/2FA/TOTP/YubiKey/Exclude/Travel`

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "No TOTP profile configured" | Add `[TOTP Configuration]` section to YubiKey item |
| "No accounts found" | Check accounts have correct `Include` tag |
| "Too many accounts" | Adjust tags; some accounts must be excluded |
| "URI invalid" | Verify TOTP secret is valid base32 in 1Password |

---

## Common Commands

```bash
# List all YubiKeys
bsec 1p yubikey list

# Check device status
bsec 1p yubikey status --serial 12345678

# Dry-run (always safe)
bsec 1p yubikey provision --serial 12345678 --dry-run

# Provision with touch (default, safe)
bsec 1p yubikey provision --serial 12345678

# Provision without touch (backup devices)
bsec 1p yubikey provision --serial 12345678 --no-touch

# Verify after provisioning
bsec 1p yubikey scan --serial 12345678 --update
```

---

## Key Facts

- ✅ 1Password is source of truth
- ✅ Tags control which accounts go to which devices
- ✅ Dry-run is always safe (nothing is written)
- ✅ Capacity is auto-enforced (32 or 64 slots)
- ✅ Touch requirement enabled by default
- ✅ Alphabetical sorting ensures deterministic slots

---

## Documentation Links

- **Full Guide**: [YUBIKEY-TOTP-PROVISIONING.md](docs/features/YUBIKEY-TOTP-PROVISIONING.md)
- **All Commands**: [CLI-COMMAND-REFERENCE.md](docs/reference/CLI-COMMAND-REFERENCE.md)
- **Tag Reference**: [BASTION-TAGGING-GUIDE.md](docs/security/BASTION-TAGGING-GUIDE.md)
- **Sync Alternative**: [YUBIKEY-SYNC-GUIDE.md](docs/features/yubikey/YUBIKEY-SYNC-GUIDE.md)

---

**Print this card** and keep it handy for YubiKey provisioning workflows!
