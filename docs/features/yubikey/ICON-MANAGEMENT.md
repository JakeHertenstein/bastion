# Icon Management

## Overview

Bastion integrates [aegis-icons](https://github.com/twofactor/aegis-icons) to provide consistent, recognizable icons for YubiKey OATH accounts in 1Password. Icons are embedded as file attachments to YubiKey device items and OATH account entries.

## Why Icons Matter

- **Visual Identification**: Quickly recognize accounts in OATH listings without reading issuer names.
- **Consistency**: Same icon across 1Password, YubiKey apps, and backup documentation.
- **Professional Appearance**: Polished OATH displays in 1Password and backups.

## Icon Sources

Bastion uses the [aegis-icons](https://github.com/twofactor/aegis-icons) pack, organized by type:

| Category | Purpose | Count |
|----------|---------|-------|
| `1_Primary/` | Standard issuer logos | ~500+ |
| `2_Variations/` | Alternative styles (grayscale, outlined) | ~300+ |
| `3_Generic/` | Fallback generic icons (gray circles, letters) | ~50 |
| `4_Outdated/` | Legacy/deprecated service logos | ~100 |

## Icon Matching Strategy

Bastion attempts to auto-match OATH issuer names to icon files using:

1. **Exact Match**: `"GitHub"` → `github.png`
2. **Lowercase Match**: `"GitHub"` → `github.png` (case-insensitive)
3. **Custom Aliases**: `"Gmail"` → `google.png` (hardcoded mappings)
4. **Fallback**: Generic letter/circle icon if no match found

### Custom Aliases (Hardcoded)

```python
ISSUER_ICON_ALIASES = {
    "Gmail": "google.png",
    "Google": "google.png",
    "iCloud": "apple.png",
    "Apple": "apple.png",
    "OneDrive": "microsoft.png",
    "Microsoft": "microsoft.png",
    # ... add more as needed
}
```

## Commands

### View Icon Coverage

```bash
# Show how many OATH accounts have matched icons
bsec 1p icons status

# Sample output:
# OATH Accounts with Icons: 42/156 (27%)
# Missing Icons (no match): 114
```

### Scan for Missing Icons

```bash
# Find OATH accounts without matched icons
bsec 1p icons scan

# Sample output:
# MISSING ICONS:
# - MyBank (no match found)
# - Custom Service (fallback: generic)
# ...
```

### Apply Icons to Items

```bash
# Apply icon to a specific YubiKey or OATH account item
bsec 1p icons apply --item-id abc123

# Batch apply to all items needing icons
bsec 1p icons apply --all

# Apply with a specific source (if custom icons added)
bsec 1p icons apply --item-id abc123 --source aegis
```

### Icon Storage in 1Password

Icons are stored as:
- **File Attachments**: Embedded PNG files on YubiKey device items and OATH account entries.
- **Attachment Naming**: `icon_<issuer>.png` (e.g., `icon_github.png`).
- **Metadata Field**: Optional `icon_source` field notes the source (aegis, custom, fallback).

## Integration with Recovery Bags

Exported recovery documentation includes a reference sheet of icons for issuer identification:

```bash
# Export OATH documentation with icons
bsec 1p export oath-backup --include-icons

# Output: backup-oath-icons.pdf with visual identifier sheet
```

## Extending with Custom Icons

To add custom icons for services not in aegis-icons:

1. **Prepare PNG file**: 512×512 pixels, transparent background.
2. **Place in custom folder**: `~/.bsec/custom-icons/myservice.png`
3. **Update alias mapping**: Edit `~/.bsec/config.toml`:
   ```toml
   [icons]
   custom_paths = ["~/.bsec/custom-icons"]
   aliases = { "My Service" = "myservice.png" }
   ```
4. **Rescan and apply**: `bsec 1p icons scan --refresh`

## Troubleshooting

### Icon Not Appearing

- **Check match**: Run `bsec 1p icons scan` to see if issuer is recognized.
- **Verify attachment**: In 1Password, confirm the icon file is present in item attachments.
- **Refresh**: Some 1Password clients require a refresh to display newly attached files.

### Icons Too Small or Pixelated

- **Source resolution**: Aegis-icons are optimized for ~48px display; 1Password renders them at various sizes.
- **Custom icons**: Provide 512×512 PNG for best compatibility.

### Batch Apply Fails Partway

- **Resume**: Run again with `--resume` flag to skip already-processed items.
- **Check logs**: Review error messages for specific item IDs that failed.

## See Also

- [Aegis Icons Repository](https://github.com/twofactor/aegis-icons) — Source and maintainer.
- [YubiKey Sync Guide](./YUBIKEY-SYNC-GUIDE.md) — OATH account sync with optional icon sync.
- [1PASSWORD-DATA-MODEL-DECISIONS.md](../../integration/1PASSWORD-DATA-MODEL-DECISIONS.md) — Attachment storage model.
