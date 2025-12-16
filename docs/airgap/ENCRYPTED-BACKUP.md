# Encrypted Backup Guide

This guide covers creating and managing LUKS-encrypted USB backups for GPG keys generated on the airgap machine.

## Overview

GPG key backups are critical for disaster recovery. Before transferring keys to YubiKey (which is irreversible), you must create secure backups of:

- Master secret key
- Subkeys (signing, encryption, authentication)
- Public key
- Revocation certificate

## Backup Strategy

### Recommended Approach

1. **Primary Backup**: LUKS-encrypted USB stored in home safe
2. **Secondary Backup**: LUKS-encrypted USB stored off-site (safe deposit box)
3. **Revocation Certificate**: Separate storage from keys

### Why LUKS?

- Full disk encryption with strong algorithms (AES-256-XTS)
- Standard Linux encryption (works on any Linux system)
- Password-based with optional hardware key factor
- Supports secure erase

## Creating a Backup

### Prerequisites

- USB drive (8GB+ recommended, dedicated for this purpose)
- Strong passphrase (see Passphrase Recommendations below)
- `cryptsetup` installed (standard on Linux, available on macOS via brew)

### Step 1: List Available Devices

```bash
airgap backup create --list-devices
```

This shows available USB devices. Identify your target device carefully.

**⚠️ WARNING**: The backup creation process will ERASE the entire device. Triple-check the device identifier.

### Step 2: Create Backup

```bash
airgap backup create --device /dev/diskN
```

You'll be prompted for:
1. Confirmation of device (shows size to help verify)
2. LUKS passphrase (entered twice)

The command then:
1. Creates LUKS2 container with strong parameters
2. Formats with ext4 filesystem
3. Exports GPG keys and revocation certificate
4. Generates manifest with checksums
5. Safely closes and unmounts

### LUKS Parameters Used

```
Cipher:     aes-xts-plain64
Key size:   512 bits (256-bit AES with XTS mode)
Hash:       sha512
PBKDF:      argon2id (memory-hard)
```

## Verifying a Backup

Always verify backups before relying on them:

```bash
airgap backup verify --device /dev/diskN
```

This:
1. Opens the LUKS container (requires passphrase)
2. Checks manifest exists
3. Verifies SHA-256 checksums of all files
4. Reports any mismatches or missing files

### Verification Output

```
✓ LUKS container opened
✓ Manifest found: backup_manifest.json
  Checking master-secret.asc... ✓
  Checking subkeys.asc... ✓
  Checking public.asc... ✓
  Checking revocation.asc... ✓
✓ All checksums verified
✓ Backup integrity confirmed
```

## Restoring from Backup

In case of YubiKey loss or failure:

### Step 1: Open Backup

```bash
# Linux
sudo cryptsetup open /dev/sdX bastion-backup
sudo mount /dev/mapper/bastion-backup /mnt/backup

# macOS (using FUSE)
# Requires additional setup - see macOS notes below
```

### Step 2: Import Keys

```bash
# Import master secret key
gpg --import /mnt/backup/master-secret.asc

# Import subkeys
gpg --import /mnt/backup/subkeys.asc

# Set ultimate trust
gpg --edit-key <KEY_ID>
> trust
> 5 (ultimate)
> quit
```

### Step 3: Transfer to New YubiKey

```bash
airgap keygen transfer-to-yubikey
```

### Step 4: Close Backup

```bash
sudo umount /mnt/backup
sudo cryptsetup close bastion-backup
```

## Passphrase Recommendations

### Diceware Method (Recommended)

Use physical dice to generate a random passphrase:

```bash
# Generate 6 diceware words
airgap generate entropy dice --words 6
```

Example: `horse battery staple correct osmium vulture`

**Strength**: 6 words ≈ 77 bits of entropy

### YubiKey Static Password (Optional Second Factor)

For additional security, combine diceware with a YubiKey static password:

1. Configure YubiKey slot 1 with a random static password
2. Use format: `<diceware phrase><YubiKey touch>`
3. This adds ~43 bits if using a 22-character ModHex string

### What NOT to Do

- ❌ Use passwords based on personal information
- ❌ Use short passwords (< 20 characters)
- ❌ Write passphrase on same storage as backup
- ❌ Store passphrase digitally on networked device
- ❌ Use the same passphrase for primary and secondary backups

## Backup Rotation

### Initial Setup

1. Create primary backup → Home safe
2. Create secondary backup (different passphrase) → Safe deposit box
3. Store passphrases securely and separately

### After Key Changes

When generating new keys or subkeys:

1. Update both backup copies
2. Verify both backups
3. Consider keeping previous backup briefly as transition safety

### Annual Verification

- Schedule annual backup verification
- Test full restoration in isolated environment
- Verify passphrase accessibility

## Secure Disposal

When retiring a backup device:

### Software Wipe

```bash
# Overwrite with random data
sudo dd if=/dev/urandom of=/dev/sdX bs=4M status=progress

# Or use secure-delete
sudo shred -vfz -n 3 /dev/sdX
```

### Physical Destruction

For highest security:
1. Software wipe first
2. Physical destruction (drill, shred, incinerate)

## Backup Contents

Each backup contains:

| File | Contents | Protection |
|------|----------|------------|
| `master-secret.asc` | Master secret key (Certify capability) | LUKS + GPG armor |
| `subkeys.asc` | S/E/A subkeys | LUKS + GPG armor |
| `public.asc` | Full public keyring | LUKS + GPG armor |
| `revocation.asc` | Pre-generated revocation certificate | LUKS + GPG armor |
| `backup_manifest.json` | Checksums and metadata | LUKS |

### Manifest Example

```json
{
  "created": "2024-01-15T10:30:00Z",
  "key_fingerprint": "ABCD1234...",
  "files": [
    {
      "name": "master-secret.asc",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "size": 4567
    },
    ...
  ]
}
```

## macOS Notes

macOS doesn't natively support LUKS. Options:

### Option 1: Use Linux VM

Run a Linux VM (Tails, Ubuntu) for backup operations.

### Option 2: Use cryptsetup via FUSE

```bash
# Install dependencies
brew install libgcrypt libfuse ext4fuse

# Note: This may require SIP modifications
```

### Option 3: Use macOS Disk Encryption

For macOS-only workflows, use APFS encrypted container:

```bash
# Create encrypted sparse bundle
hdiutil create -size 100m -encryption AES-256 -type SPARSEBUNDLE \
    -fs "Case-sensitive APFS" gpg-backup.sparsebundle
```

**Note**: This is less portable than LUKS but works natively on macOS.

## Troubleshooting

### "Device is busy"

```bash
# Check what's using the device
sudo lsof +D /dev/sdX
# or
sudo fuser -v /dev/sdX

# Force unmount if safe
sudo umount -f /dev/sdX1
```

### "Passphrase incorrect"

- Check for Caps Lock
- Try typing in a visible text field first
- Remember: passphrases are case-sensitive
- Check keyboard layout (especially for special characters)

### "LUKS header damaged"

If the LUKS header is corrupted:
- Use secondary backup
- LUKS header backup (if you made one separately)
- Recovery is difficult without header backup

### "Checksums don't match"

- May indicate bit rot or device failure
- Try re-exporting keys from GPG to a new backup
- Do not trust the corrupted backup

## Security Considerations

1. **Air-gapped creation**: Create backups only on air-gapped machine
2. **Verify before trusting**: Always verify backup integrity
3. **Separate storage**: Never store backup and passphrase together
4. **Physical security**: Use tamper-evident storage
5. **Access logging**: Consider who has access to storage locations
6. **Regular testing**: Verify you can actually restore from backups

## References

- [LUKS2 Specification](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS2-Specification)
- [cryptsetup Manual](https://linux.die.net/man/8/cryptsetup)
- [Diceware Passphrase](https://diceware.com/)
- [drduh YubiKey Guide - Backup](https://github.com/drduh/YubiKey-Guide#backup-keys)
