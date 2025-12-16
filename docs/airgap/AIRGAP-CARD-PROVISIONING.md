# Air-Gap Card Provisioning Guide

**Version:** 1.0  
**Date:** 2025-12-09  
**Prerequisites:** Linux system with `cryptsetup`, `parted`, `attr` packages

## Overview

This guide documents the step-by-step process for provisioning microSD cards for the air-gap system. Each card uses a two-partition scheme:

1. **Partition 1** (1MB, ext4, unencrypted): Card identification via extended attributes
2. **Partition 2** (remainder, LUKS2 or ext4): Domain-specific data storage

---

## Partition Scheme

### Encrypted Cards (SECRETS, BACKUP, AUDIT)

```
┌─────────────────────────────────────────────────────────────────┐
│ GPT Header                                                      │
├─────────────────────────────────────────────────────────────────┤
│ Partition 1: AIRGAP-ID (1MB, ext4)                             │
│   └── airgap-card.id                                           │
│       └── xattr: user.bastion.label = "Bastion/Airgap/..."     │
├─────────────────────────────────────────────────────────────────┤
│ Partition 2: AIRGAP-{DOMAIN} (remainder, LUKS2)                │
│   └── ext4 filesystem (after LUKS open)                        │
│       └── airgap-card.json (full metadata)                     │
└─────────────────────────────────────────────────────────────────┘
```

### Unencrypted Cards (OS, SCRATCH, PARITY)

```
┌─────────────────────────────────────────────────────────────────┐
│ GPT Header                                                      │
├─────────────────────────────────────────────────────────────────┤
│ Partition 1: AIRGAP-ID (1MB, ext4)                             │
│   └── airgap-card.id                                           │
│       └── xattr: user.bastion.label = "Bastion/Airgap/..."     │
├─────────────────────────────────────────────────────────────────┤
│ Partition 2: AIRGAP-{DOMAIN} (remainder, ext4 or SquashFS)     │
│   └── airgap-card.json (full metadata)                         │
└─────────────────────────────────────────────────────────────────┘
```

---

## Step-by-Step Provisioning

### Prerequisites

```bash
# Install required packages (Debian/Ubuntu)
sudo apt install parted cryptsetup attr gdisk e2fsprogs

# Verify card device (DANGEROUS: double-check this is the right device!)
lsblk
# Look for your microSD card, typically /dev/sdX or /dev/mmcblkX
```

### Step 1: Identify Card Device

```bash
# Set device variable (CRITICAL: verify this is correct!)
export CARD_DEV="/dev/sdX"

# Verify it's the right card
sudo fdisk -l $CARD_DEV
```

### Step 2: Wipe and Create GPT Partition Table

```bash
# Wipe existing partitions (WARNING: destroys all data!)
sudo wipefs -a $CARD_DEV
sudo sgdisk --zap-all $CARD_DEV

# Create new GPT partition table
sudo sgdisk --clear $CARD_DEV
```

### Step 3: Create Partitions

```bash
# Create 1MB identification partition
sudo sgdisk --new=1:2048:4095 --typecode=1:8300 --change-name=1:"AIRGAP-ID" $CARD_DEV

# Create main data partition (rest of card)
sudo sgdisk --new=2:4096:0 --typecode=2:8300 --change-name=2:"AIRGAP-SECRETS" $CARD_DEV

# Verify partition layout
sudo sgdisk --print $CARD_DEV
```

### Step 4: Format Identification Partition

```bash
# Format partition 1 as ext4
sudo mkfs.ext4 -L "AG-ID" ${CARD_DEV}1

# Mount identification partition
sudo mkdir -p /mnt/card-id
sudo mount ${CARD_DEV}1 /mnt/card-id
```

### Step 5: Create Identification File with Extended Attributes

```bash
# Set card parameters
export DOMAIN="SECRETS"
export SITE="home"
export ROLE="master"
export DATE="2025-12-09"
export FULL_LABEL="Bastion/Airgap/CARD/${DOMAIN}:${SITE}.${ROLE}:${DATE}#VERSION=1"

# Calculate Luhn mod-36 check digit (use bastion tool or manual)
# For now, placeholder - replace |X with actual check digit
export FULL_LABEL_WITH_CHECK="${FULL_LABEL}|M"

# Create identification file
echo "AG-${DOMAIN}" | sudo tee /mnt/card-id/airgap-card.id

# Set extended attribute with full label
sudo setfattr -n user.bastion.label -v "$FULL_LABEL_WITH_CHECK" /mnt/card-id/airgap-card.id

# Verify extended attribute
getfattr -n user.bastion.label /mnt/card-id/airgap-card.id

# Set immutable attribute to prevent modification
sudo chattr +i /mnt/card-id/airgap-card.id

# Unmount
sudo umount /mnt/card-id
```

### Step 6a: Format Data Partition (Encrypted Cards)

For SECRETS, BACKUP, AUDIT cards:

```bash
# Create LUKS2 encrypted container
sudo cryptsetup luksFormat \
    --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha512 \
    --pbkdf argon2id \
    --label "AIRGAP-${DOMAIN}" \
    ${CARD_DEV}2

# Open encrypted container
sudo cryptsetup luksOpen ${CARD_DEV}2 airgap_${DOMAIN,,}

# Format as ext4
sudo mkfs.ext4 -L "AG-${DOMAIN}" /dev/mapper/airgap_${DOMAIN,,}

# Mount
sudo mkdir -p /mnt/${DOMAIN,,}
sudo mount /dev/mapper/airgap_${DOMAIN,,} /mnt/${DOMAIN,,}
```

### Step 6b: Format Data Partition (Unencrypted Cards)

For OS, SCRATCH, PARITY cards:

```bash
# Format as ext4 directly
sudo mkfs.ext4 -L "AG-${DOMAIN}" ${CARD_DEV}2

# Mount
sudo mkdir -p /mnt/${DOMAIN,,}
sudo mount ${CARD_DEV}2 /mnt/${DOMAIN,,}
```

### Step 7: Create Metadata File

```bash
# Get LUKS UUID (for encrypted cards)
if [ -e "/dev/mapper/airgap_${DOMAIN,,}" ]; then
    LUKS_UUID=$(sudo cryptsetup luksUUID ${CARD_DEV}2)
else
    LUKS_UUID="N/A"
fi

# Get filesystem UUID
FS_UUID=$(sudo blkid -s UUID -o value ${CARD_DEV}2 || echo "N/A")

# Create metadata JSON
cat << EOF | sudo tee /mnt/${DOMAIN,,}/airgap-card.json
{
    "label": "${FULL_LABEL_WITH_CHECK}",
    "domain": "${DOMAIN}",
    "site": "${SITE}",
    "role": "${ROLE}",
    "date": "${DATE}",
    "version": 1,
    "hardware": {
        "brand": "SanDisk",
        "model": "SDSDQAF3-008G-I",
        "serial": "TODO_ENTER_SERIAL",
        "capacity_gb": 8
    },
    "security": {
        "encrypted": $([ "$LUKS_UUID" != "N/A" ] && echo "true" || echo "false"),
        "luks_uuid": "${LUKS_UUID}",
        "fs_uuid": "${FS_UUID}",
        "fs_label": "AG-${DOMAIN}",
        "gpt_label": "AIRGAP-${DOMAIN}"
    },
    "verification": {
        "created": "${DATE}",
        "last_verified": "${DATE}",
        "checksum": "TODO_CALCULATE"
    }
}
EOF

# Verify JSON is valid
cat /mnt/${DOMAIN,,}/airgap-card.json | python3 -m json.tool
```

### Step 8: Finalize and Unmount

```bash
# Sync writes
sync

# For encrypted cards, close LUKS
if [ -e "/dev/mapper/airgap_${DOMAIN,,}" ]; then
    sudo umount /mnt/${DOMAIN,,}
    sudo cryptsetup luksClose airgap_${DOMAIN,,}
else
    sudo umount /mnt/${DOMAIN,,}
fi

# Verify card can be detected
sudo blkid ${CARD_DEV}*
```

---

## Card-Specific Configurations

### OS Card (Unencrypted, SquashFS)

```bash
export DOMAIN="OS"
export SITE="home"
export ROLE="live"

# After Step 6b, copy golden image instead of creating airgap-card.json
# The OS card has a special structure for SquashFS boot
```

### SCRATCH Card (Unencrypted, tmpfs at runtime)

```bash
export DOMAIN="SCRATCH"
export SITE="home"
export ROLE="temp"

# Partition 2 is formatted but mostly unused
# Actual scratch space is tmpfs in RAM at runtime
```

### SECRETS Card (Encrypted, Critical)

```bash
export DOMAIN="SECRETS"
export SITE="home"
export ROLE="master"

# Use strong passphrase
# Store passphrase hint in 1Password (NOT the passphrase itself)
```

### BACKUP Card (Encrypted)

```bash
export DOMAIN="BACKUP"
export SITE="home"
export ROLE="full"

# Can use same passphrase as SECRETS or different
```

### AUDIT Card (Optionally Encrypted)

```bash
export DOMAIN="AUDIT"
export SITE="home"
export ROLE="logs"

# After provisioning, set append-only on log directory:
# sudo chattr +a /mnt/audit/logs/
```

### PARITY Card (Unencrypted)

```bash
export DOMAIN="PARITY"
export SITE="home"
export ROLE="recovery"

# Contains par2 recovery files
# Set immutable after writing:
# sudo chattr -R +i /mnt/parity/
```

---

## Card Detection Script

After provisioning, cards can be detected automatically:

```bash
#!/bin/bash
# detect-airgap-card.sh - Detect and identify air-gap cards

detect_cards() {
    echo "Scanning for air-gap cards..."
    
    for dev in /dev/sd?1 /dev/mmcblk?p1; do
        [ -e "$dev" ] || continue
        
        # Check for AIRGAP-ID partition label
        PARTLABEL=$(lsblk -no PARTLABEL "$dev" 2>/dev/null)
        if [ "$PARTLABEL" = "AIRGAP-ID" ]; then
            echo "Found air-gap card at ${dev%1}"
            
            # Mount and read label
            TMPDIR=$(mktemp -d)
            mount -o ro "$dev" "$TMPDIR" 2>/dev/null
            
            if [ -f "$TMPDIR/airgap-card.id" ]; then
                SHORT_ID=$(cat "$TMPDIR/airgap-card.id")
                FULL_LABEL=$(getfattr -n user.bastion.label --only-values "$TMPDIR/airgap-card.id" 2>/dev/null)
                
                echo "  Short ID: $SHORT_ID"
                echo "  Label:    $FULL_LABEL"
            fi
            
            umount "$TMPDIR"
            rmdir "$TMPDIR"
        fi
    done
}

detect_cards
```

---

## Verification Procedures

### Verify Card Identity

```bash
# Mount identification partition
sudo mount -o ro ${CARD_DEV}1 /mnt/card-id

# Read and display label
echo "Short ID:"
cat /mnt/card-id/airgap-card.id

echo "Full Label:"
getfattr -n user.bastion.label --only-values /mnt/card-id/airgap-card.id

# Verify immutable attribute
lsattr /mnt/card-id/airgap-card.id
# Should show: ----i--------e-- /mnt/card-id/airgap-card.id

sudo umount /mnt/card-id
```

### Verify LUKS Container

```bash
# Check LUKS header
sudo cryptsetup luksDump ${CARD_DEV}2

# Verify UUID matches records
sudo cryptsetup luksUUID ${CARD_DEV}2
```

### Verify Data Integrity

```bash
# Open and mount
sudo cryptsetup luksOpen ${CARD_DEV}2 verify_card
sudo mount -o ro /dev/mapper/verify_card /mnt/verify

# Calculate checksum of critical files
sha256sum /mnt/verify/airgap-card.json

# Close
sudo umount /mnt/verify
sudo cryptsetup luksClose verify_card
```

---

## Backup Procedures

### Backup Extended Attributes

```bash
# Backup xattrs for all cards
for card in /mnt/card-*/airgap-card.id; do
    getfattr --dump "$card" >> xattr-backup.txt
done
```

### Restore Extended Attributes

```bash
# Restore from backup
setfattr --restore=xattr-backup.txt
```

### Copy Card (Clone)

```bash
# Use dd for exact copy (both cards same size)
sudo dd if=/dev/sdX of=/dev/sdY bs=4M status=progress

# Or copy contents and recreate structure (preferred)
# 1. Provision new card with same parameters
# 2. Copy files from original
# 3. Verify checksums match
```

---

## Troubleshooting

### Extended Attribute Not Found

```bash
# Verify filesystem supports xattrs
mount | grep ${CARD_DEV}1
# Should NOT show "nouser_xattr"

# If xattrs not working, remount with user_xattr
sudo mount -o remount,user_xattr ${CARD_DEV}1 /mnt/card-id
```

### LUKS Won't Open

```bash
# Check LUKS header integrity
sudo cryptsetup luksDump ${CARD_DEV}2

# If header damaged, restore from backup header
sudo cryptsetup luksHeaderRestore ${CARD_DEV}2 --header-backup-file header-backup.img
```

### Card Not Detected

```bash
# Check kernel messages
dmesg | tail -20

# Check USB device
lsusb

# Try different USB port or reader
```

---

## Security Notes

1. **Never provision cards on an internet-connected system** for production use
2. **Verify card serial numbers** match 1Password records before use
3. **Use strong passphrases** for LUKS (20+ characters, mixed case, numbers, symbols)
4. **Test recovery procedures** before deploying to remote sites
5. **Photograph tamper seals** before sealing packages
6. **Store passphrase hints** (not passphrases) in 1Password
