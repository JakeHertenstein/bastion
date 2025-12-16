# Air-Gapped Key Generation System - AI Coding Agent Guidelines

## Project Overview

This is a **security-focused module** for the `bastion` project, implementing an air-gapped cryptographic key generation system. The system uses a **Libre Computer Sweet Potato (AML-S905X-CC-V2)** as the computing platform with **SanDisk Industrial MLC microSD cards** for domain-separated storage.

**Target Integration:** `bastion/airgap/` module in the bastion project.

### Design Documentation

| Document | Purpose |
|----------|---------|
| `docs/AIRGAP-DESIGN-DECISIONS.md` | Comprehensive design decisions and rationale |
| `docs/AIRGAP-1PASSWORD-TEMPLATES.md` | 1Password record templates for card inventory |
| `docs/AIRGAP-CARD-PROVISIONING.md` | Step-by-step card setup procedures |
| `chats/*.md` | Original Kagi/Claude conversation exports (reference) |

### Label Format

Cards use Bastion-compatible labels for 1Password integration:

```
Bastion/Airgap/CARD/{DOMAIN}:{site}.{role}:{DATE}#VERSION=1|CHECK
```

**Examples:**
- `Bastion/Airgap/CARD/SECRETS:home.master:2025-12-09#VERSION=1|M`
- `Bastion/Airgap/CARD/BACKUP:bank-a.share-2:2025-12-09#VERSION=1|X`

### Card Identification

Cards use a two-partition scheme for slot-independent detection:
1. **Partition 1** (1MB ext4): `airgap-card.id` file with `user.bastion.label` xattr
2. **Partition 2** (LUKS2 or ext4): Domain-specific encrypted data

## Architecture Summary

### Hardware Platform
- **SBC:** Libre Computer Sweet Potato AML-S905X-CC-V2 (2GB RAM, quad-core ARM Cortex-A53)
- **CRITICAL:** Must verify NO wireless hardware before deployment
- **Storage:** 7x SanDisk Industrial MLC 8GB microSD cards (6 system + 1 copy/temp)
- **Boot:** Internal microSD slot (Card 1 - Live OS)
- **Entropy Source:** Infinite Noise USB HWRNG + custom CLI toolkit with ENT validation
- **Status Indication:** 3.3V active buzzer on GPIO17

### USB Port Configuration
```
Port 1 (OTG): Infinite Noise HWRNG (direct connection)
Port 2:       Atolla 7-Port USB Hub (powered via USB-to-DC barrel cable)
              ├─ Hub Port 1-5: Card readers (Cards 2-6)
              ├─ Hub Port 6:   Card reader (Copy/Temp operations)
              └─ Hub Port 7:   USB Camera (QR codes)
Port 3:       Keyboard (wired USB, direct connection)
Port 4:       Mouse (wired USB, direct connection)
```

### 6-Card Domain Architecture (Simplified from 8)
| Card | Domain | Encryption | FS Protection | Color |
|------|--------|------------|---------------|-------|
| 1 | Live OS | None | SquashFS (RO) | GREEN |
| 2 | Scratch | None | tmpfs (RAM) | GREEN |
| 3 | SLIP-39 + KEKs/DEKs | LUKS2 | chattr +i | RED |
| 4 | Backup Data | LUKS2 | None | ORANGE |
| 5 | Audit + Metadata | LUKS2 (optional) | chattr +a (logs), +i (docs) | YELLOW |
| 6 | Parity/Recovery | None | chattr +i | YELLOW |

**Note:** Cards 3+4 and 5+7 from original 8-card design were merged for simplification.

## Security Conventions

### Operational Isolation Tiers
```
TIER 1 (Complete Isolation):
  Operations: Entropy generation, master key generation
  Connections: Power bank + Infinite Noise HWRNG only
  Enforcement: Hard block if wireless detected (no override)
  NO HDMI, NO USB hub during these operations

TIER 2 (Minimal Connections):
  Operations: SLIP-39 generation, KEK generation
  Connections: Add HDMI (display only) + Card 5 (Audit)

TIER 3 (Normal Operations):
  Operations: QR code display, verification, backup
  Connections: All peripherals as needed
```

### Hardware Verification

Wireless hardware is checked at two points:
- **Boot:** Warning banner, requires explicit `CONTINUE` input to proceed
- **Tier 1 operations:** Hard block with no override

Detection checks:
- `/sys/class/net/wlan*`, `/sys/class/net/wlp*` interfaces
- `rfkill list` output for Wireless/Bluetooth
- USB vendor IDs for common WiFi/BT adapters (Ralink, Realtek, Atheros, Intel)

### Data Transfer
- **Inbound:** SD cards with physical write-protect switch OR QR codes via USB camera
- **Outbound:** QR codes displayed on monitor
- **Error Correction:** Use QR level H (30% recovery)
- **Max Chunk Size:** 2KB per QR code
- **NEVER:** Use bidirectional USB drives

### QR Code Multi-Part Protocol

For data larger than 2KB, use the BASTION protocol:

```
BASTION:seq/total:data
```

Example for a 5KB GPG message:
```
BASTION:1/3:<base64_chunk_1>
BASTION:2/3:<base64_chunk_2>
BASTION:3/3:<base64_chunk_3>
```

**Implementation:**
```python
from airgap.qr import split_for_qr, reassemble_qr_parts

# Split large data
parts = split_for_qr(gpg_message, max_bytes=2000)
for part in parts:
    display_qr(part.to_qr_string())

# Reassemble on receiver
data = reassemble_qr_parts(collected_parts)
```

### GPG Key and Salt Transfer Workflow

The airgap machine generates GPG keys and username salts with hardware entropy,
then exports them to the manager machine via QR codes:

```
AIRGAP                              MANAGER
┌─────────────────┐                 ┌─────────────────┐
│ 1. keygen master│                 │                 │
│    (ENT-verified│                 │                 │
│     entropy)    │                 │                 │
├─────────────────┤                 │                 │
│ 2. export pubkey│ ────QR─────────▶│ import pubkey   │
│    --qr         │                 │                 │
├─────────────────┤                 │                 │
│ 3. export salt  │ ────QR─────────▶│ import salt     │
│    -r <KEY_ID>  │  (encrypted)    │ (decrypt + 1PW) │
└─────────────────┘                 └─────────────────┘
```

**CLI Commands:**
```bash
# On airgap
airgap keygen master --algorithm rsa4096 --name "Name" --email "email"
airgap keygen subkeys
airgap keygen transfer-to-yubikey
airgap backup create --device /dev/sdX
airgap export pubkey --qr
airgap export salt --recipient <KEY_ID> --bits 256

# On manager
bastion import pubkey      # Scan QR
bastion import salt        # Scan QR, decrypt with YubiKey
bastion generate username --init  # Uses imported salt
```

### Cryptographic Standards
- **Encryption:** LUKS2 with AES-XTS-256, Argon2id PBKDF
- **Hashing:** SHA-512 for key derivation, SHA-256 for checksums
- **Secret Sharing:** SLIP-39 (5 shares, 3-of-5 threshold)
- **Minimum Entropy:** 2000 bits required before key operations
- **Secure Erase:** Cryptographic erase via `cryptsetup luksErase`

### Filesystem Protection (NO physical write-protect switches on microSD)
- **SquashFS:** Read-only filesystem for Live OS (Card 1)
- **chattr +i:** Immutable files (Cards 3, 5 docs, 6)
- **chattr +a:** Append-only audit logs (Card 5 logs)
- **mount -o ro:** Read-only mounts when appropriate
- **tmpfs:** RAM-only scratch space (Card 2)

## Code Generation Guidelines

### When writing shell scripts:
```bash
# Always use absolute paths
/mnt/slip39/  # NOT relative paths

# Always verify before critical operations
check_entropy() {
    local required=2000
    local current=$(cat /proc/sys/kernel/random/entropy_avail)
    [ $current -lt $required ] && return 1
}

# Always log operations to audit (append-only)
echo "$(date -Iseconds) | OPERATION | DETAILS" >> /mnt/audit/operations/operations.log

# Use secure mount options
mount -o rw,noexec,nosuid,nodev /dev/mapper/crypt_name /mnt/path
```

### When working with LUKS encryption:
```bash
# Open encrypted container
cryptsetup luksOpen /dev/sdX1 container_name

# Mount with secure options
mount -o rw,noexec,nosuid /dev/mapper/container_name /mnt/path

# Always close properly
umount /mnt/path
cryptsetup luksClose container_name
```

### When setting filesystem protection:
```bash
# Immutable (Cards 3, 5 docs, 6 - after writing)
find /mnt/card -type f -exec chattr +i {} \;
find /mnt/card -type d -exec chattr +i {} \;

# Append-only (Card 5 - audit logs)
find /mnt/audit -name "*.log" -exec chattr +a {} \;
```

### For Par2 parity files:
```bash
# Generate parity (10-20% redundancy)
par2create -r10 -n7 /mnt/parity/card3.par2 /mnt/slip39/*

# Verify integrity
par2verify /mnt/parity/card3.par2

# Repair if needed
par2repair /mnt/parity/card3.par2
```

### For buzzer status indication:
```bash
# GPIO17 for active buzzer
BUZZER_PIN=17
echo "$BUZZER_PIN" > /sys/class/gpio/export
echo "out" > /sys/class/gpio/gpio${BUZZER_PIN}/direction

# Beep function
beep() {
    echo "1" > /sys/class/gpio/gpio${BUZZER_PIN}/value
    sleep "${1:-0.1}"
    echo "0" > /sys/class/gpio/gpio${BUZZER_PIN}/value
}

# Status patterns
# Entropy start: 2 medium beeps
# Entropy complete: 3 long beeps
# Key gen complete: 1 very long beep
# Error: 5 rapid beeps
```

### For backup verification (checksums + signatures):
```bash
# Create checksums before sealing backup
cd /mnt/backup
sha256sum * > checksums.txt

# Sign the checksum file with GPG
gpg --detach-sign --armor checksums.txt
# Creates checksums.txt.asc

# Store checksums.txt and checksums.txt.asc EXTERNALLY
# (separate from the backup media)

# During annual verification:
# 1. Verify signature
gpg --verify checksums.txt.asc checksums.txt

# 2. Verify file integrity
sha256sum -c checksums.txt

# 3. Log verification to audit
echo "$(date -Iseconds) | VERIFY | Site: $SITE | Result: $RESULT" >> /mnt/audit/verification.log
```

### For encrypted microSD backup (derived from SLIP-39):
```bash
# Key derivation from SLIP-39 master secret (conceptual)
# Use proper crypto libraries - this is pseudocode
# encryption_key = PBKDF2(master_secret, salt="microsd-backup", iterations=100000)

# Create LUKS2 encrypted partition
cryptsetup luksFormat /dev/sdX --type luks2 \
    --cipher aes-xts-plain64 \
    --key-size 512 \
    --hash sha512 \
    --pbkdf argon2id

# Open, format, and mount
cryptsetup luksOpen /dev/sdX backup_sd
mkfs.ext4 /dev/mapper/backup_sd
mount -o noexec,nosuid,nodev /dev/mapper/backup_sd /mnt/backup

# Copy data and create checksums
rsync -av /source/ /mnt/backup/
cd /mnt/backup && sha256sum * > checksums.txt
gpg --detach-sign --armor checksums.txt

# Unmount and close
umount /mnt/backup
cryptsetup luksClose backup_sd
```

# Status patterns
# Entropy start: 2 medium beeps
# Entropy complete: 3 long beeps
# Key gen complete: 1 very long beep
# Error: 5 rapid beeps
```

## Geographic Distribution

5 sites store SLIP-39 splits + complete backup sets:
1. **Primary:** Home safe (Share 1)
2. **Bank A:** Safety deposit box shared with Alice Smith (Share 2)
3. **Bank B:** Safety deposit box personal/trust (Share 3)
4. **Trusted:** Bob Jones (Share 4)
5. **Offsite:** Carol Davis (Share 5)

Recovery requires any 3 of 5 SLIP-39 splits.

### Estate Planning Integration
The SLIP-39 system protects access to 1Password vault containing:
- Financial account credentials
- Cryptocurrency holdings
- Social media and email accounts
- Cloud storage access
- Digital files and important documents

**Key Appointments (consistent across all estate documents):**
- **Primary Executor/Trustee/Agent:** Alice Smith (has access to Share 2)
- **First Alternate:** Bob Jones (holds Share 4)
- **Second Alternate:** Carol Davis (holds Share 5)

**Digital Estate Access Plan** must document:
- SLIP-39 share locations and holders
- Recovery process step-by-step instructions
- 1Password vault contents overview
- Coordination instructions for executors

### Backup Package Contents (per site)
Each geographic location receives:
- 1x SLIP-39 split (metal backup plate, NOT paper)
- 1x Complete card set (Cards 2-6 copies on encrypted microSD)
- 1x Recovery procedures document
- All items in tamper-evident packaging (see Physical Security)

### Encrypted MicroSD Backup Strategy
- Encryption key derived deterministically from SLIP-39 master secret via PBKDF2
- Use LUKS2 encryption on microSD cards (same as system cards)
- Checksums (SHA-256) + GPG signatures stored externally
- Annual verification required (flash memory degrades unpowered)

## Physical Security

- **Storage:** Fireproof safe + Faraday bag (dual-layer TitanRF)
- **Tamper Evidence:** Numbered seals on SBC enclosure, photographed
- **Perimeter:** 100ft control at home location
- **Camera Policy:** Limited camera use during operations
- **Power:** 20,000mAh power bank (dual output for SBC + hub)

### Tamper-Evident Packaging (for geographic distribution)
```
Layered approach (inside → outside):
1. Desiccant packets + humidity indicator cards
2. Anti-static bags (for electronics)
3. Clear tamper-evident bag (inner layer, for visual inspection)
4. UV security markings across seals (unique patterns, photographed)
5. Opaque tamper-evident money bag (outer layer)
```

### Tamper-Evident Supplies
- Clear tamper-evident deposit bags with sequential serial numbers
- Opaque tamper-evident money bags with sealed zippers
- UV security markers (edding 8280 or ASR Federal)
- UV flashlight (365nm) for verification
- Desiccant packets (silica gel, 5-10g)
- Humidity indicator cards
- Metal seed phrase backup plates (stainless steel)

### UV Marking Protocol
- Apply unique, asymmetric patterns across all seals
- Mark device seams (IronKey, YubiKey, card cases)
- Photograph markings under UV light before storage
- Store reference photos securely off-site
- Verify patterns match during inspections

### Verification Schedule
- **Quarterly:** Primary site (home safe) - full verification
- **Annually:** All geographic sites - tamper seals, UV marks, data integrity
- **Data integrity check:** Power up devices, verify checksums, test functionality

## Key Terminology

- **Sweet Potato:** Libre Computer AML-S905X-CC-V2 SBC
- **SLIP-39:** Shamir's Secret Sharing for mnemonics (5 splits, 3-of-5 threshold)
- **KEK:** Key Encryption Key (wraps DEKs)
- **DEK:** Data Encryption Key (encrypts actual data)
- **Golden Image:** GPG-verified, immutable SquashFS OS image
- **Cryptographic Erase:** Destroying LUKS header to permanently erase data

## Do NOT

- Generate keys without verifying entropy > 2000 bits
- Use bidirectional USB drives for data transfer
- Update OS in-place (use golden image replacement)
- Store passphrases digitally
- Connect HDMI during entropy generation (Tier 1 isolation)
- Use phone cameras for QR code operations
- Run network-related commands (system is air-gapped)
- Trust physical write-protect switches (use filesystem controls instead)
- Use wireless keyboards/mice (wired only)
- Store all SLIP-39 shares together (defeats purpose of secret sharing)
- Skip annual verification of flash memory backups (data degrades unpowered)
- Use clear bags as outer layer (use opaque for privacy)
- Neglect to photograph UV markings before sealing

## Hardware Shopping List

### Computing Hardware
- Libre Computer Sweet Potato AML-S905X-CC-V2 (2GB)
- 7x SanDisk Industrial MLC 8GB MicroSD (SDSDQAF3-008G-I)
- 7x MicroSD USB 2.0 card readers (single-slot, simple)
- Atolla 7-Port USB 3.0 Hub (CH-207U3) with 5V/4A adapter
- USB-A to DC 5.5mm x 2.1mm barrel jack cable
- Infinite Noise USB HWRNG
- 3.3V Active buzzer module (KY-012 or similar)
- Wired USB keyboard + mouse (basic, no wireless)
- USB webcam (for QR codes)
- 20,000mAh power bank (5V/3A dual output)

### Physical Security Supplies
- TitanRF Faraday bag (dual-layer)
- Fireproof safe (UL Class 350)
- Clear tamper-evident deposit bags (9"x12", sequential serial numbers)
- Opaque tamper-evident money bags (10"x15", sealed zippers)
- Numbered tamper-evident seals
- UV security markers (edding 8280 or ASR Federal)
- UV flashlight (365nm, keychain size)
- Desiccant packets (silica gel, 5-10g) - pack of 20-30
- Humidity indicator cards - pack of 10-20
- Anti-static bags (for electronics)
- Metal seed phrase backup plates (stainless steel, SLIP-39 compatible)

## Document Structure

The main document (`Air Gapped Machine for Key Generation.md`) is an exported Kagi/Claude 4.5 conversation in Q&A format with timestamps. Major sections include:
- Hardware selection and rationale (Sweet Potato, Atolla hub)
- 6-card simplified domain architecture (merged from 8)
- Color coding and labeling strategy
- Filesystem protection (LUKS2, SquashFS, chattr)
- Operational isolation tiers
- Entropy generation with buzzer feedback
- QR code data transfer
- Geographic backup distribution (5 sites, 3-of-5 threshold)
- Supply chain security (golden images, GPG verification)
- Incident response procedures
- Time synchronization (manual setting)
- Secure disposal procedures

The companion document (`SLIP-39 Seed Backup Security Measures.md`) covers:
- Tamper-evident packaging strategy (layered approach)
- UV marking protocols for covert verification
- Flash memory degradation and annual verification
- Checksum + GPG signature verification workflow
- Encrypted microSD backup strategy (SLIP-39 derived keys)
- Environmental protection (desiccants, humidity indicators)
- Safe deposit box considerations

The estate planning document (`Analyze Estate Planning For Problems.md`) covers:
- Complete estate plan analysis (Trust, Will, POA, Living Will)
- SLIP-39 integration with digital estate access
- Share distribution strategy (5 shares, 3-of-5 threshold)
- Named beneficiary approach for DNA testing protection
- Executor coordination with SLIP-39 share holders
- Digital Estate Access Plan documentation requirements
- Annual verification and maintenance schedules

## Golden Image Strategy

Use Libre Computer's official Debian 12 image as base:
1. Download and GPG-verify official image
2. Strip unnecessary packages (`network-manager`, `bluetooth*`, `wpasupplicant`)
3. Install required packages (`cryptsetup`, `gnupg2`, `rng-tools`, `ent`, `qrencode`, `zbar-tools`, `par2`)
4. Install bastion airgap toolkit
5. Create SquashFS overlay for immutability
6. Sign final image with GPG
7. Document package manifest for reproducibility
