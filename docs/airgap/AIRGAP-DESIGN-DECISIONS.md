# Air-Gap Module Design Decisions

**Version:** 1.0  
**Date:** 2025-12-09  
**Status:** Draft  
**Target:** Integration into `bastion` project as `bastion/airgap/` module

## Overview

This document captures design decisions for the air-gapped cryptographic key generation system. The system uses a **Libre Computer Sweet Potato (AML-S905X-CC-V2)** as the computing platform with domain-separated microSD card storage.

### Primary Objectives

1. Generate and protect SLIP-39 seed phrases (5 shares, 3-of-5 threshold)
2. Derive and manage cryptographic keys (GPG, SSH, cryptocurrency wallets)
3. Maintain complete network isolation with auditable operations
4. Enable geographic distribution of backup shares for estate planning

### Integration with Bastion

This module extends the existing `bastion` project, reusing:
- `bastion/label_spec.py` — Luhn mod-36 check digits, label parsing
- `seeder/src/seeder/core/seed_sources.py` — SLIP-39 generation via `shamir_mnemonic`
- `bastion/cli/commands/entropy.py` — Infinite Noise TRNG, entropy generation
- Typer + Rich CLI architecture

---

## QR Transfer Data Flows (Manager ↔ Airgap)

- **Manager ➜ Airgap (pubkey)**: `bastion sigchain import pubkey --file manager.asc` (or paste QR) → `airgap keys import manager.asc` → airgap encrypts salts with manager key.
- **Airgap ➜ Manager (salt)**: `airgap export salt --recipient <manager-key>` → scan/paste QR into `bastion sigchain import salt --vault Private` → GPG decrypts locally and stores salt in 1Password.
- **Sigchain snapshots via QR**: `bastion sigchain export-qr --max-bytes 2000` to display multi-part QR payloads; `bastion sigchain import-qr --apply` to decode and overwrite local `chain.json` (or `--output` to save decoded JSON without applying).
- **Isolation rule**: Encryption stays in airgap; manager only decrypts with its private key. QR payloads use the shared `BASTION:seq/total:<data>` framing.

### QR Protocol

**Protocol prefix**: `BASTION:` — identifies Bastion-specific QR payloads; implementation in [packages/bastion/src/bastion/qr.py](https://github.com/jakehertenstein/bastion/blob/main/packages/bastion/src/bastion/qr.py).

**Default payload limit**: ~2000 bytes per QR code; larger payloads automatically chunked with sequence numbering (e.g., `BASTION:1/3:<chunk1>`).

---

## 1. Label Format

### Decision: Bastion-Prefixed Hierarchical Labels

Labels follow the established Bastion format for 1Password tag compatibility:

```
Bastion/Airgap/CARD/{DOMAIN}:{site}.{role}:{DATE}#VERSION=1|CHECK
```

### Components

| Field | Format | Description | Examples |
|-------|--------|-------------|----------|
| **TOOL** | `Bastion` | Root tool identifier | `Bastion` |
| **MODULE** | `Airgap` | Air-gap submodule | `Airgap` |
| **TYPE** | `CARD` | Always CARD for storage media | `CARD` |
| **DOMAIN** | UPPERCASE | Card function domain | `OS`, `SECRETS`, `BACKUP`, `AUDIT`, `PARITY`, `SCRATCH` |
| **site** | lowercase | Deployment location | `home`, `bank-a`, `bank-b`, `trusted`, `offsite` |
| **role** | lowercase | Function within site | `live`, `master`, `backup-1`, `logs`, `recovery` |
| **DATE** | ISO 8601 | Creation date | `2025-12-09` |
| **VERSION** | Integer | Label format version | `1` |
| **CHECK** | Luhn mod-36 | Single character check digit | `K`, `X`, `M` |

### Example Labels

| Card | Domain | Full Label |
|------|--------|------------|
| Live OS | `OS` | `Bastion/Airgap/CARD/OS:home.live:2025-12-09#VERSION=1\|K` |
| Scratch | `SCRATCH` | `Bastion/Airgap/CARD/SCRATCH:home.temp:2025-12-09#VERSION=1\|X` |
| SLIP-39 + KEKs | `SECRETS` | `Bastion/Airgap/CARD/SECRETS:home.master:2025-12-09#VERSION=1\|M` |
| Backup | `BACKUP` | `Bastion/Airgap/CARD/BACKUP:home.full:2025-12-09#VERSION=1\|B` |
| Audit + Metadata | `AUDIT` | `Bastion/Airgap/CARD/AUDIT:home.logs:2025-12-09#VERSION=1\|A` |
| Parity | `PARITY` | `Bastion/Airgap/CARD/PARITY:home.recovery:2025-12-09#VERSION=1\|P` |

### Distributed Backup Labels

For geographic distribution, site identifies the storage location:

```
Bastion/Airgap/CARD/SECRETS:bank-a.share-2:2025-12-09#VERSION=1|X
Bastion/Airgap/CARD/BACKUP:trusted.backup-1:2025-12-09#VERSION=1|L
```

### Rationale

- **Bastion prefix** — Integrates with existing 1Password tag hierarchy
- **Airgap module** — Distinguishes from other Bastion credential types (USER, KEY)
- **site.role pattern** — Matches Bastion's `cardid.index` convention, supports multi-site deployments
- **Luhn check digit** — Detects transcription errors, consistent with Bastion labels

---

## 2. Card Architecture

### Decision: 6-Card Domain Separation

| Card | Domain | Encryption | FS Protection | Color |
|------|--------|------------|---------------|-------|
| 1 | Live OS | None | SquashFS (RO) | GREEN |
| 2 | Scratch | None | tmpfs (RAM) | GREEN |
| 3 | SLIP-39 + KEKs/DEKs | LUKS2 | chattr +i | RED |
| 4 | Backup Data | LUKS2 | None | ORANGE |
| 5 | Audit + Metadata | LUKS2 (optional) | chattr +a (logs), +i (docs) | YELLOW |
| 6 | Parity/Recovery | None | chattr +i | YELLOW |

### Hardware

- **Cards:** 7x SanDisk Industrial MLC 8GB MicroSD (SDSDQAF3-008G-I)
  - 6 system cards + 1 copy/temp operations
- **Readers:** 7x MicroSD USB 2.0 card readers (identical models)
- **Cases:** Color-coded cases matching domain colors

### Rationale

- **6 cards** — Simplified from original 8-card design by merging domains
- **Industrial MLC** — Higher write endurance, better data retention than consumer cards
- **Color coding** — Visual identification without reading labels

---

## 3. Card Identification

### Decision: Hybrid Metadata with Extended Attributes

Cards are identified without slot dependency using a two-partition scheme:

```
Partition 1: 1MB ext4 (unencrypted)
├── airgap-card.id          # Short identifier file
└── [xattr: user.bastion.label]  # Full Bastion label

Partition 2: Remainder LUKS2 (encrypted)
└── airgap-card.json        # Full metadata (inside encrypted volume)
```

### Detection Flow

1. Insert card into **any** reader slot
2. `blkid` scans for `PARTLABEL=AIRGAP-*` or `LABEL=AG-*`
3. Mount 1MB partition (no passphrase needed)
4. Read `user.bastion.label` xattr via `getfattr`
5. Parse label to determine domain, site, role
6. Prompt for LUKS passphrase if encrypted partition needed
7. Mount to standardized path (e.g., `/mnt/secrets` regardless of USB port)

### Extended Attributes

```bash
# Set label during provisioning
setfattr -n user.bastion.label \
  -v "Bastion/Airgap/CARD/SECRETS:home.master:2025-12-09#VERSION=1|M" \
  /mnt/card-id/airgap-card.id

# Read label during detection
getfattr -n user.bastion.label /mnt/card-id/airgap-card.id
```

### Storage Locations

| Location | Content | Readable Without Passphrase |
|----------|---------|----------------------------|
| GPT partition label | `AIRGAP-SECRETS` (short, 72B max) | Yes |
| ext4 filesystem label | `AG-SECRETS` (16 char max) | Yes |
| xattr `user.bastion.label` | Full Bastion label | Yes (after mounting 1MB partition) |
| `/airgap-card.json` inside LUKS | Complete metadata + checksums | No |

### Rationale

- **No slot dependency** — Any card works in any reader
- **Pre-unlock identification** — Know which card before entering passphrase
- **xattr on ext4** — Native Linux support, up to 64KB values, preserved by `tar --xattrs`, `rsync -X`
- **1MB partition** — Minimal overhead, fast mount

---

## 4. Golden Image Strategy

### Decision: Official Debian Base + Minimal Customization

Use Libre Computer's official Debian 12 image as base, customize minimally.

### Build Process

1. **Download** Libre Computer's Debian 12 ARM64 image
2. **Verify** GPG signature from Libre Computer
3. **Boot** on development machine (or QEMU)
4. **Strip** unnecessary packages:
   ```bash
   apt purge network-manager bluetooth* wpasupplicant wireless-*
   ```
5. **Install** required packages:
   ```bash
   apt install cryptsetup gnupg2 rng-tools ent qrencode zbar-tools par2 \
               python3-pip python3-venv
   ```
6. **Install** air-gap toolkit (from bastion)
7. **Create** SquashFS overlay for immutability
8. **Sign** final image with GPG
9. **Document** package manifest for reproducibility

### Golden Image Contents

```
/opt/bastion/
├── airgap/           # Air-gap module
├── seeder/           # SLIP-39 generation
└── bin/              # CLI entry points

/usr/local/share/airgap/
├── golden-image.manifest
├── golden-image.sha256
└── golden-image.sha256.sig
```

### Rationale

- **Official base** — Pre-built bootloader, kernel compatibility, faster setup
- **GPG verification** — Supply chain security
- **Minimal packages** — Reduced attack surface
- **SquashFS** — Read-only OS, no in-place updates

---

## 5. Hardware Verification

### Decision: Warn at Boot + Hard Block in Tier 1

Check for wireless hardware at two points:

### Boot-Time Check

```
┌─────────────────────────────────────────────────────────────────┐
│  ⚠️  WARNING: WIRELESS HARDWARE DETECTED                        │
│                                                                 │
│  Device: /sys/class/net/wlan0                                   │
│  Type: USB WiFi Adapter (vendor: 0x148f)                        │
│                                                                 │
│  Air-gapped operations require NO wireless hardware.            │
│  Remove the device and reboot, or type CONTINUE to proceed.     │
│                                                                 │
│  > _                                                            │
└─────────────────────────────────────────────────────────────────┘
```

- Requires explicit `CONTINUE` input (not just Enter)
- Logged to audit card

### Tier 1 Operation Check

- **Hard block** with no override during:
  - Entropy generation
  - Master key generation
  - SLIP-39 share creation
- Error message explains requirement
- User must physically remove device and restart operation

### Detection Methods

```python
def check_wireless() -> list[str]:
    """Return list of detected wireless devices."""
    devices = []
    
    # Check network interfaces
    for iface in Path("/sys/class/net").iterdir():
        if iface.name.startswith(("wlan", "wlp", "wifi")):
            devices.append(f"Network interface: {iface.name}")
    
    # Check rfkill
    rfkill = subprocess.run(["rfkill", "list"], capture_output=True, text=True)
    if "Wireless" in rfkill.stdout or "Bluetooth" in rfkill.stdout:
        devices.append(f"RF device: {rfkill.stdout.strip()}")
    
    # Check USB vendor IDs (common WiFi/BT adapters)
    WIRELESS_VENDORS = {"148f", "0bda", "0cf3", "8087"}  # Ralink, Realtek, Atheros, Intel BT
    lsusb = subprocess.run(["lsusb"], capture_output=True, text=True)
    for line in lsusb.stdout.splitlines():
        for vendor in WIRELESS_VENDORS:
            if f"ID {vendor}:" in line.lower():
                devices.append(f"USB device: {line.strip()}")
    
    return devices
```

### Rationale

- **Sweet Potato has no onboard wireless** — Check guards against accidental USB dongles
- **Warn + continue at boot** — Allows debugging/testing with override
- **Hard block in Tier 1** — No compromise during critical operations

---

## 6. Secret Hierarchy

### Decision: Master Entropy → SLIP-39 → KEK → DEKs

```
                    ┌─────────────────┐
                    │ Infinite Noise  │
                    │     HWRNG       │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │ Master Entropy  │
                    │   (256 bits)    │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
     ┌────────▼────────┐     │     ┌────────▼────────┐
     │   SLIP-39       │     │     │      KEK        │
     │  (5 shares,     │     │     │ (Key Encryption │
     │   3-of-5)       │     │     │      Key)       │
     └────────┬────────┘     │     └────────┬────────┘
              │              │              │
              │         Geographic          │
              │         Distribution        │
              │                             │
                            ┌───────────────┼───────────────┐
                            │               │               │
                   ┌────────▼────┐  ┌───────▼───────┐  ┌────▼────────┐
                   │  GPG DEK    │  │   SSH DEK     │  │ Crypto DEK  │
                   │ (Ed25519)   │  │  (Ed25519)    │  │  (BIP-32)   │
                   └─────────────┘  └───────────────┘  └─────────────┘
```

### Secret Types

| Secret | Derivation | Storage | Protection |
|--------|------------|---------|------------|
| Master Entropy | Infinite Noise HWRNG | Never stored directly | Converted to SLIP-39 |
| SLIP-39 Shares | `shamir_mnemonic` library | Metal plates at 5 sites | 3-of-5 threshold |
| KEK | PBKDF2 from master | Card 3 (SECRETS) | LUKS2 + chattr +i |
| GPG Master Key | HKDF from KEK | Card 3 (SECRETS) | LUKS2 + chattr +i |
| SSH Keys | HKDF from KEK | Card 3 (SECRETS) | LUKS2 + chattr +i |
| Crypto Wallets | BIP-32 from KEK | Card 3 (SECRETS) | LUKS2 + chattr +i |
| Backup Encryption | HKDF from KEK | Derived on-demand | Never stored |

### Rationale

- **SLIP-39** — Shamir's Secret Sharing with mnemonic encoding, widely supported
- **3-of-5 threshold** — Tolerates loss of 2 shares, requires compromise of 3
- **KEK/DEK hierarchy** — Single recovery path, multiple derived secrets
- **HKDF derivation** — Deterministic, auditable, reproducible

---

## 7. Data Transfer

### Decision: Hybrid QR + Write-Protected SD

| Data Type | Method | Max Size | Direction |
|-----------|--------|----------|-----------|
| SLIP-39 shares | QR code | ~500 bytes | Outbound |
| Public keys | QR code | ~2KB | Outbound |
| Checksums | QR code | ~500 bytes | Both |
| Software updates | Write-protected SD | Unlimited | Inbound |
| Bulk backups | Write-protected SD | Unlimited | Inbound |
| Signed golden images | Write-protected SD | ~2GB | Inbound |

### QR Code Parameters

- **Error correction:** Level H (30% recovery)
- **Max chunk size:** 2KB per QR code
- **Display:** Fullscreen, high contrast
- **Scanning:** USB camera only (no phone cameras)
- **Encoding:** Base64 for binary data

### Write-Protected SD Protocol

1. Prepare data on internet-connected machine
2. Create checksums: `sha256sum * > checksums.txt`
3. Sign checksums: `gpg --detach-sign checksums.txt`
4. Copy to SD card
5. **Enable write-protect switch** on SD adapter
6. Transfer to air-gapped system
7. Verify GPG signature
8. Verify checksums
9. Process data

### Rationale

- **QR codes** — True unidirectional for small secrets, visually verifiable
- **Write-protected SD** — Practical for large data, physical protection
- **No bidirectional USB** — Eliminates exfiltration vector

---

## 8. Operational Tiers

### Decision: Three Isolation Levels

| Tier | Operations | Allowed Connections |
|------|------------|---------------------|
| **Tier 1** (Complete Isolation) | Entropy generation, master key generation | Power bank + Infinite Noise HWRNG only |
| **Tier 2** (Minimal) | SLIP-39 generation, KEK generation | + HDMI display + Card 5 (Audit) |
| **Tier 3** (Normal) | QR display, verification, backup | All peripherals as needed |

### Tier Enforcement

```python
class OperationalTier(Enum):
    TIER_1 = "complete_isolation"
    TIER_2 = "minimal"
    TIER_3 = "normal"

def enforce_tier(required: OperationalTier) -> None:
    """Enforce operational tier requirements."""
    
    if required == OperationalTier.TIER_1:
        # Hard requirements
        wireless = check_wireless()
        if wireless:
            raise SecurityError(f"Tier 1 violation: wireless detected: {wireless}")
        
        usb_devices = get_usb_devices()
        allowed = {"infinite_noise_hwrng"}
        if usb_devices - allowed:
            raise SecurityError(f"Tier 1 violation: unauthorized USB: {usb_devices - allowed}")
```

### Rationale

- **Tier 1** — Maximum security for irreversible operations
- **Tier 2** — Balance security with operational needs
- **Tier 3** — Normal operations with full audit trail

---

## 9. Geographic Distribution

### Decision: 5 Sites with Named Share Holders

| Site | Location | Share Holder | SLIP-39 Share | Backup Set |
|------|----------|--------------|---------------|------------|
| 1 | Home safe | Primary (self) | Share 1 | Complete |
| 2 | Bank A (shared SDB) | Alice Smith | Share 2 | Complete |
| 3 | Bank B (personal SDB) | Trust | Share 3 | Complete |
| 4 | Trusted friend | Bob Jones | Share 4 | Complete |
| 5 | Family | Carol Davis | Share 5 | Complete |

### Backup Package Contents

Each site receives:
- 1x SLIP-39 share (metal backup plate)
- 1x Complete card set (Cards 2-6 on encrypted microSD)
- 1x Recovery procedures document
- Tamper-evident packaging (numbered seals, UV markings)

### Estate Planning Integration

- **Primary Executor:** Alice Smith (Share 2)
- **First Alternate:** Bob Jones (Share 4)
- **Second Alternate:** Carol Davis (Share 5)

Recovery requires coordination of any 3 share holders.

### Rationale

- **5 sites** — Geographic redundancy, natural disaster protection
- **3-of-5 threshold** — Balance availability vs security
- **Named holders** — Clear chain of custody for estate planning

---

## 10. 1Password Integration

### Decision: Card Inventory with Bastion Tag Hierarchy

Store card metadata in 1Password under `Bastion/Airgap/CARD/` tags.

### Tag Hierarchy

```
Bastion/
└── Airgap/
    └── CARD/
        ├── OS/
        ├── SCRATCH/
        ├── SECRETS/
        ├── BACKUP/
        ├── AUDIT/
        └── PARITY/
```

### Record Template

See `AIRGAP-1PASSWORD-TEMPLATES.md` for complete templates.

### Rationale

- **Consistent with Bastion** — Same tag structure as USER, KEY types
- **Hardware tracking** — Serial numbers for inventory management
- **LUKS UUIDs** — Essential for recovery procedures

---

## 11. Module Structure

### Proposed `bastion/airgap/` Package

```
bastion/
├── airgap/
│   ├── __init__.py
│   ├── labels.py          # Bastion/Airgap label format
│   ├── cards.py           # Card detection, mounting, management
│   ├── hardware.py        # Wireless detection, USB enumeration
│   ├── session.py         # Operational tier enforcement
│   ├── buzzer.py          # GPIO17 status indication
│   ├── qr.py              # QR code generation/scanning
│   ├── backup.py          # Backup procedures, checksums
│   └── recovery.py        # SLIP-39 recovery workflows
├── cli/
│   └── commands/
│       └── airgap_commands.py  # Typer CLI commands
└── docs/
    └── airgap/
        ├── DESIGN-DECISIONS.md
        ├── 1PASSWORD-TEMPLATES.md
        ├── CARD-PROVISIONING.md
        └── chats/          # Preserved Kagi conversation exports
```

### CLI Commands (Proposed)

```bash
bastion airgap status          # Show tier, cards, hardware
bastion airgap card detect     # Scan and identify inserted cards
bastion airgap card provision  # Set up new card with partitions/labels
bastion airgap entropy check   # Verify entropy sources
bastion airgap session start   # Begin operational session with tier
bastion airgap backup create   # Create backup with checksums
bastion airgap backup verify   # Verify backup integrity
bastion airgap qr export       # Generate QR codes for data
bastion airgap qr import       # Scan and import QR codes
bastion airgap recovery plan   # Display recovery procedures
```

---

## Migration Checklist

- [ ] Create `bastion/airgap/` package structure
- [ ] Implement `labels.py` using existing `bastion/label_spec.py`
- [ ] Implement `hardware.py` with wireless detection
- [ ] Implement `cards.py` with xattr-based detection
- [ ] Add `airgap_commands.py` to CLI
- [ ] Copy documentation to `bastion/docs/airgap/`
- [x] Merge copilot-instructions into bastion's instructions
- [ ] Archive standalone air-gap workspace
