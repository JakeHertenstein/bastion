# Air-Gap 1Password Record Templates

**Version:** 1.0  
**Date:** 2025-12-09  
**Tag Hierarchy:** `Bastion/Airgap/CARD/`

## Overview

This document defines 1Password record templates for tracking air-gap system components. All records use the `Bastion/Airgap/CARD/` tag hierarchy for consistent organization.

---

## Card Inventory Record

### Template: Storage Card

**Category:** Secure Note  
**Tags:** `Bastion/Airgap/CARD/{DOMAIN}`

```
Title: {Site} {Role} {Domain} Card

[Bastion Label]
  Label:       Bastion/Airgap/CARD/{DOMAIN}:{site}.{role}:{DATE}#VERSION=1|{CHECK}
  Domain:      {DOMAIN}
  Site:        {site}
  Role:        {role}
  Date:        {DATE}
  Version:     1

[Hardware]
  Brand:       SanDisk
  Model:       SDSDQAF3-008G-I (Industrial MLC)
  Serial:      {SERIAL_NUMBER}
  Capacity:    8GB
  Color Code:  {COLOR}

[Security]
  Encrypted:   {Yes/No}
  LUKS UUID:   {UUID or N/A}
  FS Label:    {FILESYSTEM_LABEL}
  GPT Label:   {PARTITION_LABEL}

[Verification]
  Created:     {CREATION_DATE}
  Last Verify: {LAST_VERIFICATION_DATE}
  Checksum:    {SHA256_FIRST_8_CHARS}

[Notes]
  {Any additional notes about this card}
```

---

## Example Records

### Example: Home Master Secrets Card

**Tags:** `Bastion/Airgap/CARD/SECRETS`

```
Title: Home Master Secrets Card

[Bastion Label]
  Label:       Bastion/Airgap/CARD/SECRETS:home.master:2025-12-09#VERSION=1|M
  Domain:      SECRETS
  Site:        home
  Role:        master
  Date:        2025-12-09
  Version:     1

[Hardware]
  Brand:       SanDisk
  Model:       SDSDQAF3-008G-I (Industrial MLC)
  Serial:      A1B2C3D4E5F6
  Capacity:    8GB
  Color Code:  RED

[Security]
  Encrypted:   Yes
  LUKS UUID:   12345678-abcd-1234-abcd-123456789abc
  FS Label:    AG-SECRETS
  GPT Label:   AIRGAP-SECRETS

[Verification]
  Created:     2025-12-09
  Last Verify: 2025-12-09
  Checksum:    a1b2c3d4

[Notes]
  Primary secrets card containing SLIP-39 shares and KEK/DEK hierarchy.
  Stored in home safe, Faraday bag.
```

### Example: Bank-A Backup Secrets Card

**Tags:** `Bastion/Airgap/CARD/SECRETS`

```
Title: Bank-A Share-2 Secrets Card

[Bastion Label]
  Label:       Bastion/Airgap/CARD/SECRETS:bank-a.share-2:2025-12-09#VERSION=1|X
  Domain:      SECRETS
  Site:        bank-a
  Role:        share-2
  Date:        2025-12-09
  Version:     1

[Hardware]
  Brand:       SanDisk
  Model:       SDSDQAF3-008G-I (Industrial MLC)
  Serial:      F6E5D4C3B2A1
  Capacity:    8GB
  Color Code:  RED

[Security]
  Encrypted:   Yes
  LUKS UUID:   87654321-dcba-4321-dcba-cba987654321
  FS Label:    AG-SECRETS
  GPT Label:   AIRGAP-SECRETS

[Verification]
  Created:     2025-12-09
  Last Verify: 2025-12-09
  Checksum:    e5f6a7b8

[Notes]
  Backup copy for Alice Smith (Share 2).
  Stored in Bank A safety deposit box.
  Annual verification required.
```

### Example: Home Live OS Card

**Tags:** `Bastion/Airgap/CARD/OS`

```
Title: Home Live OS Card

[Bastion Label]
  Label:       Bastion/Airgap/CARD/OS:home.live:2025-12-09#VERSION=1|K
  Domain:      OS
  Site:        home
  Role:        live
  Date:        2025-12-09
  Version:     1

[Hardware]
  Brand:       SanDisk
  Model:       SDSDQAF3-008G-I (Industrial MLC)
  Serial:      123456789ABC
  Capacity:    8GB
  Color Code:  GREEN

[Security]
  Encrypted:   No
  LUKS UUID:   N/A
  FS Label:    AG-OS
  GPT Label:   AIRGAP-OS

[Golden Image]
  Image:       liveOS-v1.0.squashfs
  Image SHA:   abc123def456...
  Signed By:   user@example.com
  Signature:   liveOS-v1.0.squashfs.sha256.sig

[Verification]
  Created:     2025-12-09
  Last Verify: 2025-12-09
  Checksum:    abc123de

[Notes]
  Primary boot card with SquashFS read-only filesystem.
  Contains Debian 12 + bastion airgap toolkit.
```

### Example: Home Audit Card

**Tags:** `Bastion/Airgap/CARD/AUDIT`

```
Title: Home Audit Logs Card

[Bastion Label]
  Label:       Bastion/Airgap/CARD/AUDIT:home.logs:2025-12-09#VERSION=1|A
  Domain:      AUDIT
  Site:        home
  Role:        logs
  Date:        2025-12-09
  Version:     1

[Hardware]
  Brand:       SanDisk
  Model:       SDSDQAF3-008G-I (Industrial MLC)
  Serial:      DEF456789012
  Capacity:    8GB
  Color Code:  YELLOW

[Security]
  Encrypted:   Yes (optional)
  LUKS UUID:   aabbccdd-1122-3344-5566-778899aabbcc
  FS Label:    AG-AUDIT
  GPT Label:   AIRGAP-AUDIT

[Protection]
  Log Files:   chattr +a (append-only)
  Doc Files:   chattr +i (immutable)

[Verification]
  Created:     2025-12-09
  Last Verify: 2025-12-09
  Checksum:    def45678

[Notes]
  Append-only audit logs for all air-gap operations.
  Also contains metadata and documentation.
```

---

## Geographic Distribution Records

### Template: Site Package Record

**Category:** Secure Note  
**Tags:** `Bastion/Airgap/SITE`

```
Title: {Site Name} Backup Package

[Location]
  Site ID:     {site}
  Type:        {Home Safe / Safety Deposit Box / Trusted Third Party}
  Address:     {Address or description}
  Holder:      {Person responsible}
  Contact:     {Phone/Email}

[SLIP-39 Share]
  Share #:     {1-5}
  Format:      Metal plate (stainless steel)
  Words:       20 words
  
[Cards Included]
  SECRETS:     Bastion/Airgap/CARD/SECRETS:{site}.share-{n}:DATE#VERSION=1|X
  BACKUP:      Bastion/Airgap/CARD/BACKUP:{site}.backup-1:DATE#VERSION=1|B
  AUDIT:       Bastion/Airgap/CARD/AUDIT:{site}.logs:DATE#VERSION=1|A
  PARITY:      Bastion/Airgap/CARD/PARITY:{site}.recovery:DATE#VERSION=1|P

[Security]
  Packaging:   Tamper-evident bag (Serial: {SEAL_NUMBER})
  UV Marking:  {Pattern description}
  Photo Ref:   {1Password document reference}

[Verification]
  Deployed:    {DATE}
  Last Check:  {DATE}
  Next Check:  {DATE + 1 year}

[Notes]
  {Instructions for accessing, verification schedule, etc.}
```

### Example: Bank-A Site Package

**Tags:** `Bastion/Airgap/SITE`

```
Title: Bank-A Backup Package

[Location]
  Site ID:     bank-a
  Type:        Safety Deposit Box (shared)
  Address:     First National Bank, 123 Main St
  Holder:      Alice Smith
  Contact:     [Reference to 1Password contact]

[SLIP-39 Share]
  Share #:     2
  Format:      Metal plate (stainless steel)
  Words:       20 words
  
[Cards Included]
  SECRETS:     Bastion/Airgap/CARD/SECRETS:bank-a.share-2:2025-12-09#VERSION=1|X
  BACKUP:      Bastion/Airgap/CARD/BACKUP:bank-a.backup-1:2025-12-09#VERSION=1|B
  AUDIT:       Bastion/Airgap/CARD/AUDIT:bank-a.logs:2025-12-09#VERSION=1|A
  PARITY:      Bastion/Airgap/CARD/PARITY:bank-a.recovery:2025-12-09#VERSION=1|P

[Security]
  Packaging:   Tamper-evident bag (Serial: TE-2025-0042)
  UV Marking:  Diagonal stripes across seal
  Photo Ref:   bank-a-package-sealed.jpg

[Verification]
  Deployed:    2025-12-09
  Last Check:  2025-12-09
  Next Check:  2026-12-09

[Notes]
  Access requires both Alice Smith and self.
  Annual verification during existing SDB visit.
  Coordinate with Alice Smith for verification.
```

---

## Hardware Inventory Records

### Template: USB Reader

**Category:** Secure Note  
**Tags:** `Bastion/Airgap/HARDWARE`

```
Title: MicroSD Reader #{N}

[Hardware]
  Type:        MicroSD USB Card Reader
  Brand:       {Brand}
  Model:       {Model}
  Serial:      {Serial if available}
  USB:         USB 2.0

[Assignment]
  Primary Use: {Card domain or "floating"}
  Location:    {Home / Travel kit}

[Notes]
  Readers are interchangeable; cards identified by label, not slot.
```

### Template: SBC Platform

**Category:** Secure Note  
**Tags:** `Bastion/Airgap/HARDWARE`

```
Title: Air-Gap SBC (Sweet Potato)

[Hardware]
  Type:        Single Board Computer
  Brand:       Libre Computer
  Model:       AML-S905X-CC-V2 (Sweet Potato)
  Serial:      {Board serial}
  RAM:         2GB DDR3
  CPU:         Quad-core ARM Cortex-A53

[Verification]
  Wireless:    None (verified)
  Bluetooth:   None (verified)

[Storage]
  Boot:        Internal MicroSD slot
  External:    4x USB 2.0 ports

[Peripherals]
  HWRNG:       Infinite Noise USB (Port 1/OTG)
  Hub:         Atolla 7-Port USB Hub (Port 2)
  Keyboard:    Wired USB (Port 3)
  Mouse:       Wired USB (Port 4)

[Notes]
  Stored in Faraday bag when not in use.
  Tamper seals on enclosure (Serial: TS-2025-001).
```

---

## Tag Hierarchy Summary

```
Bastion/
└── Airgap/
    ├── CARD/
    │   ├── OS/           # Operating system cards
    │   ├── SCRATCH/      # Temporary workspace cards
    │   ├── SECRETS/      # SLIP-39 + KEK/DEK cards
    │   ├── BACKUP/       # Backup data cards
    │   ├── AUDIT/        # Audit log cards
    │   └── PARITY/       # Par2 recovery cards
    ├── SITE/             # Geographic distribution sites
    └── HARDWARE/         # Physical equipment inventory
```

---

## Maintenance

### Quarterly Tasks (Home Site)
- [ ] Verify home card checksums
- [ ] Review audit logs
- [ ] Update 1Password "Last Verify" dates

### Annual Tasks (All Sites)
- [ ] Visit each geographic site
- [ ] Verify tamper seals and UV markings
- [ ] Power up cards, verify checksums
- [ ] Test LUKS unlock
- [ ] Update 1Password records
- [ ] Schedule next verification
