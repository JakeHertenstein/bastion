# Recovery Bag Physical Design Specification

> **Version**: 1.0.0
> **Created**: 2025-12-12
> **Status**: Design Complete

---

## Overview

This document specifies the physical components, assembly procedure, and labeling system for Bastion recovery bags. Each bag contains the artifacts necessary to participate in emergency recovery of the digital estate.

---

## 1. Shopping List

### 1.1 Per-Bag Components

| Qty | Item | Specification | Source | Est. Cost |
|-----|------|---------------|--------|-----------|
| 1 | Tamper-evident bag | 6×9" security bag with serial number | Amazon/Uline | $1-2 |
| 1 | Waterproof pouch | Small dry bag or ziplock | REI/Amazon | $2-5 |
| 1 | Metal share plate | SLIP-39 share stamped/engraved | Cryptosteel/DIY | $30-50 |
| 1 | MicroSD card | 32GB+ industrial grade | Samsung PRO Endurance | $10-15 |
| 1 | MicroSD to USB-A adapter | Standard USB-A reader | Amazon | $5-8 |
| 1 | YubiKey 5 Nano | USB-A form factor | Yubico | $50 |
| 1 | Humidity indicator card | 6-dot cobalt-free type | Amazon/Uline | $0.50 |
| 1 | Desiccant packet | Silica gel, 5g | Amazon/Uline | $0.25 |
| 1 | Recovery guide | Printed, laminated | Self | $2-3 |
| 1 | 1Password Emergency Kit | Printed, in envelope | Self | $0.50 |

**Per-bag total**: ~$100-135

### 1.2 Shared/One-Time Components

| Qty | Item | Specification | Source | Est. Cost |
|-----|------|---------------|--------|-----------|
| 1 | Airgapped SBC | Orange Pi 5 or similar ARM | Amazon/AliExpress | $80-120 |
| 1 | USB-A hub | 4+ port, powered optional | Amazon | $15-25 |
| 1 | Label maker | Brother P-Touch or similar | Amazon | $30-50 |
| 1 | Label tape | TZe laminated, black on white | Amazon | $15-20 |
| 5 | Metal stamp set | 4mm letter/number punches | Amazon/Harbor Freight | $15-25 |
| 1 | Laminator | Basic letter-size | Amazon | $25-35 |
| 1 | Laminating pouches | 5mil, letter size | Amazon | $10-15 |

**One-time setup total**: ~$190-290

### 1.3 For 3-Bag Standard Deployment

- 3× per-bag kits: ~$300-400
- 1× shared components: ~$190-290
- **Total system cost**: ~$500-700

---

## 2. Bag Assembly Procedure

### 2.1 Pre-Assembly Checklist

- [ ] Clean, dry workspace
- [ ] All components verified functional
- [ ] SLIP-39 shares generated and verified
- [ ] Archive encrypted and copied to all SD cards
- [ ] YubiKeys programmed with identical credentials
- [ ] Humidity indicator shows DRY (blue dots)
- [ ] Camera ready for documentation photos

### 2.2 Assembly Steps

```
1. PREPARE METAL SHARE
   - Stamp share words onto metal plate
   - Verify stamping is legible
   - Label plate with share number (1 of 5, etc.)

2. PREPARE SD CARD
   - Verify LUKS archive mounts correctly
   - Verify archive contents with checksums
   - Label SD card with Greek letter (α, β, γ)
   - Insert into USB-A adapter

3. PREPARE YUBIKEY
   - Verify FIDO2 credentials registered
   - Verify OATH/TOTP seeds loaded
   - Note serial number for records

4. PREPARE DOCUMENTS
   - Print Recovery Guide (2-sided)
   - Laminate Recovery Guide
   - Print 1Password Emergency Kit
   - Place Emergency Kit in small envelope
   - Label envelope "1Password Emergency Kit"

5. INNER ASSEMBLY (Waterproof Pouch)
   - Place metal share plate (largest item, bottom)
   - Place SD card + adapter
   - Place YubiKey
   - Add desiccant packet
   - Add humidity indicator card (visible through pouch)
   - Squeeze out air, seal pouch

6. OUTER ASSEMBLY (Tamper-Evident Bag)
   - Place waterproof pouch in bag
   - Place laminated Recovery Guide (visible)
   - Place 1Password envelope
   - Record bag serial number
   - Seal bag per manufacturer instructions
   - Apply label to bag exterior

7. DOCUMENTATION
   - Photograph sealed bag (front, showing serial)
   - Photograph seal detail
   - Record in 1Password
   - Update manifest
```

### 2.3 Post-Assembly Verification

- [ ] Bag sealed completely (no gaps)
- [ ] Serial number recorded
- [ ] Photos uploaded to 1Password
- [ ] Manifest updated with bag details
- [ ] Sigchain entry created

---

## 3. Label Specifications

### 3.1 Bag Exterior Label

**Format**: Brother TZe tape, 12mm or 18mm width

```
┌────────────────────────────────────────┐
│  BASTION RECOVERY BAG                  │
│  Serial: B1-2025-001                   │
│  Location: HOME                        │
│  Created: 2025-12-12                   │
│  DO NOT OPEN UNLESS AUTHORIZED         │
└────────────────────────────────────────┘
```

**Label Fields**:
- **Serial**: `B<bag#>-<year>-<sequence>`
  - B1, B2, B3 = Bag number
  - 2025 = Year created
  - 001 = Sequence within year (for replacements)
- **Location**: HOME | BANK | CUSTODIAN-A | CUSTODIAN-B | ATTORNEY
- **Created**: ISO date of assembly

### 3.2 Metal Share Plate Marking

**Format**: Stamped or engraved on metal

```
SHARE 1 OF 5
─────────────
[SLIP-39 WORDS]
─────────────
B1-2025-001
```

### 3.3 MicroSD Card Label

**Format**: Micro label or engraved

```
α (or β, γ)
LUKS2
B1-2025-001
```

### 3.4 USB Adapter Label

**Format**: Small label on adapter body

```
SD α → USB
B1-2025-001
```

### 3.5 Recovery Guide Header

**Format**: Printed document, first page header

```
╔══════════════════════════════════════════╗
║     BASTION EMERGENCY RECOVERY GUIDE     ║
║                                          ║
║  Bag Serial: B1-2025-001                 ║
║  Version: 2025-12-12                     ║
║  Owner: [Name]                           ║
╚══════════════════════════════════════════╝
```

---

## 4. Serial Number System

### 4.1 Format Definition

```
Component: Prefix-Year-Sequence

Bag:       B<n>-YYYY-SSS     e.g., B1-2025-001
Share:     S<n>-YYYY-SSS     e.g., S1-2025-001
SD Card:   SD<α>-YYYY-SSS    e.g., SDα-2025-001
YubiKey:   YK-<serial>       e.g., YK-12345678
```

### 4.2 Sequence Rules

- Sequence resets each year
- Replacement bags increment sequence: B1-2025-002
- All components in a bag share the same sequence
- Orphaned components (replaced individually) note parent serial

### 4.3 Version Correlation

All components created together share:
- Same year
- Same sequence number
- Same manifest hash (first 8 chars)

Example: All components in the 2025 initial deployment:
- B1-2025-001, B2-2025-001, B3-2025-001
- S1-2025-001 through S5-2025-001
- SDα-2025-001, SDβ-2025-001, SDγ-2025-001

---

## 5. Storage Requirements

### 5.1 Environmental Conditions

| Parameter | Acceptable Range | Ideal |
|-----------|------------------|-------|
| Temperature | 32-100°F (0-38°C) | 60-75°F (15-24°C) |
| Humidity | 20-80% RH | 30-50% RH |
| Light | Indirect/dark | Dark |
| Magnetic | Away from strong fields | >6" from magnets |

### 5.2 Humidity Indicator Reading

6-dot card interpretation:
- All BLUE: <20% RH - Excellent
- 1-2 PINK: 20-40% RH - Good
- 3-4 PINK: 40-60% RH - Acceptable
- 5-6 PINK: >60% RH - **Replace desiccant**

### 5.3 Location Requirements

| Location | Requirements |
|----------|--------------|
| Home Safe | Fire-rated, bolted, climate controlled |
| Bank Safe Deposit | Standard size, document access procedures |
| Custodian | Secure location, written acknowledgment |
| Attorney | Secure file storage, engagement letter reference |

---

## 6. Inspection Procedure

### 6.1 Routine Inspection (Annual)

Without opening bag:
1. Verify seal is intact
2. Check humidity indicator through pouch (if visible)
3. Photograph current state
4. Compare to previous photos
5. Log inspection in 1Password

### 6.2 Triggered Inspection

If concern about bag condition:
1. Document reason for inspection
2. Photograph before opening
3. Open bag, inspect contents
4. If contents OK, reassemble in NEW bag
5. Update all records with new serial
6. Dispose of old bag securely

---

## 7. Replacement Procedures

### 7.1 Planned Replacement (Rotation)

Every 3-5 years or upon component updates:
1. Generate new archive with current data
2. Assemble new bags with incremented serials
3. Distribute new bags to locations
4. Collect old bags
5. Verify old bag seals intact
6. Destroy old bags securely
7. Update all records

### 7.2 Emergency Replacement

If bag compromised (seal broken, lost, etc.):
1. **Assess scope**: Which bag(s) affected?
2. **If <3 bags compromised**: System still secure
3. Generate new shares (full re-key recommended)
4. Assemble new bags for ALL locations
5. Distribute replacements
6. Collect any recoverable old bags
7. Document incident in sigchain

### 7.3 Component-Only Replacement

If only SD card or YubiKey needs update:
1. Open bag (document seal break)
2. Replace specific component
3. Seal in new bag with incremented serial
4. Update records with component change note

---

## 8. Secure Destruction

### 8.1 Metal Share Plates

- Physical destruction required
- Options: Angle grinder, industrial shredder
- Verify words are unreadable
- Photograph destruction for records

### 8.2 MicroSD Cards

- Secure erase (LUKS header destruction)
- Physical destruction (crush, shred)
- Do not simply format

### 8.3 YubiKeys

- Reset to factory (removes all credentials)
- Physical destruction optional
- Can be repurposed if reset

### 8.4 Paper Documents

- Cross-cut shredding minimum
- Burn if available
- Do not recycle intact

### 8.5 Tamper-Evident Bags

- Cut into multiple pieces
- Serial number must be destroyed
- Dispose in separate trash bags

---

## 9. Supply Sources

### 9.1 Recommended Vendors

| Component | Vendor | Product |
|-----------|--------|---------|
| Security bags | Uline | S-11566 (6×9 tamper evident) |
| Waterproof pouch | Loksak | aLOKSAK 4×7 |
| Metal plates | Cryptosteel | Capsule or Cassette |
| MicroSD | Samsung | PRO Endurance 32GB |
| SD Adapter | Anker | USB 3.0 Card Reader |
| YubiKey | Yubico | YubiKey 5 Nano |
| Humidity cards | Dry & Dry | 6-dot cobalt-free |
| Desiccant | Dry & Dry | 5g silica gel packets |
| Labels | Brother | TZe-231 (12mm B/W) |

### 9.2 Alternative Suppliers

- Security bags: Amazon, Staples (generic)
- Metal plates: Blockplate, Billfodl (alternatives)
- SD cards: SanDisk High Endurance (alternative)

---

## Appendix A: Recovery Guide Template

See [RECOVERY-GUIDE-TEMPLATE.md](./RECOVERY-GUIDE-TEMPLATE.md)

## Appendix B: 1Password Record Template

```
Title: Recovery Bag B1-2025-001
Category: Secure Note
Tags: Bastion/Estate/Recovery-Bag

Fields:
- Serial: B1-2025-001
- Location: Home Safe
- Created: 2025-12-12
- Share Number: 1 of 5
- SD Card: α
- YubiKey Serial: 12345678
- Manifest Hash: a1b2c3d4

Attachments:
- seal-photo-front.jpg
- seal-photo-detail.jpg
- inspection-2025-12-12.jpg
```

## Appendix C: Inspection Log Template

```
## Inspection: B1-2025-001

Date: YYYY-MM-DD
Inspector: [Name]
Type: Routine | Triggered | Pre-transfer

### Observations
- Seal intact: Yes/No
- Humidity indicator: [X] dots pink
- Physical condition: [Description]
- Location verified: Yes/No

### Action Required
- [ ] None
- [ ] Replace desiccant
- [ ] Replace bag
- [ ] Full replacement

### Photos
- [Link to 1Password attachment]

### Signature
Inspected by: _________________ Date: _________
```
