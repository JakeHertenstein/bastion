# Estate Version Control Specification

> **Version**: 1.0.0
> **Created**: 2025-12-12
> **Status**: Design Complete

---

## Overview

This document defines the version control system for Bastion digital estate components. The goal is to maintain cryptographic proof of authenticity and enable verification that all components belong to the same deployment generation.

---

## 1. Version Correlation Model

### 1.1 Core Principle

All components created in a single deployment share:
1. **Year**: Calendar year of creation
2. **Sequence**: Deployment sequence within year  
3. **Manifest Hash**: SHA-256 of signed manifest (first 8 chars)

This creates a three-part version identifier that cryptographically links all components.

### 1.2 Version Identifier Format

```
Full:    YYYY-SSS-HHHHHHHH
Short:   YYYY-SSS
Example: 2025-001-a1b2c3d4
```

### 1.3 Component Serial Formats

| Component | Format | Example |
|-----------|--------|---------|
| Recovery Bag | B<n>-YYYY-SSS | B1-2025-001 |
| Metal Share | S<n>-YYYY-SSS | S1-2025-001 |
| SD Card | SD<letter>-YYYY-SSS | SDα-2025-001 |
| Archive | archive-YYYY-SSS.luks | archive-2025-001.luks |
| Manifest | manifest-YYYY-SSS.sig | manifest-2025-001.sig |

---

## 2. Manifest Structure

### 2.1 Manifest Contents

```yaml
# manifest-2025-001.yaml
version: "1.0"
created: "2025-12-12T10:30:00Z"
deployment: "2025-001"

owner:
  name: "[Redacted in distributed copies]"
  email_hash: "sha256:first8chars"

components:
  bags:
    - serial: "B1-2025-001"
      location: "HOME"
      share: 1
      sd_card: "α"
      yubikey_serial: "12345678"
    - serial: "B2-2025-001"
      location: "BANK"
      share: 2
      sd_card: "β"
      yubikey_serial: "12345679"
    - serial: "B3-2025-001"
      location: "CUSTODIAN-A"
      share: 3
      sd_card: "γ"
      yubikey_serial: "12345680"

  shares:
    threshold: 3
    total: 5
    locations:
      - share: 1, location: "B1-2025-001"
      - share: 2, location: "B2-2025-001"
      - share: 3, location: "B3-2025-001"
      - share: 4, location: "CUSTODIAN-B"
      - share: 5, location: "ATTORNEY"

  archive:
    filename: "archive-2025-001.luks"
    encryption: "LUKS2"
    cipher: "aes-xts-plain64"
    kdf: "argon2id"
    hash: "sha256:fullhash"

  yubikeys:
    model: "YubiKey 5 Nano"
    serials:
      - "12345678"
      - "12345679"
      - "12345680"

checksums:
  algorithm: "sha256"
  archive: "full64charhash..."
  sd_alpha: "full64charhash..."
  sd_beta: "full64charhash..."
  sd_gamma: "full64charhash..."

signature:
  key_fingerprint: "ABCD1234..."
  algorithm: "Ed25519"
  
timestamps:
  created: "2025-12-12T10:30:00Z"
  ots_pending: true
```

### 2.2 Manifest Signing

```bash
# Sign manifest
gpg --armor --detach-sign manifest-2025-001.yaml

# Creates: manifest-2025-001.yaml.asc

# Verify signature
gpg --verify manifest-2025-001.yaml.asc manifest-2025-001.yaml
```

### 2.3 OpenTimestamps Anchoring

```bash
# Create timestamp
ots stamp manifest-2025-001.yaml.asc

# Creates: manifest-2025-001.yaml.asc.ots

# Verify timestamp (after Bitcoin confirmation)
ots verify manifest-2025-001.yaml.asc.ots
```

---

## 3. Sigchain Integration

### 3.1 Event Types

```
ESTATE_DEPLOY      - New deployment created
ESTATE_BAG_SEAL    - Individual bag sealed
ESTATE_BAG_INSPECT - Bag inspection performed
ESTATE_BAG_OPEN    - Bag opened (authorized or not)
ESTATE_BAG_REPLACE - Bag replaced with new serial
ESTATE_REKEY       - Full system re-keying
ESTATE_TRANSFER    - Custody transferred
```

### 3.2 Event Structure

```json
{
  "event_type": "ESTATE_DEPLOY",
  "timestamp": "2025-12-12T10:30:00Z",
  "deployment": "2025-001",
  "manifest_hash": "sha256:a1b2c3d4...",
  "details": {
    "bags_created": 3,
    "shares_total": 5,
    "threshold": 3
  },
  "prev_hash": "sha256:previous_event_hash",
  "signature": "base64:signature..."
}
```

### 3.3 Chain Verification

```bash
bsec sigchain verify --deployment 2025-001
```

Output:
```
Sigchain Verification: 2025-001
================================
Events: 7
First: 2025-12-12T10:30:00Z (ESTATE_DEPLOY)
Last:  2025-12-12T11:45:00Z (ESTATE_BAG_SEAL)

Chain Integrity: ✓ Valid
Signatures:      ✓ All verified
Timestamps:      ✓ OTS anchored

Events:
  1. ESTATE_DEPLOY      2025-12-12T10:30:00Z ✓
  2. ESTATE_BAG_SEAL    2025-12-12T10:45:00Z ✓ (B1-2025-001)
  3. ESTATE_BAG_SEAL    2025-12-12T11:00:00Z ✓ (B2-2025-001)
  4. ESTATE_BAG_SEAL    2025-12-12T11:15:00Z ✓ (B3-2025-001)
  ...
```

---

## 4. Version Lifecycle

### 4.1 States

```
PENDING   → Components being assembled
ACTIVE    → Deployed and in use
REPLACED  → Superseded by newer version
REVOKED   → Compromised, do not use
```

### 4.2 Transitions

```
PENDING  --[all bags sealed]--> ACTIVE
ACTIVE   --[new deployment]---> REPLACED
ACTIVE   --[compromise]-------> REVOKED
REPLACED --[destroy old]------> [archived]
REVOKED  --[destroy all]------> [archived]
```

### 4.3 Version History Record

Stored in 1Password:

```
Title: Deployment History
Category: Secure Note
Tags: Bastion/Estate/History

## Active Deployment
- Version: 2025-001
- Created: 2025-12-12
- Status: ACTIVE
- Manifest: sha256:a1b2c3d4...

## Previous Deployments
### 2024-001 (REPLACED)
- Created: 2024-06-15
- Replaced: 2025-12-12
- Reason: Annual rotation
- Destruction confirmed: 2025-12-15
```

---

## 5. Cross-Reference System

### 5.1 Component → Deployment Lookup

Given any component serial, find its deployment:

```
Input:  B2-2025-001
Parse:  B<bag>=2, <year>=2025, <seq>=001
Result: Deployment 2025-001
```

### 5.2 Deployment → Components Lookup

Given deployment, list all components:

```bash
bsec estate list --deployment 2025-001
```

Output:
```
Deployment: 2025-001
Created: 2025-12-12
Status: ACTIVE

Bags:
  B1-2025-001  HOME        Share 1, SD α
  B2-2025-001  BANK        Share 2, SD β
  B3-2025-001  CUSTODIAN-A Share 3, SD γ

Shares:
  S1-2025-001  → B1-2025-001
  S2-2025-001  → B2-2025-001
  S3-2025-001  → B3-2025-001
  S4-2025-001  CUSTODIAN-B (share only)
  S5-2025-001  ATTORNEY (share only)

Archive: archive-2025-001.luks
Manifest: manifest-2025-001.sig
```

### 5.3 Verification Query

Given a bag, verify it belongs to current active deployment:

```bash
bsec estate verify B2-2025-001
```

Output:
```
Bag: B2-2025-001
Deployment: 2025-001
Status: ACTIVE ✓

Matches active deployment: ✓
Manifest signature valid:  ✓
OTS timestamp verified:    ✓
Sigchain event found:      ✓ (ESTATE_BAG_SEAL @ 2025-12-12T11:00:00Z)

This bag is authentic and current.
```

---

## 6. Replacement Scenarios

### 6.1 Full Rotation (Planned)

Annual or scheduled replacement of entire system:

```
Old: 2025-001 (ACTIVE)
New: 2026-001 (PENDING → ACTIVE)

Steps:
1. Create 2026-001 manifest
2. Assemble all new components
3. Sign and timestamp manifest
4. Distribute new bags
5. Collect old bags
6. Verify old seals intact
7. Mark 2025-001 as REPLACED
8. Destroy old components
9. Log destruction in sigchain
```

### 6.2 Single Bag Replacement

One bag damaged or compromised:

```
Old: B2-2025-001
New: B2-2025-002 (incremented sequence for that bag only)

Note: Creates a "mixed" deployment with version annotation:
- 2025-001 base
- B2 updated to 2025-002

Manifest updated with amendment:
  amendments:
    - date: 2025-08-15
      type: "BAG_REPLACE"
      old: "B2-2025-001"
      new: "B2-2025-002"
      reason: "Water damage"
```

### 6.3 Emergency Re-Key

If compromise suspected:

```
Old: 2025-001 (ACTIVE → REVOKED)
New: 2025-002 (PENDING → ACTIVE)

Steps:
1. Generate NEW master seed
2. Create entirely new deployment
3. All new shares, archives, bags
4. Distribute replacements
5. Mark 2025-001 as REVOKED
6. Destroy all old components immediately
7. Do NOT wait for old bag collection
```

---

## 7. 1Password Metadata Integration

### 7.1 Record Types

```
Category: Secure Note
Tag Hierarchy:
  Bastion/
    Estate/
      Deployment/    - Deployment records
      Recovery-Bag/  - Individual bag records
      History/       - Version history
      Manifest/      - Manifest copies
```

### 7.2 Deployment Record Template

```
Title: Deployment 2025-001
Tags: Bastion/Estate/Deployment

## Status
Current: ACTIVE

## Components
- Bags: 3 (B1, B2, B3)
- Shares: 5 (3-of-5 threshold)
- SD Cards: 3 (α, β, γ)
- YubiKeys: 3

## Verification
- Manifest Hash: sha256:a1b2c3d4...
- GPG Signature: ✓ Verified
- OTS Timestamp: ✓ Block 800000

## Attachments
- manifest-2025-001.yaml
- manifest-2025-001.yaml.asc
- manifest-2025-001.yaml.asc.ots
```

### 7.3 Bag Record Template

```
Title: Recovery Bag B1-2025-001
Tags: Bastion/Estate/Recovery-Bag

## Identity
- Serial: B1-2025-001
- Deployment: 2025-001
- Location: Home Safe

## Contents
- Share: 1 of 5
- SD Card: α
- YubiKey: 12345678

## Status
- Sealed: 2025-12-12
- Last Inspection: 2025-12-12
- Condition: Sealed/Intact

## Attachments
- seal-photo-front.jpg
- seal-photo-detail.jpg
```

---

## 8. Audit Trail

### 8.1 Required Audit Points

| Event | Logged In | Timestamped |
|-------|-----------|-------------|
| Deployment created | Sigchain, 1P | OTS |
| Bag sealed | Sigchain, 1P | OTS |
| Bag inspected | 1P | — |
| Bag opened | Sigchain, 1P | OTS |
| Bag replaced | Sigchain, 1P | OTS |
| System re-keyed | Sigchain, 1P | OTS |
| Component destroyed | Sigchain, 1P | — |

### 8.2 Audit Query

```bash
bsec estate audit --deployment 2025-001 --from 2025-01-01
```

Output:
```
Audit Log: Deployment 2025-001
From: 2025-01-01 to present

Date                Event              Target        Verified
─────────────────────────────────────────────────────────────
2025-12-12 10:30    ESTATE_DEPLOY      2025-001     ✓ OTS
2025-12-12 10:45    ESTATE_BAG_SEAL    B1-2025-001  ✓ OTS
2025-12-12 11:00    ESTATE_BAG_SEAL    B2-2025-001  ✓ OTS
2025-12-12 11:15    ESTATE_BAG_SEAL    B3-2025-001  ✓ OTS
2025-06-15 14:00    ESTATE_BAG_INSPECT B1-2025-001  —
2025-06-15 14:30    ESTATE_BAG_INSPECT B2-2025-001  —

Total events: 6
OTS verified: 4
```

---

## 9. Recovery Verification

### 9.1 During Recovery

When bags are opened for recovery, verify versions match:

```bash
# On airgap machine with collected bags
bsec estate verify-recovery B1-2025-001 B2-2025-001 B3-2025-001
```

Output:
```
Recovery Verification
═════════════════════

Bags presented: 3
  B1-2025-001  ✓ Valid
  B2-2025-001  ✓ Valid  
  B3-2025-001  ✓ Valid

Deployment match: ✓ All from 2025-001
Threshold met:    ✓ 3 of 3 required shares
Archive match:    ✓ All SD cards contain identical archive

Ready for recovery: YES
```

### 9.2 Mismatch Handling

If versions don't match:

```
WARNING: Version Mismatch Detected

Bags presented:
  B1-2025-001  Deployment: 2025-001
  B2-2025-002  Deployment: 2025-001 (amended)
  B3-2024-001  Deployment: 2024-001 ← MISMATCH

B3-2024-001 is from a previous deployment.
This may indicate:
  - Old bag not replaced during rotation
  - Bag swap or tampering
  - Collection error

Recommended action:
  - Locate B3-2025-001 from CUSTODIAN-A
  - Or use Share 4 from CUSTODIAN-B instead
```

---

## Appendix: Version Control Checklist

### New Deployment

- [ ] Generate new sequence number
- [ ] Create manifest YAML
- [ ] Sign manifest with GPG
- [ ] Timestamp with OpenTimestamps
- [ ] Log ESTATE_DEPLOY to sigchain
- [ ] Create 1Password deployment record
- [ ] Label all components with version
- [ ] Log each ESTATE_BAG_SEAL
- [ ] Upload all photos
- [ ] Verify OTS confirmation (wait ~2 hours)

### Replacement

- [ ] Determine scope (full/partial)
- [ ] Increment appropriate serial(s)
- [ ] Update or create new manifest
- [ ] Sign updated manifest
- [ ] Log appropriate events
- [ ] Update 1Password records
- [ ] Mark old version as REPLACED
- [ ] Document destruction of old components
