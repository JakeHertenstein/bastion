# FLT: Fortified Life Trust — Johnny Decimal Taxonomy

> **Version**: 1.0.0
> **Created**: 2025-12-12
> **System**: Johnny Decimal (https://johnnydecimal.com)

---

## Overview

FLT (Fortified Life Trust) is the Johnny Decimal namespace for digital estate planning and legacy management. This taxonomy organizes all components of the Bastion recovery system, legal documents, and related artifacts.

### Johnny Decimal Primer

```
Area:     10-19 (broad category)
Category: 11, 12, 13... (specific type within area)
ID:       11.01, 11.02... (individual item)

Format:   AC.ID where A=Area, C=Category, ID=unique
```

---

## Area Map

```
FLT - Fortified Life Trust
══════════════════════════

10-19  LEGAL FOUNDATION
20-29  CRYPTOGRAPHIC ROOT  
30-39  PHYSICAL ARTIFACTS
40-49  DIGITAL ARCHIVES
50-59  VERIFICATION CHAIN
60-69  PROCEDURES
70-79  CUSTODIANS
80-89  HISTORY & AUDIT
90-99  REFERENCE
```

---

## 10-19: Legal Foundation

Legal documents that authorize and govern the recovery system.

```
10-19 LEGAL FOUNDATION
├── 11 Trust Documents
│   ├── 11.01 Revocable Living Trust (main document)
│   ├── 11.02 Trust Amendment - Digital Assets
│   ├── 11.03 Schedule A - Trust Assets
│   ├── 11.04 Exhibit D - Digital Recovery System
│   └── 11.05 Exhibit E - Custodian Acknowledgment Form
│
├── 12 Powers of Attorney
│   ├── 12.01 Durable Financial POA
│   ├── 12.02 POA Digital Asset Addendum
│   └── 12.03 Limited POA - Digital Recovery
│
├── 13 Healthcare Directives
│   ├── 13.01 Advance Healthcare Directive
│   ├── 13.02 HIPAA Authorization
│   └── 13.03 Digital Health Access Provision
│
├── 14 Will & Probate
│   ├── 14.01 Last Will and Testament
│   ├── 14.02 Pour-Over Provisions
│   └── 14.03 Executor Instructions Letter
│
└── 15 Executed Acknowledgments
    ├── 15.01 Custodian Ack - [Name A]
    ├── 15.02 Custodian Ack - [Name B]
    └── 15.03 Attorney Engagement Letter
```

---

## 20-29: Cryptographic Root

The seed and all cryptographic derivations.

```
20-29 CRYPTOGRAPHIC ROOT
├── 21 Master Seed
│   ├── 21.01 SLIP-39 Seed (256-bit)
│   ├── 21.02 Optional Passphrase (25th word)
│   └── 21.03 Seed Generation Record
│
├── 22 Shamir Shares
│   ├── 22.01 Share 1 - Home
│   ├── 22.02 Share 2 - Bank
│   ├── 22.03 Share 3 - Custodian A
│   ├── 22.04 Share 4 - Custodian B
│   └── 22.05 Share 5 - Attorney
│
├── 23 Derived Keys
│   ├── 23.01 Archive Encryption Key (HKDF)
│   ├── 23.02 YubiKey PIN (HKDF)
│   ├── 23.03 GPG Signing Key (Ed25519)
│   └── 23.04 Username Salt (HKDF)
│
└── 24 Key Derivation Specs
    ├── 24.01 HKDF Parameters
    ├── 24.02 Argon2id Parameters
    └── 24.03 Context Strings
```

---

## 30-39: Physical Artifacts

Tangible items that store or protect secrets.

```
30-39 PHYSICAL ARTIFACTS
├── 31 Metal Share Plates
│   ├── 31.01 Plate S1-2025-001
│   ├── 31.02 Plate S2-2025-001
│   ├── 31.03 Plate S3-2025-001
│   ├── 31.04 Plate S4-2025-001
│   └── 31.05 Plate S5-2025-001
│
├── 32 Recovery Bags
│   ├── 32.01 Bag B1-2025-001 (Home)
│   ├── 32.02 Bag B2-2025-001 (Bank)
│   └── 32.03 Bag B3-2025-001 (Custodian A)
│
├── 33 MicroSD Cards
│   ├── 33.01 SD Card α (SDα-2025-001)
│   ├── 33.02 SD Card β (SDβ-2025-001)
│   └── 33.03 SD Card γ (SDγ-2025-001)
│
├── 34 Hardware Security Keys
│   ├── 34.01 YubiKey Primary (daily carry)
│   ├── 34.02 YubiKey Backup 1 (Bag 1)
│   ├── 34.03 YubiKey Backup 2 (Bag 2)
│   └── 34.04 YubiKey Backup 3 (Bag 3)
│
├── 35 Airgap Computer
│   ├── 35.01 ARM SBC Hardware
│   ├── 35.02 Boot Media (Live Image)
│   ├── 35.03 USB Hub
│   └── 35.04 Display/Keyboard
│
└── 36 Supporting Materials
    ├── 36.01 Humidity Indicator Cards
    ├── 36.02 Desiccant Packets
    ├── 36.03 Waterproof Pouches
    └── 36.04 Tamper-Evident Bags (unused)
```

---

## 40-49: Digital Archives

Encrypted containers and their contents.

```
40-49 DIGITAL ARCHIVES
├── 41 LUKS Containers
│   ├── 41.01 archive-2025-001.luks
│   ├── 41.02 Archive Header Backup
│   └── 41.03 Archive Checksum Record
│
├── 42 Archive Contents
│   ├── 42.01 1Password Export (.1pux)
│   ├── 42.02 GPG Keyring Export
│   ├── 42.03 SSH Keys Archive
│   ├── 42.04 Crypto Wallet Seeds
│   └── 42.05 Estate Documents PDF
│
├── 43 1Password Exports
│   ├── 43.01 Full Vault Export
│   ├── 43.02 Emergency Kits
│   └── 43.03 Export Verification Log
│
└── 44 Supplementary Data
    ├── 44.01 Photo Archive
    ├── 44.02 Document Scans
    └── 44.03 Account Inventory
```

---

## 50-59: Verification Chain

Trust anchors and audit mechanisms.

```
50-59 VERIFICATION CHAIN
├── 51 Manifests
│   ├── 51.01 manifest-2025-001.yaml
│   ├── 51.02 manifest-2025-001.yaml.asc (GPG sig)
│   └── 51.03 manifest-2025-001.yaml.asc.ots
│
├── 52 GPG Infrastructure
│   ├── 52.01 Signing Key (public)
│   ├── 52.02 Key Fingerprint Record
│   └── 52.03 Keyserver Publication
│
├── 53 OpenTimestamps
│   ├── 53.01 OTS Proofs Archive
│   ├── 53.02 Bitcoin Block References
│   └── 53.03 Verification Records
│
├── 54 Sigchain
│   ├── 54.01 Sigchain Database
│   ├── 54.02 Event Types Definition
│   └── 54.03 Chain Verification Log
│
└── 55 1Password Metadata
    ├── 55.01 Deployment Records
    ├── 55.02 Bag Photo Attachments
    └── 55.03 Inspection Logs
```

---

## 60-69: Procedures

Operational guides and checklists.

```
60-69 PROCEDURES
├── 61 Initial Setup
│   ├── 61.01 Seed Generation Procedure
│   ├── 61.02 Share Stamping Guide
│   ├── 61.03 Archive Creation Steps
│   └── 61.04 Bag Assembly Checklist
│
├── 62 Maintenance
│   ├── 62.01 Annual Inspection Procedure
│   ├── 62.02 Rotation Schedule
│   ├── 62.03 Component Replacement Guide
│   └── 62.04 Archive Update Procedure
│
├── 63 Recovery
│   ├── 63.01 Emergency Recovery Guide
│   ├── 63.02 Airgap Boot Procedure
│   ├── 63.03 Share Combination Steps
│   └── 63.04 Post-Recovery Checklist
│
├── 64 Destruction
│   ├── 64.01 Metal Plate Destruction
│   ├── 64.02 SD Card Secure Erase
│   ├── 64.03 YubiKey Reset Procedure
│   └── 64.04 Paper Shredding Protocol
│
└── 65 Emergency Contacts
    ├── 65.01 Attorney Contact Info
    ├── 65.02 Custodian Contact List
    └── 65.03 Technical Support Contacts
```

---

## 70-79: Custodians

People who hold custody of components.

```
70-79 CUSTODIANS
├── 71 Primary Owner
│   ├── 71.01 Owner Profile
│   ├── 71.02 Owner Locations (Home, Bank)
│   └── 71.03 Owner Contact Methods
│
├── 72 Successor Trustee
│   ├── 72.01 Successor Profile
│   ├── 72.02 Succession Triggers
│   └── 72.03 Handoff Procedures
│
├── 73 Bag Custodians
│   ├── 73.01 Custodian A Profile
│   ├── 73.02 Custodian B Profile
│   └── 73.03 Custodian Responsibilities
│
├── 74 Share-Only Custodians
│   ├── 74.01 Attorney (Share 5)
│   └── 74.02 Custodian B (Share 4)
│
└── 75 Executor Chain
    ├── 75.01 Primary Executor
    ├── 75.02 Alternate 1
    ├── 75.03 Alternate 2
    └── 75.04 Alternate 3
```

---

## 80-89: History & Audit

Historical records and change tracking.

```
80-89 HISTORY & AUDIT
├── 81 Deployment History
│   ├── 81.01 Deployment 2025-001 (Active)
│   ├── 81.02 [Future deployments...]
│   └── 81.nn Previous Deployments
│
├── 82 Inspection History
│   ├── 82.01 Inspection 2025-12-12
│   └── 82.nn [Subsequent inspections]
│
├── 83 Incident Records
│   ├── 83.01 [Any incidents...]
│   └── 83.nn [Incident responses]
│
├── 84 Change Log
│   ├── 84.01 System Changes
│   ├── 84.02 Document Revisions
│   └── 84.03 Custodian Changes
│
└── 85 Destruction Records
    ├── 85.01 [Destruction events...]
    └── 85.nn [Verification photos]
```

---

## 90-99: Reference

Supporting documentation and specifications.

```
90-99 REFERENCE
├── 91 Technical Specifications
│   ├── 91.01 SLIP-39 Specification
│   ├── 91.02 LUKS2 Parameters
│   ├── 91.03 YubiKey Configuration
│   └── 91.04 OpenTimestamps Protocol
│
├── 92 Bastion Documentation
│   ├── 92.01 README
│   ├── 92.02 DEFENSE-IN-DEPTH-GAPS
│   ├── 92.03 ENTROPY-SYSTEM
│   └── 92.04 [Other Bastion docs]
│
├── 93 Legal Templates
│   ├── 93.01 Custodian Acknowledgment Template
│   ├── 93.02 POA Language Template
│   └── 93.03 Trust Amendment Template
│
├── 94 Vendor Information
│   ├── 94.01 Yubico (YubiKeys)
│   ├── 94.02 Cryptosteel (Metal plates)
│   └── 94.03 Hardware suppliers
│
└── 95 External Resources
    ├── 95.01 Johnny Decimal System
    ├── 95.02 SLIP-39 Reference
    └── 95.03 1Password CLI Documentation
```

---

## Index Format

Full Johnny Decimal IDs for FLT use the prefix notation:

```
FLT.AC.ID

Examples:
  FLT.21.01  - Master SLIP-39 Seed
  FLT.32.01  - Recovery Bag B1-2025-001
  FLT.51.01  - Manifest for deployment 2025-001
  FLT.63.01  - Emergency Recovery Guide
```

---

## Cross-Reference Table

| Component | JD ID | Serial/Name | Location |
|-----------|-------|-------------|----------|
| Master Seed | FLT.21.01 | — | Derived from shares |
| Share 1 | FLT.22.01 | S1-2025-001 | B1 (Home) |
| Share 2 | FLT.22.02 | S2-2025-001 | B2 (Bank) |
| Share 3 | FLT.22.03 | S3-2025-001 | B3 (Custodian A) |
| Share 4 | FLT.22.04 | S4-2025-001 | Custodian B |
| Share 5 | FLT.22.05 | S5-2025-001 | Attorney |
| Bag 1 | FLT.32.01 | B1-2025-001 | Home Safe |
| Bag 2 | FLT.32.02 | B2-2025-001 | Bank Safe Deposit |
| Bag 3 | FLT.32.03 | B3-2025-001 | Custodian A |
| SD α | FLT.33.01 | SDα-2025-001 | B1 |
| SD β | FLT.33.02 | SDβ-2025-001 | B2 |
| SD γ | FLT.33.03 | SDγ-2025-001 | B3 |
| Archive | FLT.41.01 | archive-2025-001.luks | SD cards |
| Manifest | FLT.51.01 | manifest-2025-001.yaml | 1Password |
| Recovery Guide | FLT.63.01 | — | In each bag |
| Trust | FLT.11.01 | — | Attorney file |
| POA | FLT.12.01 | — | Attorney file |

---

## Usage Notes

### Finding Items

1. **By function**: Start with Area (10s=Legal, 20s=Crypto, 30s=Physical, etc.)
2. **By type**: Narrow to Category (31=Metal plates, 32=Bags, 33=SD cards)
3. **By instance**: Identify specific ID (32.01=Bag 1, 32.02=Bag 2)

### Adding Items

- New items get next available ID in their category
- Never reuse IDs (even if item destroyed)
- Document additions in 84.01 Change Log

### Relating to Bastion

Bastion CLI could reference JD IDs:

```bash
# Reference item by JD ID
bastion estate show FLT.32.01

# List items in category
bastion estate list FLT.32

# Search across areas
bastion estate search "custodian"
```

---

## Appendix: Quick Reference Card

```
╔═══════════════════════════════════════════════════════╗
║              FLT JOHNNY DECIMAL QUICK REF             ║
╠═══════════════════════════════════════════════════════╣
║  10-19  Legal        Trust, POA, Will, Acknowledgments║
║  20-29  Crypto       Seed, Shares, Derived Keys       ║
║  30-39  Physical     Plates, Bags, SD Cards, YubiKeys ║
║  40-49  Archives     LUKS containers, Exports         ║
║  50-59  Verification Manifests, Signatures, Sigchain  ║
║  60-69  Procedures   Setup, Maintenance, Recovery     ║
║  70-79  Custodians   Owner, Trustees, Executors       ║
║  80-89  History      Deployments, Inspections, Audits ║
║  90-99  Reference    Specs, Docs, Templates           ║
╠═══════════════════════════════════════════════════════╣
║  Format: FLT.AC.ID   Example: FLT.32.01 = Bag 1       ║
╚═══════════════════════════════════════════════════════╝
```
