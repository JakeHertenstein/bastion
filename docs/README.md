# Bastion Documentation

## Overview

Bastion is a security management CLI for 1Password that provides:
- **Password rotation tracking** with risk-tiered schedules
- **Deterministic username generation** for privacy
- **Hardware entropy collection** from YubiKeys, Infinite Noise TRNGs, and dice
- **YubiKey TOTP management** with multi-key synchronization
 - **Seeder: Offline memory aid** for high‑entropy passwords without a manager; usage validated via entropy and attack‑cost analysis (see packages/seeder/README.md)

## Getting Started

| Document | Description |
|----------|-------------|
| [🚀 GETTING-STARTED.md](getting-started/GETTING-STARTED.md) | **10-minute setup guide** — Install, configure, first sync |
| [DEBUG-GETTING-STARTED.md](getting-started/DEBUG-GETTING-STARTED.md) | Next steps for debugging YubiKey password issues |
| [PLATFORM-COMPATIBILITY.md](getting-started/PLATFORM-COMPATIBILITY.md) | OS support matrix and external dependencies |

## Core Features

### Entropy System

| Document | Description |
|----------|-------------|
| [ENTROPY-SYSTEM.md](features/entropy/ENTROPY-SYSTEM.md) | Hardware entropy collection, XOR+SHAKE256 combining, and 1Password storage |
| [ENTROPY-QUICKREF.md](features/entropy/ENTROPY-QUICKREF.md) | Quick reference for entropy commands |
| [INFNOISE-INSTALLATION.md](features/entropy/INFNOISE-INSTALLATION.md) | Infinite Noise TRNG hardware setup (macOS) |

### Username Generator

| Document | Description |
|----------|-------------|
| [USERNAME-GENERATOR-GUIDE.md](features/username/USERNAME-GENERATOR-GUIDE.md) | Deterministic username generation using HMAC-SHA512 (default) |

### YubiKey Integration

| Document | Description |
|----------|-------------|
| [YubiKey-Sync-Guide](features/yubikey/YUBIKEY-SYNC-GUIDE.md) | Multi-key TOTP synchronization and 1Password linking |
| [ICON-MANAGEMENT.md](features/yubikey/ICON-MANAGEMENT.md) | Icon matching and attachment for OATH accounts |

## 1Password Integration

| Document | Description |
|----------|-------------|
| [1PASSWORD-DATA-MODEL-DECISIONS.md](integration/1PASSWORD-DATA-MODEL-DECISIONS.md) | Data model design decisions for authenticator tokens |
| [1PASSWORD-LINKING-IMPLEMENTATION.md](integration/1PASSWORD-LINKING-IMPLEMENTATION.md) | Native item linking using Related Items |
| [TOKEN-SECTION-STRUCTURE.md](integration/TOKEN-SECTION-STRUCTURE.md) | Token section structure (YubiKey, Phone App, SMS) |
| [BASTION-METADATA-GUIDE.md](integration/BASTION-METADATA-GUIDE.md) | Bastion Metadata section for risk tracking |

## Security & Risk

| Document | Description |
|----------|-------------|
| [BASTION-TAGGING-GUIDE.md](security/BASTION-TAGGING-GUIDE.md) | Hierarchical tag system for account classification |
| [RISK-ANALYSIS.md](security/RISK-ANALYSIS.md) | Risk scoring algorithm and analysis system |

## Airgap

| Document | Description |
|----------|-------------|
| [AIRGAP-DESIGN-DECISIONS.md](airgap/AIRGAP-DESIGN-DECISIONS.md) | Design decisions and security model for the air-gapped system |
| [AIRGAP-CARD-PROVISIONING.md](airgap/AIRGAP-CARD-PROVISIONING.md) | Provisioning encrypted microSD cards and physical procedures |
| [ENCRYPTED-BACKUP.md](airgap/ENCRYPTED-BACKUP.md) | Encrypted backup workflow and verification |
| [GPG-KEY-SETUP.md](airgap/GPG-KEY-SETUP.md) | GPG key generation and transfer via QR |
| [RECOVERY-GUIDE-TEMPLATE.md](airgap/RECOVERY-GUIDE-TEMPLATE.md) | Recovery guide template placeholder (to be completed) |
| [RECOVERY-BAG-PHYSICAL-DESIGN.md](airgap/RECOVERY-BAG-PHYSICAL-DESIGN.md) | Physical recovery bag design and tamper-evidence procedures |
| [ESTATE-VERSION-CONTROL.md](airgap/ESTATE-VERSION-CONTROL.md) | Version control for airgap estate and backup procedures |

## Technical Specifications
## Seeder (Offline Passwords)

Outcome: high‑entropy offline passwords without a manager — deterministic seed cards validated by entropy analysis and attack‑cost modeling.

| [CRYPTO-FUNCTION-MATRIX.md](reference/CRYPTO-FUNCTION-MATRIX.md) | Cryptographic standards and algorithm reference |
| [SIGCHAIN-GUIDE.md](reference/SIGCHAIN-GUIDE.md) | Signature chain (audit trail) design and usage |
|----------|-------------|
| [packages/seeder/README.md](../packages/seeder/README.md) | Overview, CLI/web usage, security notes |
| [packages/seeder/docs/design.md](../packages/seeder/docs/design.md) | Design and deterministic generation workflow |
| [packages/seeder/docs/SECURITY_REVIEW_STRATEGY.md](../packages/seeder/docs/SECURITY_REVIEW_STRATEGY.md) | Security review and validation approach |

## Reference

| Document | Description |
|----------|-------------|
| [LABEL-FORMAT-SPECIFICATION.md](reference/LABEL-FORMAT-SPECIFICATION.md) | Bastion label format for metadata encoding |
| [CRYPTO-FUNCTION-MATRIX.md](reference/CRYPTO-FUNCTION-MATRIX.md) | Cryptographic standards and algorithm reference |

## Troubleshooting

| Document | Description |
|----------|-------------|
| [REGRESSION-FIX-SUMMARY.md](troubleshooting/REGRESSION-FIX-SUMMARY.md) | YubiKey password retrieval fixes and verbose logging |
| [YUBIKEY-DEBUG-GUIDE.md](troubleshooting/YUBIKEY-DEBUG-GUIDE.md) | Comprehensive YubiKey debugging with VS Code integration |
| [YUBIKEY-DEBUG-QUICK-REF.md](troubleshooting/YUBIKEY-DEBUG-QUICK-REF.md) | One-page YubiKey debugging quick reference |
| [DEFENSE-IN-DEPTH-GAPS.md](troubleshooting/DEFENSE-IN-DEPTH-GAPS.md) | Security architecture gaps and mitigation plans |

## Development

| Resource | Description |
|----------|-------------|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Development setup and contribution guidelines |
| [.github/copilot-instructions.md](../.github/copilot-instructions.md) | AI assistant context (monorepo, airgap, seeder) |

**Versioning**: Bastion follows [SemVer](https://semver.org/). The canonical version is stored in [../VERSION](../VERSION) and dynamically read by each package's `pyproject.toml`.

## Link Validation

Run the link validator to check docs for broken links:
```bash
python3 scripts/validate-doc-links.py --ignore docs/private/ --verbose
```

Automated validation:
- **Pre-commit hook** (if `.pre-commit-config.yaml` is configured): Runs on each commit
- **GitHub Actions** (`.github/workflows/validate-links.yml`): Runs on pull requests to `docs/**`
