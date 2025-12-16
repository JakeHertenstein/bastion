# Bastion Documentation

## Overview

Bastion is a security management CLI for 1Password that provides:
- **Password rotation tracking** with risk-tiered schedules
- **Deterministic username generation** for privacy
- **Hardware entropy collection** from YubiKeys, Infinite Noise TRNGs, and dice
- **YubiKey TOTP management** with multi-key synchronization

## Getting Started

| Document | Description |
|----------|-------------|
| [🚀 GETTING-STARTED.md](GETTING-STARTED.md) | **10-minute setup guide** — Install, configure, first sync |
| [RISK-ANALYSIS.md](RISK-ANALYSIS.md) | Risk scoring algorithm and analysis system |

## Core Features

### Entropy System

| Document | Description |
|----------|-------------|
| [ENTROPY-SYSTEM.md](ENTROPY-SYSTEM.md) | Hardware entropy collection, XOR+SHAKE256 combining, and 1Password storage |
| [ENTROPY-QUICKREF.md](ENTROPY-QUICKREF.md) | Quick reference for entropy commands |
| [INFNOISE-INSTALLATION.md](INFNOISE-INSTALLATION.md) | Infinite Noise TRNG hardware setup (macOS) |

### Username Generator

| Document | Description |
|----------|-------------|
| [USERNAME-GENERATOR-GUIDE.md](USERNAME-GENERATOR-GUIDE.md) | Deterministic username generation using HMAC-SHA512 (default) |

### YubiKey Integration

| Document | Description |
|----------|-------------|
| [YUBIKEY-SYNC-GUIDE.md](YUBIKEY-SYNC-GUIDE.md) | Multi-key TOTP synchronization and 1Password linking |

## 1Password Integration

| Document | Description |
|----------|-------------|
| [1PASSWORD-DATA-MODEL-DECISIONS.md](1PASSWORD-DATA-MODEL-DECISIONS.md) | Data model design decisions for authenticator tokens |
| [1PASSWORD-LINKING-IMPLEMENTATION.md](1PASSWORD-LINKING-IMPLEMENTATION.md) | Native item linking using Related Items |
| [TOKEN-SECTION-STRUCTURE.md](TOKEN-SECTION-STRUCTURE.md) | Token section structure (YubiKey, Phone App, SMS) |
| [BASTION-METADATA-GUIDE.md](BASTION-METADATA-GUIDE.md) | Bastion Metadata section for risk tracking |

## Tagging System

| Document | Description |
|----------|-------------|
| [BASTION-TAGGING-GUIDE.md](BASTION-TAGGING-GUIDE.md) | Hierarchical tag system for account classification |

## Technical Specifications

| Document | Description |
|----------|-------------|
| [LABEL-FORMAT-SPECIFICATION.md](LABEL-FORMAT-SPECIFICATION.md) | Bastion label format for metadata encoding |

## Development

| Resource | Description |
|----------|-------------|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Development setup and contribution guidelines |
| [.github/copilot-instructions.md](../.github/copilot-instructions.md) | AI assistant context and versioning policy |

**Versioning**: Bastion follows [SemVer](https://semver.org/). Version is defined in `bastion/__init__.py`.
