# Bastion Airgap

Air-gapped cryptographic key generation system for SLIP-39 secret sharing.

## Overview

Bastion Airgap provides a secure, air-gapped environment for generating and managing master secrets using:

- **Libre Computer Sweet Potato** as the air-gapped computing platform
- **6-card microSD domain architecture** for isolated key management
- **SLIP-39** (Shamir's Secret Sharing) for 5-share, 3-of-5 recovery
- **Infinite Noise HWRNG** for hardware entropy
- **QR code data transfer** for input/output without network connectivity

## Installation

```bash
# From the airgap directory
pip install -e .

# With camera support for QR code reading
pip install -e ".[camera]"
```

## Usage

```bash
# Card management
airgap cards list
airgap cards provision
airgap cards verify

# Entropy operations
airgap entropy collect
airgap entropy verify

# Key generation (Tier 1 operations)
airgap keygen master
airgap keygen slip39

# System checks
airgap check wireless
airgap check tier
```

## Documentation

See `docs/airgap/` in the main Bastion repository for detailed documentation:

- `AIRGAP-DESIGN-DECISIONS.md` - Architecture and security decisions
- `AIRGAP-CARD-PROVISIONING.md` - MicroSD card setup guide
- `AIRGAP-1PASSWORD-TEMPLATES.md` - 1Password integration templates

## Security Model

This tool is designed for **Tier 1** (highest security) operations:

- No network connectivity
- No wireless hardware
- Hardware entropy only
- QR code data transfer
- Physical isolation

## License

PolyForm Noncommercial License 1.0.0
