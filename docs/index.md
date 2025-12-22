---
title: Bastion Security Suite
description: Hardware-entropy, deterministic identities, air‑gapped secrets, and 1Password‑native security governance.
layout: default
---

# Bastion — Security Management for 1Password

Build verifiable trust with hardware entropy, deterministic identities, air‑gapped secrets, and deep 1Password CLI v2 integration.

<!-- Hero logo -->
<img src="assets/logos/bastion-logo.svg" alt="Bastion Logo" width="160" />

## Highlights
- Hardware entropy: YubiKey HMAC, Infinite Noise TRNG, dice; XOR + SHAKE256 combination.
- Deterministic usernames: reproducible, auditable labels and verification.
- 1Password‑native: encrypted local cache, hierarchical tags, safe field linking.
- Air‑gap tooling: SLIP‑39 (3‑of‑5), QR transfer (non‑secret), wireless hard‑block enforcement.
- Seeder app: offline high‑entropy token matrices (CR80 cards) with Argon2id.

## Quickstart

Install:
  pip install bastion-security

Initialize configuration:
  bsec init

1Password sync:
  bsec 1p sync

Generate a deterministic username:
  bsec generate username github.com

Collect hardware entropy from YubiKey:
  bsec generate entropy yubikey --bits 8192

Air‑gap public key export via QR (on air‑gapped device):
  airgap export pubkey --qr

## Packages
- [packages/airgap/README.md](../packages/airgap/README.md)
- Getting Started: [docs/GETTING-STARTED.md](getting-started/GETTING-STARTED.md)
- Air‑gap Design: [docs/airgap/AIRGAP-DESIGN-DECISIONS.md](airgap/AIRGAP-DESIGN-DECISIONS.md)
 - Tagging: [docs/security/BASTION-TAGGING-GUIDE.md](security/BASTION-TAGGING-GUIDE.md)
 - Linking: [docs/integration/1PASSWORD-LINKING-IMPLEMENTATION.md](integration/1PASSWORD-LINKING-IMPLEMENTATION.md)
 - Crypto Matrix: [docs/reference/CRYPTO-FUNCTION-MATRIX.md](reference/CRYPTO-FUNCTION-MATRIX.md)

### Troubleshooting
- Multi‑Machine Cache Sync: [docs/troubleshooting/MULTI-MACHINE-CACHE-SYNC.md](troubleshooting/MULTI-MACHINE-CACHE-SYNC.md)

### Air‑gap Assets
- Recovery Bag Diagram: [docs/airgap/recovery-bag.mmd](airgap/recovery-bag.mmd)

## Demos
Recorded flows live in [scripts/demos/README.md](../scripts/demos/README.md). Example sessions:
- Initial setup: scripts/demos/demo-01-initial-setup.cast
- Daily checks: scripts/demos/demo-02-daily-check.cast
- YubiKey management: scripts/demos/demo-03-yubikey-mgmt.cast
- Username generation: scripts/demos/demo-04-username-gen.cast
- Entropy collection: scripts/demos/demo-05-entropy-collect.cast

## Seeder App
Generate offline high‑entropy token matrices for recovery cards.

- Deterministic 10×10 token grids; CSV export.
- Argon2id KDF; rejection sampling to remove modulo bias.
- Multiple sources (simple phrase, BIP‑39, SLIP‑39) with HMAC labeling.
- Offline/PWA web UI; no tracking.

**[Try the live app](https://seeder.bastion.jakehertenstein.omg.lol)** | [Documentation](../packages/seeder/README.md) | [Seeder Docs](../packages/seeder/docs/)
