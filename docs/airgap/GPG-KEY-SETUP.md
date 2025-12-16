# GPG Key Setup for Airgap-Manager Workflow

This guide covers generating GPG keys on the airgap machine with ENT-verified entropy, transferring them to YubiKey, and establishing secure communication with the manager machine.

## Overview

The airgap/manager architecture uses GPG encryption for secure data transfer:

```
┌─────────────────┐                     ┌─────────────────┐
│   AIRGAP        │                     │   MANAGER       │
│                 │                     │                 │
│  Generate Keys  │ ───── QR ─────────▶ │  Import PubKey  │
│  (with HW RNG)  │                     │                 │
│                 │                     │                 │
│  Export Salt    │ ───── QR ─────────▶ │  Import Salt    │
│  (encrypted)    │   (GPG encrypted)   │  (decrypt)      │
│                 │                     │                 │
│  Backup Keys    │ ───── USB ────────▶ │  (offline)      │
│  (LUKS USB)     │   (cold storage)    │                 │
└─────────────────┘                     └─────────────────┘
```

## Prerequisites

### Airgap Machine

- Air-gapped system (no network)
- Hardware entropy source (Infinite Noise TRNG recommended)
- YubiKey 5 series with OpenPGP support
- USB drive for encrypted backups
- `ent` tool for entropy analysis: `brew install ent` or `apt install ent`

### Manager Machine

- Network-connected system
- 1Password CLI configured
- USB QR scanner (or webcam)
- YubiKey with same keys (for decryption)

## Step 1: Generate Master Key

Generate a GPG master key with ENT-verified entropy from hardware RNG:

```bash
# On airgap machine
airgap keygen master --algorithm rsa4096 --name "Your Name" --email "you@example.com"
```

This command:
1. Collects entropy from Infinite Noise TRNG (or YubiKey if unavailable)
2. Runs ENT analysis to verify quality (requires GOOD or better)
3. Injects entropy into kernel pool via `RNDADDENTROPY`
4. Invokes GPG key generation

**Options:**
- `--algorithm`: `rsa4096` (compatible) or `ed25519` (modern)
- `--min-quality`: `EXCELLENT` (default), `GOOD`, `FAIR`
- `--bits`: Entropy bits to collect (default: 8192)

### Entropy Quality Thresholds

| Quality | Chi-Square | Serial Correlation | Mean Deviation |
|---------|------------|-------------------|----------------|
| EXCELLENT | 125-275 | < 0.01 | < 1.0 |
| GOOD | 100-300 | < 0.05 | < 2.0 |
| FAIR | 50-350 | < 0.10 | < 5.0 |

## Step 2: Generate Subkeys

Create signing, encryption, and authentication subkeys:

```bash
airgap keygen subkeys
```

This creates:
- **[S]** Signing subkey (code signing, git commits)
- **[E]** Encryption subkey (encrypting data)
- **[A]** Authentication subkey (SSH, login)

## Step 3: Transfer to YubiKey

Move subkeys to YubiKey hardware (irreversible):

```bash
airgap keygen transfer-to-yubikey
```

**Warning**: This operation moves keys to YubiKey. The private keys will no longer exist on the airgap machine after transfer.

YubiKey slot assignments:
- Signature slot → Signing subkey [S]
- Encryption slot → Encryption subkey [E]  
- Authentication slot → Authentication subkey [A]

## Step 4: Create Encrypted Backup

Before transferring to YubiKey, create an encrypted backup:

```bash
# List available USB devices
airgap backup create --list-devices

# Create LUKS-encrypted backup
airgap backup create --device /dev/diskN
```

This creates a LUKS2-encrypted container containing:
- Master secret key
- Subkeys
- Public key
- Revocation certificate

### Backup Security

- Use a strong passphrase (diceware recommended)
- Store backup in secure location (safe deposit box)
- Consider creating multiple backup copies
- Test restoration before relying on backup

### Verify Backup

```bash
airgap backup verify --device /dev/diskN
```

## Step 5: Export Public Key

Export public key for the manager machine:

```bash
# Export to file (for USB transfer)
airgap export pubkey --output pubkey.asc

# Display as QR code (for scanning)
airgap export pubkey --qr
```

## Step 6: Import on Manager

On the manager machine, import the public key:

```bash
# From file (USB transfer)
bastion import pubkey --file pubkey.asc

# From QR scanner
bastion import pubkey
# Then scan QR code(s)
```

## Salt Export/Import Workflow

Once keys are established, export encrypted salt:

### On Airgap (Export)

```bash
airgap export salt --recipient <KEY_ID> --bits 256
```

This:
1. Generates 256-bit salt with ENT-verified entropy
2. Encrypts to manager's public key
3. Displays as QR code(s) for scanning

### On Manager (Import)

```bash
bastion import salt
# Scan QR code(s) with USB scanner
# Touch YubiKey when prompted for decryption
```

The salt is stored in 1Password with tag `Bastion/SALT/username`.

## Key Management Commands

### List Keys

```bash
# On airgap - show secret keys
airgap keys list --secret

# Show public keys only
airgap keys list
```

### Import Keys

```bash
# Import a public key file
airgap keys import pubkey.asc
```

### Export Keys

```bash
# Export public key
airgap keys export --key <KEY_ID> --output key.asc

# Export secret key (DANGER - backup only)
airgap keys export --key <KEY_ID> --secret --output secret.asc
```

## QR Code Protocol

Multi-QR codes use the `BASTION:` protocol:

```
BASTION:1/3:<base64_chunk_1>
BASTION:2/3:<base64_chunk_2>
BASTION:3/3:<base64_chunk_3>
```

- Maximum 2000 bytes per QR code
- Error correction level: H (30% recovery)
- Automatic reassembly on import

## Troubleshooting

### "No hardware entropy available"

- Connect Infinite Noise TRNG or YubiKey
- Check device permissions: `ls -la /dev/infnoise`
- Verify YubiKey detected: `ykman info`

### "Entropy quality below threshold"

- Try collecting more bits: `--bits 16384`
- Use a different entropy source
- For development only: `--min-quality FAIR`

### "GPG key generation failed"

- Check GPG version: `gpg --version` (needs 2.2+)
- Verify gpg-agent running: `gpgconf --launch gpg-agent`
- Check for existing keys: `gpg --list-secret-keys`

### "YubiKey touch timeout"

- Touch YubiKey within 60 seconds when prompted
- Check YubiKey connection: `gpg --card-status`
- Reset GPG agent: `gpgconf --kill gpg-agent`

### "1Password error on import"

- Ensure `op` CLI is authenticated: `op whoami`
- Check vault exists: `op vault list`
- Verify write permissions to vault

## Security Considerations

1. **Never connect airgap machine to network** - All transfers via QR/USB
2. **Verify entropy quality** - Always check ENT analysis output
3. **Backup before YubiKey transfer** - Key movement is irreversible
4. **Protect backup passphrase** - Consider diceware + YubiKey static
5. **Store revocation certificate separately** - Not on same backup device
6. **Verify key fingerprints** - Always verify after transfer

## References

- [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) - Comprehensive YubiKey GPG guide
- [GnuPG Manual](https://www.gnupg.org/documentation/manuals/gnupg/) - Official documentation
- [NIST SP 800-90B](https://csrc.nist.gov/publications/detail/sp/800-90b/final) - Entropy source recommendations
- [Infinite Noise TRNG](https://www.waywardgeek.net/infnoise/) - Hardware RNG documentation
