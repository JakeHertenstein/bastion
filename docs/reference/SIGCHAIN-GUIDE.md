# Sigchain Guide

Bastion's sigchain provides a cryptographic audit trail for all security operations. Every username generation, entropy collection, tag change, and password rotation is recorded in an append-only log with optional Bitcoin timestamping.

## Overview

The sigchain is inspired by [Keybase's sigchain design](https://book.keybase.io/docs/sigchain), adapted for personal security management:

```
┌─────────────────────────────────────────────────────────────────┐
│                    BASTION SIGCHAIN                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────┐    ┌──────┐    ┌──────┐    ┌──────┐                  │
│  │ E1   │───▶│ E2   │───▶│ E3   │───▶│ E4   │───▶ ...         │
│  │h:null│    │h:H(1)│    │h:H(2)│    │h:H(3)│                  │
│  └──────┘    └──────┘    └──────┘    └──────┘                  │
│     │           │           │           │                       │
│     └───────────┴───────────┴───────────┘                       │
│                       │                                         │
│              ┌────────▼────────┐                                │
│              │   Merkle Root   │                                │
│              │    (anchor)     │                                │
│              └────────┬────────┘                                │
│                       │                                         │
│              ┌────────▼────────┐                                │
│              │  Bitcoin Block  │                                │
│              │  (OTS proof)    │                                │
│              └─────────────────┘                                │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### Bastion Manager (Connected Machine)
- Daily-use machine with network access
- Submits merkle roots to OTS calendar servers
- Imports events from Bastion Enclave
- Stores chain in Git with GPG-signed commits

### Bastion Enclave (Air-Gapped Machine)
- Offline machine for high-security operations
- Generates keys, SLIP-39 shares, collects entropy
- Exports events via QR codes for Manager import
- Minimal sigchain without OTS (Manager handles anchoring)

## Event Types

| Event Type | Source | Description |
|------------|--------|-------------|
| `PASSWORD_ROTATION` | Manager | Password change recorded |
| `USERNAME_GENERATED` | Manager | Deterministic username created |
| `ENTROPY_POOL_CREATED` | Both | Entropy collected and stored |
| `TAG_OPERATION` | Manager | Tag added/removed/renamed |
| `CONFIG_CHANGE` | Manager | Configuration modified |
| `ENCLAVE_IMPORT` | Manager | Batch imported from Enclave |
| `OTS_ANCHOR` | Manager | Merkle root timestamped |
| `KEY_GENERATED` | Enclave | GPG/SSH key created |
| `SHARE_CREATED` | Enclave | SLIP-39 share generated |
| `BACKUP_VERIFIED` | Enclave | Backup integrity checked |

## Storage Locations

### Git Repository (`~/.bastion/sigchain/`)
```
sigchain/
├── .git/                  # GPG-signed commits
├── chain.json             # Full chain state
├── events/
│   ├── 2025-01-15.jsonl  # Daily event logs
│   └── 2025-01-16.jsonl
└── proofs/
    ├── pending/          # Awaiting Bitcoin confirmation
    └── completed/        # Bitcoin-attested proofs
```

### 1Password (Sync & Human-Readable)
- **Secure Note**: "Bastion Sigchain"
  - Chain head (hash, seqno, device)
  - Recent session summaries
  - Anchor statistics

## CLI Commands

### Session Management
```bash
# Start interactive session (recommended)
bastion session start

# Session with custom timeout
bastion session start --timeout 30

# Non-interactive session
bastion session start --no-interactive
```

### Sigchain Operations
```bash
# View chain status
bastion sigchain status

# View recent events
bastion sigchain log
bastion sigchain log --limit 50
bastion sigchain log --type PASSWORD_ROTATION
bastion sigchain log --date 2025-01-15

# Verify chain integrity
bastion sigchain verify
bastion sigchain verify --verbose

# Export for external audit
bastion sigchain export -o audit.json
bastion sigchain export -o audit.jsonl --format jsonl
```

### OpenTimestamps
```bash
# Check OTS status
bastion ots status

# List pending anchors
bastion ots pending

# Upgrade pending proofs (check for Bitcoin confirmation)
bastion ots upgrade

# Verify specific event's timestamp
bastion ots verify 42  # seqno 42
```

## Integration with Commands

Sigchain events are automatically recorded when you use Bastion commands:

```bash
# This records a USERNAME_GENERATED event
bastion generate username github.com

# This records an ENTROPY_POOL_CREATED event
bastion generate entropy yubikey

# This records TAG_OPERATION events
bastion add tag Bastion/Tier/1 --has-tag Bastion/Type/Bank
```

## Programmatic Usage

### Recording Events
```python
from bastion.sigchain import record_username_generated

# Record username generation
record_username_generated(
    domain="github.com",
    algorithm="sha3-512",
    label="Bastion/USER/SHA3/512:github.com:2025-01-15#VERSION=1&LENGTH=16",
    username="generated_username",  # Will be hashed
    length=16,
    saved_to_1password=True,
    account_uuid="abc123...",
)
```

### Using Sessions
```python
from bastion.sigchain import sigchain_session, UsernameGeneratedPayload

with sigchain_session() as chain:
    # All events in this block are batched
    payload = UsernameGeneratedPayload(...)
    chain.append(payload)
    
    # More operations...
    
# Session ends: events committed, OTS anchor submitted
```

### Low-Level API
```python
from bastion.sigchain import Sigchain, DeviceType

chain = Sigchain(device=DeviceType.MANAGER)
chain.append(payload)
chain.verify()
merkle_root = chain.get_merkle_root()
```

## OpenTimestamps Anchoring

### How It Works

1. **Session ends** → Compute merkle root of all session events
2. **Submit** → Send merkle root to OTS calendar servers (Alice, Bob, Finney)
3. **Wait** → Calendars aggregate and embed in Bitcoin transaction (~hours to ~weeks)
4. **Upgrade** → Retrieve Bitcoin attestation proof
5. **Verify** → Anyone can verify timestamp using Bitcoin blockchain

### Calendar Servers

| Server | URL | Notes |
|--------|-----|-------|
| Alice | `https://alice.btc.calendar.opentimestamps.org` | Primary |
| Bob | `https://bob.btc.calendar.opentimestamps.org` | Backup |
| Finney | `https://finney.calendar.forever.covfefe.org` | Community |

### Proof Lifecycle

```
PENDING          CONFIRMED
┌────────┐       ┌────────┐
│ Submit │  ───▶ │ Proof  │
│ to OTS │       │ Ready  │
└────────┘       └────────┘
    │                │
    ▼                ▼
 ~hours           Bitcoin
 to weeks         Attested
```

## QR Code Transfer (Enclave → Manager)

Events from the air-gapped Enclave are transferred via QR codes:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENCLAVE → MANAGER                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Enclave Session                    Manager Import              │
│  ┌────────────┐                     ┌────────────┐             │
│  │ Event 1    │                     │ Scan QR    │             │
│  │ Event 2    │ ─── QR Code ───▶    │ Verify     │             │
│  │ Event 3    │     (zlib+b64)      │ Append     │             │
│  └────────────┘                     └────────────┘             │
│        │                                  │                     │
│        ▼                                  ▼                     │
│  Merkle Root                        ENCLAVE_IMPORT              │
│  (for Manager                       event created               │
│   to anchor)                                                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### QR Format
- **Compression**: zlib level 9
- **Encoding**: Base64
- **Max size**: 2KB per QR (Level H error correction)
- **Splitting**: Large batches split across multiple QRs

## GPG Signing

Git commits in the sigchain repository are GPG-signed:

```bash
# Verify commits
cd ~/.bastion/sigchain
git log --show-signature

# Configure GPG key
git config user.signingkey YOUR_KEY_ID
git config commit.gpgsign true
```

### Mock Mode (Testing)
For testing without GPG setup:
```python
from bastion.sigchain.gpg import GPGSigner

signer = GPGSigner(mock=True)
sig = signer.sign(b"data")
result = signer.verify(b"data", sig.signature)
assert result.valid
```

## Verification

### Chain Integrity
```bash
# Verify hash chain
bastion sigchain verify

# What it checks:
# 1. Each link's prev_hash matches previous link's hash
# 2. Sequence numbers are consecutive
# 3. No gaps or duplicates
```

### Bitcoin Attestation
```bash
# Verify specific event has Bitcoin timestamp
bastion ots verify 42

# This proves:
# - Event existed at time of Bitcoin block
# - Chain up to that point was unmodified
```

### Full Audit
```bash
# Export full chain for external audit
bastion sigchain export -o audit.jsonl --format jsonl

# Each line contains:
# - Link metadata (seqno, hashes, timestamps)
# - Full payload data
# - OTS proof references
```

## Security Properties

| Property | Mechanism |
|----------|-----------|
| **Append-Only** | Hash chain - modifying history breaks chain |
| **Timestamped** | OTS Bitcoin anchors provide unforgeable timestamps |
| **Non-Repudiation** | GPG signatures on Git commits |
| **Auditable** | JSONL format, exportable for third-party verification |
| **Offline Capable** | Enclave events work without network |

## Configuration

In `~/.bastion/config.toml`:
```toml
[sigchain]
enabled = true

[session]
timeout_minutes = 15

[gpg]
sign_commits = true
key_id = "YOUR_GPG_KEY_ID"  # Optional, uses default if not set

[ots]
enabled = true
calendars = ["alice", "bob", "finney"]
```

## Troubleshooting

### "No sigchain initialized"
```bash
bastion session start  # Creates sigchain directory and first session
```

### "GPG signing failed"
```bash
# Check GPG agent
gpg-connect-agent /bye

# List available keys
gpg --list-secret-keys --keyid-format long

# Or use mock mode for testing
```

### "OTS upgrade shows 'still pending'"
Bitcoin confirmation takes time. Calendar servers aggregate multiple requests into single transactions. Check back in a few hours to a few days.

### "Chain verification failed"
The chain has been corrupted. Check:
1. Git repository for unauthorized modifications
2. Disk errors
3. Concurrent writes from multiple processes
