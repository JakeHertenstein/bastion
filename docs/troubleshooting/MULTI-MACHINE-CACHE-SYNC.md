````markdown
# Multi-Machine Cache Synchronization (v0.3.1+)

## Overview

Bastion implements a stable machine UUID system to safely synchronize encrypted caches across multiple machines while preventing accidental key mismatches.

## Machine UUID

### What It Is

A stable, persistent identifier derived from your machine's hardware:

- **macOS**: SHA-512 hash of system serial number
- **Linux/Windows**: SHA-512 hash of primary MAC address
- **Fallback**: Generated UUID (only if hardware methods unavailable)

The UUID is computed on-demand and changes only if the hashing algorithm is updated across major versions.

### Viewing Your Machine UUID

```bash
bsec show machine
```

Output:
```
                 Machine Identity                  
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property     ┃ Value                            ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Machine UUID │ b0be8437a7ed7184dca0aedab66e0896 │
│ UUID Source  │ macOS System Serial (SHA-512)    │
│ Hostname     │ Jakes-MacBook-Air-5.local        │
│ Node Name    │ Jakes-MacBook-Air-5.local        │
│ Architecture │ arm64                            │
└──────────────┴──────────────────────────────────┘

The machine UUID is stable across hostname changes and reboots.
It's derived from hardware identifiers when possible.
```

## Storage Locations

### 1. 1Password Key Entry

**Item**: "Bastion Cache Key" (Secure Note in Private vault)

**Fields**:
- `encryption_key` - The Fernet encryption key (updated on rotation)
- `machine_uuid` - UUID of machine that created/rotated the key
- `created_on_machine` - UUID of machine that initially created the key
- `rotated_at` - Timestamp of last rotation
- `rotated_on_machine` - UUID of machine that last rotated the key
- `last_machine_hostname` - Hostname of last rotation machine

### 2. Cache Metadata

**File**: `~/.bsec/cache/db.enc` (encrypted)

**Metadata Fields**:
- `machine_uuid` - Current machine's UUID (set on every sync)
- `machine_hostname` - Current machine's hostname
- `machine_node` - Current machine's node name

### 3. File Fallback (Rarely Used)

**File**: `~/.bsec/machine-uuid` (only created if hardware methods fail)

- Plain text file containing the UUID
- Survives across reboots and cache deletions
- Set with restrictive permissions (0o600)

## Synchronization Workflow

### First Machine (Key Creation)

```bash
# Machine A
bsec 1p sync vault
# Creates:
# - Fernet encryption key in 1P
# - Machine UUID A in 1P key entry
# - Encrypted cache with UUID A in metadata
```

### Second Machine (Safe Multi-Machine Access)

```bash
# Machine B
bsec 1p sync vault
# 1. Validates: current UUID B vs 1P key UUID A
# 2. Detects mismatch
# 3. Auto-recovery triggered:
#    - Backs up old cache to ~/.bsec/backups/db.enc.bad-<timestamp>
#    - Initializes fresh database
#    - Syncs all 443 accounts from 1P
#    - Updates 1P key entry machine_uuid to B
```

### Same Machine After Key Rotation

```bash
# Machine A (after 90-day encryption key rotation)
bsec 1p sync vault
# 1. Validates: UUID A (cached) vs UUID A (1P) ✓ Match
# 2. Decrypts cache with old key
# 3. Re-encrypts with new key
# 4. Updates 1P entry: machine_uuid still A
# 5. Backup created: ~/.bsec/backups/db.enc.<timestamp>
```

## Auto-Recovery Behavior

### Trigger: UUID Mismatch

When `bsec 1p sync vault` runs:

1. **Validation Phase**: Read machine_uuid from 1Password key entry
2. **Current UUID**: Compute UUID for current machine
3. **Comparison**: If UUIDs don't match:
   - Backup old cache: `~/.bsec/backups/db.enc.bad-YYYYMMDDTHHMMSSZ`
   - Initialize fresh database
   - Sync all items from 1Password
   - Update 1P key entry with new UUID

### Data Preservation

- Old cache backed up with timestamp
- No data loss (can restore from 1P)
- New cache built from live 1P vault data

### Error Message

```
EncryptionError: Machine UUID mismatch: cache key was created on 
a different machine.
Key machine UUID: 8227af8750a7a9b8ac2261c8234e4f0e
Current machine UUID: b0be8437a7ed7184dca0aedab66e0896
Auto-recovery: backing up cache and creating fresh database.
```

## Best Practices

### Multi-Machine Setup

1. **Primary Machine**: Run `bsec 1p sync vault` first to initialize
2. **Secondary Machines**: Run sync; auto-recovery will set up cache
3. **Verify**: Run `bsec show machine` on each machine to see UUID

### Moving to New Machine

```bash
# Old machine: backup optional (1P has everything)
# New machine:
bsec 1p sync vault
# Auto-recovery sets up fresh cache with new UUID
# All accounts sync from 1P automatically
```

### Hostname Changes

Machine UUID remains stable even after hostname change:

```bash
# Old hostname
bsec show machine
# → UUID: b0be8437...

# Change hostname
sudo scutil --set ComputerName "new-name"

# UUID unchanged (derived from serial/MAC, not hostname)
bsec show machine
# → UUID: b0be8437... (same)
```

### Backup and Recovery

```bash
# View backups
ls -la ~/.bsec/backups/

# Restore from backup (if needed)
# Manual: copy db.enc.bad-<timestamp> to db.enc
# Then run: bsec 1p sync vault
```

## Key Rotation

Encryption key rotates automatically every 90 days (configurable):

```bash
# During sync, if key is 90+ days old:
bsec 1p sync vault
# → Rolling encryption key...
# → New key generated and stored in 1P
# → Cache re-encrypted
# → Old backup created: ~/.bsec/backups/db.enc.<timestamp>
```

Machine UUID remains unchanged during key rotation (same machine).

## Troubleshooting

### "Machine UUID mismatch" Error

**Cause**: Cache created on different machine or algorithm changed

**Solution**: Run `bsec 1p sync vault` to trigger auto-recovery

**What happens**:
- Old cache backed up
- Fresh database created
- Accounts re-synced from 1P
- Machine UUID updated in 1P

### Suspicious Backup Files

```bash
# Check backup integrity
ls -la ~/.bsec/backups/db.enc.bad-*

# If you want to restore a backup:
# 1. Rename: mv db.enc.bad-<ts> db.enc
# 2. Sync: bsec 1p sync vault
```

### Different UUIDs on Same Machine After Update

**Cause**: Hashing algorithm changed (e.g., SHA-256 to SHA-512)

**Solution**: 
```bash
bsec 1p sync vault
# Auto-recovery handles it:
# - Backs up old cache
# - Creates fresh from 1P
# - Updates 1P with new UUID
```

## Security Implications

### Prevents

- ✅ Cache decryption on wrong machine
- ✅ Key misuse across machines
- ✅ Accidental data corruption from mismatched keys

### Preserves

- ✅ All account data (stored in 1Password)
- ✅ Rotation history (stored in 1Password)
- ✅ Full recovery via 1Password sync

### Requires

- 🔐 Access to 1Password vault (for encryption key)
- 🔐 1Password CLI authentication
- 🔐 Machine hardware identifier stability

## Implementation Details

### UUID Generation Algorithm (v0.3.1)

```python
# bastion-core/src/bastion_core/platform.py

def get_machine_uuid() -> str:
    # Priority order:
    if is_macos():
        # Try system serial number
        result = subprocess.run(["system_profiler", "SPHardwareDataType"])
        serial = extract_serial(result.stdout)
        return hashlib.sha512(serial.encode()).hexdigest()[:32]
    
    # Fallback: MAC address
    mac = uuid.getnode()
    return hashlib.sha512(str(mac).encode()).hexdigest()[:32]
    
    # Last resort: generated UUID
    return uuid.uuid4().hex[:32]
```

### Validation Flow

```python
# packages/bastion/src/bastion/db.py

def load(self) -> Database:
    try:
        # 1. Validate machine UUID matches 1P entry
        self._validate_machine_uuid()
        
        # 2. Decrypt cache with key from 1P
        encrypted_data = self.cache_path.read_bytes()
        decrypted = self._decrypt(encrypted_data)
        
        # 3. Parse and return
        return Database.model_validate(json.loads(decrypted))
        
    except EncryptionError:
        # Auto-recovery:
        # - Backup bad cache
        # - Initialize fresh database
        return self._initialize_new()
```

## References

- [Crypto Standards](../reference/CRYPTO-FUNCTION-MATRIX.md) — SHA-512 algorithm details
- [Getting Started](../getting-started/GETTING-STARTED.md) — First-time setup
- [Cache Configuration](../../packages/bastion/src/bastion/config.py) — Paths and settings

````
