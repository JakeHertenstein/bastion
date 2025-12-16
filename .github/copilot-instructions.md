# Copilot Instructions for Bastion

## Purpose

Bastion is a security management CLI for 1Password that provides password rotation tracking, deterministic username generation, and high-quality entropy collection from hardware sources. It integrates deeply with 1Password CLI v2.

## Quick Facts

- **PyPI package**: `bastion-security` (`pip install bastion-security`)
- **Primary CLI**: `bsec` (alias: `bastion` for backward compatibility)
- **1Password integration**: All data stored in 1Password vaults via `op` CLI
- **Documentation**: `docs/` directory contains all guides and specifications
- **Current version**: 0.3.0 (pre-1.0 development phase)

## Versioning (SemVer)

Bastion follows [Semantic Versioning 2.0.0](https://semver.org/):

**Format**: `MAJOR.MINOR.PATCH`

| Component | When to Increment | Example |
|-----------|-------------------|--------|
| **MAJOR** | Breaking changes to CLI, config, or stored data formats | 1.0.0 → 2.0.0 |
| **MINOR** | New features, backward-compatible | 0.1.0 → 0.2.0 |
| **PATCH** | Bug fixes, documentation, refactoring | 0.1.0 → 0.1.1 |

**Pre-1.0 Rules** (current phase):
- API and CLI may change between minor versions
- 0.x.y versions are for initial development
- Breaking changes can occur in 0.MINOR bumps

**Version Source of Truth**:
- Single source: `bastion/__init__.py` → `__version__ = "X.Y.Z"`
- `pyproject.toml` reads dynamically via `{attr = "bastion.__version__"}`
- Seeder follows parent version

**Release Workflow**:
1. Update `bastion/__init__.py` with new version
2. Create git tag: `git tag v0.1.0`
3. Push tag: `git push origin-private v0.1.0`
4. Create GitHub release from tag on private repo

**Public Repo Sync** (squash workflow):
```bash
# Sync develop to public with squash (all commits become one)
./scripts/sync-to-public.sh "v0.3.0: Feature summary"
```
- Private repo (`origin-private`): Full commit history, WIP commits
- Public repo (`public`): Squashed releases only, clean history
- Always push to `origin-private` first, then sync to `public`

**Breaking Changes Include**:
- CLI command/option renames or removals
- 1Password field/section format changes
- Config file format changes
- Cache/database schema changes
- Tag format changes (`Bastion/*` hierarchy)

## Core Modules

| Module | Purpose |
|--------|---------|
| `cli/` | CLI commands organized by domain |
| `config.py` | Cache paths and infrastructure |
| `db.py` | Encrypted cache and database management |
| `entropy.py` | Entropy pool management and combination |
| `entropy_yubikey.py` | YubiKey HMAC-SHA1 entropy collection |
| `entropy_dice.py` | Physical dice roll entropy collection |
| `entropy_infnoise.py` | Infinite Noise TRNG integration |
| `username_generator.py` | Deterministic username generation |
| `models.py` | Pydantic models for accounts and passwords |
| `op_client.py` | 1Password CLI wrapper |
| `tag_operations.py` | Hierarchical tag management |

## Cache and Data Storage

All cache files are stored in `~/.bsec/cache/` (auto-migrates from legacy `~/.bastion/`):
- `db.enc` - Fernet-encrypted 1Password sync cache
- `yubikey-slots.json` - YubiKey OATH slot mappings
- `password-rotation.json` - Rotation tracking database

Backups stored in `~/.bsec/backups/`.

Configuration in `bastion/config.py` provides:
- `get_yubikey_cache_path()` - Auto-migrates from legacy `./yubikey-slots-cache.json`
- `get_password_rotation_db_path()` - Auto-migrates from legacy `./password-rotation-database.json`
- `get_encrypted_db_path()` - Auto-migrates from legacy `~/.bastion/cache.db.enc`

## CLI Commands

```bash
# Entropy generation
bsec generate entropy yubikey --bits 8192
bsec generate entropy combined --sources yubikey,infnoise --bits 32768
bsec generate entropy dice --bits 256

# Username generation
bsec generate username --init                    # Initialize salt
bsec generate username github.com               # Generate for domain
bsec generate username github.com --no-save     # Preview only
bsec verify username github.com <username>      # Verify generated username

# Sync and reporting
bsec sync                                       # Sync from 1Password (batch fetch)
bsec report                                     # Rotation status report

# YubiKey management
bsec yubikey cache-slots                        # Cache OATH slots from connected YubiKeys
bsec yubikey cache-slots --force-refresh        # Force refresh cache
bsec refresh yubikey                            # Refresh slot cache
bsec clean yubikey                              # Remove stale cache entries

# Tag management
bsec tags list
bsec tags apply <item-id> --tag "Bastion/Type/Bank"
```

## Architecture Patterns

### 1Password Field Conventions

- **Section format**: `Section Name.Field Name[type]=value`
- **Field types**: `text`, `date`, `concealed`
- **Tags**: Hierarchical format `Bastion/Category/Subcategory`

### Entropy System

- **Sources**: YubiKey HMAC, Infinite Noise TRNG, dice rolls, system RNG
- **Combination**: XOR + SHAKE256 extension (preserves max entropy size)
- **Storage**: Base64 in 1Password password field with metadata sections
- **Analysis**: ENT tool for statistical validation

### Cryptographic Standards (v0.3.0)

| Category | Algorithm | Purpose |
|----------|-----------|---------|
| Entropy stretching | SHAKE256 | XOF for extending entropy pools |
| Key derivation | HKDF-SHA512 | Deriving keys from master entropy |
| Content hashing | SHA-512 | Usernames, labels, integrity checks |
| Authenticated hashing | HMAC-SHA512 | YubiKey challenge-response |
| Encryption | Fernet | Local cache encryption |

See `docs/CRYPTO-FUNCTION-MATRIX.md` for complete documentation.

### Bastion Labels

Format: `Bastion/<Category>/<Type>/<Algorithm>:<data>:<date>#PARAMS|CHECK`

Parameters use URL query-string notation. VERSION holds Bastion tool SemVer.

Examples:
- `Bastion/SALT/HKDF/SHA2/512:username-generator:2025-11-30#VERSION=0.3.0`
- `Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=0.3.0&LENGTH=16|K`

See `docs/LABEL-FORMAT-SPECIFICATION.md` for complete specification.

## Development Guidelines

### Development Environment Setup

**CRITICAL - Python 3.14 + iCloud Drive Incompatibility**:

The project lives in iCloud Drive, which causes a fatal issue with Python 3.14:
1. iCloud automatically sets the macOS `UF_HIDDEN` flag on files starting with `_`
2. `uv sync` creates `.pth` files like `_bastion_security.pth` for editable installs
3. Python 3.14 added a check that **skips `.pth` files with the hidden flag**
4. Result: `ModuleNotFoundError: No module named 'bastion'`

**Solution**: The `.venv` directory is a **symlink** pointing outside iCloud:
```
.venv → ~/.local/venvs/bastion
```

**If you get `ModuleNotFoundError`**:
```bash
# Check symlink is intact
ls -la .venv

# If missing or broken, recreate:
rm -rf .venv
mkdir -p ~/.local/venvs/bastion
ln -s ~/.local/venvs/bastion .venv
uv sync
```

**For new development machines**:
```bash
# 1. Create venv location outside iCloud
mkdir -p ~/.local/venvs/bastion

# 2. Create symlink in project
ln -s ~/.local/venvs/bastion .venv

# 3. Install dependencies
uv sync
```

### Security Requirements

- **No hardcoded secrets**: Never commit real UUIDs, emails, or credentials
- **Determinism**: Username and entropy operations must be reproducible
- **Offline capability**: Core crypto operations work without network
- **1Password dependency**: All persistent storage via 1Password

### 1Password CLI Limitations

**CRITICAL - Passkey Data Loss Bug** (see `bastion/support/1PASSWORD-CLI-PASSKEY-BUG.md`):
- `op item get --format json` does NOT include passkey data
- `op item edit <uuid> -` with JSON stdin DELETES passkeys permanently
- Items with `Bastion/2FA/Passkey/Software` tag have 1Password-stored passkeys at risk
- Use field assignment syntax instead: `op item edit <uuid> "field[type]=value"`
- The `linking.py` module checks for this tag and blocks unsafe edits

### Code Conventions

- **Type hints**: All functions must have type annotations
- **Docstrings**: Google-style docstrings for public functions
- **Error handling**: Use `typer.Exit(1)` for CLI errors, exceptions for library errors
- **Console output**: Use Rich `console.print()` with color styling

### Testing

- Tests in `tests/` directory (pytest)
- Mock 1Password CLI calls for unit tests
- Integration tests require 1Password authentication

## Subprojects

### Seeder (`seeder/`)

Separate tool for seed card generation (CR80 password cards). Has its own:
- `pyproject.toml`
- Test suite
- Documentation

Not directly integrated with Bastion CLI.

## File Patterns to Avoid Committing

- `output/` - Exported CSVs and analysis results
- `docs/internal/` - Internal architecture and security docs
- Legacy data files (now in `~/.bsec/cache/`):
  - `backup-*.json`
  - `*-salts.json`
  - `password-rotation-database.json`
  - `yubikey-slots-cache.json`
  - `yubikey_migration.log.json`
