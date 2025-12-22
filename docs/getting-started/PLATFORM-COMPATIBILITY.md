# Platform Compatibility Guide

Bastion is currently developed and tested exclusively on **macOS 14+ (Tahoe/Sonoma)**. This guide details feature availability across different platforms and environments.

## Support Tiers

| Tier | Platform | Status | Notes |
|------|----------|--------|-------|
| **Tier 1** | macOS 14+ | ✅ Full Support | Primary development platform; all features tested |
| **Tier 2** | Linux | ⚠️ Experimental | Core features should work; untested by maintainers |
| **Tier 3** | Windows | ❌ Not Supported | Not supported at this time; WSL recommended; contributions welcome |

## Core Features (Cross-Platform)

These features work on any platform with Python 3.11+ and the required dependencies:

- ✅ Core CLI commands (`bsec`)
- ✅ 1Password sync and operations
- ✅ Tag management and hierarchical tags
- ✅ Report generation
- ✅ Username generation (deterministic, offline-capable)
- ✅ Config management (`~/.bsec/cache/`)
- ✅ Encrypted cache (Fernet)
- ✅ Password rotation tracking
- ✅ YubiKey HMAC entropy generation
- ✅ Physical dice entropy collection
- ✅ Python `secrets` module entropy fallback
- ✅ All cryptographic operations (SHAKE256, HKDF, HMAC-SHA512, SHA-512)

## External Tool Dependencies

| Tool | Purpose | macOS | Linux | Windows | Installation |
|------|---------|-------|-------|---------|---|
| **op** | 1Password CLI v2 | ✅ | ✅ | ✅ | `brew install 1password-cli` (macOS); official installer (Linux/Windows) |
| **ykman** | YubiKey Manager | ✅ | ✅ | ✅ | `brew install ykman` (macOS); `apt install yubikey-manager` (Linux); `pip install yubikey-manager` |
| **infnoise** | Infinite Noise TRNG | ✅ | ✅ | ❌ | Build from source; Linux/macOS only |
| **ent** | Entropy analysis | ✅ | ✅ | ❌ | `brew install ent` (macOS); `apt install ent` (Linux) |
| **gpg** | Sigchain signing | ✅ | ✅ | ✅ | `brew install gnupg` (macOS); `apt install gnupg` (Linux); GPG4Win (Windows) |
| **/dev/urandom** | System entropy | ✅ | ✅ | ❌ | Unix-like systems only |
| **pbpaste/pbcopy** | Clipboard operations | ✅ | ❌ | ❌ | macOS built-in; not available elsewhere |
| **osascript** | AppleScript automation | ✅ | ❌ | ❌ | macOS built-in |

## Entropy Sources by Platform

| Entropy Source | macOS | Linux | Windows | Hardware Required |
|---|---|---|---|---|
| **YubiKey HMAC-SHA1** | ✅ Full | ✅ Full | ✅ Full | YubiKey with HMAC-SHA1 slot |
| **Infinite Noise TRNG** | ✅ Full | ✅ Full | ❌ Not Available | Infinite Noise USB device; no Windows drivers |
| **System RNG (/dev/urandom)** | ✅ Full | ✅ Full | ❌ Not Available | Built-in Unix utility |
| **System RNG (/dev/random)** | ✅ Full | ✅ Full | ❌ Not Available | Unix blocking entropy |
| **Python secrets module** | ✅ Full | ✅ Full | ✅ Full | None; cross-platform fallback |
| **Physical dice rolls** | ✅ Full | ✅ Full | ✅ Full | Casino dice; pure CLI input |
| **Combined entropy** | ✅ Full | ✅ Full | ⚠️ Limited | All sources available; limited to Python/YubiKey/dice |

## macOS-Exclusive Features

These features are only available on macOS and require the `pbpaste`, `pbcopy`, or `osascript` commands:

- 🍎 **Clipboard-based passkey audit** — Auto-read JSON from clipboard for passkey health checks
- 🍎 **1Password UI automation** — AppleScript support to auto-open items, bring app to foreground
- 🍎 **Desktop notifications** — Native macOS notifications (terminal bell fallback available on other platforms)
- 🍎 **Auto-copy passwords** — `pbcopy` integration for clipboard workflows

**Workarounds on Linux/Windows:**
- Manual JSON export and import instead of clipboard operations
- Manual 1Password item navigation
- Terminal output only (no notifications)

## Linux-Exclusive Features

These features depend on Unix system utilities not available on Windows:

- 🐧 **System entropy reads** — `/dev/urandom` and `/dev/random` access
- 🐧 **Infinite Noise TRNG** — Requires Linux drivers and build environment
- 🐧 **ENT statistical analysis** — Entropy validation tool (macOS support via Homebrew)

## Windows Compatibility

### Native Windows

Bastion is **not officially supported** on native Windows. However, core features that don't depend on Unix utilities will work:

- ✅ Core CLI (with limitations)
- ✅ 1Password CLI integration
- ✅ YubiKey support (via `ykman`)
- ✅ Dice entropy collection
- ✅ Python secrets fallback
- ✅ All crypto operations
- ❌ System entropy sources (`/dev/urandom`)
- ❌ Infinite Noise TRNG
- ❌ Clipboard operations (`pbpaste`/`pbcopy`)
- ❌ Desktop notifications

### Windows Subsystem for Linux (WSL)

**Recommended for Windows users.** WSL provides full Linux environment support:

```bash
# Install WSL with Ubuntu (or other modern Linux distro)
wsl --install -d Ubuntu

# Inside WSL, install Bastion
pip install bastion-security
```

With WSL, you get:
- ✅ All Linux features
- ✅ `/dev/urandom` and `/dev/random` access
- ✅ Infinite Noise TRNG support
- ✅ Full entropy collection
- ⚠️ YubiKey support (requires USB device passthrough configuration)

## Installation by Platform

### macOS

```bash
# Via Homebrew (recommended)
brew install bastion-security

# Via PyPI
pip install bastion-security
```

**Additional setup for Python 3.14 + iCloud Drive:**

If your project lives in iCloud Drive, you must symlink `.venv` outside iCloud due to a macOS hidden flag (`UF_HIDDEN`) issue:

```bash
mkdir -p ~/.local/venvs/bastion
ln -s ~/.local/venvs/bastion .venv
uv sync
```

See [Development Setup](./GETTING-STARTED.md#development-environment-setup) for details.

### Linux

```bash
# Debian/Ubuntu
sudo apt install python3-pip python3-venv
pip install bastion-security

# Or build from source
git clone https://github.com/jakehertenstein/bastion.git
cd bastion
uv sync
```

### Windows (not supported, use WSL)

```bash
# Install WSL first
wsl --install -d Ubuntu

# Then follow Linux instructions inside WSL
```

## Known Platform-Specific Issues

### macOS + Python 3.14 + iCloud Drive

**Issue:** Python 3.14 added a check that skips `.pth` files with the macOS `UF_HIDDEN` flag. iCloud Drive automatically sets this flag on files starting with `_`, breaking editable installs.

**Symptom:** `ModuleNotFoundError: No module named 'bastion'`

**Fix:** Use symlink workaround outside iCloud (see Installation section above).

### Linux + YubiKey

**Issue:** YubiKey access may require `udev` rules configuration.

**Fix:**
```bash
sudo groupadd -f plugdev
sudo usermod -a -G plugdev $USER
# Install udev rules from YubiKey Manager
ykman config usb --help
```

### Windows + Clipboard Operations

**Issue:** `pbpaste`/`pbcopy` commands don't exist on Windows.

**Workaround:** Export JSON manually and use file-based workflows instead of clipboard.

## Hardware Compatibility

### YubiKey

| Platform | Status | Notes |
|---|---|---|
| macOS | ✅ Full | Tested; all YubiKey applets supported |
| Linux | ✅ Full | Requires `udev` rules configuration |
| Windows | ✅ Partial | `ykman` works; may need driver installation |
| WSL | ⚠️ Limited | USB passthrough required; see WSL documentation |

### Infinite Noise TRNG

| Platform | Status | Notes |
|---|---|---|
| macOS | ✅ Full | Build from source; USB device recognized |
| Linux | ✅ Full | Supported; may need `udev` rules |
| Windows | ❌ Not Available | No Windows drivers available |
| WSL | ⚠️ Limited | USB passthrough required |

## Python Version Support

| Python | macOS | Linux | Windows | Status |
|---|---|---|---|---|
| 3.11 | ✅ | ✅ | ✅ | Minimum supported |
| 3.12 | ✅ | ✅ | ✅ | Well-tested |
| 3.13 | ✅ | ✅ | ✅ | Supported |
| 3.14 | ✅ | ✅ | ✅ | Tested on macOS only |

**Note:** Only macOS development has been thoroughly tested. Python version compatibility assumed for Linux/Windows based on code analysis, not actual testing.

## Testing Status

| Environment | Tested | Notes |
|---|---|---|
| macOS 14 Tahoe (Apple Silicon) | ✅ Yes | Primary development platform; all features tested |
| macOS 14 Sonoma (Intel) | ✅ Assumed | Not explicitly tested; should work |
| Linux (modern distros) | ❌ No | Code suggests compatibility; no formal testing |
| Windows (native) | ❌ No | Not supported; not tested |
| Windows (WSL2) | ❌ No | Should work; not tested |

## Migration Between Platforms

Bastion data is portable because it uses 1Password vaults as the source of truth:

1. **Export data:** Sync to 1Password on source platform (`bsec sync`)
2. **Transfer:** 1Password vault automatically syncs across devices
3. **Import data:** Install Bastion on target platform and sync (`bsec sync`)

Cache files (`~/.bsec/cache/`) are platform-specific and don't need to be transferred; they will be regenerated automatically.

## Contributions Welcome

If you're interested in improving platform compatibility:

- **Linux testing:** Test on different distributions (Debian, Ubuntu, Fedora, Arch, etc.)
- **Windows support:** Develop cross-platform alternatives for `pbpaste`, `/dev/urandom`, etc.
- **CI/CD:** Add GitHub Actions for multi-platform testing
- **Documentation:** Share your experience with platform-specific workflows

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for details on contributing.

## FAQ

**Q: Can I use Bastion on Windows?**  
A: Not officially supported. Use WSL for Windows. Contributions to add native Windows support are welcome.

**Q: Will Bastion work on Linux?**  
A: Core features should work, but it's untested. Please report issues you encounter.

**Q: What about macOS versions older than 14?**  
A: Not tested or supported. We recommend macOS 14 (Tahoe) or later.

**Q: Can I use Bastion on a Raspberry Pi or other ARM Linux?**  
A: Theoretically yes, if Python 3.11+ and 1Password CLI are available. Not tested.

**Q: Does Bastion work offline?**  
A: Partially. Username generation and entropy collection work offline. 1Password sync requires network access.

**Q: Can I run Bastion in a container?**  
A: Yes. Docker containers are typically Linux-based, so Linux compatibility applies. Mount YubiKey/TRNG devices as needed.
