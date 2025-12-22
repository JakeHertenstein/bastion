# bastion-core

Shared core utilities for the Bastion security toolchain.

## Features

- **Platform Detection**: Detect macOS, Linux, Windows and their versions
- **Hardware Detection**: Check for YubiKey, Infinite Noise TRNG, TPM availability
- **Machine UUID**: Stable machine identifier derived from hardware (SHA-512)
- **Network Checks**: Verify air-gap status and network connectivity

## Usage

```python
from bastion_core import platform, hardware

# Platform checks
if platform.is_macos():
    print(f"Running on macOS {platform.macos_version()}")

# Machine identity
uuid = platform.get_machine_uuid()
print(f"Machine UUID: {uuid}")

# Hardware checks
if hardware.has_yubikey():
    print("YubiKey detected")

# Network checks  
from bastion_core.network import is_airgapped
if is_airgapped():
    print("System appears to be air-gapped")
```

## Installation

This package is part of the Bastion monorepo and is typically installed as a dependency of other Bastion packages.

```bash
# From workspace root
uv sync
```
