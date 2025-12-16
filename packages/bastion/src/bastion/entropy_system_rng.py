"""System entropy collection from OS random number generators.

This module provides functions to collect cryptographically secure random bytes
from the operating system's entropy sources:
- /dev/urandom: Non-blocking, cryptographically secure PRNG (preferred)
- /dev/random: Blocking, hardware entropy pool (optional, may be slow)

Both sources are cryptographically secure on modern systems (Linux, macOS, *BSD).
/dev/urandom is recommended as it never blocks and provides high-quality entropy.
"""

import platform
import subprocess
from pathlib import Path
from dataclasses import dataclass


@dataclass
class SystemRNGMetadata:
    """Metadata about system RNG collection."""
    os_name: str
    os_version: str
    os_release: str
    kernel_version: str
    source_device: str  # "/dev/urandom" or "/dev/random"
    byte_count: int
    
    def to_dict(self) -> dict:
        """Convert to dictionary for storage.
        
        Field names use Title Case for 1Password canonical form.
        """
        return {
            "OS Name": self.os_name,
            "OS Version": self.os_version,
            "OS Release": self.os_release,
            "Kernel Version": self.kernel_version,
            "Source Device": self.source_device,
        }


class SystemRNGError(Exception):
    """Raised when system RNG collection fails."""
    pass


def get_system_info() -> dict:
    """Collect system information for metadata.
    
    Returns:
        Dictionary with OS name, version, release, kernel version
    """
    system_info = {
        "os_name": platform.system(),  # 'Darwin', 'Linux', etc.
        "os_version": platform.version(),
        "os_release": platform.release(),
        "kernel_version": "",
    }
    
    # Try to get kernel version on Unix systems
    try:
        if system_info["os_name"] in ["Darwin", "Linux"]:
            result = subprocess.run(
                ["uname", "-v"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            system_info["kernel_version"] = result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        system_info["kernel_version"] = "unknown"
    
    return system_info


def collect_urandom_entropy(bits: int = 512) -> tuple[bytes, SystemRNGMetadata]:
    """Collect entropy from /dev/urandom (non-blocking, preferred).
    
    /dev/urandom is a cryptographically secure PRNG that never blocks.
    On modern systems (Linux 3.17+, macOS, BSD), it's seeded from hardware
    entropy and provides high-quality random data suitable for all
    cryptographic purposes.
    
    Args:
        bits: Number of bits to collect (must be multiple of 8)
        
    Returns:
        Tuple of (entropy_bytes, metadata)
        
    Raises:
        SystemRNGError: If collection fails
        ValueError: If bits is not a multiple of 8
    """
    if bits % 8 != 0:
        raise ValueError(f"Bits must be multiple of 8, got {bits}")
    
    byte_count = bits // 8
    
    # Check if /dev/urandom exists
    urandom_path = Path("/dev/urandom")
    if not urandom_path.exists():
        raise SystemRNGError("/dev/urandom not found (non-Unix system?)")
    
    try:
        # Read from /dev/urandom
        with open(urandom_path, "rb") as f:
            entropy_bytes = f.read(byte_count)
        
        if len(entropy_bytes) != byte_count:
            raise SystemRNGError(
                f"Expected {byte_count} bytes, got {len(entropy_bytes)}"
            )
        
        # Collect system metadata
        system_info = get_system_info()
        metadata = SystemRNGMetadata(
            os_name=system_info["os_name"],
            os_version=system_info["os_version"],
            os_release=system_info["os_release"],
            kernel_version=system_info["kernel_version"],
            source_device="/dev/urandom",
            byte_count=byte_count,
        )
        
        return (entropy_bytes, metadata)
        
    except IOError as e:
        raise SystemRNGError(f"Failed to read /dev/urandom: {e}") from e


def collect_random_entropy(
    bits: int = 512,
    timeout_seconds: int = 30
) -> tuple[bytes, SystemRNGMetadata]:
    """Collect entropy from /dev/random (blocking, hardware pool).
    
    /dev/random blocks if the kernel entropy pool is depleted. On modern
    systems, this is rarely necessary as /dev/urandom is cryptographically
    secure. Use this only if you specifically need hardware entropy pool
    access and can tolerate blocking.
    
    Args:
        bits: Number of bits to collect (must be multiple of 8)
        timeout_seconds: Maximum seconds to wait before timing out
        
    Returns:
        Tuple of (entropy_bytes, metadata)
        
    Raises:
        SystemRNGError: If collection fails or times out
        ValueError: If bits is not a multiple of 8
    """
    if bits % 8 != 0:
        raise ValueError(f"Bits must be multiple of 8, got {bits}")
    
    byte_count = bits // 8
    
    # Check if /dev/random exists
    random_path = Path("/dev/random")
    if not random_path.exists():
        raise SystemRNGError("/dev/random not found (non-Unix system?)")
    
    try:
        # Use dd to read with timeout
        # dd if=/dev/random of=/dev/stdout bs=64 count=1 2>/dev/null
        result = subprocess.run(
            [
                "dd",
                "if=/dev/random",
                "of=/dev/stdout",
                f"bs={byte_count}",
                "count=1",
            ],
            capture_output=True,
            timeout=timeout_seconds,
            check=True,
        )
        
        entropy_bytes = result.stdout
        
        if len(entropy_bytes) != byte_count:
            raise SystemRNGError(
                f"Expected {byte_count} bytes, got {len(entropy_bytes)}"
            )
        
        # Collect system metadata
        system_info = get_system_info()
        metadata = SystemRNGMetadata(
            os_name=system_info["os_name"],
            os_version=system_info["os_version"],
            os_release=system_info["os_release"],
            kernel_version=system_info["kernel_version"],
            source_device="/dev/random",
            byte_count=byte_count,
        )
        
        return (entropy_bytes, metadata)
        
    except subprocess.TimeoutExpired:
        raise SystemRNGError(
            f"/dev/random blocked for more than {timeout_seconds}s. "
            "Consider using /dev/urandom instead."
        ) from None
    except subprocess.CalledProcessError as e:
        raise SystemRNGError(f"Failed to read /dev/random: {e}") from e
    except FileNotFoundError:
        raise SystemRNGError("dd command not found") from None


def check_system_rng_available() -> dict:
    """Check which system RNG sources are available.
    
    Returns:
        Dictionary with availability status:
        {
            "urandom": bool,
            "random": bool,
            "os_name": str,
        }
    """
    return {
        "urandom": Path("/dev/urandom").exists(),
        "random": Path("/dev/random").exists(),
        "os_name": platform.system(),
    }
