"""
Platform detection utilities.

Provides cross-platform detection for macOS, Linux, and Windows,
including version information and architecture details.
"""

import hashlib
import platform as stdlib_platform
import subprocess
import sys
import uuid
from functools import lru_cache
from pathlib import Path
from typing import Literal

__all__ = [
    "current_platform",
    "is_macos",
    "is_linux",
    "is_windows",
    "macos_version",
    "architecture",
    "is_arm64",
    "is_x86_64",
    "python_version",
    "get_machine_identifier",
    "get_machine_uuid",
]

PlatformName = Literal["macos", "linux", "windows", "unknown"]


@lru_cache(maxsize=1)
def current_platform() -> PlatformName:
    """
    Detect the current operating system.

    Returns:
        One of: "macos", "linux", "windows", "unknown"
    """
    system = stdlib_platform.system().lower()
    if system == "darwin":
        return "macos"
    elif system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    return "unknown"


def is_macos() -> bool:
    """Check if running on macOS."""
    return current_platform() == "macos"


def is_linux() -> bool:
    """Check if running on Linux."""
    return current_platform() == "linux"


def is_windows() -> bool:
    """Check if running on Windows."""
    return current_platform() == "windows"


@lru_cache(maxsize=1)
def macos_version() -> tuple[int, int, int] | None:
    """
    Get macOS version as (major, minor, patch) tuple.

    Returns:
        Version tuple like (14, 2, 1) for Sonoma 14.2.1, or None if not macOS
    """
    if not is_macos():
        return None

    version_str = stdlib_platform.mac_ver()[0]
    if not version_str:
        return None

    parts = version_str.split(".")
    try:
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        return (major, minor, patch)
    except ValueError:
        return None


@lru_cache(maxsize=1)
def architecture() -> Literal["arm64", "x86_64", "unknown"]:
    """
    Get CPU architecture.

    Returns:
        One of: "arm64", "x86_64", "unknown"
    """
    machine = stdlib_platform.machine().lower()
    if machine in ("arm64", "aarch64"):
        return "arm64"
    elif machine in ("x86_64", "amd64"):
        return "x86_64"
    return "unknown"


def get_machine_identifier() -> dict[str, str]:
    """
    Get machine identity information.

    Returns:
        Dictionary with 'hostname' and 'node_name' keys.
        Useful for machine-aware cache key tracking.
    """
    return {
        "hostname": stdlib_platform.node(),
        "node_name": stdlib_platform.node(),
    }


def is_arm64() -> bool:
    """Check if running on ARM64 (Apple Silicon, etc.)."""
    return architecture() == "arm64"


def is_x86_64() -> bool:
    """Check if running on x86_64 (Intel/AMD)."""
    return architecture() == "x86_64"


def python_version() -> tuple[int, int, int]:
    """Get Python version as (major, minor, patch) tuple."""
    return (sys.version_info.major, sys.version_info.minor, sys.version_info.micro)


@lru_cache(maxsize=1)
def has_homebrew() -> bool:
    """Check if Homebrew is installed (macOS/Linux)."""
    if is_windows():
        return False
    try:
        result = subprocess.run(
            ["brew", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


@lru_cache(maxsize=1)
def homebrew_prefix() -> str | None:
    """
    Get Homebrew prefix path.

    Returns:
        Path like "/opt/homebrew" (ARM) or "/usr/local" (Intel), or None
    """
    if not has_homebrew():
        return None
    try:
        result = subprocess.run(
            ["brew", "--prefix"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None

@lru_cache(maxsize=1)
def get_machine_uuid() -> str:
    """
    Get a stable, persistent machine UUID.

    On first call, attempts to retrieve system hardware identifier:
    - macOS: System serial number (stable, survives renames)
    - Linux/Windows: MAC address hash (stable, survives renames)
    - Fallback: Generates and caches persistent UUID in ~/.bsec/machine-uuid

    Returns:
        UUID string that uniquely identifies this machine.
        Same across reboots and hostname changes.
    """
    # Try to get persistent system identifier
    if is_macos():
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            for line in result.stdout.split("\n"):
                if "Serial Number" in line:
                    serial = line.split(":")[-1].strip()
                    if serial:
                        return hashlib.sha512(serial.encode()).hexdigest()[:32]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Fallback: use MAC address hash (same across reboots)
    try:
        mac = uuid.getnode()
        if mac != 0:  # 0 means couldn't get MAC, fallback to file
            return hashlib.sha512(str(mac).encode()).hexdigest()[:32]
    except Exception:
        pass

    # Last resort: persistent file in ~/.bsec/
    try:
        uuid_file = Path.home() / ".bsec" / "machine-uuid"
        if uuid_file.exists():
            return uuid_file.read_text(encoding="utf-8").strip()
        else:
            # Generate new persistent UUID
            uuid_file.parent.mkdir(parents=True, exist_ok=True)
            new_uuid = uuid.uuid4().hex[:32]
            uuid_file.write_text(new_uuid, encoding="utf-8")
            uuid_file.chmod(0o600)
            return new_uuid
    except Exception:
        pass

    # Absolute fallback (should never reach)
    return uuid.uuid4().hex[:32]
