"""
Platform detection utilities.

Provides cross-platform detection for macOS, Linux, and Windows,
including version information and architecture details.
"""

import platform as stdlib_platform
import subprocess
import sys
from functools import lru_cache
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
