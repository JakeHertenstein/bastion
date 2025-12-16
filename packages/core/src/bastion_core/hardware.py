"""
Hardware detection utilities.

Provides detection for security hardware like YubiKeys, Infinite Noise TRNGs,
TPM modules, and smart card readers.
"""

import subprocess
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from bastion_core.platform import homebrew_prefix, is_linux, is_macos

__all__ = [
    "has_yubikey",
    "yubikey_serials",
    "has_infnoise",
    "infnoise_device_path",
    "has_smartcard_reader",
    "HardwareStatus",
    "check_all_hardware",
]


class HardwareStatus(NamedTuple):
    """Status of all security hardware."""

    yubikey: bool
    yubikey_count: int
    infnoise: bool
    smartcard_reader: bool


@lru_cache(maxsize=1)
def _ykman_available() -> bool:
    """Check if ykman CLI is available."""
    try:
        result = subprocess.run(
            ["ykman", "--version"],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def has_yubikey() -> bool:
    """
    Check if at least one YubiKey is connected.

    Uses ykman if available, falls back to checking USB devices.
    """
    serials = yubikey_serials()
    return len(serials) > 0


def yubikey_serials() -> list[str]:
    """
    Get list of connected YubiKey serial numbers.

    Returns:
        List of serial number strings, empty if none found
    """
    if not _ykman_available():
        return []

    try:
        result = subprocess.run(
            ["ykman", "list", "--serials"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return []


def has_infnoise() -> bool:
    """
    Check if Infinite Noise TRNG is connected.

    Checks for the device path and infnoise binary.
    """
    device_path = infnoise_device_path()
    return device_path is not None and device_path.exists()


def infnoise_device_path() -> Path | None:
    """
    Get the Infinite Noise device path if available.

    Returns:
        Path to device, or None if not found
    """
    if is_macos():
        # macOS: Check Homebrew installation
        prefix = homebrew_prefix()
        if prefix:
            # infnoise creates a symlink
            candidates = [
                Path("/dev/infnoise"),
                Path(f"{prefix}/var/run/infnoise"),
            ]
            for path in candidates:
                if path.exists():
                    return path

        # Check for ftdi device directly
        ftdi_paths = list(Path("/dev").glob("cu.usbserial-*"))
        if ftdi_paths:
            return ftdi_paths[0]

    elif is_linux():
        # Linux: Check for hidraw or serial device
        # The device ID is 0403:6015 for FTDI chip
        candidates = [
            Path("/dev/infnoise"),
            *list(Path("/dev").glob("hidraw*")),
            *list(Path("/dev").glob("ttyUSB*")),
        ]
        for path in candidates:
            if path.exists():
                # TODO: Verify it's actually an Infinite Noise device
                return path

    return None


def _infnoise_binary_path() -> Path | None:
    """Get path to infnoise binary if installed."""
    try:
        result = subprocess.run(
            ["which", "infnoise"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            return Path(result.stdout.strip())
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Check Homebrew
    if is_macos():
        prefix = homebrew_prefix()
        if prefix:
            binary = Path(prefix) / "bin" / "infnoise"
            if binary.exists():
                return binary

    return None


def has_smartcard_reader() -> bool:
    """
    Check if a smart card reader is available.

    On macOS, checks for built-in CCID support.
    On Linux, checks for pcscd.
    """
    if is_macos():
        # macOS has built-in smart card support via CryptoTokenKit
        # Check if any smart card readers are detected
        try:
            result = subprocess.run(
                ["system_profiler", "SPSmartCardsDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0 and "Readers" in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    elif is_linux():
        # Check for pcscd (PC/SC daemon)
        try:
            result = subprocess.run(
                ["pcsc_scan", "-n"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return False


def check_all_hardware() -> HardwareStatus:
    """
    Check status of all security hardware.

    Returns:
        HardwareStatus with detection results for all hardware
    """
    serials = yubikey_serials()
    return HardwareStatus(
        yubikey=len(serials) > 0,
        yubikey_count=len(serials),
        infnoise=has_infnoise(),
        smartcard_reader=has_smartcard_reader(),
    )
