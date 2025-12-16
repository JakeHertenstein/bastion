"""
Air-gap detection and verification.

Provides utilities to verify that a system is properly air-gapped
(no network connectivity) for secure cryptographic operations.
"""

import subprocess
from typing import NamedTuple

from bastion_core.platform import is_linux, is_macos, is_windows

__all__ = [
    "is_airgapped",
    "check_airgap_status",
    "AirgapStatus",
    "has_network_interfaces",
]


class AirgapStatus(NamedTuple):
    """Detailed status of air-gap configuration."""

    is_airgapped: bool
    has_wifi: bool
    has_ethernet: bool
    has_bluetooth: bool
    active_interfaces: list[str]
    warnings: list[str]


def has_network_interfaces() -> bool:
    """
    Check if any network interfaces are active.

    Returns:
        True if any non-loopback network interfaces are up
    """
    if is_macos():
        return _has_network_interfaces_macos()
    elif is_linux():
        return _has_network_interfaces_linux()
    elif is_windows():
        return _has_network_interfaces_windows()
    return True  # Assume connected if we can't detect


def _has_network_interfaces_macos() -> bool:
    """Check network interfaces on macOS."""
    try:
        # Get list of active network services
        result = subprocess.run(
            ["networksetup", "-listallhardwareports"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return True  # Assume connected on error

        # Check if any interface is active
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return True

        # Look for active interfaces (status: active, has inet)
        lines = result.stdout.split("\n")
        current_interface = ""
        for line in lines:
            if not line.startswith("\t") and ":" in line:
                current_interface = line.split(":")[0]
            # Skip loopback
            if current_interface == "lo0":
                continue
            # Check for IP address assignment
            if "inet " in line and "127.0.0.1" not in line:
                return True

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return True  # Assume connected on error

    return False


def _has_network_interfaces_linux() -> bool:
    """Check network interfaces on Linux."""
    try:
        result = subprocess.run(
            ["ip", "addr", "show"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return True

        # Look for interfaces with state UP and IP addresses
        lines = result.stdout.split("\n")
        for line in lines:
            # Skip loopback and look for non-localhost IPs
            if "inet " in line and "127.0.0.1" not in line:
                if "scope global" in line:
                    return True

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return True

    return False


def _has_network_interfaces_windows() -> bool:
    """Check network interfaces on Windows."""
    try:
        result = subprocess.run(
            ["ipconfig"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            return True

        # Look for IPv4 addresses that aren't localhost
        for line in result.stdout.split("\n"):
            if "IPv4" in line and "127.0.0.1" not in line:
                return True

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return True

    return False


def is_airgapped() -> bool:
    """
    Quick check if system appears to be air-gapped.

    Returns:
        True if no active network interfaces are detected
    """
    return not has_network_interfaces()


def check_airgap_status() -> AirgapStatus:
    """
    Perform detailed air-gap verification.

    Checks for WiFi, Ethernet, Bluetooth, and any active network interfaces.
    Returns warnings for any potential network vectors.

    Returns:
        AirgapStatus with detailed information about network status
    """
    warnings: list[str] = []
    active_interfaces: list[str] = []
    has_wifi = False
    has_ethernet = False
    has_bluetooth = False

    if is_macos():
        # Check WiFi status
        try:
            result = subprocess.run(
                ["networksetup", "-getairportpower", "en0"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "On" in result.stdout:
                has_wifi = True
                warnings.append("WiFi is enabled")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check Bluetooth
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip() == "1":
                has_bluetooth = True
                warnings.append("Bluetooth is enabled")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Get active interfaces
        try:
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                current_iface = ""
                for line in result.stdout.split("\n"):
                    if not line.startswith("\t") and ":" in line:
                        current_iface = line.split(":")[0]
                    if current_iface == "lo0":
                        continue
                    if "inet " in line and "127.0.0.1" not in line:
                        active_interfaces.append(current_iface)
                        if current_iface.startswith("en"):
                            if current_iface == "en0":
                                # Usually WiFi on Mac
                                pass  # Already checked
                            else:
                                has_ethernet = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    elif is_linux():
        # Check for WiFi interfaces
        try:
            result = subprocess.run(
                ["iw", "dev"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "Interface" in result.stdout:
                has_wifi = True
                warnings.append("WiFi interface detected")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check Bluetooth
        try:
            result = subprocess.run(
                ["bluetoothctl", "show"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "Powered: yes" in result.stdout:
                has_bluetooth = True
                warnings.append("Bluetooth is enabled")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Get active interfaces
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show", "up"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line and "lo:" not in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            iface = parts[1].strip()
                            active_interfaces.append(iface)
                            if iface.startswith("eth") or iface.startswith("enp"):
                                has_ethernet = True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Add warnings for active interfaces
    if active_interfaces:
        warnings.append(f"Active interfaces: {', '.join(active_interfaces)}")

    airgapped = not has_wifi and not has_ethernet and len(active_interfaces) == 0

    return AirgapStatus(
        is_airgapped=airgapped,
        has_wifi=has_wifi,
        has_ethernet=has_ethernet,
        has_bluetooth=has_bluetooth,
        active_interfaces=active_interfaces,
        warnings=warnings,
    )
