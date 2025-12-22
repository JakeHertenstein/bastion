"""
Network connectivity checking utilities.

Provides functions to check internet connectivity and reach specific hosts.
Used to verify network status and detect air-gap breaks.
"""

import socket
import subprocess
from functools import lru_cache

__all__ = [
    "has_internet_connectivity",
    "can_reach_host",
    "can_reach_dns",
]

# Well-known DNS servers for connectivity checks
GOOGLE_DNS = "8.8.8.8"
CLOUDFLARE_DNS = "1.1.1.1"
QUAD9_DNS = "9.9.9.9"


def can_reach_host(host: str, port: int = 443, timeout: float = 3.0) -> bool:
    """
    Check if a specific host:port is reachable.

    Args:
        host: Hostname or IP address
        port: Port number (default 443 for HTTPS)
        timeout: Connection timeout in seconds

    Returns:
        True if host is reachable
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except OSError:
        return False


def can_reach_dns(dns_server: str = CLOUDFLARE_DNS, timeout: float = 2.0) -> bool:
    """
    Check if DNS server is reachable (indicates network connectivity).

    Args:
        dns_server: DNS server IP to check
        timeout: Connection timeout in seconds

    Returns:
        True if DNS server is reachable
    """
    return can_reach_host(dns_server, port=53, timeout=timeout)


@lru_cache(maxsize=1)
def has_internet_connectivity(timeout: float = 3.0) -> bool:
    """
    Check if system has internet connectivity.

    Attempts to reach multiple DNS servers to confirm connectivity.
    Results are cached for performance.

    Args:
        timeout: Timeout per connection attempt

    Returns:
        True if any internet connectivity is detected
    """
    # Try multiple DNS servers for redundancy
    for dns in [CLOUDFLARE_DNS, GOOGLE_DNS, QUAD9_DNS]:
        if can_reach_dns(dns, timeout=timeout):
            return True
    return False


def clear_connectivity_cache() -> None:
    """Clear the connectivity check cache to force re-check."""
    has_internet_connectivity.cache_clear()


def ping_host(host: str, count: int = 1, timeout: float = 3.0) -> bool:
    """
    Ping a host using system ping command.

    Note: Requires network access. Use can_reach_host() for most cases.

    Args:
        host: Hostname or IP address
        count: Number of ping attempts
        timeout: Timeout per ping

    Returns:
        True if ping succeeds
    """
    try:
        # Use different ping flags for different platforms
        import platform

        if platform.system().lower() == "windows":
            cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), host]

        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout * count + 5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
