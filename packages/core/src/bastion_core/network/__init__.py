"""
Network detection and air-gap verification utilities.

Provides functions to detect network connectivity status, verify air-gap
configuration, and check for specific network services.
"""

from bastion_core.network.airgap import (
    AirgapStatus,
    check_airgap_status,
    has_network_interfaces,
    is_airgapped,
)
from bastion_core.network.connectivity import (
    can_reach_dns,
    can_reach_host,
    has_internet_connectivity,
)

__all__ = [
    # Air-gap checks
    "is_airgapped",
    "check_airgap_status",
    "AirgapStatus",
    "has_network_interfaces",
    # Connectivity checks
    "has_internet_connectivity",
    "can_reach_host",
    "can_reach_dns",
]
