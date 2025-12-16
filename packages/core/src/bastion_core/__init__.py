"""
bastion-core: Shared utilities for the Bastion security toolchain.

This package provides platform detection, hardware checks, and network
utilities that are shared across bastion, airgap, and other tools.
"""

__version__ = "0.3.0"

from bastion_core import hardware, platform

__all__ = ["platform", "hardware", "__version__"]
