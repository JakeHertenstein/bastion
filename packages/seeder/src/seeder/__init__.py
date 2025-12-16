"""
Seeder - Password Token Matrix Generator

A secure, deterministic password token generator that creates 10×10 matrices 
of cryptographic tokens from various seed sources.
"""

# Import version from parent bastion package
try:
    from bastion import __version__
except ImportError:
    __version__ = "0.1.0"  # Fallback for standalone development
__author__ = "Seeder Development Team"
__description__ = "Password Token Matrix Generator"

from .core.grid import SeederGrid
from .core.crypto import SeedCardDigest, PasswordEntropyAnalyzer
from .core.seed_sources import SeedSources

__all__ = [
    "SeederGrid",
    "SeedCardDigest", 
    "PasswordEntropyAnalyzer",
    "SeedSources"
]
