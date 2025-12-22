"""
Seeder - Password Token Matrix Generator

A secure, deterministic password token generator that creates 10×10 matrices 
of cryptographic tokens from various seed sources.
"""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


def _read_root_version() -> str:
    try:
        p = Path(__file__).resolve()
        for parent in [p.parent, *p.parents]:
            vf = (parent / "VERSION")
            if vf.exists():
                return vf.read_text(encoding="utf-8").strip()
    except Exception:
        pass
    return "0.0.0"

try:
    __version__ = version("bastion-seeder")
except PackageNotFoundError:
    __version__ = _read_root_version()

__author__ = "Seeder Development Team"
__description__ = "Password Token Matrix Generator"

from .core.crypto import PasswordEntropyAnalyzer, SeedCardDigest
from .core.grid import SeederGrid
from .core.seed_sources import SeedSources

__all__ = [
    "SeederGrid",
    "SeedCardDigest",
    "PasswordEntropyAnalyzer",
    "SeedSources"
]
