"""
bastion-core: Shared utilities for the Bastion security toolchain.

This package provides platform detection, hardware checks, and network
utilities that are shared across bastion, airgap, and other tools.
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
    __version__ = version("bastion-core")
except PackageNotFoundError:
    __version__ = _read_root_version()

from bastion_core import hardware, platform

__all__ = ["platform", "hardware", "__version__"]
