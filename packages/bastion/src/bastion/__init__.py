"""Bastion - Password rotation tracking and security management for 1Password."""

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
    __version__ = version("bastion-security")
except PackageNotFoundError:
    __version__ = _read_root_version()
