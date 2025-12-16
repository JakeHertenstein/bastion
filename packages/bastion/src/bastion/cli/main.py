"""Main CLI application assembly.

This module creates and configures the main Typer application.
Commands are organized by domain in the commands/ subpackage.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Import the main app with all commands registered
from .app import app

# =============================================================================
# SEEDER INTEGRATION (Optional)
# =============================================================================
# Try to import seeder either from the local sibling directory or as an installed package.
# Seeder has additional dependencies (argon2-cffi, mnemonic, etc.) that may not be installed.
# IMPORTANT: Try local path FIRST to avoid Python caching a failed import.
_seeder_app = None

# First try: local sibling directory (seeder/src/seeder)
# This must come FIRST because Python caches failed imports
try:
    seeder_src = Path(__file__).parent.parent.parent / "seeder" / "src"
    if seeder_src.exists():
        sys.path.insert(0, str(seeder_src))
        from seeder.cli.main import app as _seeder_app
        # Keep path in sys.path - seeder needs it for its submodules
except ImportError:
    # Missing seeder or its dependencies - that's fine, it's optional
    pass

# Second try: installed package (only if local didn't work)
if _seeder_app is None:
    try:
        from seeder.cli.main import app as _seeder_app
    except ImportError:
        pass

if _seeder_app is not None:
    app.add_typer(_seeder_app, name="seeder", help="Password token matrix generator (seed cards)")


# =============================================================================
# AIRGAP INTEGRATION (Optional)
# =============================================================================
# Try to import airgap either from the local sibling directory or as an installed package.
# Airgap has additional dependencies (shamir-mnemonic, qrcode, etc.) that may not be installed.
_airgap_app = None

# First try: local sibling directory (airgap/src/airgap)
try:
    airgap_src = Path(__file__).parent.parent.parent / "airgap" / "src"
    if airgap_src.exists():
        sys.path.insert(0, str(airgap_src))
        from airgap.cli.main import app as _airgap_app
except ImportError:
    pass

# Second try: installed package (only if local didn't work)
if _airgap_app is None:
    try:
        from airgap.cli.main import app as _airgap_app
    except ImportError:
        pass

if _airgap_app is not None:
    app.add_typer(_airgap_app, name="airgap", help="Air-gapped key generation (SLIP-39)")


if __name__ == "__main__":
    app()
