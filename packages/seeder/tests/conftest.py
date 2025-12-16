"""Pytest configuration for seeder tests.

This conftest.py ensures the seeder package is importable when running
tests from the monorepo root via testpaths = ["packages/*/tests"].
"""

import sys
from pathlib import Path

# Add seeder src to path for pytest collection
seeder_src = Path(__file__).parent.parent / "src"
if seeder_src.exists() and str(seeder_src) not in sys.path:
    sys.path.insert(0, str(seeder_src))
