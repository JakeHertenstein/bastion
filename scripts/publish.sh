#!/bin/bash
set -euo pipefail

# Clean old build artifacts
echo "Cleaning dist/ ..."
rm -rf "$(dirname "$0")/../dist"/*


# Determine repo root before changing directories
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Build the package
echo "Building package ..."
cd "$REPO_ROOT/packages/bastion"
uv build


# Show resulting files (always from repo root)
echo "Built files:"
ls -lh "$REPO_ROOT/dist"

echo "To publish to TestPyPI:"
echo "  uv publish --publish-url https://test.pypi.org/legacy/"
echo "To publish to PyPI:"
echo "  uv publish"
