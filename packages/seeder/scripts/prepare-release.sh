#!/bin/bash
# =============================================================================
# prepare-release.sh - Clean repository for main branch / release
# =============================================================================
# Usage: ./scripts/prepare-release.sh [--dry-run]
#
# This script prepares the codebase for merging to main branch:
# 1. Removes development artifacts
# 2. Strips console.log/debug statements from JS
# 3. Validates no sensitive data is present
# 4. Runs tests to ensure everything works
# =============================================================================

set -e

DRY_RUN=false
if [[ "$1" == "--dry-run" ]]; then
    DRY_RUN=true
    echo "🔍 DRY RUN MODE - No changes will be made"
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Seed Card - Release Preparation Script${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Navigate to repo root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$REPO_ROOT"

echo -e "${YELLOW}📍 Working in: $REPO_ROOT${NC}"
echo ""

# =============================================================================
# Step 1: Check for sensitive files that should NOT be committed
# =============================================================================
echo -e "${BLUE}Step 1: Checking for sensitive files...${NC}"

SENSITIVE_PATTERNS=(
    "*.pem"
    "*.key"
    ".env"
    ".env.*"
    "secrets/*"
    "private/*"
    "real_mnemonics/*"
    "personal_seeds/*"
)

FOUND_SENSITIVE=false
for pattern in "${SENSITIVE_PATTERNS[@]}"; do
    if compgen -G "$pattern" > /dev/null 2>&1; then
        echo -e "${RED}  ❌ Found sensitive file: $pattern${NC}"
        FOUND_SENSITIVE=true
    fi
done

if [ "$FOUND_SENSITIVE" = true ]; then
    echo -e "${RED}  ⚠️  Sensitive files detected! Ensure they're in .gitignore${NC}"
else
    echo -e "${GREEN}  ✅ No sensitive files found${NC}"
fi
echo ""

# =============================================================================
# Step 2: Clean build artifacts
# =============================================================================
echo -e "${BLUE}Step 2: Cleaning build artifacts...${NC}"

CLEAN_DIRS=(
    "__pycache__"
    ".pytest_cache"
    "*.egg-info"
    "htmlcov"
    "docs/web/dist"
    "docs/web/dev-build"
    "docs/web/node_modules"
    ".mypy_cache"
    ".coverage"
)

for dir in "${CLEAN_DIRS[@]}"; do
    if [ -d "$dir" ] || compgen -G "$dir" > /dev/null 2>&1; then
        if [ "$DRY_RUN" = true ]; then
            echo -e "${YELLOW}  Would remove: $dir${NC}"
        else
            rm -rf $dir
            echo -e "${GREEN}  Removed: $dir${NC}"
        fi
    fi
done

# Clean Python cache recursively
if [ "$DRY_RUN" = false ]; then
    find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    echo -e "${GREEN}  Cleaned Python cache files${NC}"
else
    echo -e "${YELLOW}  Would clean Python cache files${NC}"
fi
echo ""

# =============================================================================
# Step 3: Check for debug statements in JavaScript (excluding node_modules/dist)
# =============================================================================
echo -e "${BLUE}Step 3: Checking for debug statements in JS...${NC}"

JS_FILES=$(find docs/web/public docs/web/src -name "*.js" -type f 2>/dev/null || true)
DEBUG_FOUND=false

for file in $JS_FILES; do
    # Check for console.log (excluding legitimate uses)
    if grep -n "console\.log" "$file" | grep -v "// keep" | grep -v "error" > /dev/null 2>&1; then
        echo -e "${YELLOW}  ⚠️  console.log found in: $file${NC}"
        DEBUG_FOUND=true
    fi
    
    # Check for debugger statements
    if grep -n "debugger" "$file" > /dev/null 2>&1; then
        echo -e "${RED}  ❌ debugger statement in: $file${NC}"
        DEBUG_FOUND=true
    fi
done

if [ "$DEBUG_FOUND" = false ]; then
    echo -e "${GREEN}  ✅ No debug statements found in source files${NC}"
fi
echo ""

# =============================================================================
# Step 4: Check for TODO/FIXME comments
# =============================================================================
echo -e "${BLUE}Step 4: Checking for TODO/FIXME comments...${NC}"

TODO_COUNT=$(grep -rn "TODO\|FIXME\|XXX\|HACK" src/ docs/web/public/ docs/web/src/ 2>/dev/null | wc -l || echo "0")
if [ "$TODO_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}  ⚠️  Found $TODO_COUNT TODO/FIXME comments${NC}"
    grep -rn "TODO\|FIXME" src/ docs/web/public/ docs/web/src/ 2>/dev/null | head -5 || true
else
    echo -e "${GREEN}  ✅ No TODO/FIXME comments${NC}"
fi
echo ""

# =============================================================================
# Step 5: Verify .gitignore is comprehensive
# =============================================================================
echo -e "${BLUE}Step 5: Verifying .gitignore...${NC}"

REQUIRED_IGNORES=(
    "__pycache__"
    "*.pyc"
    "venv/"
    ".env"
    "node_modules/"
    "*.csv"
    "htmlcov/"
)

for pattern in "${REQUIRED_IGNORES[@]}"; do
    if grep -q "$pattern" .gitignore 2>/dev/null; then
        echo -e "${GREEN}  ✅ $pattern${NC}"
    else
        echo -e "${RED}  ❌ Missing: $pattern${NC}"
    fi
done
echo ""

# =============================================================================
# Step 6: Run tests
# =============================================================================
echo -e "${BLUE}Step 6: Running tests...${NC}"

if [ "$DRY_RUN" = false ]; then
    if [ -d "venv" ]; then
        source venv/bin/activate
        
        echo "  Running Python tests..."
        if python -m pytest tests/ -v --tb=short 2>/dev/null; then
            echo -e "${GREEN}  ✅ Python tests passed${NC}"
        else
            echo -e "${RED}  ❌ Python tests failed${NC}"
        fi
    else
        echo -e "${YELLOW}  ⚠️  No venv found, skipping Python tests${NC}"
    fi
else
    echo -e "${YELLOW}  Would run: pytest tests/ -v${NC}"
fi
echo ""

# =============================================================================
# Step 7: Generate release checklist
# =============================================================================
echo -e "${BLUE}Step 7: Release Checklist${NC}"
echo ""
echo "Before merging to main:"
echo "  □ All tests pass"
echo "  □ Version number updated in pyproject.toml"
echo "  □ CHANGELOG.md updated"
echo "  □ No console.log/debugger in JS"
echo "  □ No sensitive data in repo"
echo "  □ CSP headers are strict"
echo "  □ README is up to date"
echo ""
echo "After merge:"
echo "  □ Create git tag: git tag -a v1.x.x -m 'Release v1.x.x'"
echo "  □ Push tag: git push origin v1.x.x"
echo "  □ Verify GitHub Pages deployment"
echo "  □ Test deployed site"
echo ""

# =============================================================================
# Summary
# =============================================================================
echo -e "${BLUE}============================================${NC}"
if [ "$DRY_RUN" = true ]; then
    echo -e "${YELLOW}  DRY RUN COMPLETE - No changes made${NC}"
else
    echo -e "${GREEN}  ✅ Release preparation complete!${NC}"
fi
echo -e "${BLUE}============================================${NC}"
