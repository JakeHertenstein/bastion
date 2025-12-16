#!/bin/bash
# Cleanup Script: Remove duplicate files from refactoring
# This script removes old flat structure files that have been moved to src/

set -e

echo "🧹 Cleaning up duplicate files from refactoring..."

# Files that have been moved to src/seeder/core/
OLD_CORE_FILES=(
    "config.py"
    "crypto.py" 
    "exceptions.py"
    "grid.py"
    "seed_sources.py"
    "word_generator.py"
)

# Files that have been moved to src/seeder/integrations/
OLD_INTEGRATION_FILES=(
    "onepassword_integration.py"
)

# Files that have been moved to tests/
OLD_TEST_FILES=(
    "test_comprehensive.py"
    "test_modular.py"
    "test_structure.py"
)

# Old CLI structure that's been moved to src/seeder/cli/
OLD_CLI_DIRS=(
    "cli/"
    "commands/"
)

# Temporary files from refactoring
OLD_REFACTOR_FILES=(
    "seeder_refactored.py"
    "logging_config.py"  # Not needed in new structure
)

echo "📁 Removing old core files..."
for file in "${OLD_CORE_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "   Removing $file"
        rm "$file"
    fi
done

echo "📁 Removing old integration files..."
for file in "${OLD_INTEGRATION_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "   Removing $file" 
        rm "$file"
    fi
done

echo "📁 Removing old test files..."
for file in "${OLD_TEST_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "   Removing $file"
        rm "$file"
    fi
done

echo "📁 Removing old CLI directories..."
for dir in "${OLD_CLI_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "   Removing $dir"
        rm -rf "$dir"
    fi
done

echo "📁 Removing refactoring artifacts..."
for file in "${OLD_REFACTOR_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "   Removing $file"
        rm "$file"
    fi
done

# Clean up __pycache__ directories
echo "🗑️ Cleaning up __pycache__ directories..."
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete 2>/dev/null || true

# Move design.md to docs/ if it exists
if [ -f "design.md" ]; then
    echo "📄 Moving design.md to docs/"
    mv "design.md" "docs/"
fi

# Check if the main seeder.py is still needed or if it should be removed
if [ -f "seeder.py" ]; then
    echo "⚠️  Found seeder.py in root - checking if it's needed..."
    # Check if it's different from the new CLI structure
    if [ -f "src/seeder/cli/main.py" ]; then
        echo "   New CLI structure exists, archiving old seeder.py"
        mv "seeder.py" "seeder_legacy.py.bak"
    fi
fi

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "📋 Summary of actions:"
echo "   • Removed duplicate core files (now in src/seeder/core/)"
echo "   • Removed duplicate integration files (now in src/seeder/integrations/)"
echo "   • Removed duplicate test files (now in tests/)" 
echo "   • Removed old CLI directories (now in src/seeder/cli/)"
echo "   • Cleaned up refactoring artifacts"
echo "   • Cleaned up __pycache__ directories"
echo "   • Moved design.md to docs/"
echo ""
echo "🔧 Remaining structure:"
tree . -I "__pycache__|venv|*.pyc|.git|.DS_Store" -a -L 2

echo ""
echo "⚡ Next steps:"
echo "   1. Test the new structure: python seeder --help"
echo "   2. Run tests: python -m pytest tests/"
echo "   3. Commit the cleaned structure: git add ."
