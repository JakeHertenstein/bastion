#!/bin/bash
# Quick Development Environment Setup for Seed Card

set -e

echo "🔧 Setting up Seed Card development environment..."

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Please run this script from the Seed Card project root"
    exit 1
fi

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    echo "📦 Activating virtual environment..."
    source venv/bin/activate
else
    echo "❌ Virtual environment not found. Please create one first:"
    echo "   python3 -m venv venv"
    echo "   source venv/bin/activate"
    echo "   pip install -e .[dev]"
    exit 1
fi

# Install development dependencies
echo "📦 Installing development dependencies..."
pip install -e .[dev]

# Install additional development tools
echo "🛠️ Installing development tools..."
pip install pytest-cov safety bandit

# Run initial code quality check
echo "🧹 Running initial code quality check..."
if command -v black &> /dev/null; then
    black src/ tests/ --check || echo "⚠️ Code formatting needed - run: black src/ tests/"
fi

if command -v isort &> /dev/null; then
    isort src/ tests/ --check-only --profile black || echo "⚠️ Import sorting needed - run: isort src/ tests/ --profile black"
fi

# Run tests
echo "🧪 Running initial test suite..."
python -m pytest tests/ -v --tb=short || echo "⚠️ Some tests failed - check output above"

# Security check
echo "🔒 Running security check..."
safety check || echo "⚠️ Security vulnerabilities found - review output above"

# Check git configuration
echo "🔄 Checking git configuration..."
if [ ! -d ".git" ]; then
    echo "❌ Not a git repository. Initialize with: git init"
else
    echo "✅ Git repository detected"
    git status --porcelain | head -10 | while read -r line; do
        echo "   $line"
    done
fi

echo ""
echo "🎉 Development environment setup complete!"
echo ""
echo "📋 Next steps:"
echo "   1. Open VS Code: code seed-card.code-workspace"
echo "   2. Install recommended extensions when prompted"
echo "   3. Run tests: python -m pytest tests/"
echo "   4. Start developing!"
echo ""
echo "🔧 Available commands:"
echo "   • Run CLI: python seeder --help"
echo "   • Run tests: python -m pytest tests/"
echo "   • Format code: black src/ tests/"
echo "   • Type check: mypy src/seeder"
echo "   • Full quality check: Run VS Code task 'Full Code Quality Check'"
echo ""
echo "📚 Documentation:"
echo "   • Git Strategy: docs/GIT_STRATEGY.md"
echo "   • VS Code Guide: docs/VSCODE_GUIDE.md"
echo "   • Main README: README.md"
