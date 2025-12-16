#!/bin/bash
# Seed Card Password Token Generator - Setup Script

set -e  # Exit on any error

echo "🎴 Seed Card Password Token Generator - Setup"
echo "============================================="

# Check Python version
python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
echo "📋 Python version: $python_version"

if [[ $(echo "$python_version >= 3.8" | bc -l) -eq 0 ]]; then
    echo "❌ Error: Python 3.8 or higher required"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "🔧 Creating virtual environment..."
    python3 -m venv venv
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "📦 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "✅ Setup complete!"
echo ""
echo "🚀 Quick start:"
echo "   source venv/bin/activate"
echo "   python3 seeder.py demo"
echo ""
echo "📚 Full documentation:"
echo "   python3 seeder.py --help"
echo "   python3 seeder.py show info"
echo ""
echo "🔧 Install bash completion:"
echo "   python3 seeder.py install-completion"
echo ""
echo "⚠️  Security reminder:"
echo "   This tool is designed for online passwords with rate limiting."
echo "   Always use 2FA for sensitive accounts."
