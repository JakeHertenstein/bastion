# VS Code Development Environment Guide

## 🎯 Overview

This guide provides comprehensive VS Code configuration for optimal development experience with the Seed Card project.

## 🚀 Quick Setup

### 1. Open Workspace
```bash
# Option 1: Open workspace file (recommended)
code seed-card.code-workspace

# Option 2: Open folder
code .
```

### 2. Install Recommended Extensions
VS Code will prompt to install recommended extensions. Accept to install:

- **Python Extension Pack** - Core Python development
- **Python Debugger (debugpy)** - Modern Python debugging
- **Black Formatter** - Code formatting
- **isort** - Import organization  
- **MyPy Type Checker** - Static type checking
- **Flake8** - Code linting
- **Ruff** - Fast Python linter
- **Pytest** - Test runner integration
- **GitHub Copilot** - AI assistance
- **Todo Tree** - Track TODO/FIXME comments

## 🐍 Python Configuration

### Virtual Environment Setup

The workspace is configured to automatically use the project's virtual environment:

```json
{
    "python.defaultInterpreterPath": "./venv/bin/python",
    "python.terminal.activateEnvironment": true,
    "python.analysis.extraPaths": ["./src"]
}
```

### Code Quality Tools

**Automatic formatting on save:**
- **Black** for code formatting (88 character line length)
- **isort** for import organization
- **MyPy** for type checking
- **Flake8** for linting

## 🔧 Debug Configurations

### Available Debug Configurations

1. **🐍 Debug Seeder CLI** - Debug the main CLI application
2. **🔑 Debug BIP-39 Generation** - Test BIP-39 mnemonic processing
3. **📊 Debug CSV Export** - Test CSV export functionality
4. **🧪 Run Unit Tests** - Debug test execution
5. **🔍 Debug Specific Test** - Debug currently open test file
6. **🔧 Debug Core Module** - Debug any core module
7. **📋 Debug 1Password Integration** - Test 1Password integration

### Quick Debug Examples

```bash
# Start debugging with F5 or:
# Debug Panel → Select configuration → Start Debugging

# Set breakpoints by clicking line numbers
# Use Debug Console to evaluate expressions
# Step through code with F10 (step over), F11 (step into)
```

## ⚡ Tasks and Commands

### Built-in Tasks (Ctrl+Shift+P → "Tasks: Run Task")

1. **🧪 Run All Tests** - Execute complete test suite
2. **🔧 Run Seeder CLI** - Quick CLI execution
3. **📦 Install Dependencies** - Install/update dependencies
4. **🎨 Format Code** - Format all Python files
5. **📋 Sort Imports** - Organize imports
6. **🔍 Type Check** - Run MyPy type checking
7. **🧹 Lint Code** - Run Flake8 linting
8. **🔄 Full Code Quality Check** - Run all quality checks sequentially
9. **📊 Generate Coverage Report** - Create test coverage report
10. **🚀 Build Package** - Build distribution package
11. **🔒 Security Check** - Run security vulnerability scan

### Keyboard Shortcuts

```
F5                 - Start Debugging
Ctrl+Shift+`       - Open Terminal
Ctrl+Shift+P       - Command Palette
Ctrl+K Ctrl+S      - Keyboard Shortcuts
Ctrl+`             - Toggle Terminal
Ctrl+B             - Toggle Sidebar
Ctrl+Shift+E       - Explorer
Ctrl+Shift+F       - Search
Ctrl+Shift+G       - Source Control
Ctrl+Shift+D       - Debug
Ctrl+Shift+X       - Extensions
```

## 🧪 Testing Integration

### Test Discovery and Execution

VS Code automatically discovers tests using pytest:

```json
{
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests/", "-v"],
    "python.testing.autoTestDiscoverOnSaveEnabled": true
}
```

### Test Explorer

- **Test Explorer Panel** - View all tests hierarchically
- **Run Tests** - Click play button next to test/class/file
- **Debug Tests** - Click debug button to debug specific tests
- **Test Output** - View test results and failures
- **Coverage** - Generate and view coverage reports

### Coverage Reports

```bash
# Generate coverage report (via task or terminal)
python -m pytest tests/ --cov=src/seeder --cov-report=html --cov-report=term

# View HTML report
open htmlcov/index.html
```

## 🎨 Code Quality Integration

### Automatic Code Formatting

**On Save Actions:**
```json
{
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
        "source.organizeImports": "explicit"
    }
}
```

**Manual Formatting:**
- **Shift+Alt+F** - Format document
- **Ctrl+Shift+P** → "Format Document"
- **Ctrl+Shift+P** → "Organize Imports"

### Linting and Type Checking

**Real-time feedback:**
- **Red squiggles** - Syntax errors
- **Yellow squiggles** - Warnings (unused imports, etc.)
- **Blue squiggles** - Type hints and suggestions
- **Green squiggles** - Spelling errors (with Code Spell Checker)

### Problem Panel

- **Ctrl+Shift+M** - Open Problems panel
- View all linting errors, type issues, and warnings
- Click to navigate to specific issues
- Filter by error type or file

## 🔍 Advanced Features

### IntelliSense and Code Navigation

**Navigation:**
- **Ctrl+Click** - Go to definition
- **Alt+F12** - Peek definition
- **Shift+F12** - Find all references
- **Ctrl+T** - Go to symbol in workspace
- **Ctrl+Shift+O** - Go to symbol in file

**IntelliSense:**
- **Ctrl+Space** - Trigger suggestions
- **Ctrl+Shift+Space** - Parameter hints
- **F2** - Rename symbol
- **Ctrl+.** - Quick fix

### Multi-Repository Management

**Git Integration:**
```json
{
    "git.ignoreLimitWarning": true,
    "git.enableSmartCommit": true,
    "git.confirmSync": false
}
```

**Source Control Panel:**
- **Ctrl+Shift+G** - Open Source Control
- Stage changes with **+** button
- Commit with **Ctrl+Enter**
- View git history and branches
- Handle merge conflicts with built-in tools

### Workspace Features

**File Exclusions:**
```json
{
    "files.exclude": {
        "**/__pycache__": true,
        "**/*.pyc": true,
        "**/venv": true,
        "**/.pytest_cache": true
    }
}
```

**Search Exclusions:**
```json
{
    "search.exclude": {
        "**/__pycache__": true,
        "**/venv": true,
        "**/build": true,
        "**/dist": true
    }
}
```

## 🔐 Security and Privacy

### Sensitive File Handling

**Excluded from version control:**
```gitignore
.vscode/settings.json    # Personal settings
*.csv                    # Test data
*.key                    # Private keys
config/private/          # Private configurations
```

**Environment Variables:**
```json
{
    "terminal.integrated.env.osx": {
        "PYTHONPATH": "${workspaceFolder}/src"
    }
}
```

### Secret Management

**For 1Password integration:**
1. Store tokens in environment variables
2. Use `.env` files (gitignored)
3. Configure debug environments carefully

## 🚀 Performance Optimization

### VS Code Performance

**Optimize for large projects:**
```json
{
    "files.watcherExclude": {
        "**/.git/objects/**": true,
        "**/node_modules/**": true,
        "**/venv/**": true,
        "**/__pycache__/**": true
    },
    "python.analysis.autoImportCompletions": true,
    "python.analysis.include": ["src/**", "tests/**"],
    "python.analysis.exclude": ["**/__pycache__", "**/venv"]
}
```

### Extension Optimization

**Disable unused language extensions:**
- Disable JavaScript/TypeScript extensions if not needed
- Disable Docker extensions if not using containers
- Keep only Python-related extensions active

## 🛠️ Troubleshooting

### Common Issues

**1. Python interpreter not found:**
```bash
# Solution: Select correct interpreter
Ctrl+Shift+P → "Python: Select Interpreter" → Choose ./venv/bin/python
```

**2. Import errors in tests:**
```bash
# Solution: Check PYTHONPATH setting
"python.analysis.extraPaths": ["./src"]
```

**3. Debugger not stopping at breakpoints:**
```bash
# Solution: Ensure debugpy is used
"type": "debugpy"  # Not "python"
```

**4. Tests not discovered:**
```bash
# Solution: Refresh test discovery
Ctrl+Shift+P → "Python: Refresh Tests"
```

### Performance Issues

**If VS Code is slow:**
1. Check excluded files configuration
2. Disable unnecessary extensions
3. Increase memory limit if needed
4. Close unused editor tabs

### Integration Issues

**Git worktree problems:**
```bash
# Solution: Open each worktree separately
code ../seed-card-public
code ../seed-card-private  
code ../seed-card-enterprise
```

## 📋 Checklists

### Daily Development Checklist

- [ ] Activate virtual environment
- [ ] Pull latest changes
- [ ] Run full code quality check
- [ ] Write/update tests for new features
- [ ] Generate coverage report
- [ ] Commit with clear messages

### Code Review Checklist

- [ ] All tests passing
- [ ] Code formatted with Black
- [ ] Imports organized with isort
- [ ] Type hints added
- [ ] No linting errors
- [ ] Security scan passed
- [ ] Documentation updated

### Release Checklist

- [ ] Version numbers updated
- [ ] Changelog updated
- [ ] All tests passing
- [ ] Coverage above threshold
- [ ] Security scan clean
- [ ] Documentation up to date
- [ ] Git tags created

This configuration provides a comprehensive development environment optimized for the Seed Card project's specific needs.
