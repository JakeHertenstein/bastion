# Contributing to Bastion

Thank you for your interest in contributing to Bastion!

## Development Setup

### Prerequisites

- Python 3.11+
- [1Password CLI v2](https://developer.1password.com/docs/cli/) (`op`)
- [YubiKey Manager](https://www.yubico.com/support/download/yubikey-manager/) (`ykman`) — for YubiKey features
- Optional: [Infinite Noise TRNG](https://github.com/waywardgeek/infnoise) — for hardware entropy

### Installation

```bash
# Clone the repository
git clone https://github.com/jakehertenstein/bastion.git
cd bastion

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install in development mode
pip install -e ".[dev]"

# Verify installation
bastion --version
```

### Running Tests

```bash
# Run all unit tests (no 1Password required)
uv run pytest packages/bastion/tests/ -v

# Run with coverage
uv run pytest packages/bastion/tests/ --cov=bastion --cov-report=html

# Run specific test file
uv run pytest packages/bastion/tests/test_entropy.py
```

### Integration Tests

Integration tests require 1Password CLI to be installed and authenticated:

```bash
# Sign in to 1Password CLI
eval $(op signin)

# Run integration tests
uv run pytest packages/bastion/tests/test_integration.py -v

# Run all tests including integration
uv run pytest packages/bastion/tests/ -v
```

Integration tests are automatically skipped if 1Password is not authenticated.

### Code Quality

```bash
# Type checking
mypy bastion --ignore-missing-imports

# Linting
ruff check bastion/

# Format check
ruff format --check bastion/
```

## Project Structure

```
bastion/
├── bastion/              # Main package
│   ├── cli.py            # Typer CLI application
│   ├── entropy.py        # Entropy pool management
│   ├── entropy_*.py      # Source-specific collectors
│   ├── username_generator.py
│   ├── models.py         # Pydantic models
│   ├── op_client.py      # 1Password CLI wrapper
│   └── ...
├── docs/                 # Documentation
├── tests/                # Test suite
├── seeder/               # Seed card generator (separate tool)
└── pyproject.toml
```

## Coding Guidelines

### Style

- **Type hints**: All functions must have type annotations
- **Docstrings**: Google-style docstrings for public functions
- **Formatting**: Use `ruff format` for consistent style

### Security Requirements

- **No hardcoded secrets**: Never commit real UUIDs, emails, or credentials
- **Example data**: Use `@example.com` for emails, `12345678` for serials
- **Determinism**: Cryptographic operations must be reproducible given same inputs

### CLI Conventions

- Use [Typer](https://typer.tiangolo.com/) for command definitions
- Use [Rich](https://rich.readthedocs.io/) for console output with colors
- Exit with `raise typer.Exit(1)` for errors

### Error Handling

```python
# CLI errors - exit gracefully
if not valid:
    console.print("[red]Error:[/red] Invalid input")
    raise typer.Exit(1)

# Library errors - raise exceptions
if not data:
    raise ValueError("Missing required data")
```

## Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Write** tests for new functionality
4. **Ensure** all tests pass (`pytest`)
5. **Check** code quality (`mypy`, `ruff`)
6. **Commit** with clear messages
7. **Push** to your fork
8. **Open** a Pull Request

### Commit Messages

Use conventional commit format:

```
feat: add entropy source validation
fix: handle empty YubiKey response
docs: update entropy system guide
test: add username generator edge cases
```

### Versioning (SemVer)

Bastion uses [Semantic Versioning](https://semver.org/):

| Type | When | Version Change |
|------|------|----------------|
| **MAJOR** | Breaking changes (CLI, config, data formats) | 1.0.0 → 2.0.0 |
| **MINOR** | New features (backward-compatible) | 0.1.0 → 0.2.0 |
| **PATCH** | Bug fixes, docs, refactoring | 0.1.0 → 0.1.1 |

**Version is defined in** `bastion/__init__.py` — update there for releases.

**Release process**:
1. Update `__version__` in `bastion/__init__.py`
2. Commit: `git commit -m "chore: bump version to X.Y.Z"`
3. Tag: `git tag vX.Y.Z`
4. Push: `git push origin develop --tags`
5. Create GitHub release from tag

## Documentation

- User-facing docs go in `docs/`
- Update `docs/README.md` index when adding new docs
- Use consistent naming: `FEATURE-NAME.md` (uppercase with hyphens)
- Include examples and CLI commands

## Questions?

Open an issue for questions, bug reports, or feature requests.

## License

By contributing, you agree that your contributions will be licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).
