# Terminal Demo Recording System

Asciinema terminal demos for the Bastion README.

## Quick Start

```bash
# Record all demos (auto-executes each script)
./record-all.sh

# Record a specific demo
./record-all.sh 3
```

## Prerequisites

1. **asciinema**: `brew install asciinema`
2. **Bastion**: Installed (`pip install -e packages/bastion`)

## Demo Scripts

All demos use **simulated output** to:
- Keep recordings consistent and reproducible
- Avoid exposing real account data
- Work without requiring YubiKey or 1Password auth

| # | Script | Cast File | Description |
|---|--------|-----------|-------------|
| 1 | `01-initial-setup.sh` | `demo-01-initial-setup.cast` | Install, sync, first report |
| 2 | `02-daily-check.sh` | `demo-02-daily-check.cast` | Report status, overdue alerts |
| 3 | `03-yubikey-mgmt.sh` | `demo-03-yubikey-mgmt.cast` | List, scan, cache YubiKeys |
| 4 | `04-username-gen.sh` | `demo-04-username-gen.cast` | Generate deterministic usernames |
| 5 | `05-entropy-collect.sh` | `demo-05-entropy-collect.cast` | Collect from multiple sources |

## Recording Workflow

```bash
# Record all demos
./record-all.sh

# Review a recording
asciinema play demo-01-setup.cast

# Play at 2x speed
asciinema play -s 2 demo-01-setup.cast
```

## Preparation (Optional)

For a clean recording environment:

```bash
# Set clean prompt
export PS1='$ '

# Resize terminal to 80×24
# Clear terminal
clear
```

## Converting to GIF

```bash
# Install agg (asciinema gif generator)
cargo install --git https://github.com/asciinema/agg

# Convert
agg demo-01-setup.cast demo-01-setup.gif --font-size 14
```

## Uploading to asciinema.org

```bash
asciinema upload demo-01-setup.cast
```
