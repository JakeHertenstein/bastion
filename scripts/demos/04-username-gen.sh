#!/bin/bash
# Demo 4: Username Generation
# Duration: ~30 seconds
# Description: Deterministic username generation (simulated output)
#
# Uses simulated output for clean demo

echo "# Deterministic Username Generation"
echo ""
sleep 1

# Step 1: Show help
echo "$ bsec generate username --help"
sleep 0.5
cat << 'EOF'
Usage: bsec generate username [OPTIONS] DOMAIN

  Generate a deterministic username for a domain.

  The username is derived from your master salt (stored in 1Password)
  and the domain name, ensuring you always get the same result.

Options:
  --no-save     Preview only, don't save to 1Password
  --init        Initialize or rotate the master salt
  --help        Show this message and exit.
EOF
echo ""
sleep 2

# Step 2: Generate for GitHub (simulated)
echo "$ bsec generate username github.com --no-save"
sleep 0.5
cat << 'EOF'
Generating username for github.com...
🔑 Using salt from 1Password

Generated: github_k7m2p9x4
EOF
echo ""
sleep 2

# Step 3: Generate for AWS (simulated)
echo "$ bsec generate username aws.amazon.com --no-save"
sleep 0.5
cat << 'EOF'
Generating username for aws.amazon.com...
🔑 Using salt from 1Password

Generated: aws_w3n8v5j1
EOF
echo ""
sleep 2

# Step 4: Verify a username (simulated)
echo "$ bsec verify username github.com github_k7m2p9x4"
sleep 0.5
cat << 'EOF'
Verifying username...
✅ VALID - This username was generated from your salt
EOF
echo ""
sleep 2

echo "# ✅ Unique usernames per-site, reproducible from your salt!"
