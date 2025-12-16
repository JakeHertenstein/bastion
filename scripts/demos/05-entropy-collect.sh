#!/bin/bash
# Demo 5: Entropy Collection
# Duration: ~45 seconds
# Description: Hardware entropy collection (simulated output)
#
# Uses simulated output for clean demo

echo "# Hardware Entropy Collection"
echo ""
sleep 1

# Step 1: Show entropy help
echo "$ bsec generate entropy --help"
sleep 0.5
cat << 'EOF'
Usage: bsec generate entropy [SOURCE]

  Collect high-quality entropy from hardware sources.

Sources:
  yubikey        YubiKey HMAC-SHA1 challenge-response
  infnoise       Infinite Noise TRNG device
  dice           Physical dice rolls (manual input)
  batch-*        Batch collection (batch-yubikey, batch-infnoise)
  combine        Combine multiple entropy pools (XOR + SHAKE256)
EOF
echo ""
sleep 2

# Step 2: Collect from YubiKey (simulated)
echo "$ bsec generate entropy yubikey --bits 512"
sleep 0.5
cat << 'EOF'
Collecting entropy from YubiKey...
  Challenge-response rounds: 8
  Raw bytes collected: 64

ENT Analysis:
  Entropy: 7.982 bits/byte (ideal: 8.0)
  Chi-square: 248.32 (p=0.53)
  Quality: EXCELLENT

✅ Entropy pool created: abc12345-...
EOF
echo ""
sleep 3

# Step 3: Batch collection (simulated)
echo "$ bsec generate entropy batch-yubikey --count 5"
sleep 0.5
cat << 'EOF'
Collecting 5 YubiKey entropy pools...
  [1/5] ✓ EXCELLENT  [2/5] ✓ EXCELLENT  [3/5] ✓ EXCELLENT
  [4/5] ✓ EXCELLENT  [5/5] ✓ EXCELLENT

✅ Created 5 entropy pools
EOF
echo ""
sleep 2

# Step 4: Combine sources (simulated)
echo "$ bsec generate entropy combine --sources yubikey,infnoise"
sleep 0.5
cat << 'EOF'
Combining entropy sources...
  ├─ yubikey:  Pool abc123... (8192 bits) ✓
  └─ infnoise: Pool def456... (8192 bits) ✓

Combination: XOR + SHAKE256
  • No single source failure compromises output
  • Result entropy ≥ max(source entropies)

✅ Combined pool created: xyz789-...
EOF
echo ""
sleep 2

echo "# ✅ High-quality entropy ready for cryptographic use!"
