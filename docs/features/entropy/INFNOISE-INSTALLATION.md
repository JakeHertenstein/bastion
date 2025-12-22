# Infinite Noise TRNG Installation Guide

This guide covers installation of the leetronics Infinite Noise True Random Number Generator (TRNG) driver for use with Bastion.

## Hardware

The Infinite Noise TRNG is a USB hardware device that generates true random numbers using thermal noise and a modular entropy multiplier architecture.

**Device specifications:**
- USB interface (FTDI chip)
- ~300,000 bits/second throughput
- ~0.86 bits entropy per output bit
- Built-in Keccak-1600 whitening
- Open-source hardware and software

**Purchase:** [leetronics on Tindie](https://www.tindie.com/products/leetronics/infinite-noise-trng/) or build from schematics.

## macOS Installation

### Prerequisites

```bash
# Install FTDI and USB libraries
brew install libftdi libusb
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/leetronics/infnoise
cd infnoise/software

# Build for macOS
make -f Makefile.macos

# Verify build
./infnoise --help
```

### Install System-Wide (Optional)

```bash
# Copy to /usr/local/bin
sudo cp infnoise /usr/local/bin/

# Verify installation
which infnoise
infnoise --help
```

### FTDI Kernel Driver Conflict

macOS includes a built-in FTDI driver that may conflict with libftdi. If the device is not detected:

```bash
# Check if kernel driver is loaded
kextstat | grep -i ftdi

# Unload the kernel driver (requires sudo)
sudo kextunload -b com.FTDI.driver.FTDIUSBSerialDriver

# Try again
infnoise --list-devices
```

**Note:** The kernel driver will reload on reboot. For permanent unloading, you may need to modify system settings (see macOS security documentation).

## Linux Installation

### Debian/Ubuntu

```bash
# Install dependencies
sudo apt install build-essential libftdi-dev

# Clone and build
git clone https://github.com/leetronics/infnoise
cd infnoise/software
make -f Makefile.linux

# Install
sudo make -f Makefile.linux install
```

### Udev Rules (Required for non-root access)

```bash
# Create udev rule
sudo tee /etc/udev/rules.d/75-infnoise.rules << 'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="0403", ATTR{idProduct}=="6015", MODE="0666", GROUP="plugdev"
EOF

# Reload rules
sudo udevadm control --reload-rules
sudo udevadm trigger

# Add user to plugdev group (if not already)
sudo usermod -a -G plugdev $USER

# Log out and back in for group change to take effect
```

## Verification

### List Devices

```bash
infnoise --list-devices
# Should show connected Infinite Noise device(s)
```

### Test Output

```bash
# Generate 64 bytes and display as hex
infnoise | head -c 64 | xxd

# Generate 1KB for ENT analysis
infnoise | head -c 1024 > test_entropy.bin
ent test_entropy.bin
```

### Health Check

```bash
# Run with debug output
infnoise --debug --no-output
# Shows entropy quality metrics and health status
```

## Usage with Bastion

Once installed, use the Infinite Noise TRNG as an entropy source:

```bash
# Generate default 8192 bits (1KB, minimum for ENT analysis)
bsec generate entropy infnoise

# Generate 16384 bits (2KB) for extra margin
bsec generate entropy infnoise --bits 16384
```

## Troubleshooting

### "infnoise command not found"

```bash
# Check if in PATH
which infnoise

# If built locally, use full path or install system-wide
./infnoise/software/infnoise --list-devices
```

### "No Infinite Noise devices found"

1. Verify USB connection: `lsusb` (Linux) or `system_profiler SPUSBDataType` (macOS)
2. Check for FTDI device with VID:PID 0403:6015
3. On macOS: Unload kernel FTDI driver (see above)
4. On Linux: Verify udev rules and group membership

### "Permission denied"

- **Linux**: Add udev rules and ensure user is in `plugdev` group
- **macOS**: Try running with `sudo` to diagnose, then fix permissions

### "Device failed health check"

The Infinite Noise TRNG has built-in health monitoring. If health checks fail:

1. Try disconnecting and reconnecting the device
2. Try a different USB port
3. Check for electrical interference
4. Contact leetronics support if persistent

## References

- [GitHub Repository](https://github.com/leetronics/infnoise)
- [Technical Documentation](https://github.com/leetronics/infnoise/blob/master/software/README.md)
- [Hardware Schematics](https://github.com/leetronics/infnoise/tree/master/hardware)
