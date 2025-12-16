"""Infinite Noise TRNG entropy collection.

This module collects entropy from the leetronics Infinite Noise True Random
Number Generator (TRNG), a USB hardware device using modular entropy multiplication.

The Infinite Noise TRNG uses a "Modular Entropy Multiplier" architecture with
thermal noise as the entropy source. It includes built-in health monitoring
and Keccak-1600 whitening for cryptographic-quality output.

Key characteristics:
- Produces ~0.86 bits of entropy per output bit (with loop gain K=1.82)
- Outputs ~300,000 bits/second raw, whitened to cryptographic quality
- USB device using FTDI interface

Reference: https://github.com/leetronics/infnoise
"""

import subprocess
import re
from typing import Optional
from dataclasses import dataclass


@dataclass
class InfNoiseMetadata:
    """Metadata about Infinite Noise TRNG collection."""
    serial: str
    byte_count: int
    whitened: bool
    multiplier: int
    collection_method: str = "infnoise CLI"
    
    def to_dict(self) -> dict[str, str | int | bool]:
        """Convert to dictionary for storage in 1Password.
        
        Field names use Title Case for 1Password canonical form.
        """
        return {
            "Serial Number": self.serial,
            "Whitened": str(self.whitened),
            "Collection Method": self.collection_method,
        }


class InfNoiseError(Exception):
    """Raised when Infinite Noise TRNG operations fail."""
    pass


def list_infnoise_devices() -> list[dict[str, str]]:
    """List connected Infinite Noise TRNG devices.
    
    Returns:
        List of dicts with 'serial' key for each device
        
    Raises:
        InfNoiseError: If listing fails
    """
    try:
        result = subprocess.run(
            ["infnoise", "--list-devices"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        
        # Parse output - infnoise outputs "ID: N, Manufacturer: X, Description: Y, Serial: Z"
        devices = []
        output = result.stdout + result.stderr
        
        # Look for "Serial: XXXXX" pattern (handles serial like "1337-151562E9")
        serial_pattern = re.findall(r'Serial:\s*([A-Za-z0-9-]+)', output)
        if serial_pattern:
            for serial in serial_pattern:
                devices.append({"serial": serial})
        
        # If no serials found but command succeeded, device may be present
        if not devices and result.returncode == 0:
            devices.append({"serial": "unknown"})
        
        return devices
        
    except subprocess.TimeoutExpired:
        raise InfNoiseError(
            "infnoise --list-devices timed out"
        ) from None
    except FileNotFoundError:
        raise InfNoiseError(
            "infnoise command not found. Install from: "
            "https://github.com/leetronics/infnoise"
        ) from None


def check_infnoise_available() -> tuple[bool, Optional[str]]:
    """Check if Infinite Noise TRNG is available.
    
    Returns:
        Tuple of (is_available, error_message)
        If available, error_message is None
        If not available, error_message explains why
    """
    try:
        devices = list_infnoise_devices()
        if devices:
            return (True, None)
        else:
            return (False, "No Infinite Noise devices found. Is device connected?")
    except InfNoiseError as e:
        return (False, str(e))


def collect_infnoise_entropy(
    bits: int = 512,
    raw: bool = False,
    multiplier: int = 0,
) -> tuple[bytes, InfNoiseMetadata]:
    """Collect entropy from Infinite Noise TRNG.
    
    Uses the infnoise CLI to collect random bytes from the hardware TRNG.
    By default, output is whitened using Keccak-1600 for cryptographic quality.
    
    Args:
        bits: Number of bits to collect (must be multiple of 8)
        raw: If True, output raw bits without Keccak whitening
        multiplier: Output multiplier (0 = full entropy, >0 = stretched output)
        
    Returns:
        Tuple of (entropy_bytes, metadata)
        
    Raises:
        InfNoiseError: If collection fails
        ValueError: If bits is invalid
    """
    if bits % 8 != 0:
        raise ValueError(f"Bits must be multiple of 8, got {bits}")
    
    byte_count = bits // 8
    
    if byte_count == 0:
        raise ValueError("Must request at least 8 bits (1 byte)")
    
    # Check device availability first
    available, error = check_infnoise_available()
    if not available:
        raise InfNoiseError(error)
    
    # Get device serial for metadata
    try:
        devices = list_infnoise_devices()
        serial = devices[0]["serial"] if devices else "unknown"
    except InfNoiseError:
        serial = "unknown"
    
    try:
        # Build command
        # infnoise outputs to stdout continuously, we need to read exact bytes
        cmd = ["infnoise"]
        
        if raw:
            cmd.append("--raw")
        
        if multiplier > 0:
            cmd.extend(["--multiplier", str(multiplier)])
        
        # Run infnoise and read exactly byte_count bytes
        # Use head -c to limit output, or read from process directly
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        
        try:
            # Read exactly the bytes we need
            entropy_bytes = process.stdout.read(byte_count)
            
            # Terminate the process since we have what we need
            process.terminate()
            process.wait(timeout=5)
            
        except Exception as e:
            process.kill()
            raise InfNoiseError(f"Failed to read entropy: {e}") from e
        
        if len(entropy_bytes) != byte_count:
            raise InfNoiseError(
                f"Expected {byte_count} bytes, got {len(entropy_bytes)}. "
                "Device may have disconnected or failed health check."
            )
        
        # Create metadata
        metadata = InfNoiseMetadata(
            serial=serial,
            byte_count=byte_count,
            whitened=not raw,
            multiplier=multiplier,
        )
        
        return (entropy_bytes, metadata)
        
    except subprocess.TimeoutExpired:
        raise InfNoiseError(
            "infnoise timed out. Is device connected and working?"
        ) from None
    except FileNotFoundError:
        raise InfNoiseError(
            "infnoise command not found. Install from: "
            "https://github.com/leetronics/infnoise"
        ) from None


def estimate_collection_time(bits: int) -> tuple[int, float]:
    """Estimate time to collect entropy from Infinite Noise TRNG.
    
    The device outputs approximately 300,000 bits/second raw.
    With Keccak whitening, throughput is still very high.
    
    Args:
        bits: Number of bits to collect
        
    Returns:
        Tuple of (bits, estimated_seconds)
    """
    # ~300,000 bits/second = ~37,500 bytes/second
    # With overhead, estimate conservatively at 30,000 bytes/second
    bytes_needed = bits // 8
    seconds = bytes_needed / 30000.0
    
    # Minimum estimate is 0.1 seconds for device initialization
    seconds = max(0.1, seconds)
    
    return (bits, seconds)
