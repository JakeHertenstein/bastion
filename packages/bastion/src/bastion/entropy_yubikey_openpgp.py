"""YubiKey OpenPGP hardware RNG entropy collection.

This module collects entropy from YubiKey's hardware random number generator
via the OpenPGP applet using the SCD RANDOM command through gpg-connect-agent.

The YubiKey 5 series has OpenPGP 3.4+ support which includes direct access
to the hardware RNG. This provides true hardware randomness without requiring
HMAC-SHA1 challenge-response.

Reference: https://support.yubico.com/s/article/YubiKey-52-enhancements-to-OpenPGP-34-support
"""

import subprocess
import re
from typing import Optional
from dataclasses import dataclass


@dataclass
class YubiKeyOpenPGPMetadata:
    """Metadata about YubiKey OpenPGP RNG collection."""
    serial_number: str
    version: str
    manufacturer: str
    application_id: str
    byte_count: int
    collection_method: str = "gpg-connect-agent SCD RANDOM"
    
    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary for storage.
        
        Field names use Title Case for 1Password canonical form.
        """
        return {
            "Serial Number": self.serial_number,
            "Version": self.version,
            "Manufacturer": self.manufacturer,
            "Application ID": self.application_id,
            "Collection Method": self.collection_method,
        }


class YubiKeyOpenPGPError(Exception):
    """Raised when YubiKey OpenPGP operations fail."""
    pass


def get_yubikey_openpgp_info() -> dict[str, str]:
    """Get YubiKey OpenPGP card information.
    
    Returns:
        Dictionary with serial_number, version, manufacturer, application_id
        
    Raises:
        YubiKeyOpenPGPError: If card info cannot be retrieved
    """
    try:
        result = subprocess.run(
            ["gpg", "--card-status"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        
        output = result.stdout
        
        # Parse card status output
        info = {
            "serial_number": "",
            "version": "",
            "manufacturer": "",
            "application_id": "",
        }
        
        # Extract fields using regex
        serial_match = re.search(r'Serial number\s*\.+:\s*(\d+)', output)
        if serial_match:
            info["serial_number"] = serial_match.group(1)
        
        version_match = re.search(r'Version\s*\.+:\s*([\d.]+)', output)
        if version_match:
            info["version"] = version_match.group(1)
        
        manufacturer_match = re.search(r'Manufacturer\s*\.+:\s*(.+)', output)
        if manufacturer_match:
            info["manufacturer"] = manufacturer_match.group(1).strip()
        
        app_id_match = re.search(r'Application ID\s*\.+:\s*([A-F0-9]+)', output)
        if app_id_match:
            info["application_id"] = app_id_match.group(1)
        
        if not info["serial_number"]:
            raise YubiKeyOpenPGPError("Could not parse YubiKey serial number")
        
        return info
        
    except subprocess.CalledProcessError as e:
        raise YubiKeyOpenPGPError(
            f"Failed to get card status: {e.stderr}"
        ) from e
    except subprocess.TimeoutExpired:
        raise YubiKeyOpenPGPError(
            "gpg --card-status timed out. Is YubiKey inserted?"
        ) from None
    except FileNotFoundError:
        raise YubiKeyOpenPGPError(
            "gpg command not found. Install GnuPG."
        ) from None


def collect_yubikey_openpgp_entropy(
    bits: int = 512,
    require_touch: bool = False
) -> tuple[bytes, YubiKeyOpenPGPMetadata]:
    """Collect entropy from YubiKey hardware RNG via OpenPGP.
    
    Uses gpg-connect-agent with the SCD RANDOM command to extract random
    bytes directly from the YubiKey's hardware random number generator.
    
    The YubiKey 5 series has a hardware TRNG (True Random Number Generator)
    that provides high-quality randomness suitable for cryptographic use.
    
    Args:
        bits: Number of bits to collect (must be multiple of 8, max 65535 bytes)
        require_touch: If True, requires physical touch (not implemented in SCD RANDOM)
        
    Returns:
        Tuple of (entropy_bytes, metadata)
        
    Raises:
        YubiKeyOpenPGPError: If collection fails
        ValueError: If bits is invalid
    """
    if bits % 8 != 0:
        raise ValueError(f"Bits must be multiple of 8, got {bits}")
    
    byte_count = bits // 8
    
    if byte_count > 65535:
        raise ValueError(f"Maximum bytes is 65535, requested {byte_count}")
    
    if byte_count == 0:
        raise ValueError("Must request at least 8 bits (1 byte)")
    
    # Get YubiKey info first
    card_info = get_yubikey_openpgp_info()
    
    try:
        # Use gpg-connect-agent to get random bytes
        # Command format: "SCD RANDOM <byte_count>"
        result = subprocess.run(
            ["gpg-connect-agent", f"SCD RANDOM {byte_count}", "/bye"],
            capture_output=True,
            check=True,
            timeout=30,
        )
        
        # Parse output - format is "D <raw_bytes>\nOK\n"
        output = result.stdout
        
        # Find the data line starting with "D "
        # The format is: b'D <raw_bytes>\nOK\n'
        if not output.startswith(b'D '):
            raise YubiKeyOpenPGPError(
                "Unexpected output format from gpg-connect-agent"
            )
        
        # Extract data between "D " and "\nOK"
        # Split at newline to separate data from "OK"
        lines = output.split(b'\n')
        if len(lines) < 2 or lines[1] != b'OK':
            raise YubiKeyOpenPGPError(
                f"Unexpected output format: {output[:100]}"
            )
        
        # Data is everything after "D " prefix on first line
        data_line = lines[0]
        entropy_encoded = data_line[2:]  # Skip "D " prefix
        
        # Decode percent-encoding (gpg-connect-agent encodes some bytes)
        # Use urllib.parse.unquote_to_bytes for proper percent-decoding
        from urllib.parse import unquote_to_bytes
        entropy_bytes = unquote_to_bytes(entropy_encoded)
        
        if len(entropy_bytes) != byte_count:
            raise YubiKeyOpenPGPError(
                f"Expected {byte_count} bytes, got {len(entropy_bytes)}"
            )
        
        # Create metadata
        metadata = YubiKeyOpenPGPMetadata(
            serial_number=card_info["serial_number"],
            version=card_info["version"],
            manufacturer=card_info["manufacturer"],
            application_id=card_info["application_id"],
            byte_count=byte_count,
        )
        
        return (entropy_bytes, metadata)
        
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.decode('utf-8', errors='replace') if e.stderr else ""
        raise YubiKeyOpenPGPError(
            f"Failed to collect random data: {stderr}"
        ) from e
    except subprocess.TimeoutExpired:
        raise YubiKeyOpenPGPError(
            "gpg-connect-agent timed out. Is YubiKey inserted?"
        ) from None
    except FileNotFoundError:
        raise YubiKeyOpenPGPError(
            "gpg-connect-agent command not found. Install GnuPG."
        ) from None


def check_yubikey_openpgp_available() -> tuple[bool, Optional[str]]:
    """Check if YubiKey OpenPGP is available.
    
    Returns:
        Tuple of (is_available, error_message)
        If available, error_message is None
        If not available, error_message explains why
    """
    try:
        # Try to get card info
        get_yubikey_openpgp_info()
        return (True, None)
    except YubiKeyOpenPGPError as e:
        return (False, str(e))
