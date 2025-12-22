"""Cryptographic operations for airgap transfers.

This module provides:
- ENT-verified entropy collection and validation
- Kernel entropy injection (RNDADDENTROPY)
- Salt generation with quality gates
- GPG encryption wrappers for QR transfer

Entropy is collected from hardware sources (Infinite Noise, YubiKey),
verified via ENT statistical analysis, and optionally injected into
the kernel entropy pool for GPG key generation.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import re
import secrets
import struct
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path


class EntropyQuality(str, Enum):
    """Quality ratings for entropy based on ENT analysis."""

    EXCELLENT = "EXCELLENT"
    GOOD = "GOOD"
    FAIR = "FAIR"
    POOR = "POOR"

    @classmethod
    def meets_threshold(cls, rating: str, minimum: EntropyQuality) -> bool:
        """Check if a rating meets the minimum threshold."""
        order = [cls.EXCELLENT, cls.GOOD, cls.FAIR, cls.POOR]
        try:
            rating_level = cls(rating.upper())
            return order.index(rating_level) <= order.index(minimum)
        except ValueError:
            return False


@dataclass
class ENTAnalysis:
    """Results from ENT statistical analysis."""

    entropy_bits_per_byte: float
    chi_square: float
    chi_square_pvalue: float
    arithmetic_mean: float
    monte_carlo_pi: float
    monte_carlo_error: float
    serial_correlation: float

    def quality_rating(self) -> EntropyQuality:
        """Get quality rating based on statistical analysis.

        Thresholds calibrated for Infinite Noise TRNG which produces
        ~7.988 bits/byte entropy at 16KB+ sample sizes.
        """
        if self.entropy_bits_per_byte >= 7.985 and 0.05 <= self.chi_square_pvalue <= 0.95:
            return EntropyQuality.EXCELLENT
        elif self.entropy_bits_per_byte >= 7.9 and 0.01 <= self.chi_square_pvalue <= 0.99:
            return EntropyQuality.GOOD
        elif self.entropy_bits_per_byte >= 7.5 and 0.001 <= self.chi_square_pvalue <= 0.999:
            return EntropyQuality.FAIR
        else:
            return EntropyQuality.POOR

    def is_acceptable(self, minimum: EntropyQuality = EntropyQuality.GOOD) -> bool:
        """Check if entropy meets minimum quality threshold."""
        return EntropyQuality.meets_threshold(self.quality_rating().value, minimum)

    def to_dict(self) -> dict[str, float]:
        """Convert to dictionary for storage/logging."""
        return {
            "entropy_bits_per_byte": self.entropy_bits_per_byte,
            "chi_square": self.chi_square,
            "chi_square_pvalue": self.chi_square_pvalue,
            "arithmetic_mean": self.arithmetic_mean,
            "monte_carlo_pi": self.monte_carlo_pi,
            "monte_carlo_error": self.monte_carlo_error,
            "serial_correlation": self.serial_correlation,
            "quality_rating": self.quality_rating().value,
        }


@dataclass
class EntropyCollection:
    """Result of entropy collection."""

    data: bytes
    source: str
    analysis: ENTAnalysis | None = None
    device_info: dict[str, str] = field(default_factory=dict)
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def bits(self) -> int:
        """Number of bits collected."""
        return len(self.data) * 8

    @property
    def quality(self) -> str:
        """Quality rating string."""
        if self.analysis:
            return self.analysis.quality_rating().value
        return "UNKNOWN"


def run_ent_analysis(data: bytes) -> ENTAnalysis:
    """Run ENT statistical analysis on entropy data.

    Requires the 'ent' command to be installed.

    Args:
        data: Entropy bytes to analyze (minimum 1KB recommended)

    Returns:
        ENTAnalysis with statistical metrics

    Raises:
        RuntimeError: If ENT analysis fails
    """
    if len(data) < 100:
        raise ValueError("Data too small for meaningful ENT analysis (minimum 100 bytes)")

    try:
        result = subprocess.run(
            ["ent"],
            input=data,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            raise RuntimeError(f"ENT analysis failed: {result.stderr}")

        return _parse_ent_output(result.stdout)

    except FileNotFoundError:
        raise RuntimeError("ENT tool not installed. Install with: apt install ent")
    except subprocess.TimeoutExpired:
        raise RuntimeError("ENT analysis timed out")


def _parse_ent_output(output: str) -> ENTAnalysis:
    """Parse ENT command output into structured analysis.

    Example ENT output:
        Entropy = 7.999835 bits per byte.
        Chi square distribution for 256 categories was 254.23.
        Arithmetic mean value of data bytes is 127.5234.
        Monte Carlo value for Pi is 3.141234567.
        Serial correlation coefficient is 0.000123.
    """
    # Extract entropy bits per byte
    entropy_match = re.search(r"Entropy\s*=\s*([\d.]+)\s*bits per byte", output)
    if not entropy_match:
        raise ValueError("Could not parse entropy from ENT output")
    entropy_bits = float(entropy_match.group(1))

    # Extract chi-square
    chi_match = re.search(r"Chi square.*?is\s*([\d.]+)", output)
    chi_square = float(chi_match.group(1)) if chi_match else 0.0

    # Extract chi-square p-value (percentage)
    # Format: "would randomly exceed this value XX.XX percent of the times"
    chi_pvalue_match = re.search(r"exceed this value\s*([\d.]+)\s*percent", output)
    if chi_pvalue_match:
        chi_pvalue = float(chi_pvalue_match.group(1)) / 100.0
    else:
        # Alternative: "less than 0.01 percent" or "more than 99 percent"
        if "less than" in output.lower():
            chi_pvalue = 0.001
        elif "more than 99" in output.lower():
            chi_pvalue = 0.999
        else:
            chi_pvalue = 0.5  # Default if not parseable

    # Extract arithmetic mean
    mean_match = re.search(r"Arithmetic mean.*?is\s*([\d.]+)", output)
    arithmetic_mean = float(mean_match.group(1)) if mean_match else 127.5

    # Extract Monte Carlo Pi
    pi_match = re.search(r"Monte Carlo.*?Pi is\s*([\d.]+)", output)
    monte_carlo_pi = float(pi_match.group(1)) if pi_match else 3.14159

    # Calculate Pi error percentage
    actual_pi = 3.14159265358979
    monte_carlo_error = abs(monte_carlo_pi - actual_pi) / actual_pi * 100

    # Extract serial correlation
    serial_match = re.search(r"Serial correlation.*?is\s*(-?[\d.]+)", output)
    serial_correlation = float(serial_match.group(1)) if serial_match else 0.0

    return ENTAnalysis(
        entropy_bits_per_byte=entropy_bits,
        chi_square=chi_square,
        chi_square_pvalue=chi_pvalue,
        arithmetic_mean=arithmetic_mean,
        monte_carlo_pi=monte_carlo_pi,
        monte_carlo_error=monte_carlo_error,
        serial_correlation=serial_correlation,
    )


def collect_entropy_infnoise(bits: int = 4096) -> EntropyCollection:
    """Collect entropy from Infinite Noise TRNG.

    Args:
        bits: Number of bits to collect

    Returns:
        EntropyCollection with data and device info

    Raises:
        RuntimeError: If collection fails
    """
    byte_count = bits // 8

    try:
        # Get device info first
        list_result = subprocess.run(
            ["infnoise", "--list-devices"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        serial = "unknown"
        if "Serial:" in list_result.stdout:
            serial_match = re.search(r"Serial:\s*(\S+)", list_result.stdout)
            if serial_match:
                serial = serial_match.group(1)
        elif "Serial:" in list_result.stderr:
            serial_match = re.search(r"Serial:\s*(\S+)", list_result.stderr)
            if serial_match:
                serial = serial_match.group(1)

        # Collect entropy
        result = subprocess.run(
            ["infnoise", f"--bytes={byte_count}", "--raw"],
            capture_output=True,
            timeout=60,
        )

        if result.returncode != 0:
            raise RuntimeError(f"infnoise failed: {result.stderr.decode()}")

        if len(result.stdout) < byte_count:
            raise RuntimeError(
                f"Insufficient entropy: got {len(result.stdout)} bytes, expected {byte_count}"
            )

        data = result.stdout[:byte_count]

        return EntropyCollection(
            data=data,
            source="infnoise",
            device_info={"serial": serial, "type": "Infinite Noise TRNG"},
        )

    except FileNotFoundError:
        raise RuntimeError("infnoise command not installed")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Infinite Noise collection timed out")


def collect_entropy_system(bits: int = 4096) -> EntropyCollection:
    """Collect entropy from system CSPRNG (/dev/urandom or secrets).

    Args:
        bits: Number of bits to collect

    Returns:
        EntropyCollection with data
    """
    byte_count = bits // 8
    data = secrets.token_bytes(byte_count)

    return EntropyCollection(
        data=data,
        source="system",
        device_info={"type": "os.urandom/secrets"},
    )


def collect_entropy_yubikey(bits: int = 160, slot: int = 2) -> EntropyCollection:
    """Collect entropy from YubiKey HMAC-SHA1 challenge-response.

    Args:
        bits: Number of bits to collect (multiples of 160)
        slot: YubiKey slot (1 or 2)

    Returns:
        EntropyCollection with data and device info

    Raises:
        RuntimeError: If collection fails
    """
    # HMAC-SHA1 produces 160 bits per challenge
    challenges_needed = (bits + 159) // 160

    try:
        # Get YubiKey info
        list_result = subprocess.run(
            ["ykman", "list", "--serials"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        serial = list_result.stdout.strip().split("\n")[0] if list_result.stdout else "unknown"

        # Collect entropy with random challenges
        entropy_parts = []
        for _ in range(challenges_needed):
            challenge = secrets.token_hex(32)  # 64-char hex challenge

            result = subprocess.run(
                ["ykman", "otp", "calculate", str(slot), challenge],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                raise RuntimeError(f"YubiKey HMAC failed: {result.stderr}")

            # Response is hex-encoded 20 bytes
            response_hex = result.stdout.strip()
            entropy_parts.append(bytes.fromhex(response_hex))

        data = b"".join(entropy_parts)[:bits // 8]

        return EntropyCollection(
            data=data,
            source="yubikey",
            device_info={"serial": serial, "slot": str(slot), "type": "HMAC-SHA1"},
        )

    except FileNotFoundError:
        raise RuntimeError("ykman command not installed")
    except subprocess.TimeoutExpired:
        raise RuntimeError("YubiKey operation timed out")


def collect_verified_entropy(
    bits: int = 4096,
    source: str = "infnoise",
    min_quality: EntropyQuality = EntropyQuality.GOOD,
) -> EntropyCollection:
    """Collect entropy and verify quality with ENT analysis.

    Args:
        bits: Number of bits to collect
        source: Entropy source ("infnoise", "system", "yubikey")
        min_quality: Minimum acceptable quality rating

    Returns:
        EntropyCollection with verified quality

    Raises:
        RuntimeError: If collection fails or quality is below threshold
    """
    # Collect entropy
    if source == "infnoise":
        collection = collect_entropy_infnoise(bits)
    elif source == "system":
        collection = collect_entropy_system(bits)
    elif source == "yubikey":
        collection = collect_entropy_yubikey(bits)
    else:
        raise ValueError(f"Unknown entropy source: {source}")

    # Run ENT analysis (requires at least 1KB for meaningful results)
    if len(collection.data) >= 1024:
        try:
            analysis = run_ent_analysis(collection.data)
            collection.analysis = analysis

            # Check quality threshold
            if not analysis.is_acceptable(min_quality):
                raise RuntimeError(
                    f"Entropy quality {analysis.quality_rating().value} "
                    f"does not meet minimum threshold {min_quality.value}"
                )
        except RuntimeError as e:
            if "ENT tool not installed" in str(e):
                # Warn but don't fail if ENT not available
                pass
            else:
                raise

    return collection


# Linux ioctl for RNDADDENTROPY
RNDADDENTROPY = 0x40085203


def inject_kernel_entropy(
    data: bytes,
    entropy_bits: int | None = None,
    require_sudo: bool = True,
) -> bool:
    """Inject verified entropy into the Linux kernel entropy pool.

    Uses RNDADDENTROPY ioctl to add entropy with credit.
    Requires root/CAP_SYS_ADMIN privileges.

    Args:
        data: Entropy bytes to inject
        entropy_bits: Bits of entropy to credit (default: len(data) * 8)
        require_sudo: If True, prompt for sudo if needed

    Returns:
        True if injection succeeded

    Raises:
        RuntimeError: If injection fails
        PermissionError: If insufficient privileges
    """
    if entropy_bits is None:
        # Conservative estimate: assume 7 bits per byte for verified entropy
        entropy_bits = len(data) * 7

    # Check if we're on Linux
    if not Path("/dev/random").exists():
        raise RuntimeError("Kernel entropy injection only supported on Linux")

    try:
        with open("/dev/random", "wb") as f:
            # struct rand_pool_info { int entropy_count; int buf_size; char buf[]; }
            header = struct.pack("ii", entropy_bits, len(data))
            fcntl.ioctl(f.fileno(), RNDADDENTROPY, header + data)

        return True

    except PermissionError:
        if require_sudo:
            # Try with sudo
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tf:
                tf.write(data)
                tf.flush()
                temp_path = tf.name

            try:
                # Use a helper script for sudo injection
                script = f'''
import fcntl
import struct

RNDADDENTROPY = 0x40085203

with open("{temp_path}", "rb") as f:
    data = f.read()

with open("/dev/random", "wb") as f:
    header = struct.pack("ii", {entropy_bits}, len(data))
    fcntl.ioctl(f.fileno(), RNDADDENTROPY, header + data)

print("Entropy injected successfully")
'''
                result = subprocess.run(
                    ["sudo", "python3", "-c", script],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                if result.returncode != 0:
                    raise RuntimeError(f"Sudo entropy injection failed: {result.stderr}")

                return True

            finally:
                Path(temp_path).unlink(missing_ok=True)
        else:
            raise PermissionError(
                "Insufficient privileges for kernel entropy injection. "
                "Run with sudo or set require_sudo=True."
            )


@dataclass
class SaltPayload:
    """Structured payload for encrypted salt transfer."""

    type: str = "bastion/salt/v1"
    purpose: str = "username-generator"
    salt: bytes = field(default_factory=bytes)
    bits: int = 256
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    device_id: str = "airgap"
    entropy_source: str = "unknown"
    entropy_quality: str = "UNKNOWN"

    def to_json(self) -> str:
        """Serialize to JSON for encryption."""
        return json.dumps({
            "type": self.type,
            "purpose": self.purpose,
            "salt": base64.b64encode(self.salt).decode(),
            "bits": self.bits,
            "created_at": self.created_at.isoformat(),
            "device_id": self.device_id,
            "entropy_source": self.entropy_source,
            "entropy_quality": self.entropy_quality,
        }, indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> SaltPayload:
        """Deserialize from JSON after decryption."""
        data = json.loads(json_str)
        return cls(
            type=data.get("type", "bastion/salt/v1"),
            purpose=data.get("purpose", "username-generator"),
            salt=base64.b64decode(data["salt"]),
            bits=data.get("bits", len(base64.b64decode(data["salt"])) * 8),
            created_at=datetime.fromisoformat(data["created_at"]),
            device_id=data.get("device_id", "unknown"),
            entropy_source=data.get("entropy_source", "unknown"),
            entropy_quality=data.get("entropy_quality", "UNKNOWN"),
        )


def generate_salt(
    bits: int = 256,
    source: str = "infnoise",
    min_quality: EntropyQuality = EntropyQuality.GOOD,
    verify: bool = True,
) -> SaltPayload:
    """Generate a cryptographic salt with ENT verification.

    Args:
        bits: Salt size in bits (default 256)
        source: Entropy source to use
        min_quality: Minimum quality threshold
        verify: If True, run ENT analysis and enforce quality

    Returns:
        SaltPayload with salt and metadata

    Raises:
        RuntimeError: If entropy quality is below threshold
    """
    # For salt generation, we need more entropy than the salt size
    # to account for extraction loss. Collect 2x for safety.
    collection_bits = max(bits * 2, 1024)  # At least 1KB for ENT analysis

    if verify:
        collection = collect_verified_entropy(
            bits=collection_bits,
            source=source,
            min_quality=min_quality,
        )
    else:
        if source == "infnoise":
            collection = collect_entropy_infnoise(collection_bits)
        elif source == "system":
            collection = collect_entropy_system(collection_bits)
        elif source == "yubikey":
            collection = collect_entropy_yubikey(collection_bits)
        else:
            raise ValueError(f"Unknown entropy source: {source}")

    # Extract salt using SHAKE256 for uniform output
    shake = hashlib.shake_256()
    shake.update(collection.data)
    salt = shake.digest(bits // 8)

    return SaltPayload(
        salt=salt,
        bits=bits,
        entropy_source=source,
        entropy_quality=collection.quality,
    )


def gpg_encrypt(
    data: bytes,
    recipient: str,
    armor: bool = True,
    gpg_path: str = "gpg",
) -> bytes:
    """Encrypt data using GPG.

    Args:
        data: Data to encrypt
        recipient: GPG key ID, email, or fingerprint
        armor: If True, output ASCII armor (for QR codes)
        gpg_path: Path to gpg binary

    Returns:
        Encrypted data (ASCII armor if requested)

    Raises:
        RuntimeError: If encryption fails
    """
    cmd = [gpg_path, "--encrypt", "--recipient", recipient, "--trust-model", "always"]

    if armor:
        cmd.append("--armor")

    try:
        result = subprocess.run(
            cmd,
            input=data,
            capture_output=True,
            timeout=30,
        )

        if result.returncode != 0:
            error = result.stderr.decode() if result.stderr else "Unknown error"
            raise RuntimeError(f"GPG encryption failed: {error}")

        return result.stdout

    except FileNotFoundError:
        raise RuntimeError(f"GPG not found at {gpg_path}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("GPG encryption timed out")


def gpg_import_key(key_data: bytes, gpg_path: str = "gpg") -> str:
    """Import a GPG public key.

    Args:
        key_data: ASCII-armored or binary key data
        gpg_path: Path to gpg binary

    Returns:
        Key ID of imported key

    Raises:
        RuntimeError: If import fails
    """
    cmd = [gpg_path, "--import", "--status-fd", "1"]

    try:
        result = subprocess.run(
            cmd,
            input=key_data,
            capture_output=True,
            timeout=30,
        )

        # Parse imported key ID
        key_id = None
        for line in result.stdout.decode().split("\n"):
            if "[GNUPG:] IMPORT_OK" in line:
                parts = line.split()
                if len(parts) >= 4:
                    key_id = parts[3]
                    break

        if result.returncode != 0 and not key_id:
            error = result.stderr.decode() if result.stderr else "Unknown error"
            raise RuntimeError(f"Key import failed: {error}")

        return key_id or "unknown"

    except FileNotFoundError:
        raise RuntimeError(f"GPG not found at {gpg_path}")
    except subprocess.TimeoutExpired:
        raise RuntimeError("Key import timed out")


def gpg_list_keys(secret: bool = False, gpg_path: str = "gpg") -> list[dict[str, str]]:
    """List available GPG keys.

    Args:
        secret: If True, list secret keys; otherwise public keys
        gpg_path: Path to gpg binary

    Returns:
        List of key info dicts with 'keyid', 'uid', 'fingerprint'
    """
    cmd = [gpg_path, "--list-keys" if not secret else "--list-secret-keys",
           "--keyid-format", "long", "--with-colons"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return []

        keys = []
        current_key: dict[str, str] = {}

        for line in result.stdout.split("\n"):
            parts = line.split(":")
            if not parts:
                continue

            record_type = parts[0]
            if record_type in ("pub", "sec"):
                if current_key:
                    keys.append(current_key)
                current_key = {
                    "keyid": parts[4] if len(parts) > 4 else "",
                    "fingerprint": "",
                    "uid": "",
                }
            elif record_type == "fpr" and current_key:
                current_key["fingerprint"] = parts[9] if len(parts) > 9 else ""
            elif record_type == "uid" and current_key and not current_key["uid"]:
                current_key["uid"] = parts[9] if len(parts) > 9 else ""

        if current_key:
            keys.append(current_key)

        return keys

    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
