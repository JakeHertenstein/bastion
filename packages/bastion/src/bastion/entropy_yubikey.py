"""YubiKey entropy collection via HMAC-SHA1 challenge-response.

This module collects high-quality entropy from YubiKey's HMAC-SHA1
challenge-response function. The YubiKey's internal hardware RNG
generates the secret key used for HMAC computation, making outputs
cryptographically unpredictable even when challenges are known.

ENTROPY EXPLANATION:
- YubiKey's HMAC-SHA1 uses a secret key derived from hardware RNG
- Even with known challenges, responses are unpredictable without the key
- Each 20-byte HMAC-SHA1 response contains ~160 bits of entropy
- The secret key itself was generated with hardware-quality randomness
- Multiple challenge-response rounds provide additional entropy
"""

import secrets
import subprocess


class YubiKeyEntropyError(Exception):
    """Error during YubiKey entropy collection."""
    pass


def check_yubikey_available() -> bool:
    """Check if ykman is installed and YubiKey is accessible.
    
    Returns:
        True if YubiKey can be used for entropy collection
    """
    try:
        result = subprocess.run(
            ["ykman", "list"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        return bool(result.stdout.strip())
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False


def collect_yubikey_entropy(
    bits: int = 512,
    slot: int = 2,
) -> bytes:
    """Collect entropy from YubiKey HMAC-SHA1 challenge-response.
    
    The YubiKey's HMAC function uses a hardware-derived secret key that is
    never exposed. Each challenge produces a cryptographically secure 20-byte
    response based on this secret. Since the key is unknown, responses are
    indistinguishable from random data even when challenges are known.
    
    Entropy per response: ~160 bits (20 bytes of unpredictable output)
    
    Note: Touch requirement is configured when programming the slot, not per-use.
    Configure with: ykman otp chalresp --generate --touch <slot>
    
    Args:
        bits: Target entropy in bits (minimum 256)
        slot: YubiKey OTP slot (1 or 2, default 2)
        
    Returns:
        Concatenated HMAC-SHA1 responses (raw bytes)
        
    Raises:
        YubiKeyEntropyError: If YubiKey is unavailable or collection fails
        ValueError: If bits < 256 (minimum for cryptographic use)
    """
    if bits < 256:
        raise ValueError("Minimum 256 bits required for cryptographic entropy")
    
    if slot not in (1, 2):
        raise ValueError("Slot must be 1 or 2")
    
    # Check YubiKey availability
    if not check_yubikey_available():
        raise YubiKeyEntropyError(
            "YubiKey not found. Please insert YubiKey and ensure ykman is installed.\n"
            "Install: brew install ykman (macOS) or apt install yubikey-manager (Linux)"
        )
    
    # Calculate number of challenges needed
    # Each HMAC-SHA1 response is 20 bytes (160 bits)
    bytes_needed = (bits + 7) // 8  # Round up
    responses_needed = (bytes_needed + 19) // 20  # Round up
    
    responses: list[bytes] = []
    
    for i in range(responses_needed):
        # Generate random challenge (64 bytes for good mixing)
        challenge = secrets.token_bytes(64)
        challenge_hex = challenge.hex()
        
        # Build ykman command for challenge-response calculation
        cmd = ["ykman", "otp", "calculate", str(slot), challenge_hex]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            # Parse hex response
            response_hex = result.stdout.strip()
            response_bytes = bytes.fromhex(response_hex)
            
            if len(response_bytes) != 20:
                raise YubiKeyEntropyError(
                    f"Unexpected response length: {len(response_bytes)} bytes (expected 20)"
                )
            
            responses.append(response_bytes)
            
        except subprocess.TimeoutExpired as e:
            # Check if slot needs to be programmed
            stderr_bytes = e.stderr if e.stderr else b""
            stderr_str = stderr_bytes.decode() if isinstance(stderr_bytes, bytes) else str(stderr_bytes)
            if "Program a challenge-response credential" in stderr_str:
                raise YubiKeyEntropyError(
                    f"Slot {slot} is not configured for HMAC-SHA1 challenge-response.\n"
                    f"Configure it with: ykman otp chalresp --generate {slot}\n"
                    f"Or use a different slot: --slot 1 or --slot 2"
                ) from e
            else:
                raise YubiKeyEntropyError(
                    f"YubiKey operation timed out after 30 seconds.\n"
                    f"Stderr: {stderr_str}"
                ) from e
        except subprocess.CalledProcessError as e:
            raise YubiKeyEntropyError(
                f"YubiKey challenge-response failed: {e.stderr}"
            ) from e
        except ValueError as e:
            raise YubiKeyEntropyError(
                f"Failed to parse YubiKey response: {e}"
            ) from e
    
    # Concatenate all responses
    all_entropy = b''.join(responses)
    
    # Truncate to exact byte count needed
    return all_entropy[:bytes_needed]


def estimate_collection_time(bits: int) -> tuple[int, float]:
    """Estimate time to collect entropy from YubiKey.
    
    Args:
        bits: Target entropy in bits
        
    Returns:
        Tuple of (num_challenges, estimated_seconds)
    """
    bytes_needed = (bits + 7) // 8
    responses_needed = (bytes_needed + 19) // 20
    
    # Each challenge-response takes ~0.5 seconds
    estimated_seconds = responses_needed * 0.5
    
    return (responses_needed, estimated_seconds)
