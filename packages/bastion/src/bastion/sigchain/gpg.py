"""GPG signing support with mock mode for testing.

This module provides GPG signature creation and verification,
with a mock mode that can be used in tests or environments
where GPG is not available.

The mock mode produces deterministic signatures that can be
verified without actual GPG keys, useful for:
- Unit testing
- CI/CD environments
- Development without GPG setup
"""

from __future__ import annotations

import base64
import hashlib
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum


class SignatureStatus(str, Enum):
    """GPG signature verification status."""

    GOOD = "G"       # Good signature from trusted key
    BAD = "B"        # Bad signature
    UNKNOWN = "U"    # Good signature from unknown key
    EXPIRED = "X"    # Good signature from expired key
    EXPIRED_KEY = "Y"  # Good signature from expired key (key expired)
    REVOKED = "R"    # Good signature from revoked key
    NO_PUBKEY = "E"  # Cannot verify - no public key
    NONE = "N"       # No signature


@dataclass
class GPGSignature:
    """Represents a GPG signature with metadata."""

    signature: bytes
    key_id: str
    signer_name: str | None
    timestamp: datetime
    is_mock: bool = False

    def to_armor(self) -> str:
        """Convert signature to ASCII-armored format."""
        if self.is_mock:
            # Mock armor format
            b64 = base64.b64encode(self.signature).decode()
            return f"-----BEGIN MOCK GPG SIGNATURE-----\n{b64}\n-----END MOCK GPG SIGNATURE-----"
        return base64.b64encode(self.signature).decode()


@dataclass
class VerificationResult:
    """Result of signature verification."""

    valid: bool
    status: SignatureStatus
    key_id: str | None
    signer_name: str | None
    timestamp: datetime | None
    error: str | None = None


class GPGSigner:
    """GPG signing with mock support for testing.

    Example:
        # Real GPG signing
        signer = GPGSigner()
        sig = signer.sign(b"data to sign")

        # Mock mode for testing
        mock_signer = GPGSigner(mock=True)
        sig = mock_signer.sign(b"data to sign")
        result = mock_signer.verify(b"data to sign", sig.signature)
        assert result.valid
    """

    # Mock key ID for testing (looks like a real key ID)
    MOCK_KEY_ID = "MOCK4B4574F10N5"
    MOCK_SIGNER = "Bastion Test <test@bastion.local>"

    def __init__(
        self,
        mock: bool = False,
        key_id: str | None = None,
        gpg_path: str = "gpg",
    ) -> None:
        """Initialize GPG signer.

        Args:
            mock: If True, use mock signatures (no real GPG)
            key_id: GPG key ID to use for signing (None = default key)
            gpg_path: Path to gpg binary
        """
        self.mock = mock
        self.key_id = key_id
        self.gpg_path = gpg_path

        # Mock state for deterministic testing
        self._mock_key_id = self.MOCK_KEY_ID
        self._mock_signer = self.MOCK_SIGNER

    def is_available(self) -> bool:
        """Check if GPG is available.

        Returns:
            True if GPG binary is accessible
        """
        if self.mock:
            return True

        try:
            result = subprocess.run(
                [self.gpg_path, "--version"],
                capture_output=True,
                timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def get_default_key(self) -> str | None:
        """Get the default GPG signing key ID.

        Returns:
            Key ID or None if not found
        """
        if self.mock:
            return self._mock_key_id

        try:
            result = subprocess.run(
                [self.gpg_path, "--list-secret-keys", "--keyid-format", "long"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            # Parse output to find first key ID
            for line in result.stdout.split("\n"):
                if line.strip().startswith("sec"):
                    # Format: sec   rsa4096/KEYID 2024-01-01 [SC]
                    parts = line.split("/")
                    if len(parts) >= 2:
                        key_part = parts[1].split()[0]
                        return key_part
            return None
        except Exception:
            return None

    def sign(self, data: bytes) -> GPGSignature:
        """Sign data with GPG.

        Args:
            data: Data to sign

        Returns:
            GPGSignature object

        Raises:
            RuntimeError: If signing fails
        """
        timestamp = datetime.now(UTC)

        if self.mock:
            return self._mock_sign(data, timestamp)

        return self._real_sign(data, timestamp)

    def _mock_sign(self, data: bytes, timestamp: datetime) -> GPGSignature:
        """Create a mock signature for testing.

        The mock signature is deterministic and verifiable within
        the mock system, but not cryptographically secure.

        Args:
            data: Data to sign
            timestamp: Signing timestamp

        Returns:
            Mock GPGSignature
        """
        # Create deterministic mock signature
        # Format: MOCK_SIG|timestamp|sha256(data)|key_id
        # Using | as delimiter to avoid conflict with : in ISO timestamps
        data_hash = hashlib.sha256(data).hexdigest()
        ts_str = timestamp.isoformat()

        sig_content = f"MOCK_SIG|{ts_str}|{data_hash}|{self._mock_key_id}"
        signature = sig_content.encode()

        return GPGSignature(
            signature=signature,
            key_id=self._mock_key_id,
            signer_name=self._mock_signer,
            timestamp=timestamp,
            is_mock=True,
        )

    def _real_sign(self, data: bytes, timestamp: datetime) -> GPGSignature:
        """Create a real GPG signature.

        Args:
            data: Data to sign
            timestamp: Signing timestamp

        Returns:
            GPGSignature object

        Raises:
            RuntimeError: If GPG signing fails
        """
        cmd = [self.gpg_path, "--detach-sign", "--armor"]

        if self.key_id:
            cmd.extend(["--local-user", self.key_id])

        try:
            result = subprocess.run(
                cmd,
                input=data,
                capture_output=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise RuntimeError(f"GPG signing failed: {result.stderr.decode()}")

            # Parse key ID from signature
            key_id = self.key_id or self.get_default_key() or "unknown"

            return GPGSignature(
                signature=result.stdout,
                key_id=key_id,
                signer_name=None,  # Would need to look up
                timestamp=timestamp,
                is_mock=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("GPG signing timed out")
        except FileNotFoundError:
            raise RuntimeError(f"GPG not found at {self.gpg_path}")

    def verify(
        self,
        data: bytes,
        signature: bytes,
    ) -> VerificationResult:
        """Verify a GPG signature.

        Args:
            data: Original data that was signed
            signature: Signature to verify

        Returns:
            VerificationResult with status and details
        """
        if self.mock:
            return self._mock_verify(data, signature)

        return self._real_verify(data, signature)

    def _mock_verify(
        self,
        data: bytes,
        signature: bytes,
    ) -> VerificationResult:
        """Verify a mock signature.

        Args:
            data: Original data
            signature: Mock signature bytes

        Returns:
            VerificationResult
        """
        try:
            sig_str = signature.decode()

            if not sig_str.startswith("MOCK_SIG|"):
                return VerificationResult(
                    valid=False,
                    status=SignatureStatus.BAD,
                    key_id=None,
                    signer_name=None,
                    timestamp=None,
                    error="Not a mock signature",
                )

            # Parse mock signature (using | delimiter)
            parts = sig_str.split("|")
            if len(parts) != 4:
                return VerificationResult(
                    valid=False,
                    status=SignatureStatus.BAD,
                    key_id=None,
                    signer_name=None,
                    timestamp=None,
                    error="Invalid mock signature format",
                )

            _, ts_str, expected_hash, key_id = parts

            # Verify hash
            actual_hash = hashlib.sha256(data).hexdigest()
            if actual_hash != expected_hash:
                return VerificationResult(
                    valid=False,
                    status=SignatureStatus.BAD,
                    key_id=key_id,
                    signer_name=self._mock_signer,
                    timestamp=datetime.fromisoformat(ts_str),
                    error="Data hash mismatch",
                )

            return VerificationResult(
                valid=True,
                status=SignatureStatus.GOOD,
                key_id=key_id,
                signer_name=self._mock_signer,
                timestamp=datetime.fromisoformat(ts_str),
            )
        except Exception as e:
            return VerificationResult(
                valid=False,
                status=SignatureStatus.BAD,
                key_id=None,
                signer_name=None,
                timestamp=None,
                error=str(e),
            )

    def _real_verify(
        self,
        data: bytes,
        signature: bytes,
    ) -> VerificationResult:
        """Verify a real GPG signature.

        Args:
            data: Original data
            signature: GPG signature

        Returns:
            VerificationResult
        """
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmpdir:
            data_path = Path(tmpdir) / "data"
            sig_path = Path(tmpdir) / "data.sig"

            data_path.write_bytes(data)
            sig_path.write_bytes(signature)

            try:
                result = subprocess.run(
                    [
                        self.gpg_path,
                        "--verify",
                        "--status-fd", "1",
                        str(sig_path),
                        str(data_path),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                # Parse status output
                status = SignatureStatus.NONE
                key_id = None
                signer_name = None
                timestamp = None

                for line in result.stdout.split("\n"):
                    if "[GNUPG:] GOODSIG" in line:
                        status = SignatureStatus.GOOD
                        parts = line.split(" ", 3)
                        if len(parts) >= 3:
                            key_id = parts[2]
                        if len(parts) >= 4:
                            signer_name = parts[3]
                    elif "[GNUPG:] BADSIG" in line:
                        status = SignatureStatus.BAD
                    elif "[GNUPG:] ERRSIG" in line:
                        status = SignatureStatus.NO_PUBKEY
                    elif "[GNUPG:] EXPKEYSIG" in line:
                        status = SignatureStatus.EXPIRED_KEY
                    elif "[GNUPG:] REVKEYSIG" in line:
                        status = SignatureStatus.REVOKED
                    elif "[GNUPG:] SIG_CREATED" in line:
                        # Parse timestamp if available
                        pass

                return VerificationResult(
                    valid=status == SignatureStatus.GOOD,
                    status=status,
                    key_id=key_id,
                    signer_name=signer_name,
                    timestamp=timestamp,
                )
            except subprocess.TimeoutExpired:
                return VerificationResult(
                    valid=False,
                    status=SignatureStatus.NONE,
                    key_id=None,
                    signer_name=None,
                    timestamp=None,
                    error="Verification timed out",
                )
            except Exception as e:
                return VerificationResult(
                    valid=False,
                    status=SignatureStatus.NONE,
                    key_id=None,
                    signer_name=None,
                    timestamp=None,
                    error=str(e),
                )


def get_signer(mock: bool | None = None) -> GPGSigner:
    """Get appropriate GPG signer based on environment.

    Args:
        mock: Force mock mode (None = auto-detect)

    Returns:
        GPGSigner instance
    """
    if mock is not None:
        return GPGSigner(mock=mock)

    # Auto-detect: use mock if GPG not available
    signer = GPGSigner(mock=False)
    if not signer.is_available():
        return GPGSigner(mock=True)

    return signer


def gpg_import_public_key(key_data: bytes, gpg_path: str = "gpg") -> str:
    """Import a public key into the local keyring."""
    try:
        result = subprocess.run(
            [gpg_path, "--import", "--status-fd", "1"],
            input=key_data,
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError as exc:  # pragma: no cover - env dependent
        raise RuntimeError(f"GPG not found at {gpg_path}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("GPG import timed out") from exc

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


def gpg_decrypt(data: bytes, gpg_path: str = "gpg") -> bytes:
    """Decrypt data using the local private key."""
    try:
        result = subprocess.run(
            [gpg_path, "--decrypt"],
            input=data,
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError as exc:  # pragma: no cover - env dependent
        raise RuntimeError(f"GPG not found at {gpg_path}") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("GPG decryption timed out") from exc

    if result.returncode != 0:
        error = result.stderr.decode() if result.stderr else "Unknown error"
        raise RuntimeError(f"GPG decryption failed: {error}")

    return result.stdout
