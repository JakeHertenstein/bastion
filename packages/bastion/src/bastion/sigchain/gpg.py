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
from datetime import datetime, timezone
from enum import Enum
from typing import Any


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
        timestamp = datetime.now(timezone.utc)
        
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


@dataclass
class EncryptionResult:
    """Result of GPG encryption."""
    
    ciphertext: bytes
    recipient: str
    is_armored: bool
    is_mock: bool = False


@dataclass
class DecryptionResult:
    """Result of GPG decryption."""
    
    plaintext: bytes
    key_id: str | None
    is_mock: bool = False


class GPGEncryptor:
    """GPG encryption/decryption with mock support for testing.
    
    Designed for encrypting small payloads (salts, keys) for QR transfer
    between airgap and manager machines.
    
    Example:
        # Real GPG encryption
        encryptor = GPGEncryptor()
        result = encryptor.encrypt(b"secret salt", recipient="0x1234ABCD")
        
        # Decrypt (requires YubiKey touch if key is on card)
        decrypted = encryptor.decrypt(result.ciphertext)
        
        # Mock mode for testing
        mock = GPGEncryptor(mock=True)
        result = mock.encrypt(b"test", recipient="test@example.com")
        decrypted = mock.decrypt(result.ciphertext)
    """
    
    MOCK_RECIPIENT = "mock@bastion.local"
    
    def __init__(
        self,
        mock: bool = False,
        gpg_path: str = "gpg",
        timeout: int = 60,  # Longer timeout for YubiKey touch
    ) -> None:
        """Initialize GPG encryptor.
        
        Args:
            mock: If True, use mock encryption (no real GPG)
            gpg_path: Path to gpg binary
            timeout: Command timeout in seconds (default 60 for YubiKey)
        """
        self.mock = mock
        self.gpg_path = gpg_path
        self.timeout = timeout
        
        # Mock encryption key (deterministic for testing)
        self._mock_key = b"BASTION_MOCK_KEY_32_BYTES_LONG!!"
    
    def is_available(self) -> bool:
        """Check if GPG is available."""
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
    
    def list_keys(self, secret: bool = False) -> list[dict[str, Any]]:
        """List available GPG keys.
        
        Args:
            secret: If True, list secret keys; otherwise public keys
            
        Returns:
            List of key info dicts with 'keyid', 'uid', 'fingerprint'
        """
        if self.mock:
            return [{"keyid": "MOCK4B4574F10N5", "uid": self.MOCK_RECIPIENT, "fingerprint": "MOCK" * 10}]
        
        cmd = [self.gpg_path, "--list-keys" if not secret else "--list-secret-keys", 
               "--keyid-format", "long", "--with-colons"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return []
            
            keys = []
            current_key: dict[str, Any] = {}
            
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
        except Exception:
            return []
    
    def encrypt(
        self,
        data: bytes,
        recipient: str,
        armor: bool = True,
        sign: bool = False,
    ) -> EncryptionResult:
        """Encrypt data to a GPG recipient.
        
        Args:
            data: Data to encrypt
            recipient: Key ID, email, or fingerprint
            armor: If True, output ASCII armor (for QR codes)
            sign: If True, also sign the message
            
        Returns:
            EncryptionResult with ciphertext
            
        Raises:
            RuntimeError: If encryption fails
        """
        if self.mock:
            return self._mock_encrypt(data, recipient, armor)
        
        return self._real_encrypt(data, recipient, armor, sign)
    
    def _mock_encrypt(
        self,
        data: bytes,
        recipient: str,
        armor: bool,
    ) -> EncryptionResult:
        """Create mock encrypted message for testing.
        
        Uses simple XOR + base64 that can be "decrypted" in mock mode.
        """
        # XOR with repeating key
        key_repeated = (self._mock_key * ((len(data) // len(self._mock_key)) + 1))[:len(data)]
        encrypted = bytes(a ^ b for a, b in zip(data, key_repeated))
        
        # Add header for identification
        payload = b"MOCK_GPG:" + recipient.encode() + b":" + encrypted
        
        if armor:
            b64 = base64.b64encode(payload).decode()
            armored = f"-----BEGIN PGP MESSAGE-----\nMock-Recipient: {recipient}\n\n{b64}\n-----END PGP MESSAGE-----"
            ciphertext = armored.encode()
        else:
            ciphertext = payload
        
        return EncryptionResult(
            ciphertext=ciphertext,
            recipient=recipient,
            is_armored=armor,
            is_mock=True,
        )
    
    def _real_encrypt(
        self,
        data: bytes,
        recipient: str,
        armor: bool,
        sign: bool,
    ) -> EncryptionResult:
        """Encrypt with real GPG."""
        cmd = [self.gpg_path, "--encrypt", "--recipient", recipient, "--trust-model", "always"]
        
        if armor:
            cmd.append("--armor")
        if sign:
            cmd.append("--sign")
        
        try:
            result = subprocess.run(
                cmd,
                input=data,
                capture_output=True,
                timeout=self.timeout,
            )
            
            if result.returncode != 0:
                error = result.stderr.decode() if result.stderr else "Unknown error"
                raise RuntimeError(f"GPG encryption failed: {error}")
            
            return EncryptionResult(
                ciphertext=result.stdout,
                recipient=recipient,
                is_armored=armor,
                is_mock=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"GPG encryption timed out after {self.timeout}s")
        except FileNotFoundError:
            raise RuntimeError(f"GPG not found at {self.gpg_path}")
    
    def decrypt(self, data: bytes) -> DecryptionResult:
        """Decrypt GPG-encrypted data.
        
        May trigger YubiKey touch if decryption key is on card.
        
        Args:
            data: Encrypted data (armor or binary)
            
        Returns:
            DecryptionResult with plaintext
            
        Raises:
            RuntimeError: If decryption fails
        """
        if self.mock:
            return self._mock_decrypt(data)
        
        return self._real_decrypt(data)
    
    def _mock_decrypt(self, data: bytes) -> DecryptionResult:
        """Decrypt mock encrypted message."""
        try:
            # Handle armored format
            data_str = data.decode() if isinstance(data, bytes) else data
            
            if "-----BEGIN PGP MESSAGE-----" in data_str:
                # Extract base64 payload
                lines = data_str.split("\n")
                b64_lines = []
                in_body = False
                for line in lines:
                    if line.startswith("-----END"):
                        break
                    if in_body and line.strip():
                        b64_lines.append(line.strip())
                    if line == "" and not in_body:
                        in_body = True
                
                payload = base64.b64decode("".join(b64_lines))
            else:
                payload = data
            
            # Parse mock format
            if not payload.startswith(b"MOCK_GPG:"):
                raise RuntimeError("Not a mock-encrypted message")
            
            parts = payload.split(b":", 2)
            if len(parts) != 3:
                raise RuntimeError("Invalid mock message format")
            
            recipient = parts[1].decode()
            encrypted = parts[2]
            
            # XOR decrypt
            key_repeated = (self._mock_key * ((len(encrypted) // len(self._mock_key)) + 1))[:len(encrypted)]
            plaintext = bytes(a ^ b for a, b in zip(encrypted, key_repeated))
            
            return DecryptionResult(
                plaintext=plaintext,
                key_id=f"MOCK:{recipient}",
                is_mock=True,
            )
        except Exception as e:
            raise RuntimeError(f"Mock decryption failed: {e}")
    
    def _real_decrypt(self, data: bytes) -> DecryptionResult:
        """Decrypt with real GPG (may require YubiKey touch)."""
        cmd = [self.gpg_path, "--decrypt", "--status-fd", "2"]
        
        try:
            result = subprocess.run(
                cmd,
                input=data,
                capture_output=True,
                timeout=self.timeout,
            )
            
            if result.returncode != 0:
                error = result.stderr.decode() if result.stderr else "Unknown error"
                # Check for common errors
                if "No secret key" in error:
                    raise RuntimeError("No secret key available for decryption. Is YubiKey connected?")
                if "Bad passphrase" in error or "PIN" in error:
                    raise RuntimeError("Incorrect PIN or passphrase")
                raise RuntimeError(f"GPG decryption failed: {error}")
            
            # Parse key ID from status output
            key_id = None
            stderr_str = result.stderr.decode() if result.stderr else ""
            for line in stderr_str.split("\n"):
                if "[GNUPG:] ENC_TO" in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        key_id = parts[2]
                        break
            
            return DecryptionResult(
                plaintext=result.stdout,
                key_id=key_id,
                is_mock=False,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(
                f"GPG decryption timed out after {self.timeout}s. "
                "If using YubiKey, ensure you touched it when prompted."
            )
        except FileNotFoundError:
            raise RuntimeError(f"GPG not found at {self.gpg_path}")
    
    def import_key(self, key_data: bytes) -> str:
        """Import a GPG public key.
        
        Args:
            key_data: ASCII-armored or binary key data
            
        Returns:
            Key ID of imported key
            
        Raises:
            RuntimeError: If import fails
        """
        if self.mock:
            return "MOCK4B4574F10N5"
        
        cmd = [self.gpg_path, "--import", "--status-fd", "1"]
        
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
        except subprocess.TimeoutExpired:
            raise RuntimeError("Key import timed out")
        except FileNotFoundError:
            raise RuntimeError(f"GPG not found at {self.gpg_path}")
    
    def export_public_key(self, key_id: str, armor: bool = True) -> bytes:
        """Export a GPG public key.
        
        Args:
            key_id: Key ID, email, or fingerprint
            armor: If True, output ASCII armor
            
        Returns:
            Public key data
            
        Raises:
            RuntimeError: If export fails
        """
        if self.mock:
            mock_key = f"-----BEGIN PGP PUBLIC KEY BLOCK-----\nMock-Key-ID: {key_id}\n\nmock_key_data_base64\n-----END PGP PUBLIC KEY BLOCK-----"
            return mock_key.encode()
        
        cmd = [self.gpg_path, "--export", key_id]
        if armor:
            cmd.append("--armor")
        
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=10)
            
            if result.returncode != 0 or not result.stdout:
                error = result.stderr.decode() if result.stderr else "Key not found"
                raise RuntimeError(f"Key export failed: {error}")
            
            return result.stdout
        except subprocess.TimeoutExpired:
            raise RuntimeError("Key export timed out")
        except FileNotFoundError:
            raise RuntimeError(f"GPG not found at {self.gpg_path}")


def get_encryptor(mock: bool | None = None) -> GPGEncryptor:
    """Get appropriate GPG encryptor based on environment.
    
    Args:
        mock: Force mock mode (None = auto-detect)
        
    Returns:
        GPGEncryptor instance
    """
    if mock is not None:
        return GPGEncryptor(mock=mock)
    
    # Auto-detect: use mock if GPG not available
    encryptor = GPGEncryptor(mock=False)
    if not encryptor.is_available():
        return GPGEncryptor(mock=True)
    
    return encryptor
