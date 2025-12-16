"""Database I/O with atomic writes, backups, and optional encryption."""

import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .models import Database, Metadata
from .config import (
    BASTION_CACHE_DIR,
    BASTION_BACKUP_DIR,
    ENCRYPTED_DB_PATH,
    BASTION_KEY_ITEM_NAME,
    BASTION_KEY_VAULT,
    LEGACY_ENCRYPTED_DB,
    ensure_cache_infrastructure,
)


class EncryptionError(Exception):
    """Raised when encryption/decryption fails."""
    pass


def _get_fernet():
    """Lazy import Fernet to avoid startup overhead if not needed."""
    try:
        from cryptography.fernet import Fernet
        return Fernet
    except ImportError:
        raise ImportError(
            "cryptography package required for encrypted cache. "
            "Install with: pip install cryptography"
        )


class BastionCacheManager:
    """Manage encrypted Bastion cache stored in ~/.bastion/cache/."""
    
    def __init__(self):
        """Initialize the Bastion cache manager."""
        self.cache_dir = BASTION_CACHE_DIR
        self.cache_path = ENCRYPTED_DB_PATH
        self.backup_dir = BASTION_BACKUP_DIR
        self._encryption_key: bytes | None = None
    
    def ensure_infrastructure(self) -> None:
        """Create ~/.bastion directory structure if needed."""
        ensure_cache_infrastructure()
    
    def _get_encryption_key(self) -> bytes:
        """Fetch encryption key from 1Password.
        
        Returns:
            Fernet-compatible encryption key (32 bytes, base64 encoded)
            
        Raises:
            EncryptionError: If key cannot be retrieved
        """
        if self._encryption_key:
            return self._encryption_key
        
        try:
            # Try to get existing key from 1Password
            result = subprocess.run(
                ["op", "item", "get", BASTION_KEY_ITEM_NAME, 
                 "--vault", BASTION_KEY_VAULT, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
            item = json.loads(result.stdout)
            
            # Find the encryption_key field
            for field in item.get("fields", []):
                if field.get("label") == "encryption_key":
                    key_b64 = field.get("value")
                    if key_b64:
                        self._encryption_key = key_b64.encode()
                        return self._encryption_key
            
            raise EncryptionError(f"Field 'encryption_key' not found in {BASTION_KEY_ITEM_NAME}")
            
        except subprocess.CalledProcessError:
            raise EncryptionError(
                f"Bastion cache key not found in 1Password. "
                f"Run 'bastion migrate from-sat' to create it, or create a Secure Note "
                f"named '{BASTION_KEY_ITEM_NAME}' in {BASTION_KEY_VAULT} vault with an "
                f"'encryption_key' field containing a Fernet key."
            )
    
    def create_encryption_key(self) -> str:
        """Generate a new Fernet encryption key and store in 1Password.
        
        Returns:
            The base64-encoded key that was created
            
        Raises:
            EncryptionError: If key cannot be created/stored
        """
        Fernet = _get_fernet()
        
        # Generate new Fernet key
        key = Fernet.generate_key().decode()
        
        try:
            # Create Secure Note in 1Password with the key
            # Use JSON template for creating the item
            item_template = {
                "title": BASTION_KEY_ITEM_NAME,
                "category": "SECURE_NOTE",
                "vault": {"name": BASTION_KEY_VAULT},
                "fields": [
                    {
                        "id": "encryption_key",
                        "type": "CONCEALED",
                        "label": "encryption_key",
                        "value": key,
                    },
                    {
                        "id": "created",
                        "type": "STRING",
                        "label": "created",
                        "value": datetime.now(timezone.utc).isoformat(),
                    },
                    {
                        "id": "purpose",
                        "type": "STRING", 
                        "label": "purpose",
                        "value": "Encrypts ~/.bastion/cache/db.enc local cache file",
                    },
                ],
                "tags": ["Bastion/System/Cache-Key"],
            }
            
            result = subprocess.run(
                ["op", "item", "create", "--format", "json"],
                input=json.dumps(item_template),
                capture_output=True,
                text=True,
                check=True,
            )
            
            self._encryption_key = key.encode()
            return key
            
        except subprocess.CalledProcessError as e:
            raise EncryptionError(f"Failed to store encryption key in 1Password: {e.stderr}")
    
    def key_exists(self) -> bool:
        """Check if encryption key already exists in 1Password."""
        try:
            result = subprocess.run(
                ["op", "item", "get", BASTION_KEY_ITEM_NAME,
                 "--vault", BASTION_KEY_VAULT, "--format", "json"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def roll_key(self) -> None:
        """Generate a new encryption key and re-encrypt the cache.
        
        Security: Key is rolled on each sync to limit exposure window.
        
        Process (write-first for safety):
        1. Generate new Fernet key
        2. Decrypt cache with current key
        3. Encrypt cache with new key and write atomically
        4. Update 1Password with new key
        5. Clear in-memory key cache
        
        If step 4 fails, the cache is already encrypted with the new key,
        but 1Password still has the old key. This is recoverable by
        re-running sync (which will fail to decrypt, prompting cache rebuild).
        """
        Fernet = _get_fernet()
        
        # Generate new key
        new_key = Fernet.generate_key()
        
        # Read and decrypt with current key
        if not self.cache_path.exists():
            # No cache to re-encrypt, just update the key
            self._update_key_in_1password(new_key.decode())
            self._encryption_key = new_key
            return
        
        with open(self.cache_path, "rb") as f:
            encrypted_data = f.read()
        
        # Decrypt with current key
        decrypted_data = self._decrypt(encrypted_data)
        
        # Encrypt with new key
        f_new = Fernet(new_key)
        new_encrypted_data = f_new.encrypt(decrypted_data)
        
        # Atomic write with new encryption
        tmp_path = self.cache_path.with_suffix(".tmp")
        with open(tmp_path, "wb") as f:
            f.write(new_encrypted_data)
        os.chmod(tmp_path, 0o600)
        tmp_path.replace(self.cache_path)
        
        # Update 1Password with new key (after cache is safely written)
        self._update_key_in_1password(new_key.decode())
        
        # Clear cached key so next access uses new key
        self._encryption_key = new_key
    
    def _update_key_in_1password(self, new_key: str) -> None:
        """Update the encryption key in 1Password.
        
        Uses field assignment syntax (not JSON stdin) to avoid the
        passkey deletion bug with op item edit.
        
        Args:
            new_key: New Fernet key (base64 encoded string)
        """
        rotated_at = datetime.now(timezone.utc).isoformat()
        
        try:
            subprocess.run(
                [
                    "op", "item", "edit", BASTION_KEY_ITEM_NAME,
                    "--vault", BASTION_KEY_VAULT,
                    f"encryption_key[concealed]={new_key}",
                    f"rotated_at[text]={rotated_at}",
                ],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as e:
            raise EncryptionError(
                f"Failed to update encryption key in 1Password: {e.stderr}\n"
                f"Cache has been re-encrypted with new key but 1Password still has old key.\n"
                f"Manual recovery: Delete ~/.bsec/cache/db.enc and re-sync."
            )
    
    def _encrypt(self, data: bytes) -> bytes:
        """Encrypt data using Fernet.
        
        Args:
            data: Plaintext bytes to encrypt
            
        Returns:
            Encrypted bytes
        """
        Fernet = _get_fernet()
        key = self._get_encryption_key()
        f = Fernet(key)
        return f.encrypt(data)
    
    def _decrypt(self, data: bytes) -> bytes:
        """Decrypt data using Fernet.
        
        Args:
            data: Encrypted bytes
            
        Returns:
            Decrypted plaintext bytes
            
        Raises:
            EncryptionError: If decryption fails (wrong key, corrupted data)
        """
        Fernet = _get_fernet()
        from cryptography.fernet import InvalidToken
        
        key = self._get_encryption_key()
        f = Fernet(key)
        try:
            return f.decrypt(data)
        except InvalidToken:
            raise EncryptionError(
                "Failed to decrypt cache. The encryption key may have changed. "
                "Try deleting ~/.bastion/cache/db.enc and re-syncing."
            )
    
    def load(self) -> Database:
        """Load and decrypt database from encrypted cache.
        
        Automatically migrates from legacy ~/.bastion/cache.db.enc path
        if the new path doesn't exist but the old one does.
        
        Returns:
            Database object
        """
        self.ensure_infrastructure()
        
        # Auto-migrate from legacy path if needed
        if not self.cache_path.exists() and LEGACY_ENCRYPTED_DB.exists():
            LEGACY_ENCRYPTED_DB.rename(self.cache_path)
        
        if not self.cache_path.exists():
            return self._initialize_new()
        
        with open(self.cache_path, "rb") as f:
            encrypted_data = f.read()
        
        decrypted_data = self._decrypt(encrypted_data)
        data = json.loads(decrypted_data.decode("utf-8"))
        return Database.model_validate(data)
    
    def save(self, db: Database, backup: bool = True) -> None:
        """Encrypt and save database atomically with optional backup.
        
        Args:
            db: Database object to save
            backup: Whether to create a backup first
        """
        self.ensure_infrastructure()
        
        if backup and self.cache_path.exists():
            self._backup()
        
        db.metadata.updated_at = datetime.now(timezone.utc)
        
        # Serialize to JSON
        json_data = json.dumps(db.model_dump(mode="json"), indent=2, default=str)
        
        # Encrypt
        encrypted_data = self._encrypt(json_data.encode("utf-8"))
        
        # Atomic write
        tmp_path = self.cache_path.with_suffix(".tmp")
        with open(tmp_path, "wb") as f:
            f.write(encrypted_data)
        
        # Set restrictive permissions before moving
        os.chmod(tmp_path, 0o600)
        tmp_path.replace(self.cache_path)
    
    def _backup(self) -> None:
        """Create timestamped backup of encrypted cache."""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = self.backup_dir / f"cache-{timestamp}.db.enc"
        shutil.copy2(self.cache_path, backup_path)
        
        # Keep only last 30 backups
        backups = sorted(self.backup_dir.glob("cache-*.db.enc"))
        for old_backup in backups[:-30]:
            old_backup.unlink()
    
    def _initialize_new(self) -> Database:
        """Create new database."""
        now = datetime.now(timezone.utc)
        return Database(
            metadata=Metadata(
                created_at=now,
                updated_at=now,
                compromise_baseline="2025-01-01",
            ),
            accounts={},
        )


class DatabaseManager:
    """Manage database file operations (LEGACY - plaintext format).
    
    DEPRECATED: Use BastionCacheManager for encrypted storage.
    This class is retained for backward compatibility during migration.
    Will be removed in a future version.
    """

    def __init__(self, db_path: Path, backup_dir: Path | None = None):
        self.db_path = db_path
        self.backup_dir = backup_dir or db_path.parent / ".rotation-backups"
        self.backup_dir.mkdir(exist_ok=True)

    def load(self) -> Database:
        """Load database from file."""
        if not self.db_path.exists():
            return self._initialize_new()
        
        with open(self.db_path) as f:
            data = json.load(f)
        return Database.model_validate(data)

    def save(self, db: Database, backup: bool = True) -> None:
        """Save database atomically with optional backup."""
        if backup and self.db_path.exists():
            self._backup()
        
        db.metadata.updated_at = datetime.now(timezone.utc)
        
        # Atomic write
        tmp_path = self.db_path.with_suffix(".tmp")
        with open(tmp_path, "w") as f:
            json.dump(db.model_dump(mode="json"), f, indent=2, default=str)
        
        tmp_path.replace(self.db_path)

    def _backup(self) -> None:
        """Create timestamped backup."""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = self.backup_dir / f"rotation-db-{timestamp}.json"
        shutil.copy2(self.db_path, backup_path)
        
        # Keep only last 30 backups
        backups = sorted(self.backup_dir.glob("rotation-db-*.json"))
        for old_backup in backups[:-30]:
            old_backup.unlink()

    def _initialize_new(self) -> Database:
        """Create new database."""
        now = datetime.now(timezone.utc)
        return Database(
            metadata=Metadata(
                created_at=now,
                updated_at=now,
                compromise_baseline="2025-01-01",
            ),
            accounts={},
        )
