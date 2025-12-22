"""Database I/O with atomic writes, backups, and optional encryption."""

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from .config import (
    BASTION_BACKUP_DIR,
    BASTION_CACHE_DIR,
    BASTION_KEY_ITEM_NAME,
    BASTION_KEY_VAULT,
    ENCRYPTED_DB_PATH,
    LEGACY_ENCRYPTED_DB,
    ensure_cache_infrastructure,
)
from .models import Database, Metadata


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

            # Extract encryption_key field
            key_b64 = None
            
            for field in item.get("fields", []):
                if field.get("label") == "encryption_key":
                    key_b64 = field.get("value")
                    break

            if not key_b64:
                raise EncryptionError(f"Field 'encryption_key' not found in {BASTION_KEY_ITEM_NAME}")

            self._encryption_key = key_b64.encode()
            return self._encryption_key

        except subprocess.CalledProcessError:
            raise EncryptionError(
                f"Bastion cache key not found in 1Password. "
                f"Run 'bastion migrate from-sat' to create it, or create a Secure Note "
                f"named '{BASTION_KEY_ITEM_NAME}' in {BASTION_KEY_VAULT} vault with an "
                f"'encryption_key' field containing a Fernet key."
            )

    def _validate_machine_uuid(self) -> None:
        """Validate that current machine UUID matches the 1Password key entry.
        
        Raises:
            EncryptionError: If UUIDs don't match (triggers auto-recovery in load())
        """
        from bastion_core.platform import get_machine_uuid
        
        try:
            result = subprocess.run(
                ["op", "item", "get", BASTION_KEY_ITEM_NAME,
                 "--vault", BASTION_KEY_VAULT, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
            )
            item = json.loads(result.stdout)
            
            # Extract machine_uuid field
            key_machine_uuid = None
            for field in item.get("fields", []):
                if field.get("label") == "machine_uuid":
                    key_machine_uuid = field.get("value")
                    break
            
            # Validate if UUID exists in 1P entry
            if key_machine_uuid:
                current_uuid = get_machine_uuid()
                if key_machine_uuid != current_uuid:
                    raise EncryptionError(
                        f"Machine UUID mismatch: cache key was created on a different machine.\n"
                        f"Key machine UUID: {key_machine_uuid}\n"
                        f"Current machine UUID: {current_uuid}\n"
                        f"Auto-recovery: backing up cache and creating fresh database."
                    )
        except subprocess.CalledProcessError:
            # If we can't get the key, let _get_encryption_key() handle it
            pass

    def create_encryption_key(self) -> str:
        """Generate a new Fernet encryption key and store in 1Password.
        
        Returns:
            The base64-encoded key that was created
            
        Raises:
            EncryptionError: If key cannot be created/stored
        """
        from bastion_core.platform import get_machine_identifier, get_machine_uuid
        
        Fernet = _get_fernet()

        # Generate new Fernet key
        key = Fernet.generate_key().decode()
        machine_id = get_machine_identifier()
        machine_uuid = get_machine_uuid()
        created_at = datetime.now(UTC).isoformat()

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
                        "value": created_at,
                    },
                    {
                        "id": "purpose",
                        "type": "STRING",
                        "label": "purpose",
                        "value": "Encrypts ~/.bastion/cache/db.enc local cache file",
                    },
                    {
                        "id": "machine_hostname",
                        "type": "STRING",
                        "label": "machine_hostname",
                        "value": machine_id["hostname"],
                    },
                    {
                        "id": "created_on_machine",
                        "type": "STRING",
                        "label": "created_on_machine",
                        "value": machine_id["node_name"],
                    },
                    {
                        "id": "machine_uuid",
                        "type": "STRING",
                        "label": "machine_uuid",
                        "value": machine_uuid,
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
        from bastion_core.platform import get_machine_identifier, get_machine_uuid
        
        rotated_at = datetime.now(UTC).isoformat()
        machine_id = get_machine_identifier()
        machine_uuid = get_machine_uuid()

        try:
            subprocess.run(
                [
                    "op", "item", "edit", BASTION_KEY_ITEM_NAME,
                    "--vault", BASTION_KEY_VAULT,
                    f"encryption_key[concealed]={new_key}",
                    f"rotated_at[text]={rotated_at}",
                    f"rotated_on_machine[text]={machine_id['node_name']}",
                    f"last_machine_hostname[text]={machine_id['hostname']}",
                    f"machine_uuid[text]={machine_uuid}",
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
            # Provide accurate path and machine context for troubleshooting
            try:
                from bastion_core.platform import get_machine_identifier
                machine = get_machine_identifier()
                machine_info = f" on machine {machine['hostname']}"
            except Exception:
                machine_info = ""
            raise EncryptionError(
                "Failed to decrypt cache. The encryption key may have changed. "
                f"Cache path: {self.cache_path}{machine_info}. "
                "If you recently synced on a different machine, delete or move the cache file and re-sync: "
                f"rm -f {self.cache_path} && bastion 1p sync vault"
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

        # Attempt to decrypt. If decryption fails due to key mismatch,
        # automatically back up the cache and initialize a fresh database.
        try:
            # Validate machine UUID before attempting decryption
            self._validate_machine_uuid()
            
            with open(self.cache_path, "rb") as f:
                encrypted_data = f.read()

            decrypted_data = self._decrypt(encrypted_data)
            data = json.loads(decrypted_data.decode("utf-8"))
            return Database.model_validate(data)
        except EncryptionError as e:
            # Backup the bad cache for forensic analysis, then start fresh
            try:
                ts = datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')
                backup_name = self.backup_dir / f"db.enc.bad-{ts}"
                os.makedirs(self.backup_dir, exist_ok=True)
                shutil.move(str(self.cache_path), str(backup_name))
            except Exception:
                # If backup fails, continue with fresh init
                pass
            # Initialize new database
            return self._initialize_new()

    def save(self, db: Database, backup: bool = True) -> None:
        """Encrypt and save database atomically with optional backup.
        
        Args:
            db: Database object to save
            backup: Whether to create a backup first
        """
        self.ensure_infrastructure()

        if backup and self.cache_path.exists():
            self._backup()

        db.metadata.updated_at = datetime.now(UTC)

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
        now = datetime.now(UTC)
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

        db.metadata.updated_at = datetime.now(UTC)

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
        now = datetime.now(UTC)
        return Database(
            metadata=Metadata(
                created_at=now,
                updated_at=now,
                compromise_baseline="2025-01-01",
            ),
            accounts={},
        )
