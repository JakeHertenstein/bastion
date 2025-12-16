"""YubiKey TOTP slot cache and transaction management."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .db import BastionCacheManager


class YubiKeyTransaction:
    """Transaction record for YubiKey TOTP migration."""
    
    def __init__(
        self,
        account_name: str,
        account_uuid: str,
        issuer: str,
        action: str,
        status: str,
        completed_serials: list[str],
        failed_serials: list[str],
        timestamp: datetime | None = None,
    ):
        self.account_name = account_name
        self.account_uuid = account_uuid
        self.issuer = issuer
        self.action = action  # "migrate", "rollback"
        self.status = status  # "complete", "partial", "failed"
        self.completed_serials = completed_serials
        self.failed_serials = failed_serials
        self.timestamp = timestamp or datetime.now(timezone.utc)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "account_name": self.account_name,
            "account_uuid": self.account_uuid,
            "issuer": self.issuer,
            "action": self.action,
            "status": self.status,
            "completed_serials": self.completed_serials,
            "failed_serials": self.failed_serials,
            "timestamp": self.timestamp.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "YubiKeyTransaction":
        """Create from dictionary."""
        return cls(
            account_name=data["account_name"],
            account_uuid=data["account_uuid"],
            issuer=data["issuer"],
            action=data["action"],
            status=data["status"],
            completed_serials=data["completed_serials"],
            failed_serials=data["failed_serials"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
        )


class YubiKeySerialInfo:
    """Information about a specific YubiKey."""
    
    def __init__(
        self,
        serial: str,
        role: str = "",
        accounts: list[dict[str, Any]] | None = None,
        last_updated: datetime | None = None,
        op_uuid: str | None = None,
    ):
        self.serial = serial
        self.role = role  # e.g., "Daily Carry", "Home Safe", etc.
        # accounts is now list of dicts: {"oath_name": str, "op_uuid": str, "op_title": str, "added_date": str}
        self.accounts = accounts or []
        self.last_updated = last_updated or datetime.now(timezone.utc)
        self.op_uuid = op_uuid  # 1Password UUID for YubiKey crypto wallet item
    
    @property
    def slot_count(self) -> int:
        """Number of OATH slots used."""
        return len(self.accounts)
    
    @property
    def slots_remaining(self) -> int:
        """Number of OATH slots remaining (max 32)."""
        return 32 - self.slot_count
    
    @property
    def cache_age_days(self) -> int:
        """Age of cache in days."""
        now = datetime.now(timezone.utc)
        delta = now - self.last_updated
        return delta.days
    
    @property
    def is_stale(self) -> bool:
        """Check if cache is stale (>7 days old)."""
        return self.cache_age_days > 7
    
    def get_oath_names(self) -> list[str]:
        """Get list of OATH account names."""
        return [acc["oath_name"] if isinstance(acc, dict) else acc for acc in self.accounts]
    
    def get_uuid_for_oath_name(self, oath_name: str) -> str | None:
        """Get 1Password UUID for a given OATH account name."""
        for acc in self.accounts:
            if isinstance(acc, dict) and acc.get("oath_name") == oath_name:
                return acc.get("op_uuid")
        return None
    
    def find_oath_name_by_uuid(self, op_uuid: str) -> str | None:
        """Find OATH account name by 1Password UUID."""
        for acc in self.accounts:
            if isinstance(acc, dict) and acc.get("op_uuid") == op_uuid:
                return acc.get("oath_name")
        return None
    
    def add_or_update_mapping(
        self, 
        oath_name: str, 
        op_uuid: str, 
        op_title: str,
        added_date: datetime | None = None,
    ) -> None:
        """Add or update an account mapping."""
        added_date = added_date or datetime.now(timezone.utc)
        
        # Remove old entry if exists
        self.accounts = [acc for acc in self.accounts if not (isinstance(acc, dict) and acc.get("oath_name") == oath_name)]
        
        # Add new entry
        self.accounts.append({
            "oath_name": oath_name,
            "op_uuid": op_uuid,
            "op_title": op_title,
            "added_date": added_date.isoformat(),
        })
        self.last_updated = datetime.now(timezone.utc)
    
    def remove_account_by_oath_name(self, oath_name: str) -> bool:
        """Remove an account by OATH name. Returns True if account was found and removed."""
        original_count = len(self.accounts)
        self.accounts = [acc for acc in self.accounts if not (isinstance(acc, dict) and acc.get("oath_name") == oath_name)]
        removed = len(self.accounts) < original_count
        if removed:
            self.last_updated = datetime.now(timezone.utc)
        return removed
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "serial": self.serial,
            "role": self.role,
            "accounts": self.accounts,
            "slot_count": self.slot_count,
            "last_updated": self.last_updated.isoformat(),
        }
        if self.op_uuid is not None:
            result["op_uuid"] = self.op_uuid
        return result
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "YubiKeySerialInfo":
        """Create from dictionary."""
        return cls(
            serial=data["serial"],
            role=data.get("role", ""),
            accounts=data.get("accounts", []),
            last_updated=datetime.fromisoformat(data["last_updated"]),
            op_uuid=data.get("op_uuid"),
        )


class YubiKeyCache:
    """Manage YubiKey TOTP slot cache and transactions.
    
    Supports two storage modes:
    1. Encrypted (preferred): Stores in db.yubikey_cache via BastionCacheManager
    2. Legacy file: Stores in plaintext JSON file (deprecated)
    
    Use from_encrypted() or from_file() factory methods to create.
    """
    
    def __init__(
        self,
        cache_path: Path | None = None,
        cache_manager: BastionCacheManager | None = None,
    ):
        """Initialize cache.
        
        Args:
            cache_path: Path to legacy plaintext cache file (deprecated)
            cache_manager: BastionCacheManager for encrypted storage (preferred)
        """
        self.cache_path = cache_path
        self._cache_manager = cache_manager
        self._use_encrypted = cache_manager is not None
        
        self.serials: dict[str, YubiKeySerialInfo] = {}
        self.transactions: list[YubiKeyTransaction] = []
        self.metadata = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
    
    @classmethod
    def from_encrypted(cls, cache_manager: BastionCacheManager) -> YubiKeyCache:
        """Create cache using encrypted storage (preferred).
        
        Args:
            cache_manager: BastionCacheManager instance
            
        Returns:
            YubiKeyCache configured for encrypted storage
        """
        cache = cls(cache_manager=cache_manager)
        cache.load()
        return cache
    
    @classmethod
    def from_file(cls, cache_path: Path) -> YubiKeyCache:
        """Create cache using legacy file storage (deprecated).
        
        Args:
            cache_path: Path to plaintext JSON cache file
            
        Returns:
            YubiKeyCache configured for file storage
        """
        cache = cls(cache_path=cache_path)
        cache.load()
        return cache
    
    def load(self) -> None:
        """Load cache from storage."""
        if self._use_encrypted:
            self._load_from_encrypted()
        elif self.cache_path:
            self._load_from_file()
    
    def _load_from_encrypted(self) -> None:
        """Load from encrypted database."""
        if not self._cache_manager:
            return
        
        db = self._cache_manager.load()
        if db.yubikey_cache is None:
            return
        
        data = db.yubikey_cache
        
        # Load metadata
        self.metadata = data.get("metadata", self.metadata)
        
        # Load serials
        self.serials = {
            serial: YubiKeySerialInfo.from_dict(info)
            for serial, info in data.get("serials", {}).items()
        }
        
        # Load transactions
        self.transactions = [
            YubiKeyTransaction.from_dict(tx)
            for tx in data.get("transactions", [])
        ]
    
    def _load_from_file(self) -> None:
        """Load from legacy plaintext file."""
        if not self.cache_path or not self.cache_path.exists():
            return
        
        with open(self.cache_path) as f:
            data = json.load(f)
        
        # Load metadata
        self.metadata = data.get("metadata", self.metadata)
        
        # Load serials
        self.serials = {
            serial: YubiKeySerialInfo.from_dict(info)
            for serial, info in data.get("serials", {}).items()
        }
        
        # Load transactions
        self.transactions = [
            YubiKeyTransaction.from_dict(tx)
            for tx in data.get("transactions", [])
        ]
    
    def save(self) -> None:
        """Save cache to storage."""
        if self._use_encrypted:
            self._save_to_encrypted()
        elif self.cache_path:
            self._save_to_file()
    
    def _save_to_encrypted(self) -> None:
        """Save to encrypted database."""
        if not self._cache_manager:
            return
        
        self.metadata["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        data = {
            "metadata": self.metadata,
            "serials": {
                serial: info.to_dict()
                for serial, info in self.serials.items()
            },
            "transactions": [tx.to_dict() for tx in self.transactions],
        }
        
        # Load existing db, update yubikey_cache, save
        db = self._cache_manager.load()
        db.yubikey_cache = data
        self._cache_manager.save(db)
    
    def _save_to_file(self) -> None:
        """Save to legacy plaintext file (deprecated)."""
        if not self.cache_path:
            return
            
        self.metadata["updated_at"] = datetime.now(timezone.utc).isoformat()
        
        data = {
            "metadata": self.metadata,
            "serials": {
                serial: info.to_dict()
                for serial, info in self.serials.items()
            },
            "transactions": [tx.to_dict() for tx in self.transactions],
        }
        
        # Atomic write
        tmp_path = self.cache_path.with_suffix(".tmp")
        with open(tmp_path, "w") as f:
            json.dump(data, f, indent=2)
        
        tmp_path.replace(self.cache_path)
    
    def to_dict(self) -> dict[str, Any]:
        """Export cache data as dictionary for migration."""
        return {
            "metadata": self.metadata,
            "serials": {
                serial: info.to_dict()
                for serial, info in self.serials.items()
            },
            "transactions": [tx.to_dict() for tx in self.transactions],
        }
    
    def refresh_serial(self, serial: str, role: str = "", password: str | None = None) -> tuple[bool, str]:
        """
        Refresh OATH accounts for a specific YubiKey.
        
        Args:
            serial: YubiKey serial number
            role: Optional role description
            password: Optional OATH password (if None, will prompt via stdin)
        
        Returns:
            (success, message)
        """
        try:
            # Run ykman to list OATH accounts
            if password:
                # Use provided password
                result = subprocess.run(
                    ["ykman", "--device", serial, "oath", "accounts", "list"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    input=f"{password}\n".encode(),
                    timeout=30,
                    check=False,
                )
            else:
                # Inherit stderr for password prompt, capture stdout for account list
                result = subprocess.run(
                    ["ykman", "--device", serial, "oath", "accounts", "list"],
                    stdout=subprocess.PIPE,
                    stderr=None,  # Inherit stderr so password prompt is visible
                    stdin=sys.stdin,  # Connect stdin for password input
                    text=True,
                    timeout=30,
                    check=False,
                )
            
            if result.returncode != 0:
                return False, "Failed to list OATH accounts (check password if prompted)"
            
            # Parse account list (handle both text and bytes)
            stdout_text = result.stdout if isinstance(result.stdout, str) else result.stdout.decode()
            oath_names = [line.strip() for line in stdout_text.strip().split("\n") if line.strip()]
            
            # Preserve existing mappings if cache exists
            existing_mappings = {}
            if serial in self.serials:
                for acc in self.serials[serial].accounts:
                    if isinstance(acc, dict):
                        existing_mappings[acc["oath_name"]] = acc
            
            # Build new accounts list, preserving UUID mappings where they exist
            new_accounts = []
            for oath_name in oath_names:
                if oath_name in existing_mappings:
                    # Keep existing mapping
                    new_accounts.append(existing_mappings[oath_name])
                else:
                    # New account without mapping yet (will be added during migration)
                    new_accounts.append({
                        "oath_name": oath_name,
                        "op_uuid": "",
                        "op_title": "",
                        "added_date": datetime.now(timezone.utc).isoformat(),
                    })
            
            # Update cache
            existing_role = self.serials[serial].role if serial in self.serials else role
            self.serials[serial] = YubiKeySerialInfo(
                serial=serial,
                role=role or existing_role,
                accounts=new_accounts,
                last_updated=datetime.now(timezone.utc),
            )
            
            return True, f"Refreshed {len(oath_names)} accounts"
        
        except subprocess.TimeoutExpired:
            return False, "Timeout waiting for YubiKey"
        except FileNotFoundError:
            return False, "ykman not found - install with: brew install ykman"
        except Exception as e:
            return False, f"Error: {e!s}"
    
    def list_connected_yubikeys(self) -> list[str]:
        """
        List serial numbers of connected YubiKeys.
        
        Returns:
            List of serial numbers
        """
        try:
            result = subprocess.run(
                ["ykman", "list", "--serials"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            
            if result.returncode == 0:
                return [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
            return []
        
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            return []
    
    def log_transaction(self, transaction: YubiKeyTransaction) -> None:
        """Add a transaction to the log."""
        self.transactions.append(transaction)
    
    def get_partial_migrations(self) -> list[YubiKeyTransaction]:
        """Get transactions with partial status."""
        return [tx for tx in self.transactions if tx.status == "partial"]
    
    def get_transaction_for_account(self, account_uuid: str) -> YubiKeyTransaction | None:
        """Get most recent transaction for an account."""
        account_txs = [tx for tx in self.transactions if tx.account_uuid == account_uuid]
        if account_txs:
            return max(account_txs, key=lambda tx: tx.timestamp)
        return None
    
    def get_stale_serials(self) -> list[str]:
        """Get serials with stale cache (>7 days)."""
        return [serial for serial, info in self.serials.items() if info.is_stale]
    
    def get_account_serials(self, issuer: str, account: str) -> list[str]:
        """
        Get list of serials that have a specific OATH account.
        
        Args:
            issuer: OATH issuer
            account: OATH account name
        
        Returns:
            List of serial numbers
        """
        full_name = f"{issuer}:{account}"
        return [
            serial
            for serial, info in self.serials.items()
            if full_name in info.get_oath_names()
        ]
