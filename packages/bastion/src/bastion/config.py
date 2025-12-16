"""Bastion configuration and paths.

Centralized configuration for cache directories, file paths, and settings.
All cache/data files are stored in ~/.bsec/ to keep the workspace clean.
Legacy ~/.bastion/ is auto-migrated on first run.

Configuration is stored in ~/.bsec/config.toml and can be customized
via 'bsec config' commands or by editing the file directly.
"""

import tomllib
from pathlib import Path
from typing import Any
import shutil


# Base directories (new: .bsec, legacy: .bastion)
BSEC_DIR = Path.home() / ".bsec"
LEGACY_BASTION_DIR = Path.home() / ".bastion"

# Use .bsec if it exists, otherwise check for .bastion to migrate
def _get_bastion_dir() -> Path:
    """Get the bastion directory, migrating from .bastion to .bsec if needed."""
    if BSEC_DIR.exists():
        return BSEC_DIR
    if LEGACY_BASTION_DIR.exists():
        # Auto-migrate .bastion to .bsec
        try:
            shutil.move(str(LEGACY_BASTION_DIR), str(BSEC_DIR))
            return BSEC_DIR
        except (OSError, shutil.Error):
            # Migration failed, use legacy path
            return LEGACY_BASTION_DIR
    # Fresh install, use new path
    return BSEC_DIR

BASTION_DIR = _get_bastion_dir()
BASTION_CACHE_DIR = BASTION_DIR / "cache"
BASTION_BACKUP_DIR = BASTION_DIR / "backups"
BASTION_CONFIG_PATH = BASTION_DIR / "config.toml"

# Cache files
ENCRYPTED_DB_PATH = BASTION_CACHE_DIR / "db.enc"
YUBIKEY_CACHE_PATH = BASTION_CACHE_DIR / "yubikey-slots.json"
PASSWORD_ROTATION_DB_PATH = BASTION_CACHE_DIR / "password-rotation.json"

# Sigchain paths
SIGCHAIN_DIR = BASTION_DIR / "sigchain"
SIGCHAIN_LOG_PATH = SIGCHAIN_DIR / "events.jsonl"
SIGCHAIN_HEAD_PATH = SIGCHAIN_DIR / "head.json"
OTS_PENDING_DIR = SIGCHAIN_DIR / "ots" / "pending"
OTS_COMPLETED_DIR = SIGCHAIN_DIR / "ots" / "completed"

# Legacy paths (for migration)
LEGACY_ENCRYPTED_DB = BASTION_DIR / "cache.db.enc"
LEGACY_YUBIKEY_CACHE = Path.cwd() / "yubikey-slots-cache.json"
LEGACY_PASSWORD_ROTATION_DB = Path.cwd() / "password-rotation-database.json"

# 1Password settings (defaults, can be overridden in config.toml)
BASTION_KEY_ITEM_NAME = "Bastion Cache Key"
BASTION_KEY_VAULT = "Private"

# Default configuration values
DEFAULT_CONFIG = {
    "general": {
        "default_vault": "Private",
    },
    "entropy": {
        "default_bits": 8192,
        "expiry_days": 90,
        "quality_threshold": "GOOD",
    },
    "username": {
        "default_length": 16,
        "default_algorithm": "sha512",
    },
    "rotation": {
        "default_interval_days": 90,
        "warning_days": 14,
    },
    "yubikey": {
        "default_slot": 2,
        "challenge_iterations": 1024,
    },
    "session": {
        "timeout_minutes": 15,
        "auto_anchor": True,
        "gpg_sign_commits": True,
    },
    "sigchain": {
        "ots_enabled": True,
        "ots_calendars": [
            "https://alice.btc.calendar.opentimestamps.org",
            "https://bob.btc.calendar.opentimestamps.org",
            "https://finney.calendar.forever.covfefe.org",
        ],
        "sync_to_1password": True,
    },
}


class BastionConfig:
    """Bastion configuration manager.
    
    Loads configuration from ~/.bastion/config.toml with fallback to defaults.
    Configuration can be modified via the 'bastion config' commands.
    """
    
    _instance: "BastionConfig | None" = None
    _config: dict[str, Any] | None = None
    
    def __new__(cls) -> "BastionConfig":
        """Singleton pattern to avoid re-reading config file."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self) -> None:
        """Initialize configuration manager."""
        if self._config is None:
            self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from file or use defaults."""
        if BASTION_CONFIG_PATH.exists():
            try:
                with open(BASTION_CONFIG_PATH, "rb") as f:
                    file_config = tomllib.load(f)
                # Merge with defaults (file values override defaults)
                self._config = self._merge_config(DEFAULT_CONFIG, file_config)
            except (tomllib.TOMLDecodeError, OSError):
                self._config = DEFAULT_CONFIG.copy()
        else:
            self._config = DEFAULT_CONFIG.copy()
    
    def _merge_config(self, defaults: dict, overrides: dict) -> dict:
        """Deep merge configuration dictionaries."""
        result = defaults.copy()
        for key, value in overrides.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_config(result[key], value)
            else:
                result[key] = value
        return result
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get a configuration value.
        
        Args:
            section: Configuration section (e.g., "entropy", "username")
            key: Key within section
            default: Default value if not found
            
        Returns:
            Configuration value or default
        """
        if self._config is None:
            self._load_config()
        return self._config.get(section, {}).get(key, default)
    
    def get_section(self, section: str) -> dict[str, Any]:
        """Get entire configuration section.
        
        Args:
            section: Configuration section name
            
        Returns:
            Dictionary of section values
        """
        if self._config is None:
            self._load_config()
        return self._config.get(section, {})
    
    @property
    def default_vault(self) -> str:
        """Get default 1Password vault name."""
        return self.get("general", "default_vault", "Private")
    
    @property
    def entropy_bits(self) -> int:
        """Get default entropy collection size in bits."""
        return self.get("entropy", "default_bits", 8192)
    
    @property
    def entropy_expiry_days(self) -> int:
        """Get default entropy pool expiry in days."""
        return self.get("entropy", "expiry_days", 90)
    
    @property
    def username_length(self) -> int:
        """Get default username length."""
        return self.get("username", "default_length", 16)
    
    @property
    def username_algorithm(self) -> str:
        """Get default username generation algorithm."""
        return self.get("username", "default_algorithm", "sha512")
    
    @property
    def rotation_interval_days(self) -> int:
        """Get default password rotation interval in days."""
        return self.get("rotation", "default_interval_days", 90)
    
    @property
    def yubikey_slot(self) -> int:
        """Get default YubiKey HMAC slot."""
        return self.get("yubikey", "default_slot", 2)
    
    @property
    def session_timeout_minutes(self) -> int:
        """Get session timeout in minutes."""
        return self.get("session", "timeout_minutes", 15)
    
    @property
    def session_auto_anchor(self) -> bool:
        """Get whether to auto-anchor on session end."""
        return self.get("session", "auto_anchor", True)
    
    @property
    def gpg_sign_commits(self) -> bool:
        """Get whether to GPG sign sigchain commits."""
        return self.get("session", "gpg_sign_commits", True)
    
    @property
    def ots_enabled(self) -> bool:
        """Get whether OpenTimestamps is enabled."""
        return self.get("sigchain", "ots_enabled", True)
    
    @property
    def ots_calendars(self) -> list[str]:
        """Get list of OTS calendar server URLs."""
        return self.get("sigchain", "ots_calendars", [
            "https://alice.btc.calendar.opentimestamps.org",
            "https://bob.btc.calendar.opentimestamps.org",
            "https://finney.calendar.forever.covfefe.org",
        ])
    
    @property
    def sigchain_sync_to_1password(self) -> bool:
        """Get whether to sync sigchain head to 1Password."""
        return self.get("sigchain", "sync_to_1password", True)
    
    def reload(self) -> None:
        """Reload configuration from disk."""
        self._config = None
        self._load_config()
    
    @staticmethod
    def save_config(config: dict[str, Any]) -> None:
        """Save configuration to ~/.bastion/config.toml.
        
        Args:
            config: Configuration dictionary to save
        """
        ensure_cache_infrastructure()
        
        lines = ["# Bastion Configuration", "# Generated by 'bastion config init'", ""]
        
        for section, values in config.items():
            lines.append(f"[{section}]")
            for key, value in values.items():
                if isinstance(value, str):
                    lines.append(f'{key} = "{value}"')
                elif isinstance(value, bool):
                    lines.append(f"{key} = {str(value).lower()}")
                else:
                    lines.append(f"{key} = {value}")
            lines.append("")
        
        BASTION_CONFIG_PATH.write_text("\n".join(lines))
    
    @staticmethod
    def config_exists() -> bool:
        """Check if configuration file exists."""
        return BASTION_CONFIG_PATH.exists()


# Global config instance
def get_config() -> BastionConfig:
    """Get the global configuration instance.
    
    Returns:
        BastionConfig singleton instance
    """
    return BastionConfig()


def ensure_cache_infrastructure() -> None:
    """Create ~/.bastion/cache directory structure if needed.
    
    Creates:
        ~/.bastion/
        ~/.bastion/cache/
        ~/.bastion/backups/
    
    All directories are created with mode 0o700 (owner-only access).
    """
    BASTION_DIR.mkdir(mode=0o700, exist_ok=True)
    BASTION_CACHE_DIR.mkdir(mode=0o700, exist_ok=True)
    BASTION_BACKUP_DIR.mkdir(mode=0o700, exist_ok=True)


def get_yubikey_cache_path() -> Path:
    """Get the YubiKey cache file path.
    
    Auto-migrates from legacy ./yubikey-slots-cache.json if needed.
    
    Returns:
        Path to ~/.bastion/cache/yubikey-slots.json
    """
    ensure_cache_infrastructure()
    
    # Auto-migrate from legacy path if needed
    if not YUBIKEY_CACHE_PATH.exists() and LEGACY_YUBIKEY_CACHE.exists():
        LEGACY_YUBIKEY_CACHE.rename(YUBIKEY_CACHE_PATH)
    
    return YUBIKEY_CACHE_PATH


def get_encrypted_db_path() -> Path:
    """Get the encrypted database file path.
    
    Returns:
        Path to ~/.bastion/cache/db.enc
    """
    ensure_cache_infrastructure()
    return ENCRYPTED_DB_PATH


def get_password_rotation_db_path() -> Path:
    """Get the password rotation database path.
    
    Auto-migrates from legacy ./password-rotation-database.json if needed.
    
    Returns:
        Path to ~/.bastion/cache/password-rotation.json
    """
    ensure_cache_infrastructure()
    
    # Auto-migrate from legacy path if needed
    if not PASSWORD_ROTATION_DB_PATH.exists() and LEGACY_PASSWORD_ROTATION_DB.exists():
        LEGACY_PASSWORD_ROTATION_DB.rename(PASSWORD_ROTATION_DB_PATH)
    
    return PASSWORD_ROTATION_DB_PATH


def migrate_legacy_cache_files() -> dict[str, bool]:
    """Migrate cache files from legacy locations to ~/.bastion/cache/.
    
    Migrates:
        - ~/.bastion/cache.db.enc → ~/.bastion/cache/db.enc
        - ./yubikey-slots-cache.json → ~/.bastion/cache/yubikey-slots.json
        - ./password-rotation-database.json → ~/.bastion/cache/password-rotation.json
    
    Returns:
        Dictionary of {filename: migrated} indicating which files were moved
    """
    ensure_cache_infrastructure()
    results = {}
    
    # Migrate encrypted database
    if LEGACY_ENCRYPTED_DB.exists() and not ENCRYPTED_DB_PATH.exists():
        LEGACY_ENCRYPTED_DB.rename(ENCRYPTED_DB_PATH)
        results["db.enc"] = True
    else:
        results["db.enc"] = False
    
    # Migrate YubiKey cache
    if LEGACY_YUBIKEY_CACHE.exists() and not YUBIKEY_CACHE_PATH.exists():
        LEGACY_YUBIKEY_CACHE.rename(YUBIKEY_CACHE_PATH)
        results["yubikey-slots.json"] = True
    else:
        results["yubikey-slots.json"] = False
    
    # Migrate password rotation database
    if LEGACY_PASSWORD_ROTATION_DB.exists() and not PASSWORD_ROTATION_DB_PATH.exists():
        LEGACY_PASSWORD_ROTATION_DB.rename(PASSWORD_ROTATION_DB_PATH)
        results["password-rotation.json"] = True
    else:
        results["password-rotation.json"] = False
    
    return results


def ensure_sigchain_infrastructure() -> None:
    """Create sigchain directory structure if needed.
    
    Creates:
        ~/.bastion/sigchain/
        ~/.bastion/sigchain/ots/pending/
        ~/.bastion/sigchain/ots/completed/
    
    All directories are created with mode 0o700 (owner-only access).
    """
    SIGCHAIN_DIR.mkdir(mode=0o700, exist_ok=True)
    OTS_PENDING_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    OTS_COMPLETED_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


def get_sigchain_dir() -> Path:
    """Get the sigchain directory path.
    
    Returns:
        Path to ~/.bastion/sigchain/
    """
    ensure_sigchain_infrastructure()
    return SIGCHAIN_DIR


def get_sigchain_log_path() -> Path:
    """Get the sigchain events log path.
    
    Returns:
        Path to ~/.bastion/sigchain/events.jsonl
    """
    ensure_sigchain_infrastructure()
    return SIGCHAIN_LOG_PATH


def get_sigchain_head_path() -> Path:
    """Get the sigchain head state path.
    
    Returns:
        Path to ~/.bastion/sigchain/head.json
    """
    ensure_sigchain_infrastructure()
    return SIGCHAIN_HEAD_PATH


def get_ots_pending_dir() -> Path:
    """Get the OTS pending anchors directory.
    
    Returns:
        Path to ~/.bastion/sigchain/ots/pending/
    """
    ensure_sigchain_infrastructure()
    return OTS_PENDING_DIR


def get_ots_completed_dir() -> Path:
    """Get the OTS completed anchors directory.
    
    Returns:
        Path to ~/.bastion/sigchain/ots/completed/
    """
    ensure_sigchain_infrastructure()
    return OTS_COMPLETED_DIR
