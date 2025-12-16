"""Shared helper functions for CLI commands."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional, TYPE_CHECKING

import typer

from ..config import get_password_rotation_db_path

if TYPE_CHECKING:
    from ..db import DatabaseManager, BastionCacheManager


# Common type annotations for CLI options
DbPathOption = Annotated[
    Optional[Path],
    typer.Option(
        "--db",
        help="Database file path",
        envvar="PASSWORD_ROTATION_DB",
    ),
]


def get_db_manager(db_path: Path | None = None) -> "DatabaseManager":
    """Get database manager with default path (LEGACY - plaintext).
    
    DEPRECATED: Use get_encrypted_db_manager() for new code.
    
    Args:
        db_path: Optional path to database file. Defaults to ~/.bsec/cache/password-rotation.json
        
    Returns:
        DatabaseManager instance
    """
    from ..db import DatabaseManager
    
    if db_path is None:
        db_path = get_password_rotation_db_path()
    return DatabaseManager(db_path)


def get_encrypted_db_manager() -> "BastionCacheManager":
    """Get encrypted cache manager.
    
    Returns BastionCacheManager which stores encrypted data at ~/.bsec/cache/db.enc
    with key stored in 1Password.
    
    Returns:
        BastionCacheManager instance
    """
    from ..db import BastionCacheManager
    return BastionCacheManager()


def format_date(dt: datetime | None) -> str:
    """Format a datetime for display.
    
    Args:
        dt: Datetime to format, or None
        
    Returns:
        Formatted date string or "Never"
    """
    if dt is None:
        return "Never"
    return dt.strftime("%Y-%m-%d")


def format_days(days: int | None) -> str:
    """Format days until rotation for display.
    
    Args:
        days: Number of days, or None
        
    Returns:
        Formatted string with appropriate styling hint
    """
    if days is None:
        return "N/A"
    if days < 0:
        return f"{abs(days)} days overdue"
    if days == 0:
        return "Due today"
    return f"{days} days"


def utc_now() -> datetime:
    """Get current UTC datetime.
    
    Returns:
        Current datetime in UTC timezone
    """
    return datetime.now(timezone.utc)


def get_yubikey_service() -> "YubiKeyService":
    """Get YubiKey service for querying 1Password as source of truth.
    
    Returns:
        YubiKeyService instance
    """
    from ..yubikey_service import YubiKeyService
    
    cache_mgr = get_encrypted_db_manager()
    return YubiKeyService(cache_mgr)


def get_yubikey_cache() -> "YubiKeyCache":
    """Get YubiKey cache from encrypted storage.
    
    DEPRECATED: Use get_yubikey_service() for new code. This wrapper
    maintains backward compatibility with existing code during migration.
    
    Returns:
        YubiKeyCache instance loaded from encrypted database
    """
    import warnings
    warnings.warn(
        "get_yubikey_cache() is deprecated. Use get_yubikey_service() instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    from ..yubikey_cache import YubiKeyCache
    
    cache_mgr = get_encrypted_db_manager()
    return YubiKeyCache.from_encrypted(cache_mgr)


if TYPE_CHECKING:
    from ..yubikey_service import YubiKeyService
    from ..yubikey_cache import YubiKeyCache
