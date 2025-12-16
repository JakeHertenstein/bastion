"""Sigchain integration helpers for CLI commands.

This module provides easy-to-use functions for emitting sigchain events
from existing Bastion CLI commands. It handles session management and
provides a clean API for recording audit events.

Usage in CLI commands:
    from bastion.sigchain.integration import emit_event, get_active_session

    # Emit an event (creates session if needed)
    emit_event(UsernameGeneratedPayload(...))

    # Or check for active session first
    session = get_active_session()
    if session:
        session.record_event(payload)
"""

from __future__ import annotations

import hashlib
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from rich.console import Console

if TYPE_CHECKING:
    from .events import EventPayload
    from .session import SessionManager
    from .chain import Sigchain

console = Console()

# Global session state
_active_session: "SessionManager | None" = None
_session_lock = threading.Lock()


def get_active_session() -> "SessionManager | None":
    """Get the currently active session, if any.
    
    Returns:
        Active SessionManager or None
    """
    return _active_session


def set_active_session(session: "SessionManager | None") -> None:
    """Set the active session.
    
    Args:
        session: SessionManager instance or None to clear
    """
    global _active_session
    with _session_lock:
        _active_session = session


def is_sigchain_enabled() -> bool:
    """Check if sigchain is enabled in config.
    
    Returns:
        True if sigchain auditing is enabled
    """
    try:
        from ..config import get_config
        config = get_config()
        return config.get("sigchain", "enabled", True)
    except Exception:
        return True  # Default to enabled


def emit_event(
    payload: "EventPayload",
    require_session: bool = False,
    silent: bool = True,
) -> bool:
    """Emit a sigchain event.
    
    If a session is active, appends to it. Otherwise, creates a
    single-use mini-session for this event.
    
    Args:
        payload: Event payload to record
        require_session: If True, fail silently when no session
        silent: If True, don't print status messages
        
    Returns:
        True if event was recorded successfully
    """
    from .session import SessionManager
    
    session = get_active_session()
    
    if session and session.active:
        # Use existing session
        try:
            session.record_event(payload)
            if not silent:
                console.print(f"[dim]📝 Recorded: {payload.get_summary()}[/dim]")
            return True
        except Exception as e:
            if not silent:
                console.print(f"[yellow]Warning: Failed to record event: {e}[/yellow]")
            return False
    
    if require_session:
        return False
    
    # Check if sigchain is enabled
    if not is_sigchain_enabled():
        return False
    
    # Create single-event mini-session (no anchor, quick commit)
    try:
        single_session = SessionManager(timeout_minutes=1)
        chain = single_session.start()
        chain.append(payload)
        single_session.end(anchor=False, commit=True)
        if not silent:
            console.print(f"[dim]📝 Recorded: {payload.get_summary()}[/dim]")
        return True
    except Exception as e:
        if not silent:
            console.print(f"[yellow]Warning: Failed to record event: {e}[/yellow]")
        return False


@contextmanager
def sigchain_session(
    timeout_minutes: int | None = None,
    anchor_on_end: bool = True,
) -> Iterator["Sigchain"]:
    """Context manager for sigchain sessions.
    
    Usage:
        with sigchain_session() as chain:
            # ... do operations ...
            chain.append(payload)
    
    Args:
        timeout_minutes: Session timeout (default from config)
        anchor_on_end: Whether to submit OTS anchor on session end
        
    Yields:
        Sigchain instance
    """
    from .session import SessionManager
    
    session = SessionManager(timeout_minutes=timeout_minutes)
    
    try:
        chain = session.start()
        set_active_session(session)
        yield chain
    finally:
        set_active_session(None)
        if session.active:
            session.end(anchor=anchor_on_end)


# =============================================================================
# Convenience functions for specific event types
# =============================================================================

def record_username_generated(
    domain: str,
    algorithm: str,
    label: str,
    username: str,
    length: int,
    saved_to_1password: bool = False,
    account_uuid: str | None = None,
) -> bool:
    """Record a username generation event.
    
    Args:
        domain: Domain the username was generated for
        algorithm: Hash algorithm used
        label: Full Bastion label
        username: Generated username (will be hashed for storage)
        length: Username length
        saved_to_1password: Whether saved to 1Password
        account_uuid: 1Password item UUID if saved
        
    Returns:
        True if recorded successfully
    """
    from .events import UsernameGeneratedPayload
    
    # Hash the username - we don't store the actual username in the audit log
    username_hash = hashlib.sha256(username.encode()).hexdigest()
    
    payload = UsernameGeneratedPayload(
        domain=domain,
        algorithm=algorithm,
        label=label,
        username_hash=username_hash,
        length=length,
        saved_to_1password=saved_to_1password,
        account_uuid=account_uuid,
    )
    
    return emit_event(payload)


def record_entropy_pool_created(
    pool_uuid: str,
    serial_number: int,
    source: str,
    bits: int,
    quality_rating: str,
    entropy_per_byte: float,
    device_serial: str | None = None,
) -> bool:
    """Record an entropy pool creation event.
    
    Args:
        pool_uuid: 1Password item UUID
        serial_number: Pool serial number
        source: Entropy source
        bits: Bits collected
        quality_rating: ENT quality rating
        entropy_per_byte: Measured entropy
        device_serial: Hardware device serial if applicable
        
    Returns:
        True if recorded successfully
    """
    from .events import EntropyPoolCreatedPayload
    
    payload = EntropyPoolCreatedPayload(
        pool_uuid=pool_uuid,
        serial_number=serial_number,
        source=source,
        bits=bits,
        quality_rating=quality_rating,
        entropy_per_byte=entropy_per_byte,
        device_serial=device_serial,
    )
    
    return emit_event(payload)


def record_tag_operation(
    account_uuid: str,
    account_title: str,
    action: str,
    tags_before: list[str],
    tags_after: list[str],
) -> bool:
    """Record a tag operation event.
    
    Args:
        account_uuid: 1Password item UUID
        account_title: Account title
        action: "add", "remove", or "replace"
        tags_before: Tags before operation
        tags_after: Tags after operation
        
    Returns:
        True if recorded successfully
    """
    from .events import TagOperationPayload
    
    # Validate action
    if action not in ("add", "remove", "replace"):
        return False
    
    payload = TagOperationPayload(
        account_uuid=account_uuid,
        account_title=account_title,
        action=action,  # type: ignore
        tags_before=tags_before,
        tags_after=tags_after,
    )
    
    return emit_event(payload)


def record_password_rotation(
    account_uuid: str,
    account_title: str,
    domain: str,
    new_change_date: str,
    previous_change_date: str | None = None,
    rotation_interval_days: int = 90,
    tier: str = "Tier 2",
) -> bool:
    """Record a password rotation event.
    
    Args:
        account_uuid: 1Password item UUID
        account_title: Account title
        domain: Primary domain
        new_change_date: New password change date (YYYY-MM-DD)
        previous_change_date: Previous change date
        rotation_interval_days: Days until next rotation
        tier: Account tier
        
    Returns:
        True if recorded successfully
    """
    from .events import PasswordRotationPayload
    
    payload = PasswordRotationPayload(
        account_uuid=account_uuid,
        account_title=account_title,
        domain=domain,
        new_change_date=new_change_date,
        previous_change_date=previous_change_date,
        rotation_interval_days=rotation_interval_days,
        tier=tier,
    )
    
    return emit_event(payload)


def record_config_change(
    config_section: str,
    config_key: str,
    old_value: str | None,
    new_value: str | None,
    source: str = "cli",
) -> bool:
    """Record a configuration change event.
    
    Args:
        config_section: Config section changed
        config_key: Config key changed
        old_value: Previous value
        new_value: New value
        source: Change source
        
    Returns:
        True if recorded successfully
    """
    from .events import ConfigChangePayload
    
    payload = ConfigChangePayload(
        config_section=config_section,
        config_key=config_key,
        old_value=old_value,
        new_value=new_value,
        source=source,
    )
    
    return emit_event(payload)
