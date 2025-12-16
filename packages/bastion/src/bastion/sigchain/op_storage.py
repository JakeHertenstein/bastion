"""1Password storage for sigchain metadata.

This module stores sigchain state in 1Password for:
- Cross-machine synchronization of chain head
- Human-readable audit summaries
- Backup of critical chain metadata

Storage Format:
    A secure note titled "Bastion Sigchain" contains:
    - Chain Head section: current head hash, seqno, device
    - Session History section: recent session summaries
    - Anchor Status section: pending/completed OTS anchors
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from rich.console import Console

from .models import ChainHead, DeviceType


console = Console()


@dataclass
class SessionSummary:
    """Summary of a sigchain session."""
    
    session_id: str
    started_at: datetime
    ended_at: datetime
    event_count: int
    event_types: list[str]
    anchor_submitted: bool
    
    def to_display(self) -> str:
        """Format for 1Password display."""
        duration = (self.ended_at - self.started_at).total_seconds() / 60
        types = ", ".join(set(self.event_types))
        anchor = "✓" if self.anchor_submitted else "pending"
        return (
            f"{self.started_at.strftime('%Y-%m-%d %H:%M')} | "
            f"{self.event_count} events | "
            f"{duration:.1f}min | "
            f"anchor: {anchor}"
        )


class SigchainStorage:
    """Store sigchain metadata in 1Password.
    
    This class manages a special 1Password secure note that tracks
    the sigchain state, providing:
    - Persistence across machine restarts
    - Sync across devices via 1Password
    - Human-readable audit trail in 1Password UI
    
    Example:
        >>> storage = SigchainStorage()
        >>> storage.save_chain_head(head)
        >>> loaded = storage.load_chain_head()
    """
    
    ITEM_TITLE = "Bastion Sigchain"
    ITEM_TAG = "Bastion/System/Sigchain"
    DEFAULT_VAULT = "Private"
    
    # Section names
    SECTION_HEAD = "Chain Head"
    SECTION_SESSIONS = "Recent Sessions"
    SECTION_ANCHORS = "OTS Anchors"
    
    def __init__(self, vault: str | None = None) -> None:
        """Initialize storage.
        
        Args:
            vault: 1Password vault name (default: Private)
        """
        self.vault = vault or self.DEFAULT_VAULT
        self._item_uuid: str | None = None
    
    def _run_op(self, args: list[str]) -> tuple[bool, str, str]:
        """Run an op CLI command.
        
        Args:
            args: Command arguments
            
        Returns:
            Tuple of (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                ["op"] + args,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return (
                result.returncode == 0,
                result.stdout,
                result.stderr,
            )
        except FileNotFoundError:
            return False, "", "1Password CLI not found"
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    def _find_item(self) -> str | None:
        """Find the sigchain item UUID.
        
        Returns:
            Item UUID or None if not found
        """
        if self._item_uuid:
            return self._item_uuid
        
        success, stdout, _ = self._run_op([
            "item", "list",
            "--vault", self.vault,
            "--tags", self.ITEM_TAG,
            "--format", "json",
        ])
        
        if not success:
            return None
        
        try:
            items = json.loads(stdout)
            for item in items:
                if item.get("title") == self.ITEM_TITLE:
                    self._item_uuid = item.get("id")
                    return self._item_uuid
        except json.JSONDecodeError:
            pass
        
        return None
    
    def _create_item(self) -> str | None:
        """Create the sigchain secure note.
        
        Returns:
            New item UUID or None on failure
        """
        # Build the create command
        cmd = [
            "item", "create",
            "--category", "secure note",
            "--title", self.ITEM_TITLE,
            "--vault", self.vault,
            "--tags", self.ITEM_TAG,
            f"{self.SECTION_HEAD}.Status[text]=Initialized",
            f"{self.SECTION_HEAD}.Created[text]={datetime.now(timezone.utc).isoformat()}",
            f"{self.SECTION_SESSIONS}.History[text]=No sessions yet",
            f"{self.SECTION_ANCHORS}.Status[text]=No anchors yet",
        ]
        
        success, stdout, stderr = self._run_op(cmd)
        
        if not success:
            console.print(f"[red]Failed to create sigchain item: {stderr}[/red]")
            return None
        
        # Parse UUID from output
        try:
            result = json.loads(stdout)
            self._item_uuid = result.get("id")
            return self._item_uuid
        except json.JSONDecodeError:
            # Try to find the newly created item
            return self._find_item()
    
    def _get_or_create_item(self) -> str | None:
        """Get existing item or create new one.
        
        Returns:
            Item UUID or None on failure
        """
        uuid = self._find_item()
        if uuid:
            return uuid
        return self._create_item()
    
    def save_chain_head(self, head: ChainHead) -> bool:
        """Save chain head state to 1Password.
        
        Args:
            head: ChainHead to save
            
        Returns:
            True if saved successfully
        """
        uuid = self._get_or_create_item()
        if not uuid:
            return False
        
        # Update fields
        cmd = [
            "item", "edit", uuid,
            "--vault", self.vault,
            f"{self.SECTION_HEAD}.Head Hash[text]={head.head_hash}",
            f"{self.SECTION_HEAD}.Sequence Number[text]={head.seqno}",
            f"{self.SECTION_HEAD}.Device[text]={head.device.value}",
            f"{self.SECTION_HEAD}.Last Updated[text]={datetime.now(timezone.utc).isoformat()}",
        ]
        
        if head.last_events_summary:
            cmd.append(f"{self.SECTION_HEAD}.Last Events[text]={head.last_events_summary}")
        
        success, _, stderr = self._run_op(cmd)
        
        if not success:
            console.print(f"[yellow]Warning: Failed to save chain head: {stderr}[/yellow]")
            return False
        
        return True
    
    def load_chain_head(self) -> ChainHead | None:
        """Load chain head state from 1Password.
        
        Returns:
            ChainHead or None if not found
        """
        uuid = self._find_item()
        if not uuid:
            return None
        
        success, stdout, _ = self._run_op([
            "item", "get", uuid,
            "--vault", self.vault,
            "--format", "json",
        ])
        
        if not success:
            return None
        
        try:
            item = json.loads(stdout)
            fields = self._parse_fields(item)
            
            head_hash = fields.get(f"{self.SECTION_HEAD}.Head Hash")
            seqno_str = fields.get(f"{self.SECTION_HEAD}.Sequence Number")
            device_str = fields.get(f"{self.SECTION_HEAD}.Device")
            
            if not head_hash or not seqno_str:
                return None
            
            return ChainHead(
                head_hash=head_hash,
                seqno=int(seqno_str),
                device=DeviceType(device_str) if device_str else DeviceType.MANAGER,
                last_events_summary=fields.get(f"{self.SECTION_HEAD}.Last Events"),
            )
        except (json.JSONDecodeError, ValueError, KeyError):
            return None
    
    def add_session_summary(self, summary: SessionSummary) -> bool:
        """Add a session summary to the history.
        
        Args:
            summary: Session summary to add
            
        Returns:
            True if added successfully
        """
        uuid = self._get_or_create_item()
        if not uuid:
            return False
        
        # Get existing history
        success, stdout, _ = self._run_op([
            "item", "get", uuid,
            "--vault", self.vault,
            "--format", "json",
        ])
        
        history_lines = []
        if success:
            try:
                item = json.loads(stdout)
                fields = self._parse_fields(item)
                existing = fields.get(f"{self.SECTION_SESSIONS}.History", "")
                if existing and existing != "No sessions yet":
                    history_lines = existing.split("\n")
            except json.JSONDecodeError:
                pass
        
        # Add new summary at top, keep last 10
        history_lines.insert(0, summary.to_display())
        history_lines = history_lines[:10]
        
        # Update field
        history_text = "\n".join(history_lines)
        
        success, _, stderr = self._run_op([
            "item", "edit", uuid,
            "--vault", self.vault,
            f"{self.SECTION_SESSIONS}.History[text]={history_text}",
        ])
        
        return success
    
    def update_anchor_status(
        self,
        pending_count: int,
        completed_count: int,
        last_anchor_time: datetime | None = None,
    ) -> bool:
        """Update OTS anchor status.
        
        Args:
            pending_count: Number of pending anchors
            completed_count: Number of completed anchors
            last_anchor_time: Time of last anchor submission
            
        Returns:
            True if updated successfully
        """
        uuid = self._get_or_create_item()
        if not uuid:
            return False
        
        status = f"Pending: {pending_count}, Confirmed: {completed_count}"
        if last_anchor_time:
            status += f"\nLast: {last_anchor_time.strftime('%Y-%m-%d %H:%M')}"
        
        success, _, _ = self._run_op([
            "item", "edit", uuid,
            "--vault", self.vault,
            f"{self.SECTION_ANCHORS}.Status[text]={status}",
        ])
        
        return success
    
    def _parse_fields(self, item: dict[str, Any]) -> dict[str, str]:
        """Parse fields from 1Password item JSON.
        
        Args:
            item: Raw item JSON
            
        Returns:
            Dict mapping "Section.Label" to value
        """
        fields = {}
        
        for field in item.get("fields", []):
            section = field.get("section", {}).get("label", "")
            label = field.get("label", "")
            value = field.get("value", "")
            
            if section and label:
                key = f"{section}.{label}"
            elif label:
                key = label
            else:
                continue
            
            fields[key] = value
        
        return fields
    
    def get_full_state(self) -> dict[str, Any] | None:
        """Get full sigchain state from 1Password.
        
        Returns:
            Dict with all stored state, or None if not found
        """
        uuid = self._find_item()
        if not uuid:
            return None
        
        success, stdout, _ = self._run_op([
            "item", "get", uuid,
            "--vault", self.vault,
            "--format", "json",
        ])
        
        if not success:
            return None
        
        try:
            item = json.loads(stdout)
            fields = self._parse_fields(item)
            
            return {
                "uuid": uuid,
                "head_hash": fields.get(f"{self.SECTION_HEAD}.Head Hash"),
                "seqno": fields.get(f"{self.SECTION_HEAD}.Sequence Number"),
                "device": fields.get(f"{self.SECTION_HEAD}.Device"),
                "last_updated": fields.get(f"{self.SECTION_HEAD}.Last Updated"),
                "session_history": fields.get(f"{self.SECTION_SESSIONS}.History"),
                "anchor_status": fields.get(f"{self.SECTION_ANCHORS}.Status"),
            }
        except json.JSONDecodeError:
            return None
    
    def delete_item(self) -> bool:
        """Delete the sigchain item (for testing/reset).
        
        Returns:
            True if deleted successfully
        """
        uuid = self._find_item()
        if not uuid:
            return True  # Already doesn't exist
        
        success, _, _ = self._run_op([
            "item", "delete", uuid,
            "--vault", self.vault,
        ])
        
        if success:
            self._item_uuid = None
        
        return success
