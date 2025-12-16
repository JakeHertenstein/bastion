"""Git log integration for sigchain audit trail.

Provides pretty-printing of sigchain history from git,
GPG signature verification, and log filtering.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .models import DeviceType, SigchainLink


console = Console()


@dataclass
class GitCommit:
    """Represents a git commit with signature status."""
    
    hash: str
    short_hash: str
    author: str
    date: datetime
    message: str
    gpg_status: str  # "G" = good, "B" = bad, "U" = unknown, "N" = no sig
    gpg_signer: str | None
    files_changed: list[str]


class SigchainGitLog:
    """Git log interface for the sigchain repository."""
    
    def __init__(self, sigchain_dir: Path | None = None) -> None:
        """Initialize git log interface.
        
        Args:
            sigchain_dir: Path to sigchain git repo
        """
        from ..config import BASTION_DIR
        
        self.sigchain_dir = sigchain_dir or BASTION_DIR / "sigchain"
    
    def get_commits(
        self,
        count: int = 20,
        verify_signatures: bool = True,
    ) -> list[GitCommit]:
        """Get recent commits from git log.
        
        Args:
            count: Maximum commits to return
            verify_signatures: Whether to verify GPG signatures
            
        Returns:
            List of GitCommit objects
        """
        if not (self.sigchain_dir / ".git").exists():
            return []
        
        # Git log format: hash|short|author|date|message|gpg_status|gpg_signer
        format_str = "%H|%h|%an|%aI|%s|%G?|%GS"
        
        cmd = ["git", "log", f"--format={format_str}", f"-n{count}"]
        if verify_signatures:
            cmd.append("--show-signature")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=self.sigchain_dir,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            return []
        
        commits = []
        for line in result.stdout.strip().split("\n"):
            if not line or "|" not in line:
                continue
            
            parts = line.split("|")
            if len(parts) < 7:
                continue
            
            commits.append(GitCommit(
                hash=parts[0],
                short_hash=parts[1],
                author=parts[2],
                date=datetime.fromisoformat(parts[3]),
                message=parts[4],
                gpg_status=parts[5] or "N",
                gpg_signer=parts[6] if parts[6] else None,
                files_changed=[],
            ))
        
        return commits
    
    def get_events_from_jsonl(
        self,
        date: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
    ) -> Iterator[tuple[SigchainLink, dict[str, Any]]]:
        """Read events from JSONL files.
        
        Args:
            date: Filter by date (YYYY-MM-DD)
            event_type: Filter by event type
            limit: Maximum events to return
            
        Yields:
            Tuples of (link, payload)
        """
        events_dir = self.sigchain_dir / "events"
        if not events_dir.exists():
            return
        
        # Get JSONL files, optionally filtered by date
        if date:
            files = [events_dir / f"{date}.jsonl"]
        else:
            files = sorted(events_dir.glob("*.jsonl"), reverse=True)
        
        count = 0
        for file_path in files:
            if not file_path.exists():
                continue
            
            with open(file_path) as f:
                for line in f:
                    if count >= limit:
                        return
                    
                    try:
                        entry = json.loads(line)
                        link = SigchainLink.model_validate(entry["link"])
                        payload = entry.get("payload", {})
                        
                        if event_type and link.event_type != event_type:
                            continue
                        
                        yield link, payload
                        count += 1
                        
                    except (json.JSONDecodeError, KeyError):
                        continue
    
    def print_log(
        self,
        count: int = 20,
        verify: bool = True,
        show_events: bool = True,
    ) -> None:
        """Pretty-print git log with optional event details.
        
        Args:
            count: Number of commits to show
            verify: Verify GPG signatures
            show_events: Include event summaries
        """
        commits = self.get_commits(count=count, verify_signatures=verify)
        
        if not commits:
            console.print("[yellow]No commits found in sigchain repository[/yellow]")
            return
        
        console.print(f"\n[bold]Sigchain Git Log[/bold] ({self.sigchain_dir})\n")
        
        for commit in commits:
            # Signature status indicator
            if commit.gpg_status == "G":
                sig_icon = "[green]✓[/green]"
                sig_text = f"Signed by {commit.gpg_signer}" if commit.gpg_signer else "Good signature"
            elif commit.gpg_status == "B":
                sig_icon = "[red]✗[/red]"
                sig_text = "Bad signature!"
            elif commit.gpg_status == "U":
                sig_icon = "[yellow]?[/yellow]"
                sig_text = "Unknown signer"
            else:
                sig_icon = "[dim]○[/dim]"
                sig_text = "Unsigned"
            
            # Format date
            date_str = commit.date.strftime("%Y-%m-%d %H:%M")
            
            console.print(
                f"{sig_icon} [cyan]{commit.short_hash}[/cyan] "
                f"[dim]{date_str}[/dim] "
                f"{commit.message}"
            )
            
            if verify and commit.gpg_status != "N":
                console.print(f"    [dim]{sig_text}[/dim]")
    
    def print_events(
        self,
        date: str | None = None,
        event_type: str | None = None,
        limit: int = 50,
    ) -> None:
        """Pretty-print events from JSONL files.
        
        Args:
            date: Filter by date
            event_type: Filter by event type
            limit: Maximum events
        """
        table = Table(title="Sigchain Events")
        table.add_column("#", style="cyan", width=6)
        table.add_column("Type", style="green", width=20)
        table.add_column("Device", width=8)
        table.add_column("Timestamp", width=19)
        table.add_column("Summary", style="dim")
        
        for link, payload in self.get_events_from_jsonl(
            date=date,
            event_type=event_type,
            limit=limit,
        ):
            # Device icon
            device_icon = "💻" if link.device == DeviceType.MANAGER else "🔒"
            
            # Build summary from payload
            summary = ""
            if "account_title" in payload:
                summary = payload["account_title"]
            elif "domain" in payload:
                summary = payload["domain"]
            elif "serial_number" in payload:
                summary = f"Pool #{payload['serial_number']}"
            
            table.add_row(
                str(link.seqno),
                link.event_type,
                f"{device_icon} {link.device.value[:3]}",
                link.source_timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(link.source_timestamp, datetime) else str(link.source_timestamp)[:19],
                summary[:40] + "..." if len(summary) > 40 else summary,
            )
        
        console.print(table)
    
    def verify_chain(self) -> tuple[bool, str]:
        """Verify the sigchain integrity.
        
        Returns:
            Tuple of (is_valid, message)
        """
        chain_file = self.sigchain_dir / "chain.json"
        if not chain_file.exists():
            return False, "Chain file not found"
        
        try:
            from .chain import Sigchain
            chain = Sigchain.load_from_file(chain_file)
            chain.verify(full=True)
            return True, f"Chain verified: {chain.seqno} events, head={chain.head_hash[:16]}..."
        except Exception as e:
            return False, f"Verification failed: {e}"
    
    def print_status(self) -> None:
        """Print overall sigchain status."""
        console.print("\n[bold]Sigchain Status[/bold]\n")
        
        # Check repo
        if not (self.sigchain_dir / ".git").exists():
            console.print("[yellow]⚠ Sigchain repository not initialized[/yellow]")
            console.print(f"  Run 'bastion session start' to create at {self.sigchain_dir}")
            return
        
        # Chain verification
        is_valid, message = self.verify_chain()
        if is_valid:
            console.print(f"[green]✓[/green] {message}")
        else:
            console.print(f"[red]✗[/red] {message}")
        
        # Git status
        commits = self.get_commits(count=1, verify_signatures=True)
        if commits:
            latest = commits[0]
            sig_status = {
                "G": "[green]signed[/green]",
                "B": "[red]BAD SIG[/red]",
                "U": "[yellow]unknown signer[/yellow]",
                "N": "[dim]unsigned[/dim]",
            }.get(latest.gpg_status, "unknown")
            
            console.print(f"  Latest commit: {latest.short_hash} ({sig_status})")
            console.print(f"  Date: {latest.date.strftime('%Y-%m-%d %H:%M')}")
        
        # Events summary
        events_dir = self.sigchain_dir / "events"
        if events_dir.exists():
            jsonl_files = list(events_dir.glob("*.jsonl"))
            console.print(f"  Event logs: {len(jsonl_files)} days")
