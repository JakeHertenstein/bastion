"""Sigchain session management — interactive CLI with auto-timeout.

The session manager provides:
- Persistent interactive session with sigchain state
- 15-minute inactivity timeout (configurable)
- Automatic OTS anchoring on session end
- GPG-signed git commits on session end
- Graceful shutdown handling
"""

from __future__ import annotations

import atexit
import json
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from rich.console import Console
from rich.prompt import Prompt

from .chain import Sigchain, SigchainError
from .models import ChainHead, DeviceType

if TYPE_CHECKING:
    from .events import EventPayload


console = Console()


class SessionTimeoutError(Exception):
    """Raised when session times out due to inactivity."""
    pass


class SessionManager:
    """Manages interactive sigchain sessions.
    
    A session maintains sigchain state, tracks pending events for OTS
    anchoring, and auto-terminates after a configurable inactivity period.
    
    Usage:
        session = SessionManager()
        session.start()
        # ... interactive operations ...
        session.end()
    
    Or as context manager:
        with SessionManager() as session:
            session.record_event(payload)
    """
    
    DEFAULT_TIMEOUT_MINUTES = 15
    
    def __init__(
        self,
        timeout_minutes: int | None = None,
        sigchain_dir: Path | None = None,
        device: DeviceType = DeviceType.MANAGER,
    ) -> None:
        """Initialize session manager.
        
        Args:
            timeout_minutes: Inactivity timeout (default: 15)
            sigchain_dir: Path to sigchain git repo (default: ~/.bastion/sigchain)
            device: Device type for this session
        """
        from ..config import BASTION_DIR, get_config
        
        config = get_config()
        self.timeout_minutes = timeout_minutes or config.get(
            "session", "timeout_minutes", self.DEFAULT_TIMEOUT_MINUTES
        )
        self.sigchain_dir = sigchain_dir or BASTION_DIR / "sigchain"
        self.device = device
        
        # Session state
        self.chain: Sigchain | None = None
        self.active = False
        self.session_start_time: datetime | None = None
        self.last_activity: datetime | None = None
        self.pending_anchor_start_seqno: int | None = None
        
        # Timeout thread
        self._timeout_thread: threading.Thread | None = None
        self._stop_timeout = threading.Event()
        
        # Signal handlers
        self._original_sigint: signal.Handlers | None = None
        self._original_sigterm: signal.Handlers | None = None
    
    def start(self) -> Sigchain:
        """Start an interactive session.
        
        Loads existing chain from disk, sets up timeout monitoring,
        and registers cleanup handlers.
        
        Returns:
            The sigchain instance for this session
        """
        if self.active:
            raise SigchainError("Session already active")
        
        console.print(f"\n[bold cyan]🔐 Starting Bastion session[/bold cyan]")
        console.print(f"   Timeout: {self.timeout_minutes} minutes of inactivity")
        
        # Ensure sigchain directory exists
        self.sigchain_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize git repo if needed
        self._init_git_repo()
        
        # Load or create chain
        chain_file = self.sigchain_dir / "chain.json"
        if chain_file.exists():
            self.chain = Sigchain.load_from_file(chain_file)
            console.print(f"   Loaded chain: {self.chain.seqno} events")
        else:
            self.chain = Sigchain(device=self.device)
            console.print("   Created new chain")
        
        # Record starting point for OTS anchor
        self.pending_anchor_start_seqno = self.chain.seqno + 1
        
        # Start session
        self.active = True
        self.session_start_time = datetime.now(timezone.utc)
        self.last_activity = self.session_start_time
        
        # Setup cleanup handlers
        self._setup_signal_handlers()
        atexit.register(self._atexit_handler)
        
        # Start timeout monitor
        self._start_timeout_monitor()
        
        console.print(f"   Session started at {self.session_start_time.strftime('%H:%M:%S')}\n")
        
        return self.chain
    
    def end(self, anchor: bool = True, commit: bool = True) -> None:
        """End the session gracefully.
        
        Args:
            anchor: Submit OTS anchor for session events
            commit: GPG-sign and commit to git
        """
        if not self.active:
            return
        
        console.print(f"\n[bold cyan]🔒 Ending Bastion session[/bold cyan]")
        
        # Stop timeout monitor
        self._stop_timeout.set()
        if self._timeout_thread:
            self._timeout_thread.join(timeout=1)
        
        # Restore signal handlers
        self._restore_signal_handlers()
        
        # Remove atexit handler
        try:
            atexit.unregister(self._atexit_handler)
        except Exception:
            pass
        
        if self.chain:
            events_this_session = self.chain.seqno - (self.pending_anchor_start_seqno or 1) + 1
            if events_this_session < 0:
                events_this_session = 0
            
            console.print(f"   Events this session: {events_this_session}")
            
            # Save chain
            chain_file = self.sigchain_dir / "chain.json"
            self.chain.save_to_file(chain_file)
            console.print(f"   Saved chain to {chain_file}")
            
            # Export session events to JSONL
            if events_this_session > 0:
                self._export_session_events()
            
            # Submit OTS anchor
            if anchor and events_this_session > 0:
                self._submit_ots_anchor()
            
            # Git commit
            if commit:
                self._git_commit()
        
        self.active = False
        duration = datetime.now(timezone.utc) - (self.session_start_time or datetime.now(timezone.utc))
        console.print(f"   Session duration: {duration.total_seconds() / 60:.1f} minutes\n")
    
    def record_event(self, payload: EventPayload) -> None:
        """Record an event to the chain.
        
        Updates last activity time to prevent timeout.
        
        Args:
            payload: Event payload to record
        """
        if not self.active or not self.chain:
            raise SigchainError("No active session")
        
        self.chain.append(payload)
        self.last_activity = datetime.now(timezone.utc)
    
    def touch(self) -> None:
        """Update last activity time to prevent timeout."""
        self.last_activity = datetime.now(timezone.utc)
    
    def get_remaining_time(self) -> float:
        """Get remaining time before timeout in seconds."""
        if not self.last_activity:
            return 0
        
        elapsed = (datetime.now(timezone.utc) - self.last_activity).total_seconds()
        remaining = (self.timeout_minutes * 60) - elapsed
        return max(0, remaining)
    
    # =========================================================================
    # Private Methods
    # =========================================================================
    
    def _init_git_repo(self) -> None:
        """Initialize git repository if not exists."""
        git_dir = self.sigchain_dir / ".git"
        if git_dir.exists():
            return
        
        console.print("   Initializing git repository...")
        subprocess.run(
            ["git", "init"],
            cwd=self.sigchain_dir,
            capture_output=True,
            check=True,
        )
        
        # Create .gitignore
        gitignore = self.sigchain_dir / ".gitignore"
        gitignore.write_text("*.tmp\n*.bak\n")
        
        # Initial commit
        subprocess.run(
            ["git", "add", ".gitignore"],
            cwd=self.sigchain_dir,
            capture_output=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "Initialize sigchain repository"],
            cwd=self.sigchain_dir,
            capture_output=True,
        )
    
    def _export_session_events(self) -> None:
        """Export session events to daily JSONL file."""
        if not self.chain or not self.pending_anchor_start_seqno:
            return
        
        events_dir = self.sigchain_dir / "events"
        events_dir.mkdir(exist_ok=True)
        
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        events_file = events_dir / f"{today}.jsonl"
        
        # Append to existing file
        with open(events_file, "a") as f:
            for line in self.chain.export_events_jsonl(
                start_seqno=self.pending_anchor_start_seqno,
                end_seqno=self.chain.seqno,
            ):
                f.write(line + "\n")
        
        console.print(f"   Exported events to {events_file.name}")
    
    def _submit_ots_anchor(self) -> None:
        """Submit OTS anchor for session events."""
        if not self.chain or not self.pending_anchor_start_seqno:
            return
        
        # Check if we have events to anchor
        if self.pending_anchor_start_seqno > self.chain.seqno:
            return
        
        merkle_root = self.chain.get_merkle_root(
            start_seqno=self.pending_anchor_start_seqno,
            end_seqno=self.chain.seqno,
        )
        
        console.print(f"   Merkle root: {merkle_root[:16]}...")
        
        # TODO: Integrate with OTS client when implemented
        # For now, just record the anchor event
        from .events import OTSAnchorPayload
        
        anchor_payload = OTSAnchorPayload(
            merkle_root=merkle_root,
            events_start_seqno=self.pending_anchor_start_seqno,
            events_end_seqno=self.chain.seqno,
            calendars=["alice.btc.calendar.opentimestamps.org"],
            pending_proof_hash="",  # Will be filled by OTS client
        )
        
        self.chain.append(anchor_payload)
        console.print(f"   OTS anchor recorded (pending submission)")
    
    def _git_commit(self) -> None:
        """Create GPG-signed git commit."""
        try:
            # Stage changes
            subprocess.run(
                ["git", "add", "-A"],
                cwd=self.sigchain_dir,
                capture_output=True,
                check=True,
            )
            
            # Check if there are changes to commit
            result = subprocess.run(
                ["git", "status", "--porcelain"],
                cwd=self.sigchain_dir,
                capture_output=True,
                text=True,
            )
            
            if not result.stdout.strip():
                console.print("   No changes to commit")
                return
            
            # Create commit message
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            events_count = (self.chain.seqno - (self.pending_anchor_start_seqno or 1) + 1) if self.chain else 0
            message = f"Session end: {events_count} events @ {timestamp}"
            
            # Try GPG-signed commit first, fall back to unsigned
            commit_cmd = ["git", "commit", "-S", "-m", message]
            result = subprocess.run(
                commit_cmd,
                cwd=self.sigchain_dir,
                capture_output=True,
                text=True,
            )
            
            if result.returncode != 0:
                # Try without GPG signing
                console.print("   [yellow]GPG signing failed, committing unsigned[/yellow]")
                commit_cmd = ["git", "commit", "-m", message]
                subprocess.run(
                    commit_cmd,
                    cwd=self.sigchain_dir,
                    capture_output=True,
                    check=True,
                )
            
            console.print(f"   Git commit: {message[:50]}...")
            
        except subprocess.CalledProcessError as e:
            console.print(f"   [yellow]Git commit failed: {e}[/yellow]")
    
    def _start_timeout_monitor(self) -> None:
        """Start background thread to monitor inactivity."""
        self._stop_timeout.clear()
        self._timeout_thread = threading.Thread(
            target=self._timeout_loop,
            daemon=True,
            name="sigchain-timeout",
        )
        self._timeout_thread.start()
    
    def _timeout_loop(self) -> None:
        """Background loop checking for timeout."""
        while not self._stop_timeout.is_set():
            if self.get_remaining_time() <= 0:
                console.print("\n[yellow]⏰ Session timeout - auto-ending...[/yellow]")
                # End session from main thread
                self.end(anchor=True, commit=True)
                break
            
            # Check every 10 seconds
            self._stop_timeout.wait(10)
    
    def _setup_signal_handlers(self) -> None:
        """Install signal handlers for graceful shutdown."""
        self._original_sigint = signal.signal(signal.SIGINT, self._signal_handler)
        self._original_sigterm = signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _restore_signal_handlers(self) -> None:
        """Restore original signal handlers."""
        if self._original_sigint:
            signal.signal(signal.SIGINT, self._original_sigint)
        if self._original_sigterm:
            signal.signal(signal.SIGTERM, self._original_sigterm)
    
    def _signal_handler(self, signum: int, frame) -> None:
        """Handle interrupt signals gracefully."""
        console.print(f"\n[yellow]Received signal {signum}, ending session...[/yellow]")
        self.end(anchor=True, commit=True)
        sys.exit(128 + signum)
    
    def _atexit_handler(self) -> None:
        """Handle process exit."""
        if self.active:
            console.print("\n[yellow]Process exiting, ending session...[/yellow]")
            self.end(anchor=True, commit=True)
    
    # =========================================================================
    # Context Manager
    # =========================================================================
    
    def __enter__(self) -> SessionManager:
        """Enter session context."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit session context."""
        self.end(anchor=True, commit=True)


# =============================================================================
# Interactive REPL
# =============================================================================

def run_interactive_session(
    timeout_minutes: int | None = None,
    callback: Callable[[SessionManager, str], bool] | None = None,
) -> None:
    """Run an interactive sigchain session with REPL.
    
    Args:
        timeout_minutes: Override default timeout
        callback: Function to handle commands (return False to exit)
    """
    with SessionManager(timeout_minutes=timeout_minutes) as session:
        console.print("[bold]Bastion Interactive Session[/bold]")
        console.print("Type 'help' for commands, 'quit' to exit\n")
        
        while session.active:
            try:
                remaining = session.get_remaining_time()
                prompt = f"bastion [{remaining/60:.0f}m] > "
                
                cmd = Prompt.ask(prompt)
                session.touch()
                
                if cmd.lower() in ("quit", "exit", "q"):
                    break
                
                if cmd.lower() == "help":
                    _print_help()
                    continue
                
                if cmd.lower() == "status":
                    _print_status(session)
                    continue
                
                # Custom callback for additional commands
                if callback:
                    if not callback(session, cmd):
                        break
                        
            except (KeyboardInterrupt, EOFError):
                console.print("\n")
                break


def _print_help() -> None:
    """Print help for interactive session."""
    console.print("""
[bold]Commands:[/bold]
  help    - Show this help
  status  - Show session status
  quit    - End session
  
[dim]Activity keeps the session alive. Session auto-ends after timeout.[/dim]
""")


def _print_status(session: SessionManager) -> None:
    """Print session status."""
    if not session.chain:
        console.print("[yellow]No chain loaded[/yellow]")
        return
    
    console.print(f"""
[bold]Session Status[/bold]
  Chain events:  {session.chain.seqno}
  This session:  {session.chain.seqno - (session.pending_anchor_start_seqno or 1) + 1}
  Head hash:     {session.chain.head_hash[:16] if session.chain.head_hash else 'N/A'}...
  Time left:     {session.get_remaining_time()/60:.1f} minutes
""")
