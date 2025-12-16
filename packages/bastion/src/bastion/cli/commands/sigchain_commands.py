"""Sigchain CLI commands for Bastion.

Commands for managing the audit sigchain:
  - session: Interactive session management
  - sigchain: Chain inspection and verification
  - ots: OpenTimestamps anchor management
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from bastion.config import (
    get_config,
    get_sigchain_dir,
    get_sigchain_log_path,
    get_sigchain_head_path,
    get_ots_pending_dir,
)
from bastion.sigchain import (
    Sigchain,
    ChainHead,
    SigchainGitLog,
)
from bastion.sigchain.session import SessionManager, run_interactive_session
from bastion.ots import OTSAnchor, OTSCalendar, check_ots_available

console = Console()

# =============================================================================
# SIGCHAIN APP (bastion sigchain ...)
# =============================================================================

sigchain_app = typer.Typer(
    name="sigchain",
    help="Audit sigchain management and verification",
    no_args_is_help=True,
)


@sigchain_app.command("status")
def sigchain_status() -> None:
    """Show sigchain status and statistics."""
    head_path = get_sigchain_head_path()
    log_path = get_sigchain_log_path()
    
    # Load chain head if exists
    if head_path.exists():
        head = ChainHead.model_validate_json(head_path.read_text())
        
        table = Table(title="Sigchain Status", box=box.ROUNDED)
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Latest Seqno", str(head.seqno))
        table.add_row("Head Hash", head.head_hash[:16] + "...")
        table.add_row("Device", head.device.value)
        
        if head.last_anchor_time:
            table.add_row("Last Anchor Time", head.last_anchor_time.strftime("%Y-%m-%d %H:%M:%S UTC"))
        if head.last_anchor_block:
            table.add_row("Last Anchor Block", str(head.last_anchor_block))
        
        console.print(table)
        
        # Count events in log
        if log_path.exists():
            with open(log_path, encoding="utf-8") as f:
                event_count = sum(1 for _ in f)
            console.print(f"\n📜 Events in log: {event_count}")
    else:
        console.print("[yellow]No sigchain initialized yet.[/yellow]")
        console.print("Start a session with: [cyan]bastion session start[/cyan]")


@sigchain_app.command("log")
def sigchain_log(
    limit: Annotated[int, typer.Option("--limit", "-n", help="Number of entries to show")] = 20,
    show_hashes: Annotated[bool, typer.Option("--hashes", help="Show full hashes")] = False,
    date_filter: Annotated[Optional[str], typer.Option("--date", "-d", help="Filter by date (YYYY-MM-DD)")] = None,
    event_type_filter: Annotated[Optional[str], typer.Option("--type", "-t", help="Filter by event type")] = None,
) -> None:
    """Show sigchain event log."""
    sigchain_dir = get_sigchain_dir()
    
    git_log = SigchainGitLog(sigchain_dir)
    events = list(git_log.get_events_from_jsonl(
        date=date_filter,
        event_type=event_type_filter,
        limit=limit,
    ))
    
    if not events:
        console.print("[yellow]No events in sigchain log.[/yellow]")
        return
    
    table = Table(title=f"Sigchain Events (last {limit})", box=box.ROUNDED)
    table.add_column("#", style="dim")
    table.add_column("Type", style="cyan")
    table.add_column("Summary")
    table.add_column("Timestamp", style="dim")
    if show_hashes:
        table.add_column("Hash", style="dim")
    
    for link, payload in events:
        # Build summary from payload
        summary: str = ""
        if "account_title" in payload:
            summary = str(payload["account_title"])
        elif "domain" in payload:
            summary = str(payload["domain"])
        elif "serial_number" in payload:
            summary = f"Pool #{payload['serial_number']}"
        
        timestamp_str = link.source_timestamp.strftime("%Y-%m-%d %H:%M")
        
        row: list[str] = [
            str(link.seqno),
            link.event_type,
            summary[:50] if summary else "",
            timestamp_str,
        ]
        if show_hashes:
            row.append(link.payload_hash[:12] + "...")
        table.add_row(*row)
    
    console.print(table)


@sigchain_app.command("verify")
def sigchain_verify(
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show detailed output")] = False,
) -> None:
    """Verify sigchain integrity."""
    sigchain_dir = get_sigchain_dir()
    
    console.print("[cyan]Verifying sigchain integrity...[/cyan]")
    
    git_log = SigchainGitLog(sigchain_dir)
    valid, message = git_log.verify_chain()
    
    if valid:
        console.print(f"[green]✓ {message}[/green]")
        if verbose:
            events = list(git_log.get_events_from_jsonl(limit=1000))
            console.print(f"  Total events: {len(events)}")
            if events:
                console.print(f"  First seqno: {events[0][0].seqno}")
                console.print(f"  Last seqno: {events[-1][0].seqno}")
    else:
        console.print(f"[red]✗ {message}[/red]")
        raise typer.Exit(1)


@sigchain_app.command("export")
def sigchain_export(
    output: Annotated[Path, typer.Option("--output", "-o", help="Output file path")],
    output_format: Annotated[str, typer.Option("--format", "-f", help="Export format")] = "json",
) -> None:
    """Export sigchain to file."""
    sigchain_dir = get_sigchain_dir()
    chain_file = sigchain_dir / "chain.json"
    
    if not chain_file.exists():
        console.print("[yellow]No sigchain found.[/yellow]")
        raise typer.Exit(1)
    
    chain = Sigchain.load_from_file(chain_file)
    
    if output_format == "json":
        import json
        output.write_text(json.dumps(
            [link.model_dump(mode="json") for link in chain.links],
            indent=2
        ))
    else:
        # JSONL format
        with open(output, "w", encoding="utf-8") as f:
            for line in chain.export_events_jsonl():
                f.write(line + "\n")
    
    console.print(f"[green]Exported {len(chain.links)} events to {output}[/green]")


# =============================================================================
# SESSION APP (bastion session ...)
# =============================================================================

session_app = typer.Typer(
    name="session",
    help="Interactive session management",
    no_args_is_help=True,
)


@session_app.command("start")
def session_start(
    interactive: Annotated[bool, typer.Option("--interactive", "-i", help="Start interactive REPL")] = True,
    timeout: Annotated[Optional[int], typer.Option("--timeout", "-t", help="Session timeout in minutes")] = None,
) -> None:
    """Start a new session.
    
    Sessions provide:
    - Automatic event logging to sigchain
    - Batch anchoring with OpenTimestamps
    - GPG-signed Git commits
    - 15-minute inactivity timeout (configurable)
    """
    config = get_config()
    timeout_mins = timeout or config.session_timeout_minutes
    
    console.print(Panel.fit(
        "[cyan]Starting Bastion Manager Session[/cyan]\n\n"
        f"• Timeout: {timeout_mins} minutes\n"
        f"• GPG Signing: {'enabled' if config.gpg_sign_commits else 'disabled'}\n"
        f"• OTS Anchoring: {'enabled' if config.ots_enabled else 'disabled'}",
        title="Session",
        border_style="cyan",
    ))
    
    if interactive:
        run_interactive_session(timeout_minutes=timeout_mins)
    else:
        # Non-interactive mode - just create session
        session = SessionManager(timeout_minutes=timeout_mins)
        session.start()
        console.print("\n[green]Session started[/green]")
        console.print("Use [cyan]bastion session end[/cyan] to end the session.")


@session_app.command("end")
def session_end() -> None:
    """End the current session and anchor events."""
    # This would need session state persistence to work properly
    # For now, interactive sessions handle their own cleanup
    console.print("[yellow]Use Ctrl+D or 'exit' in interactive sessions.[/yellow]")
    console.print("Non-interactive sessions must be ended programmatically.")


# =============================================================================
# OTS APP (bastion ots ...)
# =============================================================================

ots_app = typer.Typer(
    name="ots",
    help="OpenTimestamps anchor management",
    no_args_is_help=True,
)


@ots_app.command("status")
def ots_status() -> None:
    """Show OpenTimestamps anchor status."""
    available, msg = check_ots_available()
    
    if not available:
        console.print(f"[yellow]{msg}[/yellow]")
        console.print("\nInstall with: [cyan]pip install opentimestamps-client[/cyan]")
        return
    
    console.print("[green]✓ OpenTimestamps CLI available[/green]\n")
    
    # Show anchor statistics
    ots_anchor = OTSAnchor(get_ots_pending_dir().parent)
    stats = ots_anchor.get_stats()
    
    table = Table(title="Anchor Statistics", box=box.ROUNDED)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Pending Anchors", str(stats["pending_count"]))
    table.add_row("Completed Anchors", str(stats["completed_count"]))
    table.add_row("Events Pending", str(stats["total_events_pending"]))
    table.add_row("Events Anchored", str(stats["total_events_anchored"]))
    
    console.print(table)


@ots_app.command("pending")
def ots_pending() -> None:
    """List pending timestamp anchors."""
    ots_anchor = OTSAnchor(get_ots_pending_dir().parent)
    pending = ots_anchor.load_pending()
    
    if not pending:
        console.print("[green]No pending anchors[/green]")
        return
    
    table = Table(title="Pending Anchors", box=box.ROUNDED)
    table.add_column("Session", style="cyan")
    table.add_column("Merkle Root", style="dim")
    table.add_column("Events")
    table.add_column("Created", style="dim")
    table.add_column("Attempts")
    
    for anchor in pending:
        table.add_row(
            anchor.session_id[:8] + "...",
            anchor.merkle_root[:12] + "...",
            str(anchor.event_count),
            anchor.created_at.strftime("%Y-%m-%d %H:%M"),
            str(anchor.upgrade_attempts),
        )
    
    console.print(table)


@ots_app.command("upgrade")
def ots_upgrade() -> None:
    """Attempt to upgrade pending anchors with Bitcoin attestations."""
    available, msg = check_ots_available()
    if not available:
        console.print(f"[red]{msg}[/red]")
        raise typer.Exit(1)
    
    ots_anchor = OTSAnchor(get_ots_pending_dir().parent)
    calendar = OTSCalendar()
    pending = ots_anchor.load_pending()
    
    if not pending:
        console.print("[green]No pending anchors to upgrade[/green]")
        return
    
    console.print(f"[cyan]Attempting to upgrade {len(pending)} pending anchors...[/cyan]\n")
    
    upgraded = 0
    for anchor in pending:
        console.print(f"  Checking {anchor.merkle_root[:12]}... ", end="")
        
        if anchor.ots_proof_pending:
            from bastion.ots.client import OTSProof
            
            proof = OTSProof(
                digest=anchor.merkle_root,
                proof_data=anchor.ots_proof_pending,
            )
            
            upgraded_proof = calendar.upgrade(proof)
            
            if upgraded_proof.bitcoin_attested:
                console.print("[green]✓ Upgraded[/green]")
                upgraded += 1
                
                # Convert to completed anchor
                from bastion.ots.anchor import CompletedAnchor
                completed = CompletedAnchor(
                    merkle_root=anchor.merkle_root,
                    session_id=anchor.session_id,
                    created_at=anchor.created_at,
                    seqno_range=anchor.seqno_range,
                    event_count=anchor.event_count,
                    ots_proof=upgraded_proof.proof_data,
                    bitcoin_block_height=upgraded_proof.block_height,
                    bitcoin_block_hash=upgraded_proof.block_hash,
                    bitcoin_timestamp=upgraded_proof.block_time,
                )
                ots_anchor.save_completed(completed)
            else:
                console.print("[yellow]Still pending[/yellow]")
                anchor.upgrade_attempts += 1
                anchor.last_upgrade_attempt = datetime.now(timezone.utc)
                ots_anchor.save_pending(anchor)
        else:
            console.print("[dim]No proof data[/dim]")
    
    console.print(f"\n[green]Upgraded {upgraded}/{len(pending)} anchors[/green]")


@ots_app.command("verify")
def ots_verify(
    seqno: Annotated[int, typer.Argument(help="Sigchain sequence number to verify")],
) -> None:
    """Verify OTS proof for a specific sigchain event."""
    ots_anchor = OTSAnchor(get_ots_pending_dir().parent)
    anchor = ots_anchor.get_anchor_for_seqno(seqno)
    
    if not anchor:
        console.print(f"[yellow]No anchor found containing seqno {seqno}[/yellow]")
        raise typer.Exit(1)
    
    from bastion.ots.anchor import PendingAnchor
    
    if isinstance(anchor, PendingAnchor):
        console.print(f"[yellow]Seqno {seqno} is in a pending anchor (not yet Bitcoin-attested)[/yellow]")
        console.print(f"  Merkle root: {anchor.merkle_root[:16]}...")
        console.print(f"  Created: {anchor.created_at}")
        console.print("  Run [cyan]bastion ots upgrade[/cyan] to check for attestation")
    else:
        console.print(f"[green]✓ Seqno {seqno} is Bitcoin-attested[/green]")
        console.print(f"  Merkle root: {anchor.merkle_root[:16]}...")
        if anchor.bitcoin_block_height:
            console.print(f"  Bitcoin block: {anchor.bitcoin_block_height}")
        if anchor.bitcoin_timestamp:
            console.print(f"  Block time: {anchor.bitcoin_timestamp}")


# =============================================================================
# IMPORT APP (bastion import ...)
# =============================================================================

import_app = typer.Typer(
    name="import",
    help="Import data from airgap machine",
    no_args_is_help=True,
)


@import_app.command("salt")
def import_salt(
    input_file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Read from file instead of scanner")] = None,
    vault: Annotated[str, typer.Option("--vault", "-v", help="1Password vault")] = "Private",
    passphrase: Annotated[Optional[str], typer.Option("--passphrase", "-p", help="GPG passphrase (for non-YubiKey)")] = None,
) -> None:
    """Import encrypted salt from airgap via QR scanner.
    
    Reads GPG-encrypted salt data from scanner input (or file), decrypts it
    using your GPG key (may require YubiKey touch), and stores it in 1Password
    for use with the username generator.
    
    The scanner input is collected until the -----END PGP MESSAGE----- marker
    is detected.
    
    Examples:
        bastion import salt                    # Scan QR codes from scanner
        bastion import salt --file salt.gpg   # Read from file
        bastion import salt -v Personal        # Store in Personal vault
    """
    import subprocess
    import json
    import sys
    
    from bastion.sigchain.gpg import get_encryptor, DecryptionResult
    
    console.print(Panel.fit(
        "[bold cyan]Salt Import from Airgap[/bold cyan]\n\n"
        "Imports GPG-encrypted salt from airgap machine.\n"
        "Requires your GPG private key (YubiKey touch if configured).",
        title="🔐 import salt",
    ))
    
    # Step 1: Collect encrypted data
    if input_file:
        if not input_file.exists():
            console.print(f"[red]File not found: {input_file}[/red]")
            raise typer.Exit(1)
        encrypted_data = input_file.read_text()
        console.print(f"[dim]Read {len(encrypted_data)} bytes from {input_file}[/dim]")
    else:
        console.print("\n[cyan]Step 1: Scan QR code(s)...[/cyan]")
        console.print("[dim]Waiting for scanner input. Multi-QR codes supported.[/dim]")
        console.print("[dim]Scanning ends when -----END PGP MESSAGE----- is detected.[/dim]")
        console.print()
        
        # Collect scanner input
        collected_parts: dict[int, str] = {}
        total_parts: Optional[int] = None
        buffer: list[str] = []
        
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                
                # Check for multi-QR protocol
                if line.startswith("BASTION:"):
                    # Parse: BASTION:seq/total:data
                    try:
                        _, seq_total, data = line.split(":", 2)
                        seq, tot = map(int, seq_total.split("/"))
                        collected_parts[seq] = data
                        total_parts = tot
                        console.print(f"  [green]✓ Part {seq}/{tot} received[/green]")
                        
                        # Check if complete
                        if len(collected_parts) == total_parts:
                            console.print("[green]All parts received![/green]")
                            break
                    except ValueError:
                        # Not valid multi-QR, treat as raw data
                        buffer.append(line)
                else:
                    # Raw data (single QR or file)
                    buffer.append(line)
                    
                    # Check for end marker
                    if "-----END PGP MESSAGE-----" in line:
                        console.print("[green]End marker detected[/green]")
                        break
                        
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled[/yellow]")
            raise typer.Exit(1)
        
        # Reassemble data
        if collected_parts:
            # Multi-QR: combine in sequence order
            encrypted_data = "".join(
                collected_parts[i] for i in range(1, (total_parts or 0) + 1)
            )
        else:
            # Single QR or raw input
            encrypted_data = "\n".join(buffer)
        
        console.print(f"[dim]Collected {len(encrypted_data)} bytes[/dim]")
    
    if "-----BEGIN PGP MESSAGE-----" not in encrypted_data:
        console.print("[red]Invalid input: No PGP message detected[/red]")
        raise typer.Exit(1)
    
    # Step 2: Decrypt with GPG
    console.print("\n[cyan]Step 2: Decrypting with GPG...[/cyan]")
    console.print("[dim]Touch YubiKey if prompted...[/dim]")
    
    encryptor = get_encryptor()
    try:
        result: DecryptionResult = encryptor.decrypt(
            encrypted_data.encode(),
            passphrase=passphrase,
        )
        if not result.success:
            console.print(f"[red]Decryption failed: {result.error}[/red]")
            raise typer.Exit(1)
        
        console.print("[green]✓ Decryption successful[/green]")
        if result.signer_key:
            console.print(f"  Signed by: {result.signer_key}")
    except Exception as e:
        console.print(f"[red]Decryption error: {e}[/red]")
        raise typer.Exit(1)
    
    # Step 3: Parse salt payload
    console.print("\n[cyan]Step 3: Parsing salt payload...[/cyan]")
    
    try:
        payload = json.loads(result.plaintext.decode())
        salt_b64 = payload.get("salt_b64")
        salt_bits = payload.get("bits")
        entropy_source = payload.get("entropy_source", "unknown")
        entropy_quality = payload.get("entropy_quality", "unknown")
        created_at = payload.get("created_at", "unknown")
        
        if not salt_b64:
            console.print("[red]Invalid payload: missing salt_b64[/red]")
            raise typer.Exit(1)
        
        console.print(f"  Salt bits: {salt_bits}")
        console.print(f"  Entropy: {entropy_source} ({entropy_quality})")
        console.print(f"  Created: {created_at}")
    except json.JSONDecodeError as e:
        console.print(f"[red]Invalid JSON payload: {e}[/red]")
        raise typer.Exit(1)
    
    # Step 4: Store in 1Password
    console.print(f"\n[cyan]Step 4: Storing in 1Password ({vault})...[/cyan]")
    
    try:
        # Create item with salt
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        title = f"Username Salt ({today})"
        
        # Build op command
        cmd = [
            "op", "item", "create",
            "--category", "Secure Note",
            "--title", title,
            "--vault", vault,
            "--tags", "Bastion/SALT/username",
            f"Salt[password]={salt_b64}",
            f"Metadata.Bits[text]={salt_bits}",
            f"Metadata.Entropy Source[text]={entropy_source}",
            f"Metadata.Entropy Quality[text]={entropy_quality}",
            f"Metadata.Created[text]={created_at}",
            f"Metadata.Imported[text]={datetime.now(timezone.utc).isoformat()}",
        ]
        
        op_result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if op_result.returncode != 0:
            console.print(f"[red]1Password error: {op_result.stderr}[/red]")
            raise typer.Exit(1)
        
        # Parse result for UUID
        import re
        uuid_match = re.search(r'"id":\s*"([^"]+)"', op_result.stdout)
        item_uuid = uuid_match.group(1) if uuid_match else "unknown"
        
        console.print(f"[green]✓ Salt stored in 1Password[/green]")
        console.print(f"  Title: {title}")
        console.print(f"  UUID: {item_uuid}")
        console.print(f"  Vault: {vault}")
        
    except subprocess.TimeoutExpired:
        console.print("[red]1Password operation timed out[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]1Password error: {e}[/red]")
        raise typer.Exit(1)
    
    # Step 5: Instructions for next steps
    console.print("\n" + "=" * 60)
    console.print("[bold green]✓ Salt import complete![/bold green]")
    console.print("=" * 60)
    console.print("\nNext steps:")
    console.print(f"  1. Verify: [cyan]op item get '{title}' --vault {vault}[/cyan]")
    console.print(f"  2. Initialize username generator: [cyan]bastion generate username --init[/cyan]")
    console.print("  3. Generate usernames: [cyan]bastion generate username github.com[/cyan]")


@import_app.command("pubkey")
def import_pubkey(
    input_file: Annotated[Optional[Path], typer.Option("--file", "-f", help="Read from file instead of scanner")] = None,
) -> None:
    """Import GPG public key from airgap via QR scanner.
    
    Reads an ASCII-armored public key from scanner input or file and imports
    it into the local GPG keyring for encrypting data back to airgap.
    
    Examples:
        bastion import pubkey                    # Scan QR codes from scanner
        bastion import pubkey --file key.asc    # Read from file
    """
    import subprocess
    import sys
    
    console.print(Panel.fit(
        "[bold cyan]Public Key Import[/bold cyan]\n\n"
        "Imports GPG public key from airgap machine.\n"
        "Used for encrypting responses back to airgap.",
        title="🔑 import pubkey",
    ))
    
    # Collect key data
    if input_file:
        if not input_file.exists():
            console.print(f"[red]File not found: {input_file}[/red]")
            raise typer.Exit(1)
        key_data = input_file.read_text()
        console.print(f"[dim]Read {len(key_data)} bytes from {input_file}[/dim]")
    else:
        console.print("\n[cyan]Scan public key QR code(s)...[/cyan]")
        console.print("[dim]Scanning ends when -----END PGP PUBLIC KEY BLOCK----- is detected.[/dim]")
        console.print()
        
        collected_parts: dict[int, str] = {}
        total_parts: Optional[int] = None
        buffer: list[str] = []
        
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith("BASTION:"):
                    try:
                        _, seq_total, data = line.split(":", 2)
                        seq, tot = map(int, seq_total.split("/"))
                        collected_parts[seq] = data
                        total_parts = tot
                        console.print(f"  [green]✓ Part {seq}/{tot} received[/green]")
                        
                        if len(collected_parts) == total_parts:
                            console.print("[green]All parts received![/green]")
                            break
                    except ValueError:
                        buffer.append(line)
                else:
                    buffer.append(line)
                    if "-----END PGP PUBLIC KEY BLOCK-----" in line:
                        console.print("[green]End marker detected[/green]")
                        break
                        
        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled[/yellow]")
            raise typer.Exit(1)
        
        if collected_parts:
            key_data = "".join(
                collected_parts[i] for i in range(1, (total_parts or 0) + 1)
            )
        else:
            key_data = "\n".join(buffer)
    
    if "-----BEGIN PGP PUBLIC KEY BLOCK-----" not in key_data:
        console.print("[red]Invalid input: No public key detected[/red]")
        raise typer.Exit(1)
    
    # Import key
    console.print("\n[cyan]Importing key into GPG keyring...[/cyan]")
    
    try:
        result = subprocess.run(
            ["gpg", "--import"],
            input=key_data.encode(),
            capture_output=True,
            timeout=10,
        )
        
        if result.returncode != 0:
            console.print(f"[red]Import failed: {result.stderr.decode()}[/red]")
            raise typer.Exit(1)
        
        # Parse imported key info from stderr
        stderr = result.stderr.decode()
        console.print(f"[green]✓ Key imported successfully[/green]")
        
        # Show key details
        import re
        key_match = re.search(r'key ([A-F0-9]+):', stderr)
        if key_match:
            key_id = key_match.group(1)
            console.print(f"  Key ID: {key_id}")
            
            # Show full key info
            info_result = subprocess.run(
                ["gpg", "--list-keys", key_id],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if info_result.returncode == 0:
                console.print(f"\n[dim]{info_result.stdout}[/dim]")
                
    except subprocess.TimeoutExpired:
        console.print("[red]GPG operation timed out[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Import error: {e}[/red]")
        raise typer.Exit(1)


# =============================================================================
# REGISTRATION
# =============================================================================

def register_commands(app: typer.Typer) -> None:
    """Register sigchain commands with the main app."""
    app.add_typer(sigchain_app, name="sigchain", help="Audit sigchain management")
    app.add_typer(session_app, name="session", help="Interactive session management")
    app.add_typer(ots_app, name="ots", help="OpenTimestamps anchoring")
    app.add_typer(import_app, name="import", help="Import data from airgap")
