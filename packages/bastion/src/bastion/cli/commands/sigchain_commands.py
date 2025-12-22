"""Sigchain CLI commands for Bastion.

Commands for managing the audit sigchain:
  - session: Interactive session management
  - sigchain: Chain inspection and verification
  - ots: OpenTimestamps anchor management
"""

from __future__ import annotations

import base64
import json
import zlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from bastion.config import (
    get_config,
    get_ots_pending_dir,
    get_sigchain_dir,
    get_sigchain_head_path,
    get_sigchain_log_path,
)
from bastion.ots import OTSAnchor, OTSCalendar, check_ots_available
from bastion.qr import decode_qr_payloads, generate_qr_terminal, split_for_qr
from bastion.sigchain import (
    ChainHead,
    Sigchain,
    SigchainGitLog,
    gpg_decrypt,
    gpg_import_public_key,
)
from bastion.sigchain.session import SessionManager, run_interactive_session
from bastion.username_generator import UsernameGenerator, UsernameGeneratorConfig

console = Console()


def _collect_qr_payloads(prompt_title: str, max_parts: int) -> list[str]:
    """Prompt user to paste QR payloads (single or multi-part)."""
    console.print(f"[cyan]{prompt_title}[/cyan]")
    console.print("Paste each scanned QR payload (leave blank to finish).")
    payloads: list[str] = []
    part = 1
    while part <= max_parts:
        entry = typer.prompt(f"QR part {part}", default="")
        if not entry.strip():
            break
        payloads.append(entry.strip())
        part += 1
    return payloads

# =============================================================================
# SIGCHAIN APP (bastion sigchain ...)
# =============================================================================

sigchain_app = typer.Typer(
    name="sigchain",
    help="Audit sigchain management and verification",
    no_args_is_help=True,
)


import_app = typer.Typer(
    name="import",
    help="Import encrypted payloads (salt, pubkey) via QR or file",
    no_args_is_help=True,
)

sigchain_app.add_typer(import_app, name="import")


@import_app.command("pubkey")
def import_pubkey(
    file: Annotated[Path | None, typer.Option("--file", "-f", help="Path to ASCII-armored public key or QR payload")] = None,
    gpg_path: Annotated[str, typer.Option("--gpg-path", help="Path to gpg binary")] = "gpg",
    max_parts: Annotated[int, typer.Option("--max-parts", help="Maximum QR parts to accept")] = 25,
) -> None:
    """Import a public key into the manager keyring."""
    try:
        if file:
            payload = file.read_bytes()
        else:
            qr_strings = _collect_qr_payloads("Paste QR payload(s) for public key", max_parts)
            if not qr_strings:
                console.print("[yellow]No QR data provided.[/yellow]")
                raise typer.Exit(1)
            payload_str = decode_qr_payloads(qr_strings)
            payload = payload_str.encode()
        key_id = gpg_import_public_key(payload, gpg_path=gpg_path)
        console.print(f"[green]✓ Imported public key[/green] (key id: {key_id})")
    except Exception as exc:
        console.print(f"[red]Import failed:[/red] {exc}")
        raise typer.Exit(1)


@import_app.command("salt")
def import_salt(
    file: Annotated[Path | None, typer.Option("--file", "-f", help="Path to encrypted salt payload (ASCII armor or QR text)")] = None,
    vault: Annotated[str, typer.Option("--vault", "-v", help="1Password vault to store imported salt")] = "Private",
    gpg_path: Annotated[str, typer.Option("--gpg-path", help="Path to gpg binary")] = "gpg",
    max_parts: Annotated[int, typer.Option("--max-parts", help="Maximum QR parts to accept")] = 25,
) -> None:
    """Import an encrypted salt from airgap via QR or file."""
    try:
        if file:
            encrypted_payload = file.read_text().strip()
        else:
            qr_strings = _collect_qr_payloads("Paste QR payload(s) for encrypted salt", max_parts)
            if not qr_strings:
                console.print("[yellow]No QR data provided.[/yellow]")
                raise typer.Exit(1)
            encrypted_payload = decode_qr_payloads(qr_strings)
        plaintext = gpg_decrypt(encrypted_payload.encode(), gpg_path=gpg_path).decode()
        payload = json.loads(plaintext)
        salt_b64 = payload.get("salt")
        if not salt_b64:
            raise RuntimeError("Decrypted payload missing 'salt'")
        salt_bytes = base64.b64decode(salt_b64)
        salt_hex = salt_bytes.hex()
        config = UsernameGeneratorConfig()
        generator = UsernameGenerator(config=config)
        salt_value, salt_uuid, serial = generator.create_salt_item(
            salt=salt_hex,
            vault=vault,
        )
        console.print(f"[green]✓ Imported salt[/green] into vault [bold]{vault}[/bold]")
        console.print(f"[dim]UUID: {salt_uuid} • Serial: {serial} • Bits: {payload.get('bits', len(salt_bytes)*8)} • Source: {payload.get('entropy_source', 'unknown')}[/dim]")
    except Exception as exc:
        console.print(f"[red]Salt import failed:[/red] {exc}")
        raise typer.Exit(1)


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
    date_filter: Annotated[str | None, typer.Option("--date", "-d", help="Filter by date (YYYY-MM-DD)")] = None,
    event_type_filter: Annotated[str | None, typer.Option("--type", "-t", help="Filter by event type")] = None,
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


@sigchain_app.command("export-qr")
def sigchain_export_qr(
    max_bytes: Annotated[int, typer.Option("--max-bytes", help="Max bytes per QR code")] = 2000,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Optional file to write QR payloads (newline separated)")] = None,
) -> None:
    """Export sigchain as QR payloads (compressed base64)."""
    chain_file = get_sigchain_dir() / "chain.json"
    if not chain_file.exists():
        console.print("[yellow]No sigchain found.[/yellow]")
        raise typer.Exit(1)
    raw = chain_file.read_text()
    compressed = zlib.compress(raw.encode("utf-8"), level=9)
    payload = base64.b64encode(compressed).decode()
    parts = split_for_qr(payload, max_bytes=max_bytes)
    console.print(f"[cyan]QR parts:[/cyan] {len(parts)}")
    if output:
        output.write_text("\n".join(p.to_qr_string() for p in parts), encoding="utf-8")
        console.print(f"[green]✓ Wrote QR payloads to {output}[/green]")
    for part in parts:
        console.print(f"\n[bold]Part {part.sequence}/{part.total}[/bold] ({len(part.data)} chars)")
        console.print(generate_qr_terminal(part.to_qr_string()))


@sigchain_app.command("import-qr")
def sigchain_import_qr(
    file: Annotated[Path | None, typer.Option("--file", "-f", help="File with QR payloads (newline separated)")] = None,
    output: Annotated[Path | None, typer.Option("--output", "-o", help="Write decoded chain JSON to file (default: sigchain-import.json)")] = None,
    apply_chain: Annotated[bool, typer.Option("--apply", help="Overwrite local chain.json with imported data")] = False,
    max_parts: Annotated[int, typer.Option("--max-parts", help="Maximum QR parts to accept interactively")] = 25,
) -> None:
    """Import sigchain data from QR payloads."""
    try:
        if file:
            qr_strings = [line.strip() for line in file.read_text().splitlines() if line.strip()]
        else:
            qr_strings = _collect_qr_payloads("Paste QR payload(s) for sigchain", max_parts)
        if not qr_strings:
            console.print("[yellow]No QR data provided.[/yellow]")
            raise typer.Exit(1)
        payload = decode_qr_payloads(qr_strings)
        compressed = base64.b64decode(payload)
        json_text = zlib.decompress(compressed).decode()
        json.loads(json_text)  # validation only
        if apply_chain:
            chain_file = get_sigchain_dir() / "chain.json"
            chain_file.parent.mkdir(parents=True, exist_ok=True)
            chain_file.write_text(json_text, encoding="utf-8")
            console.print(f"[green]✓ Applied imported chain to {chain_file}[/green]")
        else:
            out_path = output or Path("sigchain-import.json")
            out_path.write_text(json_text, encoding="utf-8")
            console.print(f"[green]✓ Wrote decoded chain to {out_path}[/green]")
    except Exception as exc:
        console.print(f"[red]Import failed:[/red] {exc}")
        raise typer.Exit(1)


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
    timeout: Annotated[int | None, typer.Option("--timeout", "-t", help="Session timeout in minutes")] = None,
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
                anchor.last_upgrade_attempt = datetime.now(UTC)
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
# REGISTRATION
# =============================================================================

def register_commands(app: typer.Typer) -> None:
    """Register sigchain commands with the main app."""
    app.add_typer(sigchain_app, name="sigchain", help="Audit sigchain management")
    app.add_typer(session_app, name="session", help="Interactive session management")
    app.add_typer(ots_app, name="ots", help="OpenTimestamps anchoring")
