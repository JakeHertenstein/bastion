"""Export command helpers for Bastion CLI."""

import json
from pathlib import Path

from rich.console import Console

from ...op_client import OpClient

console = Console()


def export_tagging_candidates(output_path: Path) -> None:
    """Find and export items without Bastion/* tags.
    
    Args:
        output_path: Path to write JSON output
    """
    console.print("[cyan]Finding items without Bastion/* tags...[/cyan]")
    
    op_client = OpClient()
    all_items = op_client.list_items()
    
    candidates = []
    for item in all_items:
        # Get full item details
        full_item = op_client.get_item(item["id"])
        tags = full_item.get("tags", [])
        
        # Check if item has any Bastion/* tags
        has_bastion_tag = any(tag.startswith("Bastion/") for tag in tags)
        
        if not has_bastion_tag:
            candidate = {
                "uuid": item["id"],
                "title": item["title"],
                "category": full_item.get("category", "unknown"),
                "vault": item.get("vault", {}).get("name", "unknown"),
                "tags": tags,
                "urls": [url.get("href", "") for url in full_item.get("urls", [])],
                "notes": full_item.get("notesPlain", "")[:200] if full_item.get("notesPlain") else "",
            }
            candidates.append(candidate)
    
    with open(output_path, "w") as f:
        json.dump(candidates, f, indent=2)
    
    console.print(f"[green]✅ Exported {len(candidates)} candidates to {output_path}[/green]")
    console.print("\n[dim]You can now review these items and apply appropriate Bastion/* tags[/dim]")
