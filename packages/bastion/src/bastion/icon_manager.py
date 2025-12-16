"""Icon management for YubiKey OATH accounts using aegis-icons.

This module handles embedding aegis-icons as attachments in 1Password items,
matching OATH account names to appropriate icons, and exporting icon packs.

Strategy: Store icons as file attachments in 1Password items (Strategy A).
This keeps all data self-contained in the vault.
"""

import json
import subprocess
import re
import hashlib
from pathlib import Path
from typing import Optional
from rich.console import Console

console = Console()


class IconManager:
    """Manage aegis-icons for YubiKey OATH accounts."""
    
    # Common issuer aliases for icon matching
    ISSUER_ALIASES = {
        "google": ["google", "gmail", "google workspace"],
        "microsoft": ["microsoft", "outlook", "office365", "azure"],
        "github": ["github"],
        "amazon": ["amazon", "aws", "amazon web services"],
        "apple": ["apple", "icloud"],
        "dropbox": ["dropbox"],
        "facebook": ["facebook", "meta"],
        "twitter": ["twitter", "x"],
        "linkedin": ["linkedin"],
        "reddit": ["reddit"],
        "discord": ["discord"],
        "slack": ["slack"],
        "cloudflare": ["cloudflare"],
        "digitalocean": ["digitalocean"],
        "heroku": ["heroku"],
        "notion": ["notion"],
        "paypal": ["paypal"],
        "stripe": ["stripe"],
        "twitch": ["twitch"],
        "zoom": ["zoom"],
        "ubiquiti": ["unifi", "ubiquiti", "ui"],
        "fidelity": ["fidelity", "fidelity investments"],
    }
    
    def __init__(self, aegis_icons_dir: Optional[Path] = None):
        """Initialize icon manager.
        
        Args:
            aegis_icons_dir: Path to aegis-icons repository (SVG files)
                           If None, will look for it in common locations
        """
        self.aegis_icons_dir = aegis_icons_dir or self._find_aegis_icons()
        
    def _find_aegis_icons(self) -> Optional[Path]:
        """Try to locate aegis-icons repository."""
        # Common locations - try both SVG and PNG
        candidates = [
            Path.home() / "repos" / "aegis-icons" / "icons" / "1_Primary",
            Path.home() / "repos" / "aegis-icons" / "PNG",
            Path.home() / "Downloads" / "aegis-icons" / "icons" / "1_Primary",
            Path.home() / "Downloads" / "aegis-icons" / "PNG",
            Path("/opt/aegis-icons/icons/1_Primary"),
            Path("/opt/aegis-icons/PNG"),
        ]
        
        # Also check in current workspace
        workspace_candidates = [
            Path.cwd() / "aegis-icons" / "icons" / "1_Primary",
            Path.cwd() / "aegis-icons" / "PNG",
        ]
        candidates = workspace_candidates + candidates
        
        for path in candidates:
            if path.exists() and path.is_dir():
                return path
        
        return None
    
    def _get_file_checksum(self, file_path: Path) -> str:
        """Get SHA256 checksum of file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Hex digest of SHA256 checksum
        """
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def normalize_issuer(self, issuer: str) -> str:
        """Normalize issuer name for matching.
        
        Args:
            issuer: Raw issuer name (e.g., "Google (personal)")
            
        Returns:
            Normalized issuer (e.g., "google")
        """
        # Remove disambiguation and special chars
        issuer = re.sub(r'\s*\([^)]*\)', '', issuer)  # Remove (personal), etc.
        issuer = issuer.lower().strip()
        issuer = re.sub(r'[^a-z0-9]', '', issuer)  # Keep only alphanumeric
        return issuer
    
    def match_icon(self, issuer: str, custom_mapping: Optional[dict] = None) -> Optional[str]:
        """Match issuer to icon filename.
        
        Args:
            issuer: Issuer name (e.g., "Google", "Google (personal)")
            custom_mapping: Optional dict of issuer -> icon_filename overrides
            
        Returns:
            Icon filename (e.g., "google.png") or None if no match
        """
        # 1. Check custom mapping first
        if custom_mapping and issuer in custom_mapping:
            return custom_mapping[issuer]
        
        # 2. Normalize issuer
        normalized = self.normalize_issuer(issuer)
        
        # 3. Try direct match (prefer SVG, fallback to PNG)
        if self.aegis_icons_dir:
            for ext in [".svg", ".png"]:
                direct_path = self.aegis_icons_dir / f"{normalized}{ext}"
                if direct_path.exists():
                    return f"{normalized}{ext}"
        
        # 4. Try aliases (prefer SVG, fallback to PNG)
        for icon_name, aliases in self.ISSUER_ALIASES.items():
            if normalized in aliases:
                if self.aegis_icons_dir:
                    for ext in [".svg", ".png"]:
                        icon_path = self.aegis_icons_dir / f"{icon_name}{ext}"
                        if icon_path.exists():
                            return f"{icon_name}{ext}"
                # Fallback if no directory
                return f"{icon_name}.svg"
        
        # 5. No match found
        return None
    
    def get_icon_path(self, icon_filename: str) -> Optional[Path]:
        """Get full path to icon file.
        
        Args:
            icon_filename: Icon filename (e.g., "google.png")
            
        Returns:
            Full path to icon file or None if not found
        """
        if not self.aegis_icons_dir:
            return None
        
        icon_path = self.aegis_icons_dir / icon_filename
        return icon_path if icon_path.exists() else None
    
    def attach_icon_to_item(self, item_uuid: str, icon_filename: str) -> bool:
        """Attach icon file to 1Password item.
        
        Args:
            item_uuid: 1Password item UUID
            icon_filename: Icon filename (e.g., "google.png")
            
        Returns:
            True if successful, False otherwise
        """
        import os
        
        # Validate file extension
        valid_extensions = {'.png', '.svg', '.jpg', '.jpeg'}
        _, ext = os.path.splitext(icon_filename.lower())
        if ext not in valid_extensions:
            console.print(f"[yellow]Invalid icon file extension: {icon_filename} (must be .png, .svg, .jpg, or .jpeg)[/yellow]")
            return False
        
        icon_path = self.get_icon_path(icon_filename)
        if not icon_path:
            console.print(f"[yellow]Icon not found: {icon_filename}[/yellow]")
            return False
        
        # Verify file exists and is readable
        if not os.path.isfile(icon_path):
            console.print(f"[yellow]Icon file not accessible: {icon_path}[/yellow]")
            return False
        
        try:
            # First, remove legacy fields if they exist (Icon, Icon Filename)
            # These were created with the old format that didn't preserve extensions
            try:
                subprocess.run(
                    ["op", "item", "edit", item_uuid, "Icons.Icon[delete]"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError:
                pass  # Field may not exist
            
            try:
                subprocess.run(
                    ["op", "item", "edit", item_uuid, "Icons.Icon Filename[delete]"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError:
                pass  # Field may not exist
            
            # Attach file using op CLI field syntax in Icons section
            # Escape dots in filename so 1Password preserves extension for preview support
            escaped_filename = icon_filename.replace(".", "\\.")
            result = subprocess.run(
                ["op", "item", "edit", item_uuid, f"Icons.{escaped_filename}[file]={icon_path}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            return True
            
        except subprocess.CalledProcessError as e:
            console.print(f"[red]Failed to attach icon: {e.stderr}[/red]")
            return False
    
    def get_attached_icons(self, item_uuid: str) -> list[dict]:
        """Get list of attached files from 1Password item.
        
        Args:
            item_uuid: 1Password item UUID
            
        Returns:
            List of attachment info dicts with 'id' and 'name' keys
        """
        try:
            result = subprocess.run(
                ["op", "item", "get", item_uuid, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            item_data = json.loads(result.stdout)
            files = item_data.get("files", [])
            
            return [{"id": f.get("id"), "name": f.get("name")} for f in files]
            
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            return []
    
    def export_icon_from_item(self, item_uuid: str, output_dir: Path, icon_name: Optional[str] = None) -> Optional[Path]:
        """Export icon attachment from 1Password item.
        
        Args:
            item_uuid: 1Password item UUID
            output_dir: Directory to save icon
            icon_name: Optional specific icon filename to export (if multiple attachments)
            
        Returns:
            Path to exported file or None if failed
        """
        try:
            # Get item details including files
            result = subprocess.run(
                ["op", "item", "get", item_uuid, "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            item_data = json.loads(result.stdout)
            files = item_data.get("files", [])
            
            if not files:
                return None
            
            # Find the icon file in Icons section
            target_file = None
            for f in files:
                section = f.get("section", {})
                if section.get("label") == "Icons":
                    target_file = f
                    break
            
            if not target_file:
                return None
            
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Get the icon filename from Icon Filename field
            icon_filename = target_file.get("name", "icon.svg")
            for field in item_data.get("fields", []):
                if (field.get("label") == "Icon Filename" and 
                    field.get("section", {}).get("label") == "Icons"):
                    icon_filename = field.get("value", icon_filename)
                    break
            
            output_path = output_dir / icon_filename
            
            # Get vault name
            vault_name = item_data.get("vault", {}).get("name", "Private")
            
            # Remove existing file to avoid overwrite prompt
            if output_path.exists():
                output_path.unlink()
            
            # Download file using op read with correct vault name
            subprocess.run(
                ["op", "read", f"op://{vault_name}/{item_uuid}/Icons/Icon", f"--out-file={output_path}"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            return output_path
            
        except subprocess.CalledProcessError:
            # Item may not exist or have attachments - this is expected for some items
            return None
        except json.JSONDecodeError:
            # Malformed response from op CLI
            return None
    
    def auto_match_and_attach_all(self, dry_run: bool = False, force: bool = False) -> dict:
        """Auto-match and attach icons for all YubiKey OATH accounts.
        
        Args:
            dry_run: If True, only show what would be done
            force: If True, re-attach icons even if already present
            
        Returns:
            Dict with statistics: matched, attached, skipped, failed
        """
        stats = {"matched": 0, "attached": 0, "skipped": 0, "failed": 0}
        
        try:
            # Get all items with Bastion/2FA/TOTP/YubiKey tag
            result = subprocess.run(
                ["op", "item", "list", "--tags", "Bastion/2FA/TOTP/YubiKey", "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            items = json.loads(result.stdout)
            
            for item in items:
                uuid = item.get("id", "")
                title = item.get("title", "")
                
                # Get full item to check for existing icons and oath_name
                detail_result = subprocess.run(
                    ["op", "item", "get", uuid, "--format", "json"],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=30,
                )
                
                detail_data = json.loads(detail_result.stdout)
                
                # Check if already has icon attachment
                if detail_data.get("files") and not force:
                    console.print(f"[dim]⏭️  {title}: Already has attachment[/dim]")
                    stats["skipped"] += 1
                    continue
                
                # Get OATH Name from Token sections (look for any "OATH Name" field)
                oath_name = None
                for field in detail_data.get("fields", []):
                    if field.get("label") == "OATH Name" and field.get("value"):
                        oath_name = field.get("value")
                        break
                
                if not oath_name:
                    console.print(f"[yellow]⚠️  {title}: No OATH Name found[/yellow]")
                    stats["skipped"] += 1
                    continue
                
                # Extract issuer from oath_name (format: "Issuer:account" or "Issuer")
                issuer = oath_name.split(":")[0] if ":" in oath_name else oath_name
                
                # Match icon
                icon_filename = self.match_icon(issuer)
                
                if not icon_filename:
                    console.print(f"[yellow]❓ {title}: No icon match for '{issuer}'[/yellow]")
                    stats["failed"] += 1
                    continue
                
                stats["matched"] += 1
                console.print(f"[cyan]✓ {title}: Matched '{issuer}' → {icon_filename}[/cyan]")
                
                if not dry_run:
                    if self.attach_icon_to_item(uuid, icon_filename):
                        stats["attached"] += 1
                        console.print(f"[green]  ✅ Attached {icon_filename}[/green]")
                    else:
                        stats["failed"] += 1
                        console.print("[red]  ❌ Failed to attach[/red]")
            
            return stats
            
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            console.print(f"[red]Error: {e}[/red]")
            return stats
    
    def export_all_icons(self, output_dir: Path) -> int:
        """Export all icons from YubiKey OATH items to directory.
        
        Detects conflicts when multiple items have same icon filename but different content.
        Skips duplicates (same filename and checksum).
        
        Args:
            output_dir: Directory to save icons
            
        Returns:
            Number of unique icons exported
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        count = 0
        
        try:
            # Get all items with Bastion/2FA/TOTP/YubiKey tag
            result = subprocess.run(
                ["op", "item", "list", "--tags", "Bastion/2FA/TOTP/YubiKey", "--format", "json"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            
            items = json.loads(result.stdout)
            
            # Track exported icons and their checksums
            exported_icons = {}  # filename -> (checksum, title)
            
            for item in items:
                uuid = item.get("id", "")
                title = item.get("title", "")
                
                exported_path = self.export_icon_from_item(uuid, output_dir)
                if exported_path:
                    # Get checksum of exported file
                    checksum = self._get_file_checksum(exported_path)
                    filename = exported_path.name
                    
                    # Check if we've seen this filename before
                    if filename in exported_icons:
                        prev_checksum, prev_title = exported_icons[filename]
                        if checksum != prev_checksum:
                            console.print(f"[yellow]⚠️  {title}: Icon '{filename}' differs from {prev_title}[/yellow]")
                            # Rename to avoid conflict
                            conflict_path = output_dir / f"{exported_path.stem}_conflict_{count}{exported_path.suffix}"
                            exported_path.rename(conflict_path)
                            console.print(f"    Saved as {conflict_path.name}")
                            exported_icons[conflict_path.name] = (checksum, title)
                            count += 1
                        else:
                            console.print(f"[cyan]✓ {title}: Icon matches {prev_title} (skipped duplicate)[/cyan]")
                            # File is already correct, no need to keep this copy
                            # (it was re-exported from 1P and overwrote the original, but checksums match)
                    else:
                        exported_icons[filename] = (checksum, title)
                        console.print(f"[green]✓ {title}: Exported {filename}[/green]")
                        count += 1
                else:
                    console.print(f"[dim]⏭️  {title}: No icon attached[/dim]")
            
            return count
            
        except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
            console.print(f"[red]Error: {e}[/red]")
            return count
