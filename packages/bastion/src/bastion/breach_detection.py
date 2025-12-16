"""Breach detection using Have I Been Pwned API."""

import hashlib
import time

import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .models import Account, Database
from .op_client import OpClient


class BreachDetector:
    """Check passwords against Have I Been Pwned database."""
    
    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    
    def __init__(self, console: Console):
        """Initialize breach detector."""
        self.console = console
    
    def _get_password_hash_prefix(self, password: str) -> tuple[str, str]:
        """
        Get SHA-1 hash of password and split into prefix/suffix for k-anonymity.
        
        Returns:
            Tuple of (first 5 chars, remaining chars)
        """
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        return sha1[:5], sha1[5:]
    
    def check_password(self, password: str) -> tuple[bool, int]:
        """
        Check if password has been breached using HIBP k-anonymity API.
        
        Args:
            password: Password to check
            
        Returns:
            Tuple of (is_breached, breach_count)
        """
        prefix, suffix = self._get_password_hash_prefix(password)
        
        try:
            response = httpx.get(
                f"{self.HIBP_API_URL}{prefix}",
                timeout=10.0,
                headers={"User-Agent": "SecurityAnalysisTool/2.0"},
            )
            response.raise_for_status()
            
            # Parse response: each line is "SUFFIX:COUNT"
            for line in response.text.splitlines():
                hash_suffix, count = line.split(":")
                if hash_suffix == suffix:
                    return True, int(count)
            
            return False, 0
        
        except httpx.HTTPError as e:
            self.console.print(f"[yellow]Warning: HIBP API error: {e}[/yellow]")
            return False, 0
    
    def check_account_from_1password(
        self,
        account: Account,
        op_client: OpClient,
    ) -> tuple[bool, int]:
        """
        Check if account password is breached by retrieving from 1Password.
        
        Args:
            account: Account to check
            op_client: 1Password CLI client
            
        Returns:
            Tuple of (is_breached, breach_count)
        """
        try:
            # Get password from 1Password
            item = op_client.get_item(account.uuid)
            if not item or "fields" not in item:
                return False, 0
            
            # Find password field
            password = None
            for field in item.get("fields", []):
                if field.get("type") == "CONCEALED" and field.get("purpose") == "PASSWORD":
                    password = field.get("value")
                    break
            
            if not password:
                self.console.print(f"[dim]No password field found for {account.title}[/dim]")
                return False, 0
            
            # Check against HIBP
            return self.check_password(password)
        
        except Exception as e:
            self.console.print(f"[yellow]Error checking {account.title}: {e}[/yellow]")
            return False, 0
    
    def scan_all_accounts(
        self,
        db: Database,
        op_client: OpClient,
        update_tags: bool = False,
    ) -> dict[str, tuple[bool, int]]:
        """
        Scan all accounts for breached passwords.
        
        Args:
            db: Database with accounts
            op_client: 1Password CLI client
            update_tags: If True, add bastion-sec-breach-exposed tag to breached accounts
            
        Returns:
            Dictionary mapping account UUID to (is_breached, breach_count)
        """
        results = {}
        breached_count = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
        ) as progress:
            task = progress.add_task(
                f"Checking {len(db.accounts)} passwords against HIBP...",
                total=len(db.accounts),
            )
            
            for uuid, account in db.accounts.items():
                progress.update(task, description=f"Checking {account.title}...")
                
                is_breached, count = self.check_account_from_1password(account, op_client)
                results[uuid] = (is_breached, count)
                
                if is_breached:
                    breached_count += 1
                    self.console.print(
                        f"[red]🚨 BREACH: {account.title} - "
                        f"password found {count:,} times in breaches[/red]"
                    )
                    
                    if update_tags and "Bastion/Security/Breach-Exposed" not in account.tag_list:
                        # Add breach tag
                        new_tags = account.tag_list + ["Bastion/Security/Breach-Exposed"]
                        account.tags = ", ".join(new_tags)
                        
                        # Update in 1Password
                        result = op_client.edit_item_tags(uuid, new_tags)
                        if result == "success":
                            self.console.print("  [green]✅ Tagged in 1Password[/green]")
                        else:
                            self.console.print(f"  [yellow]⚠️ Could not tag: {result}[/yellow]")
                
                progress.advance(task)
                
                # Rate limiting: HIBP allows ~1 request per 1.5 seconds
                time.sleep(1.6)
        
        # Summary
        self.console.print("\n[cyan]" + "=" * 60 + "[/cyan]")
        self.console.print("[bold]Breach Scan Complete[/bold]")
        self.console.print(f"  Total accounts: {len(db.accounts)}")
        self.console.print(f"  [red]Breached: {breached_count}[/red]")
        self.console.print(f"  [green]Clean: {len(db.accounts) - breached_count}[/green]")
        
        if breached_count > 0:
            self.console.print("\n[red]⚠️  ACTION REQUIRED: Rotate breached passwords immediately![/red]")
        
        self.console.print("[cyan]" + "=" * 60 + "[/cyan]")
        
        return results
