"""Report generation."""

from rich.console import Console

from .models import Database


class ReportGenerator:
    """Generate rotation status reports."""

    def __init__(self, console: Console):
        self.console = console

    def generate_report(self, db: Database) -> None:
        """Generate full rotation status report."""
        self.console.print("\n[bold cyan]=" * 50 + "[/bold cyan]")
        self.console.print("[bold cyan]PASSWORD ROTATION STATUS REPORT[/bold cyan]")
        self.console.print("[bold cyan]=" * 50 + "[/bold cyan]\n")
        
        self.console.print(f"Last Sync: {db.metadata.last_sync or 'Never'}")
        self.console.print(f"Compromise Baseline: {db.metadata.compromise_baseline}\n")
        
        # Summary counts
        total = len(db.accounts)
        pre_baseline = sum(1 for a in db.accounts.values() if a.is_pre_baseline)
        overdue = sum(1 for a in db.accounts.values() if a.days_until_rotation is not None and a.days_until_rotation < 0)
        due_soon = sum(1 for a in db.accounts.values() if a.days_until_rotation is not None and 0 <= a.days_until_rotation <= 30)
        
        self.console.print("[bold]📊 Summary:[/bold]")
        self.console.print(f"  Total Accounts: {total}")
        self.console.print(f"  🔴 Pre-Baseline (URGENT): {pre_baseline}")
        self.console.print(f"  🟡 Overdue: {overdue}")
        self.console.print(f"  🟠 Due Soon (30 days): {due_soon}\n")
        
        # Pre-baseline passwords
        if pre_baseline > 0:
            self.console.print("[bold red]🔴 URGENT: Pre-Baseline Passwords[/bold red]")
            self.console.print("━" * 60)
            for account in db.accounts.values():
                if account.is_pre_baseline:
                    self.console.print(f"  ⚠️  {account.title} ({account.tier}) - Last changed: {account.last_password_change}")
            self.console.print()
        
        # Overdue
        if overdue > 0:
            self.console.print("[bold yellow]🟡 OVERDUE: Passwords Past Rotation Date[/bold yellow]")
            self.console.print("━" * 60)
            for account in db.accounts.values():
                if account.days_until_rotation is not None and account.days_until_rotation < 0:
                    self.console.print(f"  ⏰ {account.title} - Overdue by {-account.days_until_rotation} days (Next: {account.next_rotation_date})")
            self.console.print()
        
        # Due soon
        if due_soon > 0:
            self.console.print("[bold]🟠 DUE SOON: Passwords Expiring in 30 Days[/bold]")
            self.console.print("━" * 60)
            for account in db.accounts.values():
                if account.days_until_rotation is not None and 0 <= account.days_until_rotation <= 30:
                    self.console.print(f"  📅 {account.title} - {account.days_until_rotation} days (Next: {account.next_rotation_date})")
            self.console.print()
        
        # 2FA risks
        fido2_count = sum(1 for a in db.accounts.values() if a.has_fido2)
        totp_count = sum(1 for a in db.accounts.values() if a.has_totp)
        sms_count = sum(1 for a in db.accounts.values() if a.has_sms)
        no2fa_count = sum(1 for a in db.accounts.values() if a.has_no2fa)
        downgraded_count = sum(1 for a in db.accounts.values() if a.is_2fa_downgraded)
        
        if sms_count > 0 or no2fa_count > 0 or downgraded_count > 0:
            self.console.print("[bold yellow]⚠️  2FA SECURITY RISKS:[/bold yellow]")
            self.console.print("━" * 60)
            if fido2_count > 0:
                self.console.print(f"  🟢 FIDO2/YubiKey: {fido2_count} accounts")
            if totp_count > 0:
                self.console.print(f"  🟡 TOTP Only: {totp_count} accounts")
            if sms_count > 0:
                self.console.print(f"  🔴 SMS Only (HIGH RISK): {sms_count} accounts")
            if no2fa_count > 0:
                self.console.print(f"  🔴 No 2FA (CRITICAL): {no2fa_count} accounts")
            if downgraded_count > 0:
                self.console.print(f"  ⚠️  2FA Downgraded: {downgraded_count} accounts")
            self.console.print()
            
            # List critical risks
            if sms_count > 0 or no2fa_count > 0:
                self.console.print("[bold red]🔴 CRITICAL 2FA RISKS:[/bold red]")
                for account in db.accounts.values():
                    if account.has_sms or account.has_no2fa:
                        self.console.print(f"  • {account.title} ({account.tier}) - 2FA: {account.twofa_method or 'Unknown'} - {account.risk_notes or 'No notes'}")
                self.console.print()
