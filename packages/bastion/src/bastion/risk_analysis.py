"""Risk analysis and scoring for accounts."""

from collections import defaultdict
from typing import Any

from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table

from .models import Account, RiskLevel, TwoFAMethod


class RiskAnalyzer:
    """Analyze and compute risk scores for accounts."""

    def __init__(self, accounts: dict[str, Account]):
        """Initialize with account data."""
        self.accounts = accounts
        self.dependency_graph = self._build_dependency_graph()

    def _build_dependency_graph(self) -> dict[str, list[str]]:
        """
        Build dependency graph with email recovery as default.

        Returns mapping of account_uuid -> list of account_uuids it can recover.

        Algorithm:
        1. Find accounts with Bastion/Capability/Recovery or Bastion/Capability/Identity (email accounts)
        2. DEFAULT: Assume all accounts are recoverable by email
        3. EXCEPTION: Skip accounts with Bastion/Dependency/No-Email-Recovery tag
        4. Match recovery_email from username against email accounts
        5. ALTERNATE: Also check alternate_recovery_email field for secondary recovery

        IMPORTANT: Most accounts are recoverable by email. Use Bastion/Dependency/No-Email-Recovery
        tag for exceptions (like 1Password which requires Secret Key + Master Password).

        ALTERNATE RECOVERY: Accounts with alternate_recovery_email field will create
        additional dependency edges (e.g., Square can be recovered by both primary and
        alternate email accounts).
        """
        graph = defaultdict(list)

        # Find accounts with recovery capability (identity providers, email accounts)
        recovery_accounts = {
            uuid: acc for uuid, acc in self.accounts.items()
            if "Bastion/Capability/Recovery" in acc.capabilities or "Bastion/Capability/Identity" in acc.capabilities
        }

        # Build edges: Default to email recovery unless explicitly excluded
        for uuid, account in self.accounts.items():
            # EXCEPTION: Skip accounts that cannot be recovered by email
            if "Bastion/Dependency/No-Email-Recovery" in account.dependencies:
                continue

            # Extract the primary email this account uses
            recovery_email = account.recovery_email
            if not recovery_email:
                # No email in username - cannot match, skip
                continue

            # Match primary recovery email
            for rec_uuid, rec_acc in recovery_accounts.items():
                # Must be an email account
                if "Bastion/Type/Email" not in rec_acc.tag_list:
                    continue

                # Check if recovery account's username matches our recovery email
                if rec_acc.username and recovery_email.lower() in rec_acc.username.lower():
                    if uuid not in graph[rec_uuid]:
                        graph[rec_uuid].append(uuid)
                # Or if the account title contains the email (e.g., "Gmail - jake@example.com")
                elif recovery_email.lower() in rec_acc.title.lower():
                    if uuid not in graph[rec_uuid]:
                        graph[rec_uuid].append(uuid)

            # ALTERNATE RECOVERY: Check alternate_recovery_email field
            if account.alternate_recovery_email:
                alternate_email = account.alternate_recovery_email

                for rec_uuid, rec_acc in recovery_accounts.items():
                    if "Bastion/Type/Email" not in rec_acc.tag_list:
                        continue

                    # Match alternate email against recovery accounts
                    if rec_acc.username and alternate_email.lower() in rec_acc.username.lower():
                        if uuid not in graph[rec_uuid]:
                            graph[rec_uuid].append(uuid)
                    elif alternate_email.lower() in rec_acc.title.lower():
                        if uuid not in graph[rec_uuid]:
                            graph[rec_uuid].append(uuid)

        return dict(graph)

    def get_dependency_count(self, account_uuid: str) -> int:
        """Get count of accounts this account can recover."""
        return len(self.dependency_graph.get(account_uuid, []))

    def analyze_account(self, account: Account) -> dict[str, Any]:
        """
        Analyze a single account and return detailed risk assessment.

        Returns:
            Dictionary with risk score, level, and breakdown
        """
        dep_count = self.get_dependency_count(account.uuid)
        raw_score, risk_level = account.compute_risk_score(dep_count)

        return {
            "uuid": account.uuid,
            "title": account.title,
            "risk_score": raw_score,
            "risk_level": risk_level,
            "strongest_2fa": account.strongest_2fa,
            "weakest_2fa": account.weakest_2fa,
            "capabilities": account.capabilities,
            "dependency_count": dep_count,
            "has_breach": account.has_breach_exposure,
            "is_shared": account.is_shared_access,
            "security_controls": account.security_controls,
        }

    def analyze_all(self) -> list[dict[str, Any]]:
        """Analyze all accounts and return sorted by risk score."""
        results = [self.analyze_account(acc) for acc in self.accounts.values()]
        return sorted(results, key=lambda x: x["risk_score"], reverse=True)

    def filter_by_risk_level(self, level: RiskLevel) -> list[dict[str, Any]]:
        """Filter accounts by risk level."""
        return [r for r in self.analyze_all() if r["risk_level"] == level]

    def filter_by_tag(self, tag: str) -> list[dict[str, Any]]:
        """Filter accounts that have a specific tag."""
        filtered_accounts = {
            uuid: acc for uuid, acc in self.accounts.items()
            if tag in acc.tag_list
        }
        analyzer = RiskAnalyzer(filtered_accounts)
        return analyzer.analyze_all()

    def filter_by_capability(self, capability: str) -> list[dict[str, Any]]:
        """Filter accounts with specific capability."""
        return self.filter_by_tag(f"Bastion/Capability/{capability}")

    def filter_by_weakest_2fa(self, method: TwoFAMethod) -> list[dict[str, Any]]:
        """Filter accounts with specific weakest 2FA method."""
        filtered_accounts = {
            uuid: acc for uuid, acc in self.accounts.items()
            if acc.weakest_2fa == method
        }
        analyzer = RiskAnalyzer(filtered_accounts)
        return analyzer.analyze_all()

    def get_breach_exposed(self) -> list[dict[str, Any]]:
        """Get all accounts with breach-exposed passwords."""
        return self.filter_by_tag("Bastion/Security/Breach-Exposed")

    def get_no_rate_limit(self) -> list[dict[str, Any]]:
        """Get accounts with no rate limiting (brute force vulnerable)."""
        return self.filter_by_tag("Bastion/Security/No-Rate-Limit")

    def get_sms_enabled(self) -> list[dict[str, Any]]:
        """Get accounts with SMS 2FA enabled (even as fallback)."""
        return self.filter_by_tag("Bastion/2FA/SMS")

    def get_shared_access(self) -> list[dict[str, Any]]:
        """Get accounts with shared access."""
        return self.filter_by_tag("Bastion/Capability/Shared-Access")

    def print_risk_report(self, console: Console, results: list[dict[str, Any]] | None = None, limit: int | None = 20) -> None:
        """Print formatted risk report.

        Args:
            console: Rich console for output
            results: Analysis results (if None, will analyze all)
            limit: Maximum number of rows to display (None = show all)
        """
        if results is None:
            results = self.analyze_all()

        if not results:
            console.print("[yellow]No accounts found[/yellow]")
            return

        # Summary
        risk_counts = defaultdict(int)
        for r in results:
            risk_counts[r["risk_level"]] += 1

        console.print("\n[bold]Risk Summary[/bold]")
        console.print(f"  CRITICAL: {risk_counts[RiskLevel.CRITICAL]} accounts")
        console.print(f"  HIGH: {risk_counts[RiskLevel.HIGH]} accounts")
        console.print(f"  MEDIUM: {risk_counts[RiskLevel.MEDIUM]} accounts")
        console.print(f"  LOW: {risk_counts[RiskLevel.LOW]} accounts")

        # Detailed table
        table = Table(title="\nAccount Risk Analysis", show_lines=True)
        table.add_column("Account", style="cyan", no_wrap=True)
        table.add_column("Risk Score", justify="right", style="bold")
        table.add_column("Level", justify="center")
        table.add_column("Weakest 2FA", justify="center")
        table.add_column("Strongest 2FA", justify="center")
        table.add_column("Capabilities", style="dim")
        table.add_column("Issues", style="yellow")

        # Determine how many to show
        display_count = len(results) if limit is None else min(limit, len(results))

        for r in results[:display_count]:
            # Risk level color
            level_color = {
                RiskLevel.CRITICAL: "red bold",
                RiskLevel.HIGH: "red",
                RiskLevel.MEDIUM: "yellow",
                RiskLevel.LOW: "green",
            }[r["risk_level"]]

            # Issues
            issues = []
            if r["has_breach"]:
                issues.append("🚨 BREACH")
            if r["is_shared"]:
                issues.append("👥 SHARED")
            if r["weakest_2fa"] == TwoFAMethod.SMS:
                issues.append("📱 SMS")
            if r["weakest_2fa"] == TwoFAMethod.NONE:
                issues.append("⚠️ NO 2FA")
            if r["dependency_count"] > 0:
                issues.append(f"🔗 {r['dependency_count']} deps")

            # Capabilities (abbreviated)
            caps = [c.replace("Bastion/Capability/", "") for c in r["capabilities"][:3]]
            caps_str = ", ".join(caps)
            if len(r["capabilities"]) > 3:
                caps_str += "..."

            table.add_row(
                r["title"][:30],
                str(r["risk_score"]),
                f"[{level_color}]{r['risk_level'].value.upper()}[/{level_color}]",
                r["weakest_2fa"].value.upper(),
                r["strongest_2fa"].value.upper(),
                caps_str,
                " ".join(issues),
            )

        console.print(table)

        if limit is not None and len(results) > limit:
            console.print(f"\n[dim]... and {len(results) - limit} more accounts (use --limit 0 to show all)[/dim]")

    def print_dependency_graph(
        self,
        console: Console,
        account_title: str | None = None,
        account_uuid: str | None = None,
    ) -> None:
        """Print dependency graph for an account (prefer UUID for disambiguation)."""

        account: Account | None = None

        if account_uuid:
            account = self.accounts.get(account_uuid)
            if not account:
                console.print(f"[red]Account UUID not found: {account_uuid}[/red]")
                return
        elif account_title:
            # Prefer exact, then substring match
            lower_title = account_title.lower()
            exact_matches = [acc for acc in self.accounts.values() if acc.title.lower() == lower_title]
            partial_matches = [acc for acc in self.accounts.values() if lower_title in acc.title.lower()]
            
            # Combine matches (exact first, then partial, remove duplicates)
            all_matches = exact_matches + [acc for acc in partial_matches if acc not in exact_matches]
            
            if len(all_matches) > 1:
                # Multiple matches - prompt user to select
                console.print(f"\n[yellow]Found {len(all_matches)} accounts matching '{account_title}':[/yellow]\n")
                for idx, acc in enumerate(all_matches[:20], 1):  # Limit to 20 for usability
                    # Show additional context to help differentiate
                    context_parts = []
                    if acc.username:
                        context_parts.append(f"[dim]{acc.username}[/dim]")
                    if acc.urls:
                        # Show first URL if multiple
                        first_url = acc.urls.split(",")[0].strip()
                        context_parts.append(f"[dim cyan]{first_url}[/dim cyan]")
                    context = " - " + " ".join(context_parts) if context_parts else ""
                    console.print(f"  {idx}. {acc.title}{context}")
                if len(all_matches) > 20:
                    console.print(f"  [dim]... and {len(all_matches) - 20} more[/dim]")
                
                console.print("")
                choice = Prompt.ask(
                    "Select account",
                    choices=[str(i) for i in range(1, min(len(all_matches), 20) + 1)],
                    default="1"
                )
                account = all_matches[int(choice) - 1]
            elif len(all_matches) == 1:
                account = all_matches[0]

        if not account:
            console.print(f"[red]Account not found: {account_title or account_uuid or 'unspecified'}[/red]")
            if account_title:
                # Show similar matches to help user
                lower_search = account_title.lower()
                similar = [
                    acc.title for acc in self.accounts.values()
                    if any(word in acc.title.lower() for word in lower_search.split())
                ]
                if similar:
                    console.print("\n[yellow]Did you mean one of these?[/yellow]")
                    for title in sorted(similar)[:10]:
                        console.print(f"  • {title}")
                    if len(similar) > 10:
                        console.print(f"  [dim]... and {len(similar) - 10} more[/dim]")
            return

        console.print(f"\n[bold]Dependency Analysis: {account.title}[/bold]\n")

        # What this account depends on
        if account.dependencies:
            console.print("[cyan]This account depends on:[/cyan]")
            for dep in account.dependencies:
                console.print(f"  • {dep.replace('Bastion/Dependency/', '')}")
        else:
            console.print("[dim]No external dependencies tagged[/dim]")

        # What depends on this account
        downstream = self.dependency_graph.get(account.uuid, [])
        if downstream:
            console.print(f"\n[yellow]This account can recover {len(downstream)} accounts:[/yellow]")
            for dep_uuid in downstream[:10]:
                dep_acc = self.accounts.get(dep_uuid)
                if dep_acc:
                    console.print(f"  • {dep_acc.title}")
            if len(downstream) > 10:
                console.print(f"  [dim]... and {len(downstream) - 10} more[/dim]")
        else:
            console.print("\n[dim]No accounts depend on this one[/dim]")
