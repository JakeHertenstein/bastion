"""Validation rules for security policies."""

from abc import ABC, abstractmethod
from enum import Enum

from rich.console import Console
from rich.table import Table

from .models import Account


class ViolationSeverity(str, Enum):
    """Severity levels for validation violations."""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class ValidationViolation:
    """A validation rule violation."""
    
    def __init__(
        self,
        severity: ViolationSeverity,
        rule_name: str,
        account: Account,
        message: str,
        fix_suggestion: str = "",
    ):
        self.severity = severity
        self.rule_name = rule_name
        self.account = account
        self.message = message
        self.fix_suggestion = fix_suggestion
    
    def __str__(self) -> str:
        return f"[{self.severity.value.upper()}] {self.rule_name}: {self.account.title} - {self.message}"


class ValidationRule(ABC):
    """Base class for validation rules."""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Rule name."""
        pass
    
    @property
    @abstractmethod
    def description(self) -> str:
        """Rule description."""
        pass
    
    @abstractmethod
    def validate(self, account: Account) -> list[ValidationViolation]:
        """
        Validate an account against this rule.
        
        Args:
            account: Account to validate
            
        Returns:
            List of violations (empty if valid)
        """
        pass


class NoSharedIdentityRule(ValidationRule):
    """Accounts with identity/recovery capabilities must not be in shared vaults."""
    
    @property
    def name(self) -> str:
        return "no-shared-identity"
    
    @property
    def description(self) -> str:
        return "Accounts with Bastion/Capability/Identity or Bastion/Capability/Recovery cannot be in shared vaults"
    
    def validate(self, account: Account) -> list[ValidationViolation]:
        violations = []
        
        # Check if account has identity or recovery capability
        has_identity = "Bastion/Capability/Identity" in account.capabilities
        has_recovery = "Bastion/Capability/Recovery" in account.capabilities
        
        if not (has_identity or has_recovery):
            return violations
        
        # Check if in shared vault (not Private)
        if account.vault_name != "Private":
            caps = []
            if has_identity:
                caps.append("Bastion/Capability/Identity")
            if has_recovery:
                caps.append("Bastion/Capability/Recovery")
            
            message = f"Has {', '.join(caps)} but stored in '{account.vault_name}' vault"
            fix = "Move to Private vault. Identity and recovery accounts must never be shared."
            
            violations.append(
                ValidationViolation(
                    severity=ViolationSeverity.CRITICAL,
                    rule_name=self.name,
                    account=account,
                    message=message,
                    fix_suggestion=fix,
                )
            )
        
        return violations


class SharedNeedsRationaleRule(ValidationRule):
    """Accounts in shared vaults must have a sharing rationale tag."""
    
    @property
    def name(self) -> str:
        return "shared-needs-rationale"
    
    @property
    def description(self) -> str:
        return "Accounts in shared vaults must have at least one Bastion/Why/* tag"
    
    def validate(self, account: Account) -> list[ValidationViolation]:
        violations = []
        
        # Only check shared vaults
        if account.vault_name == "Private":
            return violations
        
        # Check for Bastion/Why/* tags
        rationale_tags = [t for t in account.tag_list if t.startswith("Bastion/Why/")]
        
        if not rationale_tags:
            message = f"Stored in '{account.vault_name}' vault but missing Bastion/Why/* rationale tag"
            fix = "Add one of: Bastion/Why/Joint-Account, Bastion/Why/Beneficiary, Bastion/Why/Household, Bastion/Why/Emergency-Backup, Bastion/Why/Executor-Access, Bastion/Why/Family-Bills"
            
            violations.append(
                ValidationViolation(
                    severity=ViolationSeverity.WARNING,
                    rule_name=self.name,
                    account=account,
                    message=message,
                    fix_suggestion=fix,
                )
            )
        
        return violations


class SharedAccessTagRule(ValidationRule):
    """Accounts in shared vaults should have Bastion/Capability/Shared-Access tag."""
    
    @property
    def name(self) -> str:
        return "shared-access-tag"
    
    @property
    def description(self) -> str:
        return "Accounts in shared vaults should be tagged with Bastion/Capability/Shared-Access"
    
    def validate(self, account: Account) -> list[ValidationViolation]:
        violations = []
        
        # Only check shared vaults
        if account.vault_name == "Private":
            return violations
        
        # Check for Bastion/Capability/Shared-Access tag
        if not account.is_shared_access:
            message = f"Stored in '{account.vault_name}' vault but missing Bastion/Capability/Shared-Access tag"
            fix = "Add Bastion/Capability/Shared-Access tag if this account truly has sharing capabilities"
            
            violations.append(
                ValidationViolation(
                    severity=ViolationSeverity.WARNING,
                    rule_name=self.name,
                    account=account,
                    message=message,
                    fix_suggestion=fix,
                )
            )
        
        return violations


class TOTPSubtagRule(ValidationRule):
    """Bastion/2FA/TOTP/* subtags require parent Bastion/2FA/TOTP tag."""
    
    @property
    def name(self) -> str:
        return "totp-subtag-requires-parent"
    
    @property
    def description(self) -> str:
        return "Bastion/2FA/TOTP/YubiKey or Bastion/2FA/TOTP/Phone-App tags require parent Bastion/2FA/TOTP parent tag"
    
    def validate(self, account: Account) -> list[ValidationViolation]:
        violations = []
        
        # Check for TOTP storage location tags
        totp_subtags = [t for t in account.tag_list if t.startswith("Bastion/2FA/TOTP/")]
        if not totp_subtags:
            return violations
        
        # Check if Bastion/2FA/TOTP parent tag exists
        has_totp_parent = "Bastion/2FA/TOTP" in account.tag_list
        
        if not has_totp_parent:
            message = f"Has {', '.join(totp_subtags)} but missing Bastion/2FA/TOTP parent tag"
            fix = "Add Bastion/2FA/TOTP tag to indicate TOTP 2FA is enabled"
            
            violations.append(
                ValidationViolation(
                    severity=ViolationSeverity.WARNING,
                    rule_name=self.name,
                    account=account,
                    message=message,
                    fix_suggestion=fix,
                )
            )
        
        return violations


class MultiYubiKeyRedundancyRule(ValidationRule):
    """Bastion/Redundancy/Multi-YubiKey requires Bastion/2FA/TOTP/YubiKey tag."""
    
    @property
    def name(self) -> str:
        return "multi-yubikey-requires-hardware-totp"
    
    @property
    def description(self) -> str:
        return "Bastion/Redundancy/Multi-YubiKey tag only valid with Bastion/2FA/TOTP/YubiKey (hardware TOTP)"
    
    def validate(self, account: Account) -> list[ValidationViolation]:
        violations = []
        
        # Check for redundancy tag
        has_multi_yubikey = "Bastion/Redundancy/Multi-YubiKey" in account.tag_list
        if not has_multi_yubikey:
            return violations
        
        # Check if using hardware TOTP
        has_yubikey_totp = "Bastion/2FA/TOTP/YubiKey" in account.tag_list
        
        if not has_yubikey_totp:
            message = "Has Bastion/Redundancy/Multi-YubiKey but TOTP not on YubiKey hardware"
            fix = "Add Bastion/2FA/TOTP/YubiKey tag, or remove redundancy tag if TOTP on phone app"
            
            violations.append(
                ValidationViolation(
                    severity=ViolationSeverity.WARNING,
                    rule_name=self.name,
                    account=account,
                    message=message,
                    fix_suggestion=fix,
                )
            )
        
        return violations


class ValidationEngine:
    """Runs validation rules against accounts."""
    
    def __init__(self):
        self.rules: list[ValidationRule] = [
            NoSharedIdentityRule(),
            SharedNeedsRationaleRule(),
            SharedAccessTagRule(),
            TOTPSubtagRule(),
            MultiYubiKeyRedundancyRule(),
        ]
    
    def validate_all(self, accounts: list[Account] | dict[str, Account]) -> list[ValidationViolation]:
        """
        Validate all accounts against all rules.
        
        Args:
            accounts: List or dict of accounts to validate
            
        Returns:
            List of all violations found
        """
        violations = []
        
        # Handle both list and dict inputs
        account_list = accounts.values() if isinstance(accounts, dict) else accounts
        
        for account in account_list:
            for rule in self.rules:
                violations.extend(rule.validate(account))
        return violations
    
    def print_report(self, violations: list[ValidationViolation], console: Console):
        """
        Print validation report.
        
        Args:
            violations: List of violations to report
            console: Rich console for output
        """
        if not violations:
            console.print("[green]✓ All validation rules passed![/green]")
            return
        
        # Count by severity
        critical_count = sum(1 for v in violations if v.severity == ViolationSeverity.CRITICAL)
        warning_count = sum(1 for v in violations if v.severity == ViolationSeverity.WARNING)
        info_count = sum(1 for v in violations if v.severity == ViolationSeverity.INFO)
        
        # Summary
        console.print("\n[bold]Validation Report[/bold]")
        console.print(f"Total violations: {len(violations)}")
        if critical_count > 0:
            console.print(f"  [red]CRITICAL: {critical_count}[/red]")
        if warning_count > 0:
            console.print(f"  [yellow]WARNING: {warning_count}[/yellow]")
        if info_count > 0:
            console.print(f"  [blue]INFO: {info_count}[/blue]")
        console.print()
        
        # Group by severity
        for severity in [ViolationSeverity.CRITICAL, ViolationSeverity.WARNING, ViolationSeverity.INFO]:
            severity_violations = [v for v in violations if v.severity == severity]
            if not severity_violations:
                continue
            
            # Color mapping
            color_map = {
                ViolationSeverity.CRITICAL: "red",
                ViolationSeverity.WARNING: "yellow",
                ViolationSeverity.INFO: "blue",
            }
            color = color_map[severity]
            
            console.print(f"[{color} bold]{severity.value.upper()} Violations[/{color} bold]")
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("Account", style="cyan")
            table.add_column("Vault", style="magenta")
            table.add_column("Rule", style="white")
            table.add_column("Issue", style=color)
            table.add_column("Fix", style="green")
            
            for violation in severity_violations:
                table.add_row(
                    violation.account.title,
                    violation.account.vault_name,
                    violation.rule_name,
                    violation.message,
                    violation.fix_suggestion,
                )
            
            console.print(table)
            console.print()
    
    def has_critical_violations(self, violations: list[ValidationViolation]) -> bool:
        """Check if any violations are CRITICAL severity."""
        return any(v.severity == ViolationSeverity.CRITICAL for v in violations)
