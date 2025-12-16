"""Data models for password rotation tracking."""

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field


class TwoFAMethod(str, Enum):
    """2FA method types in order of strength (strongest to weakest)."""
    FIDO2 = "fido2"
    TOTP = "totp"
    PUSH = "push"
    SMS = "sms"
    EMAIL = "email"
    NONE = "none"


class RiskLevel(str, Enum):
    """Computed risk levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Metadata(BaseModel):
    """Database metadata."""

    version: str = "2.1"
    created_at: datetime | str | None = None  # Legacy: "created"
    created: str | None = None  # Legacy field
    updated_at: datetime | str | None = None
    last_sync: datetime | str | None = None
    compromise_baseline: str  # YYYY-MM-DD
    op_cli_version: str | None = None
    last_migration: datetime | str | None = None
    
    def model_post_init(self, __context: object) -> None:
        """Handle legacy field names."""
        if self.created and not self.created_at:
            self.created_at = self.created
        if not self.updated_at:
            self.updated_at = self.created_at or self.created


class MigrationEntry(BaseModel):
    """Migration history entry."""

    timestamp: datetime
    action: str
    tags: str | None = None
    result: str = "success"
    account_uuid: str | None = None


class Account(BaseModel):
    """Account data."""

    uuid: str
    title: str
    vault_name: str = "Private"  # 1Password vault name
    username: str = ""  # Username/email field from 1Password
    alternate_recovery_email: str = ""  # Secondary recovery email (for Square, etc.)
    tier: Literal["Tier 1", "Tier 2", "Tier 3"]
    tags: str = ""  # Comma-separated
    urls: str = ""
    
    # Rotation
    rotation_tag: str = ""
    rotation_interval_override: str = ""
    last_password_change: str = ""
    next_rotation_date: str = ""
    days_until_rotation: int | None = None
    is_pre_baseline: bool = False
    
    # Legacy 2FA fields (kept for backward compatibility)
    twofa_method: str = ""
    twofa_risk: str = ""
    yubikeys_registered: str = ""
    has_fido2: bool = False
    has_totp: bool = False
    has_sms: bool = False
    has_no2fa: bool = False
    is_2fa_downgraded: bool = False
    
    # Other
    dependency: str = ""
    risk_notes: str = ""
    mitigation: str = ""
    notes: str = ""
    last_synced: str = ""
    migration_history: list[MigrationEntry] = Field(default_factory=list)
    fields_cache: list[dict] = Field(default_factory=list)  # Cache of 1Password fields
    
    # Computed fields for tag-based analysis
    @computed_field
    @property
    def vault(self) -> str:
        """Alias for vault_name (backward compatibility)."""
        return self.vault_name
    
    @computed_field
    @property
    def tag_list(self) -> list[str]:
        """Parse tags into list."""
        if not self.tags:
            return []
        return [t.strip() for t in self.tags.split(",") if t.strip()]
    
    @computed_field
    @property
    def capabilities(self) -> list[str]:
        """Extract capability tags."""
        return [t for t in self.tag_list if t.startswith("Bastion/Capability/") or t.startswith("Bastion/Cap/")]
    
    @computed_field
    @property
    def twofa_methods(self) -> list[TwoFAMethod]:
        """Extract 2FA method tags and return as enum list."""
        methods = []
        tag_map = {
            # Bastion 2FA tag format
            "Bastion/2FA/FIDO2-Hardware": TwoFAMethod.FIDO2,
            "Bastion/2FA/Passkey/Software": TwoFAMethod.FIDO2,
            "Bastion/2FA/FIDO2": TwoFAMethod.FIDO2,
            "Bastion/2FA/TOTP": TwoFAMethod.TOTP,
            "Bastion/2FA/Push": TwoFAMethod.PUSH,
            "Bastion/2FA/SMS": TwoFAMethod.SMS,
            "Bastion/2FA/Email": TwoFAMethod.EMAIL,
            "Bastion/2FA/None": TwoFAMethod.NONE,
        }
        for tag in self.tag_list:
            if tag in tag_map:
                methods.append(tag_map[tag])
        return methods or [TwoFAMethod.NONE]
    
    @computed_field
    @property
    def strongest_2fa(self) -> TwoFAMethod:
        """Compute strongest 2FA method (best available)."""
        if not self.twofa_methods:
            return TwoFAMethod.NONE
        # Enum values are in order strongest to weakest
        return min(self.twofa_methods, key=lambda m: list(TwoFAMethod).index(m))
    
    @computed_field
    @property
    def weakest_2fa(self) -> TwoFAMethod:
        """Compute weakest 2FA method (attack surface)."""
        if not self.twofa_methods:
            return TwoFAMethod.NONE
        # Return the weakest enabled method
        return max(self.twofa_methods, key=lambda m: list(TwoFAMethod).index(m))
    
    @computed_field
    @property
    def security_controls(self) -> list[str]:
        """Extract security control tags."""
        return [t for t in self.tag_list if t.startswith("Bastion/Security/")]
    
    @computed_field
    @property
    def dependencies(self) -> list[str]:
        """Extract dependency tags."""
        return [t for t in self.tag_list if t.startswith("Bastion/Dependency/")]
    
    @computed_field
    @property
    def compliance_tags(self) -> list[str]:
        """Extract compliance tags."""
        return [t for t in self.tag_list if t.startswith("Bastion/Compliance/")]
    
    @computed_field
    @property
    def pii_tags(self) -> list[str]:
        """Extract PII sensitivity tags."""
        return [t for t in self.tag_list if t.startswith("Bastion/PII/")]
    
    @computed_field
    @property
    def is_shared_access(self) -> bool:
        """Check if account has shared access."""
        return "Bastion/Capability/Shared-Access" in self.tag_list
    
    @computed_field
    @property
    def has_breach_exposure(self) -> bool:
        """Check if password is breach-exposed."""
        return "Bastion/Security/Breach-Exposed" in self.tag_list
    
    @computed_field
    @property
    def has_rate_limiting(self) -> bool:
        """Check if account has rate limiting."""
        return "Bastion/Security/Rate-Limited" in self.tag_list
    
    @computed_field
    @property
    def has_human_verification(self) -> bool:
        """Check if account requires human verification for sensitive ops."""
        return "Bastion/Security/Human-Verification" in self.tag_list
    
    @computed_field
    @property
    def recovery_email(self) -> str:
        """Extract email address from username field for dependency matching."""
        if not self.username:
            return ""
        # Simple email extraction - if username looks like an email, return it
        import re
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        match = re.search(email_pattern, self.username)
        return match.group(0) if match else ""
    
    def compute_risk_score(self, dependency_count: int = 0) -> tuple[int, RiskLevel]:
        """
        Compute risk score based on attributes.
        
        Args:
            dependency_count: Number of accounts this can reset/recover
            
        Returns:
            Tuple of (raw_score, risk_level)
        """
        # 1. Capability scores
        capability_scores = {
            "Bastion/Capability/Money-Transfer": 50,
            "Bastion/Capability/Recovery": 100,
            "Bastion/Capability/Secrets": 40,
            "Bastion/Capability/Identity": 100,
            "Bastion/Capability/Aggregator": 60,
            "Bastion/Capability/Device-Mgmt": 30,
            "Bastion/Capability/Credit-Access": 30,
            "Bastion/Capability/Data-Export": 20,
        }
        cap_score = sum(capability_scores.get(cap, 0) for cap in self.capabilities)
        
        # 2. Weakest 2FA score (attack surface)
        twofa_scores = {
            TwoFAMethod.NONE: 200,
            TwoFAMethod.EMAIL: 100,
            TwoFAMethod.SMS: 100,
            TwoFAMethod.PUSH: 50,
            TwoFAMethod.TOTP: 30,
            TwoFAMethod.FIDO2: 0,
        }
        twofa_score = twofa_scores.get(self.weakest_2fa, 0)
        
        # 3. Security control modifiers
        security_modifiers = 0
        if self.has_breach_exposure:
            security_modifiers += 150  # CRITICAL
        if not self.has_rate_limiting and "Bastion/Security/No-Rate-Limit" in self.security_controls:
            security_modifiers += 50
        if self.has_human_verification:
            security_modifiers -= 30
        if "Bastion/Security/Device-Binding" in self.security_controls:
            security_modifiers -= 20
        if "Bastion/Security/IP-Restrictions" in self.security_controls:
            security_modifiers -= 15
        if "Bastion/Security/Session-Timeout" in self.security_controls:
            security_modifiers -= 10
        if "Bastion/Security/Password-Max-Length" in self.security_controls:
            security_modifiers += 20
        if "Bastion/Security/Password-No-Special" in self.security_controls:
            security_modifiers += 10
        
        # Base score
        base_score = cap_score + twofa_score + security_modifiers
        
        # 4. Multipliers
        shared_multiplier = 1.5 if self.is_shared_access else 1.0
        
        # Dependency multiplier (1.2 per downstream account)
        dependency_multiplier = 1.0 + (dependency_count * 0.2)
        
        # PII multiplier
        pii_multiplier = 1.0
        if "Bastion/PII/Financial" in self.pii_tags:
            pii_multiplier = 1.5
        elif "Bastion/PII/Government" in self.pii_tags:
            pii_multiplier = 1.8
        elif "Bastion/PII/Health" in self.pii_tags:
            pii_multiplier = 1.3
        
        # Compliance modifier (slight reduction for regulatory oversight)
        compliance_modifier = 0
        if "Bastion/Compliance/FDIC" in self.compliance_tags or "Bastion/Compliance/SIPC" in self.compliance_tags:
            compliance_modifier = -10
        
        # Final calculation
        final_score = int(
            (base_score + compliance_modifier) 
            * shared_multiplier 
            * dependency_multiplier 
            * pii_multiplier
        )
        
        # Determine risk level
        if final_score >= 500:
            risk_level = RiskLevel.CRITICAL
        elif final_score >= 300:
            risk_level = RiskLevel.HIGH
        elif final_score >= 150:
            risk_level = RiskLevel.MEDIUM
        else:
            risk_level = RiskLevel.LOW
        
        return final_score, risk_level


class Database(BaseModel):
    """Complete database."""

    metadata: Metadata
    accounts: dict[str, Account] = Field(default_factory=dict)
    yubikey_cache: dict[str, Any] | None = Field(default=None)
    """YubiKey serial → OATH account cache. DEPRECATED: Use YubiKeyService instead."""
