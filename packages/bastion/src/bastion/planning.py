"""Rotation planning logic."""

from datetime import datetime

import pendulum

from .models import Account


class RotationPlanner:
    """Calculate rotation schedules and process 1Password items."""

    TIER_INTERVALS = {
        "Tier 1": 90,
        "Tier 2": 180,
        "Tier 3": 365,
    }

    def process_item(self, item: dict, baseline: str) -> Account:
        """Process a 1Password item into an Account model."""
        uuid = item["id"]
        title = item["title"]
        
        # Extract vault
        vault_name = item.get("vault", {}).get("name", "Private")
        
        # Extract username
        username = self._extract_username(item)
        
        # Extract tags
        tags = item.get("tags", [])
        tags_str = ", ".join(tags) if isinstance(tags, list) else ""
        
        # Determine tier from tags
        tier = self._determine_tier(tags)
        
        # Extract URLs
        urls = [url.get("href", "") for url in item.get("urls", [])]
        urls_str = ", ".join(urls)
        
        # Extract password updated timestamp
        password_updated = self._extract_password_timestamp(item)
        
        # Extract custom fields
        fields = item.get("fields", [])
        custom_fields = {f.get("label", ""): f.get("value", "") for f in fields}
        
        # Extract alternate recovery email if present
        alternate_recovery_email = custom_fields.get("alternate_recovery_email", "") or custom_fields.get("Alternate Recovery Email", "")
        
        # Cache fields for audit commands (to avoid re-fetching from 1Password)
        fields_cache = fields if fields else []
        
        # Detect rotation tags
        rotation_tag, rotation_interval = self._detect_rotation_tag(tags)
        
        # Calculate rotation schedule
        if rotation_interval is None:
            rotation_interval = self.TIER_INTERVALS.get(tier, 180)
        
        next_rotation_date = ""
        days_until = None
        if password_updated:
            next_rotation_date = self._calculate_next_rotation(password_updated, rotation_interval)
            if next_rotation_date:
                days_until = self._calculate_days_until(next_rotation_date)
        
        # Check if pre-baseline
        is_pre_baseline = False
        if password_updated:
            is_pre_baseline = password_updated < baseline
        
        # Extract 2FA info
        twofa_flags = self._extract_2fa_flags(tags)
        
        return Account(
            uuid=uuid,
            title=title,
            vault_name=vault_name,
            username=username,
            alternate_recovery_email=alternate_recovery_email,
            tier=tier,
            fields_cache=fields_cache,
            tags=tags_str,
            urls=urls_str,
            rotation_tag=rotation_tag,
            rotation_interval_override=str(rotation_interval) if rotation_tag else "",
            last_password_change=password_updated,
            next_rotation_date=next_rotation_date,
            days_until_rotation=days_until,
            is_pre_baseline=is_pre_baseline,
            twofa_method=custom_fields.get("2FA Method", ""),
            twofa_risk=custom_fields.get("2FA Risk", ""),
            yubikeys_registered=custom_fields.get("YubiKeys Registered", ""),
            has_fido2=twofa_flags["fido2"],
            has_totp=twofa_flags["totp"],
            has_sms=twofa_flags["sms"],
            has_no2fa=twofa_flags["no2fa"],
            is_2fa_downgraded=twofa_flags["downgraded"],
            dependency=custom_fields.get("Dependency", ""),
            risk_notes=custom_fields.get("Risk Notes", ""),
            mitigation=custom_fields.get("Mitigation", ""),
            notes="",
            last_synced=datetime.now().isoformat(),
        )

    def _determine_tier(self, tags: list[str]) -> str:
        """Determine tier from tags."""
        tags_lower = [t.lower() for t in tags]
        if "tier1" in tags_lower:
            return "Tier 1"
        elif "tier2" in tags_lower:
            return "Tier 2"
        elif "tier3" in tags_lower:
            return "Tier 3"
        return "Tier 2"  # default

    def _extract_password_timestamp(self, item: dict) -> str:
        """Extract password field update timestamp."""
        fields = item.get("fields", [])
        for field in fields:
            if field.get("id") == "password" or field.get("type") == "CONCEALED":
                updated_at = field.get("updated_at")
                if updated_at:
                    return updated_at
        
        # Fallback to item updated_at
        return item.get("updated_at", "")

    def _detect_rotation_tag(self, tags: list[str]) -> tuple[str, int | None]:
        """Detect Bastion/Rotation/* tags."""
        for tag in tags:
            if tag == "Bastion/Rotation/90d":
                return (tag, 90)
            elif tag == "Bastion/Rotation/180d":
                return (tag, 180)
            elif tag == "Bastion/Rotation/365d":
                return (tag, 365)
            elif tag == "Bastion/Rotation/Manual":
                return (tag, None)
        return ("", None)

    def _calculate_next_rotation(self, last_change: str, interval_days: int) -> str:
        """Calculate next rotation date."""
        try:
            dt = pendulum.parse(last_change)
            next_dt = dt.add(days=interval_days)
            return next_dt.to_date_string()
        except Exception:
            return ""

    def _calculate_days_until(self, next_rotation: str) -> int:
        """Calculate days until next rotation."""
        try:
            next_dt = pendulum.parse(next_rotation)
            now = pendulum.now()
            return (next_dt - now).days
        except Exception:
            return 0

    def _extract_2fa_flags(self, tags: list[str]) -> dict[str, bool]:
        """Extract 2FA-related boolean flags from tags."""
        return {
            "fido2": "fido2-enabled" in tags,
            "totp": "totp-only" in tags,
            "sms": "sms-only" in tags,
            "no2fa": "no-2fa" in tags,
            "downgraded": "2fa-downgraded" in tags,
        }
    
    def _extract_username(self, item: dict) -> str:
        """Extract username/email field from 1Password item."""
        fields = item.get("fields", [])
        
        # Look for username field
        for field in fields:
            field_id = field.get("id", "")
            field_type = field.get("type", "")
            field_label = field.get("label", "").lower()
            
            # Common username field patterns
            if field_id == "username" or field_type == "STRING" and "username" in field_label:
                return field.get("value", "")
            if "email" in field_label and field_type == "EMAIL":
                return field.get("value", "")
        
        # Fallback: check for any email-type field
        for field in fields:
            if field.get("type") == "EMAIL":
                return field.get("value", "")
        
        return ""
