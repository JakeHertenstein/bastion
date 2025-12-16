"""Validation logic for tag consistency."""

from .models import Database


def validate_tags(db: Database) -> list[str]:
    """Validate tag consistency and return list of errors."""
    errors = []
    
    for account in db.accounts.values():
        tags_list = [t.strip() for t in account.tags.split(",") if t.strip()]
        
        # Check for multiple Bastion/Rotation/* tags
        rotation_tags = [t for t in tags_list if t.startswith("Bastion/Rotation/")]
        if len(rotation_tags) > 1:
            errors.append(
                f"{account.title} ({account.uuid}): Multiple rotation tags found: {', '.join(rotation_tags)}"
            )
        
        # Check for invalid rotation tag values
        valid_rotation = ["Bastion/Rotation/90d", "Bastion/Rotation/180d", "Bastion/Rotation/365d", "Bastion/Rotation/Manual"]
        for tag in rotation_tags:
            if tag not in valid_rotation:
                errors.append(
                    f"{account.title} ({account.uuid}): Invalid rotation tag: {tag}"
                )
        
        # Check for tier/rotation mismatches (warnings)
        if account.tier == "Tier 1" and "Bastion/Rotation/365d" in tags_list:
            errors.append(
                f"WARNING: {account.title}: Tier 1 with 365d rotation (may be intentional)"
            )
        if account.tier == "Tier 2" and "Bastion/Rotation/90d" in tags_list:
            errors.append(
                f"WARNING: {account.title}: Tier 2 with 90d rotation (may be intentional)"
            )
    
    return errors
