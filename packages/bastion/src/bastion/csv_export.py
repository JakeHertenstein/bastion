"""CSV export functionality."""

import csv
from pathlib import Path

from .models import Database


def export_to_csv(db: Database, output_path: Path) -> None:
    """Export database to CSV format."""
    headers = [
        "Account", "Tier", "UUID", "Last Changed", "Next Rotation", "Days Until",
        "Pre-Baseline", "2FA Method", "2FA Risk", "YubiKeys", "Risk Notes",
        "Mitigation", "Dependency", "URLs", "Notes"
    ]
    
    with open(output_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        
        for account in db.accounts.values():
            writer.writerow([
                account.title,
                account.tier,
                account.uuid,
                account.last_password_change,
                account.next_rotation_date,
                account.days_until_rotation,
                account.is_pre_baseline,
                account.twofa_method,
                account.twofa_risk,
                account.yubikeys_registered,
                account.risk_notes,
                account.mitigation,
                account.dependency,
                account.urls,
                account.notes,
            ])
