"""Mermaid diagram generation."""

from datetime import datetime
from pathlib import Path

from .models import Database


def generate_mermaid_diagram(db: Database, output_path: Path) -> None:
    """Generate Mermaid diagram from database."""
    lines = [
        "# Account Security Architecture - Live Data",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "**Source:** password-rotation-database.json",
        "",
        "## Account Hierarchy by Tier & 2FA Risk",
        "",
        "```mermaid",
        "graph LR",
        '    Tier1["🔴 Tier 1<br/>Critical"]',
        '    Tier2["🟡 Tier 2<br/>Important"]',
        '    Tier3["🟢 Tier 3<br/>Standard"]',
        "",
    ]
    
    # Tier 1 accounts
    for account in db.accounts.values():
        if account.tier == "Tier 1":
            safe_name = _sanitize_node_name(account.title)
            risk_class = _get_risk_class(account)
            lines.append(f'    T1_{safe_name}["{account.title}"]:::{risk_class}')
            lines.append(f'    Tier1 --> T1_{safe_name}')
    
    lines.append("")
    
    # Tier 2 accounts
    for account in db.accounts.values():
        if account.tier == "Tier 2":
            safe_name = _sanitize_node_name(account.title)
            risk_class = _get_risk_class(account)
            lines.append(f'    T2_{safe_name}["{account.title}"]:::{risk_class}')
            lines.append(f'    Tier2 --> T2_{safe_name}')
    
    lines.append("")
    
    # Tier 3 accounts
    for account in db.accounts.values():
        if account.tier == "Tier 3":
            safe_name = _sanitize_node_name(account.title)
            risk_class = _get_risk_class(account)
            lines.append(f'    T3_{safe_name}["{account.title}"]:::{risk_class}')
            lines.append(f'    Tier3 --> T3_{safe_name}')
    
    lines.extend([
        "",
        "    classDef fido2 fill:#51cf66,stroke:#2f9e44,color:#000",
        "    classDef totp fill:#fab005,stroke:#f59f00,color:#000",
        "    classDef sms fill:#ff6b6b,stroke:#c92a2a,color:#fff",
        "    classDef no2fa fill:#c92a2a,stroke:#862e2e,color:#fff",
        "    classDef unknown fill:#adb5bd,stroke:#495057,color:#000",
        "```",
        "",
        "## 2FA Risk Heatmap",
        "",
        "```mermaid",
        'pie title "2FA Security Distribution"',
    ])
    
    # Count 2FA types
    fido2_count = sum(1 for a in db.accounts.values() if a.has_fido2)
    totp_count = sum(1 for a in db.accounts.values() if a.has_totp)
    sms_count = sum(1 for a in db.accounts.values() if a.has_sms)
    no2fa_count = sum(1 for a in db.accounts.values() if a.has_no2fa)
    
    if fido2_count > 0:
        lines.append(f'    "FIDO2/YubiKey (Secure)" : {fido2_count}')
    if totp_count > 0:
        lines.append(f'    "TOTP (Acceptable)" : {totp_count}')
    if sms_count > 0:
        lines.append(f'    "SMS (High Risk)" : {sms_count}')
    if no2fa_count > 0:
        lines.append(f'    "No 2FA (Critical)" : {no2fa_count}')
    
    lines.extend([
        "```",
        "",
        "## Critical 2FA Risks",
        "",
        "| Account | Tier | 2FA Method | Risk Level | Mitigation |",
        "|---------|------|------------|------------|------------|",
    ])
    
    # Add critical risks
    for account in db.accounts.values():
        if account.has_sms or account.has_no2fa or account.is_2fa_downgraded:
            lines.append(
                f"| {account.title} | {account.tier} | {account.twofa_method or 'Unknown'} | "
                f"{account.twofa_risk or 'Unknown'} | {account.mitigation or 'None documented'} |"
            )
    
    lines.extend([
        "",
        "## Rotation Status by Tier",
        "",
        "```mermaid",
        "gantt",
        "    title Password Rotation Timeline",
        "    dateFormat YYYY-MM-DD",
        "    axisFormat %b %d",
    ])
    
    # Add rotation timeline (next 90 days)
    count = 0
    for account in db.accounts.values():
        if account.days_until_rotation is not None and account.days_until_rotation <= 90:
            crit = "crit," if account.days_until_rotation < 0 else ""
            safe_title = account.title.replace(" ", "_")
            lines.append(
                f"    {account.title} ({account.tier}) : {crit}{safe_title}, "
                f"{account.next_rotation_date}, 1d"
            )
            count += 1
            if count >= 20:
                break
    
    lines.append("```")
    
    # Write to file
    with open(output_path, "w") as f:
        f.write("\n".join(lines))


def _sanitize_node_name(name: str) -> str:
    """Sanitize node name for Mermaid."""
    import re
    sanitized = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    return sanitized[:50]


def _get_risk_class(account) -> str:
    """Get CSS class for 2FA risk level."""
    if account.has_fido2:
        return "fido2"
    elif account.has_totp:
        return "totp"
    elif account.has_sms:
        return "sms"
    elif account.has_no2fa:
        return "no2fa"
    else:
        return "unknown"
