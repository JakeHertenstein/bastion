"""Mermaid diagram generation."""

from datetime import datetime
from pathlib import Path

from .models import Database, RiskLevel, TwoFAMethod
from .risk_analysis import RiskAnalyzer


def generate_mermaid_diagram(db: Database, output_path: Path) -> None:
    """Generate Mermaid diagram from database."""
    lines = [
        "# Account Security Architecture - Live Data",
        "",
        f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "**Source:** password-rotation-database.json",
        "",
        "## Account Hierarchy by Risk Level",
        "",
        "```mermaid",
        "graph LR",
        '    Critical["🔴 CRITICAL<br/>High Risk"]',
        '    High["🟠 HIGH<br/>Elevated Risk"]',
        '    Medium["🟡 MEDIUM<br/>Standard"]',
        '    Low["🟢 LOW<br/>Managed"]',
        "",
    ]

    # CRITICAL accounts
    for account in db.accounts.values():
        if account.risk_level == RiskLevel.CRITICAL:
            safe_name = _sanitize_node_name(account.title)
            risk_class = _get_risk_class(account)
            lines.append(f'    C_{safe_name}["{account.title}"]:::{risk_class}')
            lines.append(f'    Critical --> C_{safe_name}')

    lines.append("")

    # HIGH accounts
    for account in db.accounts.values():
        if account.risk_level == RiskLevel.HIGH:
            safe_name = _sanitize_node_name(account.title)
            risk_class = _get_risk_class(account)
            lines.append(f'    H_{safe_name}["{account.title}"]:::{risk_class}')
            lines.append(f'    High --> H_{safe_name}')

    lines.append("")

    # MEDIUM accounts
    for account in db.accounts.values():
        if account.risk_level == RiskLevel.MEDIUM:
            safe_name = _sanitize_node_name(account.title)
            risk_class = _get_risk_class(account)
            lines.append(f'    M_{safe_name}["{account.title}"]:::{risk_class}')
            lines.append(f'    Medium --> M_{safe_name}')

    lines.append("")

    # LOW accounts
    for account in db.accounts.values():
        if account.risk_level == RiskLevel.LOW:
            safe_name = _sanitize_node_name(account.title)
            risk_class = _get_risk_class(account)
            lines.append(f'    L_{safe_name}["{account.title}"]:::{risk_class}')
            lines.append(f'    Low --> L_{safe_name}')

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

    # Count 2FA types (using computed properties from tags)
    fido2_count = sum(1 for a in db.accounts.values() if a.strongest_2fa == TwoFAMethod.FIDO2)
    totp_count = sum(1 for a in db.accounts.values() if a.strongest_2fa == TwoFAMethod.TOTP)
    push_count = sum(1 for a in db.accounts.values() if a.strongest_2fa == TwoFAMethod.PUSH)
    sms_count = sum(1 for a in db.accounts.values() if a.strongest_2fa == TwoFAMethod.SMS)
    email_count = sum(1 for a in db.accounts.values() if a.strongest_2fa == TwoFAMethod.EMAIL)
    no2fa_count = sum(1 for a in db.accounts.values() if a.strongest_2fa == TwoFAMethod.NONE)

    if fido2_count > 0:
        lines.append(f'    "FIDO2/YubiKey (Secure)" : {fido2_count}')
    if totp_count > 0:
        lines.append(f'    "TOTP (Acceptable)" : {totp_count}')
    if push_count > 0:
        lines.append(f'    "Push Notification (Good)" : {push_count}')
    if sms_count > 0:
        lines.append(f'    "SMS (High Risk)" : {sms_count}')
    if email_count > 0:
        lines.append(f'    "Email (Medium Risk)" : {email_count}')
    if no2fa_count > 0:
        lines.append(f'    "No 2FA (Critical)" : {no2fa_count}')

    lines.extend([
        "```",
        "",
        "## Critical 2FA Risks",
        "",
        "| Account | Risk Level | 2FA Method | Risk Assessment | Mitigation |",
        "|---------|-----------|------------|-----------------|------------|",
    ])

    # Add critical risks
    for account in db.accounts.values():
        is_critical = account.strongest_2fa in [TwoFAMethod.SMS, TwoFAMethod.EMAIL, TwoFAMethod.NONE]
        if is_critical:
            lines.append(
                f"| {account.title} | {account.risk_level.value.upper()} | {account.strongest_2fa.value.upper()} | "
                f"{'CRITICAL' if account.strongest_2fa == TwoFAMethod.NONE else 'HIGH'} | "
                f"{account.mitigation or 'None documented'} |"
            )

    lines.extend([
        "",
        "## Rotation Status by Risk Level",
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
                f"    {account.title} ({account.risk_level.value}) : {crit}{safe_title}, "
                f"{account.next_rotation_date}, 1d"
            )
            count += 1
            if count >= 20:
                break

    lines.append("```")

    # Add dependency graph visualization
    analyzer = RiskAnalyzer(db.accounts)
    if analyzer.dependency_graph:
        lines.extend([
            "",
            "## Account Recovery Dependencies",
            "",
            "Shows which accounts can recover which others based on recovery email configuration.",
            "",
            "```mermaid",
            "graph LR",
        ])

        # Create node IDs for all accounts
        account_nodes = {}
        for account in db.accounts.values():
            safe_id = _sanitize_node_name(account.title)
            account_nodes[account.uuid] = safe_id

        # Add dependency edges
        for source_uuid, dependent_uuids in analyzer.dependency_graph.items():
            source_account = db.accounts.get(source_uuid)
            if not source_account:
                continue

            source_id = account_nodes[source_uuid]
            for dependent_uuid in dependent_uuids:
                dependent_account = db.accounts.get(dependent_uuid)
                if not dependent_account:
                    continue

                dependent_id = account_nodes[dependent_uuid]
                # Format: "Source (can recover) --> Dependent"
                lines.append(f'    {source_id} -->|"recovers"| {dependent_id}')

        lines.append("```")
        lines.extend([
            "",
            "**Legend:** An edge from Account A to Account B means Account A's recovery email can be used to recover Account B.",
            "",
        ])

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
    if account.strongest_2fa == TwoFAMethod.FIDO2:
        return "fido2"
    elif account.strongest_2fa == TwoFAMethod.TOTP:
        return "totp"
    elif account.strongest_2fa in [TwoFAMethod.PUSH, TwoFAMethod.EMAIL]:
        return "totp"  # Medium risk, use same color
    elif account.strongest_2fa == TwoFAMethod.SMS:
        return "sms"
    elif account.strongest_2fa == TwoFAMethod.NONE:
        return "no2fa"
    else:
        return "unknown"
