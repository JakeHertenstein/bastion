# Bastion Metadata Section - Closed-Loop Risk Management

## Overview

The **Bastion Metadata** section provides structured date/event tracking for login items, enabling closed-loop risk management with measurable security metrics.

## Purpose

Traditional password managers track credentials but not security lifecycle events. Bastion Metadata adds:

1. **Temporal tracking** - When passwords/TOTP/usernames were changed
2. **Event logging** - Security reviews, breach detection, remediation
3. **Risk scoring** - Current risk level with calculation timestamp
4. **Forward scheduling** - Next review/rotation due dates
5. **Audit trail** - History of security actions

## Field Catalog

### Password Management
- **Password Changed** (date) - Last password change date
- **Password Expires** (date) - Password expiration date
- **Password Rotation Policy** (text) - Rotation interval (90d/180d/365d/manual)

### Username Management
- **Username Changed** (date) - Last username/email change
- **Username Type** (text) - "generated" or "manual"

### 2FA/TOTP Management
- **TOTP Seed Issued** (date) - When TOTP was first set up
- **TOTP Seed Expires** (date) - If service has expiring TOTP seeds
- **TOTP Seed Changed** (date) - Last time TOTP secret was rotated
- **2FA Method Changed** (date) - When 2FA configuration was modified

### Security Events
- **Last Security Review** (date) - Manual security audit date
- **Breach Detected** (date) - Date breach exposure was identified
- **Breach Remediated** (date) - Date breach was addressed

### Account Lifecycle
- **Account Created** (date) - Account creation date
- **Last Activity** (date) - Last known activity on account

### Recovery & Access
- **Recovery Email Changed** (date) - When recovery email was updated
- **Recovery Phone Changed** (date) - When recovery phone was updated
- **Backup Codes Generated** (date) - When backup codes were created

### Risk Scoring
- **Risk Level** (text) - CRITICAL/HIGH/MEDIUM/LOW
- **Risk Score** (text) - Numeric risk score
- **Risk Last Calculated** (date) - When risk score was computed

### Monitoring
- **Next Review Due** (date) - Scheduled security review
- **Next Rotation Due** (date) - Scheduled password rotation

### Notes
- **Bastion Notes** (text) - Security-specific notes separate from main notes

## CLI Usage

### View Current Metadata
```bash
bsec 1p update metadata <UUID> --show
```

### Set Individual Fields
```bash
# Record password change
bsec 1p update metadata <UUID> --password-changed 2025-11-27

# Record TOTP setup
bsec 1p update metadata <UUID> --totp-issued 2024-06-15

# Record security review
bsec 1p update metadata <UUID> --last-review 2025-11-15 --next-review 2026-02-15

# Set risk level
bsec 1p update metadata <UUID> --risk-level MEDIUM

# Add security notes
bsec 1p update metadata <UUID> --bastion-notes "MFA upgrade pending approval"
```

### Set Multiple Fields at Once
```bash
bsec 1p update metadata <UUID> \
  --password-changed 2025-11-27 \
  --totp-issued 2024-06-15 \
  --last-review 2025-11-15 \
  --risk-level HIGH \
  --bastion-notes "Requires immediate password rotation"
```

## Integration with Existing Commands

### Automatic Date Stamping

**`bsec 1p add totp` command:**
```python
# After adding TOTP to YubiKey
update_sat_metadata(account.uuid, 
                   totp_seed_issued=today(),
                   twofa_method_changed=today())
```

**Password rotation workflow:**
```python
# After rotating password
update_sat_metadata(account.uuid,
                   password_changed=today(),
                   next_rotation_due=calculate_next_rotation(policy))
```

**Breach detection (`bsec 1p check breaches`):**
```python
# When breach detected
update_sat_metadata(account.uuid,
                   breach_detected=today(),
                   risk_level="CRITICAL")

# After remediation
update_sat_metadata(account.uuid,
                   breach_remediated=today(),
                   password_changed=today(),
                   risk_level="MEDIUM")
```

## Validation Rules

Add to `validation_rules.py`:

```python
class SATMetadataConsistencyRule(ValidationRule):
    """Validate Bastion Metadata date consistency."""
    
    def validate(self, accounts):
        violations = []
        
        for uuid, account in accounts.items():
            metadata = get_sat_metadata(uuid)
            if not metadata:
                continue
            
            # Password Changed ≤ today
            if metadata.password_changed:
                if parse_date(metadata.password_changed) > date.today():
                    violations.append(f"{account.title}: Password Changed is in the future")
            
            # Password Expires > Password Changed
            if metadata.password_changed and metadata.password_expires:
                if parse_date(metadata.password_expires) <= parse_date(metadata.password_changed):
                    violations.append(f"{account.title}: Password Expires before Password Changed")
            
            # Breach Remediated > Breach Detected
            if metadata.breach_detected and metadata.breach_remediated:
                if parse_date(metadata.breach_remediated) < parse_date(metadata.breach_detected):
                    violations.append(f"{account.title}: Breach Remediated before Breach Detected")
        
        return violations
```

## Closed-Loop Metrics

### Key Performance Indicators

1. **Password Age Distribution**
   - Query all items, calculate `today() - password_changed`
   - Identify passwords > 365 days old

2. **Review Coverage**
   - Count items with `last_security_review` vs. total items
   - Calculate average days since last review

3. **Breach Response Time**
   - Calculate `breach_remediated - breach_detected` for all breaches
   - Target: < 24 hours

4. **Rotation Compliance**
   - Compare `next_rotation_due` to today
   - Count overdue accounts

5. **Risk Distribution**
   - Count items by Risk Level (CRITICAL/HIGH/MEDIUM/LOW)
   - Track risk score trends over time

### Example Queries

```bash
# Find accounts needing review
bsec 1p query --with-bastion-tags | jq '.[] | select(.metadata.next_review_due < "2025-11-27")'

# Find passwords > 1 year old
bsec 1p query --with-bastion-tags | jq '.[] | select(.metadata.password_changed < "2024-11-27")'

# Find unresolved breaches
bsec 1p query --with-bastion-tags | jq '.[] | select(.metadata.breach_detected != null and .metadata.breach_remediated == null)'
```

## Migration Strategy

### Phase 1: MVP Fields (Immediate)
- Password Changed
- TOTP Seed Issued
- Last Security Review
- Next Review Due
- Risk Level

### Phase 2: Full Lifecycle (Week 2)
- All password/username/2FA date fields
- Breach detection/remediation
- Account lifecycle dates

### Phase 3: Automation (Week 3-4)
- Auto-populate metadata during command execution
- Validation rules integration
- KPI dashboard generation

## Benefits

1. **Measurable Security**: Convert from reactive to proactive with metrics
2. **Audit Trail**: Complete history of security actions
3. **Risk Visibility**: Real-time risk scoring with justification
4. **Compliance**: Demonstrate rotation policies are followed
5. **Automation**: Enable scheduled reviews and alerts

## Future Enhancements

1. **Automated Reminders**: Email when `next_review_due` approaches
2. **KPI Dashboard**: `bsec 1p report metrics` shows all KPIs
3. **Trend Analysis**: Track security posture improvement over time
4. **Policy Enforcement**: Block operations on overdue accounts
5. **Export to SIEM**: Push metadata to security monitoring systems
