# Risk Analysis System

**Version**: 1.0  
**Date**: 2025-12-02

## Overview

Bastion implements a comprehensive attribute-based security risk analysis system using flexible capability-based scoring rather than rigid tier classifications.

## Tag Schema

All tags use hierarchical format: `Bastion/Category/Value`

### Capability Tags (`Bastion/Capability/*`)

Tags describe what an account can DO:

| Tag | Description |
|-----|-------------|
| `Bastion/Capability/Money-Transfer` | Wire/ACH/bill pay capability |
| `Bastion/Capability/Recovery` | Can reset other accounts |
| `Bastion/Capability/Secrets` | Stores API keys/tokens |
| `Bastion/Capability/Device-Management` | Device management (Apple ID, etc.) |
| `Bastion/Capability/Identity` | Primary email/identity provider |
| `Bastion/Capability/Credit-Access` | Can apply for credit |
| `Bastion/Capability/Data-Export` | Exportable PII/financial data |
| `Bastion/Capability/Crypto` | Cryptocurrency transfer |

### 2FA Tags (`Bastion/2FA/*`)

Tags describe what's ENABLED (strongest/weakest auto-computed):

| Tag | Description |
|-----|-------------|
| `Bastion/2FA/FIDO2-Hardware` | Hardware passkey (YubiKey, Titan) |
| `Bastion/2FA/Passkey/Software` | Software passkey (device/browser/1Password) |
| `Bastion/2FA/TOTP` | Authenticator app enabled |
| `Bastion/2FA/Push` | Push notifications |
| `Bastion/2FA/SMS` | SMS enabled (including as fallback) |
| `Bastion/2FA/Email` | Email codes enabled |
| `Bastion/2FA/None` | No 2FA |

**Key Insight**: Just tag what's enabled - Bastion auto-computes:
- **Strongest**: Best method available
- **Weakest**: Attack surface (lowest security method enabled)

### Security Tags (`Bastion/Security/*`)

| Tag | Description |
|-----|-------------|
| `Bastion/Security/Rate-Limited` | Login rate limiting active |
| `Bastion/Security/Breach-Exposed` | Password in HIBP database (URGENT) |
| `Bastion/Security/Human-Verification` | Requires human approval |
| `Bastion/Security/Weak-Password` | Password doesn't meet requirements |

### Dependency Tags (`Bastion/Dependency/*`)

| Tag | Description |
|-----|-------------|
| `Bastion/Dependency/No-Email-Recovery` | Cannot be recovered by email |
| `Bastion/Dependency/Phone-SMS` | Depends on phone SMS |
| `Bastion/Dependency/Secret-Key` | Requires secret key/seed phrase |
| `Bastion/Dependency/YubiKey` | Requires YubiKey for recovery |

### Compliance Tags (`Bastion/Compliance/*`)

| Tag | Description |
|-----|-------------|
| `Bastion/Compliance/HIPAA` | Healthcare data |
| `Bastion/Compliance/PCI` | Credit card data |
| `Bastion/Compliance/GLBA` | Financial privacy |
| `Bastion/Compliance/GDPR` | EU data protection |

## Risk Scoring Algorithm

```python
base_score = capability_score + weakest_2fa_score + security_modifiers
final_risk = base_score × shared_access_multiplier × dependency_multiplier × pii_multiplier
```

### Scoring Components

**Capability Points:**

| Capability | Points |
|------------|--------|
| Recovery | +100 |
| Identity | +100 |
| Money-Transfer | +50 |
| Secrets | +40 |
| Device-Management | +30 |
| Credit-Access | +30 |
| Data-Export | +20 |

**Weakest 2FA Points:**

| Method | Points |
|--------|--------|
| None | +200 |
| SMS/Email | +100 |
| Push | +50 |
| TOTP | +30 |
| FIDO2 | +0 |

**Security Modifiers:**

| Modifier | Points |
|----------|--------|
| Breach-Exposed | +150 (CRITICAL!) |
| Human-Verification | -30 |

**Multipliers:**
- Shared access: ×1.5
- Dependencies: ×(1.0 + 0.2 per downstream account)
- PII Financial: ×1.5
- PII Health: ×1.3

### Risk Levels

| Level | Score | Rotation |
|-------|-------|----------|
| **CRITICAL** | 500+ | 30-day max |
| **HIGH** | 300-499 | 60-day |
| **MEDIUM** | 150-299 | 90-day |
| **LOW** | 0-149 | 180-365 day |

## CLI Commands

### `bsec 1p analyze risk`

```bash
# Show all accounts sorted by risk
bsec 1p analyze risk

# Show only CRITICAL accounts
bsec 1p analyze risk --level critical

# Find accounts with SMS enabled
bsec 1p analyze risk --has-tag Bastion/2FA/SMS

# Find money-transfer accounts with weak 2FA
bsec 1p analyze risk --has-capability Money-Transfer --weakest-2fa sms
```

### `bsec 1p analyze dependencies`

```bash
# Show dependency tree for account
bsec 1p analyze dependencies --account Gmail
```

### `bsec 1p check breaches`

```bash
# Scan all passwords against HIBP
bsec 1p check breaches

# Scan and auto-tag breached accounts
bsec 1p check breaches --update-tags
```

## Key Features

### 1. Auto-Computed Weakest Link

Just tag what's enabled:
```
Tags: Bastion/2FA/FIDO2-Hardware, Bastion/2FA/TOTP, Bastion/2FA/SMS
Auto-computed:
  - Strongest: FIDO2
  - Weakest: SMS (attack surface!)
```

### 2. Breach Detection Integration

- Uses Have I Been Pwned API with k-anonymity
- Auto-tags breached accounts: `Bastion/Security/Breach-Exposed`
- Adds +150 risk points

### 3. Dependency Graph Analysis

- Accounts with `Bastion/Capability/Recovery` get dependency multipliers
- Example: Gmail can reset 15 accounts → ×3.0 multiplier

### 4. Flexible Querying

- By risk level: `--level critical`
- By capability: `--has-capability Money-Transfer`
- By 2FA weakness: `--weakest-2fa sms`
- By breach status: `--breach-exposed`

## Example Output

```
Risk Summary
  CRITICAL: 2 accounts
  HIGH: 5 accounts
  MEDIUM: 12 accounts
  LOW: 20 accounts

Account Risk Analysis
┌────────────────┬────────┬──────────┬─────────┬──────────┬─────────────┬────────────────────┐
│ Account        │ Score  │ Level    │ Weakest │ Strongest│ Capabilities│ Issues             │
├────────────────┼────────┼──────────┼─────────┼──────────┼─────────────┼────────────────────┤
│ Gmail          │ 900    │ CRITICAL │ FIDO2   │ FIDO2    │ Identity... │ 🔗 15 deps         │
│ Chase          │ 255    │ MEDIUM   │ SMS     │ FIDO2    │ Money-Tr... │ 📱 SMS             │
│ PayPal         │ 525    │ CRITICAL │ SMS     │ SMS      │ Money-Tr... │ 🚨 BREACH 📱 SMS   │
└────────────────┴────────┴──────────┴─────────┴──────────┴─────────────┴────────────────────┘
```

## Related Documentation

- [BASTION-TAGGING-GUIDE.md](./BASTION-TAGGING-GUIDE.md) - Complete tag reference
- [LABEL-FORMAT-SPECIFICATION.md](./LABEL-FORMAT-SPECIFICATION.md) - Label format details
