# Quick Reference: Bastion Tagging Workflow

**Version**: 1.0  
**Date**: 2025-12-02  
**Status**: Hierarchical `Bastion/*` tag format

---

## Tag Format Convention

**Rule**: Use hierarchical `Bastion/Category/Value` format for all tags.

This creates a browsable folder structure in 1Password:
```
Bastion/
├── Type/
│   ├── Bank
│   ├── Email
│   └── Healthcare
├── Capability/
│   ├── Money-Transfer
│   └── Recovery
├── 2FA/
│   ├── TOTP
│   └── FIDO2-Hardware
└── Tier/
    ├── 1
    ├── 2
    └── 3
```

---

## Core Tag Categories

### 1. Type Tags (`Bastion/Type/*`)

What kind of institution/service this is:

```
Bastion/Type/Bank              # Traditional banking
Bastion/Type/Investment        # Investment/brokerage
Bastion/Type/Payment           # Payment processor (PayPal, Venmo)
Bastion/Type/Credit-Card       # Credit card or credit account
Bastion/Type/Insurance         # Insurance provider
Bastion/Type/Utility           # Utility service
Bastion/Type/Email             # Email service provider
Bastion/Type/Shopping          # E-commerce/retail
Bastion/Type/Blockchain        # Cryptocurrency exchange or blockchain service
Bastion/Type/Healthcare        # Healthcare: providers, portals, pharmacies
Bastion/Type/Password-Manager  # Password managers (1Password, etc.)
Bastion/Type/Cloud             # Cloud services (AWS, Azure, etc.)
Bastion/Type/Phone             # Phone/mobile carriers
Bastion/Type/Tax-Service       # Tax preparation services
Bastion/Type/Credit-Monitoring # Credit monitoring services
Bastion/Type/Loan              # Loan services
Bastion/Type/Mortgage          # Mortgage services
Bastion/Type/Aggregator        # Financial aggregators
```

**Healthcare Clarification**: `Bastion/Type/Healthcare` is intentionally broad:
- Medical providers & patient portals (MyChart, FollowMyHealth)
- Health insurance - use both `Bastion/Type/Healthcare` + `Bastion/Type/Insurance`
- Pharmacies (CVS, Walgreens, mail-order)
- Medical supply companies
- Telehealth services

### 2. Capability Tags (`Bastion/Capability/*`)

What the account can DO:

```
Bastion/Capability/Money-Transfer    # Can send/receive money
Bastion/Capability/Recovery          # Can recover other accounts
Bastion/Capability/Identity          # Primary identity provider (Google, Microsoft SSO)
Bastion/Capability/Secrets           # Stores secrets/credentials (1Password)
Bastion/Capability/Crypto            # Can send/receive cryptocurrency
Bastion/Capability/ICE               # In Case of Emergency contact/recovery info
Bastion/Capability/Device-Control    # Controls devices (Find My, MDM)
Bastion/Capability/Device-Management # Manages device settings
Bastion/Capability/Credit-Access     # Access to credit/loans
Bastion/Capability/Data-Export       # Can export user data
Bastion/Capability/Shared-Family     # Shared with family members
Bastion/Capability/Shared-Executor   # Shared with executor
Bastion/Capability/Shared-Beneficiary # Shared with beneficiaries
Bastion/Capability/Shared-Business   # Shared for business purposes
```

### 3. Security Priority (Use 1Password Watchtower)

> **Note**: The `Bastion/Tier/*` tags have been **deprecated** in v0.3.0.
> 
> 1Password's Watchtower already assigns security scores to items based on:
> - Password strength
> - Breach exposure
> - 2FA availability
> - Password age
> 
> Use Watchtower's built-in prioritization instead of manual tier tagging.

### 4. Dependency Tags (`Bastion/Dependency/*`)

What this account depends on for recovery - **exception-based** approach:

```
Bastion/Dependency/No-Email-Recovery  # EXCEPTION: Cannot be recovered by email
Bastion/Dependency/Phone-SMS          # Recovery requires phone SMS verification
Bastion/Dependency/Secret-Key         # Requires secret key/seed phrase
Bastion/Dependency/Backup-Codes       # Has backup codes for recovery
Bastion/Dependency/Trusted-Device     # Requires trusted device
Bastion/Dependency/YubiKey            # Requires YubiKey for recovery
Bastion/Dependency/Recovery-Contacts  # Has recovery contacts configured
Bastion/Dependency/Trusted-Contact    # Has trusted contact for recovery
```

**IMPORTANT**: 
- **DEFAULT**: All accounts with email in username field are recoverable by email
- **EXCEPTION**: Use `Bastion/Dependency/No-Email-Recovery` for accounts that CANNOT be recovered by email

### 5. 2FA Method Tags (`Bastion/2FA/*`)

What 2FA methods are actually enabled - list all that apply:

```
Bastion/2FA/FIDO2-Hardware  # Hardware security key (YubiKey, Titan)
Bastion/2FA/Passkey/Software  # Software passkey (device/browser/1Password)
Bastion/2FA/FIDO2           # Generic FIDO2 (when type is unknown)
Bastion/2FA/TOTP            # TOTP authenticator app
Bastion/2FA/Push            # Push notification to app
Bastion/2FA/SMS             # SMS code (SECURITY RISK)
Bastion/2FA/Email           # Email code
Bastion/2FA/None            # No 2FA available or enabled
```

**Important**: List ALL enabled methods to compute strongest and weakest 2FA.

### 6. Security Tags (`Bastion/Security/*`)

Account-level security status:

```
Bastion/Security/Rate-Limited        # Login attempts are rate limited
Bastion/Security/Human-Verification  # Requires human verification
Bastion/Security/Breach-Exposed      # Password in known breach (ACTION REQUIRED)
Bastion/Security/Weak-Password       # Password doesn't meet requirements
Bastion/Security/Shared-Password     # Password reused across accounts
Bastion/Security/Leaked              # Credentials leaked
Bastion/Security/Compromised         # Account compromised
Bastion/Security/Suspicious          # Suspicious activity detected
Bastion/Security/Locked              # Account locked
Bastion/Security/Disabled            # Account disabled
Bastion/Security/Expired             # Account/password expired
```

### 7. Compliance Tags (`Bastion/Compliance/*`)

Regulatory compliance requirements:

```
Bastion/Compliance/HIPAA  # Healthcare data
Bastion/Compliance/PCI    # Credit card data
Bastion/Compliance/GLBA   # Financial privacy
Bastion/Compliance/GDPR   # EU data protection
Bastion/Compliance/SOX    # Financial reporting
```

### 8. PII Tags (`Bastion/PII/*`)

Type of personal information stored:

```
Bastion/PII/Financial   # Bank accounts, credit cards
Bastion/PII/Health      # Medical records (HIPAA-protected)
Bastion/PII/Blockchain  # Crypto wallet addresses
Bastion/PII/Contact     # Emergency contacts, addresses
Bastion/PII/SSN         # Social Security Number
```

### 9. Why/Sharing Tags (`Bastion/Why/*`)

Why this item is in a shared vault:

```
Bastion/Why/Joint-Account     # Jointly owned account
Bastion/Why/Executor-Access   # Executor/attorney needs access
Bastion/Why/Beneficiary-Info  # Beneficiary information
Bastion/Why/Business-Shared   # Business shared access
Bastion/Why/Family-Emergency  # Family emergency access
Bastion/Why/Estate-Planning   # Estate planning purposes
```

### 10. Rotation Tags (`Bastion/Rotation/*`)

Password rotation schedule:

```
Bastion/Rotation/90d    # Rotate every 90 days
Bastion/Rotation/180d   # Rotate every 180 days
Bastion/Rotation/365d   # Rotate annually
Bastion/Rotation/Never  # Never rotate (service accounts, etc.)
```

---

## Example Accounts

### Identity Provider (Tier 1)
```
Title: "Google (Primary)"
Username: "user@example.com"
Tags:
  - Bastion/Type/Email
  - Bastion/Capability/Identity
  - Bastion/Capability/Recovery
  - Bastion/2FA/FIDO2-Hardware
  - Bastion/2FA/TOTP
  - Bastion/Tier/1
```

### Password Manager (Tier 1)
```
Title: "1Password"
Username: "user@example.com"
Tags:
  - Bastion/Type/Password-Manager
  - Bastion/Capability/Secrets
  - Bastion/Dependency/No-Email-Recovery
  - Bastion/Dependency/Secret-Key
  - Bastion/2FA/FIDO2-Hardware
  - Bastion/Tier/1
```

### Bank Account (Tier 2)
```
Title: "Chase Bank"
Username: "user@example.com"
Tags:
  - Bastion/Type/Bank
  - Bastion/Capability/Money-Transfer
  - Bastion/2FA/Push
  - Bastion/2FA/SMS
  - Bastion/PII/Financial
  - Bastion/Compliance/GLBA
  - Bastion/Tier/2
```

### Cryptocurrency Exchange
```
Title: "Coinbase"
Username: "user@example.com"
Tags:
  - Bastion/Type/Blockchain
  - Bastion/Capability/Crypto
  - Bastion/2FA/TOTP
  - Bastion/2FA/SMS
  - Bastion/PII/Blockchain
  - Bastion/PII/Financial
  - Bastion/Tier/2
```

### Healthcare Portal
```
Title: "MyChart (Hospital)"
Username: "user@example.com"
Tags:
  - Bastion/Type/Healthcare
  - Bastion/Compliance/HIPAA
  - Bastion/PII/Health
  - Bastion/2FA/SMS
  - Bastion/Tier/3
```

### Self-Custody Wallet (No Email Recovery)
```
Title: "MetaMask Wallet"
Username: "(no email - self-custody)"
Tags:
  - Bastion/Type/Blockchain
  - Bastion/Capability/Crypto
  - Bastion/Dependency/No-Email-Recovery
  - Bastion/Dependency/Secret-Key
  - Bastion/PII/Blockchain
  - Bastion/2FA/None
  - Bastion/Tier/1
```

---

## CLI Commands

```bash
# Add a tag to items matching a query
bsec 1p tags apply Bastion/Capability/Money-Transfer --has-tag Bastion/Type/Bank

# Add tier tags
bsec 1p tags apply Bastion/Tier/2 --query 'vault:Private'

# Remove a tag
bsec 1p tags remove Bastion/Tier/3 --has-tag Bastion/Type/Bank

# Find items with a specific tag
bsec 1p tags list Bastion/Type/Bank --query 'tier:1'

# List all tags
bsec 1p tags list

# Apply a tag to a specific item
bsec 1p tags apply <item-id> --tag "Bastion/Tier/1"
```

---

## Validation Rules

### Rule 1: NoSharedIdentityRule (CRITICAL)

Accounts with `Bastion/Capability/Identity` or `Bastion/Capability/Recovery` **must** be in Private vault.

### Rule 2: SharedNeedsRationaleRule (WARNING)

Items in shared vaults **should** have at least one `Bastion/Why/*` tag.

### Rule 3: Tier Assignment

- **Tier 1**: Identity providers, password managers, primary email
- **Tier 2**: Financial accounts, recovery-capable accounts  
- **Tier 3**: Standard accounts with PII
- **Tier 4**: Low-value accounts (entertainment, newsletters)

---

## Quick Tagging Checklist

For each account, determine:

- [ ] **Type** - What kind of service? (`Bastion/Type/*`)
- [ ] **Tier** - How critical? (`Bastion/Tier/*`)
- [ ] **Capabilities** - What can it do? (`Bastion/Capability/*`)
- [ ] **2FA Methods** - What's enabled? (`Bastion/2FA/*`) - List ALL
- [ ] **Dependencies** - Special recovery needs? (`Bastion/Dependency/*`)
- [ ] **PII Level** - What data does it contain? (`Bastion/PII/*`)
- [ ] **Compliance** - Any regulatory requirements? (`Bastion/Compliance/*`)
- [ ] **Sharing** - Is it shared? Why? (`Bastion/Why/*` if not Private)

---

## Complete Tag Reference

### By Category

| Category | Prefix | Example |
|----------|--------|---------|
| Type | `Bastion/Type/` | `Bastion/Type/Bank` |
| Capability | `Bastion/Capability/` | `Bastion/Capability/Money-Transfer` |
| Tier | `Bastion/Tier/` | `Bastion/Tier/1` |
| Dependency | `Bastion/Dependency/` | `Bastion/Dependency/Secret-Key` |
| 2FA | `Bastion/2FA/` | `Bastion/2FA/TOTP` |
| Security | `Bastion/Security/` | `Bastion/Security/Breach-Exposed` |
| Compliance | `Bastion/Compliance/` | `Bastion/Compliance/HIPAA` |
| PII | `Bastion/PII/` | `Bastion/PII/Financial` |
| Why | `Bastion/Why/` | `Bastion/Why/Joint-Account` |
| Rotation | `Bastion/Rotation/` | `Bastion/Rotation/90d` |
