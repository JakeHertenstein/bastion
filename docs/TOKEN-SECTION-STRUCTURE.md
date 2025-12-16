# Authenticator Token Section Structure

**Date**: 2025-11-22  
**Status**: Implemented - All 17 items migrated  
**Migration Tool**: `bastion/migration_yubikey_fields.py`

## Overview

Individual token sections in 1Password login items with type-specific fields for multi-authenticator support. This structure replaces the legacy flat field and section-based formats with a clean, extensible, human-readable design.

## Structure

### Token Sections

Each authenticator token gets its own section numbered sequentially:
- `Token 1`
- `Token 2`
- `Token 3`
- etc.

### Field Types by Authenticator Type

#### YubiKey Type
```
Token 1:
  Serial: 12345678
  Type: YubiKey
  OATH Name: Google:user@example.com
  TOTP Enabled: yes
  PassKey Enabled: 
```

**Required Fields:**
- `Serial` (text): YubiKey serial number (8-digit numeric)
- `Type` (text): "YubiKey"
- `OATH Name` (text): OATH account identifier (Issuer:Account format)
- `TOTP Enabled` (text): "yes" or empty
- `PassKey Enabled` (text): "yes" or empty

#### Phone App Type
```
Token 2:
  Serial: Phone-App-UUID-2024
  Type: Phone App
  OATH Name: Google:user@example.com
  App Name: Google Authenticator
```

**Required Fields:**
- `Serial` (text): Unique identifier for phone app token
- `Type` (text): "Phone App"
- `OATH Name` (text): OATH account identifier
- `App Name` (text): Name of authenticator app

#### SMS Type
```
Token 3:
  Serial: SMS-555-0123
  Type: SMS
  Phone Number: (555) 123-4567
  Carrier Name: Verizon
```

**Required Fields:**
- `Serial` (text): Unique identifier for SMS token
- `Type` (text): "SMS"
- `Phone Number` (phone): Phone number in any standard format
- `Carrier Name` (text): Mobile carrier name

## Migration Path

### Old Format (Deprecated)
```
Flat custom fields:
  yubikey_oath_name: Google:user@example.com
  yubikey_serials: 12345678,23456789,34567890
```

### New Format (Current)
```
Token 1:
  Serial: 12345678
  Type: YubiKey
  OATH Name: Google:user@example.com
  TOTP Enabled: yes
  PassKey Enabled: 

Token 2:
  Serial: 23456789
  Type: YubiKey
  OATH Name: Google:user@example.com
  TOTP Enabled: yes
  PassKey Enabled: 

Token 3:
  Serial: 34567890
  Type: YubiKey
  OATH Name: Google:user@example.com
  TOTP Enabled: yes
  PassKey Enabled: 
```

## Validation Rules

1. **Sequential Numbering**: Token sections must be numbered 1, 2, 3... with no gaps
2. **Type Validity**: Type field must be "YubiKey", "Phone App", or "SMS"
3. **Type-Specific Fields**: Required fields must be present based on type
4. **Serial Format**: 
   - YubiKey: 8-digit numeric
   - Phone App: Any unique identifier
   - SMS: Any unique identifier (commonly phone-based)

## Benefits

1. **Individual Section per Token**: Each authenticator is a distinct, self-contained section
2. **Multi-Authenticator Support**: Single account can have YubiKey, Phone App, and SMS tokens
3. **Type-Specific Fields**: Relevant fields per authenticator type (no OATH Name for SMS)
4. **Extensibility**: Easy to add new authenticator types (WebAuthn, U2F, etc.)
5. **Clean Organization**: Human-readable section names and field labels
6. **Tag Alignment**: Structure supports Bastion/TOTP/YubiKey, Bastion/TOTP/Phone-App, Bastion/TOTP/SMS tags

## Usage Examples

### Migrate Existing Items
```bash
# Check migration status
bastion migrate fields yubikey --status

# Migrate single item (interactive)
bastion migrate fields yubikey --uuid <UUID>

# Migrate all items
bastion migrate fields yubikey --all

# Dry run
bastion migrate fields yubikey --uuid <UUID> --dry-run
```

### Add Phone App Token (Future)
```bash
# Add phone app token to existing account
bastion yubikey add-phone-token <UUID> --identifier "Google-Authenticator" --app "Google Authenticator"
```

### Add SMS Token (Future)
```bash
# Add SMS token to existing account
bastion yubikey add-sms-token <UUID> --phone "+1-555-123-4567" --carrier "Verizon"
```

## Migration Status

**Completed**: 2025-11-22  
**Items Migrated**: 17/17 (100%)

### Migration Phases Executed
1. **Phase 1 (Add)**: 13 items - Created Token sections from old flat fields
2. **Phase 2 (Convert Legacy)**: 3 items - Converted YubiKey TOTP + Tokens sections to Token N sections
   - 1Password (Example): 4 tokens
   - example-domain.com: 5 tokens
   - Proxmox: 5 tokens
3. **Phase 3 (Delete Legacy)**: 1 item - Removed legacy sections while preserving Token sections
   - Google: 25 tokens (cleaned up orphaned YubiKey TOTP section)

All items now use the Token N section structure with human-readable field names.

## CLI Reading Functions

The CLI automatically detects and reads from all formats (backward compatible):

1. **New Token Sections**: Primary format (Token 1, Token 2, etc.)
2. **Legacy Tokens Section**: Backward compatibility (Tokens.token_1, etc.)
3. **Old Flat Fields**: Backward compatibility (yubikey_oath_name, yubikey_serials)

Functions like `_get_yubikey_field()` transparently handle all three formats.
