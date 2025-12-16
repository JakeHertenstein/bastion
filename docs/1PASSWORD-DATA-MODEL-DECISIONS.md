# 1Password Data Model Design Decisions

**Date**: 2025-11-22  
**Status**: Implemented  
**Context**: Security Analysis Tool (Bastion) 2.0 data model for authenticator tokens

---

## 🎯 Core Design Principles

### 1. Human-Readable Over Machine-Optimal

**Decision**: Use natural language field names and values, not snake_case or abbreviated formats.

**Rationale**:
- 1Password is a human interface - users need to read and understand fields quickly
- Emergency access scenarios require non-technical people to understand data
- Debugging and manual verification must be straightforward
- Machine parsing can adapt; human comprehension cannot

**Examples**:
- ✅ `Serial`, `Type`, `OATH Name`, `TOTP Enabled`
- ❌ `yubikey_serial`, `token_type`, `oath_name`, `totp_enabled`

**Trade-offs**:
- Slightly more verbose in code (field name strings)
- Requires case-sensitive field name handling
- **Benefit**: Zero learning curve for anyone viewing 1Password items

---

### 2. Individual Sections Over Composite Structures

**Decision**: Each authenticator token gets its own numbered section (`Token 1`, `Token 2`, etc.), not a single umbrella section with sub-fields.

**Previous Format** (Rejected):
```
YubiKey TOTP:
  oath_name: Google:user@example.com
  
Tokens:
  token_1: 12345678
  token_2: 23456789
  token_3: 34567890
```

**Current Format** (Implemented):
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
```

**Rationale**:
- **Visual Clarity**: Each token is visually distinct in 1Password UI
- **Extensibility**: Adding/removing tokens doesn't require parsing CSV or JSON
- **Type-Specific Fields**: Different authenticator types can have different fields
- **Tag Alignment**: Can tag items with `Bastion/TOTP/YubiKey`, `Bastion/TOTP/Phone-App`, `Bastion/TOTP/SMS` independently
- **Future-Proof**: Can add WebAuthn, U2F, hardware keys with unique fields

**Trade-offs**:
- More 1Password API calls to read all tokens (one per section)
- Slightly more complex CLI code to aggregate tokens
- **Benefit**: Clean separation of concerns, easier to extend with new token types

---

### 3. Type-Specific Fields Over Universal Schema

**Decision**: Different authenticator types have different required fields based on their nature.

**Field Matrix**:

| Field | YubiKey | Phone App | SMS |
|-------|---------|-----------|-----|
| Serial | ✅ 8-digit number | ✅ UUID/identifier | ✅ UUID/identifier |
| Type | ✅ "YubiKey" | ✅ "Phone App" | ✅ "SMS" |
| OATH Name | ✅ Issuer:Account | ✅ Issuer:Account | ❌ N/A |
| TOTP Enabled | ✅ yes/empty | ❌ N/A | ❌ N/A |
| PassKey Enabled | ✅ yes/empty | ❌ N/A | ❌ N/A |
| App Name | ❌ N/A | ✅ "Google Authenticator" | ❌ N/A |
| Phone Number | ❌ N/A | ❌ N/A | ✅ phone field type |
| Carrier Name | ❌ N/A | ❌ N/A | ✅ "Verizon" |

**Rationale**:
- SMS tokens don't have OATH names (they're not TOTP-based)
- YubiKeys have TOTP/PassKey capabilities that phone apps don't track
- Phone apps need app name for user context (Authy vs. Google Authenticator)
- SMS tokens need carrier info for troubleshooting delivery issues

**Validation**:
- CLI enforces type-specific required fields
- Migration tool validates field presence based on `Type` value
- Future token types can define their own field schemas

**Trade-offs**:
- Validation logic is more complex (type-dependent)
- Documentation must specify per-type requirements
- **Benefit**: Data model reflects real-world authenticator differences

---

### 4. Canonical Type Values

**Decision**: Use title-case, human-readable canonical values for `Type` field, not lowercase or codes.

**Canonical Values**:
- `YubiKey` (not `yubikey`, `yk`, or `hardware`)
- `Phone App` (not `phone_app`, `totp_app`, or `mobile`)
- `SMS` (not `sms`, `text`, or `phone`)

**Rationale**:
- Consistent with human-readable principle
- Easier to read in 1Password UI
- Clear distinction between types without abbreviations
- Extensible: `WebAuthn Device`, `Hardware Token`, `Biometric Key` fit pattern

**Validation**:
- Type field is case-sensitive
- Migration tool and CLI validate against canonical list
- New types must be added to canonical list explicitly

---

### 5. Sequential Numbering with No Gaps

**Decision**: Token sections must be numbered sequentially (1, 2, 3...) with no gaps.

**Valid**:
```
Token 1, Token 2, Token 3
Token 1, Token 2, Token 3, Token 4, Token 5
```

**Invalid**:
```
Token 1, Token 3, Token 5  ❌ (gaps)
Token 0, Token 1, Token 2  ❌ (starts at 0)
Token A, Token B, Token C  ❌ (not numeric)
```

**Rationale**:
- Predictable iteration for CLI tools (range 1 to N)
- No ambiguity about token count
- Easier debugging (missing tokens show as gaps)
- Consistent with human counting (1-indexed)

**Migration Behavior**:
- When adding tokens, find max existing number and increment
- When removing tokens, optionally renumber to close gaps (not required)
- Status reporting shows token count (e.g., "5 tokens")

---

### 6. Backward Compatibility During Migration

**Decision**: Support reading from three formats during transition period, write only new format.

**Supported Read Formats**:
1. **Old Flat Fields** (deprecated, pre-2025):
   - `yubikey_oath_name` (text)
   - `yubikey_serials` (CSV: "123,456,789")

2. **Legacy Intermediate** (deprecated, mid-2025):
   - `YubiKey TOTP` section with `oath_name`, `serials`
   - `Tokens` section with `token_1`, `token_2`, etc.

3. **Current Token Sections** (active, 2025-11-22):
   - `Token N` sections with type-specific fields

**Write Format**: Only Token N sections (current format)

**Rationale**:
- Zero-downtime migration (CLI works before and after migration)
- Users can migrate items individually or in batches
- Rollback possible if issues discovered
- No hard cutover date required

**CLI Behavior**:
```python
def _get_yubikey_field(uuid, field_name):
    # Try Token sections first (new format)
    # Fall back to legacy Tokens section
    # Fall back to old flat fields
    # Return None if not found
```

**Migration Tool**:
- Detects format automatically
- Phases: add, convert_legacy, delete_legacy, delete, done
- Dry-run mode for safety
- Non-interactive mode for batch operations

---

### 7. Phone Field Type for Phone Numbers

**Decision**: Use 1Password's native `phone` field type for SMS token phone numbers, not `text`.

**Example**:
```
Token 3:
  Serial: SMS-555-0123
  Type: SMS
  Phone Number: (555) 123-4567  [phone field type]
  Carrier Name: Verizon
```

**Rationale**:
- 1Password formats phone numbers consistently
- Click-to-call/SMS functionality in 1Password apps
- Validation by 1Password (proper phone format)
- International format support (E.164)

**Implementation**:
```python
# CLI code
{
    "label": "Phone Number",
    "type": "PHONE",  # 1Password API constant
    "value": phone_number
}
```

---

### 8. Empty vs. Absent Fields

**Decision**: Optional fields can be present-but-empty or absent entirely. Required fields must be present (can be empty if truly unknown).

**Examples**:

**Valid (field present but empty)**:
```
Token 1:
  Serial: 12345678
  Type: YubiKey
  OATH Name: Google:user@example.com
  TOTP Enabled: yes
  PassKey Enabled:              ← Empty but present
```

**Valid (field absent)**:
```
Token 1:
  Serial: 12345678
  Type: YubiKey
  OATH Name: Google:user@example.com
  TOTP Enabled: yes
                                ← PassKey Enabled not present at all
```

**Invalid (required field absent)**:
```
Token 1:
  Type: YubiKey               ← Missing required Serial field
  OATH Name: Google:user@example.com
```

**Rationale**:
- 1Password API allows both patterns
- Empty fields show in UI (visual consistency)
- Absent fields reduce clutter for truly optional data
- Migration tool creates empty placeholders for forward compatibility

**CLI Handling**:
```python
# Treat both as "not set"
field_value = get_field(item, "PassKey Enabled")
if not field_value or field_value.strip() == "":
    # Field is not set
```

---

### 9. OATH Name Format: Issuer:Account

**Decision**: OATH Name must follow `Issuer:Account` format consistently.

**Examples**:
- ✅ `Google:user@example.com`
- ✅ `1Password (Example):email@example.com`
- ✅ `AWS:arn:aws:iam::123456789012:user/admin`
- ❌ `user@example.com` (missing issuer)
- ❌ `Google - user@example.com` (wrong separator)
- ❌ `Google user@example.com` (no separator)

**Rationale**:
- Standard TOTP/OATH format (RFC 6238)
- Matches QR code format when provisioning YubiKeys
- Consistent with 1Password's TOTP item format
- Required for YubiKey Manager import/export
- Enables account-level deduplication (same issuer:account across tokens)

**Validation**:
- Must contain exactly one colon
- Issuer cannot be empty
- Account cannot be empty
- Colons in account part should be escaped or URI-encoded

**Migration Behavior**:
- Preserve OATH Name exactly as stored
- Don't attempt to reformat or "fix" existing names
- Warn if format doesn't match standard (but allow it)

---

### 10. Migration Phases: Explicit State Machine

**Decision**: Migration follows explicit phases with clear transitions, not implicit logic.

**Phase Flow**:
```
none → add → delete → done
none → convert_legacy → delete_legacy → done
done → done (idempotent)
```

**Phase Definitions**:
1. **none**: Cannot determine state (error or edge case)
2. **add**: Old flat fields only → create Token sections
3. **convert_legacy**: YubiKey TOTP + Tokens sections → Token sections
4. **delete_legacy**: Legacy sections + Token sections → delete legacy only
5. **delete**: Old flat + Token sections → delete old flat
6. **done**: Only Token sections present

**Rationale**:
- Clear error messages ("item is in phase X, need to run phase Y")
- Safe progression (never delete before creating)
- Skip phases that don't apply (no old fields = skip delete)
- Idempotent operations (running done phase on done item is safe)
- Dry-run testing per phase

**Implementation**:
```python
def analyze_item_state(item_data):
    state = {
        "has_old_fields": bool,
        "has_legacy_fields": bool,
        "has_new_fields": bool,
        "phase": str
    }
    # State detection logic
    return state
```

**Status Display**:
```
Google     example1234abcd  delete_legacy  Google:user@work.example.com  25 tokens
Proxmox    example5678efgh  done          Proxmox:root@pam        5 tokens
```

---

## 🔄 Migration Tool Architecture

### Three-Format Support

The migration tool handles three distinct legacy formats that appeared over time:

1. **Old Flat Fields** (earliest format):
   ```
   yubikey_oath_name: Google:user@example.com
   yubikey_serials: 12345678,23456789,34567890
   ```

2. **Legacy Intermediate** (mid-period format):
   ```
   YubiKey TOTP:
     oath_name: Google:user@example.com
     serials: 12345678,23456789,34567890
   
   Tokens:
     token_1: 12345678
     token_2: 23456789
     token_3: 34567890
   ```

3. **Current Token Sections** (final format):
   ```
   Token 1:
     Serial: 12345678
     Type: YubiKey
     OATH Name: Google:user@example.com
     TOTP Enabled: yes
     PassKey Enabled: 
   ```

### Phase Detection Logic

```python
if has_old_fields and not has_new_fields:
    phase = "add"
elif has_legacy_fields and not has_new_fields:
    phase = "convert_legacy"
elif has_legacy_fields and has_new_fields:
    phase = "delete_legacy"
elif has_old_fields and has_new_fields:
    phase = "delete"
elif has_new_fields and not has_old_fields and not has_legacy_fields:
    phase = "done"
else:
    phase = "none"
```

### Migration Methods

1. **add_new_fields()**: Create Token sections from old flat fields
2. **convert_legacy_tokens()**: Convert legacy sections to Token sections
3. **delete_legacy_fields()**: Delete legacy sections (keep Token sections)
4. **delete_old_fields()**: Delete old flat fields (keep Token sections)

### Safety Features

- **Dry-run mode**: Preview changes without executing
- **Interactive mode**: Prompt before each migration
- **Non-interactive mode**: Batch operations with `--all` flag
- **Validation**: Check data integrity before deletion
- **Logging**: JSON log of all operations (`yubikey_migration.log.json`)
- **Status table**: Overview of all items and phases

---

## 🎯 Design Goals Achieved

### ✅ Human Readability
- Natural language field names
- Clear section structure
- Self-documenting data model

### ✅ Extensibility
- Type-specific fields support new authenticator types
- Sequential token numbering allows unlimited tokens
- Canonical types can grow (WebAuthn, U2F, etc.)

### ✅ Safety
- Backward compatibility during migration
- Explicit phases prevent data loss
- Dry-run and interactive modes for verification

### ✅ Consistency
- Canonical values enforced
- Sequential numbering required
- OATH Name format standardized

### ✅ Practicality
- Zero-downtime migration
- Works with existing Bastion 2.0 tag system
- CLI automatically detects format

---

## 📊 Migration Statistics

**Date Completed**: 2025-11-22  
**Total Items**: 17  
**Success Rate**: 100%

### Phase Breakdown
- **Phase 1 (Add)**: 13 items
- **Phase 2 (Convert Legacy)**: 3 items
  - 1Password (Example): 4 tokens
  - example-domain.com: 5 tokens
  - Proxmox: 5 tokens
- **Phase 3 (Delete Legacy)**: 1 item
  - Google: 25 tokens

### Verification
All migrated items verified with:
```bash
op item get <uuid> --fields "Token 1.Serial,Token 1.Type,Token 1.OATH Name"
```

Example output:
```
45678901,YubiKey,1Password (Example):email@example.com
```

---

## 🔮 Future Enhancements

### ✅ Implemented Features (Phase 1 - 2025-11-23)

**Foundation Components**:
- ✅ `TokenAnalyzer` - Utility class for parsing token structure (~300 lines)
- ✅ `TokenValidator` - Validation framework with phone/OATH/serial validators (~250 lines)
- ✅ `TokenTagManager` - Automatic tag management for token operations (~190 lines)

**Core CLI Commands**:
1. ✅ **`bastion add app token`** - Add Phone App authenticator tokens
   ```bash
   bastion add app token <UUID> --app "Google Authenticator" --identifier "Phone-App-Google-2025"
   ```
   - Validates OATH name format (Issuer:Account)
   - Checks serial uniqueness
   - Auto-adds `Bastion/TOTP/Phone-App` tag
   - Interactive confirmation with --dry-run support

2. ✅ **`bastion add sms token`** - Add SMS authenticator tokens
   ```bash
   bastion add sms token <UUID> --phone "+1-555-123-4567" --carrier "Verizon"
   ```
   - Auto-generates serial (SMS-4567) if not provided
   - Permissive phone number validation with warnings
   - Auto-adds `Bastion/TOTP/SMS` tag
   - Uses 1Password's native phone field type

3. ✅ **`bastion remove token`** - Remove tokens by number
   ```bash
   bastion remove token <UUID> 2 [--renumber]
   ```
   - Shows token details before removal
   - Warns if removing last token of type
   - Auto-removes type tags when appropriate
   - Optional --renumber to close gaps

4. ✅ **`bastion renumber token`** - Close gaps in token numbering
   ```bash
   bastion renumber token <UUID>
   ```
   - Detects and displays gaps
   - Preserves all token data during renumbering
   - Safe READ → DELETE → CREATE sequence

**Validation Features**:
- ✅ Phone number format linting (permissive with warnings)
- ✅ OATH name format validation (Issuer:Account)
- ✅ Serial uniqueness checking (within-item)
- ✅ Token count warnings (10+ tokens)
- ✅ Type-specific field validation

**Tag Management**:
- ✅ Auto-add tags when tokens added (Bastion/TOTP/Phone-App, Bastion/TOTP/SMS)
- ✅ Auto-remove tags when last token of type removed
- ✅ Mixed token type support (preserves all relevant tags)
- ✅ Tag sync utility for fixing mismatches

### Planned Features (Future Phases)

1. **Additional Token Types** (Priority 2):
   - WebAuthn Device (for FIDO2 devices)
   - Hardware Token (for RSA SecurID, etc.)
   - Biometric Key (for fingerprint readers)

2. **Enhanced Validation** (Priority 3):
   - Cross-item serial detection (with --check-duplicates-global flag)
   - E.164 phone number normalization (optional)
   - OATH name auto-correction suggestions
   - Token expiration tracking for Hardware Tokens

3. **Bulk Operations** (Priority 4):
   - `bastion token list` - Show all tokens across items
   - `bastion token sync-tags` - Bulk tag synchronization
   - `bastion token validate` - Comprehensive validation report
   - `bastion token migrate-to-phone` - Convert YubiKey to Phone App

4. **Reporting** (Priority 5):
   - Token statistics in `bastion report`
   - Token type distribution charts
   - Authenticator coverage analysis
   - Expiration warnings

---

## 📖 Related Documents

- `TOKEN-SECTION-STRUCTURE.md` - Technical structure and usage examples
- `RISK-ANALYSIS.md` - Risk scoring algorithm and analysis system
- `BASTION-TAGGING-GUIDE.md` - Tag hierarchy and management
- `CRITICAL-DECISIONS.md` - 1Password security architecture decisions
- `bastion/migration_yubikey_fields.py` - Migration tool implementation

---

**Next Steps**: Document future CLI commands and extend validation rules for additional token types.
