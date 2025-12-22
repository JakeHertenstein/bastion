# 1Password Item Linking Implementation

## Overview

This document captures the findings, limitations, and implementation details for creating native bidirectional links between 1Password items using the Related Items feature.

## Discovery Process

### Initial Attempts (Failed)
1. **Command-line field assignment syntax**: `op item edit ITEM "section.field[reference]=UUID"` - Not supported
2. **JSON stdin without proper structure**: Missing required properties caused silent failures
3. **JSON stdin with `reference` property**: Worked once, then became unreliable (~20-50% success rate)

### Successful Approach (Working)
Using JSON stdin with proper section management and field structure:

```python
# 1. Get item JSON
item_data = json.loads(subprocess.run(["op", "item", "get", ITEM_UUID, "--format", "json"], ...))

# 2. Ensure sections array exists
if "sections" not in item_data:
    item_data["sections"] = []

# 3. Ensure "Related Items" section exists
section_id = None
for section in item_data["sections"]:
    if section.get("label") == "Related Items":
        section_id = section.get("id")
        break

if not section_id:
    section_id = "related_items"
    item_data["sections"].append({
        "id": section_id,
        "label": "Related Items"
    })

# 4. Add REFERENCE field (1Password generates the reference property automatically)
new_field = {
    "section": {"id": section_id, "label": "Related Items"},
    "type": "REFERENCE",
    "label": "Target Item Title",
    "value": "target-uuid"
}
item_data["fields"].append(new_field)

# 5. Submit via stdin (DO NOT include "reference" property - it's auto-generated)
subprocess.run(["op", "item", "edit", ITEM_UUID, "-"], input=json.dumps(item_data), ...)
```

## Key Findings

### Critical Requirements
1. **Sections array must exist** - Create empty array if missing
2. **Related Items section must exist** - Create with proper ID and label
3. **DO NOT include `reference` property** - 1Password CLI generates this automatically
4. **Use proper section ID** - Either "linked items" (1Password default) or "related_items" (custom)

### Item Type Support

#### ✅ Fully Supported (100% Success)
- **LOGIN** - Standard login items (no `category_id`)
- **SECURE_NOTE** - Secure notes
- **PASSWORD** - Password items

#### ⚠️ Partially Supported
- **CUSTOM with `category_id`** - Can be linked TO, but cannot be edited to add links
  - Example: "Crypto Wallet" items (category_id: "115")
  - Workaround: Convert to SECURE_NOTE type or create links manually in UI

#### ❌ Not Supported
- Items without proper JSON export support
- Items that fail round-trip test: `op item get UUID --format json | op item edit UUID -`

### 1Password CLI Bug

**CUSTOM category items with `category_id` cannot be edited via JSON stdin:**

```bash
# This fails even without modifications:
op item get CUSTOM_ITEM_UUID --format json | op item edit CUSTOM_ITEM_UUID -

# Error:
[ERROR] unable to process line 1: failed to edit due to identity 
inconsistencies: for Category CUSTOM found in the template was 
inconsistent with CUSTOM found in item to be edited
```

**Root Cause**: The CLI has an undocumented limitation where CUSTOM category items with a `category_id` field cannot be edited via JSON template, even when no changes are made.

**Detection**: Check for `category == "CUSTOM"` AND `category_id` exists

**Workaround**: Convert CUSTOM items to SECURE_NOTE type before linking

## Implementation Rules

### Item Type Validation

```python
SUPPORTED_LINK_CATEGORIES = {
    "LOGIN",
    "SECURE_NOTE", 
    "PASSWORD",
}

def can_edit_item(item_data: dict) -> tuple[bool, str]:
    """Check if an item can be edited via JSON stdin."""
    category = item_data.get("category", "")
    
    # Check if category is in supported list
    if category in SUPPORTED_LINK_CATEGORIES:
        return True, ""
    
    # CUSTOM items with category_id cannot be edited
    if category == "CUSTOM" and item_data.get("category_id"):
        return False, (
            "CUSTOM items with category_id cannot be edited via JSON stdin "
            "(1Password CLI limitation). Convert to SECURE_NOTE first using: "
            "bastion convert to-note <uuid>"
        )
    
    # CUSTOM items without category_id should work
    if category == "CUSTOM":
        return True, ""
    
    # Unknown/untested category
    return False, f"Untested item category: {category}"
```

### Duplicate Detection

```python
def link_exists(item_data: dict, target_uuid: str) -> bool:
    """Check if a link already exists."""
    for field in item_data.get("fields", []):
        if (field.get("type") == "REFERENCE" and 
            field.get("value") == target_uuid and
            field.get("section", {}).get("label") == "Related Items"):
            return True
    return False
```

## Migration Strategy

### Converting CUSTOM Items to SECURE_NOTE

For items like "RSA Token" (Crypto Wallet type), convert to Secure Note:

```python
def convert_to_secure_note(item_uuid: str) -> bool:
    """Convert a CUSTOM item to SECURE_NOTE type."""
    # Get item data
    result = subprocess.run(
        ["op", "item", "get", item_uuid, "--format", "json"],
        capture_output=True, text=True, check=True, timeout=30
    )
    item_data = json.loads(result.stdout)
    
    # Change category
    item_data["category"] = "SECURE_NOTE"
    
    # Remove category_id if present
    if "category_id" in item_data:
        del item_data["category_id"]
    
    # Submit via stdin
    result = subprocess.run(
        ["op", "item", "edit", item_uuid, "-"],
        input=json.dumps(item_data),
        capture_output=True, text=True, check=True, timeout=30
    )
    
    return True
```

## CLI Commands

### Create Link
```bash
bastion create link SOURCE_UUID TARGET_UUID [--bidirectional]
```

### List Links
```bash
bastion list links ITEM_UUID
```

### Convert Item Type
```bash
bastion convert to-note ITEM_UUID [--dry-run]
bastion convert tokens-to-notes [--tag TOKEN_TAG] [--dry-run]
```

## Testing Guidelines

### Before Adding Link Support for New Item Type

1. **Round-trip test**:
   ```bash
   op item get ITEM_UUID --format json | op item edit ITEM_UUID -
   ```
   If this fails, the item type is not supported.

2. **Manual link test**:
   - Create link manually in 1Password UI
   - Verify `op item get ITEM_UUID --format json` shows REFERENCE field
   - Test `bastion list links ITEM_UUID` displays it correctly

3. **Programmatic link test**:
   ```bash
   bastion create link ITEM_UUID TARGET_UUID
   op item get ITEM_UUID --format json | jq '.fields[] | select(.type == "REFERENCE")'
   ```

### Test Matrix

| Source Type | Target Type | Status | Notes |
|------------|-------------|--------|-------|
| LOGIN | LOGIN | ✅ | Fully working |
| LOGIN | SECURE_NOTE | ✅ | Fully working |
| SECURE_NOTE | LOGIN | ✅ | Fully working |
| LOGIN | CUSTOM (Crypto Wallet) | ⚠️ | Forward only, reverse fails |
| CUSTOM (Crypto Wallet) | LOGIN | ❌ | Cannot edit CUSTOM items |
| CUSTOM (Crypto Wallet) | CUSTOM | ❌ | Cannot edit either |

## Performance Considerations

- Add 0.5 second delay between bidirectional link creation
- Prevents race conditions when editing same vault rapidly

## Version History

- **2025-11-24**: Initial implementation
  - Discovered JSON stdin approach with section management
  - Identified CUSTOM item limitation
  - Implemented graceful error handling
  - Added item type validation
  - Created conversion commands
