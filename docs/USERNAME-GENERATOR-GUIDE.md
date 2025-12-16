# Username Generator Guide

## Overview

The Bastion username generator creates **deterministic, non-reversible, traceable usernames** using HMAC-SHA512 cryptography and Base36 encoding. This ensures:

- **Deterministic**: Same service label always produces the same username
- **Non-Reversible**: Cannot derive the label from the username (one-way hash)
- **Traceable**: Can verify/regenerate usernames by recomputing with the secret salt
- **Compatible**: Uses only lowercase alphanumeric characters (a-z, 0-9)
- **Unique**: Different service labels produce completely different usernames

## Security Model

```
Service Label + Secret Salt → HMAC-SHA512 → Base36 Encoding → Username
```

- **Secret Salt**: 256-bit random value stored in 1Password
- **HMAC-SHA512**: Default cryptographic hash function (SHA256, SHA3-512 also available)
- **Base36 Encoding**: Converts hash to [a-z0-9] characters for maximum compatibility
- **Length Control**: Truncate to desired length (default: 16 characters, max: 100 for SHA512)

## Installation & Setup

### Step 1: Initialize the Generator (One-Time Setup)

Create the secret salt item in 1Password:

```bash
bastion generate username --init
```

This creates an item titled "Bastion Username Generator Salt" containing:
- 256-bit cryptographically random secret salt
- Stored in your Private vault (customizable with `--vault`)

**⚠️ CRITICAL: Back up this item immediately!**

Without the salt, you cannot:
- Regenerate existing usernames
- Verify usernames
- Maintain consistency across devices

### Step 2: Verify Installation

Generate a test username:

```bash
bastion generate username test
```

Expected output:
```
Generated username for 'test': 3k8m2n9p1q4r7s0t
```

## Basic Usage

### Generate Username (Display Only)

Generate and display a username without creating a 1Password item:

```bash
bastion generate username github
# Output: Generated username for 'github': h7x2k9m4p8q3n1r5

bastion generate username aws --length 20
# Output: Generated username for 'aws': a1b2c3d4e5f6g7h8i9j0
```

### Generate and Store in 1Password

Create a login item with the generated username:

```bash
bastion generate username github \
  --title "GitHub" \
  --website https://github.com \
  --tags "Bastion/Username/Generated,Development"
```

This creates a 1Password login item containing:
- **Title**: GitHub
- **Username**: (generated, e.g., `h7x2k9m4p8q3n1r5`)
- **Password**: (empty - you set this manually or use a password manager)
- **Website**: https://github.com
- **Tags**: `Bastion/Username/Generated`, `Development`
- **Custom Fields**:
  - `username_label`: github
  - `username_length`: 16

### Verify Username

Confirm a username matches a specific service label:

```bash
bastion generate username github --verify h7x2k9m4p8q3n1r5
```

Outputs:
- ✅ Success: "Username 'h7x2k9m4p8q3n1r5' matches label 'github'"
- ✗ Failure: "Username does NOT match label 'github'"

## Advanced Usage

### Custom Username Length

```bash
bastion generate username stripe --length 24
# Longer username for services requiring minimum length
```

**Note**: Maximum length is 51 characters (limit of Base36 encoding from SHA256 hash).

### Custom Vault

Store the salt or login items in a different vault:

```bash
# Initialize in different vault
bastion generate username --init --vault "Work"

# Create login in different vault
bastion generate username aws --title "AWS" --vault "Work"
```

### Nonce Mode (Stolen Seed Protection)

Nonce mode generates **non-recoverable usernames** that protect against stolen salt compromise.

#### The Problem

Without nonce mode, if an attacker steals your salt, they can regenerate ALL your usernames by iterating through common domains:

```python
# Attacker with stolen salt:
for domain in ['github.com', 'google.com', 'aws.amazon.com', ...]:
    username = hmac_sha512(stolen_salt, domain)  # Exposes all usernames!
```

#### The Solution

With nonce mode, a random value is included in generation that only exists in your 1Password:

```bash
bastion generate username github.com --nonce
# Output: Generated username with nonce: h7x2k9m4p8q3n1r5
# Label: Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&NONCE=Kx7mQ9bL&LENGTH=16|M
```

Even with the salt, an attacker cannot guess the random nonce.

#### Security Trade-off

| Mode | Recoverable from Salt? | Stolen Salt Risk | Required for Recovery |
|------|------------------------|------------------|----------------------|
| Standard | ✅ Yes | All usernames exposed | Salt only |
| Nonce | ❌ No | Only stored usernames | Salt + 1Password |

#### When to Use Nonce Mode

✅ **Recommended for:**
- High-security accounts (banking, email)
- When you always have 1Password access
- Defense-in-depth against salt compromise

❌ **NOT recommended for:**
- Emergency recovery scenarios (1Password may be unavailable)
- Accounts that need seed-card-only recovery
- When you want minimal recovery dependencies

#### Verifying Nonce Usernames

The nonce is embedded in the label, so verification works the same:

```bash
bastion generate username --verify h7x2k9m4p8q3n1r5 \
  --label "Bastion/USER/SHA2/512:github.com:2025-11-30#VERSION=1&NONCE=Kx7mQ9bL&LENGTH=16|M"
```

### Batch Creation

Create multiple usernames at once:

```bash
for service in github gitlab bitbucket; do
  bastion generate username $service --title "$(echo $service | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')"
done
```

## Common Workflows

### New Service Registration

1. Generate username:
   ```bash
   bastion generate username newservice
   ```

2. Copy the username to the registration form

3. Create 1Password item for reference:
   ```bash
   bastion generate username newservice \
     --title "New Service" \
     --website https://newservice.com \
     --tags "Bastion/Username/Generated"
   ```

4. Set password in 1Password (manually or use password generator)

### Cross-Device Consistency

Since usernames are deterministic:

1. Install Bastion on new device
2. Sync 1Password (ensure salt item is synced)
3. Generate username with same label:
   ```bash
   bastion generate username github
   ```
4. Produces identical username as original device

### Username Recovery

If you forget which username you used for a service:

1. Check 1Password for the login item
2. Look at the `username_label` custom field
3. Regenerate if needed:
   ```bash
   bastion generate username <label_from_field>
   ```

### Verification Workflow

Confirm a username in the wild matches your records:

```bash
# Found username: h7x2k9m4p8q3n1r5
# Suspected service: github

bastion generate username github --verify h7x2k9m4p8q3n1r5
```

## Best Practices

### Service Labeling

Use consistent, memorable labels:

- **Good**: `github`, `aws-prod`, `stripe-test`
- **Bad**: `gh`, `amazon-web-services-production-environment`

**Tip**: Keep labels short but descriptive. You'll need to remember them to regenerate usernames.

### Tag Strategy

Standardize tags for easy tracking:

- `Bastion/Username/Generated` - Mark all generated usernames
- `Bastion/Username/Personal` - Personal accounts
- `Bastion/Username/Work` - Work accounts
- `Development`, `Production`, `Testing` - Environment tags

### Salt Backup

1. **Export salt item** from 1Password after creation
2. **Store backup** in secure location (encrypted USB, secure note, password manager)
3. **Test restoration** periodically

### Security Considerations

- **Never share the salt**: Anyone with the salt can regenerate all your usernames
- **Use unique labels**: Different services should have different labels
- **Verify regularly**: Periodically verify critical usernames match their labels
- **Backup the salt**: Loss of salt = loss of traceability

## Troubleshooting

### Error: Salt item not found

**Cause**: Salt item doesn't exist in 1Password

**Solution**: Run initialization:
```bash
bastion generate username --init
```

### Error: Verification failed

**Cause**: Username was generated with different label or salt

**Solutions**:
1. Check 1Password item's `username_label` field
2. Verify you're using the correct 1Password account
3. Confirm salt item hasn't changed

### Different username on different devices

**Cause**: Using different salt items or 1Password accounts

**Solutions**:
1. Ensure 1Password sync is complete
2. Check salt item exists: `op item get "Bastion Username Generator Salt"`
3. Verify same vault is being used

## Technical Details

### Algorithm

```python
def generate_username(label: str, secret_salt: str, length: int = 16) -> str:
    # 1. Compute HMAC-SHA256
    hmac_hash = hmac.new(
        secret_salt.encode('utf-8'),
        label.encode('utf-8'),
        hashlib.sha256
    )
    
    # 2. Convert digest to integer
    hash_int = int.from_bytes(hmac_hash.digest(), 'big')
    
    # 3. Encode as Base36 (0-9a-z)
    base36_chars = '0123456789abcdefghijklmnopqrstuvwxyz'
    username = []
    while hash_int > 0 and len(username) < 51:
        hash_int, remainder = divmod(hash_int, 36)
        username.append(base36_chars[remainder])
    
    # 4. Truncate to desired length
    return ''.join(username[:length])
```

### Character Set

Base36 encoding uses: `0123456789abcdefghijklmnopqrstuvwxyz`

- **Lowercase only**: Maximum compatibility
- **Alphanumeric**: No special characters to escape
- **URL-safe**: Safe for use in URLs and APIs

### Length Constraints

- **Minimum**: 1 character (not recommended)
- **Default**: 16 characters (good balance)
- **Maximum**: 51 characters (Base36 limit from SHA256)

### 1Password Integration

The generator stores two types of items:

1. **Salt Item** (Password category):
   - Title: "Bastion Username Generator Salt"
   - Password field: 256-bit hex salt
   - Tags: `Bastion/Username/Generator`

2. **Login Items** (Login category):
   - Title: User-specified
   - Username: Generated username
   - Password: User-set (empty initially)
   - Custom Fields:
     - `username_label` (text): Original service label
     - `username_length` (text): Length used for generation
   - Tags: User-specified + `Bastion/Username/Generated`

## Command Reference

### Initialize

```bash
bastion generate username --init [--vault VAULT]
```

Create the secret salt item in 1Password.

**Options**:
- `--vault` (default: `Private`): Vault to store salt item

### Generate

```bash
bastion generate username LABEL [OPTIONS]
```

Generate a username for the specified service label.

**Arguments**:
- `LABEL`: Service label (e.g., `github`, `aws`, `stripe`)

**Options**:
- `--length` / `-l` (default: `16`): Username length (1-51)
- `--title`: Create 1Password login item with this title
- `--website` / `-w`: Website URL for login item
- `--vault` / `-v` (default: `Private`): Vault for login item
- `--tags` / `-t`: Comma-separated tags for login item

**Examples**:
```bash
# Display only
bastion generate username github

# Create login item
bastion generate username github --title "GitHub" --website https://github.com

# Custom length
bastion generate username aws --length 20

# Multiple tags
bastion generate username stripe --title "Stripe" --tags "Bastion/Username/Generated,Payment,Production"
```

### Verify

```bash
bastion generate username LABEL --verify USERNAME
```

Verify that a username matches the specified service label.

**Arguments**:
- `LABEL`: Service label to verify against
- `--verify`: Username to verify

**Example**:
```bash
bastion generate username github --verify h7x2k9m4p8q3n1r5
```

## Examples

### Complete Workflow: New Service

```bash
# Step 1: Generate username
$ bastion generate username mybank
Generated username for 'mybank': m9k2p8x3q1n4r7s5

# Step 2: Use username to register at mybank.com
# (copy m9k2p8x3q1n4r7s5 to registration form)

# Step 3: Create 1Password item
$ bastion generate username mybank \
  --title "MyBank" \
  --website https://mybank.com \
  --tags "Bastion/Username/Generated,Finance"

✅ Created login item:
   Title: MyBank
   Username: m9k2p8x3q1n4r7s5
   UUID: abc123...
   Vault: Private

Custom fields added:
   username_label: mybank
   username_length: 16

# Step 4: Set password in 1Password (use strong password generator)
```

### Recovery: Forgot Username for Service

```bash
# Check 1Password item for "GitHub"
# See custom field: username_label = github

# Regenerate username
$ bastion generate username github
Generated username for 'github': h7x2k9m4p8q3n1r5

# Verify against what you have in 1Password
$ bastion generate username github --verify h7x2k9m4p8q3n1r5
✅ Username 'h7x2k9m4p8q3n1r5' matches label 'github'
```

### Migration: Moving to New Salt

⚠️ **Warning**: This breaks all existing username traceability!

```bash
# Step 1: Export old salt
$ op item get "Bastion Username Generator Salt" --format json > old-salt-backup.json

# Step 2: Delete old salt item
$ op item delete "Bastion Username Generator Salt"

# Step 3: Create new salt
$ bastion generate username --init

# Step 4: Regenerate ALL usernames
# (requires manually updating each service with new username)
```

## FAQ

**Q: Can someone reverse-engineer my username to get the service label?**

A: No. HMAC-SHA256 is a one-way cryptographic hash. Given the username, you cannot derive the label without brute-forcing all possible labels.

**Q: What happens if I lose the salt?**

A: You lose the ability to:
- Regenerate existing usernames (you'll still have them in 1Password)
- Verify usernames against labels
- Generate new usernames with the same deterministic mapping

You would need to create a new salt and regenerate all usernames.

**Q: Can I use the same salt across multiple devices?**

A: Yes! That's the point. The salt is stored in 1Password and syncs across all your devices. Generate the same username on any device by using the same label.

**Q: Should I use different salts for personal vs. work accounts?**

A: Optional. If you want complete separation, use different vaults and initialize separate salts. Otherwise, one salt for all accounts is fine since labels differentiate services.

**Q: How is this better than random usernames?**

A: Deterministic generation means:
- No need to store usernames separately
- Can regenerate on any device
- Can verify usernames match their services
- Traceable to the original service label

**Q: Can I customize the character set (e.g., add uppercase)?**

A: Currently no. Base36 (0-9a-z) is hardcoded for maximum compatibility. Uppercase and special characters can cause issues with some services.

**Q: What's the collision probability?**

A: Negligible. HMAC-SHA256 produces 256-bit hashes. Even truncated to 16 characters (Base36), the probability of collision is astronomically low (approximately 1 in 3.7×10²⁴).

## Related Documentation

- [BASTION-TAGGING-GUIDE.md](./BASTION-TAGGING-GUIDE.md): Tag organization for username items
- [RISK-ANALYSIS.md](./RISK-ANALYSIS.md): Risk scoring algorithm and analysis system
- [bastion/username_generator.py](./bastion/username_generator.py): Implementation details

## Support

For issues or feature requests, see the main project documentation or submit an issue.
