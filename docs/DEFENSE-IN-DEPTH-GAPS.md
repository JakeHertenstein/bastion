# Defense in Depth: Gap Analysis & Roadmap

> Working document tracking identified gaps in the security strategy and planned mitigations.
> 
> Created: 2025-12-11
> Last Updated: 2025-12-11

## Status Legend

- ⬜ Not Started
- 🔄 In Progress
- ✅ Complete
- ⏸️ Deferred
- ❌ Won't Fix (with rationale)

---

## 1. Recovery Testing & Verification

**Risk**: Backups exist but have never been tested; discover failure during actual emergency.

| Item | Status | Priority | Notes |
|------|--------|----------|-------|
| SLIP-39 recovery drill schedule | ⬜ | HIGH | Quarterly? Annual? |
| `bsec 1p audit recovery-readiness` command | ⬜ | MEDIUM | Check share freshness, last test date |
| Backup media integrity verification | ⬜ | MEDIUM | Hash checks on SD cards, cloud backups |
| Document time-to-recovery target | ⬜ | LOW | RTO for "total loss" scenario |
| Recovery drill logging in sigchain | ⬜ | LOW | `RecoveryDrillCompleted` event type |

### Design Notes

```
Recovery Readiness Check:
- Last SLIP-39 share verification date (stored in 1Password note?)
- Age of backup entropy pools
- Last successful cache restoration test
- Emergency contact info freshness
```

---

## 2. Infrastructure Key Rotation

**Risk**: Long-lived keys accumulate risk; no rotation = permanent compromise if leaked.

| Item | Status | Priority | Notes |
|------|--------|----------|-------|
| Cache encryption key rotation policy | ⬜ | HIGH | Annual? After suspected compromise? |
| Username salt rotation (breaking change!) | ⬜ | LOW | Probably never—by design |
| Sigchain signing key rotation | ⬜ | MEDIUM | Key rollover event in sigchain |
| YubiKey hardware lifecycle policy | ⬜ | LOW | Replace every N years? After firmware CVE? |
| Document rotation procedures | ⬜ | MEDIUM | Step-by-step runbook |

### Design Notes

```
Key Rotation Considerations:
- Cache key: Re-encrypt cache with new key, store both temporarily
- Sigchain: KeyRotation event with new public key, signed by old key
- Username salt: NEVER rotate (breaks all generated usernames)
```

---

## 3. Operational Security (OpSec)

**Risk**: Passwords leak via side channels (clipboard, memory, logs).

| Item | Status | Priority | Notes |
|------|--------|----------|-------|
| Clipboard auto-clear | ⬜ | MEDIUM | 1Password handles this; verify Bastion doesn't bypass |
| Secure memory handling | ⬜ | LOW | Python limitation; document risk |
| 1Password history/version cleanup | ⬜ | LOW | Old password versions in item history |
| Log sanitization audit | ⬜ | MEDIUM | Ensure no secrets in debug output |
| `--no-log` flag for sensitive operations | ⬜ | LOW | Skip sigchain for specific commands |

### Design Notes

```python
# Secure string handling (best effort in Python)
import ctypes

def secure_zero(s: str) -> None:
    """Attempt to zero string memory. NOT GUARANTEED in Python."""
    # Python strings are immutable; this is theater
    # Document limitation, recommend PyNaCl SecretBox for secrets
    pass
```

---

## 4. Availability / Denial of Service

**Risk**: Cannot access critical accounts when infrastructure is unavailable.

| Item | Status | Priority | Notes |
|------|--------|----------|-------|
| Offline emergency cache | ⬜ | HIGH | Top 10 critical credentials, separate encryption |
| 1Password outage playbook | ⬜ | MEDIUM | What to do when 1P is down |
| YubiKey loss bootstrap path | ⬜ | HIGH | Both keys lost—SLIP-39 → new keys flow |
| Cache staleness indicator | ⬜ | LOW | Warn if cache >7 days old |
| `bastion emergency export` command | ⬜ | MEDIUM | Export critical subset for offline use |

### Design Notes

```
Emergency Cache Design:
- Separate from main cache (different encryption key?)
- Contains: Email, Bank, Password Manager recovery
- Stored: Encrypted USB in go-bag, safe deposit box
- Format: Simple JSON or printable PDF with QR codes
- Update trigger: After any Tier 1 password rotation
```

---

## 5. Monitoring & Alerting

**Risk**: Compromise detected too late; no visibility into ongoing attacks.

| Item | Status | Priority | Notes |
|------|--------|----------|-------|
| `bsec 1p check sigchain-integrity` | ⬜ | HIGH | Verify chain hash continuity |
| Automated integrity check (cron) | ⬜ | MEDIUM | Daily verification |
| Dark web monitoring integration | ⬜ | LOW | Third-party service? Manual process? |
| Anomaly detection design | ⬜ | LOW | What would this even look like? |
| HIBP check frequency policy | ⬜ | MEDIUM | Weekly? After every sync? |

### Design Notes

```bash
# Sigchain integrity check
bsec 1p check sigchain-integrity
# Output:
# ✓ Chain length: 1,247 events
# ✓ Hash continuity: VALID
# ✓ Head matches latest event
# ✓ OTS anchors: 12 verified, 3 pending
# ✗ Gap detected: events 892-894 missing (CRITICAL)
```

---

## 6. Insider Threat / Coercion

**Risk**: Forced to unlock under duress; no plausible deniability.

| Item | Status | Priority | Notes |
|------|--------|----------|-------|
| Duress PIN/password design | ⬜ | LOW | Legal implications vary by jurisdiction |
| Decoy vault concept | ⬜ | LOW | "Honey pot" accounts that alert |
| Hidden volume (VeraCrypt-style) | ⬜ | LOW | Probably overkill |
| Document threat model | ⬜ | MEDIUM | What threats are in scope? |

### Design Notes

```
Duress Considerations:
- Legal: Some jurisdictions penalize "lying" to authorities
- Technical: 1Password doesn't support duress features
- Practical: If sophisticated attacker, they'll know about decoys
- Decision: Document risk acceptance rather than implement?
```

---

## 7. Supply Chain Security

**Risk**: Compromised hardware/software from the start.

| Item | Status | Priority | Notes |
|------|--------|----------|-------|
| Hardware provenance checklist | ⬜ | MEDIUM | YubiKey direct from Yubico, etc. |
| 1Password CLI signature verification | ⬜ | HIGH | Verify GPG signature on download |
| Infinite Noise TRNG verification | ⬜ | MEDIUM | Build from source? Verify entropy quality |
| Python dependency pinning | ⬜ | MEDIUM | Lock versions, verify hashes |
| `bastion verify-installation` command | ⬜ | LOW | Self-check of dependencies |

### Design Notes

```bash
# 1Password CLI verification
op --version
# Verify signature (manual process currently)
gpg --verify op.sig op

# Add to bastion init?
bastion init --verify-dependencies
# Checks:
# - 1Password CLI signature
# - Python package hashes match pyproject.toml
# - YubiKey firmware version (ykman info)
```

---

## 8. Documentation / Bus Factor

**Risk**: Only you can operate the system; incapacitation = lockout for heirs.

| Item | Status | Priority | Notes |
|------|--------|----------|-------|
| `EMERGENCY-RECOVERY-RUNBOOK.md` | ⬜ | HIGH | Step-by-step for trusted heir |
| Heir designation in 1Password | ⬜ | HIGH | Emergency Kit + instructions |
| Video walkthrough of recovery | ⬜ | LOW | For non-technical heirs |
| Lawyer/executor briefing | ⬜ | MEDIUM | They know recovery bag exists |
| Annual heir instruction review | ⬜ | LOW | Ensure still accurate |

### Design Notes

```markdown
# Emergency Recovery Runbook (outline)

## For: [Trusted Person Name]
## Last Updated: YYYY-MM-DD

### If I am incapacitated or deceased:

1. Locate the Recovery Bag (location: _______)
2. Inside you will find:
   - 1Password Emergency Kit
   - SLIP-39 share #1 (shares #2-5 located at: _____)
   - YubiKey backup
   - This document
   
3. To access accounts:
   - [Step by step...]
   
4. Priority accounts to secure:
   - [ ] Email (prevents further damage)
   - [ ] Financial (banks, brokerages)
   - [ ] ...
```

---

## Implementation Priorities

### Phase 1: Critical (Next 30 days)
1. ⬜ Offline emergency cache design & implementation
2. ⬜ `EMERGENCY-RECOVERY-RUNBOOK.md` creation
3. ⬜ `bsec 1p check sigchain-integrity` command
4. ⬜ 1Password CLI signature verification in `bastion init`

### Phase 2: Important (Next 90 days)
1. ⬜ Recovery drill schedule & logging
2. ⬜ Cache encryption key rotation procedure
3. ⬜ Log sanitization audit
4. ⬜ Hardware provenance checklist

### Phase 3: Nice to Have (Backlog)
1. ⬜ `bsec 1p audit recovery-readiness`
2. ⬜ Automated daily integrity checks
3. ⬜ Threat model documentation
4. ⬜ Video walkthrough for heirs

---

## Questions to Resolve

1. **Cache key rotation**: How to handle re-encryption without downtime?
2. **Emergency cache scope**: Which accounts are "critical enough"?
3. **Duress features**: In scope or explicitly out of scope?
4. **Heir technical level**: Assume technical or write for non-technical?
5. **Recovery drill frequency**: Quarterly too often? Annual too rare?

---

## References

- [Defense in Depth section in README](../README.md#defense-in-depth)
- [SLIP-39 Implementation](./SLIP39-IMPLEMENTATION.md) (if exists)
- [Sigchain Design](./SIGCHAIN-DESIGN.md) (if exists)
- [Recovery Bag Diagram](./recovery-bag.mmd)
