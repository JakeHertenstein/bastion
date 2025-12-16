Seeder Password Token Matrix Generator — Design Document

⸻

0. Purpose

This document defines the complete design, workflow, and developer guidance for implementing the Seeder Password Token Matrix System. It provides Copilot-compatible specifications to support deterministic generation, integrity verification, and air-gapped reproducibility.

⸻

1. Design Goals
	•	Offline-only: All generation occurs on air-gapped systems.
	•	Deterministic: Same SLIP-39/BIP-39 seed → identical output.
	•	Human usable: Compact, mnemonic, easily readable matrix.
	•	Integrity verifiable: Each matrix carries a digest + barcode for validation.
	•	Traceable: JD index reference allows provenance tracking without revealing secrets.

⸻

2. Matrix Overview

2.1 Front (Matrix Surface)
	•	Matrix: 10×10 grid, columns A–J, rows 0–9.
	•	Tokens: 4 printable characters per cell.
	•	Row headers: A–J with letter-number hints (A=2, B=1, etc.).
	•	Column headers: 0–9 with numeric indexing.
	•	Column J: reserved for random/rolling references.
	•	Legend: bottom footer showing enhanced HMAC function with date:
		- Simple: HMAC512(Seed, "v1|SIMPLE|{card_date}|{card_id}") → Base90
		- Enhanced: HMAC512(Seed, "v1|{SEED_TYPE}|{card_date}|{card_id}") → Base90
	•	Date Display: Card date printed for tracking (e.g., "Card Date: 2025-03")

2.2 Back (Legend Surface)
	•	JD link: hidden index reference to Johnny.Decimal record.
	•	Integrity Digest: HMAC-SHA512(seed_bytes, b'SEEDER-DIGEST') in hex.
	•	Barcode: Code128 or QR of digest (verification only).
	•	Version mark: v1.0 / YYYY-MM.
	•	Mini legend: mnemonic reminder, conversion function, caution text.
	•	Writable box: issue date or rotation note.

⸻

3. Cryptographic Model

3.1 Seed Sources
	•	Preferred: SLIP-39 shares reconstructing a 256-bit entropy seed.
	•	Alternate: BIP-39 24-word mnemonic → PBKDF2-HMAC-SHA512 seed.
	•	Raw: direct 256-bit seed bytes (optional, offline).

3.2 Enhanced Derivation Algorithm with Flexible Date Labeling

def derive_stream(seed_bytes, label, bytes_needed):
    out = b''
    counter = 1
    while len(out) < bytes_needed:
        msg = label + counter.to_bytes(2, 'big')
        out += hmac.new(seed_bytes, msg, hashlib.sha512).digest()
        counter += 1
    return out[:bytes_needed]

3.2.1 Flexible HMAC Label Generation
	•	Base Label: "v1|{SEED_TYPE}|{card_date}|{card_id}"
	•	Enhanced Label: "v1|{SEED_TYPE}|{card_date}|{card_id}" when date specified
	•	Seed Types: SIMPLE, BIP-39, SLIP-39
	•	Examples:
		- "v1|SIMPLE|CARD" (legacy simple seed, no date)
		- "v1|SIMPLE|2025|CARD" (year-long personal card)
		- "v1|BIP-39|2025-03|CORP-BATCH" (monthly corporate batch)
		- "v1|SLIP-39|2025-01-15|BACKUP" (emergency backup with specific date)
		- "v1|SIMPLE|STAGING-2025-ALPHA|PROJECT" (project-specific identifier)

3.2.2 Date Input Flexibility
	•	Format Options: YYYY, YYYY-MM, YYYY-MM-DD, or custom text
	•	Sanitization: Input cleaned to ASCII alphanumeric + hyphens/underscores
	•	Separator: "|" (pipe) character for visual distinction and ASCII safety
	•	User Control: No forced rotation - user chooses card lifespan

3.2.3 Security Properties
	•	Domain Separation: Each date creates isolated token space
	•	Enhanced Entropy: Date variation adds ~30-40 bits to HMAC labels
	•	Perfect Determinism: Same date always produces identical tokens
	•	Complete Isolation: Different dates produce completely different tokens

	•	Expand HMAC stream deterministically using SHA-512.
	•	Map bytes → Base90 alphabet via rejection sampling.
	•	Fill 100 grid cells (A1–J10) in deterministic order.

3.3 Printed Conversion Function

Legacy Format:
HMAC512(Seed, "v1|SIMPLE|{card_date}|{card_id}") → Base90

Enhanced Format with Date Labeling:
HMAC512(Seed, "v1|{SEED_TYPE}|{card_date}|{card_id}") → Base90

Examples:
	•	HMAC512(Seed, "v1|SIMPLE|2025|CARD") → Base90
	•	HMAC512(Seed, "v1|BIP-39|2025-03|CORP") → Base90
	•	HMAC512(Seed, "v1|SLIP-39|2025-01-15|BACKUP") → Base90

This notation represents deterministic token derivation with flexible date tracking in human-readable shorthand.

⸻

4. Character Alphabet (Base90)
	•	Includes: A–Z, a–z, 0–9, and safe punctuation.
	•	Excludes: visually ambiguous symbols (\\,',",`, ).
	•	Defined in: constants.py as a single source of truth.

⸻

5. CSV Export Format & Security

5.1 CSV Schema (Secure Export)
	•	Columns: ID, Date, SHORT_HASH, SHA512, Tokens
	•	ID: User-defined card identifier (e.g., "SYS.01.02", "2025-10-26")
	•	Date: ISO date format (YYYY-MM-DD) when card was generated
	•	SHORT_HASH: First 6 characters of SHA512 hash in uppercase (Code39 barcode compatible)
	•	SHA512: Complete SHA-512 hex digest of seed bytes for integrity verification
	•	Tokens: 10×10 grid stored as newline-separated rows, space-separated tokens per row

5.2 Security Improvements
	•	**Removed Seed Column**: Previously included seed material (security risk)
	•	**Added SHORT_HASH**: 6-character uppercase hash prefix for 1Password vault lookups
	•	**Barcode Integration**: SHORT_HASH compatible with Code39 encoding for scanning
	•	**Physical Separation**: Seed material never stored in CSV, only in secure vaults
	•	**Integrity Verification**: Full SHA512 hash enables tamper detection

5.3 Workflow Integration
	•	1Password Integration: SHORT_HASH enables vault item lookup via barcode scan
	•	Card Verification: Full SHA512 hash verifies card integrity against known good state
	•	Audit Trail: Date and ID fields provide rotation and versioning history
	•	Air-gapped Export: CSV can be generated offline without exposing seed material

⸻

6. Ledger & Rotation System
	•	Each account entry uses an obfuscated IDX token instead of a site name.
	•	Ledger fields: IDX, PAT, TOKS, ROLL, LR, BLOCK, SUB, EXTRA, NOTES.
	•	Rolling entries follow ISO date (YYYY-MM); log only current state.
	•	Blocked character handling noted per site; substitutions stored in SUB.
	•	Ledger kept physically separate from printed matrix.

⸻

7. Entropy & Threat Model

Source	Secret to Attacker?	Bits
Token mapping (A/B pair)	Yes	13.3
MemWord (6 random letters)	Yes	28.2
Punctuation	Optional	3.3
Rolling token	No	0

	•	Total effective entropy: ≈ 41–45 bits (adequate for online rate-limited systems).
	•	Brute force probability (3 attempts): ~10⁻¹² chance of success.
	•	Mitigation: Mapping secrecy + memorized word form the core defense.
	•	Critical systems: Require MFA.

⸻

8. Developer Modules

File	Function
cli/seeder.py	CLI generator entrypoint
core.py	Seed derivation, HMAC expansion, Base90 mapping  
pdf.py	Matrix PDF/SVG renderer
hashutil.py	Digest + barcode generator
ledger.py	Ledger template & PDF builder
tests/	Unit tests for determinism
docs/runbook.md	Operational manual (air-gapped workflow)


⸻

9. Physical Printing
	•	Standard dimensions: 85.60 × 53.98 mm (safe area 79.6 × 47.98 mm).
	•	Row shading: alternate A–E/F–J for scanning.
	•	Header repetition: decoding hints top and bottom.
	•	Font: monospace, 6.5mm × 4.3mm cells.
	•	Finish: matte laminate.
	•	Barcode label: "Verify only."
	•	Digest label: "Integrity Digest (512b)."

⸻

10. Development Tasks
	1.	Implement deterministic HMAC stream generator.
	2.	Implement Base90 rejection sampling.
	3.	Generate 10×10 token grid (A–J × 1–10).
	4.	Render PDF/SVG matrix layout.
	5.	Produce digest + barcode.
	6.	Generate ledger CSV + printable template.
	7.	Create deterministic test vectors.
	8.	Integrate CLI commands (seeder generate, seeder verify).
	9.	Add rich docstrings + type hints for Copilot.

⸻

11. Repository Deliverables
	•	README.md — overview & usage guide.
	•	requirements.txt — minimal dependency set.
	•	examples/ — sample mnemonics + reference grids.
	•	tests/ — pytest verification.
	•	docs/runbook.md — SLIP-39 workflow + print procedures.

⸻

12. Client-Side Validation

The web interface includes JavaScript validation for improved user experience:

### BIP-39 Validation
- **Word membership**: Checks each word against the official 2048-word BIP-39 English wordlist
- **Word count**: Validates allowed counts (12, 15, 18, 21, 24 words)  
- **Checksum verification**: Full cryptographic checksum validation using Web Crypto API SHA-256
- **Real-time feedback**: Visual indicators (red border for invalid, green for valid)

### SLIP-39 Validation
- **Word count**: Validates SLIP-39 share word counts (20 or 33 words)
- **Format checking**: Basic structure validation for shares
- **Minimum shares**: Requires at least 2 valid shares for reconstruction

### Limitations
- Client-side validation provides immediate feedback but should not be considered a security boundary
- Cryptographic operations are performed by the backend CLI for final security
- JavaScript implementations serve as user experience enhancements only

### Examples Updated
All example mnemonics and SLIP-39 shares use valid test data:
- BIP-39 example: Official test vector "abandon abandon ... about"
- SLIP-39 examples: Real shares generated from CLI for "test" seed

⸻

13. Future Features
	•	Optional encrypted exports (GPG container).
	•	YubiHMAC hardware verification.
	•	Cross-platform GUI for offline generation.

⸻
