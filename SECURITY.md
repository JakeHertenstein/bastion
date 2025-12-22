# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in Bastion, please report it privately:

1. **Email**: Send details to the repository owner via GitHub's private vulnerability reporting feature
2. **GitHub Security Advisories**: Use the "Report a vulnerability" button in the Security tab

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Target**: Within 30 days for critical issues

### Scope

The following are in scope:

- Cryptographic weaknesses in entropy generation or username derivation
- Authentication bypasses or privilege escalation
- Information disclosure of secrets or sensitive data
- Command injection or arbitrary code execution
- Insecure storage of encryption keys or salts

The following are out of scope:

- Issues requiring physical access to an already-compromised machine
- Social engineering attacks
- Denial of service attacks
- Issues in dependencies (report to upstream)

## Security Design

### Threat Model

Bastion assumes:

1. **1Password is trusted**: All secrets are stored in 1Password vaults
2. **Local machine is secure**: Cache encryption protects at-rest data, not against active compromise
3. **Salt secrecy is critical**: Username determinism depends entirely on salt remaining secret

### Cryptographic Choices

| Component | Algorithm | Rationale |
|-----------|-----------|-----------|
| Username generation | HMAC-SHA512 | Hardware acceleration, 128-bit quantum security |
| Cache encryption | Fernet (AES-128-CBC + HMAC-SHA256) | Authenticated encryption, key stored in 1Password |
| Entropy combination | XOR + SHAKE256 | Preserves entropy from strongest source |
| Salt derivation | HKDF-SHA512 | Standard key derivation from high-entropy input |

### Security Practices

- **No shell=True**: All subprocess calls use argument lists
- **No eval/exec**: No dynamic code execution
- **Atomic writes**: Temp file + rename pattern prevents corruption
- **Restrictive permissions**: 0o600 for files, 0o700 for directories
- **Input sanitization**: All 1Password CLI arguments are sanitized

## AI Assistance & Verification
This project includes AI‑assisted code and documentation. All integrations and cryptographic test vectors are human‑reviewed and verified before release. AI outputs are treated as drafts; human verification is required for correctness and security.

## Disclaimer

Bastion is provided as-is for personal use. While designed with security in mind, it has not undergone formal security audit. Use at your own risk for managing sensitive credentials.
