# Recovery Guide Template (Placeholder)

This is a placeholder for the Recovery Guide Template referenced by other documents.

Until the full template is authored, use the following resources:

- [AIRGAP-CARD-PROVISIONING.md](AIRGAP-CARD-PROVISIONING.md): Steps for provisioning encrypted microSD cards
- [ENCRYPTED-BACKUP.md](ENCRYPTED-BACKUP.md): Backup encryption workflow and verification
- [GPG-KEY-SETUP.md](GPG-KEY-SETUP.md): Generating and transferring GPG keys via QR code
- [AIRGAP-DESIGN-DECISIONS.md](AIRGAP-DESIGN-DECISIONS.md): Architectural and security design for the air-gapped system

## Template Outline (To Be Completed)

- Purpose and scope
- Required hardware and media
- Pre-flight checks (Tier 1-3 operational isolation)
- Entropy generation verification (minimum 2000 bits)
- Key generation steps (master and subkeys)
- SLIP-39 share distribution and documentation
- Encrypted backup creation and verification
- Recovery procedures and validation steps
- Annual verification checklist
- Tamper-evidence protocol (seals, UV markings, photographs)

If you need this document prioritized, please open an issue describing your use case and requirements.
