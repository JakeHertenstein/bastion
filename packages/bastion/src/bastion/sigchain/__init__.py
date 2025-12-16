"""Bastion Sigchain — Cryptographic audit trail with Merkle tree anchoring.

This module implements a Keybase-inspired sigchain for auditable security operations.
Events are cryptographically linked via hash chains, with periodic Bitcoin anchoring
via OpenTimestamps.

Components:
    - Bastion Manager: Daily connected machine, submits OTS proofs
    - Bastion Enclave: Air-gapped machine, generates events offline

Storage:
    - Git repository (~/.bastion/sigchain/): Full audit trail, GPG-signed commits
    - 1Password: Chain head state and human-readable summaries
    - OTS proofs: Embedded in sigchain as OTSAnchor events

Usage:
    # Record events via integration helpers
    from bastion.sigchain.integration import record_username_generated
    record_username_generated(domain="github.com", ...)

    # Or use session context manager
    from bastion.sigchain.integration import sigchain_session
    with sigchain_session() as chain:
        chain.append(payload)
"""

from .models import (
    ChainHead,
    DeviceType,
    EnclaveImportBatch,
    SigchainLink,
)
from .events import (
    AuditEventType,
    ConfigChangePayload,
    EnclaveImportPayload,
    EntropyPoolCreatedPayload,
    EventPayload,
    OTSAnchorPayload,
    PasswordRotationPayload,
    TagOperationPayload,
    UsernameGeneratedPayload,
)
from .chain import Sigchain
from .git_log import SigchainGitLog
from .gpg import (
    GPGSigner,
    GPGSignature,
    VerificationResult,
    get_signer,
    GPGEncryptor,
    EncryptionResult,
    DecryptionResult,
    get_encryptor,
)
from .op_storage import SigchainStorage, SessionSummary
from .integration import (
    emit_event,
    get_active_session,
    set_active_session,
    sigchain_session,
    record_username_generated,
    record_entropy_pool_created,
    record_tag_operation,
    record_password_rotation,
    record_config_change,
)

__all__ = [
    # Models
    "ChainHead",
    "DeviceType",
    "EnclaveImportBatch",
    "SigchainLink",
    # Events
    "AuditEventType",
    "ConfigChangePayload",
    "EnclaveImportPayload",
    "EntropyPoolCreatedPayload",
    "EventPayload",
    "OTSAnchorPayload",
    "PasswordRotationPayload",
    "TagOperationPayload",
    "UsernameGeneratedPayload",
    # Chain
    "Sigchain",
    # Git Log
    "SigchainGitLog",
    # GPG
    "GPGSigner",
    "GPGSignature",
    "VerificationResult",
    "get_signer",
    "GPGEncryptor",
    "EncryptionResult",
    "DecryptionResult",
    "get_encryptor",
    # 1Password Storage
    "SigchainStorage",
    "SessionSummary",
    # Integration Helpers
    "emit_event",
    "get_active_session",
    "set_active_session",
    "sigchain_session",
    "record_username_generated",
    "record_entropy_pool_created",
    "record_tag_operation",
    "record_password_rotation",
    "record_config_change",
]
