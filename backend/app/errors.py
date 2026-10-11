"""Application-level error types for the voting backend.

All errors are domain-specific. HTTP status codes are assigned at the API layer,
not inside service code.
"""

from __future__ import annotations


class VotingError(Exception):
    """Base class for all voting backend errors."""

    def __init__(self, message: str, detail: str | None = None) -> None:
        super().__init__(message)
        self.detail = detail or message


# ── Credential errors ─────────────────────────────────────────────────────────


class InvalidCredentialError(VotingError):
    """Credential payload is malformed or missing required fields."""


class InvalidSignatureError(VotingError):
    """ML-DSA-65 signature verification failed."""


class UnknownIssuerKeyError(VotingError):
    """The issuer_key_id referenced by the credential is not registered."""


class ExpiredCredentialError(VotingError):
    """Credential has passed its expires_at timestamp."""


class RevokedCredentialError(VotingError):
    """Credential has been revoked off-chain."""


# ── Election errors ───────────────────────────────────────────────────────────


class ElectionNotFoundError(VotingError):
    """No election exists with the given election_id on-chain."""


class ElectionNotOpenError(VotingError):
    """The election is not in VotingOpen state."""


# ── Nullifier / commitment errors ─────────────────────────────────────────────


class NullifierAlreadyUsedError(VotingError):
    """The nullifier_hash is already recorded on-chain; double-vote attempt."""


class CommitmentAlreadyExistsError(VotingError):
    """The commitment_hash is already recorded on-chain or in storage."""


# ── Ballot errors ─────────────────────────────────────────────────────────────


class InvalidBallotError(VotingError):
    """Ballot structure is invalid (wrong field, size, or encoding)."""


class EncryptionFailureError(VotingError):
    """ML-KEM encapsulation or AES-GCM encryption failed."""


# ── Infrastructure errors ─────────────────────────────────────────────────────


class StorageFailureError(VotingError):
    """Database write failed."""


class BlockchainSubmissionFailureError(VotingError):
    """CosmWasm transaction submission failed or was rejected."""


class IdempotencyConflictError(VotingError):
    """Same idempotency key was submitted with a different request fingerprint."""


# ── Tally errors (Stage 3) ────────────────────────────────────────────────────


class TallyStateError(VotingError):
    """Election is not in the required state to begin tallying."""


class CommitmentMismatchError(VotingError):
    """Recomputed commitment hash does not match the on-chain value."""


class BallotBlobValidationError(VotingError):
    """BallotBlobV1 structure is invalid (malformed CBOR, wrong sizes, extra fields)."""


class DecryptionFailureError(VotingError):
    """AES-256-GCM authentication or ML-KEM decapsulation failed."""


class InvalidBallotPayloadError(VotingError):
    """Decrypted ballot plaintext fails schema validation."""


class BackupError(VotingError):
    """Backup write or read operation failed."""


class RecoveryError(VotingError):
    """Backup blob cannot be verified against the on-chain commitment; restore aborted."""


class ResultPublicationError(VotingError):
    """Result commitment publication failed (already published, wrong state, etc.)."""


# ── AI / telemetry errors (Stage 4) ──────────────────────────────────────────


class TelemetryValidationError(VotingError):
    """Telemetry payload contains a prohibited field (identity, ballot, or key material)."""


class AnomalyServiceError(VotingError):
    """AI anomaly inference failed.

    This is non-fatal: ballot processing must continue normally when this is raised.
    Never propagate this error into the ballot acceptance path.
    """

