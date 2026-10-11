"""ORM models for the voting backend (Architecture v2.6).

All timestamps are UTC.
No plaintext ballot choices are stored anywhere in this schema.
"""

from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _new_uuid() -> str:
    return str(uuid.uuid4())


# ── Credential status ─────────────────────────────────────────────────────────


class CredentialStatus(str, enum.Enum):
    active = "active"
    revoked = "revoked"
    expired = "expired"


# ── Ballot storage status ─────────────────────────────────────────────────────


class BallotStatus(str, enum.Enum):
    pending = "pending"
    stored = "stored"
    submitted = "submitted"
    confirmed = "confirmed"
    failed = "failed"
    retryable = "retryable"


# ── BackupStatus ──────────────────────────────────────────────────────────────


class BackupStatus(str, enum.Enum):
    pending = "pending"
    verified = "verified"
    failed = "failed"


# ─────────────────────────────────────────────────────────────────────────────
# voters
# Internal synthetic voter record. Never linked to real-world identity here.
# ─────────────────────────────────────────────────────────────────────────────


class Voter(Base):
    __tablename__ = "voters"

    voter_synth_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="active"
    )

    __table_args__ = (Index("ix_voters_status", "status"),)


# ─────────────────────────────────────────────────────────────────────────────
# credentials
# Off-chain credential records for revocation tracking.
# Revocation is an off-chain trusted control (Architecture v2.6 §4).
# ─────────────────────────────────────────────────────────────────────────────


class Credential(Base):
    __tablename__ = "credentials"

    credential_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    # Full credential JSON payload — used for audit; never logged.
    credential_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # ML-DSA-65 signature bytes (up to ~3309 bytes).
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    issuer_key_id: Mapped[str] = mapped_column(String(255), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_credentials_issuer_key_id", "issuer_key_id"),
        Index("ix_credentials_revoked", "revoked"),
        Index("ix_credentials_expires_at", "expires_at"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# encrypted_ballots
# Stores encrypted BallotBlobV1 CBOR. NO plaintext ballot choices stored here.
# ─────────────────────────────────────────────────────────────────────────────


class EncryptedBallot(Base):
    __tablename__ = "encrypted_ballots"

    ballot_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    election_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # Base64-encoded SHA3-256 hash of the nullifier (32 bytes → 44 chars base64)
    nullifier_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Base64-encoded SHA3-256 commitment hash
    commitment_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    # Complete BallotBlobV1 CBOR — encrypted; no plaintext inside.
    ballot_blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # SHA3-256 hash of the ML-KEM ciphertext (for audit)
    kem_ct_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=BallotStatus.pending.value
    )
    blockchain_tx_hash: Mapped[str | None] = mapped_column(String(128), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    backup_record: Mapped[BackupManifest | None] = relationship(
        "BackupManifest", back_populates="ballot", uselist=False
    )

    __table_args__ = (
        Index("ix_encrypted_ballots_election_id", "election_id"),
        Index("ix_encrypted_ballots_status", "storage_status"),
        UniqueConstraint("nullifier_hash", name="uq_ballots_nullifier_hash"),
        UniqueConstraint("commitment_hash", name="uq_ballots_commitment_hash"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# idempotency
# PostgreSQL-backed request idempotency (Architecture v2.6 §11).
# ─────────────────────────────────────────────────────────────────────────────


class IdempotencyRecord(Base):
    __tablename__ = "idempotency"

    idempotency_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    # SHA-256 of the canonical request body
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    # ballot_id or other resource reference
    response_reference: Mapped[str | None] = mapped_column(String(36), nullable=True)
    response_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Stored response JSON for replay
    response_body: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    __table_args__ = (Index("ix_idempotency_expires_at", "expires_at"),)


# ─────────────────────────────────────────────────────────────────────────────
# backup_manifest
# Tracks durable off-site backup of each encrypted ballot record.
# ─────────────────────────────────────────────────────────────────────────────


class BackupManifest(Base):
    __tablename__ = "backup_manifest"

    manifest_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    ballot_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("encrypted_ballots.ballot_id"), nullable=False, unique=True
    )
    # URI of the backup destination (e.g. s3://..., gcs://...)
    backup_location: Mapped[str] = mapped_column(String(512), nullable=False)
    # SHA3-256 hex digest of the backup payload for integrity verification
    backup_checksum: Mapped[str] = mapped_column(String(64), nullable=False)
    backed_up_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=BackupStatus.pending.value
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    ballot: Mapped[EncryptedBallot] = relationship(
        "EncryptedBallot", back_populates="backup_record"
    )

    __table_args__ = (Index("ix_backup_manifest_status", "status"),)


# ─────────────────────────────────────────────────────────────────────────────
# tally_runs
# Records each completed tally invocation for audit and post-hoc verification.
# canonical_result_bytes is the exact bytes used to compute result_commitment.
# completed_at is operational metadata only — NOT included in canonical bytes.
# ─────────────────────────────────────────────────────────────────────────────


class TallyRunStatus(str, enum.Enum):
    in_progress = "in_progress"
    completed = "completed"
    failed = "failed"


class TallyRun(Base):
    __tablename__ = "tally_runs"

    tally_run_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    election_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default=TallyRunStatus.in_progress.value
    )
    # Hex-encoded 32-byte SHA3-256 of canonical_result_bytes
    result_commitment_hex: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Exact canonical JSON bytes used to compute result_commitment.
    # Stored for post-hoc verification.  Contains NO voter identifiers.
    canonical_result_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # JSON-encoded audit counters (total_commitments, recovered_ballots, etc.)
    audit_counters_json: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Operational metadata — NOT part of canonical result
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_tally_runs_election_id", "election_id"),
        Index("ix_tally_runs_status", "status"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# telemetry_buckets  (Stage 4 — AI anomaly detection)
# Stores approved aggregate telemetry per (election_id, telemetry_bucket_id,
# bucket_start_ts).  Contains ONLY the approved numeric features listed in
# Architecture v2.6 §telemetry-boundary.
#
# MUST NOT contain:
#   voter_synth_id, credential_id, nullifier, nullifier_hash, plaintext ballot,
#   BallotBlobV1, private keys, ML-KEM shared secret, AES key, biometric data.
# ─────────────────────────────────────────────────────────────────────────────


class TelemetryBucket(Base):
    __tablename__ = "telemetry_buckets"

    bucket_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    election_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # SHA3-256(client_bucket_token || server_bucket_secret) — bytes32 as hex.
    # This is NOT a voter identifier; it is a privacy-preserving bucket token.
    telemetry_bucket_id_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    bucket_start_ts: Mapped[int] = mapped_column(
        BigInteger, nullable=False,
        doc="Unix timestamp (seconds) of the start of this telemetry bucket."
    )
    # ── Approved aggregate features only ──────────────────────────────────────
    submission_interval_seconds: Mapped[float | None] = mapped_column(
        nullable=True, doc="Mean inter-submission interval within this bucket (seconds)."
    )
    submission_attempts: Mapped[int | None] = mapped_column(
        Integer, nullable=True, doc="Total submission attempts in this bucket."
    )
    auth_failure_count: Mapped[int | None] = mapped_column(
        Integer, nullable=True, doc="Total authentication failures in this bucket."
    )
    encrypted_blob_size_bytes: Mapped[int | None] = mapped_column(
        Integer, nullable=True, doc="Mean encrypted ballot blob size in bytes."
    )
    # HMAC-SHA3-256(server_bucket_secret, signal || uint64_be(bucket_start)).
    # Raw behavioral signal is NOT stored.
    behavioral_signal_hash_hex: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_telemetry_buckets_election_id", "election_id"),
        Index("ix_telemetry_buckets_bucket_id_hex", "telemetry_bucket_id_hex"),
        Index(
            "ix_telemetry_buckets_composite",
            "election_id", "telemetry_bucket_id_hex", "bucket_start_ts",
        ),
    )


# ─────────────────────────────────────────────────────────────────────────────
# anomaly_results  (Stage 4 — AI anomaly detection)
# Stores advisory-only anomaly results from the Isolation Forest model.
# These results MUST NOT influence ballot acceptance, credential validity,
# nullifier uniqueness, blockchain state, tally, or result publication.
# ─────────────────────────────────────────────────────────────────────────────


class AnomalyResult(Base):
    __tablename__ = "anomaly_results"

    result_id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=_new_uuid
    )
    election_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    telemetry_bucket_id_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    bucket_start_ts: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # ── Model output ──────────────────────────────────────────────────────────
    # anomaly_score: raw Isolation Forest decision_function output.
    # This is NOT a probability of fraud and has no standardized fraud meaning.
    # Project-specific thresholds: score <= -0.1 → HIGH_RISK; <= 0.0 → SUSPICIOUS;
    # > 0.0 → NORMAL.  These are experimental thresholds defined for this project only.
    anomaly_score: Mapped[float] = mapped_column(nullable=False)
    risk_level: Mapped[str] = mapped_column(
        String(20), nullable=False,
        doc="NORMAL | SUSPICIOUS | HIGH_RISK — advisory label only."
    )
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    # JSON-encoded dict of the feature values used for this inference.
    # Contains only approved numeric features; no identity or ballot data.
    feature_summary_json: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    __table_args__ = (
        Index("ix_anomaly_results_election_id", "election_id"),
        Index("ix_anomaly_results_bucket_hex", "telemetry_bucket_id_hex"),
        Index("ix_anomaly_results_risk_level", "risk_level"),
    )
