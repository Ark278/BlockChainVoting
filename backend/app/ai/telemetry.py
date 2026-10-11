"""Telemetry service: bucket ID, behavioral hash, privacy validation, aggregation.
(Architecture v2.6 Stage 4 §§2–4)

Frozen protocol:
    client_bucket_token = HMAC-SHA3-256(client_ephemeral_secret, uint64_be(bucket_start))
    telemetry_bucket_id = SHA3-256(client_bucket_token || server_bucket_secret)   [bytes32]

    behavioral_signal_hash = HMAC-SHA3-256(
        server_bucket_secret,
        deterministic_signal || uint64_be(bucket_start)
    )

Privacy invariants:
  - Raw behavioral signal NEVER leaves this module.
  - client_ephemeral_secret is never persisted server-side.
  - Prohibited fields are rejected at parse time; their VALUES are never logged.
  - telemetry_bucket_id is NOT a persistent voter identifier.
  - No voter identity, nullifier, credential, ballot, or key material is accepted.

Approved telemetry fields (§1):
    election_id, telemetry_bucket_id, bucket_start_ts,
    submission_interval_seconds, submission_attempts,
    auth_failure_count, encrypted_blob_size_bytes,
    behavioral_signal_hash, version
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Any

from app.errors import TelemetryValidationError

# ─────────────────────────────────────────────────────────────────────────────
# Privacy boundary: prohibited field names
# ─────────────────────────────────────────────────────────────────────────────

# Field names (lowercase) that MUST NOT appear in any telemetry payload.
# This list is exhaustive. New prohibited fields must be added here.
_PROHIBITED_FIELDS: frozenset[str] = frozenset(
    {
        "voter_synth_id",
        "voter_id",
        "credential_id",
        "credential_hash",
        "credential",
        "nullifier",
        "nullifier_hash",
        "selected_option",
        "candidate",
        "candidate_choice",
        "ballot_choice",
        "plaintext",
        "plaintext_ballot",
        "ballot_plaintext",
        "ballot_blob",
        "ballotblobv1",
        "kem_ct",
        "kem_sk",
        "private_key",
        "aes_key",
        "shared_secret",
        "ml_kem_sk",
        "ml_dsa_sk",
        "biometric",
        "fingerprint",
        "face_id",
        "ip_address",
        "user_agent",
        "device_id",
        "session_id",
        "client_secret",
        "ephemeral_secret",
        "client_ephemeral_secret",
    }
)

# ─────────────────────────────────────────────────────────────────────────────
# Approved telemetry field names (complete set)
# ─────────────────────────────────────────────────────────────────────────────

APPROVED_TELEMETRY_FIELDS: frozenset[str] = frozenset(
    {
        "election_id",
        "telemetry_bucket_id",
        "bucket_start_ts",
        "submission_interval_seconds",
        "submission_attempts",
        "auth_failure_count",
        "encrypted_blob_size_bytes",
        "behavioral_signal_hash",
        "version",
    }
)

# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class TelemetryRecord:
    """Validated, parsed telemetry record containing only approved fields."""

    election_id: int
    telemetry_bucket_id_hex: str        # bytes32 as lowercase hex
    bucket_start_ts: int                # UTC unix seconds
    submission_interval_seconds: float | None = None
    submission_attempts: int | None = None
    auth_failure_count: int | None = None
    encrypted_blob_size_bytes: int | None = None
    behavioral_signal_hash_hex: str | None = None
    version: int = 1


@dataclass
class AggregatedTelemetry:
    """Aggregated telemetry over a (election_id, bucket_id, bucket_start_ts) group.

    Values are computed as mean over all records in the group (with None treated
    as 0 for numeric aggregation).
    """

    election_id: int
    telemetry_bucket_id_hex: str
    bucket_start_ts: int
    submission_interval_seconds: float
    submission_attempts: float
    auth_failure_count: float
    encrypted_blob_size_bytes: float
    behavioral_signal_hash_hex: str | None = None
    record_count: int = 1


# ─────────────────────────────────────────────────────────────────────────────
# Privacy validator
# ─────────────────────────────────────────────────────────────────────────────


def validate_telemetry_fields(payload: dict[str, Any]) -> None:
    """Reject any telemetry payload containing prohibited field names.

    Field NAME matching is case-insensitive and covers underscores/hyphens.
    Field VALUES are never logged even when a prohibited field is found.

    Args:
        payload: Raw inbound JSON dict.

    Raises:
        TelemetryValidationError: If any prohibited field is present.
    """
    found_prohibited: list[str] = []
    for key in payload:
        normalized = key.lower().replace("-", "_")
        if normalized in _PROHIBITED_FIELDS:
            found_prohibited.append(key)  # log only field NAME, not value

    if found_prohibited:
        raise TelemetryValidationError(
            f"Telemetry payload contains prohibited fields: {found_prohibited}. "
            "Remove all identity, ballot, and key material from telemetry."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Bucket ID computation (frozen protocol)
# ─────────────────────────────────────────────────────────────────────────────


def compute_client_bucket_token(
    client_ephemeral_secret: bytes,
    bucket_start: int,
) -> bytes:
    """HMAC-SHA3-256(client_ephemeral_secret, uint64_be(bucket_start)) → 32 bytes.

    The client_ephemeral_secret exists only in browser memory and is never
    persisted server-side.  Do NOT log this value.

    Args:
        client_ephemeral_secret: 32-byte random value from the browser session.
        bucket_start:             Unix timestamp (seconds) of the bucket start.

    Returns:
        32-byte client bucket token.
    """
    msg = struct.pack(">Q", bucket_start)  # uint64_be
    return hmac.new(
        client_ephemeral_secret,
        msg,
        hashlib.sha3_256,
    ).digest()


def compute_telemetry_bucket_id(
    client_bucket_token: bytes,
    server_bucket_secret: bytes,
) -> bytes:
    """SHA3-256(client_bucket_token || server_bucket_secret) → bytes32.

    This is NOT a voter identifier.  It is a privacy-preserving per-session,
    per-hour bucket token.  The same browser session in the same hour produces
    the same ID; a new session or new hour produces a different ID.

    Args:
        client_bucket_token:   Output of compute_client_bucket_token().
        server_bucket_secret:  Current hourly server secret (never logged).

    Returns:
        32-byte telemetry bucket ID.
    """
    h = hashlib.sha3_256()
    h.update(client_bucket_token)
    h.update(server_bucket_secret)
    return h.digest()


# ─────────────────────────────────────────────────────────────────────────────
# Behavioral signal hash (frozen protocol)
# ─────────────────────────────────────────────────────────────────────────────


def compute_behavioral_signal_hash(
    server_bucket_secret: bytes,
    deterministic_signal: bytes,
    bucket_start: int,
) -> bytes:
    """HMAC-SHA3-256(server_bucket_secret, deterministic_signal || uint64_be(bucket_start)).

    The raw behavioral signal is NEVER stored or transmitted to the AI service.
    Only this HMAC digest is stored (in behavioral_signal_hash_hex).
    Do NOT log server_bucket_secret or deterministic_signal.

    Args:
        server_bucket_secret:  Current server secret (never logged).
        deterministic_signal:  Raw signal bytes (never leaves this function).
        bucket_start:          Unix timestamp of bucket start.

    Returns:
        32-byte behavioral signal HMAC.
    """
    msg = deterministic_signal + struct.pack(">Q", bucket_start)
    return hmac.new(
        server_bucket_secret,
        msg,
        hashlib.sha3_256,
    ).digest()


# ─────────────────────────────────────────────────────────────────────────────
# Telemetry record parsing
# ─────────────────────────────────────────────────────────────────────────────


def parse_telemetry_record(
    payload: dict[str, Any],
    server_bucket_secret: bytes,
    client_bucket_token: bytes,
    bucket_start: int,
    deterministic_signal: bytes,
) -> TelemetryRecord:
    """Parse and validate a telemetry ingest payload into a TelemetryRecord.

    Constructs the server-side telemetry_bucket_id and behavioral_signal_hash.
    All prohibited fields are rejected before parsing.

    Args:
        payload:               Validated inbound telemetry JSON.
        server_bucket_secret:  Current server bucket secret.
        client_bucket_token:   Pre-computed client bucket token.
        bucket_start:          Unix timestamp of bucket start.
        deterministic_signal:  Raw behavioral signal (never stored/sent to AI).

    Returns:
        Validated TelemetryRecord.

    Raises:
        TelemetryValidationError: If fields are missing or invalid types.
    """
    # Compute server-side IDs
    bucket_id_bytes = compute_telemetry_bucket_id(client_bucket_token, server_bucket_secret)
    behavioral_hash_bytes = compute_behavioral_signal_hash(
        server_bucket_secret, deterministic_signal, bucket_start
    )

    # Validate required fields
    election_id = payload.get("election_id")
    if not isinstance(election_id, int):
        raise TelemetryValidationError("election_id must be an integer")

    # Optional numeric features — None allowed
    def _opt_float(key: str) -> float | None:
        v = payload.get(key)
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError) as exc:
            raise TelemetryValidationError(f"{key} must be numeric, got {v!r}") from exc

    def _opt_int(key: str) -> int | None:
        v = payload.get(key)
        if v is None:
            return None
        if not isinstance(v, int):
            raise TelemetryValidationError(f"{key} must be an integer, got {v!r}")
        return v

    return TelemetryRecord(
        election_id=election_id,
        telemetry_bucket_id_hex=bucket_id_bytes.hex(),
        bucket_start_ts=bucket_start,
        submission_interval_seconds=_opt_float("submission_interval_seconds"),
        submission_attempts=_opt_int("submission_attempts"),
        auth_failure_count=_opt_int("auth_failure_count"),
        encrypted_blob_size_bytes=_opt_int("encrypted_blob_size_bytes"),
        behavioral_signal_hash_hex=behavioral_hash_bytes.hex(),
        version=int(payload.get("version", 1)),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Aggregation
# ─────────────────────────────────────────────────────────────────────────────


def aggregate_telemetry(records: list[TelemetryRecord]) -> list[AggregatedTelemetry]:
    """Aggregate telemetry records by (election_id, telemetry_bucket_id_hex, bucket_start_ts).

    Numeric features are averaged across records in the same group.
    None values are treated as 0 for averaging purposes.
    Behavioral signal hash: last non-None value in the group.

    Args:
        records: List of validated TelemetryRecord objects.

    Returns:
        List of AggregatedTelemetry dataclasses.
    """
    groups: dict[tuple[int, str, int], list[TelemetryRecord]] = {}
    for rec in records:
        key = (rec.election_id, rec.telemetry_bucket_id_hex, rec.bucket_start_ts)
        groups.setdefault(key, []).append(rec)

    result: list[AggregatedTelemetry] = []
    for (election_id, bucket_hex, bucket_start), recs in groups.items():
        n = len(recs)

        def _mean(attr: str, local_recs: list[TelemetryRecord] = recs, local_n: int = n) -> float:
            values = [getattr(r, attr) or 0.0 for r in local_recs]
            return sum(values) / local_n

        bsh = next(
            (r.behavioral_signal_hash_hex for r in reversed(recs)
             if r.behavioral_signal_hash_hex is not None),
            None,
        )
        result.append(
            AggregatedTelemetry(
                election_id=election_id,
                telemetry_bucket_id_hex=bucket_hex,
                bucket_start_ts=bucket_start,
                submission_interval_seconds=_mean("submission_interval_seconds"),
                submission_attempts=_mean("submission_attempts"),
                auth_failure_count=_mean("auth_failure_count"),
                encrypted_blob_size_bytes=_mean("encrypted_blob_size_bytes"),
                behavioral_signal_hash_hex=bsh,
                record_count=n,
            )
        )
    return result
