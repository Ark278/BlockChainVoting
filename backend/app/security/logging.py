"""Security-aware logging helpers.

Rules:
  - NEVER log: raw nullifiers, nullifier secrets, ML-DSA/ML-KEM private keys,
    plaintext ballots, AES keys, shared secrets, or full credential payloads.
  - SAFE to log: election_id, commitment_hash (base64), submission status,
    transaction hash, request correlation ID, timing metadata.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

logger = logging.getLogger("voting.backend")


def _redact(value: Any) -> str:
    """Replace a sensitive value with a safe placeholder."""
    return "<redacted>"


def log_submission_start(
    correlation_id: str,
    election_id: int,
    commitment_hash: str,
) -> None:
    logger.info(
        "ballot_submission_start",
        extra={
            "correlation_id": correlation_id,
            "election_id": election_id,
            "commitment_hash": commitment_hash,
        },
    )


def log_submission_result(
    correlation_id: str,
    election_id: int,
    commitment_hash: str,
    status: str,
    tx_hash: str | None = None,
) -> None:
    logger.info(
        "ballot_submission_result",
        extra={
            "correlation_id": correlation_id,
            "election_id": election_id,
            "commitment_hash": commitment_hash,
            "status": status,
            "tx_hash": tx_hash or "<none>",
        },
    )


def log_credential_verification(
    correlation_id: str,
    issuer_key_id: str,
    result: str,
) -> None:
    """Log credential verification outcome — NOT the credential payload."""
    logger.info(
        "credential_verification",
        extra={
            "correlation_id": correlation_id,
            "issuer_key_id": issuer_key_id,
            "result": result,
        },
    )


def log_error(
    correlation_id: str,
    error_type: str,
    message: str,
) -> None:
    logger.error(
        "error",
        extra={
            "correlation_id": correlation_id,
            "error_type": error_type,
            "message": message,
        },
    )


def new_correlation_id() -> str:
    return str(uuid.uuid4())
