"""Ballot payload schema and validator (Architecture v2.6 Stage 3 §10).

Defines the BallotPayload schema v1 and strict validation against
the election's allowed options.  This schema is the canonical plaintext
that is encrypted by Stage 2B and decrypted by the tally service.

Schema (version 1):
    {
        "schema_version": 1,
        "election_id":    <int>,
        "selected_option": "<str>"
    }

Validation rules:
  - Exactly the three required keys; no extras.
  - schema_version == 1.
  - election_id matches the election being tallied.
  - selected_option is in the allowed options set.
  - No modification of the payload is performed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.errors import InvalidBallotPayloadError

# Canonical key set for schema version 1.
_REQUIRED_KEYS_V1: frozenset[str] = frozenset(
    {"schema_version", "election_id", "selected_option"}
)
BALLOT_PAYLOAD_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class BallotPayload:
    """Parsed, validated ballot payload (schema version 1)."""

    schema_version: int
    election_id: int
    selected_option: str


def parse_ballot_payload(plaintext: bytes) -> dict[str, Any]:
    """Decode and basic-parse ballot plaintext bytes.

    Args:
        plaintext: UTF-8 JSON bytes from AES-GCM decryption.

    Returns:
        Parsed dict (not yet validated against election context).

    Raises:
        InvalidBallotPayloadError: On decode or JSON error.
    """
    try:
        text = plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidBallotPayloadError(
            "Ballot plaintext is not valid UTF-8"
        ) from exc

    try:
        data: dict[str, Any] = json.loads(text)
    except json.JSONDecodeError as exc:
        raise InvalidBallotPayloadError(
            f"Ballot plaintext is not valid JSON: {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise InvalidBallotPayloadError("Ballot plaintext must be a JSON object")

    return data


def validate_ballot_payload(
    plaintext: bytes,
    allowed_options: frozenset[str],
    expected_election_id: int,
) -> BallotPayload:
    """Validate decrypted ballot plaintext against election schema.

    Validates:
      - Correct JSON encoding.
      - Exactly the three required keys (no extras).
      - schema_version == 1.
      - election_id == expected_election_id.
      - selected_option is in allowed_options.
      - All value types are correct.

    The function never modifies the payload.

    Args:
        plaintext:            AES-GCM decrypted bytes.
        allowed_options:      Frozen set of valid option identifiers for
                              this election.
        expected_election_id: The election_id being tallied.

    Returns:
        Validated BallotPayload.

    Raises:
        InvalidBallotPayloadError: On any validation failure.
    """
    data = parse_ballot_payload(plaintext)

    # --- Key set check ---
    actual_keys = frozenset(data.keys())
    missing = _REQUIRED_KEYS_V1 - actual_keys
    extra = actual_keys - _REQUIRED_KEYS_V1
    if missing:
        raise InvalidBallotPayloadError(
            f"Ballot payload missing required fields: {sorted(missing)}"
        )
    if extra:
        raise InvalidBallotPayloadError(
            f"Ballot payload contains unexpected fields: {sorted(extra)}"
        )

    # --- Type checks ---
    if not isinstance(data["schema_version"], int):
        raise InvalidBallotPayloadError("schema_version must be an integer")
    if not isinstance(data["election_id"], int):
        raise InvalidBallotPayloadError("election_id must be an integer")
    if not isinstance(data["selected_option"], str):
        raise InvalidBallotPayloadError("selected_option must be a string")

    # --- Schema version ---
    if data["schema_version"] != BALLOT_PAYLOAD_SCHEMA_VERSION:
        raise InvalidBallotPayloadError(
            f"Unsupported ballot schema_version {data['schema_version']!r}; "
            f"expected {BALLOT_PAYLOAD_SCHEMA_VERSION}"
        )

    # --- Election ID ---
    if data["election_id"] != expected_election_id:
        raise InvalidBallotPayloadError(
            f"Ballot election_id {data['election_id']} does not match "
            f"expected {expected_election_id}"
        )

    # --- Option validation ---
    selected = data["selected_option"]
    if not selected:
        raise InvalidBallotPayloadError("selected_option must not be empty")
    if selected not in allowed_options:
        raise InvalidBallotPayloadError(
            f"selected_option {selected!r} is not in the allowed options for this election"
        )

    return BallotPayload(
        schema_version=data["schema_version"],
        election_id=data["election_id"],
        selected_option=selected,
    )


def build_ballot_plaintext(
    election_id: int,
    selected_option: str,
) -> bytes:
    """Construct canonical ballot plaintext bytes for encryption.

    Used in tests and the vote submission service.
    Produces deterministic JSON (sorted keys, no whitespace).

    Args:
        election_id:     On-chain election ID.
        selected_option: Voter's choice string.

    Returns:
        UTF-8 JSON bytes.
    """
    payload = {
        "schema_version": BALLOT_PAYLOAD_SCHEMA_VERSION,
        "election_id": election_id,
        "selected_option": selected_option,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
