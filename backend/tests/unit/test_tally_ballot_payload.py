"""Tests: ballot payload validation (Stage 3 §17 — Ballot validation).

Tests:
  - valid ballot counted
  - invalid candidate rejected
  - malformed plaintext rejected
  - extra fields rejected
  - missing fields rejected
  - wrong schema_version rejected
  - wrong election_id rejected
  - empty selected_option rejected
"""

from __future__ import annotations

import json

import pytest

from app.errors import InvalidBallotPayloadError
from app.tally.ballot_payload import (
    BALLOT_PAYLOAD_SCHEMA_VERSION,
    build_ballot_plaintext,
    validate_ballot_payload,
)

_ALLOWED = frozenset({"candidate_A", "candidate_B", "candidate_C"})
_ELECTION_ID = 5


def _make_plaintext(**overrides: object) -> bytes:
    payload = {
        "schema_version": BALLOT_PAYLOAD_SCHEMA_VERSION,
        "election_id": _ELECTION_ID,
        "selected_option": "candidate_A",
    }
    payload.update(overrides)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# ── Valid ballot accepted ─────────────────────────────────────────────────────


def test_valid_ballot_accepted() -> None:
    pt = build_ballot_plaintext(_ELECTION_ID, "candidate_B")
    result = validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)
    assert result.selected_option == "candidate_B"
    assert result.election_id == _ELECTION_ID
    assert result.schema_version == BALLOT_PAYLOAD_SCHEMA_VERSION


def test_all_allowed_options_accepted() -> None:
    for option in _ALLOWED:
        pt = build_ballot_plaintext(_ELECTION_ID, option)
        result = validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)
        assert result.selected_option == option


# ── Invalid candidate rejected ────────────────────────────────────────────────


def test_invalid_candidate_rejected() -> None:
    pt = _make_plaintext(selected_option="candidate_X")
    with pytest.raises(InvalidBallotPayloadError, match="not in the allowed options"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)


# ── Malformed plaintext rejected ──────────────────────────────────────────────


def test_non_utf8_rejected() -> None:
    with pytest.raises(InvalidBallotPayloadError, match="UTF-8"):
        validate_ballot_payload(b"\xff\xfe", _ALLOWED, _ELECTION_ID)


def test_non_json_rejected() -> None:
    with pytest.raises(InvalidBallotPayloadError, match="JSON"):
        validate_ballot_payload(b"not json at all", _ALLOWED, _ELECTION_ID)


def test_json_array_rejected() -> None:
    with pytest.raises(InvalidBallotPayloadError, match="JSON object"):
        validate_ballot_payload(b"[1, 2, 3]", _ALLOWED, _ELECTION_ID)


# ── Extra fields rejected ─────────────────────────────────────────────────────


def test_extra_field_rejected() -> None:
    pt = _make_plaintext(unexpected_field="extra_value")
    with pytest.raises(InvalidBallotPayloadError, match="unexpected fields"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)


# ── Missing fields rejected ───────────────────────────────────────────────────


def test_missing_schema_version_rejected() -> None:
    payload = {"election_id": _ELECTION_ID, "selected_option": "candidate_A"}
    pt = json.dumps(payload).encode()
    with pytest.raises(InvalidBallotPayloadError, match="missing required fields"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)


def test_missing_selected_option_rejected() -> None:
    payload = {
        "schema_version": BALLOT_PAYLOAD_SCHEMA_VERSION,
        "election_id": _ELECTION_ID,
    }
    pt = json.dumps(payload).encode()
    with pytest.raises(InvalidBallotPayloadError, match="missing required fields"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)


# ── Wrong schema_version rejected ─────────────────────────────────────────────


def test_wrong_schema_version_rejected() -> None:
    pt = _make_plaintext(schema_version=99)
    with pytest.raises(InvalidBallotPayloadError, match="schema_version"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)


# ── Wrong election_id rejected ────────────────────────────────────────────────


def test_wrong_election_id_rejected() -> None:
    pt = _make_plaintext(election_id=999)
    with pytest.raises(InvalidBallotPayloadError, match="election_id"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)


# ── Empty selected_option rejected ────────────────────────────────────────────


def test_empty_selected_option_rejected() -> None:
    pt = _make_plaintext(selected_option="")
    with pytest.raises(InvalidBallotPayloadError, match="empty"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)


# ── Wrong type fields rejected ────────────────────────────────────────────────


def test_schema_version_string_rejected() -> None:
    pt = _make_plaintext(schema_version="1")
    with pytest.raises(InvalidBallotPayloadError, match="integer"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)


def test_election_id_string_rejected() -> None:
    pt = _make_plaintext(election_id="5")
    with pytest.raises(InvalidBallotPayloadError, match="integer"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)


def test_selected_option_int_rejected() -> None:
    pt = _make_plaintext(selected_option=1)
    with pytest.raises(InvalidBallotPayloadError, match="string"):
        validate_ballot_payload(pt, _ALLOWED, _ELECTION_ID)
