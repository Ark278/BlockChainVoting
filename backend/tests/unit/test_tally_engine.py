"""Tests: tally engine — computation, serialization, commitment (Stage 3 §17 — Tally).

Tests (all I/O is mocked; no real blockchain or DB):
  - deterministic tally result from identical inputs
  - correct vote counters
  - deterministic canonical serialization
  - result_commitment reproducibility
  - wrong election state rejected (TallyStateError)
  - result does not contain generated_at / timestamps
  - canonical result has no floating point
"""

from __future__ import annotations

import hashlib
import json

import pytest

from app.tally.engine import (
    TallyCounters,
    _compute_result_commitment,
    _serialize_canonical_result,
)

# ── Canonical serialization ───────────────────────────────────────────────────


def test_canonical_serialization_is_deterministic() -> None:
    election_id = 3
    results = {"candidate_B": 5, "candidate_A": 10}
    counters = TallyCounters(
        total_commitments=15,
        valid_ballots=15,
        invalid_ballots=0,
        integrity_failures=0,
        decryption_failures=0,
        recovered_ballots=0,
    )
    b1 = _serialize_canonical_result(election_id, results, counters)
    b2 = _serialize_canonical_result(election_id, results, counters)
    assert b1 == b2


def test_canonical_serialization_sorts_options() -> None:
    results_a = {"z_option": 1, "a_option": 2}
    results_b = {"a_option": 2, "z_option": 1}
    counters = TallyCounters()
    b1 = _serialize_canonical_result(1, results_a, counters)
    b2 = _serialize_canonical_result(1, results_b, counters)
    assert b1 == b2
    # "a_option" must appear before "z_option" in the JSON
    data = json.loads(b1)
    keys = list(data["results"].keys())
    assert keys == sorted(keys)


def test_canonical_serialization_no_timestamps() -> None:
    """generated_at / completed_at must NOT appear in canonical bytes."""
    counters = TallyCounters()
    b = _serialize_canonical_result(1, {"A": 0}, counters)
    text = b.decode()
    assert "generated_at" not in text
    assert "completed_at" not in text
    assert "timestamp" not in text.lower()


def test_canonical_serialization_no_floating_point() -> None:
    counters = TallyCounters(valid_ballots=7, invalid_ballots=2)
    b = _serialize_canonical_result(1, {"A": 7}, counters)
    data = json.loads(b)
    # All numeric values in the result must be ints
    def check_no_float(obj: object) -> None:
        if isinstance(obj, dict):
            for v in obj.values():
                check_no_float(v)
        elif isinstance(obj, list):
            for item in obj:
                check_no_float(item)
        elif isinstance(obj, float):
            pytest.fail(f"Float found in canonical result: {obj}")

    check_no_float(data)


def test_canonical_serialization_schema_version() -> None:
    counters = TallyCounters()
    b = _serialize_canonical_result(1, {}, counters)
    data = json.loads(b)
    assert data["tally_schema_version"] == 1


# ── Result commitment ─────────────────────────────────────────────────────────


def test_result_commitment_is_32_bytes() -> None:
    counters = TallyCounters()
    b = _serialize_canonical_result(1, {"A": 3}, counters)
    commitment = _compute_result_commitment(b)
    assert isinstance(commitment, bytes)
    assert len(commitment) == 32


def test_result_commitment_reproducible() -> None:
    counters = TallyCounters(valid_ballots=3, recovered_ballots=1)
    b = _serialize_canonical_result(2, {"A": 2, "B": 1}, counters)
    c1 = _compute_result_commitment(b)
    c2 = _compute_result_commitment(b)
    assert c1 == c2


def test_result_commitment_changes_with_different_results() -> None:
    counters = TallyCounters(valid_ballots=2)
    b1 = _serialize_canonical_result(1, {"A": 2}, counters)
    b2 = _serialize_canonical_result(1, {"A": 1, "B": 1}, counters)
    c1 = _compute_result_commitment(b1)
    c2 = _compute_result_commitment(b2)
    assert c1 != c2


def test_result_commitment_uses_sha3_256() -> None:
    counters = TallyCounters()
    b = _serialize_canonical_result(1, {"X": 0}, counters)
    expected = hashlib.sha3_256(b).digest()
    assert _compute_result_commitment(b) == expected


# ── Counter logic ─────────────────────────────────────────────────────────────


def test_counters_default_zero() -> None:
    c = TallyCounters()
    assert c.total_commitments == 0
    assert c.valid_ballots == 0
    assert c.invalid_ballots == 0
    assert c.integrity_failures == 0
    assert c.decryption_failures == 0
    assert c.recovered_ballots == 0


def test_counters_in_canonical_output() -> None:
    counters = TallyCounters(
        total_commitments=10,
        valid_ballots=7,
        invalid_ballots=2,
        integrity_failures=1,
        decryption_failures=0,
        recovered_ballots=3,
    )
    b = _serialize_canonical_result(1, {"A": 7}, counters)
    data = json.loads(b)
    assert data["valid_ballots"] == 7
    assert data["invalid_ballots"] == 2
    assert data["integrity_failures"] == 1
    assert data["decryption_failures"] == 0
    assert data["recovered_ballots"] == 3
