"""Tests: BallotBlobV1 validator (Stage 3 §17 — BallotBlob).

Tests:
  - valid blob passes
  - malformed CBOR rejected
  - wrong version rejected
  - incorrect KEM ciphertext size rejected
  - incorrect nonce size rejected
  - incorrect tag size rejected
  - extra fields rejected
  - missing fields rejected
  - non-canonical encoding rejected
"""

from __future__ import annotations

import os

import cbor2
import pytest

from app.errors import BallotBlobValidationError
from app.services.crypto import (
    _KEY_CIPHERTEXT,
    _KEY_KEM_CT,
    _KEY_NONCE,
    _KEY_TAG,
    _KEY_VERSION,
    BALLOT_BLOB_VERSION,
    KEM_CT_LEN,
    NONCE_LEN,
    TAG_LEN,
    encode_ballot_blob,
)
from app.tally.blob_validator import validate_ballot_blob_v1


@pytest.fixture()
def valid_blob() -> bytes:
    return encode_ballot_blob(
        kem_ct=os.urandom(KEM_CT_LEN),
        nonce=os.urandom(NONCE_LEN),
        ciphertext=b"some_ciphertext",
        tag=os.urandom(TAG_LEN),
    )


# ── Valid blob accepted ───────────────────────────────────────────────────────


def test_valid_blob_passes(valid_blob: bytes) -> None:
    result = validate_ballot_blob_v1(valid_blob)
    assert result["version"] == BALLOT_BLOB_VERSION
    assert len(result["kem_ct"]) == KEM_CT_LEN
    assert len(result["nonce"]) == NONCE_LEN
    assert len(result["tag"]) == TAG_LEN
    assert isinstance(result["ciphertext"], bytes)


# ── Malformed CBOR rejected ───────────────────────────────────────────────────


def test_malformed_cbor_rejected() -> None:
    # cbor2 may decode some garbage as a non-map scalar; the validator
    # must reject it either with 'CBOR decode failed' or 'map (dict)'.
    with pytest.raises(BallotBlobValidationError):
        validate_ballot_blob_v1(b"\xff\xfe\xfd garbage not cbor")


def test_empty_bytes_rejected() -> None:
    with pytest.raises(BallotBlobValidationError):
        validate_ballot_blob_v1(b"")


def test_non_map_cbor_rejected() -> None:
    # A CBOR list instead of a map
    blob = cbor2.dumps([1, 2, 3], canonical=True)
    with pytest.raises(BallotBlobValidationError, match="map"):
        validate_ballot_blob_v1(blob)


# ── Wrong version rejected ────────────────────────────────────────────────────


def test_wrong_version_rejected() -> None:
    raw = {
        _KEY_KEM_CT: os.urandom(KEM_CT_LEN),
        _KEY_NONCE: os.urandom(NONCE_LEN),
        _KEY_CIPHERTEXT: b"ct",
        _KEY_TAG: os.urandom(TAG_LEN),
        _KEY_VERSION: 99,
    }
    blob = cbor2.dumps(raw, canonical=True)
    with pytest.raises(BallotBlobValidationError, match="version"):
        validate_ballot_blob_v1(blob)


# ── Incorrect KEM ciphertext size rejected ────────────────────────────────────


def test_kem_ct_wrong_size_rejected() -> None:
    raw = {
        _KEY_KEM_CT: os.urandom(100),  # wrong: must be 1088
        _KEY_NONCE: os.urandom(NONCE_LEN),
        _KEY_CIPHERTEXT: b"ct",
        _KEY_TAG: os.urandom(TAG_LEN),
        _KEY_VERSION: BALLOT_BLOB_VERSION,
    }
    blob = cbor2.dumps(raw, canonical=True)
    with pytest.raises(BallotBlobValidationError, match="kem_ct"):
        validate_ballot_blob_v1(blob)


# ── Incorrect nonce size rejected ─────────────────────────────────────────────


def test_nonce_wrong_size_rejected() -> None:
    raw = {
        _KEY_KEM_CT: os.urandom(KEM_CT_LEN),
        _KEY_NONCE: os.urandom(8),   # wrong: must be 12
        _KEY_CIPHERTEXT: b"ct",
        _KEY_TAG: os.urandom(TAG_LEN),
        _KEY_VERSION: BALLOT_BLOB_VERSION,
    }
    blob = cbor2.dumps(raw, canonical=True)
    with pytest.raises(BallotBlobValidationError, match="nonce"):
        validate_ballot_blob_v1(blob)


# ── Incorrect tag size rejected ───────────────────────────────────────────────


def test_tag_wrong_size_rejected() -> None:
    raw = {
        _KEY_KEM_CT: os.urandom(KEM_CT_LEN),
        _KEY_NONCE: os.urandom(NONCE_LEN),
        _KEY_CIPHERTEXT: b"ct",
        _KEY_TAG: os.urandom(8),    # wrong: must be 16
        _KEY_VERSION: BALLOT_BLOB_VERSION,
    }
    blob = cbor2.dumps(raw, canonical=True)
    with pytest.raises(BallotBlobValidationError, match="tag"):
        validate_ballot_blob_v1(blob)


# ── Extra fields rejected ─────────────────────────────────────────────────────


def test_extra_fields_rejected() -> None:
    raw = {
        _KEY_KEM_CT: os.urandom(KEM_CT_LEN),
        _KEY_NONCE: os.urandom(NONCE_LEN),
        _KEY_CIPHERTEXT: b"ct",
        _KEY_TAG: os.urandom(TAG_LEN),
        _KEY_VERSION: BALLOT_BLOB_VERSION,
        999: b"extra_field",  # unexpected key
    }
    blob = cbor2.dumps(raw, canonical=True)
    with pytest.raises(BallotBlobValidationError, match="extra"):
        validate_ballot_blob_v1(blob)


# ── Missing fields rejected ───────────────────────────────────────────────────


def test_missing_fields_rejected() -> None:
    # Omit the nonce key
    raw = {
        _KEY_KEM_CT: os.urandom(KEM_CT_LEN),
        _KEY_CIPHERTEXT: b"ct",
        _KEY_TAG: os.urandom(TAG_LEN),
        _KEY_VERSION: BALLOT_BLOB_VERSION,
    }
    blob = cbor2.dumps(raw, canonical=True)
    with pytest.raises(BallotBlobValidationError, match="missing"):
        validate_ballot_blob_v1(blob)


# ── Non-canonical encoding rejected ──────────────────────────────────────────


def test_non_canonical_encoding_rejected() -> None:
    """A blob that decodes correctly but was not canonically encoded fails."""
    raw = {
        _KEY_KEM_CT: os.urandom(KEM_CT_LEN),
        _KEY_NONCE: os.urandom(NONCE_LEN),
        _KEY_CIPHERTEXT: b"ct",
        _KEY_TAG: os.urandom(TAG_LEN),
        _KEY_VERSION: BALLOT_BLOB_VERSION,
    }
    # Encode without canonical=True → may produce non-sorted key order
    non_canonical = cbor2.dumps(raw, canonical=False)
    canonical = cbor2.dumps(raw, canonical=True)
    if non_canonical == canonical:
        pytest.skip("cbor2 produced canonical output without flag; skip non-canonical test")
    with pytest.raises(BallotBlobValidationError, match="canonical"):
        validate_ballot_blob_v1(non_canonical)
