"""Tests: commitment hash verification (Stage 3 §17 — Commitment).

Tests:
  - correct commitment accepted
  - modified blob rejected
  - modified election_id rejected
  - modified nullifier rejected
"""

from __future__ import annotations

import hashlib
import os

import pytest

from app.services.crypto import (
    KEM_CT_LEN,
    NONCE_LEN,
    TAG_LEN,
    compute_commitment,
    encode_ballot_blob,
)


@pytest.fixture()
def sample_blob() -> bytes:
    """Build a minimal valid BallotBlobV1 CBOR blob."""
    kem_ct = os.urandom(KEM_CT_LEN)
    nonce = os.urandom(NONCE_LEN)
    ciphertext = b"encrypted_plaintext_bytes"
    tag = os.urandom(TAG_LEN)
    return encode_ballot_blob(kem_ct, nonce, ciphertext, tag)


@pytest.fixture()
def nullifier_hash() -> bytes:
    return hashlib.sha3_256(b"test_nullifier_seed").digest()


# ── Correct commitment accepted ───────────────────────────────────────────────


def test_commitment_correct_accepted(sample_blob: bytes, nullifier_hash: bytes) -> None:
    election_id = 7
    commitment = compute_commitment(election_id, nullifier_hash, sample_blob)
    assert isinstance(commitment, bytes)
    assert len(commitment) == 32
    # Recomputing must produce the same value
    commitment2 = compute_commitment(election_id, nullifier_hash, sample_blob)
    assert commitment == commitment2


# ── Modified blob rejected ────────────────────────────────────────────────────


def test_commitment_modified_blob_rejected(
    sample_blob: bytes, nullifier_hash: bytes
) -> None:
    election_id = 7
    original = compute_commitment(election_id, nullifier_hash, sample_blob)

    # Flip one bit in the blob
    tampered = bytearray(sample_blob)
    tampered[-1] ^= 0xFF
    tampered_commitment = compute_commitment(election_id, nullifier_hash, bytes(tampered))

    assert original != tampered_commitment


# ── Modified election_id rejected ─────────────────────────────────────────────


def test_commitment_modified_election_id_rejected(
    sample_blob: bytes, nullifier_hash: bytes
) -> None:
    commitment_a = compute_commitment(1, nullifier_hash, sample_blob)
    commitment_b = compute_commitment(2, nullifier_hash, sample_blob)
    assert commitment_a != commitment_b


# ── Modified nullifier rejected ───────────────────────────────────────────────


def test_commitment_modified_nullifier_rejected(sample_blob: bytes) -> None:
    nh1 = hashlib.sha3_256(b"nullifier_A").digest()
    nh2 = hashlib.sha3_256(b"nullifier_B").digest()
    commitment_a = compute_commitment(1, nh1, sample_blob)
    commitment_b = compute_commitment(1, nh2, sample_blob)
    assert commitment_a != commitment_b


# ── Commitment domain separation ─────────────────────────────────────────────


def test_commitment_uses_prefix() -> None:
    """Commitment must include the VotingCommitmentV1 prefix."""
    nh = hashlib.sha3_256(b"n").digest()
    blob = b"some_blob"
    commitment = compute_commitment(1, nh, blob)
    # Manually compute expected
    h = hashlib.sha3_256()
    h.update(b"VotingCommitmentV1")
    h.update((1).to_bytes(8, "big"))
    h.update(nh)
    h.update(blob)
    assert commitment == h.digest()


# ── Invalid input rejected ────────────────────────────────────────────────────


def test_commitment_wrong_nullifier_length() -> None:
    with pytest.raises(ValueError, match="nullifier_hash must be 32 bytes"):
        compute_commitment(1, b"short", b"blob")
