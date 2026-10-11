"""Tests: ML-KEM decapsulation + AES-GCM decryption pipeline (Stage 3 §17 — Decryption).

Tests (requires liboqs):
  - successful ML-KEM decapsulation
  - successful AES-GCM decryption
  - wrong AAD fails
  - tampered ciphertext fails
  - tampered tag fails
  - wrong KEM private key fails
"""

from __future__ import annotations

import hashlib

import pytest
from cryptography.exceptions import InvalidTag

try:
    import oqs  # type: ignore[import-untyped]

    HAS_OQS = True
except ImportError:
    HAS_OQS = False

from app.services.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    build_aad,
    compute_commitment,
    derive_aes_key,
    kem_decapsulate,
    kem_encapsulate,
)

pytestmark = pytest.mark.skipif(not HAS_OQS, reason="liboqs not installed")


@pytest.fixture()
def kem_keypair() -> tuple[bytes, bytes]:
    """Generate a fresh ML-KEM-768 keypair."""
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    return pk, sk


@pytest.fixture()
def election_setup(kem_keypair: tuple[bytes, bytes]) -> dict:
    pk, sk = kem_keypair
    election_id = 42
    nullifier_hash = hashlib.sha3_256(b"test_voter_nullifier").digest()
    plaintext = b'{"schema_version":1,"election_id":42,"selected_option":"A"}'
    aad = build_aad(election_id, nullifier_hash)

    ct, shared_secret = kem_encapsulate(pk)
    aes_key = derive_aes_key(shared_secret)
    gcm = aes_gcm_encrypt(aes_key, plaintext, aad)

    return {
        "election_id": election_id,
        "nullifier_hash": nullifier_hash,
        "pk": pk,
        "sk": sk,
        "kem_ct": ct,
        "shared_secret": shared_secret,
        "aes_key": aes_key,
        "plaintext": plaintext,
        "aad": aad,
        "nonce": gcm.nonce,
        "ciphertext": gcm.ciphertext,
        "tag": gcm.tag,
    }


# ── Successful ML-KEM decapsulation ──────────────────────────────────────────


def test_ml_kem_decapsulation_produces_32_byte_secret(
    election_setup: dict,
) -> None:
    ss = kem_decapsulate(election_setup["sk"], election_setup["kem_ct"])
    assert len(ss) == 32
    assert ss == election_setup["shared_secret"]


# ── Successful AES-GCM decryption ────────────────────────────────────────────


def test_aes_gcm_decryption_success(election_setup: dict) -> None:
    ss = kem_decapsulate(election_setup["sk"], election_setup["kem_ct"])
    aes_key = derive_aes_key(ss)
    pt = aes_gcm_decrypt(
        key=aes_key,
        nonce=election_setup["nonce"],
        ciphertext=election_setup["ciphertext"],
        tag=election_setup["tag"],
        aad=election_setup["aad"],
    )
    assert pt == election_setup["plaintext"]


# ── Wrong AAD fails ───────────────────────────────────────────────────────────


def test_wrong_aad_decryption_fails(election_setup: dict) -> None:
    ss = kem_decapsulate(election_setup["sk"], election_setup["kem_ct"])
    aes_key = derive_aes_key(ss)
    bad_aad = build_aad(election_setup["election_id"] + 1, election_setup["nullifier_hash"])
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(
            key=aes_key,
            nonce=election_setup["nonce"],
            ciphertext=election_setup["ciphertext"],
            tag=election_setup["tag"],
            aad=bad_aad,
        )


# ── Tampered ciphertext fails ─────────────────────────────────────────────────


def test_tampered_ciphertext_fails(election_setup: dict) -> None:
    ss = kem_decapsulate(election_setup["sk"], election_setup["kem_ct"])
    aes_key = derive_aes_key(ss)
    tampered = bytearray(election_setup["ciphertext"])
    tampered[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(
            key=aes_key,
            nonce=election_setup["nonce"],
            ciphertext=bytes(tampered),
            tag=election_setup["tag"],
            aad=election_setup["aad"],
        )


# ── Tampered tag fails ────────────────────────────────────────────────────────


def test_tampered_tag_fails(election_setup: dict) -> None:
    ss = kem_decapsulate(election_setup["sk"], election_setup["kem_ct"])
    aes_key = derive_aes_key(ss)
    tampered_tag = bytearray(election_setup["tag"])
    tampered_tag[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(
            key=aes_key,
            nonce=election_setup["nonce"],
            ciphertext=election_setup["ciphertext"],
            tag=bytes(tampered_tag),
            aad=election_setup["aad"],
        )


# ── Wrong KEM private key fails ───────────────────────────────────────────────


def test_wrong_kem_private_key_produces_wrong_secret(election_setup: dict) -> None:
    """Decapsulation with a different SK produces a different shared secret,
    causing AES-GCM authentication to fail."""
    with oqs.KeyEncapsulation("ML-KEM-768") as wrong_kem:
        wrong_kem.generate_keypair()
        wrong_sk = wrong_kem.export_secret_key()

    wrong_ss = kem_decapsulate(wrong_sk, election_setup["kem_ct"])
    # In ML-KEM (implicit rejection), decapsulation always succeeds but
    # produces a pseudorandom value — the result will differ from the correct SS.
    assert wrong_ss != election_setup["shared_secret"]

    wrong_aes_key = derive_aes_key(wrong_ss)
    with pytest.raises(InvalidTag):
        aes_gcm_decrypt(
            key=wrong_aes_key,
            nonce=election_setup["nonce"],
            ciphertext=election_setup["ciphertext"],
            tag=election_setup["tag"],
            aad=election_setup["aad"],
        )


# ── End-to-end round-trip with blob encoding ──────────────────────────────────


def test_full_encryption_decryption_round_trip(kem_keypair: tuple[bytes, bytes]) -> None:
    from app.services.crypto import encrypt_ballot_full  # noqa: PLC0415
    from app.tally.blob_validator import validate_ballot_blob_v1  # noqa: PLC0415

    pk, sk = kem_keypair
    election_id = 1
    nullifier_hash = hashlib.sha3_256(b"voter_1").digest()
    pk_hash = hashlib.sha3_256(pk).digest()
    plaintext = b'{"schema_version":1,"election_id":1,"selected_option":"B"}'

    pkg = encrypt_ballot_full(election_id, nullifier_hash, plaintext, pk, pk_hash)

    # Validate blob structure
    decoded = validate_ballot_blob_v1(pkg.ballot_blob)
    assert decoded["version"] == 1

    # Decrypt
    ss = kem_decapsulate(sk, decoded["kem_ct"])
    aes_key = derive_aes_key(ss)
    aad = build_aad(election_id, nullifier_hash)
    recovered = aes_gcm_decrypt(
        key=aes_key,
        nonce=decoded["nonce"],
        ciphertext=decoded["ciphertext"],
        tag=decoded["tag"],
        aad=aad,
    )
    assert recovered == plaintext

    # Commitment verification
    recomputed = compute_commitment(election_id, nullifier_hash, pkg.ballot_blob)
    assert recomputed == pkg.commitment_hash
