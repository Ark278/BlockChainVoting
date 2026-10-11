"""Cryptographic services for ballot encryption (Architecture v2.6 §6–9).

Pipeline:
    ML-KEM-768 encapsulation  →  kem_ct (1088 B) + shared_secret (32 B)
    HKDF-SHA3-256              →  aes_key (32 B)
    AES-256-GCM                →  nonce (12 B) + ciphertext + tag (16 B)
    BallotBlobV1 CBOR          →  deterministic CBOR structure
    Commitment hash            →  SHA3-256(prefix || election_id || nullifier_hash || blob)

Security notes:
  - ML-KEM encapsulation is randomized in production (never deterministic).
  - AES key and shared_secret are NEVER logged.
  - Raw nullifier is never passed into this module.
"""

from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass

import cbor2
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── liboqs availability ───────────────────────────────────────────────────────
try:
    import oqs  # type: ignore[import-untyped]

    HAS_OQS = True
except ImportError:
    oqs = None  # type: ignore[assignment]
    HAS_OQS = False

# ── Constants (Architecture v2.6 exact sizes) ─────────────────────────────────

KEM_PK_LEN = 1184       # ML-KEM-768 public key
KEM_CT_LEN = 1088       # ML-KEM-768 ciphertext
KEM_SS_LEN = 32         # ML-KEM-768 shared secret
HASH_LEN = 32           # SHA3-256 output
NONCE_LEN = 12          # AES-GCM nonce
TAG_LEN = 16            # AES-GCM tag
BALLOT_BLOB_VERSION = 1

# CBOR map keys for BallotBlobV1
_KEY_KEM_CT = 0
_KEY_NONCE = 1
_KEY_CIPHERTEXT = 2
_KEY_TAG = 3
_KEY_VERSION = 255

# ── AAD construction ──────────────────────────────────────────────────────────


def build_aad(election_id: int, nullifier_hash: bytes, version: int = 1) -> bytes:
    """Build AES-GCM Additional Authenticated Data per Architecture v2.6 §7.

    AAD = UTF-8("VotingProtocolV1") || uint64_be(election_id) || nullifier_hash || uint8(version)
    """
    if len(nullifier_hash) != HASH_LEN:
        raise ValueError(f"nullifier_hash must be {HASH_LEN} bytes, got {len(nullifier_hash)}")
    return (
        b"VotingProtocolV1"
        + election_id.to_bytes(8, byteorder="big")
        + nullifier_hash
        + struct.pack("B", version)
    )


# ── HKDF-SHA3-256 (manual, RFC 5869) ─────────────────────────────────────────


def _hmac_sha3_256(key: bytes, data: bytes) -> bytes:
    import hmac as _hmac
    return _hmac.new(key, data, hashlib.sha3_256).digest()


def hkdf_sha3_256(
    ikm: bytes,
    length: int,
    info: bytes = b"",
    salt: bytes | None = None,
) -> bytes:
    """HKDF with SHA3-256 as the hash function (RFC 5869).

    Args:
        ikm:    Input keying material (shared secret from ML-KEM).
        length: Output length in bytes (32 for AES-256 key).
        info:   Context string (b"voting-aes-key").
        salt:   Optional salt; defaults to HashLen zero bytes.

    Returns:
        `length` bytes of derived key material.
    """
    hash_len = 32  # SHA3-256 output length

    # Extract
    if salt is None:
        salt = bytes(hash_len)
    prk = _hmac_sha3_256(salt, ikm)

    # Expand
    t = b""
    okm = b""
    n_blocks = -(-length // hash_len)  # ceiling division
    for i in range(1, n_blocks + 1):
        t = _hmac_sha3_256(prk, t + info + bytes([i]))
        okm += t

    return okm[:length]


def derive_aes_key(shared_secret: bytes) -> bytes:
    """Derive a 32-byte AES-256 key from an ML-KEM shared secret.

    Uses HKDF-SHA3-256 with info=b"voting-aes-key" as specified in v2.6 §6.
    NEVER log this value.
    """
    return hkdf_sha3_256(ikm=shared_secret, length=32, info=b"voting-aes-key")


# ── ML-KEM-768 encapsulation ──────────────────────────────────────────────────


def kem_encapsulate(kem_pk: bytes) -> tuple[bytes, bytes]:
    """ML-KEM-768 (NIST FIPS 203) randomized encapsulation.

    Args:
        kem_pk: Election ML-KEM-768 public key, exactly 1184 bytes.

    Returns:
        (ciphertext, shared_secret) — each 1088 and 32 bytes respectively.
        shared_secret MUST NOT be logged or stored.

    Raises:
        RuntimeError: If liboqs is not available.
        ValueError:   If kem_pk length is wrong.
    """
    if len(kem_pk) != KEM_PK_LEN:
        raise ValueError(f"kem_pk must be {KEM_PK_LEN} bytes, got {len(kem_pk)}")
    if not HAS_OQS:
        raise RuntimeError(
            "liboqs is not installed. Install it with: pip install liboqs\n"
            "See https://github.com/open-quantum-safe/liboqs-python"
        )
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        ciphertext, shared_secret = kem.encap_secret(kem_pk)
    if len(ciphertext) != KEM_CT_LEN:
        raise RuntimeError(f"ML-KEM-768 ciphertext must be {KEM_CT_LEN} bytes, got {len(ciphertext)}")
    return ciphertext, shared_secret  # shared_secret: NEVER log


def kem_decapsulate(kem_sk: bytes, ciphertext: bytes) -> bytes:
    """ML-KEM-768 decapsulation (used by the tally service, not this service).

    Included here for completeness; the election private key must never be
    accessible to the FastAPI service.
    """
    if not HAS_OQS:
        raise RuntimeError("liboqs is not installed.")
    with oqs.KeyEncapsulation("ML-KEM-768", kem_sk) as kem:
        return kem.decap_secret(ciphertext)


# ── AES-256-GCM encryption ────────────────────────────────────────────────────


@dataclass(frozen=True)
class AESGCMResult:
    nonce: bytes       # 12 bytes
    ciphertext: bytes  # variable length
    tag: bytes         # 16 bytes


def aes_gcm_encrypt(
    key: bytes,
    plaintext: bytes,
    aad: bytes,
) -> AESGCMResult:
    """AES-256-GCM encryption.

    Args:
        key:       32-byte AES key. NEVER log.
        plaintext: Ballot plaintext bytes (canonical JSON of ballot choices).
        aad:       Additional Authenticated Data (from build_aad()).

    Returns:
        AESGCMResult with nonce, ciphertext, and authentication tag.
    """
    if len(key) != 32:
        raise ValueError(f"AES key must be 32 bytes, got {len(key)}")
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    # AESGCM.encrypt appends the 16-byte tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, aad)
    ciphertext = ct_with_tag[:-TAG_LEN]
    tag = ct_with_tag[-TAG_LEN:]
    return AESGCMResult(nonce=nonce, ciphertext=ciphertext, tag=tag)


def aes_gcm_decrypt(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes,
) -> bytes:
    """AES-256-GCM decryption (used by tally service only)."""
    if len(key) != 32:
        raise ValueError(f"AES key must be 32 bytes, got {len(key)}")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)


# ── BallotBlobV1 CBOR serialization ──────────────────────────────────────────


def encode_ballot_blob(
    kem_ct: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
) -> bytes:
    """Encode BallotBlobV1 in deterministic CBOR (RFC 8949 §4.2).

    Structure (integer map keys, sorted by key):
        0   → kem_ct     (bytes, 1088 bytes)
        1   → nonce      (bytes, 12 bytes)
        2   → ciphertext (bytes, variable)
        3   → tag        (bytes, 16 bytes)
        255 → version    (uint, 1)

    Args:
        kem_ct:     ML-KEM-768 ciphertext, exactly 1088 bytes.
        nonce:      AES-GCM nonce, exactly 12 bytes.
        ciphertext: AES-GCM ciphertext.
        tag:        AES-GCM authentication tag, exactly 16 bytes.

    Returns:
        Deterministic CBOR-encoded bytes.
    """
    if len(kem_ct) != KEM_CT_LEN:
        raise ValueError(f"kem_ct must be {KEM_CT_LEN} bytes, got {len(kem_ct)}")
    if len(nonce) != NONCE_LEN:
        raise ValueError(f"nonce must be {NONCE_LEN} bytes, got {len(nonce)}")
    if len(tag) != TAG_LEN:
        raise ValueError(f"tag must be {TAG_LEN} bytes, got {len(tag)}")

    blob_map = {
        _KEY_KEM_CT: kem_ct,
        _KEY_NONCE: nonce,
        _KEY_CIPHERTEXT: ciphertext,
        _KEY_TAG: tag,
        _KEY_VERSION: BALLOT_BLOB_VERSION,
    }
    # canonical=True → deterministic CBOR (RFC 8949 §4.2)
    return cbor2.dumps(blob_map, canonical=True)


def decode_ballot_blob(blob: bytes) -> dict:
    """Decode a BallotBlobV1 CBOR blob for audit/tally purposes."""
    raw = cbor2.loads(blob)
    return {
        "kem_ct": raw[_KEY_KEM_CT],
        "nonce": raw[_KEY_NONCE],
        "ciphertext": raw[_KEY_CIPHERTEXT],
        "tag": raw[_KEY_TAG],
        "version": raw[_KEY_VERSION],
    }


# ── Commitment hash ───────────────────────────────────────────────────────────


def compute_commitment(
    election_id: int,
    nullifier_hash: bytes,
    ballot_blob: bytes,
) -> bytes:
    """Compute the commitment hash per Architecture v2.6 §9.

    commitment_hash = SHA3-256(
        UTF-8("VotingCommitmentV1") ||
        uint64_be(election_id)      ||
        nullifier_hash              ||
        canonical_encode(BallotBlobV1)
    )

    Returns:
        32-byte commitment hash.
    """
    if len(nullifier_hash) != HASH_LEN:
        raise ValueError(f"nullifier_hash must be {HASH_LEN} bytes, got {len(nullifier_hash)}")

    h = hashlib.sha3_256()
    h.update(b"VotingCommitmentV1")
    h.update(election_id.to_bytes(8, byteorder="big"))
    h.update(nullifier_hash)
    h.update(ballot_blob)
    return h.digest()


# ── KEM public key hash verification ─────────────────────────────────────────


def verify_kem_pk_hash(kem_pk: bytes, expected_hash: bytes) -> bool:
    """Verify SHA3-256(kem_pk) == expected_hash.

    Used to confirm the on-chain kem_pk_hash matches the retrieved public key
    before using it for encapsulation.
    """
    actual = hashlib.sha3_256(kem_pk).digest()
    return actual == expected_hash


# ── Full ballot encryption pipeline ──────────────────────────────────────────


@dataclass(frozen=True)
class EncryptedBallotPackage:
    """All cryptographic outputs from a single ballot encryption operation."""

    kem_ct: bytes        # 1088 bytes — goes into BallotBlobV1
    ballot_blob: bytes   # complete BallotBlobV1 CBOR
    commitment_hash: bytes  # 32 bytes — goes to blockchain
    kem_ct_hash: bytes   # 32 bytes — for audit/storage


def encrypt_ballot_full(
    election_id: int,
    nullifier_hash: bytes,
    ballot_plaintext: bytes,
    kem_pk: bytes,
    kem_pk_hash_expected: bytes,
) -> EncryptedBallotPackage:
    """Full ballot encryption pipeline per Architecture v2.6.

    Steps:
        1. Verify kem_pk against on-chain kem_pk_hash.
        2. ML-KEM-768 randomized encapsulation.
        3. HKDF-SHA3-256(shared_secret, info="voting-aes-key") → aes_key.
        4. Build AES-GCM AAD.
        5. AES-256-GCM encryption of ballot_plaintext.
        6. Encode BallotBlobV1 (deterministic CBOR).
        7. Compute commitment_hash.

    Args:
        election_id:          On-chain election ID.
        nullifier_hash:       32-byte SHA3-256 hash of the raw nullifier.
        ballot_plaintext:     Canonical ballot payload bytes (JSON or CBOR).
        kem_pk:               ML-KEM-768 public key (1184 bytes) from chain.
        kem_pk_hash_expected: On-chain kem_pk_hash for verification (32 bytes).

    Returns:
        EncryptedBallotPackage with all outputs. AES key and shared_secret
        are not included — they are local to this function scope.
    """
    from app.errors import EncryptionFailureError  # noqa: PLC0415

    # Step 1: Verify KEM public key integrity
    if not verify_kem_pk_hash(kem_pk, kem_pk_hash_expected):
        raise EncryptionFailureError(
            "KEM public key hash mismatch: on-chain hash does not match retrieved key"
        )

    try:
        # Step 2: ML-KEM-768 encapsulation (randomized)
        kem_ct, shared_secret = kem_encapsulate(kem_pk)  # shared_secret: NEVER log

        # Step 3: HKDF-SHA3-256
        aes_key = derive_aes_key(shared_secret)  # aes_key: NEVER log

        # Step 4: AAD
        aad = build_aad(election_id, nullifier_hash)

        # Step 5: AES-256-GCM encryption
        gcm = aes_gcm_encrypt(aes_key, ballot_plaintext, aad)

        # Step 6: BallotBlobV1 CBOR
        ballot_blob = encode_ballot_blob(kem_ct, gcm.nonce, gcm.ciphertext, gcm.tag)

        # Step 7: Commitment
        commitment = compute_commitment(election_id, nullifier_hash, ballot_blob)

        # Audit hash of KEM ciphertext
        kem_ct_hash = hashlib.sha3_256(kem_ct).digest()

        return EncryptedBallotPackage(
            kem_ct=kem_ct,
            ballot_blob=ballot_blob,
            commitment_hash=commitment,
            kem_ct_hash=kem_ct_hash,
        )
    except EncryptionFailureError:
        raise
    except Exception as exc:
        raise EncryptionFailureError(f"Ballot encryption pipeline failed: {exc}") from exc
    finally:
        # Python does not guarantee immediate memory erasure, but we ensure
        # local names go out of scope here and are not returned.
        pass
