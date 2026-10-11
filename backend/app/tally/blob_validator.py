"""BallotBlobV1 strict pre-decryption validator (Architecture v2.6 Stage 3 §5).

Validates the structural integrity of a CBOR-encoded BallotBlobV1 before
any decryption attempt.  Rejection here prevents wasted decryption work on
malformed inputs and enforces the protocol wire format exactly.

Validated invariants:
  - Input is valid CBOR.
  - The decoded value is a CBOR map (dict).
  - Exactly the five canonical integer keys {0, 1, 2, 3, 255} are present.
  - version (key 255) == 1.
  - kem_ct (key 0) is bytes of exactly 1088 bytes.
  - nonce (key 1) is bytes of exactly 12 bytes.
  - ciphertext (key 2) is bytes (variable length, >= 1 byte).
  - tag (key 3) is bytes of exactly 16 bytes.
  - Re-encoding the map in canonical CBOR reproduces the original bytes
    (guarantees determinism; detects non-canonical encodings).
"""

from __future__ import annotations

import cbor2

from app.errors import BallotBlobValidationError
from app.services.crypto import (
    _KEY_CIPHERTEXT,  # 2
    _KEY_KEM_CT,  # 0
    _KEY_NONCE,  # 1
    _KEY_TAG,  # 3
    _KEY_VERSION,  # 255
    BALLOT_BLOB_VERSION,
    KEM_CT_LEN,
    NONCE_LEN,
    TAG_LEN,
)

# Canonical key set for BallotBlobV1.
_CANONICAL_KEYS: frozenset[int] = frozenset(
    {_KEY_KEM_CT, _KEY_NONCE, _KEY_CIPHERTEXT, _KEY_TAG, _KEY_VERSION}
)


def validate_ballot_blob_v1(blob_bytes: bytes) -> dict:
    """Strictly validate a BallotBlobV1 CBOR blob.

    Args:
        blob_bytes: Raw CBOR bytes retrieved from storage.

    Returns:
        Validated decoded dict with keys:
            kem_ct, nonce, ciphertext, tag, version.

    Raises:
        BallotBlobValidationError: On any structural violation.
    """
    if not isinstance(blob_bytes, bytes) or len(blob_bytes) == 0:
        raise BallotBlobValidationError("BallotBlobV1: input must be non-empty bytes")

    # --- CBOR decode ---
    try:
        raw = cbor2.loads(blob_bytes)
    except Exception as exc:
        raise BallotBlobValidationError(
            f"BallotBlobV1: CBOR decode failed: {exc}"
        ) from exc

    if not isinstance(raw, dict):
        raise BallotBlobValidationError(
            "BallotBlobV1: top-level CBOR value must be a map (dict)"
        )

    # --- Key set check (no extras, no missing) ---
    actual_keys = frozenset(raw.keys())
    missing = _CANONICAL_KEYS - actual_keys
    extra = actual_keys - _CANONICAL_KEYS
    if missing:
        raise BallotBlobValidationError(
            f"BallotBlobV1: missing required CBOR keys: {sorted(missing)}"
        )
    if extra:
        raise BallotBlobValidationError(
            f"BallotBlobV1: unexpected extra CBOR keys: {sorted(extra)}"
        )

    # --- Individual field validation ---
    version = raw[_KEY_VERSION]
    if not isinstance(version, int) or version != BALLOT_BLOB_VERSION:
        raise BallotBlobValidationError(
            f"BallotBlobV1: version must be {BALLOT_BLOB_VERSION}, got {version!r}"
        )

    kem_ct = raw[_KEY_KEM_CT]
    if not isinstance(kem_ct, bytes):
        raise BallotBlobValidationError("BallotBlobV1: kem_ct must be bytes")
    if len(kem_ct) != KEM_CT_LEN:
        raise BallotBlobValidationError(
            f"BallotBlobV1: kem_ct must be {KEM_CT_LEN} bytes, got {len(kem_ct)}"
        )

    nonce = raw[_KEY_NONCE]
    if not isinstance(nonce, bytes):
        raise BallotBlobValidationError("BallotBlobV1: nonce must be bytes")
    if len(nonce) != NONCE_LEN:
        raise BallotBlobValidationError(
            f"BallotBlobV1: nonce must be {NONCE_LEN} bytes, got {len(nonce)}"
        )

    ciphertext = raw[_KEY_CIPHERTEXT]
    if not isinstance(ciphertext, bytes):
        raise BallotBlobValidationError("BallotBlobV1: ciphertext must be bytes")
    if len(ciphertext) < 1:
        raise BallotBlobValidationError("BallotBlobV1: ciphertext must not be empty")

    tag = raw[_KEY_TAG]
    if not isinstance(tag, bytes):
        raise BallotBlobValidationError("BallotBlobV1: tag must be bytes")
    if len(tag) != TAG_LEN:
        raise BallotBlobValidationError(
            f"BallotBlobV1: tag must be {TAG_LEN} bytes, got {len(tag)}"
        )

    # --- Canonical re-encode check ---
    # Re-encode using the same canonical CBOR settings and compare with input.
    # This rejects any non-canonical encoding (e.g. indefinite-length, non-sorted).
    try:
        reencoded = cbor2.dumps(raw, canonical=True)
    except Exception as exc:
        raise BallotBlobValidationError(
            f"BallotBlobV1: canonical re-encoding failed: {exc}"
        ) from exc

    if reencoded != blob_bytes:
        raise BallotBlobValidationError(
            "BallotBlobV1: CBOR encoding is not canonical (re-encode mismatch)"
        )

    return {
        "kem_ct": kem_ct,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "tag": tag,
        "version": version,
    }
