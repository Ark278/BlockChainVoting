"""Credential verification service (Architecture v2.6 §3).

Credential format (v2.6):
{
    "credential_id": "<UUID>",
    "issued_at":     "<ISO-8601>",
    "expires_at":    "<ISO-8601>",
    "attributes":    {},
    "issuer_key_id": "<string>"
}

Verification flow:
    parse canonical payload
        → read issuer_key_id
        → query CosmWasm ISSUER_KEYS[issuer_key_id]
        → retrieve public_key + public_key_hash
        → verify ML-DSA-65 signature
        → verify SHA3-256(public_key) == stored public_key_hash
        → validate timestamps (issued_at <= now < expires_at)
        → check off-chain revocation status

Note: The issuer PRIVATE KEY is never accessed by this service.
      Only the public key is retrieved from the chain.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from app.errors import (
    ExpiredCredentialError,
    InvalidCredentialError,
    InvalidSignatureError,
    RevokedCredentialError,
    UnknownIssuerKeyError,
)

# ── liboqs for ML-DSA-65 ──────────────────────────────────────────────────────
try:
    import oqs  # type: ignore[import-untyped]

    HAS_OQS = True
except ImportError:
    oqs = None  # type: ignore[assignment]
    HAS_OQS = False

DSA_PK_LEN = 1952    # ML-DSA-65 public key (NIST FIPS 204)
HASH_LEN = 32


# ── Credential payload ────────────────────────────────────────────────────────


class CredentialPayload:
    """Parsed, validated credential payload."""

    def __init__(
        self,
        credential_id: str,
        issued_at: datetime,
        expires_at: datetime,
        attributes: dict[str, Any],
        issuer_key_id: str,
        raw_json: bytes,
    ) -> None:
        self.credential_id = credential_id
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.attributes = attributes
        self.issuer_key_id = issuer_key_id
        self.raw_json = raw_json  # canonical bytes that were signed

    def is_expired(self, now: datetime | None = None) -> bool:
        if now is None:
            now = datetime.now(UTC)
        return now >= self.expires_at


def parse_credential_payload(raw_json: bytes) -> CredentialPayload:
    """Parse and structurally validate a credential payload.

    The raw_json bytes are exactly what was signed by the issuer.
    """
    try:
        data: dict[str, Any] = json.loads(raw_json.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise InvalidCredentialError("Credential payload is not valid UTF-8 JSON") from exc

    required = {"credential_id", "issued_at", "expires_at", "attributes", "issuer_key_id"}
    missing = required - set(data.keys())
    if missing:
        raise InvalidCredentialError(f"Credential missing required fields: {missing}")

    try:
        issued_at = datetime.fromisoformat(data["issued_at"]).astimezone(UTC)
        expires_at = datetime.fromisoformat(data["expires_at"]).astimezone(UTC)
    except (ValueError, TypeError) as exc:
        raise InvalidCredentialError(f"Invalid timestamp format: {exc}") from exc

    return CredentialPayload(
        credential_id=str(data["credential_id"]),
        issued_at=issued_at,
        expires_at=expires_at,
        attributes=dict(data["attributes"]),
        issuer_key_id=str(data["issuer_key_id"]),
        raw_json=serialize_credential_payload(data),
    )


def serialize_credential_payload(data: dict[str, Any]) -> bytes:
    """Deterministically serialize a credential payload for signing/verification.
    
    Rules for Canonical JSON Serialization:
    1. Keys are sorted lexicographically (sort_keys=True)
    2. No whitespace between separators (separators=(",", ":"))
    3. Output is encoded as UTF-8 bytes
    
    This exact byte sequence is what must be signed by the issuer and verified.
    """
    # Ensure we only serialize the required schema fields if extra are present,
    # or just serialize the dict as is (assuming it's validated).
    # We will serialize exactly what is provided, relying on sort_keys.
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ── ML-DSA-65 signature verification ─────────────────────────────────────────


def verify_ml_dsa_65(
    public_key: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """Verify an ML-DSA-65 (NIST FIPS 204) signature.

    Args:
        public_key: 1952-byte ML-DSA-65 public key from on-chain registry.
        message:    Signed message (canonical credential payload bytes).
        signature:  ML-DSA-65 signature (up to 3309 bytes).

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        RuntimeError: If liboqs is not installed.
    """
    if not HAS_OQS:
        raise RuntimeError(
            "liboqs is not installed. ML-DSA-65 verification requires liboqs.\n"
            "Install with: pip install liboqs"
        )
    if len(public_key) != DSA_PK_LEN:
        raise InvalidSignatureError(
            f"Issuer public key must be {DSA_PK_LEN} bytes, got {len(public_key)}"
        )
    with oqs.Signature("ML-DSA-65") as verifier:
        return bool(verifier.verify(message, signature, public_key))


def verify_issuer_key_integrity(public_key: bytes, stored_hash: bytes) -> bool:
    """Verify SHA3-256(public_key) == stored on-chain hash.

    This ensures the public key retrieved from the chain has not been tampered with.
    """
    actual_hash = hashlib.sha3_256(public_key).digest()
    return actual_hash == stored_hash


# ── Full credential verification ──────────────────────────────────────────────


async def verify_credential(
    credential_payload_bytes: bytes,
    signature: bytes,
    blockchain_client: Any,
    revocation_repo: Any,
    now: datetime | None = None,
) -> CredentialPayload:
    """Full credential verification pipeline per Architecture v2.6 §3.

    Args:
        credential_payload_bytes: Raw UTF-8 JSON bytes that were signed.
        signature:                ML-DSA-65 signature over the payload bytes.
        blockchain_client:        Client to query CosmWasm ISSUER_KEYS.
        revocation_repo:          Repository to check off-chain revocation status.
        now:                      Override for current time (testing only).

    Returns:
        Validated CredentialPayload.

    Raises:
        InvalidCredentialError, InvalidSignatureError, UnknownIssuerKeyError,
        ExpiredCredentialError, RevokedCredentialError
    """
    if now is None:
        now = datetime.now(UTC)

    # Step 1: Parse payload
    credential = parse_credential_payload(credential_payload_bytes)

    # Step 2: Fetch issuer key from CosmWasm
    issuer_key_data = await blockchain_client.get_issuer_key(credential.issuer_key_id)
    if issuer_key_data is None:
        raise UnknownIssuerKeyError(
            f"Issuer key not found on-chain: {credential.issuer_key_id}"
        )

    public_key: bytes = issuer_key_data["public_key"]
    public_key_hash: bytes = issuer_key_data["public_key_hash"]

    # Step 3: Verify key integrity (SHA3-256(pk) == stored hash)
    if not verify_issuer_key_integrity(public_key, public_key_hash):
        raise InvalidSignatureError(
            "Issuer public key integrity check failed: hash mismatch on-chain"
        )

    # Step 4: Verify ML-DSA-65 signature
    try:
        valid = verify_ml_dsa_65(public_key, credential.raw_json, signature)
    except RuntimeError as exc:
        raise InvalidSignatureError(f"ML-DSA-65 verification runtime error: {exc}") from exc

    if not valid:
        raise InvalidSignatureError("ML-DSA-65 signature verification failed")

    # Step 5: Validate timestamps
    if now >= credential.expires_at:
        raise ExpiredCredentialError(
            f"Credential expired at {credential.expires_at.isoformat()}"
        )

    # Step 6: Off-chain revocation check
    is_revoked = await revocation_repo.is_revoked(credential.credential_id)
    if is_revoked:
        raise RevokedCredentialError(
            f"Credential {credential.credential_id} has been revoked"
        )

    return credential
