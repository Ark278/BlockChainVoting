"""Nullifier derivation service (Architecture v2.6 §5).

Exact construction:
    nullifier      = HMAC-SHA3-256(nullifier_key_election, credential_id || uint64_be(election_id))
    nullifier_hash = SHA3-256(nullifier)

Security requirements:
  - election-specific secret (nullifier_key_election) stored only in the key vault.
  - Raw nullifier is NEVER sent to the blockchain.
  - Raw nullifier is NEVER stored in PostgreSQL.
  - Only nullifier_hash is passed downstream.
"""

from __future__ import annotations

import hashlib
import hmac


def derive_nullifier(
    nullifier_key: bytes,
    credential_id: str,
    election_id: int,
) -> bytes:
    """Derive the raw nullifier using HMAC-SHA3-256.

    Args:
        nullifier_key: Election-specific secret (32 bytes from key vault). NEVER log.
        credential_id: UUID string of the voter credential.
        election_id:   On-chain election identifier.

    Returns:
        32-byte raw nullifier. NEVER store or transmit this value.
    """
    if len(nullifier_key) != 32:
        raise ValueError(f"nullifier_key must be exactly 32 bytes, got {len(nullifier_key)}")

    message = credential_id.encode("utf-8") + election_id.to_bytes(8, byteorder="big")
    nullifier = hmac.new(nullifier_key, message, hashlib.sha3_256).digest()
    return nullifier  # 32 bytes — caller must NOT persist or transmit this


def hash_nullifier(nullifier: bytes) -> bytes:
    """Compute SHA3-256(nullifier) → nullifier_hash.

    This is the only value that may be sent to the blockchain or stored.

    Args:
        nullifier: Raw 32-byte nullifier from derive_nullifier().

    Returns:
        32-byte nullifier_hash.
    """
    return hashlib.sha3_256(nullifier).digest()


def derive_and_hash(
    nullifier_key: bytes,
    credential_id: str,
    election_id: int,
) -> bytes:
    """Convenience: derive nullifier and immediately hash it.

    The intermediate raw nullifier is discarded from local scope after the call.

    Returns:
        32-byte nullifier_hash suitable for blockchain submission.
    """
    raw = derive_nullifier(nullifier_key, credential_id, election_id)
    result = hash_nullifier(raw)
    # raw nullifier goes out of scope here; Python will GC it.
    return result
