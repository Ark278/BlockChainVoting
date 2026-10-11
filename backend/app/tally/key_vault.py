"""Election Key Vault (Architecture v2.6 Stage 3 §7).

Single responsibility: supply the ML-KEM-768 private key for a specific
election to the tally service.

Security invariants:
  - The key is returned as bytes and NEVER cached beyond the call site.
  - The key is NEVER logged, stored in PostgreSQL, or included in any
    response or audit event.
  - Each call fetches the key fresh from the configured source.
  - Only the tally engine calls this; no other module may import it.

Development mode (election_key_source == "env"):
  Reads ELECTION_KEM_SK_HEX_{election_id} from the process environment.
  The variable must contain the hex-encoded ML-KEM-768 secret key.

Production mode (election_key_source == "vault"):
  Extend this class to call HashiCorp Vault, AWS Secrets Manager, or
  another HSM-backed provider.  The interface (get_kem_sk) is unchanged.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger("voting.tally.key_vault")

# ML-KEM-768 secret key length per NIST FIPS 203.
_KEM_SK_LEN = 2400  # bytes


class ElectionKeyVault:
    """Provides the election ML-KEM-768 private key to the tally engine.

    Args:
        source: Key source mode — "env" (development) or "vault" (production).
    """

    def __init__(self, source: str = "env") -> None:
        if source not in ("env", "vault"):
            raise ValueError(f"Unknown election_key_source: {source!r}")
        self._source = source

    def get_kem_sk(self, election_id: int) -> bytes:
        """Return the ML-KEM-768 private key bytes for the given election.

        The returned value MUST be used immediately for decapsulation and
        then discarded.  It must not be stored, logged, or returned to callers
        outside the tally engine.

        Args:
            election_id: On-chain election identifier.

        Returns:
            Raw ML-KEM-768 secret key bytes.

        Raises:
            RuntimeError: If the key is not configured or is malformed.
        """
        if self._source == "env":
            return self._get_from_env(election_id)
        # production: extend here
        raise RuntimeError(
            f"Key source {self._source!r} is not implemented; "
            "configure a vault backend for production use."
        )

    def _get_from_env(self, election_id: int) -> bytes:
        """Read ELECTION_KEM_SK_HEX_{election_id} from environment."""
        env_var = f"ELECTION_KEM_SK_HEX_{election_id}"
        hex_sk = os.environ.get(env_var)
        if not hex_sk:
            raise RuntimeError(
                f"Election KEM private key not configured. "
                f"Set environment variable {env_var} (hex-encoded bytes). "
                f"NEVER use this variable outside a development environment."
            )
        hex_sk = hex_sk.strip()
        try:
            sk_bytes = bytes.fromhex(hex_sk)
        except ValueError as exc:
            raise RuntimeError(
                f"ELECTION_KEM_SK_HEX_{election_id} is not valid hex"
            ) from exc
        # The ML-KEM-768 secret key is 2400 bytes per FIPS 203.
        # We accept any non-zero length to allow test keys; production
        # validation is enforced by liboqs during decapsulation.
        if len(sk_bytes) == 0:
            raise RuntimeError(
                f"ELECTION_KEM_SK_HEX_{election_id} is empty"
            )
        # DO NOT log sk_bytes or its length beyond a debug placeholder.
        logger.debug("ElectionKeyVault: loaded KEM SK for election %d [REDACTED]", election_id)
        return sk_bytes
