"""Server bucket secret manager (Architecture v2.6 Stage 4 §2).

Provides the current `server_bucket_secret` bytes to the telemetry service.

Security invariants:
  - The secret is NEVER logged or persisted (only loaded from config/env).
  - In development: read from `settings.server_bucket_secret_hex` (static).
  - In production: extend `_get_current_secret()` to fetch from an HSM or
    secrets manager keyed by `hour_ts = floor(unix_now / 3600) * 3600`.
  - The caller MUST discard the returned bytes after use; never cache them
    beyond the scope of one telemetry request.

Hour boundary:
  `hour_ts` = floor(current UTC unix timestamp / 3600) * 3600
  The same secret must be returned for all calls within the same UTC hour
  and a different secret for a different UTC hour (in production).
"""

from __future__ import annotations

import logging
import math
import time

from app.config import Settings, get_settings

logger = logging.getLogger("voting.ai.bucket_secret")


class ServerBucketSecretManager:
    """Manages the hourly-rotating server bucket secret.

    Args:
        settings: Application settings (injected for testability).
    """

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()

    def current_hour_ts(self) -> int:
        """Return the UTC hour boundary for the current time.

        Example: 13:47 UTC → 13:00 UTC expressed as unix timestamp.
        This is used to scope bucket IDs to hourly windows.
        """
        now = int(time.time())
        return math.floor(now / 3600) * 3600

    def get_secret(self) -> bytes:
        """Return the current server bucket secret bytes.

        The returned value MUST be used only for HMAC computation and then
        discarded.  It must NEVER be logged, returned to clients, or stored.

        Returns:
            32-byte server bucket secret.

        Raises:
            RuntimeError: If the secret is misconfigured.
        """
        return self._get_current_secret()

    def _get_current_secret(self) -> bytes:
        """Load secret from configuration (dev) or extend for production vault."""
        hex_secret = self._settings.server_bucket_secret_hex
        if not hex_secret:
            raise RuntimeError(
                "server_bucket_secret_hex is not configured. "
                "Set SERVER_BUCKET_SECRET_HEX env var. "
                "NEVER use a weak secret in production."
            )
        try:
            secret_bytes = bytes.fromhex(hex_secret.strip())
        except ValueError as exc:
            raise RuntimeError(
                "SERVER_BUCKET_SECRET_HEX is not valid hex"
            ) from exc
        if len(secret_bytes) < 16:
            raise RuntimeError(
                "server_bucket_secret must be at least 16 bytes (32 hex chars)"
            )
        # DO NOT log secret bytes
        logger.debug("ServerBucketSecretManager: secret loaded [REDACTED]")
        return secret_bytes
