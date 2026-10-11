"""PostgreSQL-backed idempotency service (Architecture v2.6 §11).

Rules:
  - Same idempotency_key + same request_fingerprint → return stored response.
  - Same idempotency_key + different request_fingerprint → IdempotencyConflict.
  - Expired records are ignored (treated as new requests).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.errors import IdempotencyConflictError
from app.models import IdempotencyRecord


def _fingerprint(request_body: bytes) -> str:
    """SHA-256 hex digest of the canonical request body."""
    return hashlib.sha256(request_body).hexdigest()


class IdempotencyService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._ttl = timedelta(seconds=get_settings().idempotency_ttl_seconds)

    async def check(
        self,
        idempotency_key: str,
        request_body: bytes,
    ) -> IdempotencyRecord | None:
        """Check for an existing idempotency record.

        Returns:
            Existing record if found and valid (not expired).
            None if no record found (proceed with request).

        Raises:
            IdempotencyConflictError: Same key, different fingerprint.
        """
        now = datetime.now(UTC)
        result = await self._session.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.idempotency_key == idempotency_key,
                IdempotencyRecord.expires_at > now,
            )
        )
        record = result.scalar_one_or_none()
        if record is None:
            return None

        fp = _fingerprint(request_body)
        if record.request_fingerprint != fp:
            raise IdempotencyConflictError(
                f"Idempotency key '{idempotency_key}' was used with a different request body"
            )
        return record

    async def store(
        self,
        idempotency_key: str,
        request_body: bytes,
        response_reference: str,
        response_status_code: int,
        response_body: dict,
    ) -> IdempotencyRecord:
        """Store a new idempotency record after a successful response."""
        now = datetime.now(UTC)
        record = IdempotencyRecord(
            idempotency_key=idempotency_key,
            request_fingerprint=_fingerprint(request_body),
            response_reference=response_reference,
            response_status_code=response_status_code,
            response_body=json.dumps(response_body).encode(),
            created_at=now,
            expires_at=now + self._ttl,
        )
        self._session.add(record)
        try:
            await self._session.flush()
        except IntegrityError as exc:
            await self._session.rollback()
            # Race condition: another request inserted the same key
            raise IdempotencyConflictError(
                f"Idempotency key '{idempotency_key}' conflict during concurrent insert"
            ) from exc
        return record

    async def purge_expired(self) -> int:
        """Delete expired idempotency records. Returns number deleted."""
        now = datetime.now(UTC)
        result = await self._session.execute(
            delete(IdempotencyRecord).where(IdempotencyRecord.expires_at <= now)
        )
        return result.rowcount or 0
