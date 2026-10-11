"""Off-chain revocation service (Architecture v2.6 §4).

Revocation in v2.6 is explicitly an off-chain trusted control.
The CosmWasm contract does NOT implement revocation logic.

Revocation is enforced HERE, before nullifier derivation:
    ML-DSA verification → revocation check → nullifier derivation

Architecture note: FastAPI is a trusted intermediary; this is documented clearly.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Credential


class RevocationRepository:
    """Data-access layer for credential revocation status.

    IMPORTANT: This is a trusted off-chain control. The blockchain does not
    enforce revocation. Revocation is effective only if all ballot submission
    paths run through this service.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def is_revoked(self, credential_id: str) -> bool:
        """Return True if the credential has been revoked."""
        result = await self._session.execute(
            select(Credential.revoked).where(Credential.credential_id == credential_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False  # Unknown credential — let credential verification handle it
        return bool(row)

    async def revoke(
        self,
        credential_id: str,
        reason: str | None = None,
        revoked_at: datetime | None = None,
    ) -> bool:
        """Revoke a credential. Returns True if the credential was found and revoked.

        This is an admin operation. It must not be exposed via the public ballot API.
        """
        if revoked_at is None:
            revoked_at = datetime.now(UTC)
        result = await self._session.execute(
            update(Credential)
            .where(Credential.credential_id == credential_id, Credential.revoked.is_(False))
            .values(revoked=True, revoked_at=revoked_at, revoked_reason=reason)
            .returning(Credential.credential_id)
        )
        return result.scalar_one_or_none() is not None

    async def get_credential_record(self, credential_id: str) -> Credential | None:
        result = await self._session.execute(
            select(Credential).where(Credential.credential_id == credential_id)
        )
        return result.scalar_one_or_none()

    async def store_credential(
        self,
        credential_id: str,
        credential_payload: bytes,
        signature: bytes,
        issuer_key_id: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> Credential:
        """Store a verified credential record for future revocation tracking."""
        cred = Credential(
            credential_id=credential_id,
            credential_payload=credential_payload,
            signature=signature,
            issuer_key_id=issuer_key_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        self._session.add(cred)
        await self._session.flush()
        return cred
