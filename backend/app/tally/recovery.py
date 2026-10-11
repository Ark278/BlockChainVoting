"""Ballot recovery service (Architecture v2.6 Stage 3 §16).

Implements:
  primary missing  → retrieve backup → verify commitment → restore primary
  primary corrupted → retrieve backup → verify commitment → restore primary

If the backup blob cannot be verified against the on-chain commitment,
a RecoveryError is raised and no restoration is performed.

This module is called by the TallyEngine during ballot retrieval when the
primary PostgreSQL record is missing or its commitment verification fails.
"""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING

from app.errors import RecoveryError
from app.services.crypto import compute_commitment
from app.tally.backup_storage import BallotBackupStorage

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.tally.audit_log import TallyAuditLog

logger = logging.getLogger("voting.tally.recovery")


class BallotRecovery:
    """Restore a primary ballot record from backup after verification.

    Args:
        backup_storage: Backup storage provider.
        session:        SQLAlchemy async session (used to restore DB record).
        audit_log:      Tally audit log.
    """

    def __init__(
        self,
        backup_storage: BallotBackupStorage,
        session: AsyncSession,
        audit_log: TallyAuditLog,
    ) -> None:
        self._backup = backup_storage
        self._session = session
        self._audit = audit_log

    async def recover(
        self,
        election_id: int,
        commitment_hash_hex: str,
        nullifier_hash_hex: str,
        on_chain_commitment_hash_b64: str,
    ) -> bytes:
        """Attempt to recover a ballot blob from backup.

        Flow:
            1. Read blob from backup storage.
            2. Decode commitment_hash and nullifier_hash from hex/base64.
            3. Recompute commitment hash from blob.
            4. Compare with on-chain commitment hash.
            5. If match: restore primary DB record and return blob.
            6. If mismatch: raise RecoveryError (do NOT restore).

        Args:
            election_id:                   On-chain election ID.
            commitment_hash_hex:           Hex-encoded commitment hash (used as backup key).
            nullifier_hash_hex:            Hex-encoded nullifier hash (for commitment recompute).
            on_chain_commitment_hash_b64:  Base64-encoded on-chain commitment hash.

        Returns:
            Verified BallotBlobV1 CBOR bytes.

        Raises:
            RecoveryError: If backup is missing or commitment mismatch.
        """
        # Step 1: Read from backup
        blob = self._backup.read(election_id, commitment_hash_hex)
        if blob is None:
            raise RecoveryError(
                f"Backup not found for election {election_id} "
                f"commitment {commitment_hash_hex}"
            )

        # Step 2: Decode hashes
        try:
            nullifier_hash_bytes = bytes.fromhex(nullifier_hash_hex)
        except ValueError as exc:
            raise RecoveryError(
                f"Invalid nullifier_hash_hex during recovery: {exc}"
            ) from exc

        try:
            on_chain_hash_bytes = base64.b64decode(on_chain_commitment_hash_b64)
        except Exception as exc:
            raise RecoveryError(
                f"Invalid on_chain_commitment_hash_b64 during recovery: {exc}"
            ) from exc

        # Step 3: Recompute commitment
        recomputed = compute_commitment(election_id, nullifier_hash_bytes, blob)

        # Step 4: Compare
        if recomputed != on_chain_hash_bytes:
            raise RecoveryError(
                f"Backup commitment mismatch for election {election_id} "
                f"commitment {commitment_hash_hex}: "
                "backup blob does not match on-chain commitment — not restored"
            )

        # Step 5: Restore primary DB record
        await self._restore_primary(
            election_id=election_id,
            commitment_hash_hex=commitment_hash_hex,
            nullifier_hash_hex=nullifier_hash_hex,
            on_chain_commitment_hash_b64=on_chain_commitment_hash_b64,
            ballot_blob=blob,
        )

        self._audit.record_recovered(election_id, commitment_hash_hex)
        logger.info(
            "BallotRecovery: restored primary for election=%d commitment=%s",
            election_id,
            commitment_hash_hex,
        )
        return blob

    async def _restore_primary(
        self,
        election_id: int,
        commitment_hash_hex: str,
        nullifier_hash_hex: str,
        on_chain_commitment_hash_b64: str,
        ballot_blob: bytes,
    ) -> None:
        """Insert or update the primary EncryptedBallot record."""
        from sqlalchemy import select  # noqa: PLC0415

        from app.models.ballot import BallotStatus, EncryptedBallot  # noqa: PLC0415

        commitment_hash_b64 = base64.b64encode(bytes.fromhex(commitment_hash_hex)).decode()
        nullifier_hash_b64 = base64.b64encode(bytes.fromhex(nullifier_hash_hex)).decode()

        result = await self._session.execute(
            select(EncryptedBallot).where(
                EncryptedBallot.commitment_hash == commitment_hash_b64
            )
        )
        existing = result.scalar_one_or_none()

        if existing is None:
            # Restore missing record
            import hashlib  # noqa: PLC0415

            from app.services.crypto import decode_ballot_blob  # noqa: PLC0415

            try:
                decoded = decode_ballot_blob(ballot_blob)
                kem_ct_hash_b64 = base64.b64encode(
                    hashlib.sha3_256(decoded["kem_ct"]).digest()
                ).decode()
            except Exception:  # noqa: BLE001
                kem_ct_hash_b64 = ""

            new_record = EncryptedBallot(
                election_id=election_id,
                nullifier_hash=nullifier_hash_b64,
                commitment_hash=commitment_hash_b64,
                ballot_blob=ballot_blob,
                kem_ct_hash=kem_ct_hash_b64,
                storage_status=BallotStatus.confirmed.value,
                error_message="Restored from backup during tally",
            )
            self._session.add(new_record)  # synchronous; do not await

        else:
            # Overwrite corrupted record only after commitment verification passed
            existing.ballot_blob = ballot_blob
            existing.storage_status = BallotStatus.confirmed.value
            existing.error_message = "Restored from backup during tally (commitment verified)"

        await self._session.flush()
