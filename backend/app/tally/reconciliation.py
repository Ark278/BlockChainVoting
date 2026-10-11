"""Reconciliation job (Architecture v2.6 Stage 3 §15).

Compares three sources of truth:
  1. PostgreSQL encrypted_ballots
  2. Local backup storage
  3. On-chain commitment registry

Detects:
  missing_primary       — commitment in backup/chain but NOT in DB
  missing_backup        — commitment in DB but NOT in backup
  mismatched_backup     — backup blob re-hashes to wrong commitment
  commitment_mismatch   — DB blob re-hashes to wrong on-chain commitment
  orphaned_local        — DB record not referenced on-chain

Produces a deterministic ReconciliationReport.
Never silently overwrites conflicting copies.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from app.services.crypto import compute_commitment
from app.tally.backup_storage import BallotBackupStorage

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("voting.tally.reconciliation")


@dataclass
class ReconciliationDiscrepancy:
    """A single discrepancy found during reconciliation."""

    kind: str                    # One of the five discrepancy types
    election_id: int
    commitment_hash_hex: str
    detail: str                  # Human-readable description


@dataclass
class ReconciliationReport:
    """Result of a reconciliation run."""

    election_id: int
    total_chain_commitments: int = 0
    total_db_records: int = 0
    total_backup_keys: int = 0
    discrepancies: list[ReconciliationDiscrepancy] = field(default_factory=list)

    @property
    def has_discrepancies(self) -> bool:
        return bool(self.discrepancies)

    def by_kind(self, kind: str) -> list[ReconciliationDiscrepancy]:
        return [d for d in self.discrepancies if d.kind == kind]


class ReconciliationJob:
    """Three-way reconciliation of ballots across chain, DB, and backup.

    Args:
        session:        SQLAlchemy async session for DB queries.
        backup_storage: Backup storage provider.
    """

    def __init__(
        self,
        session: AsyncSession,
        backup_storage: BallotBackupStorage,
    ) -> None:
        self._session = session
        self._backup = backup_storage

    async def run(
        self,
        election_id: int,
        chain_commitments: list[dict[str, Any]],
    ) -> ReconciliationReport:
        """Execute the reconciliation job.

        Args:
            election_id:       On-chain election identifier.
            chain_commitments: List of dicts from blockchain.list_ballot_commitments(),
                               each having: commitment_hash (b64), nullifier_hash (b64).

        Returns:
            ReconciliationReport with all detected discrepancies.
        """
        report = ReconciliationReport(election_id=election_id)
        report.total_chain_commitments = len(chain_commitments)

        # Build lookup sets
        chain_by_hex: dict[str, dict[str, Any]] = {}
        for item in chain_commitments:
            ch_bytes = base64.b64decode(item["commitment_hash"])
            ch_hex = ch_bytes.hex()
            chain_by_hex[ch_hex] = item

        # Fetch all DB records for this election
        from sqlalchemy import select  # noqa: PLC0415

        from app.models.ballot import EncryptedBallot  # noqa: PLC0415

        result = await self._session.execute(
            select(EncryptedBallot).where(EncryptedBallot.election_id == election_id)
        )
        db_records = result.scalars().all()
        report.total_db_records = len(db_records)

        db_by_hex: dict[str, EncryptedBallot] = {}
        for rec in db_records:
            ch_bytes = base64.b64decode(rec.commitment_hash)
            ch_hex = ch_bytes.hex()
            db_by_hex[ch_hex] = rec

        # Backup keys
        backup_keys = set(self._backup.list_keys(election_id))
        report.total_backup_keys = len(backup_keys)

        # --- Check 1: missing_primary ---
        # On chain but not in DB
        for ch_hex in chain_by_hex:
            if ch_hex not in db_by_hex:
                report.discrepancies.append(
                    ReconciliationDiscrepancy(
                        kind="missing_primary",
                        election_id=election_id,
                        commitment_hash_hex=ch_hex,
                        detail="Commitment registered on-chain but not found in primary DB",
                    )
                )

        # --- Check 2: orphaned_local ---
        # In DB but not on chain
        for ch_hex in db_by_hex:
            if ch_hex not in chain_by_hex:
                report.discrepancies.append(
                    ReconciliationDiscrepancy(
                        kind="orphaned_local",
                        election_id=election_id,
                        commitment_hash_hex=ch_hex,
                        detail="DB record not referenced by any on-chain commitment",
                    )
                )

        # --- Check 3: missing_backup ---
        # In DB but not in backup
        for ch_hex in db_by_hex:
            if ch_hex not in backup_keys:
                report.discrepancies.append(
                    ReconciliationDiscrepancy(
                        kind="missing_backup",
                        election_id=election_id,
                        commitment_hash_hex=ch_hex,
                        detail="DB record exists but no backup copy found",
                    )
                )

        # --- Check 4: commitment_mismatch (DB blob vs on-chain) ---
        for ch_hex, rec in db_by_hex.items():
            if ch_hex not in chain_by_hex:
                continue  # Already flagged as orphaned
            chain_item = chain_by_hex[ch_hex]
            nullifier_hash_bytes = base64.b64decode(chain_item["nullifier_hash"])
            on_chain_commitment_bytes = base64.b64decode(chain_item["commitment_hash"])
            try:
                recomputed = compute_commitment(
                    election_id, nullifier_hash_bytes, rec.ballot_blob
                )
                if recomputed != on_chain_commitment_bytes:
                    report.discrepancies.append(
                        ReconciliationDiscrepancy(
                            kind="commitment_mismatch",
                            election_id=election_id,
                            commitment_hash_hex=ch_hex,
                            detail="DB blob recomputed commitment does not match on-chain value",
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                report.discrepancies.append(
                    ReconciliationDiscrepancy(
                        kind="commitment_mismatch",
                        election_id=election_id,
                        commitment_hash_hex=ch_hex,
                        detail=f"Commitment recompute failed: {exc}",
                    )
                )

        # --- Check 5: mismatched_backup ---
        # Backup blob re-hashes to wrong commitment
        for ch_hex in backup_keys:
            if ch_hex not in chain_by_hex:
                continue  # Only check backups for chain-registered commitments
            chain_item = chain_by_hex[ch_hex]
            nullifier_hash_bytes = base64.b64decode(chain_item["nullifier_hash"])
            on_chain_commitment_bytes = base64.b64decode(chain_item["commitment_hash"])
            try:
                backup_blob = self._backup.read(election_id, ch_hex)
                if backup_blob is None:
                    continue  # Gone between list and read; harmless race
                recomputed = compute_commitment(
                    election_id, nullifier_hash_bytes, backup_blob
                )
                if recomputed != on_chain_commitment_bytes:
                    report.discrepancies.append(
                        ReconciliationDiscrepancy(
                            kind="mismatched_backup",
                            election_id=election_id,
                            commitment_hash_hex=ch_hex,
                            detail=(
                                "Backup blob recomputed commitment does not match "
                                "on-chain value; backup may be corrupted"
                            ),
                        )
                    )
            except Exception as exc:  # noqa: BLE001
                report.discrepancies.append(
                    ReconciliationDiscrepancy(
                        kind="mismatched_backup",
                        election_id=election_id,
                        commitment_hash_hex=ch_hex,
                        detail=f"Backup commitment recompute failed: {exc}",
                    )
                )

        logger.info(
            "ReconciliationJob: election=%d chain=%d db=%d backup=%d discrepancies=%d",
            election_id,
            report.total_chain_commitments,
            report.total_db_records,
            report.total_backup_keys,
            len(report.discrepancies),
        )
        return report
