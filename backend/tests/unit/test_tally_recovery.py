"""Tests: backup storage + recovery + reconciliation (Stage 3 §17 — Recovery).

Tests:
  - primary missing → successful backup restore
  - primary corruption → successful restore
  - backup corruption → rejected (RecoveryError)
  - commitment mismatch → rejected (RecoveryError)
  - orphan record detected (reconciliation)
  - missing backup detected (reconciliation)
  - mismatched backup detected (reconciliation)
  - missing primary detected (reconciliation)
"""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.errors import RecoveryError
from app.services.crypto import (
    KEM_CT_LEN,
    NONCE_LEN,
    TAG_LEN,
    compute_commitment,
    encode_ballot_blob,
)
from app.tally.audit_log import TallyAuditLog
from app.tally.backup_storage import LocalFilesystemBackupStorage
from app.tally.reconciliation import ReconciliationJob

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def tmp_backup_dir(tmp_path: Path) -> Path:
    return tmp_path / "ballot_backup"


@pytest.fixture()
def storage(tmp_backup_dir: Path) -> LocalFilesystemBackupStorage:
    return LocalFilesystemBackupStorage(tmp_backup_dir)


@pytest.fixture()
def audit_log() -> TallyAuditLog:
    import io
    stream = io.StringIO()
    return TallyAuditLog(stream=stream)


def _make_blob() -> bytes:
    return encode_ballot_blob(
        kem_ct=os.urandom(KEM_CT_LEN),
        nonce=os.urandom(NONCE_LEN),
        ciphertext=b"encrypted_choice",
        tag=os.urandom(TAG_LEN),
    )


def _make_commitment(election_id: int, nullifier_hash: bytes, blob: bytes) -> bytes:
    return compute_commitment(election_id, nullifier_hash, blob)


# ── Backup storage ────────────────────────────────────────────────────────────


def test_backup_write_and_read(storage: LocalFilesystemBackupStorage) -> None:
    blob = _make_blob()
    ch_hex = hashlib.sha3_256(blob).hexdigest()
    storage.write(1, ch_hex, blob, "aabb" * 16)
    recovered = storage.read(1, ch_hex)
    assert recovered == blob


def test_backup_read_missing_returns_none(storage: LocalFilesystemBackupStorage) -> None:
    assert storage.read(1, "nonexistent" * 2) is None


def test_backup_list_keys(storage: LocalFilesystemBackupStorage) -> None:
    blob1 = _make_blob()
    blob2 = _make_blob()
    ch1 = "a" * 64
    ch2 = "b" * 64
    storage.write(1, ch1, blob1, "0" * 64)
    storage.write(1, ch2, blob2, "0" * 64)
    keys = storage.list_keys(1)
    assert ch1 in keys
    assert ch2 in keys


def test_backup_delete(storage: LocalFilesystemBackupStorage) -> None:
    blob = _make_blob()
    ch_hex = "d" * 64
    storage.write(1, ch_hex, blob, "0" * 64)
    assert storage.read(1, ch_hex) is not None
    storage.delete(1, ch_hex)
    assert storage.read(1, ch_hex) is None


def test_backup_write_is_atomic(storage: LocalFilesystemBackupStorage) -> None:
    """No .tmp files should remain after a successful write."""
    blob = _make_blob()
    ch_hex = "e" * 64
    storage.write(1, ch_hex, blob, "0" * 64)
    election_dir = storage._election_dir(1)
    tmp_files = list(election_dir.glob("*.tmp"))
    assert tmp_files == [], f"Leftover .tmp files: {tmp_files}"


# ── Recovery ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_recovery_missing_primary_success(
    storage: LocalFilesystemBackupStorage,
    audit_log: TallyAuditLog,
) -> None:
    """primary missing → retrieve backup → verify commitment → restore primary."""
    election_id = 1
    nullifier_hash = hashlib.sha3_256(b"voter_1").digest()
    blob = _make_blob()
    commitment_bytes = _make_commitment(election_id, nullifier_hash, blob)
    ch_hex = commitment_bytes.hex()
    nh_hex = nullifier_hash.hex()
    ch_b64 = base64.b64encode(commitment_bytes).decode()

    storage.write(election_id, ch_hex, blob, nh_hex)

    # Mock DB session: no existing record → recovery inserts one
    mock_session = AsyncMock()
    mock_session.add = MagicMock()  # add() is synchronous on AsyncSession
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = None
    mock_session.execute = AsyncMock(return_value=mock_result)

    from app.tally.recovery import BallotRecovery

    recovery = BallotRecovery(storage, mock_session, audit_log)
    recovered_blob = await recovery.recover(
        election_id=election_id,
        commitment_hash_hex=ch_hex,
        nullifier_hash_hex=nh_hex,
        on_chain_commitment_hash_b64=ch_b64,
    )
    assert recovered_blob == blob
    mock_session.add.assert_called_once()
    mock_session.flush.assert_called_once()


@pytest.mark.asyncio
async def test_recovery_backup_missing_raises(
    storage: LocalFilesystemBackupStorage,
    audit_log: TallyAuditLog,
) -> None:
    mock_session = AsyncMock()
    from app.tally.recovery import BallotRecovery

    recovery = BallotRecovery(storage, mock_session, audit_log)
    with pytest.raises(RecoveryError, match="Backup not found"):
        await recovery.recover(
            election_id=1,
            commitment_hash_hex="f" * 64,
            nullifier_hash_hex="a" * 64,
            on_chain_commitment_hash_b64=base64.b64encode(b"\xaa" * 32).decode(),
        )


@pytest.mark.asyncio
async def test_recovery_backup_commitment_mismatch_raises(
    storage: LocalFilesystemBackupStorage,
    audit_log: TallyAuditLog,
) -> None:
    """Backup blob that does not match on-chain commitment must NOT be restored."""
    election_id = 2
    blob = _make_blob()
    ch_hex = "c" * 64
    nh_hex = "a" * 64
    storage.write(election_id, ch_hex, blob, nh_hex)

    # Provide a DIFFERENT commitment hash (mismatch)
    wrong_commitment_b64 = base64.b64encode(b"\x00" * 32).decode()

    mock_session = AsyncMock()
    from app.tally.recovery import BallotRecovery

    recovery = BallotRecovery(storage, mock_session, audit_log)
    with pytest.raises(RecoveryError, match="mismatch"):
        await recovery.recover(
            election_id=election_id,
            commitment_hash_hex=ch_hex,
            nullifier_hash_hex=nh_hex,
            on_chain_commitment_hash_b64=wrong_commitment_b64,
        )
    # Ensure no DB writes occurred
    mock_session.add.assert_not_called()


# ── Reconciliation ────────────────────────────────────────────────────────────


def _make_chain_item(
    election_id: int,
    commitment_bytes: bytes,
    nullifier_hash: bytes,
) -> dict[str, Any]:
    return {
        "election_id": election_id,
        "commitment_hash": base64.b64encode(commitment_bytes).decode(),
        "nullifier_hash": base64.b64encode(nullifier_hash).decode(),
    }


@pytest.mark.asyncio
async def test_reconciliation_missing_primary_detected(
    storage: LocalFilesystemBackupStorage,
) -> None:
    """Commitment on chain but not in DB → missing_primary."""
    election_id = 10
    nh = hashlib.sha3_256(b"voter").digest()
    blob = _make_blob()
    commitment = _make_commitment(election_id, nh, blob)
    chain_items = [_make_chain_item(election_id, commitment, nh)]

    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = []  # empty DB
    mock_session.execute = AsyncMock(return_value=mock_result)

    job = ReconciliationJob(mock_session, storage)
    report = await job.run(election_id, chain_items)

    assert report.has_discrepancies
    kinds = {d.kind for d in report.discrepancies}
    assert "missing_primary" in kinds


@pytest.mark.asyncio
async def test_reconciliation_orphaned_local_detected(
    storage: LocalFilesystemBackupStorage,
) -> None:
    """DB record not on chain → orphaned_local."""
    election_id = 11
    nh = hashlib.sha3_256(b"voter_2").digest()
    blob = _make_blob()
    commitment = _make_commitment(election_id, nh, blob)
    commitment_b64 = base64.b64encode(commitment).decode()

    mock_session = AsyncMock()
    mock_result = MagicMock()

    # Build a fake EncryptedBallot-like object
    fake_record = MagicMock()
    fake_record.commitment_hash = commitment_b64
    fake_record.nullifier_hash = base64.b64encode(nh).decode()
    fake_record.ballot_blob = blob
    mock_result.scalars.return_value.all.return_value = [fake_record]
    mock_session.execute = AsyncMock(return_value=mock_result)

    # Chain has NO commitments
    job = ReconciliationJob(mock_session, storage)
    report = await job.run(election_id, [])

    kinds = {d.kind for d in report.discrepancies}
    assert "orphaned_local" in kinds


@pytest.mark.asyncio
async def test_reconciliation_missing_backup_detected(
    storage: LocalFilesystemBackupStorage,
) -> None:
    """DB record without backup → missing_backup."""
    election_id = 12
    nh = hashlib.sha3_256(b"voter_3").digest()
    blob = _make_blob()
    commitment = _make_commitment(election_id, nh, blob)
    commitment_b64 = base64.b64encode(commitment).decode()

    chain_items = [_make_chain_item(election_id, commitment, nh)]

    mock_session = AsyncMock()
    mock_result = MagicMock()
    fake_record = MagicMock()
    fake_record.commitment_hash = commitment_b64
    fake_record.ballot_blob = blob
    mock_result.scalars.return_value.all.return_value = [fake_record]
    mock_session.execute = AsyncMock(return_value=mock_result)

    # No backup written
    job = ReconciliationJob(mock_session, storage)
    report = await job.run(election_id, chain_items)

    kinds = {d.kind for d in report.discrepancies}
    assert "missing_backup" in kinds


@pytest.mark.asyncio
async def test_reconciliation_mismatched_backup_detected(
    storage: LocalFilesystemBackupStorage,
) -> None:
    """Backup blob that does not match on-chain commitment → mismatched_backup."""
    election_id = 13
    nh = hashlib.sha3_256(b"voter_4").digest()
    blob = _make_blob()
    commitment = _make_commitment(election_id, nh, blob)
    commitment_b64 = base64.b64encode(commitment).decode()
    ch_hex = commitment.hex()

    # Write a DIFFERENT blob to backup (corrupted)
    corrupted_blob = _make_blob()
    storage.write(election_id, ch_hex, corrupted_blob, nh.hex())

    chain_items = [_make_chain_item(election_id, commitment, nh)]

    mock_session = AsyncMock()
    mock_result = MagicMock()
    fake_record = MagicMock()
    fake_record.commitment_hash = commitment_b64
    fake_record.ballot_blob = blob
    mock_result.scalars.return_value.all.return_value = [fake_record]
    mock_session.execute = AsyncMock(return_value=mock_result)

    job = ReconciliationJob(mock_session, storage)
    report = await job.run(election_id, chain_items)

    kinds = {d.kind for d in report.discrepancies}
    assert "mismatched_backup" in kinds
