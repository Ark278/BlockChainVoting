"""Durable encrypted ballot backup storage (Architecture v2.6 Stage 3 §14).

Defines the BallotBackupStorage protocol and a LocalFilesystemBackupStorage
implementation suitable for development and single-node deployments.

Storage model:
  - One binary file per ballot: {root}/{election_id}/{commitment_hash_hex}.bin
    Contains the raw BallotBlobV1 CBOR bytes (encrypted; no plaintext).
  - One JSON sidecar per ballot: {root}/{election_id}/{commitment_hash_hex}.meta.json
    Contains reconciliation metadata (election_id, commitment_hash_hex,
    nullifier_hash_hex, backed_up_at).
  - Writes are atomic: data written to a .tmp file then renamed.
  - Never stores plaintext ballot choices.
  - Read returns None if the file does not exist.

To use a different backend (S3, GCS, etc.) in production, implement the
BallotBackupStorage protocol and inject it into the services that use it.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from app.errors import BackupError


@runtime_checkable
class BallotBackupStorage(Protocol):
    """Protocol for durable encrypted ballot backup storage."""

    def write(
        self,
        election_id: int,
        commitment_hash_hex: str,
        ballot_blob: bytes,
        nullifier_hash_hex: str,
    ) -> None:
        """Write a BallotBlobV1 to backup storage.

        Args:
            election_id:         On-chain election identifier.
            commitment_hash_hex: Hex-encoded commitment hash (used as key).
            ballot_blob:         Raw BallotBlobV1 CBOR bytes.
            nullifier_hash_hex:  Hex-encoded nullifier hash (for metadata).

        Raises:
            BackupError: If the write fails.
        """
        ...

    def read(
        self,
        election_id: int,
        commitment_hash_hex: str,
    ) -> bytes | None:
        """Read a BallotBlobV1 from backup storage.

        Returns:
            Raw BallotBlobV1 CBOR bytes, or None if not found.

        Raises:
            BackupError: If the read fails for an unexpected reason.
        """
        ...

    def delete(
        self,
        election_id: int,
        commitment_hash_hex: str,
    ) -> None:
        """Delete a backup record (used in tests; never called during tally)."""
        ...

    def list_keys(self, election_id: int) -> list[str]:
        """List all commitment_hash_hex keys for an election.

        Returns:
            List of hex-encoded commitment hash strings.
        """
        ...


class LocalFilesystemBackupStorage:
    """Local filesystem implementation of BallotBackupStorage.

    Suitable for development and testing.  In production replace with an
    object-storage implementation (S3, GCS) implementing the same protocol.
    """

    def __init__(self, root_path: str | Path) -> None:
        self._root = Path(root_path)

    def _election_dir(self, election_id: int) -> Path:
        return self._root / str(election_id)

    def _blob_path(self, election_id: int, commitment_hash_hex: str) -> Path:
        return self._election_dir(election_id) / f"{commitment_hash_hex}.bin"

    def _meta_path(self, election_id: int, commitment_hash_hex: str) -> Path:
        return self._election_dir(election_id) / f"{commitment_hash_hex}.meta.json"

    def write(
        self,
        election_id: int,
        commitment_hash_hex: str,
        ballot_blob: bytes,
        nullifier_hash_hex: str,
    ) -> None:
        """Atomic write: blob to .tmp then rename to final path."""
        try:
            election_dir = self._election_dir(election_id)
            election_dir.mkdir(parents=True, exist_ok=True)

            blob_path = self._blob_path(election_id, commitment_hash_hex)
            tmp_path = blob_path.with_suffix(".bin.tmp")

            # Atomic blob write
            tmp_path.write_bytes(ballot_blob)
            tmp_path.rename(blob_path)

            # Sidecar metadata (no plaintext)
            meta = {
                "election_id": election_id,
                "commitment_hash_hex": commitment_hash_hex,
                "nullifier_hash_hex": nullifier_hash_hex,
                "blob_sha3_256": hashlib.sha3_256(ballot_blob).hexdigest(),
                "backed_up_at": datetime.now(UTC).isoformat(),
            }
            meta_path = self._meta_path(election_id, commitment_hash_hex)
            tmp_meta = meta_path.with_suffix(".json.tmp")
            tmp_meta.write_text(
                json.dumps(meta, indent=None, separators=(",", ":")), encoding="utf-8"
            )
            tmp_meta.rename(meta_path)
        except OSError as exc:
            raise BackupError(f"Backup write failed for {commitment_hash_hex}: {exc}") from exc

    def read(
        self,
        election_id: int,
        commitment_hash_hex: str,
    ) -> bytes | None:
        """Return blob bytes or None if not present."""
        try:
            blob_path = self._blob_path(election_id, commitment_hash_hex)
            if not blob_path.exists():
                return None
            return blob_path.read_bytes()
        except OSError as exc:
            raise BackupError(
                f"Backup read failed for {commitment_hash_hex}: {exc}"
            ) from exc

    def read_metadata(
        self,
        election_id: int,
        commitment_hash_hex: str,
    ) -> dict | None:
        """Return sidecar metadata dict or None if not present."""
        try:
            meta_path = self._meta_path(election_id, commitment_hash_hex)
            if not meta_path.exists():
                return None
            return json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BackupError(
                f"Backup metadata read failed for {commitment_hash_hex}: {exc}"
            ) from exc

    def delete(
        self,
        election_id: int,
        commitment_hash_hex: str,
    ) -> None:
        """Delete blob and metadata files if they exist."""
        try:
            blob_path = self._blob_path(election_id, commitment_hash_hex)
            meta_path = self._meta_path(election_id, commitment_hash_hex)
            if blob_path.exists():
                blob_path.unlink()
            if meta_path.exists():
                meta_path.unlink()
        except OSError as exc:
            raise BackupError(
                f"Backup delete failed for {commitment_hash_hex}: {exc}"
            ) from exc

    def list_keys(self, election_id: int) -> list[str]:
        """Return sorted list of commitment_hash_hex strings for the election."""
        election_dir = self._election_dir(election_id)
        if not election_dir.exists():
            return []
        keys: list[str] = []
        for entry in os.scandir(election_dir):
            if entry.name.endswith(".bin") and entry.is_file():
                # Strip the .bin extension to get commitment_hash_hex
                keys.append(entry.name[:-4])
        return sorted(keys)


def make_backup_storage(root_path: str | Path) -> LocalFilesystemBackupStorage:
    """Factory: create a LocalFilesystemBackupStorage rooted at root_path."""
    return LocalFilesystemBackupStorage(root_path)
