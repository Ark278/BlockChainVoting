"""Tally audit log (Architecture v2.6 Stage 3 §11).

Append-only structured event log for the tally process.

Each event is a JSON-lines record written to a file.  Events are categorized
as: integrity_failure, decryption_failure, invalid_ballot, unrecoverable,
recovered, valid_ballot.

Security invariants:
  - NEVER logs: nullifier hashes, private keys, shared secrets, AES keys,
    or plaintext ballot choices.
  - commitment_hash_hex (a public hash) may be logged for cross-referencing.
  - No voter identity information is logged.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, TextIO

logger = logging.getLogger("voting.tally.audit")

_EVENT_INTEGRITY_FAILURE = "integrity_failure"
_EVENT_DECRYPTION_FAILURE = "decryption_failure"
_EVENT_INVALID_BALLOT = "invalid_ballot"
_EVENT_UNRECOVERABLE = "unrecoverable"
_EVENT_RECOVERED = "recovered"
_EVENT_VALID_BALLOT = "valid_ballot"
_EVENT_TALLY_STARTED = "tally_started"
_EVENT_TALLY_COMPLETED = "tally_completed"
_EVENT_TALLY_FAILED = "tally_failed"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class TallyAuditLog:
    """Append-only structured tally event log.

    Each call to a record_* method appends a single JSON line to the output
    stream.  The default stream is stderr; pass a file path to write to disk.

    Usage:
        with TallyAuditLog.open(Path("tally_audit.jsonl")) as audit:
            audit.record_valid_ballot(1, "abcdef...")
    """

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream: TextIO = stream if stream is not None else sys.stderr

    @classmethod
    def open(cls, path: Path) -> TallyAuditLog:
        """Open a file-backed audit log (append mode)."""
        path.parent.mkdir(parents=True, exist_ok=True)
        stream: IO[str] = path.open("a", encoding="utf-8")
        return cls(stream=stream)  # type: ignore[arg-type]

    def _emit(self, event_type: str, election_id: int, **extra: object) -> None:
        """Append a single JSON event record to the stream."""
        record: dict = {
            "event": event_type,
            "election_id": election_id,
            "ts": _now_iso(),
        }
        # Never include: nullifier_hash, private_key, shared_secret, aes_key,
        # plaintext, or any voter-identifying field.
        record.update({k: v for k, v in extra.items()})
        try:
            line = json.dumps(record, separators=(",", ":"))
            self._stream.write(line + "\n")
            self._stream.flush()
        except Exception as exc:  # noqa: BLE001
            # Audit log failure must never abort the tally.
            logger.warning("TallyAuditLog: failed to write event %r: %s", event_type, exc)

    def record_tally_started(self, election_id: int) -> None:
        self._emit(_EVENT_TALLY_STARTED, election_id)

    def record_tally_completed(
        self,
        election_id: int,
        total_commitments: int,
        valid_ballots: int,
        invalid_ballots: int,
        integrity_failures: int,
        decryption_failures: int,
        recovered_ballots: int,
        result_commitment_hex: str,
    ) -> None:
        self._emit(
            _EVENT_TALLY_COMPLETED,
            election_id,
            total_commitments=total_commitments,
            valid_ballots=valid_ballots,
            invalid_ballots=invalid_ballots,
            integrity_failures=integrity_failures,
            decryption_failures=decryption_failures,
            recovered_ballots=recovered_ballots,
            result_commitment_hex=result_commitment_hex,
        )

    def record_tally_failed(self, election_id: int, reason: str) -> None:
        self._emit(_EVENT_TALLY_FAILED, election_id, reason=reason)

    def record_integrity_failure(
        self,
        election_id: int,
        commitment_hash_hex: str,
        reason: str,
    ) -> None:
        """Record a commitment hash mismatch or structural validation failure."""
        self._emit(
            _EVENT_INTEGRITY_FAILURE,
            election_id,
            commitment_hash_hex=commitment_hash_hex,
            reason=reason,
        )

    def record_decryption_failure(
        self,
        election_id: int,
        commitment_hash_hex: str,
        reason: str,
    ) -> None:
        """Record a KEM decapsulation or AES-GCM authentication failure."""
        self._emit(
            _EVENT_DECRYPTION_FAILURE,
            election_id,
            commitment_hash_hex=commitment_hash_hex,
            reason=reason,
        )

    def record_invalid_ballot(
        self,
        election_id: int,
        commitment_hash_hex: str,
        reason: str,
    ) -> None:
        """Record a ballot that decrypted but failed payload validation."""
        self._emit(
            _EVENT_INVALID_BALLOT,
            election_id,
            commitment_hash_hex=commitment_hash_hex,
            reason=reason,
        )

    def record_unrecoverable(
        self,
        election_id: int,
        commitment_hash_hex: str,
        reason: str,
    ) -> None:
        """Record a ballot that could not be retrieved from either source."""
        self._emit(
            _EVENT_UNRECOVERABLE,
            election_id,
            commitment_hash_hex=commitment_hash_hex,
            reason=reason,
        )

    def record_recovered(
        self,
        election_id: int,
        commitment_hash_hex: str,
    ) -> None:
        """Record a successful backup recovery."""
        self._emit(_EVENT_RECOVERED, election_id, commitment_hash_hex=commitment_hash_hex)

    def record_valid_ballot(
        self,
        election_id: int,
        commitment_hash_hex: str,
    ) -> None:
        """Record a ballot that passed all checks and was counted."""
        self._emit(_EVENT_VALID_BALLOT, election_id, commitment_hash_hex=commitment_hash_hex)

    def close(self) -> None:
        """Flush and close the underlying stream if it is not stderr."""
        try:
            if self._stream is not sys.stderr:
                self._stream.flush()
                self._stream.close()
        except Exception:  # noqa: BLE001
            pass

    def __enter__(self) -> TallyAuditLog:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
