"""Tally engine (Architecture v2.6 Stage 3 §8–13).

Implements the complete off-chain tally lifecycle:

    TALLYING state confirmed
        ↓
    Paginated ballot retrieval from blockchain
        ↓
    Per-ballot:
        lookup in PostgreSQL
        → if missing/corrupted: try backup recovery
        → validate BallotBlobV1 structure
        → verify commitment hash (on-chain vs recomputed)
        → ML-KEM-768 decapsulation → shared_secret
        → HKDF-SHA3-256 → aes_key
        → reconstruct AAD
        → AES-256-GCM decryption
        → validate ballot payload schema
        → count valid ballot
        ↓
    Deterministic tally (integer arithmetic, sorted option keys)
        ↓
    Canonical result serialization (sorted JSON, no timestamps)
        ↓
    SHA3-256(canonical_bytes) → result_commitment
        ↓
    Publish result_commitment to CosmWasm contract
        ↓
    Persist TallyRun record

Security invariants:
  - KEM private key is fetched once per ballot via ElectionKeyVault;
    it is discarded from local scope immediately after decapsulation.
  - shared_secret and aes_key are never returned, logged, or stored.
  - Plaintext ballot bytes are validated in memory and discarded.
  - Nullifier hashes come from the blockchain query response, not from
    PostgreSQL (per architecture requirement).
  - Commitment verification is enforced before decryption on every ballot.
  - Recovery path re-runs the same commitment check.

Result serialization (canonical):
    {
      "election_id":         <int>,
      "tally_schema_version": 1,
      "results":             {"<option>": <int>, ...},   ← sorted by key
      "valid_ballots":       <int>,
      "invalid_ballots":     <int>,
      "integrity_failures":  <int>,
      "decryption_failures": <int>,
      "recovered_ballots":   <int>
    }
    Keys are sorted lexicographically.
    `generated_at` / `completed_at` are NOT included (would break determinism).
    result_commitment = SHA3-256(canonical_bytes).
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from app.errors import (
    BallotBlobValidationError,
    CommitmentMismatchError,
    DecryptionFailureError,
    InvalidBallotPayloadError,
    RecoveryError,
    TallyStateError,
)
from app.services.crypto import (
    aes_gcm_decrypt,
    build_aad,
    compute_commitment,
    derive_aes_key,
    kem_decapsulate,
)
from app.tally.audit_log import TallyAuditLog
from app.tally.backup_storage import BallotBackupStorage
from app.tally.ballot_payload import validate_ballot_payload
from app.tally.blob_validator import validate_ballot_blob_v1
from app.tally.key_vault import ElectionKeyVault
from app.tally.recovery import BallotRecovery

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.services.blockchain import BlockchainClient

logger = logging.getLogger("voting.tally.engine")

TALLY_RESULT_SCHEMA_VERSION = 1
_EXPECTED_TALLYING_STATE = "Tallying"


@dataclass
class TallyCounters:
    """Mutable audit counters accumulated during a tally run."""

    total_commitments: int = 0
    recovered_ballots: int = 0
    integrity_failures: int = 0
    decryption_failures: int = 0
    invalid_ballots: int = 0
    valid_ballots: int = 0


@dataclass
class TallyResult:
    """Immutable, fully computed tally result."""

    election_id: int
    results: dict[str, int]          # option → vote count (sorted)
    counters: TallyCounters
    canonical_bytes: bytes            # exact bytes fed to SHA3-256
    result_commitment: bytes          # SHA3-256(canonical_bytes), 32 bytes
    result_commitment_hex: str
    result_commitment_b64: str
    completed_at: datetime            # operational metadata only


def _serialize_canonical_result(
    election_id: int,
    results: dict[str, int],
    counters: TallyCounters,
) -> bytes:
    """Build the canonical, deterministic tally result bytes.

    The result object contains only election-result data.
    `generated_at` / `completed_at` are deliberately excluded so that
    identical ballots always produce identical canonical bytes and
    identical result_commitment.

    Returns:
        UTF-8 JSON bytes with sorted keys and no extra whitespace.
    """
    # Sort option keys deterministically.
    sorted_results = {k: results[k] for k in sorted(results)}

    result_obj: dict[str, Any] = {
        "decryption_failures": counters.decryption_failures,
        "election_id": election_id,
        "integrity_failures": counters.integrity_failures,
        "invalid_ballots": counters.invalid_ballots,
        "recovered_ballots": counters.recovered_ballots,
        "results": sorted_results,
        "tally_schema_version": TALLY_RESULT_SCHEMA_VERSION,
        "valid_ballots": counters.valid_ballots,
    }
    # sort_keys=True guarantees deterministic key order regardless of insertion order.
    return json.dumps(result_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _compute_result_commitment(canonical_bytes: bytes) -> bytes:
    """SHA3-256(canonical_bytes) → 32-byte result_commitment."""
    return hashlib.sha3_256(canonical_bytes).digest()


class TallyEngine:
    """Off-chain tally orchestrator.

    Args:
        session:         SQLAlchemy async session for DB reads/writes.
        blockchain:      Typed CosmWasm blockchain client.
        backup_storage:  Durable ballot backup provider.
        key_vault:       Election KEM private key provider.
        audit_log:       Append-only tally audit log.
        allowed_options: Frozenset of valid ballot option identifiers.
        page_size:       Number of commitments to fetch per blockchain page.
    """

    def __init__(
        self,
        session: AsyncSession,
        blockchain: BlockchainClient,
        backup_storage: BallotBackupStorage,
        key_vault: ElectionKeyVault,
        audit_log: TallyAuditLog,
        allowed_options: frozenset[str],
        page_size: int = 50,
    ) -> None:
        self._session = session
        self._blockchain = blockchain
        self._backup = backup_storage
        self._vault = key_vault
        self._audit = audit_log
        self._allowed_options = allowed_options
        self._page_size = page_size
        self._recovery = BallotRecovery(backup_storage, session, audit_log)

    async def run(self, election_id: int) -> TallyResult:
        """Execute the full tally lifecycle for the given election.

        Raises:
            TallyStateError:  Election is not in Tallying state.
            RuntimeError:     If the KEM key is unavailable.
        """
        self._audit.record_tally_started(election_id)

        # --- Step 1: Verify election state ---
        state = await self._blockchain.get_election_state(election_id)
        if state != _EXPECTED_TALLYING_STATE:
            msg = (
                f"Election {election_id} is in state {state!r}; "
                f"tally requires state {_EXPECTED_TALLYING_STATE!r}"
            )
            self._audit.record_tally_failed(election_id, msg)
            raise TallyStateError(msg)

        # --- Step 2: Fetch all ballot commitments (paginated) ---
        all_commitments = await self._fetch_all_commitments(election_id)
        counters = TallyCounters(total_commitments=len(all_commitments))

        # Initialize option counter dict (all options start at 0)
        vote_counts: dict[str, int] = {opt: 0 for opt in self._allowed_options}

        # --- Step 3: Per-ballot processing ---
        for item in all_commitments:
            commitment_hash_b64: str = item["commitment_hash"]
            nullifier_hash_b64: str = item["nullifier_hash"]

            commitment_hash_bytes = base64.b64decode(commitment_hash_b64)
            nullifier_hash_bytes = base64.b64decode(nullifier_hash_b64)
            commitment_hash_hex = commitment_hash_bytes.hex()
            nullifier_hash_hex = nullifier_hash_bytes.hex()

            # Obtain ballot blob (primary or recovered)
            blob = await self._retrieve_blob(
                election_id=election_id,
                commitment_hash_b64=commitment_hash_b64,
                commitment_hash_hex=commitment_hash_hex,
                nullifier_hash_b64=nullifier_hash_b64,
                nullifier_hash_hex=nullifier_hash_hex,
                on_chain_commitment_bytes=commitment_hash_bytes,
                counters=counters,
            )
            if blob is None:
                # Logged and counted in _retrieve_blob; skip this ballot
                continue

            # Validate BallotBlobV1 structure
            try:
                decoded = validate_ballot_blob_v1(blob)
            except BallotBlobValidationError as exc:
                print(f"      [TallyEngine] BLOCKING LAYER: BallotBlobValidationError for {commitment_hash_hex}: {exc}")
                counters.integrity_failures += 1
                self._audit.record_integrity_failure(
                    election_id, commitment_hash_hex, str(exc)
                )
                continue

            # Verify commitment hash (recompute and compare with on-chain)
            try:
                recomputed = compute_commitment(election_id, nullifier_hash_bytes, blob)
                if recomputed != commitment_hash_bytes:
                    raise CommitmentMismatchError(
                        f"Recomputed commitment {recomputed.hex()} != "
                        f"on-chain {commitment_hash_hex}"
                    )
            except CommitmentMismatchError as exc:
                print(f"      [TallyEngine] BLOCKING LAYER: CommitmentMismatchError for {commitment_hash_hex}")
                counters.integrity_failures += 1
                self._audit.record_integrity_failure(
                    election_id, commitment_hash_hex, str(exc)
                )
                continue

            # Decrypt ballot (KEM + HKDF + AES-GCM)
            plaintext = self._decrypt_ballot(
                election_id=election_id,
                commitment_hash_hex=commitment_hash_hex,
                nullifier_hash_bytes=nullifier_hash_bytes,
                decoded=decoded,
                counters=counters,
            )
            if plaintext is None:
                continue

            # Validate ballot payload
            try:
                payload = validate_ballot_payload(
                    plaintext=plaintext,
                    allowed_options=self._allowed_options,
                    expected_election_id=election_id,
                )
            except InvalidBallotPayloadError as exc:
                counters.invalid_ballots += 1
                self._audit.record_invalid_ballot(
                    election_id, commitment_hash_hex, str(exc)
                )
                # Discard plaintext reference
                del plaintext
                continue

            # Discard plaintext immediately after validation
            del plaintext

            # Count valid ballot
            vote_counts[payload.selected_option] = (
                vote_counts.get(payload.selected_option, 0) + 1
            )
            counters.valid_ballots += 1
            self._audit.record_valid_ballot(election_id, commitment_hash_hex)

        # --- Step 4: Serialize result ---
        canonical_bytes = _serialize_canonical_result(election_id, vote_counts, counters)
        result_commitment_bytes = _compute_result_commitment(canonical_bytes)
        result_commitment_hex = result_commitment_bytes.hex()
        result_commitment_b64 = base64.b64encode(result_commitment_bytes).decode()
        completed_at = datetime.now(UTC)

        # --- Step 5: Publish result commitment ---
        tx_hash = await self._blockchain.publish_result_commitment(
            election_id=election_id,
            result_commitment_b64=result_commitment_b64,
        )
        logger.info(
            "TallyEngine: published result_commitment for election=%d tx=%s",
            election_id,
            tx_hash,
        )

        # --- Step 6: Persist TallyRun ---
        await self._persist_tally_run(
            election_id=election_id,
            result_commitment_hex=result_commitment_hex,
            canonical_bytes=canonical_bytes,
            counters=counters,
            completed_at=completed_at,
        )

        self._audit.record_tally_completed(
            election_id=election_id,
            total_commitments=counters.total_commitments,
            valid_ballots=counters.valid_ballots,
            invalid_ballots=counters.invalid_ballots,
            integrity_failures=counters.integrity_failures,
            decryption_failures=counters.decryption_failures,
            recovered_ballots=counters.recovered_ballots,
            result_commitment_hex=result_commitment_hex,
        )

        return TallyResult(
            election_id=election_id,
            results=vote_counts,
            counters=counters,
            canonical_bytes=canonical_bytes,
            result_commitment=result_commitment_bytes,
            result_commitment_hex=result_commitment_hex,
            result_commitment_b64=result_commitment_b64,
            completed_at=completed_at,
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    async def _fetch_all_commitments(self, election_id: int) -> list[dict[str, Any]]:
        """Authoritatively enumerate all commitments from the blockchain."""
        raw_list = await self._blockchain.list_ballot_commitments(election_id)
        
        all_items: list[dict[str, Any]] = []
        for c_hash_b64, n_hash_b64 in raw_list:
            all_items.append({
                "commitment_hash": c_hash_b64,
                "nullifier_hash": n_hash_b64,
            })
        return all_items

    async def _retrieve_blob(
        self,
        election_id: int,
        commitment_hash_b64: str,
        commitment_hash_hex: str,
        nullifier_hash_b64: str,
        nullifier_hash_hex: str,
        on_chain_commitment_bytes: bytes,
        counters: TallyCounters,
    ) -> bytes | None:
        """Look up blob in DB; fall back to backup recovery if needed."""
        from sqlalchemy import select  # noqa: PLC0415

        from app.models.ballot import EncryptedBallot  # noqa: PLC0415

        result = await self._session.execute(
            select(EncryptedBallot).where(
                EncryptedBallot.commitment_hash == commitment_hash_b64
            )
        )
        db_record = result.scalar_one_or_none()

        if db_record is not None:
            blob = db_record.ballot_blob
            # Quick structural check before returning
            try:
                validate_ballot_blob_v1(blob)
                return blob
            except BallotBlobValidationError:
                # Corrupted primary — fall through to recovery
                logger.warning(
                    "TallyEngine: primary blob corrupted for %s, attempting recovery",
                    commitment_hash_hex,
                )

        # Attempt backup recovery
        try:
            blob = await self._recovery.recover(
                election_id=election_id,
                commitment_hash_hex=commitment_hash_hex,
                nullifier_hash_hex=nullifier_hash_hex,
                on_chain_commitment_hash_b64=commitment_hash_b64,
            )
            counters.recovered_ballots += 1
            return blob
        except RecoveryError as exc:
            counters.integrity_failures += 1
            self._audit.record_unrecoverable(election_id, commitment_hash_hex, str(exc))
            return None

    def _decrypt_ballot(
        self,
        election_id: int,
        commitment_hash_hex: str,
        nullifier_hash_bytes: bytes,
        decoded: dict,
        counters: TallyCounters,
    ) -> bytes | None:
        """ML-KEM decapsulation → HKDF → AES-GCM decryption.

        Returns plaintext bytes or None on any failure.
        Sensitive intermediates (kem_sk, shared_secret, aes_key) are
        local to this method and are not returned.
        """
        try:
            # Fetch election KEM private key (NEVER log or store)
            kem_sk = self._vault.get_kem_sk(election_id)

            # ML-KEM-768 decapsulation
            shared_secret = kem_decapsulate(kem_sk, decoded["kem_ct"])
            del kem_sk  # discard private key immediately

            if len(shared_secret) != 32:
                raise DecryptionFailureError(
                    f"ML-KEM decapsulation: shared_secret must be 32 bytes, "
                    f"got {len(shared_secret)}"
                )

            # HKDF-SHA3-256
            aes_key = derive_aes_key(shared_secret)
            del shared_secret  # discard shared secret

            # Reconstruct AAD (same encoding as Stage 2B)
            aad = build_aad(election_id, nullifier_hash_bytes)

            # AES-256-GCM decryption (authentication is automatic)
            plaintext = aes_gcm_decrypt(
                key=aes_key,
                nonce=decoded["nonce"],
                ciphertext=decoded["ciphertext"],
                tag=decoded["tag"],
                aad=aad,
            )
            del aes_key  # discard AES key

            return plaintext

        except DecryptionFailureError as exc:
            print(f"      [TallyEngine] BLOCKING LAYER: DecryptionFailureError for {commitment_hash_hex}: {exc}")
            counters.decryption_failures += 1
            self._audit.record_decryption_failure(
                election_id, commitment_hash_hex, str(exc)
            )
            return None
        except Exception as exc:
            counters.decryption_failures += 1
            self._audit.record_decryption_failure(
                election_id,
                commitment_hash_hex,
                f"{type(exc).__name__}: {exc}",
            )
            return None

    async def _persist_tally_run(
        self,
        election_id: int,
        result_commitment_hex: str,
        canonical_bytes: bytes,
        counters: TallyCounters,
        completed_at: datetime,
    ) -> None:
        """Write TallyRun record to the database."""
        from app.models.ballot import TallyRun, TallyRunStatus  # noqa: PLC0415

        audit_counters = {
            "total_commitments": counters.total_commitments,
            "recovered_ballots": counters.recovered_ballots,
            "integrity_failures": counters.integrity_failures,
            "decryption_failures": counters.decryption_failures,
            "invalid_ballots": counters.invalid_ballots,
            "valid_ballots": counters.valid_ballots,
        }

        run = TallyRun(
            election_id=election_id,
            status=TallyRunStatus.completed.value,
            result_commitment_hex=result_commitment_hex,
            canonical_result_bytes=canonical_bytes,
            audit_counters_json=json.dumps(audit_counters).encode(),
            completed_at=completed_at,
        )
        self._session.add(run)
        await self._session.flush()
