"""FastAPI backend application for voting (Architecture v2.6)."""

import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.session import get_db
from app.errors import (
    BlockchainSubmissionFailureError,
    ExpiredCredentialError,
    IdempotencyConflictError,
    InvalidCredentialError,
    InvalidSignatureError,
    RevokedCredentialError,
    UnknownIssuerKeyError,
)
from app.models import BallotStatus, EncryptedBallot
from app.services.blockchain import BlockchainClient
from app.services.credentials import serialize_credential_payload, verify_credential
from app.services.crypto import encrypt_ballot_full
from app.services.idempotency import IdempotencyService
from app.services.nullifier import derive_and_hash
from app.services.revocation import RevocationRepository

# ── Dependency injection ──────────────────────────────────────────────────────

async def get_blockchain_client() -> BlockchainClient:
    client = BlockchainClient()
    try:
        yield client
    finally:
        await client.close()

async def get_revocation_repo(db: AsyncSession = Depends(get_db)) -> RevocationRepository:
    return RevocationRepository(db)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    pass


app = FastAPI(title="Voting Backend", lifespan=lifespan)


# ── Pydantic Schemas ──────────────────────────────────────────────────────────

class CredentialPayloadSchema(BaseModel):
    credential_id: str
    issued_at: str
    expires_at: str
    attributes: dict[str, Any]
    issuer_key_id: str

class SubmitBallotRequest(BaseModel):
    election_id: int
    credential: CredentialPayloadSchema
    credential_signature_b64: str
    ballot_plaintext: dict[str, Any]


class SubmitBallotResponse(BaseModel):
    status: str
    message: str
    ballot_id: str
    commitment_hash: str
    tx_hash: str | None = None


# ── API Routes ────────────────────────────────────────────────────────────────

@app.post("/api/v1/ballots/submit", response_model=SubmitBallotResponse, status_code=202)
async def submit_ballot(
    req: SubmitBallotRequest,
    request: Request,
    idempotency_key: str = Header(..., alias="Idempotency-Key"),
    db: AsyncSession = Depends(get_db),
    blockchain: BlockchainClient = Depends(get_blockchain_client),
    revocation_repo: RevocationRepository = Depends(get_revocation_repo),
):
    """Submit an encrypted ballot."""
    raw_body = await request.body()
    idem_service = IdempotencyService(db)
    
    try:
        idem_record = await idem_service.check(idempotency_key, raw_body)
    except IdempotencyConflictError as e:
        raise HTTPException(status_code=409, detail=str(e))
    
    if idem_record:
        if idem_record.response_status_code in (200, 201, 202):
            ballot_id = idem_record.response_reference
            if ballot_id:
                b_res = await db.execute(select(EncryptedBallot).where(EncryptedBallot.ballot_id == ballot_id))
                ballot = b_res.scalar_one_or_none()
                if ballot and ballot.storage_status in (BallotStatus.stored.value, BallotStatus.retryable.value, BallotStatus.failed.value):
                    return await _do_blockchain_submission(ballot, db, blockchain, idempotency_key, raw_body, idem_service)
                elif ballot and ballot.storage_status in (BallotStatus.submitted.value, BallotStatus.confirmed.value):
                    return JSONResponse(status_code=idem_record.response_status_code, content=json.loads(idem_record.response_body))
        if idem_record.response_body:
            return JSONResponse(status_code=idem_record.response_status_code, content=json.loads(idem_record.response_body))

    import base64
    try:
        sig_bytes = base64.b64decode(req.credential_signature_b64)
        canonical_cred = serialize_credential_payload(req.credential.model_dump())
        await verify_credential(
            credential_payload_bytes=canonical_cred,
            signature=sig_bytes,
            blockchain_client=blockchain,
            revocation_repo=revocation_repo,
        )
    except (InvalidCredentialError, InvalidSignatureError, UnknownIssuerKeyError) as e:
        await _store_err_idem(idem_service, idempotency_key, raw_body, 401, str(e), db)
        raise HTTPException(status_code=401, detail=str(e))
    except ExpiredCredentialError as e:
        await _store_err_idem(idem_service, idempotency_key, raw_body, 403, str(e), db)
        raise HTTPException(status_code=403, detail=str(e))
    except RevokedCredentialError as e:
        await _store_err_idem(idem_service, idempotency_key, raw_body, 403, str(e), db)
        raise HTTPException(status_code=403, detail=str(e))

    settings = get_settings()
    nullifier_key = bytes.fromhex(settings.nullifier_key_hex) if hasattr(settings, "nullifier_key_hex") else (b"0" * 32)
    nullifier_hash = derive_and_hash(nullifier_key, req.credential.credential_id, req.election_id)
    nullifier_hash_b64 = base64.b64encode(nullifier_hash).decode()

    if await blockchain.nullifier_used(req.election_id, nullifier_hash_b64):
        msg = "Nullifier has already been used on-chain."
        await _store_err_idem(idem_service, idempotency_key, raw_body, 409, msg, db)
        raise HTTPException(status_code=409, detail=msg)

    exist_res = await db.execute(select(EncryptedBallot).where(EncryptedBallot.nullifier_hash == nullifier_hash_b64))
    if exist_res.scalar_one_or_none():
        msg = "Nullifier has already been submitted to the backend."
        await _store_err_idem(idem_service, idempotency_key, raw_body, 409, msg, db)
        raise HTTPException(status_code=409, detail=msg)

    kem_data = await blockchain.get_election_kem_pk(req.election_id)
    if not kem_data:
        msg = f"Election {req.election_id} not found."
        await _store_err_idem(idem_service, idempotency_key, raw_body, 404, msg, db)
        raise HTTPException(status_code=404, detail=msg)
    kem_pk, kem_pk_hash = kem_data

    pt_bytes = json.dumps(req.ballot_plaintext, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        enc_pkg = encrypt_ballot_full(
            election_id=req.election_id,
            nullifier_hash=nullifier_hash,
            ballot_plaintext=pt_bytes,
            kem_pk=kem_pk,
            kem_pk_hash_expected=kem_pk_hash,
        )
    except Exception as e:
        msg = f"Encryption failed: {str(e)}"
        await _store_err_idem(idem_service, idempotency_key, raw_body, 500, msg, db)
        raise HTTPException(status_code=500, detail=msg)

    commitment_b64 = base64.b64encode(enc_pkg.commitment_hash).decode()
    kem_ct_hash_b64 = base64.b64encode(enc_pkg.kem_ct_hash).decode()

    ballot = EncryptedBallot(
        election_id=req.election_id,
        nullifier_hash=nullifier_hash_b64,
        commitment_hash=commitment_b64,
        ballot_blob=enc_pkg.ballot_blob,
        kem_ct_hash=kem_ct_hash_b64,
        storage_status=BallotStatus.stored.value,
    )
    db.add(ballot)
    await db.commit()
    await db.refresh(ballot)

    return await _do_blockchain_submission(ballot, db, blockchain, idempotency_key, raw_body, idem_service)


async def _do_blockchain_submission(ballot, db, blockchain, idempotency_key, raw_body, idem_service):
    try:
        tx_hash = await blockchain.submit_commitment(
            election_id=ballot.election_id,
            commitment_hash_b64=ballot.commitment_hash,
            nullifier_hash_b64=ballot.nullifier_hash,
        )
        ballot.blockchain_tx_hash = tx_hash
        ballot.storage_status = BallotStatus.submitted.value
        await db.commit()

        resp = {
            "status": "success",
            "message": "Ballot submitted to blockchain",
            "ballot_id": ballot.ballot_id,
            "commitment_hash": ballot.commitment_hash,
            "tx_hash": tx_hash,
        }
        await idem_service.store(idempotency_key, raw_body, ballot.ballot_id, 202, resp)
        await db.commit()
        return JSONResponse(status_code=202, content=resp)

    except BlockchainSubmissionFailureError as e:
        ballot.storage_status = BallotStatus.retryable.value
        ballot.error_message = str(e)
        await db.commit()
        resp = {
            "status": "error",
            "message": f"Blockchain submission failed: {str(e)}",
            "ballot_id": ballot.ballot_id,
            "commitment_hash": ballot.commitment_hash,
        }
        raise HTTPException(status_code=502, detail=resp)
    except Exception as e:
        ballot.storage_status = BallotStatus.failed.value
        ballot.error_message = str(e)
        await db.commit()
        raise HTTPException(status_code=500, detail="Internal server error during blockchain submission")


async def _store_err_idem(idem_service, key, body, status, detail, db):
    try:
        await idem_service.store(key, body, "", status, {"detail": detail})
        await db.commit()
    except IdempotencyConflictError:
        await db.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# Stage 4 — AI anomaly detection endpoints
#
# ADVISORY ONLY.  These endpoints:
#   - accept privacy-validated telemetry;
#   - trigger background anomaly inference;
#   - expose anomaly results for dashboard display.
#
# AI results NEVER influence ballot acceptance, credential validity,
# nullifier uniqueness, blockchain state, tally, or result publication.
# ─────────────────────────────────────────────────────────────────────────────

import struct  # noqa: E402
from fastapi import BackgroundTasks  # noqa: E402
from app.ai.anomaly_service import AnomalyDetectionService, background_infer_and_persist  # noqa: E402
from app.ai.bucket_secret import ServerBucketSecretManager  # noqa: E402
from app.ai.telemetry import (  # noqa: E402
    AggregatedTelemetry,
    validate_telemetry_fields,
    compute_client_bucket_token,
    compute_telemetry_bucket_id,
    compute_behavioral_signal_hash,
)
from app.errors import TelemetryValidationError  # noqa: E402
from app.models import AnomalyResult, TelemetryBucket  # noqa: E402


class TelemetryIngestRequest(BaseModel):
    """Inbound telemetry payload.

    Only approved fields.  Prohibited fields (voter identity, nullifiers,
    ballot content, keys) are rejected at validation time before any processing.
    """

    election_id: int
    bucket_start_ts: int                        # Unix timestamp (seconds)
    client_bucket_token_hex: str                # 32-byte hex, computed client-side
    submission_interval_seconds: float | None = None
    submission_attempts: int | None = None
    auth_failure_count: int | None = None
    encrypted_blob_size_bytes: int | None = None
    # Raw behavioral signal: a deterministic non-identifying signal (e.g. request
    # timing sequence hash). Never stored; HMAC'd server-side only.
    behavioral_signal_hex: str | None = None
    version: int = 1


@app.post("/api/v1/telemetry", status_code=202)
async def ingest_telemetry(
    request: Request,
    payload: TelemetryIngestRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Ingest a telemetry record.

    Privacy:
        - Rejects any payload containing prohibited fields (nullifiers,
          credentials, voter IDs, ballot content, keys).
        - Constructs telemetry_bucket_id server-side using the frozen protocol.
        - Never stores raw behavioral signal; HMAC-SHA3-256 digest only.
        - Fire-and-forget anomaly inference via FastAPI BackgroundTasks.
          AI failures never affect this response or the ballot acceptance path.

    Returns 422 if prohibited fields are detected.
    Returns 202 on successful ingest.
    """
    settings = get_settings()

    # Privacy guard: reject prohibited fields in the raw request body
    try:
        raw_body = await request.json()
        validate_telemetry_fields(raw_body)
    except TelemetryValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    # Decode client bucket token
    try:
        client_bucket_token = bytes.fromhex(payload.client_bucket_token_hex)
        if len(client_bucket_token) != 32:
            raise ValueError("client_bucket_token_hex must be 64 hex chars (32 bytes)")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid client_bucket_token_hex: {exc}")

    # Build server-side IDs (secret never logged or returned)
    secret_manager = ServerBucketSecretManager(settings)
    server_secret = secret_manager.get_secret()

    bucket_id_bytes = compute_telemetry_bucket_id(client_bucket_token, server_secret)
    bucket_id_hex = bucket_id_bytes.hex()

    # Behavioral signal hash (raw signal never stored)
    behavioral_hash_hex: str | None = None
    if payload.behavioral_signal_hex:
        try:
            raw_signal = bytes.fromhex(payload.behavioral_signal_hex)
        except ValueError:
            raw_signal = payload.behavioral_signal_hex.encode()
        bsh_bytes = compute_behavioral_signal_hash(
            server_secret, raw_signal, payload.bucket_start_ts
        )
        behavioral_hash_hex = bsh_bytes.hex()
        del raw_signal  # discard immediately

    del server_secret  # discard server secret immediately

    # Persist telemetry record (approved fields only)
    telemetry_record = TelemetryBucket(
        election_id=payload.election_id,
        telemetry_bucket_id_hex=bucket_id_hex,
        bucket_start_ts=payload.bucket_start_ts,
        submission_interval_seconds=payload.submission_interval_seconds,
        submission_attempts=payload.submission_attempts,
        auth_failure_count=payload.auth_failure_count,
        encrypted_blob_size_bytes=payload.encrypted_blob_size_bytes,
        behavioral_signal_hash_hex=behavioral_hash_hex,
        schema_version=1,
    )
    db.add(telemetry_record)
    await db.commit()
    await db.refresh(telemetry_record)

    # Build aggregated telemetry for AI inference
    aggregated = AggregatedTelemetry(
        election_id=payload.election_id,
        telemetry_bucket_id_hex=bucket_id_hex,
        bucket_start_ts=payload.bucket_start_ts,
        submission_interval_seconds=payload.submission_interval_seconds or 0.0,
        submission_attempts=float(payload.submission_attempts or 0),
        auth_failure_count=float(payload.auth_failure_count or 0),
        encrypted_blob_size_bytes=float(payload.encrypted_blob_size_bytes or 0),
        behavioral_signal_hash_hex=behavioral_hash_hex,
    )

    # Fire-and-forget: AI inference via BackgroundTasks (tracked, exception-safe).
    # This NEVER blocks ballot processing.  All exceptions are caught inside
    # background_infer_and_persist.
    if settings.ai_enabled:
        ai_service = AnomalyDetectionService(
            model_dir=settings.ai_model_dir,
            timeout_seconds=settings.ai_inference_timeout_seconds,
            enabled=True,
        )
        # BackgroundTasks runs after the response is sent; it is managed by
        # FastAPI and does NOT use untracked asyncio.create_task().
        background_tasks.add_task(
            background_infer_and_persist,
            ai_service,
            aggregated,
            db,
        )

    return {
        "status": "accepted",
        "bucket_id": telemetry_record.bucket_id,
        "telemetry_bucket_id_hex": bucket_id_hex[:16] + "...",  # truncated; not full hex
        "election_id": payload.election_id,
    }


@app.get("/api/v1/anomalies")
async def list_anomalies(
    election_id: int | None = None,
    risk_level: str | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """List advisory anomaly results for dashboard display.

    Returns anomaly/telemetry information only.
    Does NOT expose voter identity, nullifiers, or ballot content.

    Query parameters:
        election_id: Filter by election.
        risk_level: Filter by risk level (NORMAL | SUSPICIOUS | HIGH_RISK).
        limit: Maximum results (1–200).
    """
    limit = max(1, min(limit, 200))
    stmt = select(AnomalyResult).order_by(AnomalyResult.created_at.desc()).limit(limit)
    if election_id is not None:
        stmt = stmt.where(AnomalyResult.election_id == election_id)
    if risk_level is not None:
        stmt = stmt.where(AnomalyResult.risk_level == risk_level.upper())

    result = await db.execute(stmt)
    rows = result.scalars().all()

    return {
        "anomalies": [
            {
                "result_id": r.result_id,
                "election_id": r.election_id,
                "telemetry_bucket_id_hex": r.telemetry_bucket_id_hex,
                "bucket_start_ts": r.bucket_start_ts,
                "anomaly_score": r.anomaly_score,
                "risk_level": r.risk_level,
                "model_version": r.model_version,
                "explanation": r.explanation,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "advisory_note": (
                    "This result is advisory only and does not constitute evidence of fraud. "
                    "Ballot acceptance is determined exclusively by cryptographic verification "
                    "and smart-contract rules."
                ),
            }
            for r in rows
        ],
        "total": len(rows),
        "limit": limit,
    }


@app.get("/api/v1/anomalies/{result_id}")
async def get_anomaly(
    result_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Retrieve a single anomaly result by ID.

    Returns anomaly/telemetry information only.
    Does NOT expose voter identity, nullifiers, or ballot content.
    """
    result = await db.execute(
        select(AnomalyResult).where(AnomalyResult.result_id == result_id)
    )
    row = result.scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=404, detail=f"Anomaly result {result_id} not found")

    feature_summary = None
    if row.feature_summary_json:
        try:
            feature_summary = json.loads(row.feature_summary_json)
        except Exception:  # noqa: BLE001
            feature_summary = None

    return {
        "result_id": row.result_id,
        "election_id": row.election_id,
        "telemetry_bucket_id_hex": row.telemetry_bucket_id_hex,
        "bucket_start_ts": row.bucket_start_ts,
        "anomaly_score": row.anomaly_score,
        "risk_level": row.risk_level,
        "model_version": row.model_version,
        "feature_summary": feature_summary,
        "explanation": row.explanation,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "advisory_note": (
            "This result is advisory only and does not constitute evidence of fraud. "
            "Ballot acceptance is determined exclusively by cryptographic verification "
            "and smart-contract rules."
        ),
    }

@app.get("/api/v1/elections")
async def list_elections(blockchain: BlockchainClient = Depends(get_blockchain_client)):
    return await blockchain.list_elections()

@app.get("/api/v1/elections/{election_id}")
async def get_election(election_id: int, blockchain: BlockchainClient = Depends(get_blockchain_client)):
    election = await blockchain.get_election(election_id)
    if election is None:
        raise HTTPException(status_code=404, detail="Election not found")
    
    candidates = await blockchain.get_candidates(election_id)
    election["options"] = candidates
    return election

@app.get("/api/v1/results/{election_id}")
async def get_results(election_id: int, db: AsyncSession = Depends(get_db)):
    from app.models import TallyRun
    import json
    stmt = select(TallyRun).where(TallyRun.election_id == election_id, TallyRun.status == 'completed').order_by(TallyRun.created_at.desc()).limit(1)
    res = await db.execute(stmt)
    run = res.scalar_one_or_none()
    if run and run.canonical_result_bytes:
        data = json.loads(run.canonical_result_bytes.decode('utf-8'))
        return data
    return {
        "valid_ballots": 0,
        "invalid_ballots": 0,
        "candidate_totals": {},
        "result_commitment": None
    }

@app.get("/api/v1/commitments/{election_id}/{nullifier_hash_b64}")
async def get_public_commitment(
    election_id: int, 
    nullifier_hash_b64: str,
    db: AsyncSession = Depends(get_db),
    blockchain: BlockchainClient = Depends(get_blockchain_client)
):
    from app.models import EncryptedBallot
    # Get tx hash from DB
    stmt = select(EncryptedBallot).where(EncryptedBallot.election_id == election_id, EncryptedBallot.nullifier_hash == nullifier_hash_b64)
    res = await db.execute(stmt)
    ballot = res.scalar_one_or_none()
    tx_hash = ballot.blockchain_tx_hash if ballot else None
    
    return {
        "status": "committed" if tx_hash else "not_found",
        "tx_hash": tx_hash,
        "result_commitment": ballot.commitment_hash if ballot else None
    }

class DemoCredentialResponse(BaseModel):
    credential: CredentialPayloadSchema
    credential_signature_b64: str

@app.post("/api/v1/demo/credentials", response_model=DemoCredentialResponse)
async def issue_demo_credential(db: AsyncSession = Depends(get_db)):
    """Issue a local demo credential. NOT FOR PRODUCTION."""
    import uuid
    import base64
    import os
    from datetime import UTC, datetime, timedelta
    
    try:
        import oqs
    except ImportError:
        raise HTTPException(status_code=500, detail="oqs not installed")

    cred_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    issuer_key_id = os.environ.get(
        "DEMO_ISSUER_KEY_ID", "university_admin_3"
    )
    issuer_sk_file = os.environ.get(
        "DEMO_ISSUER_SK_FILE", "issuer_sk_university_admin_3.hex"
    )

    cred_payload = {
        "credential_id": cred_id,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "attributes": {},
        "issuer_key_id": issuer_key_id
    }
    
    canonical_cred = serialize_credential_payload(cred_payload)
    
    try:
        with open(issuer_sk_file, "r") as f:
            dsa_sk = bytes.fromhex(f.read().strip())
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Local {issuer_sk_file} not found.")
        
    with oqs.Signature("ML-DSA-65", secret_key=dsa_sk) as sig:
        signature = sig.sign(canonical_cred)
        
    from app.models import Credential
    
    db_cred = Credential(
        credential_id=cred_id,
        credential_payload=canonical_cred,
        signature=signature,
        issuer_key_id=issuer_key_id,
        issued_at=now,
        expires_at=now + timedelta(days=1),
        revoked=False
    )
    db.add(db_cred)
    await db.commit()
    
    return {
        "credential": cred_payload,
        "credential_signature_b64": base64.b64encode(signature).decode()
    }
