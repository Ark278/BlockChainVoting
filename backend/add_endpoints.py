import os

# The content to append
content = """

# ─────────────────────────────────────────────────────────────────────────────
# Stage 6 — Mocked Retrieval Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/elections")
async def list_elections():
    return [{"id": 1, "name": "Student Council Election 2026", "status": "VOTING"}]

@app.get("/api/v1/elections/{election_id}")
async def get_election(election_id: int):
    return {"id": election_id, "name": "Student Council Election 2026", "status": "VOTING", "options": ["Alice", "Bob"]}

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
"""

with open("app/api.py", "a", encoding="utf-8") as f:
    f.write(content)

print("Endpoints appended.")
