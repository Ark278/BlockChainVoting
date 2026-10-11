import asyncio
import os
import struct
import hashlib
import cbor2
import asyncpg
import httpx
import base64
import json
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env.e2e"))

DATABASE_URL = os.environ["DATABASE_URL"]
if DATABASE_URL.startswith("postgresql+asyncpg://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")

CHAIN_REST_URL = os.environ.get("CHAIN_REST_URL", "http://127.0.0.1:1317")
CONTRACT_ADDR = os.environ["VOTING_CONTRACT_ADDRESS"]

async def verify_binding(election_id: int, nullifier_hash_b64: str):
    print("=========================================")
    print("   POSTGRES <-> BLOCKCHAIN BINDING VERIFY")
    print("=========================================")
    print(f"Election ID: {election_id}")
    print(f"Nullifier Hash (B64): {nullifier_hash_b64}")

    # 1. Retrieve BallotBlobV1
    conn = await asyncpg.connect(DATABASE_URL)
    row = await conn.fetchrow(
        "SELECT commitment_hash, ballot_blob FROM encrypted_ballot WHERE election_id = $1 AND nullifier_hash = $2",
        election_id, nullifier_hash_b64
    )
    await conn.close()
    
    if not row:
        print("[-] Error: Ballot not found in database.")
        return False
        
    db_commitment_b64 = row['commitment_hash']
    blob_bytes = row['ballot_blob']
    print(f"DB Commitment: {db_commitment_b64}")

    # 2. Reconstruct canonical bytes
    raw_blob = cbor2.loads(blob_bytes)
    canonical_blob_bytes = cbor2.dumps(raw_blob, canonical=True)

    # 3. Recompute SHA3-256
    nullifier_hash_bytes = base64.b64decode(nullifier_hash_b64)
    hasher = hashlib.sha3_256()
    hasher.update(b"VotingCommitmentV1")
    hasher.update(struct.pack(">Q", election_id))
    hasher.update(nullifier_hash_bytes)
    hasher.update(canonical_blob_bytes)
    recomputed_hash = hasher.digest()
    recomputed_b64 = base64.b64encode(recomputed_hash).decode()
    print(f"Locally Recomputed SHA3-256 Commitment: {recomputed_b64}")

    # 4. Compare DB and Recomputed
    if db_commitment_b64 != recomputed_b64:
        print("[-] FAILED: DB commitment does not match recomputed commitment.")
        return False
    print("[+] DB commitment matches locally recomputed SHA3-256 commitment exactly.")

    # 5. Query Real CosmWasm Contract
    null_query = {"get_commitment": {"election_id": election_id, "commitment_hash": nullifier_hash_b64}}
    query_b64 = base64.b64encode(json.dumps(null_query).encode()).decode()
    url = f"{CHAIN_REST_URL}/cosmwasm/wasm/v1/contract/{CONTRACT_ADDR}/smart/{query_b64}"
    
    async with httpx.AsyncClient() as client:
        res = await client.get(url)
        if res.status_code != 200:
            print(f"[-] FAILED: On-chain query returned {res.status_code}: {res.text}")
            return False
            
        data = res.json()
        # The contract returns {"data": {"commitment_hash": "..."}}
        on_chain_commitment_b64 = data.get("data", {}).get("commitment_hash")
        print(f"On-Chain Commitment: {on_chain_commitment_b64}")

    # 6. Assert Exact Equality
    if db_commitment_b64 == on_chain_commitment_b64:
        print("[+] SUCCESS: On-Chain commitment exactly matches local/DB commitment.")
        return True
    else:
        print("[-] FAILED: On-Chain commitment mismatch.")
        return False

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python verify_binding.py <election_id> <nullifier_hash_b64>")
        sys.exit(1)
    asyncio.run(verify_binding(int(sys.argv[1]), sys.argv[2]))
