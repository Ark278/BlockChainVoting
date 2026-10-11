import asyncio
import time
import uuid
import base64
import json
import hashlib
from datetime import UTC, datetime, timedelta
import oqs
import httpx
import os
import csv

USE_MOCK = os.environ.get("USE_MOCK_BLOCKCHAIN", "0") == "1"

async def run_benchmark(ballot_count: int, client: httpx.AsyncClient, dsa_sk: bytes, issuer_key_id: str):
    from app.services.credentials import serialize_credential_payload
    
    start_time = time.time()
    
    # Pre-generate credentials
    creds = []
    for i in range(ballot_count):
        cred = {
            "credential_id": str(uuid.uuid4()),
            "issued_at": datetime.now(UTC).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            "attributes": {},
            "issuer_key_id": issuer_key_id
        }
        canonical = serialize_credential_payload(cred)
        with oqs.Signature("ML-DSA-65", secret_key=dsa_sk) as sig:
            signature = sig.sign(canonical)
            
        creds.append((cred, base64.b64encode(signature).decode()))
        
    prep_time = time.time() - start_time
    
    # Submit ballots concurrently
    tasks = []
    for i, (cred, sig_b64) in enumerate(creds):
        payload = {
            "election_id": 1,
            "credential": cred,
            "credential_signature_b64": sig_b64,
            "ballot_plaintext": {"choice": "A"}
        }
        idem_key = f"bench_real_{ballot_count}_{i}"
        tasks.append(client.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": idem_key}))
        
    submit_start = time.time()
    results = await asyncio.gather(*tasks, return_exceptions=True)
    submit_time = time.time() - submit_start
    
    successes = 0
    failures = 0
    for r in results:
        if isinstance(r, Exception):
            failures += 1
        elif r.status_code == 202:
            successes += 1
        else:
            failures += 1
    
    tps = ballot_count / submit_time if submit_time > 0 else 0
    avg_latency = (submit_time / ballot_count) * 1000 if ballot_count > 0 else 0
    
    print(f"{ballot_count:5d} ballots | {successes:5d} success | {failures:5d} fail | {submit_time:6.2f}s total | {tps:6.2f} TPS | {avg_latency:6.2f}ms avg/req")
    
    return {
        "workload": ballot_count,
        "success": successes,
        "fail": failures,
        "total_time_s": submit_time,
        "tps": tps,
        "avg_latency_ms": avg_latency
    }

async def main():
    print("=========================================")
    print("   STAGE 6 REAL PERFORMANCE BENCHMARK    ")
    print("=========================================")
    if USE_MOCK:
        print("\n*** MOCK BLOCKCHAIN RESULTS ***")
    else:
        print("\n*** REAL POSTGRES + REAL WASMD RESULTS ***")
    
    with oqs.Signature("ML-DSA-65") as sig:
        dsa_pk = sig.generate_keypair()
        dsa_sk = sig.export_secret_key()
        
    issuer_key_id = "bench_issuer"
    
    if USE_MOCK:
        from app.api import app
        from app.db.session import init_db, drop_db
        from tests.unit.test_ai_advisory_boundary import MockBlockchainClient, MockRevocationRepo
        from app.api import get_blockchain_client, get_revocation_repo
        
        blockchain = MockBlockchainClient()
        repo = MockRevocationRepo()
        blockchain.issuer_keys[issuer_key_id] = {
            "public_key": dsa_pk,
            "public_key_hash": hashlib.sha3_256(dsa_pk).digest()
        }
        with oqs.KeyEncapsulation("ML-KEM-768") as kem:
            kem_pk = kem.generate_keypair()
        blockchain.kems[1] = (kem_pk, hashlib.sha3_256(kem_pk).digest())
        
        app.dependency_overrides[get_blockchain_client] = lambda: blockchain
        app.dependency_overrides[get_revocation_repo] = lambda: repo
        
        await drop_db()
        await init_db()
        transport = httpx.ASGITransport(app=app)
        base_url = "http://test"
    else:
        transport = httpx.AsyncHTTPTransport()
        base_url = "http://127.0.0.1:8000"
        
    workloads = [10, 50, 100, 500, 1000, 5000, 10000]
    all_results = []
    
    async with httpx.AsyncClient(transport=transport, base_url=base_url) as client:
        print("\nStarting workloads...")
        for w in workloads:
            res = await run_benchmark(w, client, dsa_sk, issuer_key_id)
            all_results.append(res)
            # Stop if real chain isn't handling it (e.g. 0 successes)
            if not USE_MOCK and res["success"] == 0:
                print(f"    - Stopping benchmark: Target environment cannot complete workload {w}.")
                break
            
    with open("benchmark_results_real.csv", "w", newline='') as f:
        writer = csv.DictWriter(f, fieldnames=["workload", "success", "fail", "total_time_s", "tps", "avg_latency_ms"])
        writer.writeheader()
        writer.writerows(all_results)
        
    print("\nResults saved to benchmark_results_real.csv")

if __name__ == "__main__":
    asyncio.run(main())
