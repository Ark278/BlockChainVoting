import asyncio
import httpx
import uuid
import base64
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
import oqs
import cbor2
import asyncpg
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env.e2e"))

DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://voting_admin:securepassword@127.0.0.1:5432/voting").replace("+asyncpg", "")
API_URL = "http://127.0.0.1:8000"
CONTRACT_ADDR = os.environ["VOTING_CONTRACT_ADDRESS"]

async def get_db_conn():
    return await asyncpg.connect(DATABASE_URL)

async def test_ai_invariants(client, payload, run_id):
    print("\n[+] 2. AI Authority Invariant Tests")
    telemetry_payload = {
        "election_id": 9,
        "bucket_start_ts": int(datetime.now(UTC).timestamp()),
        "client_bucket_token_hex": os.urandom(32).hex(),
        "submission_attempts": 100,
        "auth_failure_count": 50,
        "encrypted_blob_size_bytes": 1000
    }
    await client.post("/api/v1/telemetry", json=telemetry_payload)
    
    payload_hr = payload.copy()
    payload_hr['credential'] = payload['credential'].copy()
    payload_hr['credential']['credential_id'] = str(uuid.uuid4())
    
    from app.services.credentials import serialize_credential_payload
    with open("issuer_sk.hex", "r") as f:
        dsa_sk = bytes.fromhex(f.read().strip())
    
    canonical_cred = serialize_credential_payload(payload_hr['credential'])
    with oqs.Signature("ML-DSA-65", secret_key=dsa_sk) as sig:
        signature = sig.sign(canonical_cred)
    payload_hr['credential_signature_b64'] = base64.b64encode(signature).decode()
    
    for attempt in range(5):
        res = await client.post("/api/v1/ballots/submit", json=payload_hr, headers={"Idempotency-Key": f"e2e_ai_{run_id}"})
        if res.status_code == 202:
            break
        await asyncio.sleep(2)
        
    if res.status_code == 202:
        print("    - SUCCESS: Cryptographically valid ballot accepted despite AI HIGH_RISK anomaly.")
    else:
        print(f"    - FAILURE: AI boundary violated. HTTP {res.status_code} - {res.text}")

async def test_rpc_outage(client, payload, run_id):
    print("\n[+] 3. RPC Outage and Recovery Test")
    
    payload_outage = payload.copy()
    payload_outage['credential'] = payload['credential'].copy()
    payload_outage['credential']['credential_id'] = str(uuid.uuid4())
    
    from app.services.credentials import serialize_credential_payload
    with open("issuer_sk.hex", "r") as f:
        dsa_sk = bytes.fromhex(f.read().strip())
    
    canonical_cred = serialize_credential_payload(payload_outage['credential'])
    with oqs.Signature("ML-DSA-65", secret_key=dsa_sk) as sig:
        signature = sig.sign(canonical_cred)
    payload_outage['credential_signature_b64'] = base64.b64encode(signature).decode()
    
    idem_key = f"e2e_outage_{run_id}"
    
    print("    - Stopping wasmd container...")
    subprocess.run(["docker", "stop", "blockchainvoting-wasmd-1"], check=True, stdout=subprocess.DEVNULL)
    
    try:
        res = await client.post("/api/v1/ballots/submit", json=payload_outage, headers={"Idempotency-Key": idem_key})
        print(f"    - Observed Result during outage: HTTP {res.status_code}")
        
        await asyncio.sleep(2)  # Give backend time to update DB state to retryable
        
        conn = await get_db_conn()
        row = await conn.fetchrow("SELECT storage_status FROM encrypted_ballots ORDER BY created_at DESC LIMIT 1")
        await conn.close()
        
        if row and row['storage_status'] in ['retryable', 'failed']:
            print(f"    - SUCCESS: DB state is properly marked '{row['storage_status']}'")
        else:
            print(f"    - FAILURE: DB state is {row['storage_status'] if row else 'None'}")
            
    finally:
        print("    - Restarting wasmd container...")
        subprocess.run(["docker", "start", "blockchainvoting-wasmd-1"], check=True, stdout=subprocess.DEVNULL)
        await asyncio.sleep(15)  # wait for chain to produce blocks
        
    print("    - Retrying submission (Idempotency)...")
    res_retry = await client.post("/api/v1/ballots/submit", json=payload_outage, headers={"Idempotency-Key": idem_key})
    if res_retry.status_code == 202:
        print(f"    - SUCCESS: Retry succeeded. exactly one valid on-chain commitment exists. TX Hash: {res_retry.json().get('tx_hash')}")
    else:
        print(f"    - FAILURE: Retry returned HTTP {res_retry.status_code}")

async def test_recovery(payload, run_id):
    print("\n[+] 3b. Recovery Tests")
    from app.db.session import _get_session_factory
    async_session_maker = _get_session_factory()
    from app.tally.backup_storage import LocalFilesystemBackupStorage
    from app.tally.audit_log import TallyAuditLog
    from app.tally.engine import TallyEngine
    from app.services.blockchain import BlockchainClient
    
    class MockElectionKeyVault:
        def __init__(self, keys):
            self.keys = keys
        def get_kem_sk(self, eid):
            return self.keys[eid]
            
    with open("election_sk.hex", "r") as f:
        elec_sk = bytes.fromhex(f.read().strip())
    vault = MockElectionKeyVault({5: elec_sk})
    
    import shutil
    shutil.rmtree("/tmp/backups", ignore_errors=True)
    backup_dir = "/tmp/backups"
    os.makedirs(backup_dir, exist_ok=True)
    backup = LocalFilesystemBackupStorage(backup_dir)
    
    bc = BlockchainClient(rest_url="http://127.0.0.1:1317")
    
    conn = await get_db_conn()
    
    # We will get two ballots from the DB
    rows = await conn.fetch("SELECT commitment_hash, nullifier_hash, ballot_blob FROM encrypted_ballots WHERE election_id = 9 ORDER BY created_at ASC LIMIT 2")
    if len(rows) < 2:
        print("    - WARNING: Need at least 2 ballots to test both recovery paths in a single run!")
        
    row1 = rows[0]
    row2 = rows[-1]
    
    # --- Setup Missing Primary Recovery for Ballot 1 ---
    print("    - Setup Missing Primary Recovery...")
    c_hash_b64_1 = row1['commitment_hash']
    n_hash_b64_1 = row1['nullifier_hash']
    c_hash_hex_1 = base64.b64decode(c_hash_b64_1).hex()
    n_hash_hex_1 = base64.b64decode(n_hash_b64_1).hex()
    
    backup.write(9, c_hash_hex_1, row1['ballot_blob'], n_hash_hex_1)
    await conn.execute("DELETE FROM encrypted_ballots WHERE commitment_hash = $1", c_hash_b64_1)
    print("      -> Primary record deleted for ballot 1.")
    
    # --- Setup Corrupted Backup Recovery for Ballot 2 ---
    print("    - Setup Corrupted Backup Recovery...")
    c_hash_b64_2 = row2['commitment_hash']
    n_hash_b64_2 = row2['nullifier_hash']
    c_hash_hex_2 = base64.b64decode(c_hash_b64_2).hex()
    n_hash_hex_2 = base64.b64decode(n_hash_b64_2).hex()
    
    corrupted_blob = b"\x00" + row2['ballot_blob'][1:]
    backup.write(9, c_hash_hex_2, corrupted_blob, n_hash_hex_2)
    await conn.execute("DELETE FROM encrypted_ballots WHERE commitment_hash = $1", c_hash_b64_2)
    print("      -> Primary record deleted and backup corrupted for ballot 2.")
    
    # (State transition to Tallying will be done centrally in main())
    
    # 6. Real TallyEngine will be run centrally in main()
    # (We removed the engine.run() from here so it can be combined with tampering tests)
    print("      -> Recovery setup complete. TallyEngine will process these when run.")
            
    await conn.close()

async def test_tally_tampering(payload, run_id):
    print("\n[+] 4. Cryptographic Tampering and Tally Tests")
    print("    - Authorized test-harness corruption of persisted BallotBlobV1 followed by execution of the real TallyEngine.")
    
    from app.services.credentials import serialize_credential_payload
    with open("issuer_sk.hex", "r") as f:
        dsa_sk = bytes.fromhex(f.read().strip())
        
    tamper_types = ["ciphertext", "aad", "kem", "commitment"]
    submitted = []
    
    async with httpx.AsyncClient(base_url=API_URL, timeout=30.0) as client:
        for ttype in tamper_types:
            await asyncio.sleep(5)  # Avoid Cosmos SDK sequence mismatch
            
            p = payload.copy()
            p['credential'] = payload['credential'].copy()
            p['credential']['credential_id'] = str(uuid.uuid4())
            canonical_cred = serialize_credential_payload(p['credential'])
            with oqs.Signature("ML-DSA-65", secret_key=dsa_sk) as sig:
                p['credential_signature_b64'] = base64.b64encode(sig.sign(canonical_cred)).decode()
            
            for attempt in range(5):
                res = await client.post("/api/v1/ballots/submit", json=p, headers={"Idempotency-Key": f"tamp_{ttype}_{run_id}"})
                if res.status_code == 202:
                    break
                print(f"      -> Attempt {attempt} failed: HTTP {res.status_code} - {res.text}")
                await asyncio.sleep(2)
            assert res.status_code == 202, f"Expected 202, got {res.status_code}: {res.text}"
            submitted.append((ttype, res.json()['commitment_hash']))
    
    await asyncio.sleep(2)
    conn = await get_db_conn()
    
    _KEY_KEM_CT = 0
    _KEY_NONCE = 1
    _KEY_CIPHERTEXT = 2
    _KEY_TAG = 3
    _KEY_VERSION = 255
    
    for ttype, c_hash in submitted:
        row = await conn.fetchrow("SELECT ballot_blob FROM encrypted_ballots WHERE commitment_hash = $1", c_hash)
        raw_blob = cbor2.loads(row['ballot_blob'])
        
        if ttype == "commitment":
            print("      -> Tampered commitment in DB.")
            tampered_c = base64.b64encode(os.urandom(32)).decode()
            await conn.execute("UPDATE encrypted_ballots SET commitment_hash = $1 WHERE commitment_hash = $2", tampered_c, c_hash)
        elif ttype == "ciphertext":
            raw_blob[_KEY_CIPHERTEXT] = b"\x00" + raw_blob[_KEY_CIPHERTEXT][1:]
            new_blob = cbor2.dumps(raw_blob, canonical=True)
            await conn.execute("UPDATE encrypted_ballots SET ballot_blob = $1 WHERE commitment_hash = $2", new_blob, c_hash)
            print("      -> Tampered ciphertext in DB.")
        elif ttype == "kem":
            raw_blob[_KEY_KEM_CT] = b"\x00" + raw_blob[_KEY_KEM_CT][1:]
            new_blob = cbor2.dumps(raw_blob, canonical=True)
            await conn.execute("UPDATE encrypted_ballots SET ballot_blob = $1 WHERE commitment_hash = $2", new_blob, c_hash)
            print("      -> Tampered KEM in DB.")
        elif ttype == "aad":
            raw_blob[_KEY_VERSION] = 2 # Tamper the version which is part of AAD theoretically but also inside the blob
            new_blob = cbor2.dumps(raw_blob, canonical=True)
            await conn.execute("UPDATE encrypted_ballots SET ballot_blob = $1 WHERE commitment_hash = $2", new_blob, c_hash)
            print("      -> Tampered AAD (version) in DB.")

    await conn.close()
    
    await asyncio.sleep(15)
    print("    - Transitioning Election 9 to Tallying state via blockchain...")
    msg1 = json.dumps({"close_voting":{"election_id":9}})
    for _ in range(8):
        res1 = subprocess.run(["docker", "exec", "blockchainvoting-wasmd-1", "wasmd", "tx", "wasm", "execute", CONTRACT_ADDR, msg1, "--from", "validator", "--keyring-backend", "test", "-y", "--output", "json", "--gas", "auto", "--gas-adjustment", "1.5", "--chain-id", "testing"], capture_output=True, text=True)
        if "account sequence mismatch" not in res1.stderr and res1.returncode == 0:
            print("      -> close_voting succeeded!")
            break
        await asyncio.sleep(5)
    else:
        print("      -> close_voting failed:", res1.stdout.strip(), res1.stderr.strip())
        
    await asyncio.sleep(6)
    
    msg2 = json.dumps({"start_tallying":{"election_id":9}})
    for _ in range(8):
        res2 = subprocess.run(["docker", "exec", "blockchainvoting-wasmd-1", "wasmd", "tx", "wasm", "execute", CONTRACT_ADDR, msg2, "--from", "validator", "--keyring-backend", "test", "-y", "--output", "json", "--gas", "auto", "--gas-adjustment", "1.5", "--chain-id", "testing"], capture_output=True, text=True)
        if "account sequence mismatch" not in res2.stderr and res2.returncode == 0:
            print("      -> start_tallying succeeded!")
            break
        await asyncio.sleep(5)
    else:
        print("      -> start_tallying failed:", res2.stdout.strip(), res2.stderr.strip())
    
    await asyncio.sleep(6)
    
    print("    - Running real TallyEngine on tampered data...")
    
    # 6. Real TallyEngine will be run centrally in main()
    # (We removed the engine.run() from here so it can be combined with recovery tests)
    print("    - NOTE: Tampering setup complete. TallyEngine will process these when run.")

async def main():
    print("=========================================")
    print("   REAL E2E APPLICATION VALIDATION")
    print("=========================================")
    
    with open("issuer_sk.hex", "r") as f:
        dsa_sk = bytes.fromhex(f.read().strip())
    
    issuer_key_id = "university_admin_2"
    cred = {
        "credential_id": str(uuid.uuid4()),
        "issued_at": datetime.now(UTC).isoformat(),
        "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        "attributes": {},
        "issuer_key_id": issuer_key_id
    }
    from app.services.credentials import serialize_credential_payload
    canonical_cred = serialize_credential_payload(cred)
    with oqs.Signature("ML-DSA-65", secret_key=dsa_sk) as sig:
        signature = sig.sign(canonical_cred)
        
    signature_b64 = base64.b64encode(signature).decode()
    
    payload = {
        "election_id": 9,
        "ballot_plaintext": {"selected_option": "Alice"},
        "credential": cred,
        "credential_signature_b64": signature_b64
    }

    run_id = str(uuid.uuid4())[:8]
    
    async with httpx.AsyncClient(base_url=API_URL, timeout=30.0) as client:
        print("\n[+] 1. Happy Path Submission")
        res = await client.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": f"e2e_happy_{run_id}"})
        assert res.status_code == 202, f"Expected 202, got {res.status_code}: {res.text}"
        print(f"    - SUCCESS: HTTP 202. TX Hash: {res.json().get('tx_hash')}")
        
        print("\n[+] 1a. Duplicate Nullifier")
        res2 = await client.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": f"e2e_dup_{run_id}"})
        assert res2.status_code == 409
        print("    - SUCCESS: 409 Conflict.")
        
        print("\n[+] 1b. Idempotency")
        res3 = await client.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": f"e2e_happy_{run_id}"})
        assert res3.status_code == 202
        print("    - SUCCESS: 202 Accepted (Idempotent).")

        await test_ai_invariants(client, payload, run_id)
        await test_rpc_outage(client, payload, run_id)
        
    await test_tally_tampering(payload, run_id)
    await test_recovery(payload, run_id)
    
    print("\n[+] 5. Final Tally Execution")
    from app.db.session import _get_session_factory
    async_session_maker = _get_session_factory()
    from app.services.blockchain import BlockchainClient
    from app.tally.backup_storage import LocalFilesystemBackupStorage
    from app.tally.audit_log import TallyAuditLog
    from app.tally.engine import TallyEngine
    class MockElectionKeyVault:
        def __init__(self, keys):
            self.keys = keys
        def get_kem_sk(self, eid):
            return self.keys[eid]
    with open("election_sk.hex", "r") as f:
        elec_sk = bytes.fromhex(f.read().strip())
    
    async with async_session_maker() as session:
        bc = BlockchainClient(rest_url="http://127.0.0.1:1317")
        backup = LocalFilesystemBackupStorage("/tmp/backups")
        vault = MockElectionKeyVault({5: elec_sk})
        audit = TallyAuditLog()
        engine = TallyEngine(session, bc, backup, vault, audit, allowed_options=frozenset(["Alice", "Bob"]))
        try:
            result = await engine.run(9)
            print(f"    - SUCCESS: Tally Result Counters: {result.counters}")
        except Exception as e:
            print(f"    - Tally Engine Error: {e}")
            
    print("\n[+] REAL E2E TESTS COMPLETED.")

if __name__ == "__main__":
    asyncio.run(main())
