import asyncio
import os
import json
import base64
import uuid
import hashlib
from dotenv import load_dotenv
load_dotenv(".env.e2e")
import httpx
import asyncpg
import cbor2
import oqs

async def get_db_conn():
    return await asyncpg.connect(os.environ["DATABASE_URL"].replace("postgresql+asyncpg", "postgresql"))
from app.services.credentials import serialize_credential_payload
from app.services.crypto import kem_encapsulate, derive_aes_key, aes_gcm_encrypt, encode_ballot_blob, build_aad, compute_commitment
def compute_nullifier(election_id, cred):
    import hashlib
    data = f"{election_id}:{cred['credential_id']}:{cred['salt']}".encode()
    return hashlib.sha3_256(data).digest()

CONTRACT_ADDR = os.environ["VOTING_CONTRACT_ADDRESS"]
API_URL = "http://localhost:8000"

async def run_tampering():
    print("\n[+] 4. Cryptographic Tampering and Tally Tests")
    
    with open("issuer_sk.hex", "r") as f:
        dsa_sk = bytes.fromhex(f.read().strip())
    
    from app.services.blockchain import BlockchainClient
    bc = BlockchainClient(rest_url=API_URL.replace("8000", "1317"))
    kem_pk, _ = await bc.get_election_kem_pk(9)
    conn = await get_db_conn()
    
    payload = {
        "credential": {
            "issuer_key_id": "issuer-1",
            "attributes": {"age": "30", "region": "US"},
            "salt": "rand123"
        },
        "choices": ["Alice"]
    }
    
    async def create_true_tampered(ttype: str):
        p = payload.copy()
        p['credential'] = payload['credential'].copy()
        p['credential']['credential_id'] = str(uuid.uuid4())
        canonical_cred = serialize_credential_payload(p['credential'])
        with oqs.Signature("ML-DSA-65", secret_key=dsa_sk) as sig:
            p['credential_signature_b64'] = base64.b64encode(sig.sign(canonical_cred)).decode()
        
        nullifier_hash = compute_nullifier(8, p['credential'])
        plaintext = json.dumps(p["choices"]).encode()
        
        kem_ct, shared_secret = kem_encapsulate(kem_pk)
        aes_key = derive_aes_key(shared_secret)
        
        # Proper AAD
        aad = build_aad(8, nullifier_hash)
        
        # Tamper AAD
        encrypt_aad = aad
        if ttype == "aad":
            # the build_aad appends b"\x01". Let's change it to b"\x02"
            encrypt_aad = aad[:-1] + b"\x02"
            
        res = aes_gcm_encrypt(aes_key, plaintext, encrypt_aad)
        nonce = res.nonce
        ciphertext = res.ciphertext
        tag = res.tag
        
        if ttype == "ciphertext":
            ciphertext = b"\x00" + ciphertext[1:]
        elif ttype == "kem":
            kem_ct = b"\x00" + kem_ct[1:]
            
        blob = encode_ballot_blob(kem_ct, nonce, ciphertext, tag)
        c_hash = compute_commitment(9, nullifier_hash, blob)
        
        c_hash_b64 = base64.b64encode(c_hash).decode()
        n_hash_b64 = base64.b64encode(nullifier_hash).decode()
        
        kem_ct_hash_b64 = base64.b64encode(hashlib.sha3_256(kem_ct).digest()).decode()
        ballot_id = str(uuid.uuid4())
        await conn.execute(
            "INSERT INTO encrypted_ballots (ballot_id, election_id, nullifier_hash, commitment_hash, ballot_blob, kem_ct_hash, storage_status, created_at, updated_at) "
            "VALUES ($1, $2, $3, $4, $5, $6, 'CONFIRMED', NOW(), NOW())",
            ballot_id, 9, n_hash_b64, c_hash_b64, blob, kem_ct_hash_b64
        )
        
        import subprocess
        msg = json.dumps({"submit_commitment": {"election_id": 9, "commitment_hash": c_hash_b64, "nullifier_hash": n_hash_b64}})
        subprocess.run(["docker", "exec", "blockchainvoting-wasmd-1", "wasmd", "tx", "wasm", "execute", CONTRACT_ADDR, msg, "--from", "validator", "--keyring-backend", "test", "-y", "--gas", "auto", "--gas-adjustment", "1.5", "--chain-id", "testing"], capture_output=True)
        await asyncio.sleep(6)
        print(f"      -> Submitted TRUE tampered {ttype} directly to chain.")
        
    for t in ["ciphertext", "kem", "aad"]:
        await create_true_tampered(t)
        
    # And one DB mutated test to show DB mutation blocks at CommitmentMismatch
    p = payload.copy()
    p['credential'] = payload['credential'].copy()
    p['credential']['credential_id'] = str(uuid.uuid4())
    canonical_cred = serialize_credential_payload(p['credential'])
    with oqs.Signature("ML-DSA-65", secret_key=dsa_sk) as sig:
        p['credential_signature_b64'] = base64.b64encode(sig.sign(canonical_cred)).decode()
    async with httpx.AsyncClient(base_url=API_URL, timeout=30.0) as client:
        res = await client.post("/api/v1/ballots/submit", json=p, headers={"Idempotency-Key": f"tamp_db_mut"})
        c_hash = res.json()['commitment_hash']
        row = await conn.fetchrow("SELECT ballot_blob FROM encrypted_ballots WHERE commitment_hash = $1", c_hash)
        raw_blob = cbor2.loads(row['ballot_blob'])
        # Mutate ciphertext slightly
        raw_blob[2] = b"\x00" + raw_blob[2][1:]
        new_blob = cbor2.dumps(raw_blob, canonical=True)
        await conn.execute("UPDATE encrypted_ballots SET ballot_blob = $1 WHERE commitment_hash = $2", new_blob, c_hash)
        print(f"      -> Mutated DB blob directly to demonstrate CommitmentMismatchError.")

    await conn.close()
    print("      -> Recovery setup complete. TallyEngine will process these when run.")

asyncio.run(run_tampering())
