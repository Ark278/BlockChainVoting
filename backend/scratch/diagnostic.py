import asyncio
import base64
import hashlib
import json
import os
import httpx
import oqs
from dotenv import load_dotenv

load_dotenv('d:/BlockChainVoting/backend/.env')
CONTRACT_ADDR = os.environ['VOTING_CONTRACT_ADDRESS']

async def get_onchain_key():
    query_str = json.dumps({'get_issuer_key': {'issuer_key_id': 'university_admin_2'}})
    cmd = [
        'docker', 'exec', 'blockchainvoting-wasmd-1', 'wasmd', 'query', 'wasm', 'contract-state', 'smart',
        CONTRACT_ADDR, query_str, '--output', 'json'
    ]
    import subprocess
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, _ = await proc.communicate()
    return json.loads(stdout.decode())['data']

async def issue_credential():
    async with httpx.AsyncClient() as client:
        res = await client.post('http://localhost:8000/api/v1/demo/credentials')
        return res.json()

def serialize_credential_payload(cred: dict) -> bytes:
    canonical_json = json.dumps(cred, sort_keys=True, separators=(',', ':'))
    return canonical_json.encode('utf-8')

async def main():
    sk_path = 'd:/BlockChainVoting/backend/issuer_sk.hex'
    with open(sk_path, 'r') as f:
        sk = bytes.fromhex(f.read().strip())
    
    # 2 & 3. Attempt exactly what was requested:
    pk = None
    try:
        with oqs.Signature('ML-DSA-65', secret_key=sk) as sig:
            pk = sig.export_public_key()
            pk_hash = hashlib.sha3_256(pk).digest()
            pk_hash_b64 = base64.b64encode(pk_hash).decode()
            print(f'Runtime PK Hash: {pk_hash_b64}')
    except AttributeError as e:
        print(f'Runtime PK Hash: ERROR ({e})')

    # 4 & 5. Query on-chain key
    onchain = await get_onchain_key()
    onchain_pk_hash = onchain["public_key_hash"]
    print(f'On-chain PK hash: {onchain_pk_hash}')
    
    # 6. Compare
    if pk:
        print(f'Do public keys match? {pk_hash_b64 == onchain_pk_hash}')
    else:
        print(f'Do public keys match? UNKNOWN (could not derive runtime PK)')

    # Then issue fresh credential
    cred_res = await issue_credential()
    cred = cred_res['credential']
    sig_b64 = cred_res['credential_signature_b64']
    sig_bytes = base64.b64decode(sig_b64)
    
    canonical_bytes = serialize_credential_payload(cred)
    
    if pk:
        with oqs.Signature('ML-DSA-65') as verifier_rt:
            is_valid_rt = verifier_rt.verify(canonical_bytes, sig_bytes, pk)
            print(f'Runtime signature verification passes: {is_valid_rt}')
    else:
        print(f'Runtime signature verification passes: N/A (no runtime PK derived)')
        
    onchain_pk = base64.b64decode(onchain['public_key'])
    with oqs.Signature('ML-DSA-65') as verifier_oc:
        try:
            is_valid_oc = verifier_oc.verify(canonical_bytes, sig_bytes, onchain_pk)
        except Exception:
            is_valid_oc = False
        print(f'On-chain signature verification passes: {is_valid_oc}')

asyncio.run(main())
