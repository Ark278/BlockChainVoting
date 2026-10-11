import asyncio
import base64
import hashlib
import json
import subprocess
import os
import uuid
import httpx
from datetime import datetime, UTC, timedelta

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
    print(f'1. Using private key file: {sk_path}')
    with open(sk_path, 'r') as f:
        sk = bytes.fromhex(f.read().strip())
    
    # Python oqs.Signature doesn't expose export_public_key() from an imported secret key.
    # We will verify if the generated signature matches the on-chain PK.
    
    onchain = await get_onchain_key()
    print(f'4. On-chain PK hash: {onchain["public_key_hash"]}')
    
    print('6. Issuing credential...')
    cred_res = await issue_credential()
    cred = cred_res['credential']
    sig_b64 = cred_res['credential_signature_b64']
    sig_bytes = base64.b64decode(sig_b64)
    
    canonical_bytes = serialize_credential_payload(cred)
    print(f'Canonical bytes: {canonical_bytes.decode()}')
    
    onchain_pk = base64.b64decode(onchain['public_key'])
    with oqs.Signature('ML-DSA-65') as verifier_oc:
        try:
            is_valid_oc = verifier_oc.verify(canonical_bytes, sig_bytes, onchain_pk)
        except Exception as e:
            is_valid_oc = False
            print(f'Exception during verify: {e}')
        print(f'8. Signature valid against on-chain PK: {is_valid_oc}')

asyncio.run(main())
