import os
import sys
import json
import base64
import requests
import hashlib

sys.path.append('d:/BlockChainVoting/backend')
from app.services.blockchain import BlockchainClient
import oqs

# 1. Read backend/issuer_sk.hex
sk_path = 'd:/BlockChainVoting/backend/issuer_sk.hex'
with open(sk_path, 'r') as f:
    sk = bytes.fromhex(f.read().strip())

# 2. Import it
with oqs.Signature('ML-DSA-65', secret_key=sk) as sig:
    try:
        pk = sig.export_public_key()
    except AttributeError:
        pk = None
        pk_hash = "Could not derive (AttributeError)"
    
if pk:
    # 4. Compute SHA3-256(public_key) and Base64 encode the hash
    sha3_256 = hashlib.sha3_256()
    sha3_256.update(pk)
    pk_hash = base64.b64encode(sha3_256.digest()).decode('utf-8')

# 5. Query Code ID 5 for issuer_key_id = "university_admin_2"
client = BlockchainClient()
import asyncio
try:
    res = asyncio.run(client.get_issuer_key("university_admin_2"))
    if not res:
        print("Issuer not found on chain")
        sys.exit(1)
    on_chain_pk = res["public_key"]
    sha3_256_onchain = hashlib.sha3_256()
    sha3_256_onchain.update(on_chain_pk)
    on_chain_pk_hash = base64.b64encode(sha3_256_onchain.digest()).decode('utf-8')
except Exception as e:
    print(f"Error querying contract: {e}")
    sys.exit(1)

print(f"runtime public-key hash: {pk_hash}")
print(f"on-chain public-key hash: {on_chain_pk_hash}")
print(f"public keys match: {pk == on_chain_pk}")

# 6. Issue a fresh demo credential
try:
    response = requests.post("http://localhost:8000/api/v1/demo/credentials")
    if response.status_code != 200:
        print(f"Failed to issue credential: {response.text}")
        sys.exit(1)
except requests.exceptions.ConnectionError:
    print("Backend server is not running or accessible at localhost:8000")
    sys.exit(1)

cred_data = response.json()
payload = cred_data["credential"]
signature_b64 = cred_data["credential_signature_b64"]
signature = base64.b64decode(signature_b64)

from app.services.credentials import serialize_credential_payload
message = serialize_credential_payload(payload)

# Verify against runtime public key
if pk:
    with oqs.Signature('ML-DSA-65') as verifier:
        try:
            runtime_valid = verifier.verify(message, signature, pk)
        except Exception as e:
            runtime_valid = False
else:
    runtime_valid = "Skipped (no pk)"

# Verify against on-chain public key
with oqs.Signature('ML-DSA-65') as verifier:
    try:
        onchain_valid = verifier.verify(message, signature, on_chain_pk)
    except Exception as e:
        onchain_valid = False

print(f"runtime signature verification passes: {runtime_valid}")
print(f"on-chain signature verification passes: {onchain_valid}")
