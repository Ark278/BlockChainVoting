import os
import sys
import json
import base64
import asyncio
import hashlib

sys.path.append('d:/BlockChainVoting/backend')
from app.api import app
from app.services.credentials import serialize_credential_payload, verify_credential
from app.services.blockchain import BlockchainClient
from fastapi.testclient import TestClient
import oqs

def main():
    # 9. Issue a fresh credential
    client = TestClient(app)
    response = client.post("/api/v1/demo/credentials")
    if response.status_code != 200:
        print(f"Failed to issue credential: {response.text}")
        sys.exit(1)
        
    cred_data = response.json()
    payload = cred_data["credential"]
    signature_b64 = cred_data["credential_signature_b64"]
    signature = base64.b64decode(signature_b64)
    
    # 10. Verify its signature against the generation-time pk
    # Load generation time pk
    with open("d:/BlockChainVoting/backend/issuer_pk_university_admin_3.hex", "r") as f:
        pk = bytes.fromhex(f.read().strip())
        
    message = serialize_credential_payload(payload)
    
    with oqs.Signature('ML-DSA-65') as verifier:
        try:
            gen_pk_valid = verifier.verify(message, signature, pk)
        except Exception as e:
            gen_pk_valid = False
            print(f"gen_pk verification error: {e}")
            
    print(f"Signature verified against generation-time pk: {gen_pk_valid}")
    
    # 11. Verify the same signature against the public key queried from the ACTIVE contract
    async def get_onchain_pk():
        bc_client = BlockchainClient()
        return await bc_client.get_issuer_key("university_admin_3")
        
    res = asyncio.run(get_onchain_pk())
    onchain_pk = res["public_key"]
    
    with oqs.Signature('ML-DSA-65') as verifier:
        try:
            onchain_pk_valid = verifier.verify(message, signature, onchain_pk)
        except Exception as e:
            onchain_pk_valid = False
            print(f"onchain_pk verification error: {e}")
            
    print(f"Signature verified against on-chain pk: {onchain_pk_valid}")
    
    # 12. Call the application's verify_credential() function
    async def run_verify_credential():
        from app.api import CredentialPayloadSchema
        
        class MockRepo:
            async def is_revoked(self, *args, **kwargs):
                return False
                
        canonical_cred = serialize_credential_payload(payload)
        bc_client = BlockchainClient()
        rev_repo = MockRepo()
        return await verify_credential(
            credential_payload_bytes=canonical_cred,
            signature=signature,
            blockchain_client=bc_client,
            revocation_repo=rev_repo,
        )
        
    verify_func_result = asyncio.run(run_verify_credential())
    print(f"verify_credential() function returns success: {verify_func_result}")
    
    # 13. Make sure university_admin_2 remains unchanged
    async def get_onchain_pk_2():
        bc_client = BlockchainClient()
        return await bc_client.get_issuer_key("university_admin_2")
        
    res2 = asyncio.run(get_onchain_pk_2())
    print(f"university_admin_2 still exists: {res2 is not None}")
    if res2:
        pk2 = res2["public_key"]
        print(f"university_admin_2 public key hash: {base64.b64encode(res2['public_key_hash']).decode()}")

if __name__ == "__main__":
    main()
