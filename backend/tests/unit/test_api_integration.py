import base64
import hashlib
import uuid
from datetime import UTC, datetime, timedelta

import oqs
import pytest
from httpx import ASGITransport, AsyncClient

from app.api import app
from app.db.session import drop_db, init_db
from app.services.credentials import (
    CredentialPayload,
    serialize_credential_payload,
    verify_credential,
)


# Mock DB and Repositories
class MockRevocationRepo:
    def __init__(self):
        self.revoked = set()
    async def is_revoked(self, credential_id: str) -> bool:
        return credential_id in self.revoked

class MockBlockchainClient:
    def __init__(self):
        self.issuer_keys = {}
        self.kems = {}
        self.used_nullifiers = set()
        self.submitted_commitments = []
    async def get_issuer_key(self, issuer_key_id: str):
        return self.issuer_keys.get(issuer_key_id)
    async def get_election_kem_pk(self, election_id: int):
        return self.kems.get(election_id)
    async def nullifier_used(self, election_id: int, nullifier_hash_b64: str) -> bool:
        return (election_id, nullifier_hash_b64) in self.used_nullifiers
    async def submit_commitment(self, election_id, commitment_hash_b64, nullifier_hash_b64, sender_address=None):
        self.submitted_commitments.append((election_id, commitment_hash_b64, nullifier_hash_b64))
        return "tx_hash_mock"


@pytest.fixture
async def setup_db():
    await init_db()
    yield
    await drop_db()


@pytest.mark.asyncio
async def test_credential_verification():
    with oqs.Signature("ML-DSA-65") as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
    
        cred = {
            "credential_id": str(uuid.uuid4()),
            "issued_at": datetime.now(UTC).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            "attributes": {},
            "issuer_key_id": "issuer1"
        }
        canonical = serialize_credential_payload(cred)
        signature = sig.sign(canonical)
        
    blockchain = MockBlockchainClient()
    blockchain.issuer_keys["issuer1"] = {
        "public_key": pk,
        "public_key_hash": hashlib.sha3_256(pk).digest()
    }
    repo = MockRevocationRepo()
    
    # Correct key
    res = await verify_credential(canonical, signature, blockchain, repo)
    assert isinstance(res, CredentialPayload)
    
    # Wrong issuer key hash
    blockchain.issuer_keys["issuer1"]["public_key_hash"] = b"wronghash"
    with pytest.raises(Exception, match="integrity check failed"):
        await verify_credential(canonical, signature, blockchain, repo)
    blockchain.issuer_keys["issuer1"]["public_key_hash"] = hashlib.sha3_256(pk).digest()
    
    # Invalid signature
    with pytest.raises(Exception, match="signature verification failed"):
        await verify_credential(canonical, b"x"*len(signature), blockchain, repo)
        
    # Expired credential
    cred["expires_at"] = (datetime.now(UTC) - timedelta(days=1)).isoformat()
    canonical_exp = serialize_credential_payload(cred)
    with oqs.Signature("ML-DSA-65", secret_key=sk) as sig:
        sig_exp = sig.sign(canonical_exp)
    with pytest.raises(Exception, match="expired"):
        await verify_credential(canonical_exp, sig_exp, blockchain, repo)
        
    # Revoked credential
    repo.revoked.add(cred["credential_id"])
    with pytest.raises(Exception, match="revoked"):
        await verify_credential(canonical, signature, blockchain, repo)


@pytest.mark.asyncio
async def test_api_submit_ballot(setup_db):
    app.dependency_overrides.clear()
    
    blockchain = MockBlockchainClient()
    repo = MockRevocationRepo()
    
    from app.api import get_blockchain_client, get_revocation_repo
    app.dependency_overrides[get_blockchain_client] = lambda: blockchain
    app.dependency_overrides[get_revocation_repo] = lambda: repo
    
    with oqs.Signature("ML-DSA-65") as sig:
        dsa_pk = sig.generate_keypair()
        blockchain.issuer_keys["issuer1"] = {
            "public_key": dsa_pk,
            "public_key_hash": hashlib.sha3_256(dsa_pk).digest()
        }
    
        cred = {
            "credential_id": str(uuid.uuid4()),
            "issued_at": datetime.now(UTC).isoformat(),
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
            "attributes": {},
            "issuer_key_id": "issuer1"
        }
        canonical = serialize_credential_payload(cred)
        signature = sig.sign(canonical)
        
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        kem_pk = kem.generate_keypair()
    blockchain.kems[1] = (kem_pk, hashlib.sha3_256(kem_pk).digest())
        
    payload = {
        "election_id": 1,
        "credential": cred,
        "credential_signature_b64": base64.b64encode(signature).decode(),
        "ballot_plaintext": {"choice": "A"}
    }
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # First submission
        response = await ac.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": "key1"})
        assert response.status_code == 202
        assert response.json()["status"] == "success"
        
        # Idempotency: same key + same request -> returns same result
        response2 = await ac.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": "key1"})
        assert response2.status_code == 202
        assert response2.json()["ballot_id"] == response.json()["ballot_id"]
        
        # Idempotency: same key + different request -> fails
        payload2 = payload.copy()
        payload2["ballot_plaintext"] = {"choice": "B"}
        response3 = await ac.post("/api/v1/ballots/submit", json=payload2, headers={"Idempotency-Key": "key1"})
        assert response3.status_code == 409
        
        # Duplicate nullifier (different idempotency key)
        response4 = await ac.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": "key2"})
        assert response4.status_code == 409
        assert "already been submitted" in response4.json()["detail"]

@pytest.mark.asyncio
async def test_api_list_elections(setup_db):
    app.dependency_overrides.clear()
    
    blockchain = MockBlockchainClient()
    from app.api import get_blockchain_client
    app.dependency_overrides[get_blockchain_client] = lambda: blockchain
    
    async def mock_list_elections():
        return [{"id": 1, "name": "Test"}]
    blockchain.list_elections = mock_list_elections
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/v1/elections")
        assert response.status_code == 200
        assert response.json() == [{"id": 1, "name": "Test"}]

@pytest.mark.asyncio
async def test_api_get_election(setup_db):
    app.dependency_overrides.clear()
    
    blockchain = MockBlockchainClient()
    from app.api import get_blockchain_client
    app.dependency_overrides[get_blockchain_client] = lambda: blockchain
    
    async def mock_get_election(election_id):
        if election_id == 1:
            return {"id": 1, "name": "Test Election"}
        return None
    blockchain.get_election = mock_get_election
    
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        response = await ac.get("/api/v1/elections/1")
        assert response.status_code == 200
        assert response.json() == {"id": 1, "name": "Test Election"}
        
        response = await ac.get("/api/v1/elections/99")
        assert response.status_code == 404

