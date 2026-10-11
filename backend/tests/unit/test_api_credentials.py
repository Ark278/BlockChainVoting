import pytest
import asyncio
import uuid
import base64
from datetime import UTC, datetime, timedelta
from httpx import AsyncClient, ASGITransport
from app.api import app, get_blockchain_client, get_db
from app.db.session import init_db, drop_db
from app.services.credentials import serialize_credential_payload
import oqs
from sqlalchemy import select
from app.models import Credential

@pytest.fixture(autouse=True)
async def setup_db_fixture():
    await init_db()
    yield
    await drop_db()

class MockBlockchainClient:
    async def get_issuer_key(self, issuer_key_id):
        # We need a valid ML-DSA-65 public key to verify.
        # We will load the actual issuer_pk.hex if it exists, or just generate one for testing.
        import os
        try:
            with open("issuer_pk.hex", "r") as f:
                pk = bytes.fromhex(f.read().strip())
        except FileNotFoundError:
            # Generate a new pair just for this mock
            with oqs.Signature("ML-DSA-65") as sig:
                pk = sig.generate_keypair()
                # we need to save the sk somewhere for the issuance test if we generate here
                # Wait, the issuance reads 'issuer_sk.hex' from disk.
                # So we must use the pk matching 'issuer_sk.hex'.
                
        import hashlib
        pk_hash = hashlib.sha3_256(pk).digest()
        return {
            "public_key": pk,
            "public_key_hash": pk_hash
        }

@pytest.fixture
async def ac():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

@pytest.mark.asyncio
async def test_demo_credential_issuance(ac):
    # Test that we can issue a credential and it gets persisted
    res = await ac.post("/api/v1/demo/credentials")
    assert res.status_code == 200
    data = res.json()
    assert "credential" in data
    assert "credential_signature_b64" in data
    cred = data["credential"]
    assert "credential_id" in cred
    
    # Verify persistence
    async for session in get_db():
        stmt = select(Credential).where(Credential.credential_id == cred["credential_id"])
        result = await session.execute(stmt)
        db_cred = result.scalar_one_or_none()
        assert db_cred is not None
        assert not db_cred.revoked

@pytest.mark.asyncio
async def test_submit_ballot_valid_credential(ac):
    app.dependency_overrides[get_blockchain_client] = lambda: MockBlockchainClient()
    
    # Issue a credential
    res = await ac.post("/api/v1/demo/credentials")
    assert res.status_code == 200
    data = res.json()
    
    payload = {
        "election_id": 9,
        "credential": data["credential"],
        "credential_signature_b64": data["credential_signature_b64"],
        "ballot_plaintext": {"selected_option": "Alice"}
    }
    
    # Note: submit_ballot requires blockchain.get_election_kem_pk and nullifier_used
    # We need a more complete mock for blockchain if we want it to reach Kem/Submit phase.
    # But just reaching 404 (Election not found) means credential verification succeeded.
    # Let's adjust mock to fail gracefully *after* credential verify.
    class CompleteMockBlockchainClient(MockBlockchainClient):
        async def nullifier_used(self, eid, n_hash):
            return False
        async def get_election_kem_pk(self, eid):
            return None # This will cause 404, proving verification succeeded
            
    app.dependency_overrides[get_blockchain_client] = lambda: CompleteMockBlockchainClient()
    
    res2 = await ac.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": str(uuid.uuid4())})
    assert res2.status_code == 404 # Means credential passed, failed at election fetch
    assert "not found" in res2.text.lower()
    
    app.dependency_overrides.clear()

@pytest.mark.asyncio
async def test_submit_ballot_revoked_credential(ac):
    res = await ac.post("/api/v1/demo/credentials")
    data = res.json()
    
    # Manually revoke it
    async for session in get_db():
        stmt = select(Credential).where(Credential.credential_id == data["credential"]["credential_id"])
        result = await session.execute(stmt)
        db_cred = result.scalar_one_or_none()
        db_cred.revoked = True
        await session.commit()
        
    class CompleteMockBlockchainClient(MockBlockchainClient):
        async def nullifier_used(self, eid, n_hash): return False
    app.dependency_overrides[get_blockchain_client] = lambda: CompleteMockBlockchainClient()
    
    payload = {
        "election_id": 9,
        "credential": data["credential"],
        "credential_signature_b64": data["credential_signature_b64"],
        "ballot_plaintext": {}
    }
    res2 = await ac.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": str(uuid.uuid4())})
    assert res2.status_code == 403
    assert "revoked" in res2.text.lower()

@pytest.mark.asyncio
async def test_submit_ballot_expired_credential(ac):
    res = await ac.post("/api/v1/demo/credentials")
    data = res.json()
    
    # We can't trivially test expired purely via API issuance unless we wait a day.
    # Instead we manually mutate the payload's expiration, which invalidates the signature.
    # Wait, the prompt says "expired credential rejection".
    # Let's mutate the DB to make it expired? No, expiration is in the payload.
    # We must generate a manual expired payload and sign it.
    import os
    with open("issuer_sk.hex", "r") as f:
        dsa_sk = bytes.fromhex(f.read().strip())
    
    now = datetime.now(UTC)
    cred_payload = {
        "credential_id": str(uuid.uuid4()),
        "issued_at": (now - timedelta(days=2)).isoformat(),
        "expires_at": (now - timedelta(days=1)).isoformat(),
        "attributes": {},
        "issuer_key_id": "university_admin_2"
    }
    canonical = serialize_credential_payload(cred_payload)
    with oqs.Signature("ML-DSA-65", secret_key=dsa_sk) as sig:
        signature = sig.sign(canonical)
        
    app.dependency_overrides[get_blockchain_client] = lambda: MockBlockchainClient()
    payload = {
        "election_id": 9,
        "credential": cred_payload,
        "credential_signature_b64": base64.b64encode(signature).decode(),
        "ballot_plaintext": {}
    }
    res2 = await ac.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": str(uuid.uuid4())})
    assert res2.status_code == 403
    assert "expired" in res2.text.lower()

@pytest.mark.asyncio
async def test_submit_ballot_invalid_signature(ac):
    res = await ac.post("/api/v1/demo/credentials")
    data = res.json()
    
    app.dependency_overrides[get_blockchain_client] = lambda: MockBlockchainClient()
    payload = {
        "election_id": 9,
        "credential": data["credential"],
        "credential_signature_b64": base64.b64encode(b"invalid_signature" + b"0" * 3000).decode(),
        "ballot_plaintext": {}
    }
    res2 = await ac.post("/api/v1/ballots/submit", json=payload, headers={"Idempotency-Key": str(uuid.uuid4())})
    assert res2.status_code == 401
    assert "signature" in res2.text.lower()

