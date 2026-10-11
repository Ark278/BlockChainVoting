"""Post-rotation end-to-end credential verification.

Steps:
  1. POST /api/v1/demo/credentials on the live FastAPI backend.
  2. Independently verify the returned signature with liboqs against:
       (a) the newly generated public key (issuer_pk_university_admin_3.hex)
       (b) the public key read from the CURRENT active contract
  3. Verify the same credential through the application's existing
     `verify_credential()` path using the real BlockchainClient and
     RevocationRepository.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
from pathlib import Path

import httpx
import oqs

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BACKEND_DIR / ".env")

CONTRACT_ADDR = os.environ["VOTING_CONTRACT_ADDRESS"]
ISSUER_KEY_ID = "university_admin_3"
PK_FILE = BACKEND_DIR / "issuer_pk_university_admin_3.hex"
API_URL = "http://127.0.0.1:8000"
WASMD_CONTAINER = "blockchainvoting-wasmd-1"


def serialize_credential_payload(cred: dict) -> bytes:
    return json.dumps(cred, sort_keys=True, separators=(",", ":")).encode("utf-8")


def query_onchain_issuer_key(issuer_id: str) -> dict:
    q = json.dumps({"get_issuer_key": {"issuer_key_id": issuer_id}})
    p = subprocess.run(
        ["docker", "exec", WASMD_CONTAINER, "wasmd", "q", "wasm",
         "contract-state", "smart", CONTRACT_ADDR, q, "--output", "json"],
        capture_output=True, text=True, check=False,
    )
    if p.returncode != 0:
        raise RuntimeError(f"query failed: {p.stderr.strip()}")
    return json.loads(p.stdout)["data"]


async def issue_demo_credential() -> dict:
    async with httpx.AsyncClient(base_url=API_URL, timeout=30.0) as client:
        resp = await client.post("/api/v1/demo/credentials")
        resp.raise_for_status()
        return resp.json()


async def main() -> None:
    print(f"Active contract (backend/.env): {CONTRACT_ADDR}")

    # ── 1. Issue through the actual FastAPI endpoint ──────────────────────────
    cred_res = await issue_demo_credential()
    cred = cred_res["credential"]
    signature = base64.b64decode(cred_res["credential_signature_b64"])
    canonical = serialize_credential_payload(cred)

    print(f"Credential ID:                 {cred['credential_id']}")
    print(f"Credential issuer_key_id:      {cred['issuer_key_id']}")
    assert cred["issuer_key_id"] == ISSUER_KEY_ID, "credential not issued under university_admin_3"

    # ── 2a. Verify against the newly generated public key ─────────────────────
    generated_pk = bytes.fromhex(PK_FILE.read_text().strip())
    with oqs.Signature("ML-DSA-65") as verifier:
        ok_generated = verifier.verify(canonical, signature, generated_pk)
    print(f"Signature valid vs generated public key: {ok_generated}")

    # ── 2b. Verify against the public key from the current contract ───────────
    onchain = query_onchain_issuer_key(ISSUER_KEY_ID)
    onchain_pk = base64.b64decode(onchain["public_key"])
    onchain_hash = base64.b64decode(onchain["public_key_hash"])
    with oqs.Signature("ML-DSA-65") as verifier:
        ok_onchain = verifier.verify(canonical, signature, onchain_pk)
    print(f"Signature valid vs on-chain public key:   {ok_onchain}")

    # Confirm hash integrity of the on-chain key (SHA3-256).
    computed = hashlib.sha3_256(onchain_pk).digest()
    hash_ok = computed == onchain_hash
    print(f"Sha3-256(on-chain pk) == stored hash:     {hash_ok}")
    print(f"Generated pk == on-chain pk:              {generated_pk == onchain_pk}")

    assert ok_generated, "signature did not verify against generated public key"
    assert ok_onchain, "signature did not verify against on-chain public key"
    assert hash_ok, "on-chain public_key_hash mismatch"

    # ── 3. Application verify_credential() path (real clients) ─────────────────
    from app.db.session import get_db
    from app.services.blockchain import BlockchainClient
    from app.services.credentials import verify_credential
    from app.services.revocation import RevocationRepository

    async for session in get_db():
        blockchain = BlockchainClient()
        try:
            repo = RevocationRepository(session)
            payload = await verify_credential(
                credential_payload_bytes=canonical,
                signature=signature,
                blockchain_client=blockchain,
                revocation_repo=repo,
            )
        finally:
            await blockchain.close()

    print(f"verify_credential() path:      OK (issuer_key_id={payload.issuer_key_id})")
    assert payload.issuer_key_id == ISSUER_KEY_ID


if __name__ == "__main__":
    asyncio.run(main())