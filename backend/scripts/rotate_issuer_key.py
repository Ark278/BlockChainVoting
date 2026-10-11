"""One-shot ML-DSA-65 issuer-key rotation for the demo.

This script:
  1. Reads the runtime backend `.env` to determine the ACTIVE contract.
  2. Sanity-checks the active contract is NOT the old Code ID 1 contract.
  3. Generates a brand-new ML-DSA-65 keypair with liboqs-python
     (`generate_keypair()` returns the public key; `export_secret_key()` returns
     the secret key).  The public key returned by `generate_keypair()` is
     captured at generation time — liboqs-python 0.16.0 has no
     `export_public_key()`.
  4. Writes the secret key to `backend/issuer_sk_university_admin_3.hex`
     (backend-only) and the public key to
     `backend/issuer_pk_university_admin_3.hex` (public — needed for
     independent signature verification; liboqs-python 0.16.0 cannot derive
     the public key from the secret key later).
  5. Registers the public key + SHA3-256 hash under the new issuer key ID
     `university_admin_3` on the ACTIVE contract via `wasmd tx wasm execute`.
  6. Verifies the registration via `get_issuer_key("university_admin_3")` and
     confirms SHA3-256(public_key) == stored public_key_hash.

The old issuer key (`university_admin_2`) and its secret key file are left
untouched.  Secret key material is never printed.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from dotenv import load_dotenv

import oqs  # liboqs-python (ML-DSA-65 / ML-KEM-768)

BACKEND_DIR = Path(__file__).resolve().parents[1]
RUNTIME_ENV = BACKEND_DIR / ".env"   # the ACTUAL backend runtime configuration
OLD_CODE_ID = "1"                     # legacy "voting" contract (Code ID 1)
NEW_ISSUER_KEY_ID = "university_admin_3"
NEW_SK_FILE = BACKEND_DIR / "issuer_sk_university_admin_3.hex"
NEW_PK_FILE = BACKEND_DIR / "issuer_pk_university_admin_3.hex"

WASMD_CONTAINER = "blockchainvoting-wasmd-1"
TX_FROM = "validator"
KEYRING = "test"
CHAIN_ID = "testing"


def load_runtime_config() -> tuple[str, str]:
    load_dotenv(RUNTIME_ENV)
    contract = os.environ.get("VOTING_CONTRACT_ADDRESS", "").strip()
    rest = os.environ.get("CHAIN_REST_URL", "http://127.0.0.1:1317").strip()
    if not contract:
        raise SystemExit("VOTING_CONTRACT_ADDRESS missing in backend/.env")
    return contract, rest


def cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the wasmd CLI inside the docker container."""
    return subprocess.run(
        ["docker", "exec", WASMD_CONTAINER, "wasmd", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )


def query_contract_info(contract: str) -> dict:
    cmd = ["q", "wasm", "contract", contract, "--output", "json"]
    p = cli(*cmd)
    if p.returncode != 0:
        raise SystemExit(f"contract info query failed: {p.stderr.strip()}")
    return json.loads(p.stdout)


def get_contract_code_id(contract: str) -> str:
    info = query_contract_info(contract)
    return str(info["contract_info"]["code_id"])


def query_issuer_key(contract: str, issuer_id: str) -> dict | None:
    q = json.dumps({"get_issuer_key": {"issuer_key_id": issuer_id}})
    p = cli("q", "wasm", "contract-state", "smart", contract, q, "--output", "json")
    if p.returncode != 0:
        raise SystemExit(f"get_issuer_key query failed: {p.stderr.strip()}")
    data = json.loads(p.stdout).get("data")
    return data


def execute_tx(contract: str, msg: dict) -> str:
    """Broadcast `register_issuer_key` via the validator account."""
    msg_str = json.dumps(msg)
    p = cli(
        "tx", "wasm", "execute", contract, msg_str,
        "--from", TX_FROM, "--keyring-backend", KEYRING,
        "-y", "--output", "json", "--gas", "auto",
        "--gas-adjustment", "1.5", "--chain-id", CHAIN_ID,
    )
    if p.returncode != 0:
        raise SystemExit(f"tx broadcast failed: {p.stderr.strip()}")
    data = json.loads(p.stdout)
    if data.get("code", 0) != 0:
        raise SystemExit(f"chain rejection: {data.get('raw_log')}")
    txhash = data.get("txhash")
    if not txhash:
        raise SystemExit(f"tx returned no txhash: {p.stdout}".strip())
    return txhash


async def wait_for_block() -> None:
    await asyncio.sleep(6)


def generate_new_signature_keypair() -> tuple[bytes, bytes]:
    """Generate a NEW ML-DSA-65 keypair.

    Returns (public_key, secret_key).  The public key is the value returned
    directly by `generate_keypair()`.  Secret key bytes are only written to the
    private key file via the caller — never printed.
    """
    with oqs.Signature("ML-DSA-65") as sig:
        public_key = sig.generate_keypair()      # captured at generation time
        secret_key = sig.export_secret_key()
    if len(public_key) != 1952:
        raise SystemExit(f"unexpected ML-DSA-65 pk length: {len(public_key)}")
    if len(secret_key) != 4032:
        raise SystemExit(f"unexpected ML-DSA-65 sk length: {len(secret_key)}")
    return public_key, secret_key


async def main() -> None:
    contract, _rest = load_runtime_config()
    print(f"Runtime contract (backend/.env): {contract}")
    txhash: str | None = None

    code_id = get_contract_code_id(contract)
    print(f"Active contract code ID:        {code_id}")
    if code_id == OLD_CODE_ID:
        raise SystemExit(
            "REFUSING to rotate on the old Code ID 1 contract. "
            "Update backend/.env VOTING_CONTRACT_ADDRESS to the current contract."
        )
    if code_id not in {"4", "5"}:
        print(f"WARNING: code ID {code_id} is not 4/5; continuing on the runtime contract only.")

    # Step 1–2: generate a fresh keypair and write key files.
    onchain_existing = query_issuer_key(contract, NEW_ISSUER_KEY_ID)
    if NEW_SK_FILE.exists() and NEW_PK_FILE.exists() and onchain_existing is not None:
        # Idempotent re-run: reuse the persisted pair and confirm it matches on-chain.
        public_key = bytes.fromhex(NEW_PK_FILE.read_text().strip())
        secret_key = bytes.fromhex(NEW_SK_FILE.read_text().strip())
        onchain_pk = base64.b64decode(onchain_existing["public_key"])
        onchain_hash = base64.b64decode(onchain_existing["public_key_hash"])
        computed_hash = hashlib.sha3_256(public_key).digest()
        if (
            public_key == onchain_pk
            and computed_hash == onchain_hash
            and len(secret_key) == 4032
        ):
            print(f"Reusing existing {NEW_ISSUER_KEY_ID} key files; on-chain registration already matches.")
            txhash = "<already registered>"
        else:
            raise SystemExit("Existing key files do not match on-chain registration; refusing to clobber.")
    else:
        public_key, secret_key = generate_new_signature_keypair()
        NEW_SK_FILE.write_text(secret_key.hex() + "\n")
        print(f"Secret key written (backend only): {NEW_SK_FILE.name} "
              f"({len(secret_key)} bytes) — contents not printed.")
        NEW_PK_FILE.write_text(public_key.hex() + "\n")
        print(f"Public key written (public):      {NEW_PK_FILE.name} "
              f"({len(public_key)} bytes).")

    # Key integrity auto-check: sign/verify with the in-memory pair.
    probe = b"issuer-key-rotation-probe"
    with oqs.Signature("ML-DSA-65", secret_key) as sig:
        probe_sig = sig.sign(probe)
    with oqs.Signature("ML-DSA-65") as verifier:
        self_roundtrip = verifier.verify(probe, probe_sig, public_key)
    print(f"Self-generate sign/verify roundtrip: {'OK' if self_roundtrip else 'FAIL'}")

    # Step 3: register under the new issuer key ID on the ACTIVE contract.
    pk_hash = hashlib.sha3_256(public_key).digest()
    if txhash is None:
        print(f"Registering {NEW_ISSUER_KEY_ID} on {contract} ...")
        action = "register_issuer_key" if onchain_existing is None else "rotate_issuer_key"
        msg = {
            action: {
                "issuer_key_id": NEW_ISSUER_KEY_ID,
                "public_key": base64.b64encode(public_key).decode(),
                "public_key_hash": base64.b64encode(pk_hash).decode(),
            }
        }
        txhash = execute_tx(contract, msg)
        await wait_for_block()
        print(f"Issuer registration tx hash:     {txhash}")

    # Step 3 (verify): read it back from the chain.
    onchain = query_issuer_key(contract, NEW_ISSUER_KEY_ID)
    if onchain is None:
        raise SystemExit(f"{NEW_ISSUER_KEY_ID} not found on-chain after registration")

    onchain_pk = base64.b64decode(onchain["public_key"])
    onchain_hash = base64.b64decode(onchain["public_key_hash"])

    # Step 4 (verify): SHA3-256(public_key) == stored public_key_hash.
    computed_hash = hashlib.sha3_256(onchain_pk).digest()
    print(f"New public key SHA3-256:        {computed_hash.hex()}")
    print(f"Stored public_key_hash:         {onchain_hash.hex()}")
    if computed_hash != onchain_hash:
        raise SystemExit("hash mismatch: stored public_key_hash != SHA3-256(public_key)")
    if onchain_pk != public_key:
        raise SystemExit("registered public key differs from generated public key")
    print(f"get_issuer_key({NEW_ISSUER_KEY_ID})       : registration verified")
    print(f"SHA3-256(pk) == stored hash    : OK")


if __name__ == "__main__":
    asyncio.run(main())