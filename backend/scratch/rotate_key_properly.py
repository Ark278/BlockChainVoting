import os
import sys
import json
import base64
import asyncio
import subprocess
import hashlib
import requests

sys.path.append('d:/BlockChainVoting/backend')
import oqs

CONTRACT_ADDR = "wasm1eyfccmjm6732k7wp4p6gdjwhxjwsvje44j0hfx8nkgrm8fs7vqfsuw7sel"

async def execute_tx(msg: dict):
    msg_str = json.dumps(msg)
    cmd = [
        "docker", "exec", "blockchainvoting-wasmd-1", "wasmd", "tx", "wasm", "execute", 
        CONTRACT_ADDR, msg_str, "--from", "validator", "--keyring-backend", "test",
        "-y", "--output", "json", "--gas", "auto", "--gas-adjustment", "1.5",
        "--chain-id", "testing"
    ]
    proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        raise Exception(f"Failed to execute tx: {stderr.decode()}")
    try:
        data = json.loads(stdout.decode())
        txhash = data["txhash"]
        # Wait for inclusion
        await asyncio.sleep(6)
        return txhash
    except Exception as e:
        raise Exception(f"Failed to parse stdout: {stdout.decode()} {e}")

async def main():
    print("Generating fresh ML-DSA-65 keypair...")
    with oqs.Signature("ML-DSA-65") as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        
    sk_file = "d:/BlockChainVoting/backend/issuer_sk_university_admin_3.hex"
    with open(sk_file, "w") as f:
        f.write(sk.hex())
    print("Saved sk to", sk_file)
    
    # Write pk to a temporary file for the next step so we can verify the credential locally
    with open("d:/BlockChainVoting/backend/scratch/pk_admin3.hex", "w") as f:
        f.write(pk.hex())
    
    pk_b64 = base64.b64encode(pk).decode()
    pk_hash = hashlib.sha3_256(pk).digest()
    pk_hash_b64 = base64.b64encode(pk_hash).decode()
    
    msg_issuer = {
        "register_issuer_key": {
            "issuer_key_id": "university_admin_3",
            "public_key": pk_b64,
            "public_key_hash": pk_hash_b64
        }
    }
    print("Registering issuer on contract...")
    try:
        txhash = await execute_tx(msg_issuer)
        print(f"Issuer registered. Tx hash: {txhash}")
    except Exception as e:
        print(f"Issuer registration failed or already exists: {e}")
        
    print("Verifying on-chain storage...")
    from app.services.blockchain import BlockchainClient
    client = BlockchainClient()
    res = await client.get_issuer_key("university_admin_3")
    if not res:
        print("Issuer university_admin_3 not found on chain!")
        sys.exit(1)
        
    stored_pk = res["public_key"]
    stored_hash = res["public_key_hash"]
    
    print(f"stored public_key == generation-time pk: {stored_pk == pk}")
    
    calc_hash = hashlib.sha3_256(stored_pk).digest()
    print(f"SHA3-256(stored public_key) == stored public_key_hash: {calc_hash == stored_hash}")
    print(f"Stored public-key hash: {base64.b64encode(stored_hash).decode()}")

if __name__ == "__main__":
    asyncio.run(main())
