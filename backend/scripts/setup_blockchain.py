import asyncio
import subprocess
import json
import base64
import os
import hashlib
from dotenv import load_dotenv
import oqs

load_dotenv(".env.e2e")
CONTRACT_ADDR = os.environ["VOTING_CONTRACT_ADDRESS"]

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
        print(f"Executed tx: {txhash}")
        # Wait for inclusion
        await asyncio.sleep(6)
        return txhash
    except Exception as e:
        raise Exception(f"Failed to parse stdout: {stdout.decode()} {e}")

async def main():
    print("Setting up real blockchain...")
    
    # 1. Register Issuer Key (ML-DSA-65)
    with oqs.Signature("ML-DSA-65") as sig:
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
    
    with open("issuer_sk.hex", "w") as f:
        f.write(sk.hex())
        
    pk_b64 = base64.b64encode(pk).decode()
    pk_hash = hashlib.sha3_256(pk).digest()
    pk_hash_b64 = base64.b64encode(pk_hash).decode()
    
    msg_issuer = {
        "register_issuer_key": {
            "issuer_key_id": "university_admin_2",
            "public_key": pk_b64,
            "public_key_hash": pk_hash_b64
        }
    }
    try:
        await execute_tx(msg_issuer)
    except Exception as e:
        print(f"Issuer key might already exist: {e}")
    
    # Election already created.
    
    print("Blockchain setup complete!")

if __name__ == "__main__":
    asyncio.run(main())
