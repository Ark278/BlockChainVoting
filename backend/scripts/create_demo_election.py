import asyncio
import os
import json
import base64
import hashlib
import oqs
import subprocess
from dotenv import load_dotenv

load_dotenv(".env")
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
        await asyncio.sleep(6)
        return txhash
    except Exception as e:
        raise Exception(f"Failed to parse stdout: {stdout.decode()} {e}")

async def main():
    print("Generating ML-KEM-768 keypair for new election...")
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        
    with open("election_sk.hex", "w") as f:
        f.write(sk.hex())
        
    pk_b64 = base64.b64encode(pk).decode()
    pk_hash = hashlib.sha3_256(pk).digest()
    pk_hash_b64 = base64.b64encode(pk_hash).decode()
    
    msg1 = {
        "create_election": {
            "election_id": 13,
            "params": {
                "name": "Blockchain Voting Demo Election",
                "description": "Privacy-preserving blockchain voting demonstration"
            },
            "kem_pk": pk_b64,
            "kem_pk_hash": pk_hash_b64
        }
    }
    print("Creating Election 13 on-chain...")
    await execute_tx(msg1)
    
    msg2 = {"open_registration": {"election_id": 13}}
    print("Opening Registration...")
    await execute_tx(msg2)
    
    msg_reg1 = {"register_candidate": {"election_id": 13, "candidate": "Alice"}}
    print("Registering Alice...")
    await execute_tx(msg_reg1)
    
    msg_reg2 = {"register_candidate": {"election_id": 13, "candidate": "Bob"}}
    print("Registering Bob...")
    await execute_tx(msg_reg2)
    
    msg3 = {"open_voting": {"election_id": 13}}
    print("Opening Voting...")
    await execute_tx(msg3)
    
    print("Done! Election 13 created, opened, and election_sk.hex saved.")

if __name__ == "__main__":
    asyncio.run(main())
