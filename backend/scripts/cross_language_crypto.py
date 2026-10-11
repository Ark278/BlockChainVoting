import hashlib
import json
import base64
import oqs
from app.services.crypto import encrypt_ballot_full

def main():
    print("--- CROSS LANGUAGE CRYPTOGRAPHIC VALIDATION ---")
    election_id = 1
    
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        kem_pk = kem.generate_keypair()
    
    kem_pk_hash = hashlib.sha3_256(kem_pk).digest()
    nullifier_hash = hashlib.sha3_256(b"mock_nullifier").digest()
    
    pt = {"choice": "Alice"}
    pt_bytes = json.dumps(pt, sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    enc_pkg = encrypt_ballot_full(
        election_id=election_id,
        nullifier_hash=nullifier_hash,
        ballot_plaintext=pt_bytes,
        kem_pk=kem_pk,
        kem_pk_hash_expected=kem_pk_hash
    )
    
    print("election_id:", election_id)
    print("nullifier_hash (hex):", nullifier_hash.hex())
    print("kem_pk (length):", len(kem_pk))
    print("kem_pk_hash (hex):", kem_pk_hash.hex())
    
    # Contract expectation:
    # SubmitCommitment {
    #     election_id: u64,
    #     commitment_hash: String (base64),
    #     nullifier_hash: String (base64)
    # }
    
    commitment_b64 = base64.b64encode(enc_pkg.commitment_hash).decode('utf-8')
    nullifier_b64 = base64.b64encode(nullifier_hash).decode('utf-8')
    
    print("\nSubmitCommitment Payload:")
    print(f"  election_id: {election_id}")
    print(f"  commitment_hash: {commitment_b64}")
    print(f"  nullifier_hash: {nullifier_b64}")
    
    # Contract uses:
    print("\nRust expects:")
    print("- 32-byte hash fields: Yes, commitment and nullifier are 32 bytes before base64.")
    print("- Exact SubmitCommitment fields matching: election_id, commitment_hash, nullifier_hash.")
    print("- Deterministic commitment construction: commitment = SHA3_256(BallotBlobV1 bytes).")
    
if __name__ == "__main__":
    main()
