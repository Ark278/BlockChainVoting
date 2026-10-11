import uuid

import oqs
import pytest

from app.services.crypto import (
    aes_gcm_decrypt,
    build_aad,
    compute_commitment,
    decode_ballot_blob,
    derive_aes_key,
    encrypt_ballot_full,
    kem_decapsulate,
    kem_encapsulate,
)
from app.services.nullifier import derive_nullifier, hash_nullifier


# --- PQC Tests ---
def test_ml_kem_768_round_trip():
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
    
    ct, ss_client = kem_encapsulate(pk)
    assert len(pk) == 1184
    assert len(ct) == 1088
    assert len(ss_client) == 32

    ss_server = kem_decapsulate(sk, ct)
    assert ss_client == ss_server

def test_ml_dsa_65_verification():
    with oqs.Signature("ML-DSA-65") as sig:
        pk = sig.generate_keypair()
        message = b"Test Message"
        signature = sig.sign(message)
    
    assert len(pk) == 1952
    
    with oqs.Signature("ML-DSA-65") as verifier:
        assert verifier.verify(message, signature, pk)
        assert not verifier.verify(b"Tampered Message", signature, pk)
        
        tampered_sig = bytearray(signature)
        tampered_sig[0] ^= 1
        assert not verifier.verify(message, bytes(tampered_sig), pk)


# --- Nullifier Tests ---
def test_nullifier_deterministic():
    key = b"0" * 32
    cred_id = str(uuid.uuid4())
    elec_id_1 = 1
    elec_id_2 = 2
    
    n1 = derive_nullifier(key, cred_id, elec_id_1)
    n2 = derive_nullifier(key, cred_id, elec_id_1)
    assert n1 == n2
    
    n3 = derive_nullifier(key, cred_id, elec_id_2)
    assert n1 != n3
    
    h1 = hash_nullifier(n1)
    assert len(h1) == 32
    assert h1 != n1


# --- Ballot Crypto Tests ---
def test_ballot_encryption_round_trip():
    # Setup KEM
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        kem_pk = kem.generate_keypair()
        kem_sk = kem.export_secret_key()
    import hashlib
    kem_pk_hash = hashlib.sha3_256(kem_pk).digest()
    
    nullifier_hash = hashlib.sha3_256(b"n").digest()
    pt = b'{"choice":"yes"}'
    elec_id = 1
    
    pkg = encrypt_ballot_full(elec_id, nullifier_hash, pt, kem_pk, kem_pk_hash)
    
    # Decryption (Server side)
    decoded = decode_ballot_blob(pkg.ballot_blob)
    assert decoded["version"] == 1
    assert decoded["kem_ct"] == pkg.kem_ct
    
    ss = kem_decapsulate(kem_sk, pkg.kem_ct)
    aes_key = derive_aes_key(ss)
    aad = build_aad(elec_id, nullifier_hash)
    
    pt_decrypted = aes_gcm_decrypt(
        aes_key, decoded["nonce"], decoded["ciphertext"], decoded["tag"], aad
    )
    assert pt_decrypted == pt
    
    # AAD Modification fails
    bad_aad = build_aad(elec_id + 1, nullifier_hash)
    with pytest.raises(Exception):
        aes_gcm_decrypt(aes_key, decoded["nonce"], decoded["ciphertext"], decoded["tag"], bad_aad)

    # Commitment deterministic
    c2 = compute_commitment(elec_id, nullifier_hash, pkg.ballot_blob)
    assert c2 == pkg.commitment_hash

