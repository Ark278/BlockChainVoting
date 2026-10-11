import platform
import sys

import oqs


def main():
    print("=== VERSIONS ===")
    print(f"Python: {platform.python_version()}")
    print("liboqs-python: 0.16.0 (from pip list)")
    print(f"liboqs C library: {oqs.oqs_version()}")
    
    print("\n=== KEM MECHANISMS ===")
    kem_mechs = oqs.get_enabled_kem_mechanisms()
    print("ML-KEM-768 enabled:", "ML-KEM-768" in kem_mechs)
    if "ML-KEM-768" not in kem_mechs:
        print("Available KEMs:", kem_mechs)
        sys.exit(1)
        
    print("\n=== SIG MECHANISMS ===")
    sig_mechs = oqs.get_enabled_sig_mechanisms()
    print("ML-DSA-65 enabled:", "ML-DSA-65" in sig_mechs)
    if "ML-DSA-65" not in sig_mechs:
        print("Available SIGs:", sig_mechs)
        sys.exit(1)

    print("\n=== ML-KEM-768 TEST ===")
    with oqs.KeyEncapsulation("ML-KEM-768") as client:
        public_key = client.generate_keypair()
        with oqs.KeyEncapsulation("ML-KEM-768") as server:
            ciphertext, shared_secret_server = server.encap_secret(public_key)
        shared_secret_client = client.decap_secret(ciphertext)
        
        print("Public Key Size:", len(public_key))
        print("Ciphertext Size:", len(ciphertext))
        print("Shared Secret Size:", len(shared_secret_client))
        print("Shared secrets match:", shared_secret_server == shared_secret_client)
        
        assert len(public_key) == 1184
        assert len(ciphertext) == 1088
        assert len(shared_secret_client) == 32
        assert shared_secret_server == shared_secret_client

    print("\n=== ML-DSA-65 TEST ===")
    message = b"Test message for ML-DSA-65"
    with oqs.Signature("ML-DSA-65") as signer:
        public_key = signer.generate_keypair()
        signature = signer.sign(message)
        
        with oqs.Signature("ML-DSA-65") as verifier:
            is_valid = verifier.verify(message, signature, public_key)
            print("Public Key Size:", len(public_key))
            print("Signature Size:", len(signature))
            print("Original signature valid:", is_valid)
            
            assert len(public_key) == 1952
            assert len(signature) == 3309
            assert is_valid
            
            # Modified message
            mod_message = b"Test mEssage for ML-DSA-65"
            is_valid_mod_msg = verifier.verify(mod_message, signature, public_key)
            print("Modified message valid:", is_valid_mod_msg)
            assert not is_valid_mod_msg
            
            # Modified signature
            mod_signature = bytearray(signature)
            mod_signature[100] ^= 1 # flip a bit
            is_valid_mod_sig = verifier.verify(message, bytes(mod_signature), public_key)
            print("Modified signature valid:", is_valid_mod_sig)
            assert not is_valid_mod_sig
            
    print("\n=== SUCCESS ===")

if __name__ == "__main__":
    main()
