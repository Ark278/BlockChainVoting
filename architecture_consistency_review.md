# Architecture Consistency Review – Final Update

**Project:** Privacy‑Preserving Blockchain Voting System with AI‑Based Anomaly Detection and Post‑Quantum Cryptography
**Version:** v2.2 (after user‑requested corrections)  
**Date:** 2026‑09‑02

---

## 1️⃣ Revised Cryptographic Execution Boundaries

| Component | Responsibility | Where the operation occurs | Determinism / WASM compatibility |
|-----------|----------------|----------------------------|-----------------------------------|
| **AES‑256‑GCM** | Encrypts the *ballot payload* (vote choice, random nonce, etc.) before it is stored off‑chain. | **Off‑chain Crypto Service** (a Rust/Python helper called by FastAPI). | Pure symmetric encryption – fully deterministic given the same key/nonce; trivially WASM‑compatible but performed off‑chain for performance. |
| **ML‑KEM** (key encapsulation) | Generates a *shared secret* that protects the AES‑256‑GCM key. The secret is encapsulated for the voting contract’s public key. | **Off‑chain Crypto Service** during **KeyGen/Encaps** phase (run when an election is created). The contract only stores the resulting *ciphertext* (the encapsulated key) and the *public key hash*. | ML‑KEM operations are heavyweight and not guaranteed to be deterministic in a WASM sandbox; therefore they are **not** executed inside the contract. |
| **ML‑DSA** (digital signatures) | Signs **anonymous credential issuance** messages. Provides authentication of the credential issuer to the backend. | **Credential Issuer Service** (off‑chain). The private key never leaves the issuer service. The contract stores only the **credential issuer’s public key** (or its hash) for verification. | ML‑DSA is deterministic for a given message and key, but the signature verification happens off‑chain; the contract only checks that the credential presented was signed by the registered public key (via a simple on‑chain hash comparison). |

### Where KeyGen, Encaps, Decaps Occur
- **KeyGen (ML‑KEM)** – Per‑election, the off‑chain service generates a fresh ML‑KEM key pair. The public key (or its hash) is registered on‑chain via a `SetKEMPublicKey` admin message. The private key is stored securely off‑chain.
- **Encaps (ML‑KEM)** – When a ballot is prepared, the off‑chain service encapsulates a fresh symmetric AES key with the on‑chain public key. The resulting ciphertext is stored off‑chain alongside the encrypted ballot; the contract stores only the *ciphertext hash* to prove that the correct encapsulation was used.
- **Decaps (ML‑KEM)** – Performed **off‑chain** after the election closes: the service uses the stored private key to decaps the symmetric key, decrypt the ballots, and feed them to the tally process. No ML‑KEM operation runs inside the contract. 

---

## 2️⃣ Concrete MVP Purpose for **ML‑DSA**

### Workflow
```
Credential Issuer Service (off‑chain) ──► ML‑DSA signing ──► Signed Credential
FastAPI Backend ──► Verify ML‑DSA signature ──► Store credential status (valid/revoked)
FastAPI Backend ──► Issue credential token to voter (opaque blob)
Voter submits ballot token to contract (via FastAPI) ──► Contract checks credential hash exists & is valid.
```

### Details
- **What is signed?**
  - A *credential payload* containing:
    - `credential_id` (random 128‑bit UUID)
    - `issued_at` timestamp
    - `expires_at` timestamp
    - Optional *attributes* (e.g., eligibility group)
    - A **cryptographic commitment** to the voter’s synthetic identifier (`commit(voter_synth_id)`).
  - The entire payload is serialized (canonical JSON) and signed with the issuer’s **ML‑DSA private key**.

- **Who owns the ML‑DSA private key?**
  - The **Credential Issuer Service** (a dedicated off‑chain micro‑service). The key is generated once per deployment and stored in a hardened secret store (e.g., Azure Key Vault, HashiCorp Vault). It is **not** stored on‑chain.

- **Public key distribution / storage**
  - The **ML‑DSA public key** (or its SHA‑256 hash) is registered on‑chain once via an admin `RegisterCredentialIssuer` message (multisig‑authorized). The contract stores this value in a `credential_issuer_pk_hash` field.
  - Off‑chain services obtain the public key from the contract (via a query) to verify signatures.

- **Verification process**
  - FastAPI receives a credential token, extracts the payload and signature, fetches the on‑chain stored `credential_issuer_pk_hash`, reconstructs the public key, and runs **ML‑DSA verification**.
  - If verification succeeds, the credential status is marked *valid* in PostgreSQL and the credential hash is added to the on‑chain `VALID_CREDENTIALS` set (as a cryptographic commitment, not the raw ID).

- **Key rotation / revocation**
  - **Rotation:** A new ML‑DSA key pair can be generated off‑chain. An admin multisig proposal invokes `RotateCredentialIssuerKey` with the new public‑key hash. The contract updates the stored hash; all previously issued credentials remain valid (the contract does not invalidate old signatures).
  - **Revocation:** Individual credentials can be revoked by adding their `credential_hash` to an on‑chain `REVOKED_CREDENTIALS` set (multisig‑authorized). The revocation list is consulted by the contract when authorising ballot submissions.

---

## 3️⃣ Voter‑ID Privacy Wording (Synthetic Identities Only)

- **Synthetic voter identifiers** (`voter_synth_id`) are **randomly generated UUIDs** that have **no relationship** to any real‑world identifier (e.g., email, phone, Aadhaar). They exist solely for research simulations.
- **No real PII** (email, phone, biometric data) is stored anywhere in the system.
- When a **pseudonymous identifier** is required (e.g., for eligibility checks), the system uses one of the following constructs:
  1. **Random synthetic identifier** – a fresh UUID per voter, stored only in the off‑chain `voters` table (private).
  2. **Keyed HMAC** – `HMAC(secret_key, voter_synth_id)` where `secret_key` is a service‑wide secret; the result can be used as a *stable* pseudonym without exposing the original UUID.
  3. **Cryptographic commitment** – `Commit(voter_synth_id, randomness)` stored in the credential payload; the commitment is public‑key‑derived and reveals nothing about `voter_synth_id`.

> **Important:** *“Hashed voter ID”* is no longer presented as an anonymization technique. The architecture now explicitly states that only **synthetic, randomly generated identifiers** are used, and any derived pseudonyms are constructed via HMAC or commitments, not simple hashes of real identifiers.

---

## 4️⃣ Credential‑to‑Ballot Linkage Re‑evaluation

### Recommended Flow (linkage avoided)
1. **Eligibility Check** – Off‑chain service confirms the synthetic voter ID belongs to an eligible voter.
2. **Credential Validation** – The service verifies the credential’s ML‑DSA signature and that it is not revoked.
3. **Derive Election‑Specific Nullifier** – The service computes `nullifier = HMAC(nullifier_key, credential_id || election_id)`; the `nullifier_key` is unique per election and kept secret off‑chain.
4. **Submit Ballot Commitment** – The voter (via FastAPI) sends the encrypted ballot **and** the derived `nullifier` to the contract. The contract stores only the `nullifier_hash` and the commitment hash.

### When a credential reference is **absolutely required**
- If auditors need to prove *who* possessed a valid credential at ballot time, the contract can store an **opaque credential hash** (e.g., `hash(credential_id)`) alongside the nullifier. This hash does **not** reveal voter identity, but it allows auditors to confirm that a *specific* credential (not the voter) was used.
- **Linkability analysis:** Storing the same credential hash across multiple elections would enable cross‑election correlation. Therefore, the hash is **combined with the election ID** before storage: `hash(credential_id || election_id)`.
- The architecture **recommends omitting** any reusable credential identifier unless a regulatory audit requirement explicitly demands it.

---

## 5️⃣ Nullifier Privacy Statement ( softened )
> “The nullifier is an **election‑scoped pseudonymous value** designed to enforce a *one‑vote‑per‑credential* rule while avoiding direct encoding of the voter identity. Its privacy properties rely on the secrecy of the per‑election nullifier key, the entropy of the credential identifier, and strict domain separation. Correlation attacks are mitigated only insofar as no other metadata (timestamps, IPs, etc.) is linked to the nullifier on‑chain.”

---

## 6️⃣ Updated Privacy Guarantee Table

| Guarantee | MVP Status | Comments |
|-----------|------------|----------|
| **Ballot Confidentiality** | **GUARANTEED** | AES‑256‑GCM encrypts payload; key protected by ML‑KEM (off‑chain). |
| **Ballot Integrity** | **GUARANTEED** | Commitment hash stored on‑chain; tampering aborts verification. |
| **Duplicate‑Vote Prevention** | **GUARANTEED** | Nullifier uniqueness enforced on‑chain. |
| **Eligibility Enforcement** | **GUARANTEED** | Off‑chain eligibility service; only valid credentials accepted. |
| **Voter Unlinkability** | **NOT GUARANTEED** | Synthetic IDs are used; however, correlation via credential hashes or nullifiers is possible if combined with external data. |
| **Coercion Resistance** | **NOT GUARANTEED** | No receipt‑free or coercion‑resistant mechanisms are implemented in the MVP. |

---

## 7️⃣ Updated Crypto Architecture Diagram (textual description)
```
Frontend (React + TypeScript)
    │
    ▼
FastAPI / Off‑chain Crypto Service
    │   ├─ AES‑256‑GCM  ← encrypts ballot payload
    │   ├─ ML‑KEM (KeyGen/Encaps/Decaps)  ← protects AES key (off‑chain only)
    │   └─ Credential Issuer Service
    │           └─ ML‑DSA signing of credential payloads
    │
    ▼
Cosmos‑SDK / CosmWasm Voting Contract (on‑chain)
    │   ├─ Stores election state, commitments, nullifier hashes
    │   ├─ Stores ML‑KEM public‑key hash (for encapsulation verification)
    │   ├─ Stores Credential Issuer ML‑DSA public‑key hash (for credential verification)
    │   └─ Authorization checks (multisig, role, credential validity)
    │
    ▼
Post‑greSQL (off‑chain) – persistence of synthetic voter IDs, eligibility, credential status, AI telemetry, etc.
```
*The diagram emphasizes that **all heavy PQ operations stay off‑chain**, while the contract only holds the minimal cryptographic artifacts needed for verification and audit.*

---

## 8️⃣ Consistency Re‑check
| Aspect | Consistency after changes |
|--------|---------------------------|
| **MUST HAVE classification** | Both ML‑KEM (key encapsulation for AES) and ML‑DSA (credential signing) have concrete MVP workflows now. |
| **Guarantees** | Ballot confidentiality/integrity/duplicate‑vote prevention are still guaranteed; voter unlinkability and coercion resistance remain *not guaranteed*. |
| **Assumptions** | Synthetic voter IDs only; no real PII stored. |
| **Trust Boundaries** | Off‑chain services own all PQ private keys; on‑chain contract only stores public‑key hashes and artifact hashes. |
| **State Machine** | Unchanged – still enforces the 5‑state lifecycle with enforced immutability after `OPEN`. |
| **Cryptographic Architecture** | Clear separation: AES for data, ML‑KEM for key protection (off‑chain), ML‑DSA for credential signatures (off‑chain). No PQ code inside WASM. |
| **Privacy Claims** | Language softened for nullifier and voter ID; no false anonymity statements. |
| **Linkability** | Credential‑to‑ballot linkage minimized; optional hashed credential per election only if audit‑required. |
| **Key Rotation / Revocation** | Defined for ML‑DSA credential‑issuer key and per‑election ML‑KEM keys. |

All sections now align with the project’s **MUST HAVE** requirements and the MVP’s realistic security posture.

---

*Prepared by Antigravity – your agency‑level coding assistant.*
