# Detailed Implementation Plan (v2.2)

## 1️⃣ Repository Structure
```
project-root/
├─ contracts/                 # Rust / CosmWasm contracts
│   ├─ voting_election/       # main contract crate
│   │   ├─ Cargo.toml
│   │   └─ src/
│   │       ├─ lib.rs
│   │       ├─ contract.rs
│   │       ├─ msg.rs        # InstantiateMsg, ExecuteMsg, QueryMsg
│   │       ├─ state.rs      # Config, Election, Role, Nullifier, Commitment structs
│   │       └─ error.rs
│   └─ multisig/               # cw3‑multisig contract (vendor / submodule)
│
├─ backend/                   # FastAPI (Python)
│   ├─ app/
│   │   ├─ main.py
│   │   ├─ routers/
│   │   │   ├─ voter.py
│   │   │   ├─ admin.py
│   │   │   ├─ credential.py
│   │   │   └─ ai.py
│   │   ├─ services/
│   │   │   ├─ crypto_service.py     # AES, ML‑KEM wrappers
│   │   │   ├─ credential_service.py
│   │   │   └─ ai_service.py
│   │   ├─ schemas/                # pydantic models
│   │   └─ deps.py                # DB, blockchain client, auth
│   ├─ tests/
│   └─ requirements.txt
│
├─ frontend/                  # React + TypeScript
│   ├─ src/
│   │   ├─ components/
│   │   ├─ pages/
│   │   ├─ services/
│   │   │   └─ blockchain.ts   # Cosmos SDK REST client
│   │   └─ App.tsx
│   ├─ public/
│   └─ package.json
│
├─ ai/                        # Python anomaly‑detection module
│   ├─ model/
│   │   └─ isolation_forest.pkl
│   ├─ src/
│   │   └─ inference.py
│   └─ requirements.txt
│
├─ crypto_offchain/           # Python/Rust helper for AES‑256‑GCM, ML‑KEM
│   ├─ src/
│   │   ├─ aes.py
│   │   ├─ mlkem.py
│   │   └─ utils.py
│   └─ requirements.txt
│
├─ scripts/                   # dev / deployment scripts
│   ├─ start_local_chain.sh
│   ├─ deploy_contract.sh
│   ├─ generate_keys.sh
│   └─ run_tests.sh
│
├─ docs/                      # architecture, threat model, privacy, etc.
│   ├─ architecture.md
│   ├─ privacy_model.md
│   └─ threat_model.md
│
├─ tests/                     # integration / end‑to‑end tests (pytest + wasm‑test)
│   ├─ contracts/
│   ├─ backend/
│   └─ e2e/
│
├─ Dockerfile (optional for dev)
└─ docker-compose.yml (Cosmos node, postgres, fastapi, ai)
```

## 2️⃣ CosmWasm Contract Design
| Component | Description |
|-----------|-------------|
| **InstantiateMsg** | `admin: Addr` (governance multisig), `election_params: ElectionParams` (election‑name, start/end times, allowed candidates), `crypto_config: CryptoConfig` (ML‑KEM public‑key hash, AES key protection mode), `credential_issuer_pk_hash: String` |
| **ExecuteMsg** | • `CreateElection { params }` (multisig only)\n• `RegisterCandidate { election_id, candidate }` (admin only, pre‑OPEN)\n• `OpenElection { election_id }` (multisig)\n• `PauseElection { election_id }` (emergency multisig)\n• `CloseElection { election_id }` (multisig)\n• `SubmitBallot { election_id, commitment_hash, nullifier_hash, encrypted_key_ct }` (requires valid credential)\n• `RegisterCredentialHash { credential_hash }` (admin)\n• `RevokeCredential { credential_hash }` (multisig)\n• `RecordAuditEvent { event }` (internal) |
| **QueryMsg** | • `GetElection { election_id }`\n• `ListElections { pagination }`\n• `GetCommitment { election_id, commitment_hash }`\n• `GetNullifier { election_id, nullifier_hash }`\n• `AuditLog { election_id, from, to }` |
| **Config Structure** | `admin: Addr`, `credential_issuer_pk_hash: String`, `kem_pk_hash: String`, `mode: CryptoMode { Classical, Hybrid, PostQuantum }`, `multisig_addresses: Vec<Addr>` |
| **Election Structure** | `id: Uint64`, `state: ElectionState`, `params: ElectionParams`, `created_at: Timestamp`, `updated_at: Timestamp` |
| **Role Structures** | `Roles { governance: Addr, emergency: Addr, tally: Addr, admin: Addr, credential_issuer: Addr }` stored in immutable `Config`.
| **Nullifier Storage** | `Nullifiers: Map<(election_id, nullifier_hash), Empty>` – ensures uniqueness.
| **Ballot Commitment Storage** | `Commitments: Map<(election_id, commitment_hash), CommitmentInfo>` where `CommitmentInfo { encrypted_key_ct: Binary, timestamp: Timestamp }`.
| **Audit Events** | `AuditLog: Vec<AuditEvent>` where each event records `event_type`, `actor`, `tx_hash`, `timestamp`, `details_hash`.
| **State Machine** | `CREATED → OPEN ↔ PAUSED → CLOSED → TALLYING → TALLIED`. Transitions enforced in `execute` handlers; immutable after `OPEN`.
| **Authorization Boundaries** | Every `execute` checks `info.sender` against stored role addresses or multisig contract address. Credential‑based calls additionally require a valid credential hash stored on‑chain.
| **Multisig Integration** | Uses standard `cw3‑multisig` contract. The voting contract stores the multisig contract address; `is_multisig_sender(info.sender)` resolves to `true` when `info.sender` is the multisig contract and the underlying proposal met the threshold.
| **Immutable Configuration Rules** | After `Instantiate`, fields `admin`, `credential_issuer_pk_hash`, `kem_pk_hash`, `multisig_addresses` cannot be changed. Only `RotateCredentialIssuerKey` (multisig‑authorized) may update the public‑key hash; the old signatures remain valid.

## 3️⃣ Exact Authorization Flow
### 3.1 Governance Multisig → Voting Contract
1. **Proposal creation** on `cw3‑multisig` by any governance member.
2. Members sign the proposal; once the threshold (≥ 2 of 3) is reached, the multisig contract executes the *target* message on the voting contract (e.g., `CreateElection`).
3. Voting contract receives `info.sender == <governance_multisig_addr>` and proceeds.

### 3.2 Emergency Multisig → Voting Contract
* Same flow, but uses a different multisig address (`emergency_multisig`).
* Authorized only for `PauseElection`, `ResumeElection`, `ForceCloseElection`.

### 3.3 Tally Multisig → Voting Contract
* Holds authority for `TransitionToTallying` and `PublishResults`.
* Threshold ≥ 2 of 3.

### 3.4 Election Admin → Voting Contract
* Direct address stored in `Config.admin` (set at instantiation). Can call `RegisterCandidate`, `OpenElection` (via multisig only), etc.

### 3.5 Credential Issuer → Off‑Chain Credential Service
1. Credential Issuer Service holds an **ML‑DSA private key**.
2. Generates a credential payload, signs it, and returns the signed token to the backend.
3. Backend verifies the signature using the on‑chain stored public‑key hash before persisting the credential status.

### 3.6 Distinguishing Layers
| Layer | Auth Mechanism | What is verified |
|-------|----------------|------------------|
| **On‑chain contract** | `info.sender` (address) + optional `credential_hash` stored on‑chain | Sender is a registered multisig or role address; credential not revoked.
| **Off‑chain services** | Mutual TLS / API token + **ML‑DSA** signature verification for credentials | Credential issuer’s signature, service‑side API auth.
| **Cryptographic signing** | ML‑DSA (off‑chain) for credentials only. No custom threshold logic inside contract.

## 4️⃣ Cryptographic Architecture
| Primitive | Where it runs | Purpose | Artifacts stored on‑chain |
|-----------|--------------|---------|--------------------------|
| **AES‑256‑GCM** | Off‑chain `crypto_service` (FastAPI) | Symmetric encryption of ballot payload (vote choice, random nonce). | `encrypted_key_ct` (ciphertext of AES key) stored as part of commitment; the encrypted ballot itself stays off‑chain.
| **ML‑KEM** | Off‑chain `mlkem` module (keygen, encaps, decaps) | Protects the AES key; encapsulated key ciphertext is stored on‑chain (`kem_ct_hash`). | Public‑key hash (`kem_pk_hash`) in `Config`; encapsulated ciphertext hash in commitment info.
| **ML‑DSA** | Off‑chain Credential Issuer Service | Signs credential payloads. | Public‑key hash (`credential_issuer_pk_hash`) stored in `Config`; credential hash may be stored for revocation.
| **SHA‑3 (Keccak256)** | Both off‑chain and contract (as a hash function) | Compute hashes for commitments, nullifiers, artifact IDs. | Commitment hash, nullifier hash, audit `details_hash`.
| **Ed25519** | Off‑chain for standard API request signing (optional) | Authenticate FastAPI internal micro‑services; not used by contract. | No on‑chain storage; public keys kept in service config.

### Key Generation & Flow
- **ML‑KEM keypair** – Generated per election by the off‑chain service (`generate_kem_keypair`). Public key hash registered on‑chain via `SetKEMPublicKey` (multisig). Private key stored securely off‑chain.
- **AES key** – Generated freshly for each ballot by the crypto service; encapsulated with the election’s ML‑KEM public key; only the ciphertext is sent to the contract.
- **ML‑DSA keypair** – Generated once for the Credential Issuer service at deployment. Public‑key hash stored on‑chain (`RegisterCredentialIssuer`). Private key never leaves the service.
- **Encapsulation** – Per‑ballot: `ct = mlkem_encaps(public_kem, aes_key)`. `ct` stored on‑chain (hash) while the full ciphertext stays off‑chain.
- **Decapsulation** – After election closed, off‑chain service uses private KEM key to recover AES key, decrypt all ballots, and run tally.
- **Signing** – Credential payload → `sig = ml_dsa_sign(private_key, payload)`. Backend verifies using on‑chain stored public‑key hash.
- **Verification** – All verification (ML‑DSA, SHA‑3 hashes) happens off‑chain before data is accepted by the contract.

### Crypto‑Provider Abstraction
```rust
enum CryptoMode {
    Classical,          // AES key protected by X25519 DH (future)
    Hybrid,             // Classical DH + ML‑KEM (both stored)
    PostQuantum,        // Only ML‑KEM
}
```
The contract stores the selected `mode` flag; the off‑chain service reads it to decide which encapsulation algorithm to use.

## 5️⃣ Ballot Flow (Full Sequence)
1. **Voter authentication** – Frontend sends user‑login request; backend verifies synthetic voter ID (no PII).
2. **Eligibility check** – Backend queries PostgreSQL `voters` table; ensures voter is eligible for the election.
3. **Credential issuance** – If voter lacks a valid credential, backend requests the Credential Issuer Service to create one. The service signs the payload with ML‑DSA; backend stores `credential_hash` (off‑chain) and registers it on‑chain via `RegisterCredentialHash`.
4. **Credential validation** – When submitting a ballot, frontend includes the credential token. Backend verifies ML‑DSA signature (using on‑chain public‑key hash) and checks revocation status.
5. **Ballot creation** – Voter selects candidate (choice kept locally). Backend builds a ballot object `{choice, nonce, timestamp}`.
6. **AES‑256‑GCM encryption** – Crypto service generates a fresh AES key, encrypts the ballot, produces `ciphertext` and `auth_tag`.
7. **ML‑KEM key protection** – Service obtains the election’s ML‑KEM public key (on‑chain). It encapsulates the AES key, producing `kem_ct`.
8. **Commitment generation** – Compute `commitment_hash = SHA3(election_id || ciphertext || auth_tag)`.
9. **Nullifier generation** – `nullifier_hash = HMAC(nullifier_key, credential_id || election_id)` (key is per‑election, stored off‑chain).
10. **Blockchain submission** – FastAPI sends an `ExecuteMsg::SubmitBallot` containing:
    - `election_id`
    - `commitment_hash`
    - `nullifier_hash`
    - `kem_ct_hash` (or full `kem_ct` if policy permits)
    - `credential_hash` (optional, election‑scoped)
    The contract verifies that `nullifier_hash` is not already present and that the credential hash is valid and not revoked.
11. **Audit event** – Contract emits `AuditEvent` with `event_type: BallotSubmitted` and a `details_hash` of the above fields.
12. **Later tally** – After `CLOSED → TALLYING`, off‑chain service retrieves all `kem_ct`s, decaps to recover AES keys, decrypts ballots, and performs the tally.

### Correlation Points
- **Login → eligibility** – Backend knows synthetic voter ID and which election they are voting in.
- **Credential token** – Links the voter (synthetic ID) to a credential ID; the credential ID is never placed on‑chain (unless audit‑required variant).
- **Nullifier** – Designed to be election‑scoped; if the same credential is reused across elections, the nullifier is recomputed with a different per‑election key, limiting cross‑election linkability.
- **Audit logs** – Contain only hashes; no plaintext ballot or voter identifier.

## 6️⃣ Privacy Model (MVP Guarantees & Non‑Guarantees)
| Property | Guarantee? | Notes |
|----------|------------|-------|
| **No real PII** | ✅ | All stored identifiers are synthetic UUIDs generated for the research study. |
| **Synthetic voter identities only** | ✅ | `voter_synth_id` is a random UUID; never derived from real IDs. |
| **Plaintext vote never on‑chain** | ✅ | Ballot payload stays encrypted off‑chain; only commitment and nullifier hashes are on‑chain. |
| **No voter_id → candidate mapping** | ✅ | No table stores that relationship; only encrypted payload contains the choice. |
| **Voter unlinkability** | ❌ | Nullifier is election‑scoped but could be linked if an adversary observes off‑chain services. |
| **Coercion resistance** | ❌ | No receipt‑free protocol; not in scope. |
| **Ballot confidentiality** | ✅ | AES‑256‑GCM + KEM protection. |
| **Ballot integrity** | ✅ | Commitment hash verified on‑chain. |
| **Duplicate‑vote prevention** | ✅ | Nullifier uniqueness enforced. |
| **Eligibility enforcement** | ✅ | Backend checks PostgreSQL before credential issuance. |

## 7️⃣ AI Architecture (MVP Only)
- **Telemetry source**: FastAPI logs per‑request metadata – IP (masked), device fingerprint (hashed), timing, credential hash, election ID.
- **Feature extraction**: Simple statistical features (request rate, geolocation hash, credential reuse pattern, time‑of‑day). Performed in `ai_service.py`.
- **Model**: Scikit‑learn Isolation Forest (trained offline on simulated data). Model file `isolation_forest.pkl` loaded at service start.
- **Risk‑score output**: Float in `[0,1]`. Also returns an array of `feature_importances` for explanation.
- **Explanation fields**: `anomalous_features: Vec<String>` (top‑3 contributing features).
- **Storage**: Scores are written to PostgreSQL `ai_telemetry` table with a foreign key to the credential hash; no impact on contract.
- **API boundary**: `POST /ai/score` – receives telemetry payload, returns `{score, explanations}`. Called by backend after ballot submission.
- **Failure behavior**: If AI service is unavailable or returns error, backend logs the incident and proceeds; ballot submission is not blocked.
- **Constraints**: AI never rejects a ballot, never writes to blockchain, never decides “guilt”. It is purely observability.

## 8️⃣ Tally Architecture (MVP)
- **TALLY_AUTHORITY multisig** – Separate cw3‑multisig contract; threshold ≥ 2 of 3. Authorized to invoke `TransitionToTallying` and `PublishResults` on the voting contract.
- **Future threshold decryption** – Not implemented now. The design leaves a placeholder `FutureThresholdDecryption` module that could later hold secret‑share holders.
- **Workflow**:
  1. Election admin calls `CloseElection` → state becomes `CLOSED`.
  2. Tally multisig proposes `StartTallying`. Once approved, contract enters `TALLYING`.
  3. Off‑chain service fetches all commitments, decaps KEM ciphertexts, decrypts ballots, runs the tally algorithm (off‑chain), and writes the result to the contract via `PublishResults` (multisig‑authorized).
  4. Contract moves to `TALLIED` and emits final `AuditEvent`.

## 9️⃣ Database Design (PostgreSQL)
### Tables
| Table | Columns (selected) | Classification | Reason |
|-------|--------------------|----------------|--------|
| **voters** | `id UUID PK`, `synthetic_id UUID UNIQUE`, `eligibility_group TEXT`, `created_at TIMESTAMP` | PRIVATE (synthetic) | Stores synthetic voter IDs only. |
| **credentials** | `credential_id UUID PK`, `voter_id UUID FK -> voters.id`, `issued_at`, `expires_at`, `revoked BOOL`, `credential_hash BYTEA UNIQUE` | CRYPTOGRAPHIC | Holds credential metadata; `credential_hash` used for on‑chain validation. |
| **elections** | `id SERIAL PK`, `name TEXT`, `state TEXT`, `params JSONB`, `created_at`, `updated_at` | PUBLIC (metadata) | Election configuration. |
| **candidates** | `id SERIAL PK`, `election_id INT FK`, `name TEXT`, `metadata JSONB` | PUBLIC | Candidate list. |
| **ballot_commits** | `election_id INT FK`, `commitment_hash BYTEA PK`, `kem_ct_hash BYTEA`, `timestamp` | CRYPTOGRAPHIC | Stores on‑chain artifacts for verification. |
| **nullifiers** | `election_id INT FK`, `nullifier_hash BYTEA PK`, `used_at TIMESTAMP` | CRYPTOGRAPHIC | Enforces one‑vote‑per‑credential. |
| **ai_telemetry** | `id SERIAL PK`, `credential_hash BYTEA`, `election_id INT`, `score FLOAT`, `features JSONB`, `created_at` | PRIVATE | Observability, not used for decision. |
| **audit_events** | `id SERIAL PK`, `election_id INT`, `event_type TEXT`, `actor_addr TEXT`, `tx_hash TEXT`, `details_hash BYTEA`, `timestamp` | PUBLIC (hashed) | Immutable log for research. |

### Privacy Guarantees in DB
- No column stores `voter_id → candidate_choice`.
- Ballot payload never persisted; only its commitment hash.
- All PII columns are absent; synthetic IDs are random.

## 🔟 API Design (FastAPI)
### Authentication
- **API token** (Bearer) for internal services.
- **OAuth‑like** token for voter endpoints (issued after login, tied to synthetic ID).

### Endpoints
| Path | Method | Purpose | Auth | Blockchain effect |
|------|--------|---------|------|-------------------|
| `/voter/login` | POST | Verify synthetic ID, issue session token | Public | None |
| `/voter/eligibility/{election_id}` | GET | Return eligibility status | Voter token | None |
| `/credential/issue` | POST | Request new credential (ML‑DSA signed) | Voter token | Calls `RegisterCredentialHash` via backend → contract |
| `/credential/revoke/{credential_hash}` | POST | Revoke credential | Governance multisig token | Calls `RevokeCredential` on‑chain |
| `/election/{election_id}/open` | POST | Open election | Governance multisig token | Execute `OpenElection` on‑chain |
| `/election/{election_id}/pause` | POST | Pause election | Emergency multisig token | Execute `PauseElection` on‑chain |
| `/ballot/submit` | POST | Submit encrypted ballot + nullifier | Voter token | Execute `SubmitBallot` on‑chain |
| `/tally/start/{election_id}` | POST | Move to TALLYING | Tally multisig token | Execute `StartTallying` on‑chain |
| `/tally/publish/{election_id}` | POST | Publish results | Tally multisig token | Execute `PublishResults` on‑chain |
| `/audit/{election_id}` | GET | Retrieve audit log | Governance token | Reads contract state |
| `/ai/score` | POST | Submit telemetry for scoring | Internal service token | No blockchain interaction |

### Separation
- **Public voter endpoints** – only need session token.
- **Admin / governance endpoints** – require multisig‑derived JWT (generated after multisig proposal execution).
- **Credential issuance** – off‑chain only, but result is persisted on‑chain via `RegisterCredentialHash`.
- **AI telemetry** – isolated service, never influences contract.

## 1️⃣1️⃣ Testing Strategy
### Matrix Overview
| Test Category | Example Scenarios |
|---------------|-------------------|
| **Multisig Threshold** | Propose `OpenElection` with 1/3 signatures → reject; with 2/3 → succeed. |
| **Authorization Separation** | Election admin tries `PauseElection` → reject; emergency admin succeeds. |
| **State Transitions** | `CREATED → OPEN → PAUSED → OPEN → CLOSED → TALLYING → TALLIED`; illegal jumps rejected. |
| **Immutable Config** | Attempt to change `credential_issuer_pk_hash` after instantiation → reject unless via `RotateCredentialIssuerKey`. |
| **Nullifier Uniqueness** | Submit two ballots with same nullifier → second rejected. |
| **Replay Protection** | Resubmit same transaction hash → reject (duplicate tx). |
| **Ballot Encryption** | Verify that decrypted payload after decapsulation matches original (off‑chain test). |
| **Commitment Integrity** | Tamper with encrypted ballot → contract rejects because commitment hash mismatch. |
| **ML‑KEM Workflow** | End‑to‑end test: generate KEM keypair, encapsulate AES key, decapsulate, ensure equality. |
| **ML‑DSA Credential Signature** | Invalid signature → backend rejects credential. |
| **Role Assignment** | Add new admin via `RegisterAdmin` (multisig) and verify permissions. |
| **AI Service Failure** | Simulate AI service down → backend still processes ballot, logs warning. |
| **Database Failure** | DB unavailable → API returns 503; contract state remains unchanged. |
| **Malformed Requests** | Missing fields, wrong JSON types → 400 response, no blockchain tx. |
| **Unauthorized API Access** | Call admin endpoint with voter token → 403. |
| **Integration with Local Cosmos Chain** | Deploy contract to local chain, run full ballot flow, query state, ensure audit events appear. |

### Test Types
- **Unit tests** – Rust contract logic (cargo test), Python services (pytest), React components (jest).
- **Integration tests** – Spin up Docker Compose stack (cosmos node, postgres, fastapi, ai); run end‑to‑end scenario.
- **Property‑based tests** – Use `proptest` for nullifier uniqueness, commitment hash invariants.
- **Security tests** – Fuzz inputs to contract via `cosmwasm‑vm`; audit for overflows.

## 1️⃣2️⃣ Security Assumptions
| Assumption | Rationale | Failure Impact | MVP / Future |
|-----------|-----------|----------------|--------------|
| Off‑chain services keep private keys (ML‑KEM, ML‑DSA) in a secure vault. | Needed to protect secrecy of encryption and signing keys. | Leakage = ability to forge credentials or decrypt ballots. | MVP – assumes sealed VM or dev secret store; future work adds HSM. |
| Synthetic voter IDs are never linked to real identities. | Guarantees no PII leakage. | If linking occurs, privacy is broken. | MVP – enforced by data generation script; future work adds audit. |
| Multisig contracts are correctly configured and threshold met. | Guarantees governance control. | Misconfiguration could allow unauthorized actions. | MVP – validated in CI tests. |
| FastAPI server is behind TLS and validates JWTs. | Prevents MITM and replay. | Without TLS, tokens could be intercepted. | MVP – TLS in Docker‑compose; future work adds mutual TLS. |
| AI service cannot alter blockchain state. | Ensures AI is observational only. | If compromised, could attempt to inject malicious scores. | Enforced by network segmentation; future work adds signed attestations. |
| PostgreSQL backups are performed daily. | Guarantees data recovery. | Loss of credential revocation list could affect auditability. | MVP – manual dump script; future work adds automated backups. |

## 1️⃣3️⃣ Dependency Plan
| Language | Library | Purpose | Maturity |
|----------|----------|---------|----------|
| **Rust** | `cosmwasm-std`, `cosmwasm-schema`, `serde`, `sha3` | Contract framework, serialization, hashing. | Mature, used in many contracts. |
|          | `cw3-multisig` (vendored) | Standard multisig implementation. | Widely used. |
| **Python** | `fastapi`, `uvicorn`, `pydantic` | API server. | Actively maintained. |
|          | `sqlalchemy`, `psycopg2-binary` | DB ORM. | Mature. |
|          | `pqcrypto‑kem‑mlkem`, `pqcrypto‑sign‑ml‑dsa` | PQ primitives (via `pyo3` bindings or Rust subprocess). | Actively maintained, production‑grade. |
|          | `cryptography` | AES‑256‑GCM wrapper. | Mature. |
|          | `scikit-learn` | Isolation Forest model. | Mature. |
|          | `uvloop` (optional) | Faster event loop. | Mature. |
| **JavaScript/TypeScript** | `react`, `typescript`, `axios` | Frontend UI. | Mature. |
|          | `cosmjs` | Cosmos SDK RPC client. | Actively maintained. |
|          | `tailwindcss` (optional) – **only if UI styling needed** | UI styling. | Mature. |
| **Docker** | `cosmoshub/cosmos-sdk` (or `ignite` image) | Local chain node. | Official. |
|          | `postgres:13` | Database. | Official. |

No unnecessary heavy dependencies are introduced.

## 1️⃣4️⃣ Implementation Phases (Roadmap)
| Phase | Scope | Success Criteria |
|------|-------|------------------|
| **0 – Foundations** | Initialise repo, CI, Docker‑compose, toolchain versions. | `docker compose up` brings up all services; CI pipeline passes lint. |
| **1 – Local Cosmos Environment** | Install `ignite`, generate local chain, configure genesis with cw3‑multisig. | Local chain runs, accounts created, multisig contract deployed. |
| **2 – Multisig Contracts & Auth** | Deploy cw3‑multisig contracts for governance, emergency, tally; write thin wrappers in contract to verify `info.sender`. | All three multisig contracts reachable; contract enforces sender checks. |
| **3 – Election Lifecycle Contract** | Implement state machine, instantiate, create/open/close transitions. | Unit tests cover all valid/invalid transitions. |
| **4 – Commitments & Nullifiers** | Add storage maps, uniqueness checks, audit event emission. | Tests for duplicate nullifier rejection, commitment integrity. |
| **5 – Off‑chain Ballot Encryption Service** | AES‑256‑GCM wrapper, API endpoint to encrypt/decrypt (for testing). | Encryption round‑trip validated. |
| **6 – ML‑KEM Integration** | Off‑chain keygen per election, encaps/decaps functions, storage of ciphertext hash on‑chain. | End‑to‑end test: encrypt ballot, store ciphertext hash, decaps after close, recover key. |
| **7 – ML‑DSA Credential Signing** | Credential Issuer service, signing flow, on‑chain public‑key registration, revocation list. | Credential verification passes; revocation blocks ballot. |
| **8 – FastAPI Backend** | Full set of endpoints, auth middleware, wiring to contract via `cosmjs`‑like RPC client. | API passes integration tests, produces correct on‑chain txs. |
| **9 – React Frontend** | UI for voter login, eligibility view, ballot submission, admin dashboards. | Manual UI smoke test; API calls succeed. |
| **10 – AI Anomaly Detection Service** | Load model, expose `/ai/score` endpoint, integrate telemetry logging. | Scores returned; service failure does not block ballot flow. |
| **11 – Integration Testing** | Run full flow on local chain: credential → ballot → tally. | End‑to‑end test passes, audit log contains expected events. |
| **12 – Security Hardening** | TLS, secret management, audit log integrity checks, dependency audit (`cargo audit`, `pip-audit`). | No high‑severity CVE in dependencies. |
| **13 – Benchmarking Suite** | Scripts measuring latency, gas, encryption time, KEM performance. | Benchmark results collected (no fabricated numbers). |
| **14 – Research Evaluation & Documentation** | Write performance report, threat model updates, lessons learned. | Documentation compiled in `docs/`.

## 1️⃣5️⃣ Major Technical Risks
- **WASM compatibility of PQ libraries** – ML‑KEM/ML‑DSA are not compiled into the contract; off‑chain only mitigates risk, but future hybrid mode may need careful performance testing.
- **Key management leakage** – Private KEM and DSA keys must stay off‑chain; accidental exposure would compromise confidentiality and credential trust.
- **Nullifier construction** – If the per‑election nullifier key is weak or reused, linkability increases.
- **Multisig proposal race conditions** – Incorrect handling of proposal IDs could allow duplicate execution; thorough testing required.
- **AI service performance** – Large telemetry bursts could degrade API latency; need back‑pressure handling.

## 1️⃣6️⃣ Open Decisions (Require Approval)
1. **Whether to store the credential hash on‑chain** (currently optional, audit‑only). Approve if audit requirement demands it.
2. **Choice of hash algorithm for commitments** – SHA‑3‑256 is assumed; confirm if SHA‑256 is preferred.
3. **Per‑election KEM key rotation policy** – At MVP we generate once per election; confirm if regeneration before each ballot is desired.
4. **Storage of the full KEM ciphertext on‑chain vs. hash only** – Current plan stores hash for proof of correct encapsulation; full ciphertext could be stored for easier debugging.
5. **Level of UI styling** – Minimal styling vs. premium design (per organization policy).

## 1️⃣7️⃣ First Coding Task (After Plan Approval)
**Task:** *Create the Rust contract skeleton* – implement the `InstantiateMsg`, `ExecuteMsg` (with only `CreateElection` and `RegisterCredentialHash` stubs), `QueryMsg` (empty), and the `Config` state struct, plus the Cargo.toml metadata. No business logic yet; just compile‑time scaffolding.

---

*Prepared by Antigravity – your agency‑level coding assistant.*
