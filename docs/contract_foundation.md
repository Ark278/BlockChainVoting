# Contract Foundation Documentation

## Purpose
The **voting_election** CosmWasm contract provides the on‑chain authority layer for the Privacy‑Preserving Blockchain Voting system. At this foundation stage it only stores configuration, basic state structures, and basic query endpoints. All business‑logic (election lifecycle, ballot handling, cryptography, multisig integration) will be added in later phases.

## Message Structure
### InstantiateMsg
```json
{
  "admin": "<governance multisig address>",
  "credential_issuer_pk_hash": "<SHA3-256 hash of ML‑DSA public key>",
  "kem_pk_hash": "<SHA3-256 hash of ML‑KEM public key>",
  "crypto_mode": "Classical | Hybrid | PostQuantum",
  "multisig_governance": "<address>",
  "multisig_emergency": "<address>",
  "multisig_tally": "<address>"
}
```
All fields are required and stored immutable (except `crypto_mode` which can be changed only via a dedicated rotate call).

### ExecuteMsg (scaffold)
At this stage each variant returns `ContractError::NotImplemented`:
- `CreateElection`
- `RegisterCandidate`
- `OpenElection`
- `PauseElection`
- `ResumeElection`
- `CloseElection`
- `StartTallying`
- `SubmitBallot`
- `PublishResults`
- `RegisterCredentialHash`
- `RevokeCredential`
- `RotateCredentialIssuerKey`

### QueryMsg (scaffold)
- `GetElection { election_id }` – returns optional `Election` struct.
- `ListElections` – returns an empty list placeholder.
- `GetCommitment { election_id, commitment_hash }` – returns optional `CommitmentInfo`.
- `GetNullifier { election_id, nullifier_hash }` – returns a boolean indicating existence.
- `AuditLog { election_id, from, to }` – not implemented yet.

## State Structure
- **Config** – stored in a singleton `CONFIG`. Holds admin addresses, crypto‑mode selection, and hash references for credential‑issuer and KEM keys.
- **Election** – stored in map `ELECTIONS` keyed by `election_id`. Includes `state` (enum), `params`, timestamps.
- **CommitmentInfo** – stored in map `COMMITMENTS` keyed by `(election_id, commitment_hash)`. Holds full KEM ciphertext and its hash.
- **NULLIFIERS** – map keyed by `(election_id, nullifier_hash)` to enforce one‑vote‑per‑credential.
- **VALID_CREDENTIALS** – set of credential hashes.

## Storage Maps (cw‑storage‑plus)
```rust
pub const CONFIG: Item<Config> = Item::new("config");
pub const ELECTIONS: Map<u64, Election> = Map::new("elections");
pub const COMMITMENTS: Map<(u64, String), CommitmentInfo> = Map::new("commitments");
pub const NULLIFIERS: Map<(u64, String), ()> = Map::new("nullifiers");
pub const VALID_CREDENTIALS: Map<String, ()> = Map::new("valid_credentials");
```

## Authorization Boundaries (MVP)
- **Instantiation** – any sender can instantiate; the provided admin address becomes the governance multisig.
- **Execute** – every execute variant currently returns `NotImplemented`. In later phases each will require:
  - `info.sender` equal to the appropriate multisig contract address, **or**
  - For credential‑related calls, the sender must be the off‑chain backend that has already verified the ML‑DSA signature.
- **Query** – read‑only, no auth checks at this stage.

## What Is NOT Implemented Yet
- Election state transitions and business logic.
- Multisig proposal handling and threshold verification.
- Cryptographic operations (ML‑KEM, ML‑DSA, AES‑GCM, KDF).
- Ballot storage, nullifier generation, or audit event emission.
- Interaction with FastAPI, PostgreSQL, or AI services.
- Any on‑chain verification of off‑chain data beyond storing hashes.

## Testing
- Basic serialization tests for `InstantiateMsg`, `ExecuteMsg`, and `QueryMsg`.
- Contract instantiation test confirming the `action=instantiate` attribute.
- Test confirming that every unimplemented `ExecuteMsg` returns `ContractError::NotImplemented`.

---
*Prepared by Antigravity – your agency‑level coding assistant.*
