# Implementation Plan for CosmWasm Voting MVP

## Goal
Implement a minimal viable voting contract in Rust/CosmWasm that satisfies the approved design:
- Election lifecycle (create, open, close)
- Candidate registration (only before open)
- Ballot commitment submission with nullifier registration and duplicate rejection
- Strict admin authorization and audit logging
- Query endpoints for elections, candidates, ballot status, and audit events

No zero‑knowledge verification, anonymous credentials, post‑quantum crypto, AI, or tallying at this stage.

## User Review Required
> [!IMPORTANT]
> Please confirm that the following plan matches your expectations before we start generating code, tests, scripts, and documentation.

- **Scope**: Only the features listed above. Future extensions (ZK proofs, PQC, AI) will be added later.
- **Tech stack**: Rust 1.71+, CosmWasm 1.4+, `cargo` for building, `wasmd` (local testnet) for deployment.
- **Deployment**: Use `ignite` (Starport) to spin up a local Cosmos SDK chain with Wasm support.
- **Testing**: Unit tests with `cosmwasm_std::testing`, integration tests using `wasmd` in Docker, plus negative cases.
- **Security checks**: Run `cargo audit`, `cargo clippy`, and `wasm-opt` size optimisation. All arithmetic will use checked ops (`checked_add`, etc.).

If you need any change, let us know now.

## Open Questions
> [!WARNING]
> - None identified for the MVP. If you anticipate additional requirements (e.g., multisig admin), tell us now.

## Proposed Changes
### Contracts
- **`src/contract.rs`** – entry points (`instantiate`, `execute`, `query`).
- **`src/msg.rs`** – `InstantiateMsg`, `ExecuteMsg`, `QueryMsg` definitions.
- **`src/state.rs`** – storage items: `ADMINS`, `ELECTIONS`, `CANDIDATES`, `NULLIFIERS`, `BALLOT_COMMITS`, `AUDIT_LOG`.
- **`src/handlers.rs`** – separate functions for each execute action (create election, register candidate, open/close, submit ballot, etc.).
- **`src/errors.rs`** – custom error enum deriving `StdError`.
- **`src/tests.rs`** – unit tests covering happy paths and negative cases.
- **`src/integration_test.rs`** – integration tests using a Dockerised `wasmd` node.

### Scripts & Config
- **`scripts/deploy.sh`** – compile contract, upload to local chain, instantiate with initial admin.
- **`scripts/start_local_chain.sh`** – use `ignite chain serve` (or `wasmd` + `cosmos-sdk`) to spin up a private chain.
- **`Dockerfile`** – for reproducible build environment.
- **`docker-compose.yml`** – bring up `wasmd` node and a simple faucet.

### Documentation
- **`README.md`** – high‑level overview, build/run instructions, API reference.
- **`docs/architecture.md`** – state diagram, message flow, security considerations.
- **`docs/api.md`** – protobuf/JSON schema for each message and query.

## Verification Plan
1. **Compile** – `cargo wasm` → `wasm-opt -Os`.
2. **Unit Tests** – `cargo test` covers all execute/queries and invariant checks (nullifier uniqueness, state transitions, auth). Negative tests ensure unauthorized accounts are rejected.
3. **Integration Tests** – spin up local `wasmd` via Docker, upload contract, run a sequence of messages exercising the full lifecycle, assert on chain state via queries.
4. **Static Analysis** – `cargo clippy -- -D warnings`, `cargo audit` for known CVEs, `cargo fmt --check`.
5. **Size Checks** – ensure final WASM binary < 1 MiB (requirement for Cosmos). Optimize with `wasm-opt`.
6. **Audit Log Validation** – after each state‑changing exec, confirm an `AuditEvent` entry exists with correct signer and hash.

## Acceptance Criteria
- All listed execute messages succeed for authorized admins and reject for others.
- Nullifier duplicate submissions are rejected with a clear error.
- Election cannot be opened without at least one candidate; cannot be closed before `end_time`.
- Queries return correct public data and do not expose any private fields.
- All tests pass, and static analysis reports no warnings or vulnerabilities.
- Deployment scripts successfully instantiate the contract on a local chain.

---
*When you approve, we will generate the full contract source tree, unit/integration tests, Docker setup, and documentation as described above.*
