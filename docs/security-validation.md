# Security Validation

## Audit Scope
- No cryptographic secrets (e.g., KEM private keys, ML-DSA secrets, AES keys, or cleartext ballots) leak into logs or telemetry.
- Isolation of the frontend: Frontend secrets (`client_ephemeral_secret`) never persist in LocalStorage, SessionStorage, or Cookies.
- AI Boundaries: Anomalies raised as `HIGH_RISK` do not mutate blockchain state, nor drop a valid ballot.

## Cross-Language Parity
- Verified via `scripts/cross_language_crypto.py`.
- Rust `SubmitCommitment` strictly demands identical hash sequences, preventing malleability attacks from Python-generated inputs.

## AI Stability
- Verified via `test_ai_advisory_boundary.py`.
- Simulating AI failure (`AI_UNAVAILABLE`) or `HIGH_RISK` states confirmed zero disruption to API endpoints serving ballot submissions.
