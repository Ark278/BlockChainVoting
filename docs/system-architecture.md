# System Architecture v2.6

## Overview
This architecture features a hybrid blockchain-assisted voting scheme ensuring end-to-end verifiability, robust anonymity, and post-quantum security.

## Components
- **React Frontend**: Untrusted thin client for visualization. Cryptography isolated to telemetry HMAC-SHA3-256.
- **FastAPI Backend**: Authoritative proxy for identity verification, ballot encryption, and telemetry.
- **CosmWasm Contract**: Immutable ledger for ballot commitments, nullifiers, and election lifecycle enforcement.
- **PostgreSQL**: Stores encrypted blob data for off-chain tallying to minimize on-chain costs.

## Cryptography
- **ML-DSA-65**: Digital signatures for credential authority.
- **ML-KEM-768**: Key encapsulation for ballot privacy.
- **AES-256-GCM**: Symmetric encryption of ballot payloads.
- **SHA3-256**: Hashing for nullifiers and commitments.

## AI Isolation
The anomaly detection model (Isolation Forest) is restricted to an isolated telemetry endpoint. It acts strictly in an advisory capacity and has zero impact on the ballot acceptance criteria.
