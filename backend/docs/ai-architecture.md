# Stage 4 — Privacy-Bounded AI Anomaly Detection

## Overview

The voting backend implements a privacy-bounded AI subsystem. Its primary objective is to identify telemetry anomalies (such as high-frequency automated submissions) without accessing sensitive voter identity or cryptographic data.

The AI subsystem operates exclusively in an **advisory capacity**. It does not enforce ballot acceptance, block credentials, or alter tally results.

## Privacy Boundary

The AI is fed from a specialized `app/ai/telemetry.py` service which acts as a strict privacy boundary. The following data points are **never** provided to the AI and are explicitly filtered during ingest:

- Voter synthetic IDs, credentials, or hashes
- Nullifiers or nullifier hashes
- Candidate choice / ballot plaintext
- Encrypted ballot blobs
- Keys (ML-KEM, AES, ML-DSA)
- Biometric data or raw PII (IPs, user agents)

### Approved AI Features

The AI evaluates exactly four numeric features per session bucket:
- `submission_interval_seconds`
- `submission_attempts`
- `auth_failure_count`
- `encrypted_blob_size_bytes`

## Session Bucket Identities

To group telemetry without exposing long-term identifiers, we implement a frozen bucket protocol:

1. **Client token**: `HMAC-SHA3-256(client_ephemeral_secret, uint64_be(bucket_start))`
2. **Server bucket ID**: `SHA3-256(client_bucket_token || server_bucket_secret)`

The `server_bucket_secret` rotates hourly, ensuring that no bucket ID can be linked across hours or distinct browser sessions.

## Execution and Failure Isolation

Inference is performed as a fire-and-forget background task using FastAPI's `BackgroundTasks`. The `AnomalyDetectionService` ensures that:

- Inference does not block the cryptographic ballot verification path.
- Any timeout or internal failure (missing model, DB error) is safely caught.
- If the AI fails, valid ballots continue to be processed and accepted normally.
