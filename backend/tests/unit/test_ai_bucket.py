"""Tests: Bucket identifiers (Stage 4 §2, §14).

Tests:
  - same ephemeral browser session + same hour → same ID
  - new hour → different ID
  - new browser session → different ID
"""

from __future__ import annotations

import os

from app.ai.telemetry import (
    compute_client_bucket_token,
    compute_telemetry_bucket_id,
)


def test_same_session_same_hour_same_id() -> None:
    client_secret = os.urandom(32)
    server_secret = os.urandom(32)
    bucket_start = 1600000000

    token1 = compute_client_bucket_token(client_secret, bucket_start)
    id1 = compute_telemetry_bucket_id(token1, server_secret)

    token2 = compute_client_bucket_token(client_secret, bucket_start)
    id2 = compute_telemetry_bucket_id(token2, server_secret)

    assert id1 == id2
    assert len(id1) == 32

def test_different_hour_different_id() -> None:
    client_secret = os.urandom(32)
    server_secret = os.urandom(32)
    bucket_start_1 = 1600000000
    bucket_start_2 = bucket_start_1 + 3600

    token1 = compute_client_bucket_token(client_secret, bucket_start_1)
    id1 = compute_telemetry_bucket_id(token1, server_secret)

    token2 = compute_client_bucket_token(client_secret, bucket_start_2)
    id2 = compute_telemetry_bucket_id(token2, server_secret)

    assert id1 != id2

def test_different_session_different_id() -> None:
    client_secret_1 = os.urandom(32)
    client_secret_2 = os.urandom(32)
    server_secret = os.urandom(32)
    bucket_start = 1600000000

    token1 = compute_client_bucket_token(client_secret_1, bucket_start)
    id1 = compute_telemetry_bucket_id(token1, server_secret)

    token2 = compute_client_bucket_token(client_secret_2, bucket_start)
    id2 = compute_telemetry_bucket_id(token2, server_secret)

    assert id1 != id2

def test_different_server_secret_different_id() -> None:
    client_secret = os.urandom(32)
    server_secret_1 = os.urandom(32)
    server_secret_2 = os.urandom(32)
    bucket_start = 1600000000

    token = compute_client_bucket_token(client_secret, bucket_start)
    id1 = compute_telemetry_bucket_id(token, server_secret_1)
    id2 = compute_telemetry_bucket_id(token, server_secret_2)

    assert id1 != id2
