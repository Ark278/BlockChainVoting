"""Tests: Behavioral signal hash (Stage 4 §3, §14).

Tests:
  - same signal + same bucket → same hash
  - same signal + different bucket → different hash
"""

from __future__ import annotations

import os

from app.ai.telemetry import compute_behavioral_signal_hash


def test_same_signal_same_bucket_same_hash() -> None:
    server_secret = os.urandom(32)
    signal = b"signal_123"
    bucket_start = 1600000000

    hash1 = compute_behavioral_signal_hash(server_secret, signal, bucket_start)
    hash2 = compute_behavioral_signal_hash(server_secret, signal, bucket_start)

    assert hash1 == hash2
    assert len(hash1) == 32

def test_same_signal_different_bucket_different_hash() -> None:
    server_secret = os.urandom(32)
    signal = b"signal_123"
    bucket_start_1 = 1600000000
    bucket_start_2 = bucket_start_1 + 3600

    hash1 = compute_behavioral_signal_hash(server_secret, signal, bucket_start_1)
    hash2 = compute_behavioral_signal_hash(server_secret, signal, bucket_start_2)

    assert hash1 != hash2

def test_different_signal_same_bucket_different_hash() -> None:
    server_secret = os.urandom(32)
    signal_1 = b"signal_123"
    signal_2 = b"signal_456"
    bucket_start = 1600000000

    hash1 = compute_behavioral_signal_hash(server_secret, signal_1, bucket_start)
    hash2 = compute_behavioral_signal_hash(server_secret, signal_2, bucket_start)

    assert hash1 != hash2
