"""Tests: Privacy boundary (Stage 4 §1, §14).

Tests:
  - prohibited fields rejected
  - raw nullifier rejected
  - credential IDs rejected
  - ballot payload rejected
  - private keys rejected
"""

from __future__ import annotations

import pytest

from app.ai.telemetry import validate_telemetry_fields
from app.errors import TelemetryValidationError

# Base valid payload
_VALID_PAYLOAD = {
    "election_id": 1,
    "version": 1,
    "submission_interval_seconds": 15.0,
    "submission_attempts": 1,
}

def test_valid_payload_accepted() -> None:
    # Should not raise
    validate_telemetry_fields(_VALID_PAYLOAD)

@pytest.mark.parametrize("prohibited_key", [
    "voter_synth_id",
    "voter_id",
    "credential_id",
    "credential_hash",
    "credential",
    "nullifier",
    "nullifier_hash",
    "selected_option",
    "candidate",
    "candidate_choice",
    "ballot_choice",
    "plaintext",
    "plaintext_ballot",
    "ballot_plaintext",
    "ballot_blob",
    "ballotblobv1",
    "kem_ct",
    "kem_sk",
    "private_key",
    "aes_key",
    "shared_secret",
    "ml_kem_sk",
    "ml_dsa_sk",
    "biometric",
    "fingerprint",
    "face_id",
    "ip_address",
    "user_agent",
    "device_id",
    "session_id",
    "client_secret",
    "ephemeral_secret",
    "client_ephemeral_secret",
])
def test_prohibited_fields_rejected(prohibited_key: str) -> None:
    payload = dict(_VALID_PAYLOAD)
    payload[prohibited_key] = "some value"
    
    with pytest.raises(TelemetryValidationError, match=prohibited_key):
        validate_telemetry_fields(payload)

def test_prohibited_fields_case_insensitive_rejected() -> None:
    payload = dict(_VALID_PAYLOAD)
    payload["NULLIFIER_HASH"] = "xyz"
    with pytest.raises(TelemetryValidationError):
        validate_telemetry_fields(payload)
