"""Application configuration via pydantic-settings."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ──────────────────────────────────────────────────────────────
    database_url: str = Field(
        default="sqlite+aiosqlite:///./voting_dev.db",
        description="SQLAlchemy async database URL",
    )

    # ── Blockchain / CosmWasm ─────────────────────────────────────────────────
    chain_rpc_url: str = Field(default="http://localhost:26657")
    chain_rest_url: str = Field(default="http://localhost:1317")
    chain_id: str = Field(default="localchain-1")
    voting_contract_address: str = Field(default="cosmos1testcontractaddress")
    chain_submitter_mnemonic: str = Field(default="", repr=False)

    # ── Key sources ───────────────────────────────────────────────────────────
    credential_issuer_key_source: Literal["chain", "local"] = Field(default="chain")
    election_key_source: Literal["env", "vault"] = Field(default="env")
    nullifier_key_source: Literal["env", "vault"] = Field(default="env")

    # ── Development test keys (hex-encoded 32 bytes per election_id) ──────────
    # NEVER use in production. Election-specific nullifier HMAC keys.
    # Key format:  DEV_NULLIFIER_KEY_ELECTION_{id}
    # Loaded dynamically; stored as env vars only.
    dev_nullifier_key_election_1: str = Field(
        default="0" * 64,  # 32 zero bytes hex — dev only
        repr=False,
    )

    # ── API ───────────────────────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")

    # ── Idempotency ───────────────────────────────────────────────────────────
    idempotency_ttl_seconds: int = Field(default=86400)

    # ── Tally / backup (Stage 3) ──────────────────────────────────────────────
    backup_storage_path: str = Field(
        default="./ballot_backup",
        description="Root directory for local-filesystem ballot backup (dev/test).",
    )
    tally_page_size: int = Field(
        default=50,
        description="Number of ballot commitments fetched per page during tally.",
        ge=1,
        le=500,
    )
    # Election KEM private keys are NOT stored here globally.
    # The ElectionKeyVault reads ELECTION_KEM_SK_HEX_{election_id} from env per request.

    # ── AI / anomaly detection (Stage 4) ──────────────────────────────────────
    # server_bucket_secret_hex: hourly-rotated HMAC key for telemetry bucket IDs.
    # In development, use a static value. In production, rotate this every hour
    # via a secrets manager and never log or persist this value.
    # NEVER send this value to any external service or log it.
    server_bucket_secret_hex: str = Field(
        default="a" * 64,  # dev-only placeholder: 32 zero-entropy bytes — NOT for production
        repr=False,
        description="Hex-encoded 32-byte server bucket secret for telemetry HMAC. Dev only.",
    )
    ai_model_dir: str = Field(
        default="./ai_models",
        description="Directory where versioned Isolation Forest model artifacts are stored.",
    )
    ai_inference_timeout_seconds: float = Field(
        default=5.0,
        description="Maximum seconds to wait for AI inference before treating as unavailable.",
        ge=0.1,
        le=60.0,
    )
    ai_enabled: bool = Field(
        default=True,
        description=(
            "Feature flag for AI anomaly detection. "
            "When False, telemetry is accepted but AI inference is skipped silently. "
            "Ballot processing is never affected by this flag."
        ),
    )





    @field_validator("dev_nullifier_key_election_1")
    @classmethod
    def validate_hex_key(cls, v: str) -> str:
        """Ensure dev keys are valid 64-char hex strings (32 bytes)."""
        if len(v) != 64:
            raise ValueError("Dev nullifier key must be 64 hex characters (32 bytes)")
        int(v, 16)  # validates hex
        return v

    def get_dev_nullifier_key(self, election_id: int) -> bytes:
        """Return the dev nullifier key for the given election_id.

        For production, replace with a call to the key vault.
        """
        # Only election_id=1 is pre-configured for dev.
        hex_key = self.dev_nullifier_key_election_1
        return bytes.fromhex(hex_key)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
