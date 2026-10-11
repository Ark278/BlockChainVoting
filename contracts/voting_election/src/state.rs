// State definitions for the voting_election contract (Architecture v2.6)
use cosmwasm_std::{Addr, Binary};
use cw_storage_plus::{Item, Map};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Cryptographic mode selection
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum CryptoMode {
    Classical,
    Hybrid,
    PostQuantum,
}

/// Global contract configuration – governance addresses only.
/// ML-KEM public keys are stored per-election, not globally.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub admin: Addr,
    pub crypto_mode: CryptoMode,
    pub multisig_governance: Addr,
    pub multisig_emergency: Addr,
    pub multisig_tally: Addr,
}

/// Election parameter bundle – extensible in future stages.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ElectionParams {
    pub name: String,
    pub description: Option<String>,
}

/// Exact eight-state election state machine per Architecture v2.6.
///
/// Legal transitions (governance unless noted):
///   Draft → Configured → RegistrationOpen → VotingOpen →
///   VotingClosed → Tallying (tally multisig) → ResultsPublished → Archived
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum ElectionState {
    Draft,
    Configured,
    RegistrationOpen,
    VotingOpen,
    VotingClosed,
    Tallying,
    ResultsPublished,
    Archived,
}

/// Per-election record.
/// `kem_pk`      – full ML-KEM-768 public key, exactly 1184 bytes.
/// `kem_pk_hash` – SHA3-256(kem_pk), exactly 32 bytes.
/// Both are supplied at `CreateElection` time and validated by the contract.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Election {
    pub id: u64,
    pub state: ElectionState,
    pub params: ElectionParams,
    pub kem_pk: Binary,      // 1184 bytes
    pub kem_pk_hash: Binary, // 32 bytes
    pub created_at: u64,
    pub updated_at: u64,
    pub opened_at: Option<u64>,
    pub voting_opened_at: Option<u64>,
    pub closed_at: Option<u64>,
    pub tally_started_at: Option<u64>,
    pub results_published_at: Option<u64>,
}

/// Issuer key record – ML-DSA-65 (NIST FIPS 204).
/// `public_key`      – exactly 1952 bytes.
/// `public_key_hash` – SHA3-256(public_key), exactly 32 bytes.
/// Multiple keys may coexist; historical keys remain queryable.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct IssuerKey {
    pub public_key: Binary,      // exactly 1952 bytes
    pub public_key_hash: Binary, // exactly 32 bytes
}

/// Commitment record – stored atomically with the nullifier.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CommitmentInfo {
    pub election_id: u64,
    pub commitment_hash: Binary,
    pub nullifier_hash: Binary,
    pub submitted_at: u64,
}

/// Result commitment published after tallying.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ResultCommitment {
    pub election_id: u64,
    pub result_hash: Binary,
    pub published_at: u64,
}

// ── Storage ──────────────────────────────────────────────────────────────────

pub const CONFIG: Item<Config> = Item::new("config");

/// Elections keyed by `election_id`.
pub const ELECTIONS: Map<u64, Election> = Map::new("elections");

/// Issuer key registry: `issuer_key_id → IssuerKey`.
/// Old keys are never deleted; rotation adds a new entry.
pub const ISSUER_KEYS: Map<&str, IssuerKey> = Map::new("issuer_keys");

/// Commitments: `(election_id, commitment_hash_b64) → CommitmentInfo`.
pub const COMMITMENTS: Map<(u64, String), CommitmentInfo> = Map::new("commitments");

/// Nullifiers: `(election_id, nullifier_hash_b64) → ()`.
/// Presence = nullifier consumed; used for double-vote prevention.
pub const NULLIFIERS: Map<(u64, String), ()> = Map::new("nullifiers");

/// Result commitments: `election_id → ResultCommitment`.
pub const RESULT_COMMITMENTS: Map<u64, ResultCommitment> = Map::new("result_commitments");

/// Election candidates: `election_id -> Vec<String>`.
pub const ELECTION_CANDIDATES: Map<u64, Vec<String>> = Map::new("election_candidates");
