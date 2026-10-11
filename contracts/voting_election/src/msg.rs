// Message definitions for the voting_election contract (Architecture v2.6)
use cosmwasm_std::Binary;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// Re-export for test convenience
pub use crate::state::ElectionParams;

/// Instantiate message – global governance configuration only.
/// ML-KEM public keys are election-specific and are supplied at CreateElection time.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    /// Admin address.
    pub admin: String,
    /// Cryptographic mode: "Classical" | "Hybrid" | "PostQuantum".
    pub crypto_mode: String,
    /// Governance multisig address (creates/manages elections).
    pub multisig_governance: String,
    /// Emergency multisig address.
    pub multisig_emergency: String,
    /// Tally multisig address (starts tallying and publishes results).
    pub multisig_tally: String,
}

/// Execute messages – core protocol operations per Architecture v2.6.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    // ── Election lifecycle ────────────────────────────────────────────────────
    /// Create a new election in Configured state.
    /// Validates kem_pk = 1184 bytes and kem_pk_hash = 32 bytes.
    CreateElection {
        election_id: u64,
        params: ElectionParams,
        /// Full ML-KEM-768 (NIST FIPS 203) public key, exactly 1184 bytes.
        kem_pk: Binary,
        /// SHA3-256(kem_pk), exactly 32 bytes.
        kem_pk_hash: Binary,
    },

    /// Register a candidate for a specific election.
    /// Only allowed during RegistrationOpen state.
    RegisterCandidate {
        election_id: u64,
        candidate: String,
    },

    /// Configured → RegistrationOpen. Governance only.
    OpenRegistration { election_id: u64 },

    /// RegistrationOpen → VotingOpen. Governance only.
    OpenVoting { election_id: u64 },

    /// VotingOpen → VotingClosed. Governance only.
    CloseVoting { election_id: u64 },

    /// VotingClosed → Tallying. Tally multisig only.
    StartTallying { election_id: u64 },

    /// Tallying → ResultsPublished. Tally multisig only.
    /// Stores the result commitment hash on-chain.
    PublishResults {
        election_id: u64,
        result_hash: Binary,
    },

    // ── Ballot submission ─────────────────────────────────────────────────────
    /// Atomically register commitment_hash and nullifier_hash.
    /// Only accepted during VotingOpen.
    /// Duplicate nullifier or duplicate commitment is rejected.
    SubmitCommitment {
        election_id: u64,
        /// Base64-encoded SHA3-256 commitment hash.
        commitment_hash: String,
        /// Base64-encoded SHA3-256 nullifier hash.
        nullifier_hash: String,
    },

    // ── Issuer key registry ───────────────────────────────────────────────────
    /// Register a new ML-DSA-65 issuer key. Governance only.
    /// Validates public_key = 1952 bytes, public_key_hash = 32 bytes.
    RegisterIssuerKey {
        issuer_key_id: String,
        public_key: Binary,
        public_key_hash: Binary,
    },

    /// Add a new ML-DSA-65 issuer key (rotation). Governance only.
    /// Old keys remain queryable; historical credentials remain verifiable.
    RotateIssuerKey {
        issuer_key_id: String,
        public_key: Binary,
        public_key_hash: Binary,
    },
}

/// Query messages – read-only accessors.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetElection {
        election_id: u64,
    },
    ListElections {
        start_after: Option<u64>,
        limit: Option<u32>,
    },
    ListCandidates {
        election_id: u64,
    },
    GetCommitment {
        election_id: u64,
        /// Base64-encoded commitment hash.
        commitment_hash: String,
    },
    NullifierUsed {
        election_id: u64,
        /// Base64-encoded nullifier hash.
        nullifier_hash: String,
    },
    GetIssuerKey {
        issuer_key_id: String,
    },
    GetResultCommitment {
        election_id: u64,
    },
    /// Paginated query for all ballot commitments in an election.
    /// Returns only (commitment_hash_b64, nullifier_hash_b64) for privacy.
    ListBallotCommitments {
        election_id: u64,
        start_after: Option<String>,
        limit: Option<u32>,
    },
}

/// Paginated response for ListBallotCommitments.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CommitmentListResponse {
    pub commitments: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct CandidateListResponse {
    pub candidates: Vec<String>,
}

