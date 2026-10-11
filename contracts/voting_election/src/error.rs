// Contract error definitions (Architecture v2.6)
use cosmwasm_std::{OverflowError, StdError};
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("unauthorized")]
    Unauthorized {},

    #[error("election not found")]
    ElectionNotFound {},

    #[error("invalid state transition")]
    InvalidStateTransition {},

    #[error("invalid ML-KEM-768 public key length: expected 1184, got {len}")]
    InvalidKemPublicKeyLength { len: usize },

    #[error("invalid ML-DSA-65 public key length: expected 1952, got {len}")]
    InvalidIssuerPublicKeyLength { len: usize },

    #[error("invalid hash length: expected 32, got {len}")]
    InvalidHashLength { len: usize },

    #[error("issuer key already exists: {issuer_key_id}")]
    IssuerKeyAlreadyExists { issuer_key_id: String },

    #[error("issuer key not found: {issuer_key_id}")]
    IssuerKeyNotFound { issuer_key_id: String },

    #[error("duplicate nullifier")]
    DuplicateNullifier {},

    #[error("duplicate commitment")]
    DuplicateCommitment {},

    #[error("result already published for election {election_id}")]
    ResultAlreadyPublished { election_id: u64 },

    #[error("invalid input: {msg}")]
    InvalidInput { msg: String },

    #[error("duplicate election")]
    DuplicateElection {},

    #[error("not implemented")]
    NotImplemented {},

    #[error("generic overflow: {0}")]
    Overflow(#[from] OverflowError),

    #[error("generic std error: {0}")]
    Std(#[from] StdError),
}

pub type ContractResult<T> = Result<T, ContractError>;
