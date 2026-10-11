// tests/integration.rs
// Stage 1 integration tests – Architecture v2.6 compliant
//
// Tests cover:
//   1. Instantiate
//   2. Complete legal election lifecycle
//   3. Illegal state transitions rejected
//   4. Governance authorization
//   5. ML-DSA-65 issuer key registration (1952 B), length validation, rotation
//   6. ML-KEM-768 election key (1184 B), length validation, 32-byte hash
//   7. Atomic SubmitCommitment: nullifier + commitment together
//   8. Duplicate nullifier rejected
//   9. Duplicate commitment rejected
//  10. Result commitment publication
//  11. Pagination
//  12. Deterministic event attributes
//  13. Query behavior

use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::{from_json, Binary};
use voting_election::contract::{execute, instantiate, query};
use voting_election::error::ContractError;
use voting_election::msg::{ElectionParams, ExecuteMsg, InstantiateMsg, QueryMsg};
use voting_election::state::{Election, ElectionState, IssuerKey, ResultCommitment};

// ── Constants (Architecture v2.6 exact sizes) ─────────────────────────────────

const KEM_PK: [u8; 1184] = [0xAB; 1184]; // ML-KEM-768 public key
const KEM_HASH: [u8; 32] = [0xCD; 32]; // SHA3-256(KEM_PK)
const DSA_PK: [u8; 1952] = [0x11; 1952]; // ML-DSA-65 public key
const DSA_HASH: [u8; 32] = [0x22; 32]; // SHA3-256(DSA_PK)

// Base64 encoding of 32-byte all-zero arrays for commitment/nullifier hashes
// [0u8; 32].to_base64() = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const COMMIT_HASH_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const NULL_HASH_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="; // [1u8; 32]

// ── Helpers ───────────────────────────────────────────────────────────────────

fn default_instantiate_msg() -> InstantiateMsg {
    InstantiateMsg {
        admin: "admin".to_string(),
        crypto_mode: "PostQuantum".to_string(),
        multisig_governance: "gov".to_string(),
        multisig_emergency: "emergency".to_string(),
        multisig_tally: "tally".to_string(),
    }
}

fn init_contract() -> (
    cosmwasm_std::OwnedDeps<
        cosmwasm_std::testing::MockStorage,
        cosmwasm_std::testing::MockApi,
        cosmwasm_std::testing::MockQuerier,
        cosmwasm_std::Empty,
    >,
    cosmwasm_std::Env,
) {
    let mut deps = mock_dependencies();
    let env = mock_env();
    instantiate(
        deps.as_mut(),
        env.clone(),
        mock_info("creator", &[]),
        default_instantiate_msg(),
    )
    .unwrap();
    (deps, env)
}

fn default_election_params() -> ElectionParams {
    ElectionParams {
        name: "Test Election".to_string(),
        description: Some("A test".to_string()),
    }
}

/// Advance election through the full lifecycle up to VotingOpen.
fn advance_to_voting_open(
    deps: &mut cosmwasm_std::OwnedDeps<
        cosmwasm_std::testing::MockStorage,
        cosmwasm_std::testing::MockApi,
        cosmwasm_std::testing::MockQuerier,
        cosmwasm_std::Empty,
    >,
    env: &cosmwasm_std::Env,
    election_id: u64,
) {
    let gov = mock_info("gov", &[]);
    // CreateElection → Configured
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CreateElection {
            election_id,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap();
    // → RegistrationOpen
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::OpenRegistration { election_id },
    )
    .unwrap();
    // → VotingOpen
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::OpenVoting { election_id },
    )
    .unwrap();
}

// ── 1. Instantiate ────────────────────────────────────────────────────────────

#[test]
fn test_instantiate_success() {
    let (mut deps, env) = (mock_dependencies(), mock_env());
    let res = instantiate(
        deps.as_mut(),
        env,
        mock_info("creator", &[]),
        default_instantiate_msg(),
    )
    .unwrap();
    assert_eq!(res.attributes[0].value, "instantiate");
}

#[test]
fn test_instantiate_invalid_crypto_mode() {
    let mut deps = mock_dependencies();
    let env = mock_env();
    let mut msg = default_instantiate_msg();
    msg.crypto_mode = "Quantum".to_string();
    let err = instantiate(deps.as_mut(), env, mock_info("c", &[]), msg).unwrap_err();
    assert!(matches!(err, ContractError::InvalidInput { .. }));
}

// ── 2. Complete legal election lifecycle ──────────────────────────────────────

#[test]
fn test_full_lifecycle() {
    let (mut deps, env) = init_contract();
    let gov = mock_info("gov", &[]);
    let tally = mock_info("tally", &[]);
    let eid = 1u64;

    // Configured
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CreateElection {
            election_id: eid,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap();

    // RegistrationOpen
    let res = execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::OpenRegistration { election_id: eid },
    )
    .unwrap();
    assert_eq!(res.attributes[0].value, "open_registration");

    // VotingOpen
    let res = execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::OpenVoting { election_id: eid },
    )
    .unwrap();
    assert_eq!(res.attributes[0].value, "open_voting");

    // VotingClosed
    let res = execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CloseVoting { election_id: eid },
    )
    .unwrap();
    assert_eq!(res.attributes[0].value, "close_voting");

    // Tallying
    let res = execute(
        deps.as_mut(),
        env.clone(),
        tally.clone(),
        ExecuteMsg::StartTallying { election_id: eid },
    )
    .unwrap();
    assert_eq!(res.attributes[0].value, "start_tallying");

    // ResultsPublished
    let res = execute(
        deps.as_mut(),
        env.clone(),
        tally.clone(),
        ExecuteMsg::PublishResults {
            election_id: eid,
            result_hash: Binary::from(DSA_HASH.as_ref()),
        },
    )
    .unwrap();
    assert_eq!(res.attributes[0].value, "publish_results");

    // Verify final state via query
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::GetElection { election_id: eid },
    )
    .unwrap();
    let election: Option<Election> = from_json(&bin).unwrap();
    assert_eq!(election.unwrap().state, ElectionState::ResultsPublished);
}

// ── 3. Illegal state transitions ──────────────────────────────────────────────

#[test]
fn test_illegal_transitions() {
    let (mut deps, env) = init_contract();
    let gov = mock_info("gov", &[]);

    // Create election
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CreateElection {
            election_id: 1,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap();

    // Configured → CloseVoting (invalid)
    assert_eq!(
        execute(
            deps.as_mut(),
            env.clone(),
            gov.clone(),
            ExecuteMsg::CloseVoting { election_id: 1 }
        )
        .unwrap_err(),
        ContractError::InvalidStateTransition {}
    );

    // Configured → OpenVoting (invalid, must be RegistrationOpen first)
    assert_eq!(
        execute(
            deps.as_mut(),
            env.clone(),
            gov.clone(),
            ExecuteMsg::OpenVoting { election_id: 1 }
        )
        .unwrap_err(),
        ContractError::InvalidStateTransition {}
    );

    // Configured → StartTallying (invalid)
    assert_eq!(
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("tally", &[]),
            ExecuteMsg::StartTallying { election_id: 1 }
        )
        .unwrap_err(),
        ContractError::InvalidStateTransition {}
    );

    // → RegistrationOpen
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::OpenRegistration { election_id: 1 },
    )
    .unwrap();

    // RegistrationOpen → OpenRegistration again (invalid)
    assert_eq!(
        execute(
            deps.as_mut(),
            env.clone(),
            gov.clone(),
            ExecuteMsg::OpenRegistration { election_id: 1 }
        )
        .unwrap_err(),
        ContractError::InvalidStateTransition {}
    );

    // RegistrationOpen → CloseVoting (invalid, must go through VotingOpen)
    assert_eq!(
        execute(
            deps.as_mut(),
            env.clone(),
            gov.clone(),
            ExecuteMsg::CloseVoting { election_id: 1 }
        )
        .unwrap_err(),
        ContractError::InvalidStateTransition {}
    );

    // → VotingOpen
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::OpenVoting { election_id: 1 },
    )
    .unwrap();

    // VotingOpen → OpenRegistration (invalid, cannot go back)
    assert_eq!(
        execute(
            deps.as_mut(),
            env.clone(),
            gov.clone(),
            ExecuteMsg::OpenRegistration { election_id: 1 }
        )
        .unwrap_err(),
        ContractError::InvalidStateTransition {}
    );

    // → VotingClosed
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CloseVoting { election_id: 1 },
    )
    .unwrap();

    // VotingClosed → PublishResults without tallying (invalid)
    assert_eq!(
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("tally", &[]),
            ExecuteMsg::PublishResults {
                election_id: 1,
                result_hash: Binary::from(KEM_HASH.as_ref()),
            }
        )
        .unwrap_err(),
        ContractError::InvalidStateTransition {}
    );
}

#[test]
fn test_nonexistent_election_not_found() {
    let (mut deps, env) = init_contract();
    let err = execute(
        deps.as_mut(),
        env,
        mock_info("gov", &[]),
        ExecuteMsg::OpenRegistration { election_id: 999 },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::ElectionNotFound {});
}

// ── 4. Governance authorization ───────────────────────────────────────────────

#[test]
fn test_governance_required_for_create() {
    let (mut deps, env) = init_contract();
    let err = execute(
        deps.as_mut(),
        env,
        mock_info("attacker", &[]),
        ExecuteMsg::CreateElection {
            election_id: 1,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});
}

#[test]
fn test_tally_required_for_start_tallying() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);
    execute(
        deps.as_mut(),
        env.clone(),
        mock_info("gov", &[]),
        ExecuteMsg::CloseVoting { election_id: 1 },
    )
    .unwrap();

    let err = execute(
        deps.as_mut(),
        env,
        mock_info("gov", &[]), // governance, not tally
        ExecuteMsg::StartTallying { election_id: 1 },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});
}

#[test]
fn test_tally_required_for_publish_results() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);
    let gov = mock_info("gov", &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CloseVoting { election_id: 1 },
    )
    .unwrap();
    execute(
        deps.as_mut(),
        env.clone(),
        mock_info("tally", &[]),
        ExecuteMsg::StartTallying { election_id: 1 },
    )
    .unwrap();

    let err = execute(
        deps.as_mut(),
        env,
        gov, // not tally
        ExecuteMsg::PublishResults {
            election_id: 1,
            result_hash: Binary::from(DSA_HASH.as_ref()),
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::Unauthorized {});
}

// ── 5. ML-DSA-65 issuer key registry ─────────────────────────────────────────

#[test]
fn test_register_issuer_key_correct_size() {
    let (mut deps, env) = init_contract();
    let res = execute(
        deps.as_mut(),
        env,
        mock_info("gov", &[]),
        ExecuteMsg::RegisterIssuerKey {
            issuer_key_id: "ik-1".to_string(),
            public_key: Binary::from(DSA_PK.as_ref()),
            public_key_hash: Binary::from(DSA_HASH.as_ref()),
        },
    )
    .unwrap();
    assert_eq!(res.attributes[0].value, "register_issuer_key");
    assert_eq!(res.attributes[1].value, "ik-1");
}

#[test]
fn test_register_issuer_key_wrong_pk_length_rejected() {
    let (mut deps, env) = init_contract();
    let short_pk = vec![0u8; 100];
    let err = execute(
        deps.as_mut(),
        env,
        mock_info("gov", &[]),
        ExecuteMsg::RegisterIssuerKey {
            issuer_key_id: "ik-bad".to_string(),
            public_key: Binary::from(short_pk),
            public_key_hash: Binary::from(DSA_HASH.as_ref()),
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        ContractError::InvalidIssuerPublicKeyLength { len: 100 }
    );
}

#[test]
fn test_register_issuer_key_wrong_hash_length_rejected() {
    let (mut deps, env) = init_contract();
    let err = execute(
        deps.as_mut(),
        env,
        mock_info("gov", &[]),
        ExecuteMsg::RegisterIssuerKey {
            issuer_key_id: "ik-bad".to_string(),
            public_key: Binary::from(DSA_PK.as_ref()),
            public_key_hash: Binary::from(vec![0u8; 16]), // wrong: 16 bytes
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::InvalidHashLength { len: 16 });
}

#[test]
fn test_duplicate_issuer_key_id_rejected() {
    let (mut deps, env) = init_contract();
    let gov = mock_info("gov", &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::RegisterIssuerKey {
            issuer_key_id: "ik-1".to_string(),
            public_key: Binary::from(DSA_PK.as_ref()),
            public_key_hash: Binary::from(DSA_HASH.as_ref()),
        },
    )
    .unwrap();

    let err = execute(
        deps.as_mut(),
        env,
        gov,
        ExecuteMsg::RegisterIssuerKey {
            issuer_key_id: "ik-1".to_string(),
            public_key: Binary::from(DSA_PK.as_ref()),
            public_key_hash: Binary::from(DSA_HASH.as_ref()),
        },
    )
    .unwrap_err();
    assert_eq!(
        err,
        ContractError::IssuerKeyAlreadyExists {
            issuer_key_id: "ik-1".to_string()
        }
    );
}

#[test]
fn test_issuer_key_rotation_old_key_remains_queryable() {
    let (mut deps, env) = init_contract();
    let gov = mock_info("gov", &[]);

    // Register ik-1
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::RegisterIssuerKey {
            issuer_key_id: "ik-1".to_string(),
            public_key: Binary::from(DSA_PK.as_ref()),
            public_key_hash: Binary::from(DSA_HASH.as_ref()),
        },
    )
    .unwrap();

    // Rotate in ik-2 (different ID → old ik-1 remains)
    let new_pk = vec![0x33u8; 1952];
    let new_hash = vec![0x44u8; 32];
    execute(
        deps.as_mut(),
        env.clone(),
        gov,
        ExecuteMsg::RotateIssuerKey {
            issuer_key_id: "ik-2".to_string(),
            public_key: Binary::from(new_pk.clone()),
            public_key_hash: Binary::from(new_hash.clone()),
        },
    )
    .unwrap();

    // ik-1 still queryable
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::GetIssuerKey {
            issuer_key_id: "ik-1".to_string(),
        },
    )
    .unwrap();
    let ik: Option<IssuerKey> = from_json(&bin).unwrap();
    assert_eq!(ik.unwrap().public_key.len(), 1952);

    // ik-2 queryable
    let bin = query(
        deps.as_ref(),
        env,
        QueryMsg::GetIssuerKey {
            issuer_key_id: "ik-2".to_string(),
        },
    )
    .unwrap();
    let ik2: Option<IssuerKey> = from_json(&bin).unwrap();
    assert_eq!(ik2.unwrap().public_key, Binary::from(new_pk));
}

// ── 6. ML-KEM-768 election key ────────────────────────────────────────────────

#[test]
fn test_create_election_correct_kem_size() {
    let (mut deps, env) = init_contract();
    execute(
        deps.as_mut(),
        env.clone(),
        mock_info("gov", &[]),
        ExecuteMsg::CreateElection {
            election_id: 1,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap();

    // Verify stored key
    let bin = query(deps.as_ref(), env, QueryMsg::GetElection { election_id: 1 }).unwrap();
    let e: Option<Election> = from_json(&bin).unwrap();
    let e = e.unwrap();
    assert_eq!(e.kem_pk.len(), 1184);
    assert_eq!(e.kem_pk_hash.len(), 32);
}

#[test]
fn test_create_election_wrong_kem_pk_length_rejected() {
    let (mut deps, env) = init_contract();
    let err = execute(
        deps.as_mut(),
        env,
        mock_info("gov", &[]),
        ExecuteMsg::CreateElection {
            election_id: 1,
            params: default_election_params(),
            kem_pk: Binary::from(vec![0u8; 500]), // wrong
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::InvalidKemPublicKeyLength { len: 500 });
}

#[test]
fn test_create_election_wrong_kem_hash_length_rejected() {
    let (mut deps, env) = init_contract();
    let err = execute(
        deps.as_mut(),
        env,
        mock_info("gov", &[]),
        ExecuteMsg::CreateElection {
            election_id: 1,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(vec![0u8; 20]), // wrong: 20 bytes
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::InvalidHashLength { len: 20 });
}

#[test]
fn test_duplicate_election_id_rejected() {
    let (mut deps, env) = init_contract();
    let gov = mock_info("gov", &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CreateElection {
            election_id: 1,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap();
    let err = execute(
        deps.as_mut(),
        env,
        gov,
        ExecuteMsg::CreateElection {
            election_id: 1,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::DuplicateElection {});
}

// ── 7. Atomic SubmitCommitment ────────────────────────────────────────────────

#[test]
fn test_submit_commitment_atomic_success() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);

    let res = execute(
        deps.as_mut(),
        env.clone(),
        mock_info("voter", &[]),
        ExecuteMsg::SubmitCommitment {
            election_id: 1,
            commitment_hash: COMMIT_HASH_B64.to_string(),
            nullifier_hash: NULL_HASH_B64.to_string(),
        },
    )
    .unwrap();
    assert_eq!(res.attributes[0].value, "submit_commitment");

    // Nullifier is consumed
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::NullifierUsed {
            election_id: 1,
            nullifier_hash: NULL_HASH_B64.to_string(),
        },
    )
    .unwrap();
    let used: bool = from_json(&bin).unwrap();
    assert!(used);

    // Commitment is stored
    let bin = query(
        deps.as_ref(),
        env,
        QueryMsg::GetCommitment {
            election_id: 1,
            commitment_hash: COMMIT_HASH_B64.to_string(),
        },
    )
    .unwrap();
    let info: Option<voting_election::state::CommitmentInfo> = from_json(&bin).unwrap();
    assert!(info.is_some());
}

#[test]
fn test_submit_commitment_rejected_outside_voting_open() {
    let (mut deps, env) = init_contract();
    let gov = mock_info("gov", &[]);

    // CreateElection (Configured) -- submission not allowed
    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CreateElection {
            election_id: 1,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap();

    let err = execute(
        deps.as_mut(),
        env.clone(),
        mock_info("voter", &[]),
        ExecuteMsg::SubmitCommitment {
            election_id: 1,
            commitment_hash: COMMIT_HASH_B64.to_string(),
            nullifier_hash: NULL_HASH_B64.to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::InvalidStateTransition {});
}

// ── 8. Duplicate nullifier rejected ──────────────────────────────────────────

#[test]
fn test_duplicate_nullifier_rejected() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);

    // First submission succeeds
    execute(
        deps.as_mut(),
        env.clone(),
        mock_info("voter1", &[]),
        ExecuteMsg::SubmitCommitment {
            election_id: 1,
            commitment_hash: COMMIT_HASH_B64.to_string(),
            nullifier_hash: NULL_HASH_B64.to_string(),
        },
    )
    .unwrap();

    // Second with same nullifier, different commitment → DuplicateNullifier
    let commit2 = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    let err = execute(
        deps.as_mut(),
        env,
        mock_info("voter2", &[]),
        ExecuteMsg::SubmitCommitment {
            election_id: 1,
            commitment_hash: commit2.to_string(),
            nullifier_hash: NULL_HASH_B64.to_string(), // same nullifier
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::DuplicateNullifier {});
}

// ── 9. Duplicate commitment rejected ─────────────────────────────────────────

#[test]
fn test_duplicate_commitment_rejected() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);

    // First submission succeeds
    execute(
        deps.as_mut(),
        env.clone(),
        mock_info("voter1", &[]),
        ExecuteMsg::SubmitCommitment {
            election_id: 1,
            commitment_hash: COMMIT_HASH_B64.to_string(),
            nullifier_hash: NULL_HASH_B64.to_string(),
        },
    )
    .unwrap();

    // Second with same commitment, different nullifier → DuplicateCommitment
    let null2 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    let err = execute(
        deps.as_mut(),
        env,
        mock_info("voter2", &[]),
        ExecuteMsg::SubmitCommitment {
            election_id: 1,
            commitment_hash: COMMIT_HASH_B64.to_string(), // same commitment
            nullifier_hash: null2.to_string(),
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::DuplicateCommitment {});
}

// ── 10. Result commitment publication ────────────────────────────────────────

#[test]
fn test_publish_results_stores_commitment() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);
    let gov = mock_info("gov", &[]);
    let tally = mock_info("tally", &[]);

    execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CloseVoting { election_id: 1 },
    )
    .unwrap();
    execute(
        deps.as_mut(),
        env.clone(),
        tally.clone(),
        ExecuteMsg::StartTallying { election_id: 1 },
    )
    .unwrap();

    let result_hash = Binary::from(KEM_HASH.as_ref());
    execute(
        deps.as_mut(),
        env.clone(),
        tally,
        ExecuteMsg::PublishResults {
            election_id: 1,
            result_hash: result_hash.clone(),
        },
    )
    .unwrap();

    let bin = query(
        deps.as_ref(),
        env,
        QueryMsg::GetResultCommitment { election_id: 1 },
    )
    .unwrap();
    let rc: Option<ResultCommitment> = from_json(&bin).unwrap();
    let rc = rc.unwrap();
    assert_eq!(rc.election_id, 1);
    assert_eq!(rc.result_hash, result_hash);
}

#[test]
fn test_result_already_published_rejected() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);
    let tally = mock_info("tally", &[]);
    let gov = mock_info("gov", &[]);

    execute(
        deps.as_mut(),
        env.clone(),
        gov,
        ExecuteMsg::CloseVoting { election_id: 1 },
    )
    .unwrap();
    execute(
        deps.as_mut(),
        env.clone(),
        tally.clone(),
        ExecuteMsg::StartTallying { election_id: 1 },
    )
    .unwrap();
    execute(
        deps.as_mut(),
        env.clone(),
        tally.clone(),
        ExecuteMsg::PublishResults {
            election_id: 1,
            result_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap();

    // Second publish attempt -- state is ResultsPublished, not Tallying → InvalidStateTransition
    let err = execute(
        deps.as_mut(),
        env,
        tally,
        ExecuteMsg::PublishResults {
            election_id: 1,
            result_hash: Binary::from(DSA_HASH.as_ref()),
        },
    )
    .unwrap_err();
    assert_eq!(err, ContractError::InvalidStateTransition {});
}

// ── 11. Pagination ────────────────────────────────────────────────────────────

#[test]
fn test_pagination_list_elections() {
    let (mut deps, env) = init_contract();
    let gov = mock_info("gov", &[]);

    // Create 35 elections
    for id in 1u64..=35 {
        execute(
            deps.as_mut(),
            env.clone(),
            gov.clone(),
            ExecuteMsg::CreateElection {
                election_id: id,
                params: ElectionParams {
                    name: format!("Election {id}"),
                    description: None,
                },
                kem_pk: Binary::from(KEM_PK.as_ref()),
                kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
            },
        )
        .unwrap();
    }

    // Default limit = 30
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::ListElections {
            start_after: None,
            limit: None,
        },
    )
    .unwrap();
    let elections: Vec<Election> = from_json(&bin).unwrap();
    assert_eq!(elections.len(), 30);
    assert_eq!(elections[0].id, 1);

    // Explicit limit and start_after
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::ListElections {
            start_after: Some(20),
            limit: Some(10),
        },
    )
    .unwrap();
    let elections: Vec<Election> = from_json(&bin).unwrap();
    assert_eq!(elections.len(), 10);
    assert_eq!(elections[0].id, 21);
    assert_eq!(elections[9].id, 30);

    // Limit capped at 30 even when 50 requested
    let bin = query(
        deps.as_ref(),
        env,
        QueryMsg::ListElections {
            start_after: None,
            limit: Some(50),
        },
    )
    .unwrap();
    let elections: Vec<Election> = from_json(&bin).unwrap();
    assert_eq!(elections.len(), 30);
}

// ── 12. Deterministic event attributes ───────────────────────────────────────

#[test]
fn test_event_attributes_deterministic() {
    let (mut deps, env) = init_contract();
    let gov = mock_info("gov", &[]);

    let res = execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::CreateElection {
            election_id: 42,
            params: default_election_params(),
            kem_pk: Binary::from(KEM_PK.as_ref()),
            kem_pk_hash: Binary::from(KEM_HASH.as_ref()),
        },
    )
    .unwrap();
    assert_eq!(res.attributes.len(), 2);
    assert_eq!(res.attributes[0].key, "action");
    assert_eq!(res.attributes[0].value, "create_election");
    assert_eq!(res.attributes[1].key, "election_id");
    assert_eq!(res.attributes[1].value, "42");

    let res = execute(
        deps.as_mut(),
        env.clone(),
        gov.clone(),
        ExecuteMsg::RegisterIssuerKey {
            issuer_key_id: "ik-events".to_string(),
            public_key: Binary::from(DSA_PK.as_ref()),
            public_key_hash: Binary::from(DSA_HASH.as_ref()),
        },
    )
    .unwrap();
    assert_eq!(res.attributes[0].key, "action");
    assert_eq!(res.attributes[0].value, "register_issuer_key");
    assert_eq!(res.attributes[1].key, "issuer_key_id");
    assert_eq!(res.attributes[1].value, "ik-events");
}

// ── 13. Query behavior ────────────────────────────────────────────────────────

#[test]
fn test_query_nonexistent_election_returns_none() {
    let (deps, env) = init_contract();
    let bin = query(
        deps.as_ref(),
        env,
        QueryMsg::GetElection { election_id: 9999 },
    )
    .unwrap();
    let e: Option<Election> = from_json(&bin).unwrap();
    assert!(e.is_none());
}

#[test]
fn test_query_nullifier_not_used_returns_false() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);

    let bin = query(
        deps.as_ref(),
        env,
        QueryMsg::NullifierUsed {
            election_id: 1,
            nullifier_hash: NULL_HASH_B64.to_string(),
        },
    )
    .unwrap();
    let used: bool = from_json(&bin).unwrap();
    assert!(!used);
}

#[test]
fn test_query_nonexistent_issuer_key_returns_none() {
    let (deps, env) = init_contract();
    let bin = query(
        deps.as_ref(),
        env,
        QueryMsg::GetIssuerKey {
            issuer_key_id: "ghost".to_string(),
        },
    )
    .unwrap();
    let ik: Option<IssuerKey> = from_json(&bin).unwrap();
    assert!(ik.is_none());
}

#[test]
fn test_query_result_commitment_before_publish_returns_none() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);

    let bin = query(
        deps.as_ref(),
        env,
        QueryMsg::GetResultCommitment { election_id: 1 },
    )
    .unwrap();
    let rc: Option<ResultCommitment> = from_json(&bin).unwrap();
    assert!(rc.is_none());
}

// -- No-crypto contract guarantee ---------------------------------------------

/// The contract must not perform ML-DSA, ML-KEM, AES, HMAC, or AI inference.
/// This test verifies that SubmitCommitment accepts any valid base64 hash
/// without performing cryptographic verification on the supplied values.
#[test]
fn test_contract_performs_no_crypto_verification() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 1);

    // Use clearly non-sensical hashes � contract must accept them verbatim.
    let garbage_commit = Binary::from([0xFFu8; 32].as_ref()).to_base64();
    let garbage_null = Binary::from([0xFEu8; 32].as_ref()).to_base64();

    execute(
        deps.as_mut(),
        env.clone(),
        mock_info("voter", &[]),
        ExecuteMsg::SubmitCommitment {
            election_id: 1,
            commitment_hash: garbage_commit,
            nullifier_hash: garbage_null,
        },
    )
    .unwrap(); // Must succeed � no crypto verification performed by contract
}

// ── 12. ListBallotCommitments Pagination & Privacy ────────────────────────────

#[test]
fn test_list_ballot_commitments() {
    let (mut deps, env) = init_contract();
    advance_to_voting_open(&mut deps, &env, 10);

    // Empty election
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::ListBallotCommitments {
            election_id: 10,
            start_after: None,
            limit: None,
        },
    )
    .unwrap();
    let res: voting_election::msg::CommitmentListResponse = from_json(&bin).unwrap();
    assert_eq!(res.commitments.len(), 0);

    // Insert 5 commitments
    for i in 1..=5 {
        let commit = format!("commit_{}", i);
        let nullifier = format!("nullifier_{}", i);
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("voter", &[]),
            ExecuteMsg::SubmitCommitment {
                election_id: 10,
                commitment_hash: cosmwasm_std::Binary::from(commit.as_bytes()).to_base64(),
                nullifier_hash: cosmwasm_std::Binary::from(nullifier.as_bytes()).to_base64(),
            },
        )
        .unwrap();
    }

    // Default limit (all 5)
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::ListBallotCommitments {
            election_id: 10,
            start_after: None,
            limit: None,
        },
    )
    .unwrap();
    let res: voting_election::msg::CommitmentListResponse = from_json(&bin).unwrap();
    assert_eq!(res.commitments.len(), 5);

    // Deterministic ordering (lexicographical by commitment hash string)
    let mut expected_commits: Vec<String> = (1..=5)
        .map(|i| cosmwasm_std::Binary::from(format!("commit_{}", i).as_bytes()).to_base64())
        .collect();
    expected_commits.sort(); // cosmwasm map is sorted

    for (i, (c, n)) in res.commitments.iter().enumerate() {
        assert_eq!(c, &expected_commits[i]);
        assert!(!n.is_empty());
    }

    // Pagination limit = 2
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::ListBallotCommitments {
            election_id: 10,
            start_after: None,
            limit: Some(2),
        },
    )
    .unwrap();
    let res1: voting_election::msg::CommitmentListResponse = from_json(&bin).unwrap();
    assert_eq!(res1.commitments.len(), 2);
    assert_eq!(res1.commitments[0].0, expected_commits[0]);
    assert_eq!(res1.commitments[1].0, expected_commits[1]);

    // Pagination start_after
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::ListBallotCommitments {
            election_id: 10,
            start_after: Some(expected_commits[1].clone()),
            limit: Some(2),
        },
    )
    .unwrap();
    let res2: voting_election::msg::CommitmentListResponse = from_json(&bin).unwrap();
    assert_eq!(res2.commitments.len(), 2);
    assert_eq!(res2.commitments[0].0, expected_commits[2]);
    assert_eq!(res2.commitments[1].0, expected_commits[3]);

    // Unknown election
    let bin = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::ListBallotCommitments {
            election_id: 999,
            start_after: None,
            limit: None,
        },
    )
    .unwrap();
    let res_unk: voting_election::msg::CommitmentListResponse = from_json(&bin).unwrap();
    assert_eq!(res_unk.commitments.len(), 0);
}
