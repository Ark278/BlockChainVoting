// src/handlers.rs – core business logic (Architecture v2.6)
//
// Contract responsibilities implemented here:
//   • Election lifecycle state machine
//   • Governance / tally authorization
//   • ML-KEM-768 public key storage per election (1184 B key + 32 B hash)
//   • ML-DSA-65 issuer key registry (1952 B key + 32 B hash)
//   • Atomic commitment + nullifier registration
//   • Nullifier uniqueness enforcement
//   • Commitment uniqueness enforcement
//   • Result commitment storage
//   • Paginated queries
//
// The contract performs NO cryptographic computation:
//   no ML-DSA, no ML-KEM, no AES-GCM, no HMAC, no SHA3.
// All hash values are supplied by the caller and stored verbatim.

use crate::error::{ContractError, ContractResult};
use crate::msg::{CommitmentListResponse, ExecuteMsg, QueryMsg};
use crate::state::{
    CommitmentInfo, Config, Election, ElectionParams, ElectionState, IssuerKey, ResultCommitment,
    COMMITMENTS, CONFIG, ELECTION_CANDIDATES, ELECTIONS, ISSUER_KEYS, NULLIFIERS, RESULT_COMMITMENTS,
};
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdError, StdResult,
};
use cw_storage_plus::Bound;

// ── Constants ────────────────────────────────────────────────────────────────

const KEM_PK_LEN: usize = 1184; // ML-KEM-768 (NIST FIPS 203)
const DSA_PK_LEN: usize = 1952; // ML-DSA-65  (NIST FIPS 204)
const HASH_LEN: usize = 32; // SHA3-256 output

// ── Helpers ──────────────────────────────────────────────────────────────────

fn ensure_governance(deps: Deps, info: &MessageInfo) -> StdResult<()> {
    let cfg = CONFIG.load(deps.storage)?;
    if info.sender != cfg.multisig_governance {
        return Err(StdError::generic_err(
            "unauthorized: not governance multisig",
        ));
    }
    Ok(())
}

fn ensure_tally(deps: Deps, info: &MessageInfo) -> StdResult<()> {
    let cfg = CONFIG.load(deps.storage)?;
    if info.sender != cfg.multisig_tally {
        return Err(StdError::generic_err("unauthorized: not tally multisig"));
    }
    Ok(())
}

fn load_election(deps: Deps, election_id: u64) -> ContractResult<Election> {
    ELECTIONS
        .may_load(deps.storage, election_id)?
        .ok_or(ContractError::ElectionNotFound {})
}

fn save_election(deps: &mut DepsMut, election: &Election) -> ContractResult<()> {
    ELECTIONS.save(deps.storage, election.id, election)?;
    Ok(())
}

fn now(env: &Env) -> u64 {
    env.block.time.seconds()
}

// ── Execute handlers ─────────────────────────────────────────────────────────

/// CreateElection – transition: → Configured
/// Validates kem_pk = 1184 bytes, kem_pk_hash = 32 bytes.
pub fn handle_create_election(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    election_id: u64,
    params: ElectionParams,
    kem_pk: Binary,
    kem_pk_hash: Binary,
) -> ContractResult<Response> {
    ensure_governance(deps.as_ref(), &info).map_err(|_| ContractError::Unauthorized {})?;

    if election_id == 0 {
        return Err(ContractError::InvalidInput {
            msg: "election_id must be non-zero".into(),
        });
    }
    if ELECTIONS.may_load(deps.storage, election_id)?.is_some() {
        return Err(ContractError::DuplicateElection {});
    }
    if kem_pk.len() != KEM_PK_LEN {
        return Err(ContractError::InvalidKemPublicKeyLength { len: kem_pk.len() });
    }
    if kem_pk_hash.len() != HASH_LEN {
        return Err(ContractError::InvalidHashLength {
            len: kem_pk_hash.len(),
        });
    }

    let ts = now(&env);
    let election = Election {
        id: election_id,
        state: ElectionState::Configured,
        params,
        kem_pk,
        kem_pk_hash,
        created_at: ts,
        updated_at: ts,
        opened_at: None,
        voting_opened_at: None,
        closed_at: None,
        tally_started_at: None,
        results_published_at: None,
    };
    save_election(&mut deps, &election)?;

    Ok(Response::new()
        .add_attribute("action", "create_election")
        .add_attribute("election_id", election_id.to_string()))
}

/// OpenRegistration – Configured → RegistrationOpen. Governance only.
pub fn handle_open_registration(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    election_id: u64,
) -> ContractResult<Response> {
    ensure_governance(deps.as_ref(), &info).map_err(|_| ContractError::Unauthorized {})?;
    let mut election = load_election(deps.as_ref(), election_id)?;
    if election.state != ElectionState::Configured {
        return Err(ContractError::InvalidStateTransition {});
    }
    let ts = now(&env);
    election.state = ElectionState::RegistrationOpen;
    election.opened_at = Some(ts);
    election.updated_at = ts;
    save_election(&mut deps, &election)?;

    Ok(Response::new()
        .add_attribute("action", "open_registration")
        .add_attribute("election_id", election_id.to_string()))
}

/// OpenVoting – RegistrationOpen → VotingOpen. Governance only.
pub fn handle_open_voting(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    election_id: u64,
) -> ContractResult<Response> {
    ensure_governance(deps.as_ref(), &info).map_err(|_| ContractError::Unauthorized {})?;
    let mut election = load_election(deps.as_ref(), election_id)?;
    if election.state != ElectionState::RegistrationOpen {
        return Err(ContractError::InvalidStateTransition {});
    }
    let ts = now(&env);
    election.state = ElectionState::VotingOpen;
    election.voting_opened_at = Some(ts);
    election.updated_at = ts;
    save_election(&mut deps, &election)?;

    Ok(Response::new()
        .add_attribute("action", "open_voting")
        .add_attribute("election_id", election_id.to_string()))
}

/// CloseVoting – VotingOpen → VotingClosed. Governance only.
pub fn handle_close_voting(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    election_id: u64,
) -> ContractResult<Response> {
    ensure_governance(deps.as_ref(), &info).map_err(|_| ContractError::Unauthorized {})?;
    let mut election = load_election(deps.as_ref(), election_id)?;
    if election.state != ElectionState::VotingOpen {
        return Err(ContractError::InvalidStateTransition {});
    }
    let ts = now(&env);
    election.state = ElectionState::VotingClosed;
    election.closed_at = Some(ts);
    election.updated_at = ts;
    save_election(&mut deps, &election)?;

    Ok(Response::new()
        .add_attribute("action", "close_voting")
        .add_attribute("election_id", election_id.to_string()))
}

/// StartTallying – VotingClosed → Tallying. Tally multisig only.
pub fn handle_start_tallying(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    election_id: u64,
) -> ContractResult<Response> {
    ensure_tally(deps.as_ref(), &info).map_err(|_| ContractError::Unauthorized {})?;
    let mut election = load_election(deps.as_ref(), election_id)?;
    if election.state != ElectionState::VotingClosed {
        return Err(ContractError::InvalidStateTransition {});
    }
    let ts = now(&env);
    election.state = ElectionState::Tallying;
    election.tally_started_at = Some(ts);
    election.updated_at = ts;
    save_election(&mut deps, &election)?;

    Ok(Response::new()
        .add_attribute("action", "start_tallying")
        .add_attribute("election_id", election_id.to_string()))
}

/// PublishResults – Tallying → ResultsPublished. Tally multisig only.
/// Stores the result commitment hash on-chain.
pub fn handle_publish_results(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    election_id: u64,
    result_hash: Binary,
) -> ContractResult<Response> {
    ensure_tally(deps.as_ref(), &info).map_err(|_| ContractError::Unauthorized {})?;
    let mut election = load_election(deps.as_ref(), election_id)?;
    if election.state != ElectionState::Tallying {
        return Err(ContractError::InvalidStateTransition {});
    }
    if RESULT_COMMITMENTS
        .may_load(deps.storage, election_id)?
        .is_some()
    {
        return Err(ContractError::ResultAlreadyPublished { election_id });
    }

    let ts = now(&env);
    election.state = ElectionState::ResultsPublished;
    election.results_published_at = Some(ts);
    election.updated_at = ts;
    save_election(&mut deps, &election)?;

    let rc = crate::state::ResultCommitment {
        election_id,
        result_hash,
        published_at: ts,
    };
    RESULT_COMMITMENTS.save(deps.storage, election_id, &rc)?;

    Ok(Response::new()
        .add_attribute("action", "publish_results")
        .add_attribute("election_id", election_id.to_string()))
}

/// SubmitCommitment – atomically registers commitment_hash and nullifier_hash.
/// Only accepted during VotingOpen.
/// Duplicate nullifier → DuplicateNullifier.
/// Duplicate commitment → DuplicateCommitment.
/// No cryptographic verification; hashes are stored verbatim.
pub fn handle_submit_commitment(
    deps: DepsMut,
    env: Env,
    _info: MessageInfo,
    election_id: u64,
    commitment_hash: String,
    nullifier_hash: String,
) -> ContractResult<Response> {
    let election = load_election(deps.as_ref(), election_id)?;
    if election.state != ElectionState::VotingOpen {
        return Err(ContractError::InvalidStateTransition {});
    }

    // 1. Nullifier uniqueness check (first, so duplicate vote is rejected before any writes)
    let null_key = (election_id, nullifier_hash.clone());
    if NULLIFIERS
        .may_load(deps.storage, null_key.clone())?
        .is_some()
    {
        return Err(ContractError::DuplicateNullifier {});
    }

    // 2. Commitment uniqueness check
    let commit_key = (election_id, commitment_hash.clone());
    if COMMITMENTS
        .may_load(deps.storage, commit_key.clone())?
        .is_some()
    {
        return Err(ContractError::DuplicateCommitment {});
    }

    // 3. Parse hashes to Binary for storage (base64 strings supplied by caller)
    let commitment_bin =
        Binary::from_base64(&commitment_hash).map_err(|_| ContractError::InvalidInput {
            msg: "commitment_hash is not valid base64".into(),
        })?;
    let nullifier_bin =
        Binary::from_base64(&nullifier_hash).map_err(|_| ContractError::InvalidInput {
            msg: "nullifier_hash is not valid base64".into(),
        })?;

    let ts = now(&env);

    // 4. Atomic write: nullifier first, then commitment
    NULLIFIERS.save(deps.storage, null_key, &())?;
    COMMITMENTS.save(
        deps.storage,
        commit_key,
        &CommitmentInfo {
            election_id,
            commitment_hash: commitment_bin,
            nullifier_hash: nullifier_bin,
            submitted_at: ts,
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "submit_commitment")
        .add_attribute("election_id", election_id.to_string()))
}

/// RegisterIssuerKey – stores ML-DSA-65 issuer public key.
/// Validates public_key = 1952 bytes, public_key_hash = 32 bytes.
/// Rejects if the issuer_key_id is already registered.
pub fn handle_register_issuer_key(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    issuer_key_id: String,
    public_key: Binary,
    public_key_hash: Binary,
) -> ContractResult<Response> {
    ensure_governance(deps.as_ref(), &info).map_err(|_| ContractError::Unauthorized {})?;

    if public_key.len() != DSA_PK_LEN {
        return Err(ContractError::InvalidIssuerPublicKeyLength {
            len: public_key.len(),
        });
    }
    if public_key_hash.len() != HASH_LEN {
        return Err(ContractError::InvalidHashLength {
            len: public_key_hash.len(),
        });
    }

    let key_ref = issuer_key_id.as_str();
    if ISSUER_KEYS.may_load(deps.storage, key_ref)?.is_some() {
        return Err(ContractError::IssuerKeyAlreadyExists {
            issuer_key_id: issuer_key_id.clone(),
        });
    }

    ISSUER_KEYS.save(
        deps.storage,
        key_ref,
        &IssuerKey {
            public_key,
            public_key_hash,
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "register_issuer_key")
        .add_attribute("issuer_key_id", issuer_key_id))
}

/// RotateIssuerKey – adds a new issuer key entry.
/// Old keys remain in storage; credentials signed by them stay valid.
/// Validates public_key = 1952 bytes, public_key_hash = 32 bytes.
pub fn handle_rotate_issuer_key(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    issuer_key_id: String,
    public_key: Binary,
    public_key_hash: Binary,
) -> ContractResult<Response> {
    ensure_governance(deps.as_ref(), &info).map_err(|_| ContractError::Unauthorized {})?;

    if public_key.len() != DSA_PK_LEN {
        return Err(ContractError::InvalidIssuerPublicKeyLength {
            len: public_key.len(),
        });
    }
    if public_key_hash.len() != HASH_LEN {
        return Err(ContractError::InvalidHashLength {
            len: public_key_hash.len(),
        });
    }

    // Rotation unconditionally overwrites the entry for this issuer_key_id.
    // Historical keys remain queryable under their own IDs.
    ISSUER_KEYS.save(
        deps.storage,
        issuer_key_id.as_str(),
        &IssuerKey {
            public_key,
            public_key_hash,
        },
    )?;

    Ok(Response::new()
        .add_attribute("action", "rotate_issuer_key")
        .add_attribute("issuer_key_id", issuer_key_id))
}

// ── Query handlers ────────────────────────────────────────────────────────────

pub fn query_get_election(deps: Deps, election_id: u64) -> ContractResult<Binary> {
    let election = ELECTIONS.may_load(deps.storage, election_id)?;
    to_json_binary(&election).map_err(Into::into)
}

pub fn query_list_elections(
    deps: Deps,
    start_after: Option<u64>,
    limit: Option<u32>,
) -> ContractResult<Binary> {
    let start = start_after.map(Bound::exclusive);
    let lim = limit.unwrap_or(30).min(30) as usize;
    let elections: Vec<Election> = ELECTIONS
        .range(deps.storage, start, None, cosmwasm_std::Order::Ascending)
        .take(lim)
        .map(|item| item.map(|(_, e)| e))
        .collect::<Result<Vec<_>, _>>()?;
    to_json_binary(&elections).map_err(Into::into)
}

pub fn query_get_commitment(
    deps: Deps,
    election_id: u64,
    commitment_hash: String,
) -> ContractResult<Binary> {
    let info = COMMITMENTS.may_load(deps.storage, (election_id, commitment_hash))?;
    to_json_binary(&info).map_err(Into::into)
}

pub fn query_nullifier_used(
    deps: Deps,
    election_id: u64,
    nullifier_hash: String,
) -> ContractResult<Binary> {
    let used = NULLIFIERS.has(deps.storage, (election_id, nullifier_hash));
    to_json_binary(&used).map_err(Into::into)
}

pub fn query_get_issuer_key(deps: Deps, issuer_key_id: String) -> ContractResult<Binary> {
    let ik = ISSUER_KEYS.may_load(deps.storage, issuer_key_id.as_str())?;
    to_json_binary(&ik).map_err(Into::into)
}

pub fn query_get_result_commitment(deps: Deps, election_id: u64) -> ContractResult<Binary> {
    let rc = RESULT_COMMITMENTS.may_load(deps.storage, election_id)?;
    to_json_binary(&rc).map_err(Into::into)
}

pub fn query_list_ballot_commitments(
    deps: Deps,
    election_id: u64,
    start_after: Option<String>,
    limit: Option<u32>,
) -> ContractResult<Binary> {
    let start = start_after.map(Bound::exclusive);
    let lim = limit.unwrap_or(30).min(100) as usize;

    let commitments: Vec<(String, String)> = COMMITMENTS
        .prefix(election_id)
        .range(deps.storage, start, None, cosmwasm_std::Order::Ascending)
        .take(lim)
        .map(|item| {
            item.map(|(commit_hash_string, info)| {
                (
                    commit_hash_string,
                    cosmwasm_std::Binary::to_base64(&info.nullifier_hash),
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let resp = CommitmentListResponse { commitments };
    to_json_binary(&resp).map_err(Into::into)
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

pub fn handle_execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> ContractResult<Response> {
    match msg {
        ExecuteMsg::CreateElection {
            election_id,
            params,
            kem_pk,
            kem_pk_hash,
        } => handle_create_election(deps, env, info, election_id, params, kem_pk, kem_pk_hash),

        ExecuteMsg::RegisterCandidate {
            election_id,
            candidate,
        } => handle_register_candidate(deps, env, info, election_id, candidate),

        ExecuteMsg::OpenRegistration { election_id } => {
            handle_open_registration(deps, env, info, election_id)
        }

        ExecuteMsg::OpenVoting { election_id } => handle_open_voting(deps, env, info, election_id),

        ExecuteMsg::CloseVoting { election_id } => {
            handle_close_voting(deps, env, info, election_id)
        }

        ExecuteMsg::StartTallying { election_id } => {
            handle_start_tallying(deps, env, info, election_id)
        }

        ExecuteMsg::PublishResults {
            election_id,
            result_hash,
        } => handle_publish_results(deps, env, info, election_id, result_hash),

        ExecuteMsg::SubmitCommitment {
            election_id,
            commitment_hash,
            nullifier_hash,
        } => handle_submit_commitment(
            deps,
            env,
            info,
            election_id,
            commitment_hash,
            nullifier_hash,
        ),

        ExecuteMsg::RegisterIssuerKey {
            issuer_key_id,
            public_key,
            public_key_hash,
        } => {
            handle_register_issuer_key(deps, env, info, issuer_key_id, public_key, public_key_hash)
        }

        ExecuteMsg::RotateIssuerKey {
            issuer_key_id,
            public_key,
            public_key_hash,
        } => handle_rotate_issuer_key(deps, env, info, issuer_key_id, public_key, public_key_hash),
    }
}

pub fn handle_query(deps: Deps, _env: Env, msg: QueryMsg) -> ContractResult<Binary> {
    match msg {
        QueryMsg::GetElection { election_id } => query_get_election(deps, election_id),
        QueryMsg::ListElections { start_after, limit } => {
            query_list_elections(deps, start_after, limit)
        }
        QueryMsg::ListCandidates { election_id } => {
            query_list_candidates(deps, election_id)
        }
        QueryMsg::GetCommitment {
            election_id,
            commitment_hash,
        } => query_get_commitment(deps, election_id, commitment_hash),
        QueryMsg::NullifierUsed {
            election_id,
            nullifier_hash,
        } => query_nullifier_used(deps, election_id, nullifier_hash),
        QueryMsg::GetIssuerKey { issuer_key_id } => query_get_issuer_key(deps, issuer_key_id),
        QueryMsg::GetResultCommitment { election_id } => {
            query_get_result_commitment(deps, election_id)
        }
        QueryMsg::ListBallotCommitments {
            election_id,
            start_after,
            limit,
        } => query_list_ballot_commitments(deps, election_id, start_after, limit),
    }
}

pub fn handle_register_candidate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    election_id: u64,
    candidate: String,
) -> ContractResult<Response> {
    ensure_governance(deps.as_ref(), &info).map_err(|_| ContractError::Unauthorized {})?;
    let election = ELECTIONS.load(deps.storage, election_id).map_err(|_| ContractError::ElectionNotFound {})?;
    if election.state != ElectionState::Configured && election.state != ElectionState::RegistrationOpen {
        return Err(ContractError::InvalidStateTransition {});
    }
    let mut candidates = ELECTION_CANDIDATES.may_load(deps.storage, election_id)?.unwrap_or_default();
    if !candidates.contains(&candidate) {
        candidates.push(candidate);
        ELECTION_CANDIDATES.save(deps.storage, election_id, &candidates)?;
    }
    Ok(Response::new().add_attribute("action", "register_candidate").add_attribute("election_id", election_id.to_string()))
}

pub fn query_list_candidates(
    deps: Deps,
    election_id: u64,
) -> ContractResult<Binary> {
    let candidates = ELECTION_CANDIDATES.may_load(deps.storage, election_id)?.unwrap_or_default();
    Ok(to_json_binary(&crate::msg::CandidateListResponse { candidates })?)
}
