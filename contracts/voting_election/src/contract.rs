// contract.rs – entry points for the voting_election contract (Architecture v2.6)
use crate::error::{ContractError, ContractResult};
use crate::handlers;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::{Config, CryptoMode, CONFIG};
use cosmwasm_std::{entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response};
use cw2::set_contract_version;

const CONTRACT_NAME: &str = "crates.io:voting_election";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> ContractResult<Response> {
    let crypto_mode = match msg.crypto_mode.as_str() {
        "Classical" => CryptoMode::Classical,
        "Hybrid" => CryptoMode::Hybrid,
        "PostQuantum" => CryptoMode::PostQuantum,
        _ => {
            return Err(ContractError::InvalidInput {
                msg: "invalid crypto_mode; expected Classical | Hybrid | PostQuantum".into(),
            })
        }
    };

    let config = Config {
        admin: deps.api.addr_validate(&msg.admin)?,
        crypto_mode,
        multisig_governance: deps.api.addr_validate(&msg.multisig_governance)?,
        multisig_emergency: deps.api.addr_validate(&msg.multisig_emergency)?,
        multisig_tally: deps.api.addr_validate(&msg.multisig_tally)?,
    };
    CONFIG.save(deps.storage, &config)?;
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> ContractResult<Response> {
    handlers::handle_execute(deps, env, info, msg)
}

#[entry_point]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> ContractResult<Binary> {
    handlers::handle_query(deps, env, msg)
}
