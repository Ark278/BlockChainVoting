#!/bin/bash
set -euo pipefail

echo "========================================="
echo "   STAGE 6 LOCAL CONTRACT DEPLOYMENT"
echo "========================================="

# 1. CONTRACT PATH BUG FIX
# Script is located at backend/scripts/deploy_local_contract.sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BACKEND_DIR="$(dirname "$DIR")"
REPO_ROOT="$(dirname "$BACKEND_DIR")"

echo "[+] Navigating to contracts directory..."
cd "$REPO_ROOT/contracts/voting_election"

echo "[+] 1. Building contract to WASM..."
if ! command -v docker &> /dev/null; then
    echo "[-] Docker not found. Required for deployment."
    exit 1
fi

echo "    - Using cosmwasm/optimizer:0.17.0"
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/optimizer:0.17.0

WASM_PATH="artifacts/voting_election.wasm"

if [ ! -f "$WASM_PATH" ]; then
    echo "[-] Build failed. No wasm found at $WASM_PATH."
    exit 1
fi

WASM_SHA256=$(sha256sum "$WASM_PATH" | awk '{print $1}')
echo "    - WASM SHA-256: $WASM_SHA256"

echo "[+] 2. Uploading to local wasmd (Docker container: blockchainvoting-wasmd-1)..."

# Verify container is running
if ! docker ps | grep -q "blockchainvoting-wasmd-1"; then
    echo "[-] Container blockchainvoting-wasmd-1 is not running."
    exit 1
fi

# Get validator address
VALIDATOR_ADDR=$(docker exec blockchainvoting-wasmd-1 wasmd keys show validator -a --keyring-backend test | tr -d '\r')
if [ -z "$VALIDATOR_ADDR" ]; then
    echo "[-] Could not find validator address in container."
    exit 1
fi
echo "    - Validator Address: $VALIDATOR_ADDR"

# Copy wasm to container
echo "[+] Copying WASM to container..."
docker cp "$WASM_PATH" blockchainvoting-wasmd-1:/tmp/voting_election.wasm

# Upload
echo "[+] Uploading contract code..."
RES=$(docker exec blockchainvoting-wasmd-1 wasmd tx wasm store /tmp/voting_election.wasm --from validator --keyring-backend test --chain-id testing -y --output json --gas auto --gas-adjustment 1.3 -b sync)
TX_HASH=$(echo "$RES" | jq -r '.txhash')
echo "    - Upload TX Hash: $TX_HASH"

echo "    - Waiting for upload tx inclusion..."
sleep 4

# Extract code ID
CODE_ID=$(docker exec blockchainvoting-wasmd-1 wasmd query tx "$TX_HASH" --output json | jq -r '.logs[0].events[] | select(.type=="store_code").attributes[] | select(.key=="code_id").value')
if [ -z "$CODE_ID" ] || [ "$CODE_ID" == "null" ]; then
    echo "[-] Failed to extract Code ID."
    exit 1
fi
echo "    - Code ID: $CODE_ID"

echo "[+] 3. Instantiating contract..."
# Corrected InstantiateMsg matching actual msg.rs structure
INIT_MSG='{"admin":"'"$VALIDATOR_ADDR"'","crypto_mode":"PostQuantum","multisig_governance":"'"$VALIDATOR_ADDR"'","multisig_emergency":"'"$VALIDATOR_ADDR"'","multisig_tally":"'"$VALIDATOR_ADDR"'"}'
echo "    - InstantiateMsg: $INIT_MSG"

INST_RES=$(docker exec blockchainvoting-wasmd-1 wasmd tx wasm instantiate "$CODE_ID" "$INIT_MSG" --from validator --keyring-backend test --label "voting" --no-admin --chain-id testing -y -b sync --output json)
INST_TX_HASH=$(echo "$INST_RES" | jq -r '.txhash')
echo "    - Instantiate TX Hash: $INST_TX_HASH"

echo "    - Waiting for instantiate tx inclusion..."
sleep 4

CONTRACT_ADDRESS=$(docker exec blockchainvoting-wasmd-1 wasmd query tx "$INST_TX_HASH" --output json | jq -r '.logs[0].events[] | select(.type=="instantiate").attributes[] | select(.key=="_contract_address").value')
if [ -z "$CONTRACT_ADDRESS" ] || [ "$CONTRACT_ADDRESS" == "null" ]; then
    echo "[-] Failed to extract Contract Address from tx, falling back to list-contract-by-code..."
    CONTRACT_ADDRESS=$(docker exec blockchainvoting-wasmd-1 wasmd query wasm list-contract-by-code "$CODE_ID" --output json | jq -r '.contracts[-1]')
fi

echo "    - Contract Address: $CONTRACT_ADDRESS"

echo "[+] 4. Verifying contract..."
CONTRACT_INFO=$(docker exec blockchainvoting-wasmd-1 wasmd query wasm contract "$CONTRACT_ADDRESS" --output json)
VERIFIED_CODE_ID=$(echo "$CONTRACT_INFO" | jq -r '.contract_info.code_id')
if [ "$VERIFIED_CODE_ID" != "$CODE_ID" ]; then
    echo "[-] Verification failed: Contract code ID mismatch ($VERIFIED_CODE_ID != $CODE_ID)"
    exit 1
fi
echo "    - Verification successful."

# Export Config
mkdir -p "$REPO_ROOT/artifacts"
cat <<EOF > "$REPO_ROOT/artifacts/local_chain_deployment.json"
{
  "chain_id": "testing",
  "rpc_url": "http://localhost:26657",
  "rest_url": "http://localhost:1317",
  "code_id": "$CODE_ID",
  "upload_tx_hash": "$TX_HASH",
  "instantiate_tx_hash": "$INST_TX_HASH",
  "contract_address": "$CONTRACT_ADDRESS",
  "wasm_sha256": "$WASM_SHA256"
}
EOF
echo "[+] Configuration exported to artifacts/local_chain_deployment.json"
