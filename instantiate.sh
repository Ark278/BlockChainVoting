#!/bin/sh
wasmd tx wasm instantiate 2 \
  '{"admin":"wasm163pd3yng70t2kjcqghjrlqzklhkdazmk672mak","crypto_mode":"PostQuantum","multisig_governance":"wasm163pd3yng70t2kjcqghjrlqzklhkdazmk672mak","multisig_emergency":"wasm163pd3yng70t2kjcqghjrlqzklhkdazmk672mak","multisig_tally":"wasm163pd3yng70t2kjcqghjrlqzklhkdazmk672mak"}' \
  --from validator --keyring-backend test --label voting_election_v2 --no-admin \
  -y --output json --gas auto --gas-adjustment 1.5 --chain-id testing
