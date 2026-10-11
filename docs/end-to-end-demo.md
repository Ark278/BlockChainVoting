# End-to-End Demo

This document describes how to execute the complete election lifecycle.

## Fast Automated E2E
To run the automated Python test suite without setting up a Dockerized chain:
1. Ensure `liboqs` is installed.
2. Run `python backend/scripts/e2e_scenario.py`.
3. The script will mock the blockchain layer but execute real FastAPI and crypto paths.

## Real Local Blockchain E2E
To test against a real CosmWasm node (e.g., LocalOsmosis or wasmd):
1. Start the local node via Docker (e.g. `docker run -d -p 1317:1317 cosmwasm/wasmd`).
2. Deploy the `voting_election` contract and note the address.
3. Update `backend/.env` with `VOTING_CONTRACT_ADDRESS` and `CHAIN_REST_URL="http://localhost:1317"`.
4. Run `USE_MOCK_BLOCKCHAIN=0 python backend/scripts/e2e_scenario.py`.

## Lifecycle
1. **Create Election**: Deploy contract on-chain.
2. **Submit Credentials**: Signed by ML-DSA-65 keys.
3. **Submit Ballot**: Fast API validates credentials, encrypts with ML-KEM-768 & AES-256-GCM.
4. **Blockchain Commit**: Nullifier and Commitment stored on chain.
5. **Tally**: Decrypts and computes deterministic JSON tally.
6. **Publish Result**: Tally commitment posted to chain.
