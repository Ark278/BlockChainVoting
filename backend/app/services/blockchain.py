"""CosmWasm blockchain client (Architecture v2.6 §12).

Provides typed query and execute operations against the voting_election contract.
All business logic remains on-chain; this service only translates between Python
types and the chain's JSON/REST API.

No contract logic is duplicated here. Pre-validation in FastAPI is advisory only;
the chain is authoritative for all on-chain rules.
"""

from __future__ import annotations

import base64
import json
import logging
from typing import Any

import httpx

from app.config import get_settings
from app.errors import (
    BlockchainSubmissionFailureError,
    ElectionNotFoundError,
)

logger = logging.getLogger("voting.blockchain")

# ── CosmWasm query types ──────────────────────────────────────────────────────


class BlockchainClient:
    """Typed CosmWasm REST client for the voting_election contract.

    All queries use the CosmWasm smart query REST endpoint:
        GET /cosmwasm/wasm/v1/contract/{address}/smart/{base64(query_json)}

    Transaction submission uses the Cosmos SDK broadcast endpoint.
    """

    def __init__(
        self,
        rest_url: str | None = None,
        contract_address: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        settings = get_settings()
        self._rest_url = (rest_url or settings.chain_rest_url).rstrip("/")
        self._contract = contract_address or settings.voting_contract_address
        self._http = http_client or httpx.AsyncClient(timeout=30.0)

    async def _query(self, query: dict[str, Any]) -> dict[str, Any]:
        """Execute a CosmWasm smart query."""
        query_b64 = base64.b64encode(json.dumps(query).encode()).decode()
        url = f"{self._rest_url}/cosmwasm/wasm/v1/contract/{self._contract}/smart/{query_b64}"
        try:
            resp = await self._http.get(url)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code == 400:
                # Contract returned an error (e.g. not found)
                body = exc.response.json()
                raise ElectionNotFoundError(str(body)) from exc
            raise BlockchainSubmissionFailureError(
                f"Chain query failed: {exc.response.status_code}"
            ) from exc
        except httpx.RequestError as exc:
            raise BlockchainSubmissionFailureError(f"Chain unreachable: {exc}") from exc

        data = resp.json()
        return data.get("data", data)  # CosmWasm wraps result in {"data": ...}

    # ── Queries ───────────────────────────────────────────────────────────────

    async def get_election(self, election_id: int) -> dict[str, Any] | None:
        """Query election state and configuration.

        Returns the Election record or None if not found.
        """
        try:
            result = await self._query({"get_election": {"election_id": election_id}})
        except ElectionNotFoundError:
            return None
        return result  # type: ignore[return-value]

    async def get_election_kem_pk(self, election_id: int) -> tuple[bytes, bytes] | None:
        """Retrieve the ML-KEM-768 public key and its hash for an election.

        Returns:
            (kem_pk: bytes, kem_pk_hash: bytes) or None if election not found.
        """
        election = await self.get_election(election_id)
        if election is None:
            return None
        pk_b64: str = election["kem_pk"]
        hash_b64: str = election["kem_pk_hash"]
        return base64.b64decode(pk_b64), base64.b64decode(hash_b64)

    async def get_issuer_key(self, issuer_key_id: str) -> dict[str, bytes] | None:
        """Retrieve an ML-DSA-65 issuer key from the on-chain registry.

        Returns:
            {"public_key": bytes, "public_key_hash": bytes} or None if not found.
        """
        result = await self._query({"get_issuer_key": {"issuer_key_id": issuer_key_id}})
        if result is None:
            return None
        return {
            "public_key": base64.b64decode(result["public_key"]),
            "public_key_hash": base64.b64decode(result["public_key_hash"]),
        }

    async def nullifier_used(self, election_id: int, nullifier_hash_b64: str) -> bool:
        """Check if a nullifier hash has already been used on-chain."""
        result = await self._query(
            {
                "nullifier_used": {
                    "election_id": election_id,
                    "nullifier_hash": nullifier_hash_b64,
                }
            }
        )
        return bool(result)

    async def get_commitment(
        self, election_id: int, commitment_hash_b64: str
    ) -> dict[str, Any] | None:
        """Query a commitment record by hash."""
        try:
            result = await self._query(
                {
                    "get_commitment": {
                        "election_id": election_id,
                        "commitment_hash": commitment_hash_b64,
                    }
                }
            )
            return result  # type: ignore[return-value]
        except ElectionNotFoundError:
            return None

    async def get_result_commitment(self, election_id: int) -> dict[str, Any] | None:
        """Query the result commitment for a completed election."""
        result = await self._query({"get_result_commitment": {"election_id": election_id}})
        return result  # type: ignore[return-value]

    async def get_candidates(self, election_id: int) -> list[str]:
        """Query the list of registered candidates for an election."""
        result = await self._query({"list_candidates": {"election_id": election_id}})
        if isinstance(result, dict) and "candidates" in result:
            return result["candidates"]
        return []

    async def list_elections(
        self, start_after: int | None = None, limit: int = 30
    ) -> list[dict[str, Any]]:
        """List elections with pagination."""
        query: dict[str, Any] = {
            "list_elections": {
                "limit": limit,
            }
        }
        if start_after is not None:
            query["list_elections"]["start_after"] = start_after
        result = await self._query(query)
        return list(result) if isinstance(result, list) else []

    async def list_ballot_commitments(
        self,
        election_id: int,
        start_after: str | None = None,
        limit: int | None = None,
    ) -> list[tuple[str, str]]:
        """Authoritative paginated on-chain commitment enumeration.

        Iterates through all pages of the ListBallotCommitments query
        to return the complete authoritative set of (commitment_hash_b64,
        nullifier_hash_b64) tuples for a given election.

        Safety:
            - Enforces the contract's maximum page size (100).
            - Detects repeated page cursors to prevent infinite loops.
            - Maximum 10000 iterations as an absolute safety bound.
        """
        page_size = min(limit or 100, 100)
        all_commitments: list[tuple[str, str]] = []
        cursor: str | None = start_after
        seen_cursors: set[str | None] = set()
        max_iterations = 10000

        for _ in range(max_iterations):
            if cursor in seen_cursors:
                break
            seen_cursors.add(cursor)

            q: dict[str, Any] = {
                "list_ballot_commitments": {
                    "election_id": election_id,
                    "limit": page_size,
                }
            }
            if cursor is not None:
                q["list_ballot_commitments"]["start_after"] = cursor

            result = await self._query(q)
            page = result.get("commitments", []) if isinstance(result, dict) else []

            if not page:
                break

            for entry in page:
                if isinstance(entry, (list, tuple)) and len(entry) == 2:
                    commit_b64, null_b64 = str(entry[0]), str(entry[1])
                    all_commitments.append((commit_b64, null_b64))

            # The last commitment_hash is the cursor for the next page
            last_commit = page[-1][0] if isinstance(page[-1], (list, tuple)) else page[-1]
            cursor = str(last_commit)

            if len(page) < page_size:
                break  # Last page

        return all_commitments

    # ── Transactions ──────────────────────────────────────────────────────────

    async def register_candidate(self, election_id: int, candidate: str) -> str:
        """Register a candidate on-chain."""
        execute_msg = {
            "register_candidate": {
                "election_id": election_id,
                "candidate": candidate,
            }
        }
        
        import os
        import subprocess
        import asyncio
        if os.environ.get("USE_MOCK_BLOCKCHAIN") == "0" and "127.0.0.1" in self._rest_url:
            msg_str = json.dumps(execute_msg)
            cmd = [
                "docker", "exec", "blockchainvoting-wasmd-1", "wasmd", "tx", "wasm", "execute", 
                self._contract, msg_str, "--from", "validator", "--keyring-backend", "test",
                "-y", "--output", "json", "--gas", "auto", "--gas-adjustment", "1.5",
                "--chain-id", "testing"
            ]
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise BlockchainSubmissionFailureError(f"Docker broadcast failed: {stderr.decode()}")
            try:
                data = json.loads(stdout.decode())
                if data.get("code", 0) != 0:
                    raise BlockchainSubmissionFailureError(f"Chain rejection: {data.get('raw_log')}")
                return data["txhash"]
            except Exception as e:
                raise BlockchainSubmissionFailureError(f"Failed to parse docker output: {str(e)} stdout: {stdout.decode()}")
        
        url = f"{self._rest_url}/cosmos/tx/v1beta1/txs"
        resp = await self._http.post(
            url,
            json={
                "tx_bytes": "",
                "mode": "BROADCAST_MODE_SYNC",
                "execute_msg": execute_msg,
            },
        )
        if resp.status_code not in (200, 201):
            raise BlockchainSubmissionFailureError(f"HTTP {resp.status_code}: {resp.text}")
        data = resp.json()
        return data.get("tx_response", {}).get("txhash", "")

    async def submit_commitment(
        self,
        election_id: int,
        commitment_hash_b64: str,
        nullifier_hash_b64: str,
        sender_address: str | None = None,
    ) -> str:
        """Submit a ballot commitment to the CosmWasm contract.

        Constructs and broadcasts a MsgExecuteContract transaction.
        Returns the transaction hash on success.

        Args:
            election_id:          On-chain election ID.
            commitment_hash_b64:  Base64-encoded 32-byte commitment hash.
            nullifier_hash_b64:   Base64-encoded 32-byte nullifier hash.
            kem_ct_hash_b64:      Base64-encoded 32-byte KEM ciphertext hash.
            sender_address:       Cosmos SDK bech32 address of the submitter.

        Returns:
            Transaction hash string (hex).
        """
        execute_msg = {
            "submit_commitment": {
                "election_id": election_id,
                "commitment_hash": commitment_hash_b64,
                "nullifier_hash": nullifier_hash_b64,
            }
        }

        import os
        import subprocess
        
        # Determine if we should mock transaction broadcast via docker exec
        if os.environ.get("USE_MOCK_BLOCKCHAIN") == "0" and "127.0.0.1" in self._rest_url:
            msg_str = json.dumps(execute_msg)
            cmd = [
                "docker", "exec", "blockchainvoting-wasmd-1", "wasmd", "tx", "wasm", "execute", 
                self._contract, msg_str, "--from", "validator", "--keyring-backend", "test",
                "-y", "--output", "json", "--gas", "auto", "--gas-adjustment", "1.5",
                "--chain-id", "testing"
            ]
            import asyncio
            proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = await proc.communicate()
            if proc.returncode != 0:
                raise BlockchainSubmissionFailureError(f"Docker broadcast failed: {stderr.decode()}")
            try:
                data = json.loads(stdout.decode())
                if data.get("code", 0) != 0:
                    raise BlockchainSubmissionFailureError(f"Chain rejection: {data.get('raw_log')}")
                return data["txhash"]
            except Exception as e:
                raise BlockchainSubmissionFailureError(f"Failed to parse docker output: {str(e)} stdout: {stdout.decode()}")

        url = f"{self._rest_url}/cosmos/tx/v1beta1/txs"
        try:
            # Placeholder: in production, `tx_bytes` is a signed protobuf tx
            resp = await self._http.post(
                url,
                json={
                    "tx_bytes": "",  # populated by signing module
                    "mode": "BROADCAST_MODE_SYNC",
                    "execute_msg": execute_msg,  # for local dev mock
                },
            )
            if resp.status_code not in (200, 201):
                body = resp.text
                raise BlockchainSubmissionFailureError(
                    f"Transaction broadcast failed: HTTP {resp.status_code}: {body}"
                )
            data = resp.json()
            tx_hash: str = data.get("tx_response", {}).get("txhash", "")
            if not tx_hash:
                raise BlockchainSubmissionFailureError(
                    "Transaction broadcast returned no txhash"
                )
            return tx_hash
        except BlockchainSubmissionFailureError:
            raise
        except httpx.RequestError as exc:
            raise BlockchainSubmissionFailureError(f"Chain unreachable: {exc}") from exc


    async def get_election_state(self, election_id: int) -> str | None:
        """Return the current state string of an election.

        Returns one of: Draft, Configured, RegistrationOpen, VotingOpen,
        VotingClosed, Tallying, ResultsPublished, Archived — or None if
        the election does not exist.
        """
        election = await self.get_election(election_id)
        if election is None:
            return None
        return str(election.get("state", ""))

    async def publish_result_commitment(
        self,
        election_id: int,
        result_commitment_b64: str,
        sender_address: str | None = None,
    ) -> str:
        """Publish the tally result commitment to the CosmWasm contract.

        Args:
            election_id:            On-chain election ID.
            result_commitment_b64:  Base64-encoded 32-byte SHA3-256 of the
                                    canonical tally result bytes.
            sender_address:         Cosmos SDK bech32 address of the submitter.

        Returns:
            Transaction hash string.

        Raises:
            ResultPublicationError: If the chain rejects the publication.
        """
        from app.errors import ResultPublicationError  # noqa: PLC0415

        execute_msg = {
            "publish_result_commitment": {
                "election_id": election_id,
                "result_commitment": result_commitment_b64,
            }
        }

        url = f"{self._rest_url}/cosmos/tx/v1beta1/txs"
        try:
            resp = await self._http.post(
                url,
                json={
                    "tx_bytes": "",  # populated by signing module in production
                    "mode": "BROADCAST_MODE_SYNC",
                    "execute_msg": execute_msg,  # for local dev mock
                },
            )
            if resp.status_code not in (200, 201):
                body = resp.text
                raise ResultPublicationError(
                    f"Result commitment publication failed: HTTP {resp.status_code}: {body}"
                )
            data = resp.json()
            tx_hash: str = data.get("tx_response", {}).get("txhash", "")
            if not tx_hash:
                raise ResultPublicationError(
                    "Result commitment publication returned no txhash"
                )
            return tx_hash
        except ResultPublicationError:
            raise
        except httpx.RequestError as exc:
            raise ResultPublicationError(f"Chain unreachable: {exc}") from exc

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._http.aclose()

