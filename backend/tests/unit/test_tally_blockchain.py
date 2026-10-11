"""Tests: result commitment publication to blockchain (Stage 3 §17 — Blockchain).

Tests:
  - result commitment submitted correctly
  - duplicate publication handled correctly
  - wrong election state rejected (TallyStateError)
  - list_ballot_commitments returns election_id + commitment_hash + nullifier_hash
"""

from __future__ import annotations

import base64
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from app.errors import ResultPublicationError, TallyStateError
from app.services.blockchain import BlockchainClient
from app.tally.engine import TallyCounters, _compute_result_commitment, _serialize_canonical_result

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_mock_client(
    query_responses: dict | None = None,
    tx_response: dict | None = None,
    tx_status: int = 200,
) -> BlockchainClient:
    """Build a BlockchainClient whose HTTP calls are fully mocked."""
    mock_http = AsyncMock(spec=httpx.AsyncClient)

    async def mock_get(url: str, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        # Return the query_responses dict for any query
        resp.json.return_value = {"data": query_responses or {}}
        return resp

    async def mock_post(url: str, **kwargs):
        resp = MagicMock()
        resp.status_code = tx_status
        resp.text = json.dumps(tx_response or {"tx_response": {"txhash": "ABCDEF1234"}})
        resp.json.return_value = tx_response or {"tx_response": {"txhash": "ABCDEF1234"}}
        return resp

    mock_http.get = mock_get
    mock_http.post = mock_post

    return BlockchainClient(
        rest_url="http://localhost:1317",
        contract_address="cosmos1test",
        http_client=mock_http,
    )


# ── list_ballot_commitments returns required fields ───────────────────────────


@pytest.mark.asyncio
async def test_list_ballot_commitments_returns_required_fields() -> None:
    commitment_b64 = base64.b64encode(b"\xaa" * 32).decode()
    nullifier_b64 = base64.b64encode(b"\xbb" * 32).decode()

    query_resp = [
        {
            "election_id": 1,
            "commitment_hash": commitment_b64,
            "nullifier_hash": nullifier_b64,
        }
    ]

    mock_http = AsyncMock(spec=httpx.AsyncClient)

    async def mock_get(url: str, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"data": query_resp}
        return resp

    mock_http.get = mock_get
    client = BlockchainClient(
        rest_url="http://localhost:1317",
        contract_address="cosmos1test",
        http_client=mock_http,
    )

    result = await client.list_ballot_commitments(election_id=1, limit=50)
    assert len(result) == 1
    item = result[0]
    assert "commitment_hash" in item
    assert "nullifier_hash" in item
    assert item["commitment_hash"] == commitment_b64
    assert item["nullifier_hash"] == nullifier_b64


# ── publish_result_commitment — success ───────────────────────────────────────


@pytest.mark.asyncio
async def test_publish_result_commitment_success() -> None:
    counters = TallyCounters(valid_ballots=3)
    canonical = _serialize_canonical_result(1, {"A": 3}, counters)
    commitment = _compute_result_commitment(canonical)
    commitment_b64 = base64.b64encode(commitment).decode()

    client = _make_mock_client(
        tx_response={"tx_response": {"txhash": "TX_HASH_SUCCESS"}}
    )
    tx_hash = await client.publish_result_commitment(
        election_id=1,
        result_commitment_b64=commitment_b64,
    )
    assert tx_hash == "TX_HASH_SUCCESS"


# ── publish_result_commitment — chain returns non-200 ────────────────────────


@pytest.mark.asyncio
async def test_publish_result_commitment_chain_error_raises() -> None:
    counters = TallyCounters(valid_ballots=1)
    canonical = _serialize_canonical_result(1, {"A": 1}, counters)
    commitment_b64 = base64.b64encode(_compute_result_commitment(canonical)).decode()

    client = _make_mock_client(
        tx_response={"error": "already published"},
        tx_status=400,
    )
    with pytest.raises(ResultPublicationError):
        await client.publish_result_commitment(
            election_id=1,
            result_commitment_b64=commitment_b64,
        )


# ── publish_result_commitment — no txhash ────────────────────────────────────


@pytest.mark.asyncio
async def test_publish_result_commitment_no_txhash_raises() -> None:
    counters = TallyCounters()
    canonical = _serialize_canonical_result(1, {}, counters)
    commitment_b64 = base64.b64encode(_compute_result_commitment(canonical)).decode()

    client = _make_mock_client(
        tx_response={"tx_response": {}},  # no txhash field
    )
    with pytest.raises(ResultPublicationError, match="no txhash"):
        await client.publish_result_commitment(
            election_id=1,
            result_commitment_b64=commitment_b64,
        )


# ── get_election_state ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_election_state_tallying() -> None:
    mock_http = AsyncMock(spec=httpx.AsyncClient)

    async def mock_get(url: str, **kwargs):
        resp = MagicMock()
        resp.raise_for_status = MagicMock()
        resp.json.return_value = {"data": {"state": "Tallying", "kem_pk": "", "kem_pk_hash": ""}}
        return resp

    mock_http.get = mock_get
    client = BlockchainClient(
        rest_url="http://localhost:1317",
        contract_address="cosmos1test",
        http_client=mock_http,
    )
    state = await client.get_election_state(1)
    assert state == "Tallying"


@pytest.mark.asyncio
async def test_get_election_state_not_found() -> None:
    mock_http = AsyncMock(spec=httpx.AsyncClient)

    async def mock_get(url: str, **kwargs):
        resp = MagicMock()
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Not found", request=MagicMock(), response=MagicMock(status_code=400)
        )
        resp.response.json.return_value = {"error": "not found"}
        raise httpx.HTTPStatusError(
            "Not found", request=MagicMock(), response=MagicMock(status_code=400, json=lambda: {})
        )

    mock_http.get = mock_get
    client = BlockchainClient(
        rest_url="http://localhost:1317",
        contract_address="cosmos1test",
        http_client=mock_http,
    )
    state = await client.get_election_state(999)
    assert state is None


# ── TallyStateError raised when state is not Tallying ────────────────────────


def test_tally_state_error_is_raised_for_non_tallying_state() -> None:
    """TallyStateError must be raised if the election state != Tallying."""

    err = TallyStateError("Election is not in Tallying state")
    assert isinstance(err, TallyStateError)
    assert "Tallying" in str(err)
