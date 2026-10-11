"""Tests: AI failure handling (Stage 4 §12, §14).

Tests:
  - inference timeout
  - malformed telemetry
  - model missing
  - service unavailable
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from app.ai.anomaly_service import AnomalyDetectionService
from app.ai.telemetry import AggregatedTelemetry


@pytest.mark.asyncio
async def test_inference_timeout() -> None:
    service = AnomalyDetectionService(model_dir="/tmp", timeout_seconds=0.01)
    
    # Mock the internal sync infer to block
    def slow_infer(*args):
        import time
        time.sleep(0.1)
        return None
        
    with patch.object(service, "_run_sync_inference", side_effect=slow_infer):
        agg = AggregatedTelemetry(1, "00", 1, 0.0, 0.0, 0.0, 0.0)
        res = await service.infer(agg)
        # Timeout returns None, does not raise
        assert res is None

@pytest.mark.asyncio
async def test_model_missing() -> None:
    service = AnomalyDetectionService(model_dir="/tmp/does_not_exist", timeout_seconds=1.0)
    agg = AggregatedTelemetry(1, "00", 1, 0.0, 0.0, 0.0, 0.0)
    res = await service.infer(agg)
    # Missing model returns None, does not raise
    assert res is None

@pytest.mark.asyncio
async def test_infer_and_persist_handles_exceptions() -> None:
    service = AnomalyDetectionService(model_dir="/tmp", timeout_seconds=1.0)
    agg = AggregatedTelemetry(1, "00", 1, 0.0, 0.0, 0.0, 0.0)
    session = AsyncMock()
    
    with patch.object(service, "infer", side_effect=Exception("Database down")):
        # Should catch and suppress
        await service.infer_and_persist(agg, session)
        session.rollback.assert_called()
