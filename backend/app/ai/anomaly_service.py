"""AI anomaly detection service (Architecture v2.6 Stage 4 §§6, 12).

Advisory-only wrapper around IsolationForestDetector.

CRITICAL — Advisory boundary:
  This service produces advisory alerts for dashboard display ONLY.
  There is no code path from this service to:
    - ballot acceptance / rejection
    - credential revocation
    - nullifier invalidation
    - blockchain transaction execution
    - tally exclusion
    - result publication

Failure isolation (§12):
  Any exception from the model (including timeouts, missing artifact, corrupt
  inference) is caught internally.  The caller receives None, logs a warning,
  and the ballot acceptance path continues normally.  AI failure NEVER stops
  ballot processing.

Async fire-and-forget (with explicit exception handling):
  The service exposes `run_background_inference()` for use with FastAPI's
  BackgroundTasks.  Exceptions are fully caught and logged; they never
  propagate to the request or the ballot path.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from app.ai.model import MODEL_VERSION, AnomalyPrediction, IsolationForestDetector
from app.ai.telemetry import AggregatedTelemetry
from app.errors import AnomalyServiceError

if TYPE_CHECKING:

    from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger("voting.ai.anomaly_service")


class AnomalyDetectionService:
    """Wraps IsolationForestDetector with timeout, failure isolation, and DB persistence.

    Args:
        model_dir:        Path to directory containing model artifacts.
        timeout_seconds:  Max seconds to allow for inference. Exceeded → None returned.
        enabled:          If False, infer() always returns None without running the model.
    """

    def __init__(
        self,
        model_dir: str,
        timeout_seconds: float = 5.0,
        enabled: bool = True,
    ) -> None:
        self._model_dir = model_dir
        self._timeout = timeout_seconds
        self._enabled = enabled
        self._detector: IsolationForestDetector | None = None

    def _get_detector(self) -> IsolationForestDetector:
        """Lazy-load the model once; reuse across requests."""
        if self._detector is None:
            det = IsolationForestDetector()
            try:
                det.load(self._model_dir)
            except AnomalyServiceError as exc:
                raise AnomalyServiceError(
                    f"Model unavailable ({exc}). AI advisory service is offline."
                ) from exc
            self._detector = det
        return self._detector

    def _run_sync_inference(self, aggregated: AggregatedTelemetry) -> AnomalyPrediction:
        """Synchronous inference (called via asyncio.get_event_loop().run_in_executor)."""
        features = {
            "submission_interval_seconds": aggregated.submission_interval_seconds,
            "submission_attempts": aggregated.submission_attempts,
            "auth_failure_count": aggregated.auth_failure_count,
            "encrypted_blob_size_bytes": aggregated.encrypted_blob_size_bytes,
        }
        return self._get_detector().predict(features)

    async def infer(
        self,
        aggregated: AggregatedTelemetry,
    ) -> AnomalyPrediction | None:
        """Run advisory anomaly inference on aggregated telemetry.

        Returns None on any failure (model missing, timeout, exception).
        Never raises.  Ballot processing is never affected by the return value.

        Args:
            aggregated: Aggregated telemetry (approved features only).

        Returns:
            AnomalyPrediction or None if AI is unavailable/disabled/failed.
        """
        if not self._enabled:
            logger.debug("AnomalyDetectionService: AI disabled; skipping inference")
            return None

        try:
            loop = asyncio.get_event_loop()
            prediction = await asyncio.wait_for(
                loop.run_in_executor(None, self._run_sync_inference, aggregated),
                timeout=self._timeout,
            )
            logger.info(
                "AnomalyDetectionService: election=%d bucket=%s score=%.4f risk=%s",
                aggregated.election_id,
                aggregated.telemetry_bucket_id_hex[:8] + "...",
                prediction.anomaly_score,
                prediction.risk_level,
            )
            return prediction

        except TimeoutError:
            logger.warning(
                "AnomalyDetectionService: inference timeout (%.1fs) for election=%d — "
                "advisory service unavailable; ballot processing unaffected",
                self._timeout,
                aggregated.election_id,
            )
            return None

        except AnomalyServiceError as exc:
            logger.warning(
                "AnomalyDetectionService: inference error for election=%d: %s — "
                "advisory service unavailable; ballot processing unaffected",
                aggregated.election_id,
                exc,
            )
            return None

        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "AnomalyDetectionService: unexpected error for election=%d: %s — "
                "ballot processing unaffected",
                aggregated.election_id,
                exc,
            )
            return None

    async def infer_and_persist(
        self,
        aggregated: AggregatedTelemetry,
        session: AsyncSession,
    ) -> None:
        """Run inference and persist the result to the anomaly_results table.

        This is the safe background task target.
        All exceptions are caught internally — this method never raises.
        Ballot processing is never blocked or affected by this method.

        Args:
            aggregated: Aggregated telemetry record.
            session:    SQLAlchemy async session for persistence.
        """
        try:
            prediction = await self.infer(aggregated)
            if prediction is None:
                # Log AI unavailability as a warning; ballot path unaffected
                await self._persist_unavailable(aggregated, session)
                return

            await self._persist_result(aggregated, prediction, session)
            await session.commit()

        except Exception as exc:  # noqa: BLE001
            # NEVER let a persistence failure propagate: ballot must proceed
            logger.error(
                "AnomalyDetectionService.infer_and_persist: unexpected error: %s "
                "(ballot processing unaffected)",
                exc,
            )
            try:
                await session.rollback()
            except Exception:  # noqa: BLE001
                pass

    async def _persist_result(
        self,
        aggregated: AggregatedTelemetry,
        prediction: AnomalyPrediction,
        session: AsyncSession,
    ) -> None:
        from app.models.ballot import AnomalyResult  # noqa: PLC0415

        record = AnomalyResult(
            election_id=aggregated.election_id,
            telemetry_bucket_id_hex=aggregated.telemetry_bucket_id_hex,
            bucket_start_ts=aggregated.bucket_start_ts,
            anomaly_score=prediction.anomaly_score,
            risk_level=prediction.risk_level,
            model_version=prediction.model_version,
            feature_summary_json=prediction.feature_summary_json,
            explanation=prediction.explanation,
        )
        session.add(record)
        await session.flush()

    async def _persist_unavailable(
        self,
        aggregated: AggregatedTelemetry,
        session: AsyncSession,
    ) -> None:
        """Store a placeholder anomaly record when AI is unavailable."""
        from app.models.ballot import AnomalyResult  # noqa: PLC0415

        record = AnomalyResult(
            election_id=aggregated.election_id,
            telemetry_bucket_id_hex=aggregated.telemetry_bucket_id_hex,
            bucket_start_ts=aggregated.bucket_start_ts,
            anomaly_score=0.0,
            risk_level="UNAVAILABLE",
            model_version=MODEL_VERSION,
            feature_summary_json=None,
            explanation="AI advisory service was unavailable. No anomaly assessment performed.",
        )
        session.add(record)
        try:
            await session.flush()
            await session.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning("AnomalyDetectionService: could not persist UNAVAILABLE record: %s", exc)
            try:
                await session.rollback()
            except Exception:  # noqa: BLE001
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Safe background task callable (for FastAPI BackgroundTasks)
# ─────────────────────────────────────────────────────────────────────────────


async def background_infer_and_persist(
    service: AnomalyDetectionService,
    aggregated: AggregatedTelemetry,
    session: AsyncSession,
) -> None:
    """Safe background task: run inference and persist.

    Designed for use with FastAPI BackgroundTasks.  All exceptions are caught.
    The ballot acceptance path is never blocked or influenced by this function.

    Usage in API handler:
        background_tasks.add_task(
            background_infer_and_persist, service, aggregated, db_session
        )
    """
    await service.infer_and_persist(aggregated, session)
