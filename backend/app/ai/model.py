"""Isolation Forest anomaly detection model (Architecture v2.6 Stage 4 §§5, 11).

Model specification (frozen for reproducibility):
    algorithm:     Isolation Forest (sklearn.ensemble.IsolationForest)
    n_estimators:  100
    contamination: 0.05   (5% assumed anomaly rate — project assumption, not fraud rate)
    random_state:  42     (for reproducibility)
    max_features:  1.0

Features (in exact order — changing order breaks reproducibility):
    [submission_interval_seconds, submission_attempts,
     auth_failure_count, encrypted_blob_size_bytes]

Risk thresholds (project-specific, experimental — NOT standardized fraud thresholds):
    score > 0.0   → NORMAL      (within training distribution)
    score ≤ 0.0   → SUSPICIOUS  (moderate statistical outlier)
    score ≤ -0.1  → HIGH_RISK   (strong statistical outlier)

IMPORTANT:
  - The anomaly_score is the raw sklearn decision_function output.
  - This score is NOT a probability of fraud.
  - These thresholds are project-specific and experimental.
  - The same score + same input → same output (given identical model artifact).
  - A HIGH_RISK score is advisory only and MUST NOT cause ballot rejection,
    credential revocation, or any modification to the tally or blockchain state.

Model versioning:
    Artifacts are stored as: {model_dir}/isolation_forest_v{MAJOR}_{MINOR}.pkl
    MODEL_VERSION constant identifies the current artifact version.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import joblib
import numpy as np

from app.ai.explainer import generate_explanation
from app.errors import AnomalyServiceError

if TYPE_CHECKING:
    from sklearn.ensemble import IsolationForest

logger = logging.getLogger("voting.ai.model")

# ─────────────────────────────────────────────────────────────────────────────
# Frozen model parameters
# ─────────────────────────────────────────────────────────────────────────────

MODEL_VERSION = "isolation_forest_v1_0"

_N_ESTIMATORS = 100
_CONTAMINATION = 0.05
_RANDOM_STATE = 42
_MAX_FEATURES = 1.0

# Exact feature order — DO NOT reorder; changing order breaks reproducibility.
FEATURE_NAMES: list[str] = [
    "submission_interval_seconds",
    "submission_attempts",
    "auth_failure_count",
    "encrypted_blob_size_bytes",
]

# ─────────────────────────────────────────────────────────────────────────────
# Risk threshold constants (project-specific, experimental)
# ─────────────────────────────────────────────────────────────────────────────

# Isolation Forest decision_function: more positive = more normal.
# These thresholds were chosen to partition the score range for advisory
# risk labeling within this project.  They are NOT standardized fraud thresholds.
THRESHOLD_HIGH_RISK: float = -0.1   # score ≤ this → HIGH_RISK
THRESHOLD_SUSPICIOUS: float = 0.0   # score ≤ this → SUSPICIOUS; else NORMAL

RISK_LEVELS = ("NORMAL", "SUSPICIOUS", "HIGH_RISK")


# ─────────────────────────────────────────────────────────────────────────────
# Data types
# ─────────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AnomalyPrediction:
    """Result of one Isolation Forest inference run."""

    anomaly_score: float        # Raw decision_function score (not a fraud probability)
    risk_level: str             # "NORMAL" | "SUSPICIOUS" | "HIGH_RISK" (advisory)
    model_version: str
    feature_summary: dict[str, float]   # Approved features used (no identity data)
    feature_summary_json: bytes         # JSON-encoded feature_summary
    explanation: str            # Human-readable advisory text


# ─────────────────────────────────────────────────────────────────────────────
# Risk classification
# ─────────────────────────────────────────────────────────────────────────────


def score_to_risk_level(score: float) -> str:
    """Map a decision_function score to a risk level using frozen thresholds.

    Project-specific thresholds (experimental):
        score ≤ -0.1 → HIGH_RISK
        score ≤  0.0 → SUSPICIOUS
        score >  0.0 → NORMAL

    These thresholds are NOT standardized fraud-detection thresholds.
    """
    if score <= THRESHOLD_HIGH_RISK:
        return "HIGH_RISK"
    if score <= THRESHOLD_SUSPICIOUS:
        return "SUSPICIOUS"
    return "NORMAL"


# ─────────────────────────────────────────────────────────────────────────────
# Model class
# ─────────────────────────────────────────────────────────────────────────────


class IsolationForestDetector:
    """Isolation Forest anomaly detector for election telemetry.

    The model operates ONLY on approved numeric telemetry features.
    It does NOT accept, process, or learn from voter identity, ballot choices,
    nullifiers, credentials, or any other prohibited data.

    Usage:
        detector = IsolationForestDetector()
        detector.train(X_train)  # X_train: array of approved features
        prediction = detector.predict(features_dict)
    """

    def __init__(self) -> None:
        self._model: IsolationForest | None = None

    def _build_model(self) -> IsolationForest:
        from sklearn.ensemble import IsolationForest  # noqa: PLC0415

        return IsolationForest(
            n_estimators=_N_ESTIMATORS,
            contamination=_CONTAMINATION,
            random_state=_RANDOM_STATE,
            max_features=_MAX_FEATURES,
        )

    def train(self, X: np.ndarray) -> None:
        """Fit the Isolation Forest on approved-feature training data.

        Args:
            X: 2D numpy array of shape (n_samples, n_features).
               Columns must match FEATURE_NAMES exactly, in order.
               Must NOT contain voter identity, ballot, or prohibited data.

        Raises:
            AnomalyServiceError: On training failure.
        """
        try:
            model = self._build_model()
            model.fit(X)
            self._model = model
            logger.info(
                "IsolationForestDetector: trained on %d samples, "
                "features=%r, contamination=%.2f, random_state=%d",
                X.shape[0], FEATURE_NAMES, _CONTAMINATION, _RANDOM_STATE,
            )
        except Exception as exc:
            raise AnomalyServiceError(f"Model training failed: {exc}") from exc

    def predict(self, features: dict[str, float]) -> AnomalyPrediction:
        """Run inference on a single aggregated telemetry record.

        Args:
            features: Dict mapping FEATURE_NAMES → numeric values.
                      All values must be approved telemetry features.
                      No identity, ballot, or prohibited data permitted.

        Returns:
            AnomalyPrediction with score, risk_level, explanation.

        Raises:
            AnomalyServiceError: If model is not trained or inference fails.
        """
        if self._model is None:
            raise AnomalyServiceError(
                "IsolationForestDetector: model is not trained. "
                "Call train() or load() before predict()."
            )

        try:
            # Build feature vector in exact canonical order
            x = np.array(
                [[features.get(name, 0.0) for name in FEATURE_NAMES]],
                dtype=np.float64,
            )
            score = float(self._model.decision_function(x)[0])
        except Exception as exc:
            raise AnomalyServiceError(f"Inference failed: {exc}") from exc

        risk_level = score_to_risk_level(score)

        feature_summary = {name: features.get(name, 0.0) for name in FEATURE_NAMES}
        feature_summary_json = json.dumps(feature_summary, sort_keys=True).encode()

        explained = generate_explanation(feature_summary, risk_level, score)

        return AnomalyPrediction(
            anomaly_score=score,
            risk_level=risk_level,
            model_version=MODEL_VERSION,
            feature_summary=feature_summary,
            feature_summary_json=feature_summary_json,
            explanation=explained.explanation,
        )

    def save(self, model_dir: str | Path) -> Path:
        """Serialize the trained model to {model_dir}/{MODEL_VERSION}.pkl.

        Args:
            model_dir: Directory to store the model artifact.

        Returns:
            Path of the saved artifact.

        Raises:
            AnomalyServiceError: If model is not trained or save fails.
        """
        if self._model is None:
            raise AnomalyServiceError("Cannot save: model has not been trained.")
        path = Path(model_dir) / f"{MODEL_VERSION}.pkl"
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            joblib.dump(self._model, path)
            logger.info("IsolationForestDetector: saved to %s", path)
            return path
        except Exception as exc:
            raise AnomalyServiceError(f"Model save failed: {exc}") from exc

    def load(self, model_dir: str | Path) -> None:
        """Load a serialized model from {model_dir}/{MODEL_VERSION}.pkl.

        Args:
            model_dir: Directory containing the model artifact.

        Raises:
            AnomalyServiceError: If the file is missing or corrupted.
        """
        path = Path(model_dir) / f"{MODEL_VERSION}.pkl"
        if not path.exists():
            raise AnomalyServiceError(
                f"Model artifact not found: {path}. "
                "Run training first: python -m app.ai.training"
            )
        try:
            self._model = joblib.load(path)
            logger.info("IsolationForestDetector: loaded from %s", path)
        except Exception as exc:
            raise AnomalyServiceError(f"Model load failed: {exc}") from exc

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    @classmethod
    def model_params(cls) -> dict:
        """Return the frozen model parameters for documentation and audit."""
        return {
            "model_version": MODEL_VERSION,
            "algorithm": "IsolationForest",
            "n_estimators": _N_ESTIMATORS,
            "contamination": _CONTAMINATION,
            "random_state": _RANDOM_STATE,
            "max_features": _MAX_FEATURES,
            "feature_names": FEATURE_NAMES,
            "risk_thresholds": {
                "HIGH_RISK": f"score <= {THRESHOLD_HIGH_RISK}",
                "SUSPICIOUS": f"score <= {THRESHOLD_SUSPICIOUS}",
                "NORMAL": f"score > {THRESHOLD_SUSPICIOUS}",
            },
            "threshold_note": (
                "These thresholds are project-specific and experimental. "
                "The anomaly score is NOT a probability of fraud and the "
                "thresholds are NOT standardized fraud-detection thresholds."
            ),
        }
