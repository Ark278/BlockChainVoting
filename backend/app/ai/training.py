"""Training and synthetic evaluation harness (Architecture v2.6 Stage 4 §§9–11).

Generates synthetic election telemetry (NOT real voter data), trains the
Isolation Forest model, evaluates it, and saves the artifact.

IMPORTANT:
  - All training data is synthetic. No real voter identities or ballot choices
    are used or referenced at any point in this module.
  - Evaluation metrics are clearly labeled as "synthetic telemetry only."
  - Do NOT interpret these metrics as real-world fraud-detection accuracy.
  - The module is runnable as: python -m app.ai.training

Synthetic scenario definitions:
    NORMAL:     typical submission patterns, low auth failures
    SUSPICIOUS: elevated frequency or auth failures
    HIGH_RISK:  extreme submission frequency + repeated auth failures

Research framing:
    A privacy-bounded anomaly-detection architecture in which AI operates on
    non-ballot, non-identity election telemetry while cryptographic verification
    and smart-contract rules remain independent and authoritative over ballot
    acceptance.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from app.ai.model import (
    FEATURE_NAMES,
    MODEL_VERSION,
    IsolationForestDetector,
    score_to_risk_level,
)

logger = logging.getLogger("voting.ai.training")

# ─────────────────────────────────────────────────────────────────────────────
# Synthetic data parameters (documented for reproducibility)
# ─────────────────────────────────────────────────────────────────────────────

SYNTH_RANDOM_STATE = 0          # Separate seed from model; deterministic data
SYNTH_N_NORMAL = 800            # Number of NORMAL samples
SYNTH_N_SUSPICIOUS = 120        # Number of SUSPICIOUS samples
SYNTH_N_HIGH_RISK = 80          # Number of HIGH_RISK samples


@dataclass
class TrainingReport:
    """Complete training and evaluation report."""

    model_version: str
    feature_names: list[str]
    model_params: dict
    training_samples: int
    test_samples: int
    synthetic_scenario_counts: dict[str, int]
    evaluation_note: str    # Always contains "synthetic" disclaimer
    # Metrics (on synthetic data only)
    precision_suspicious_plus: float    # precision for SUSPICIOUS + HIGH_RISK
    recall_suspicious_plus: float
    f1_suspicious_plus: float
    false_positive_rate: float
    false_negative_rate: float
    roc_auc: float
    threshold_note: str
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    artifact_path: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic data generation
# ─────────────────────────────────────────────────────────────────────────────


def generate_synthetic_telemetry(
    n_normal: int = SYNTH_N_NORMAL,
    n_suspicious: int = SYNTH_N_SUSPICIOUS,
    n_high_risk: int = SYNTH_N_HIGH_RISK,
    rng: np.random.Generator | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """Generate labeled synthetic telemetry feature arrays.

    All data is synthetic.  No real voter identities or ballot choices are used.
    Labels: 0 = NORMAL, 1 = anomalous (SUSPICIOUS or HIGH_RISK).

    Feature distributions (documented):
        NORMAL:
            submission_interval_seconds ~ Uniform(10, 120)
            submission_attempts         ~ Uniform(1, 5) [int]
            auth_failure_count          ~ Uniform(0, 1) [int]
            encrypted_blob_size_bytes   ~ Uniform(1000, 3000)

        SUSPICIOUS:
            submission_interval_seconds ~ Uniform(2, 10)
            submission_attempts         ~ Uniform(5, 20) [int]
            auth_failure_count          ~ Uniform(1, 5) [int]
            encrypted_blob_size_bytes   ~ Uniform(500, 5000)

        HIGH_RISK:
            submission_interval_seconds ~ Uniform(0.1, 2)
            submission_attempts         ~ Uniform(20, 100) [int]
            auth_failure_count          ~ Uniform(5, 20) [int]
            encrypted_blob_size_bytes   ~ Uniform(50, 200) or Uniform(5000, 50000)

    Returns:
        (X, y) where X.shape == (n_total, 4) and y.shape == (n_total,)
    """
    if rng is None:
        rng = np.random.default_rng(SYNTH_RANDOM_STATE)

    def _normal(n: int) -> np.ndarray:
        return np.column_stack([
            rng.uniform(10, 120, n),       # submission_interval_seconds
            rng.integers(1, 6, n),          # submission_attempts
            rng.integers(0, 2, n),          # auth_failure_count
            rng.uniform(1000, 3000, n),     # encrypted_blob_size_bytes
        ])

    def _suspicious(n: int) -> np.ndarray:
        return np.column_stack([
            rng.uniform(2, 10, n),
            rng.integers(5, 21, n),
            rng.integers(1, 6, n),
            rng.uniform(500, 5000, n),
        ])

    def _high_risk(n: int) -> np.ndarray:
        half = n // 2
        rest = n - half
        blob_small = rng.uniform(50, 200, half)
        blob_large = rng.uniform(5000, 50000, rest)
        blobs = np.concatenate([blob_small, blob_large])
        return np.column_stack([
            rng.uniform(0.1, 2, n),
            rng.integers(20, 101, n),
            rng.integers(5, 21, n),
            blobs,
        ])

    X_normal = _normal(n_normal)
    X_suspicious = _suspicious(n_suspicious)
    X_high_risk = _high_risk(n_high_risk)

    X = np.vstack([X_normal, X_suspicious, X_high_risk])
    # Label: 0 = normal, 1 = anomalous (SUSPICIOUS or HIGH_RISK)
    y = np.concatenate([
        np.zeros(n_normal, dtype=int),
        np.ones(n_suspicious + n_high_risk, dtype=int),
    ])
    # Shuffle
    idx = rng.permutation(len(X))
    return X[idx], y[idx]


# ─────────────────────────────────────────────────────────────────────────────
# Training entry point
# ─────────────────────────────────────────────────────────────────────────────


def train_and_evaluate(
    model_dir: str | Path = "./ai_models",
    n_normal: int = SYNTH_N_NORMAL,
    n_suspicious: int = SYNTH_N_SUSPICIOUS,
    n_high_risk: int = SYNTH_N_HIGH_RISK,
    test_size: float = 0.2,
) -> TrainingReport:
    """Train the Isolation Forest on synthetic data and evaluate it.

    Args:
        model_dir:   Directory to save the model artifact and report.
        n_normal:    Number of NORMAL synthetic samples.
        n_suspicious: Number of SUSPICIOUS synthetic samples.
        n_high_risk: Number of HIGH_RISK synthetic samples.
        test_size:   Fraction of data to hold out for evaluation.

    Returns:
        TrainingReport with evaluation metrics (synthetic data only).
    """
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)

    logger.info(
        "Training: synthetic data: normal=%d suspicious=%d high_risk=%d",
        n_normal, n_suspicious, n_high_risk,
    )

    # Generate synthetic data (NO real voter data)
    X, y = generate_synthetic_telemetry(n_normal, n_suspicious, n_high_risk)
    X_train_full, X_test, y_train_full, y_test = train_test_split(
        X, y, test_size=test_size, random_state=SYNTH_RANDOM_STATE
    )

    # Isolation Forest trains on normal data only (unsupervised)
    X_train_normal = X_train_full[y_train_full == 0]
    logger.info("Training: fitting on %d normal samples", len(X_train_normal))

    detector = IsolationForestDetector()
    detector.train(X_train_normal)

    # Save artifact
    artifact_path = detector.save(model_dir)

    # Evaluation on full test set
    # Predict using decision_function and apply frozen thresholds

    model = detector._model  # access internal sklearn model for bulk scoring
    assert model is not None
    test_scores = model.decision_function(X_test)

    # Convert scores to binary labels (0=normal, 1=anomalous)
    y_pred = np.array([
        0 if score_to_risk_level(s) == "NORMAL" else 1
        for s in test_scores
    ])

    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    # ROC-AUC (using decision_function score; higher = more normal)
    try:
        roc_auc = float(roc_auc_score(y_test, -test_scores))
    except Exception:  # noqa: BLE001
        roc_auc = 0.0

    report = TrainingReport(
        model_version=MODEL_VERSION,
        feature_names=FEATURE_NAMES,
        model_params=IsolationForestDetector.model_params(),
        training_samples=len(X_train_normal),
        test_samples=len(X_test),
        synthetic_scenario_counts={
            "NORMAL": n_normal,
            "SUSPICIOUS": n_suspicious,
            "HIGH_RISK": n_high_risk,
            "TOTAL": n_normal + n_suspicious + n_high_risk,
        },
        evaluation_note=(
            "SYNTHETIC TELEMETRY EVALUATION ONLY. "
            "All metrics were computed on synthetic data generated by this module. "
            "These metrics DO NOT represent real-world fraud-detection accuracy. "
            "Do not use these metrics to claim AI proves fraud or guarantees election security."
        ),
        precision_suspicious_plus=precision,
        recall_suspicious_plus=recall,
        f1_suspicious_plus=f1,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        roc_auc=roc_auc,
        threshold_note=(
            "Risk thresholds (project-specific, experimental): "
            "HIGH_RISK ≤ -0.1, SUSPICIOUS ≤ 0.0, NORMAL > 0.0. "
            "These are NOT standardized fraud-detection thresholds."
        ),
        artifact_path=str(artifact_path),
    )

    # Save evaluation report
    report_path = model_dir / "evaluation_report.json"
    report_path.write_text(
        json.dumps(asdict(report), indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Training: evaluation report saved to %s", report_path)
    logger.info(
        "Training results (SYNTHETIC ONLY): "
        "precision=%.3f recall=%.3f F1=%.3f FPR=%.3f FNR=%.3f ROC-AUC=%.3f",
        precision, recall, f1, fpr, fnr, roc_auc,
    )

    return report


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    model_dir = sys.argv[1] if len(sys.argv) > 1 else "./ai_models"
    report = train_and_evaluate(model_dir)
    print("\n=== Synthetic Evaluation Report ===")
    print(f"Note: {report.evaluation_note}")
    print(f"Model: {report.model_version}")
    print(f"Training samples (normal only): {report.training_samples}")
    print(f"Test samples: {report.test_samples}")
    print(f"Precision: {report.precision_suspicious_plus:.3f}")
    print(f"Recall:    {report.recall_suspicious_plus:.3f}")
    print(f"F1:        {report.f1_suspicious_plus:.3f}")
    print(f"FPR:       {report.false_positive_rate:.3f}")
    print(f"FNR:       {report.false_negative_rate:.3f}")
    print(f"ROC-AUC:   {report.roc_auc:.3f}")
    print(f"Artifact:  {report.artifact_path}")
