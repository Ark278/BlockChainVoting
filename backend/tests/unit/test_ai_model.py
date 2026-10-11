"""Tests: AI model (Stage 4 §5, §11, §14).

Tests:
  - normal telemetry classification
  - anomalous telemetry classification
  - deterministic model output
  - explanation generated
  - model version recorded
"""

from __future__ import annotations

import tempfile

from app.ai.model import MODEL_VERSION, IsolationForestDetector
from app.ai.training import generate_synthetic_telemetry


def test_model_training_and_prediction() -> None:
    detector = IsolationForestDetector()
    X, _ = generate_synthetic_telemetry(n_normal=100, n_suspicious=0, n_high_risk=0)
    detector.train(X)
    assert detector.is_trained

    # Predict normal
    normal_features = {
        "submission_interval_seconds": 60.0,
        "submission_attempts": 2.0,
        "auth_failure_count": 0.0,
        "encrypted_blob_size_bytes": 2000.0,
    }
    pred_normal = detector.predict(normal_features)
    assert pred_normal.risk_level == "NORMAL"
    assert pred_normal.model_version == MODEL_VERSION
    assert "advisory" in pred_normal.explanation.lower()

    # Predict anomalous (HIGH_RISK)
    high_risk_features = {
        "submission_interval_seconds": 0.5,
        "submission_attempts": 50.0,
        "auth_failure_count": 10.0,
        "encrypted_blob_size_bytes": 100.0,
    }
    pred_high = detector.predict(high_risk_features)
    assert pred_high.risk_level in ("HIGH_RISK", "SUSPICIOUS")
    assert "advisory" in pred_high.explanation.lower()

def test_deterministic_model_output() -> None:
    detector1 = IsolationForestDetector()
    detector2 = IsolationForestDetector()
    X, _ = generate_synthetic_telemetry(n_normal=100, n_suspicious=0, n_high_risk=0)
    
    detector1.train(X)
    detector2.train(X)

    features = {
        "submission_interval_seconds": 0.5,
        "submission_attempts": 50.0,
        "auth_failure_count": 10.0,
        "encrypted_blob_size_bytes": 100.0,
    }
    pred1 = detector1.predict(features)
    pred2 = detector2.predict(features)

    assert pred1.anomaly_score == pred2.anomaly_score
    assert pred1.risk_level == pred2.risk_level

def test_model_save_and_load() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        detector1 = IsolationForestDetector()
        X, _ = generate_synthetic_telemetry(n_normal=100, n_suspicious=0, n_high_risk=0)
        detector1.train(X)
        detector1.save(tmpdir)

        detector2 = IsolationForestDetector()
        detector2.load(tmpdir)

        assert detector2.is_trained
        
        features = {
            "submission_interval_seconds": 60.0,
            "submission_attempts": 2.0,
            "auth_failure_count": 0.0,
            "encrypted_blob_size_bytes": 2000.0,
        }
        pred1 = detector1.predict(features)
        pred2 = detector2.predict(features)

        assert pred1.anomaly_score == pred2.anomaly_score
