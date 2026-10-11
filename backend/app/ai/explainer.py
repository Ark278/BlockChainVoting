"""Anomaly explanation generator (Architecture v2.6 Stage 4 §7).

Generates human-readable, privacy-safe explanations for anomaly results.

Rules:
  - Explanations reference ONLY approved telemetry feature names and values.
  - Explanations use "behavioral anomaly detected" language.
  - Explanations NEVER claim a specific voter committed fraud.
  - Explanations NEVER reveal hidden voter identity or ballot information.
  - Explanations are advisory descriptions for dashboard operators only.
  - All feature value thresholds used in explanations are numeric; they are
    relative to training distribution, not fraud evidence.

Disclaimer embedded in every non-NORMAL explanation:
    "This is an advisory signal only and does not constitute evidence of fraud."
"""

from __future__ import annotations

from dataclasses import dataclass

# ─────────────────────────────────────────────────────────────────────────────
# Feature description registry
# ─────────────────────────────────────────────────────────────────────────────

# Maps feature name → human-readable description used in explanations.
_FEATURE_DESCRIPTIONS: dict[str, str] = {
    "submission_interval_seconds": "submission interval (seconds)",
    "submission_attempts": "total submission attempts",
    "auth_failure_count": "authentication failures",
    "encrypted_blob_size_bytes": "encrypted ballot blob size (bytes)",
}

# ─────────────────────────────────────────────────────────────────────────────
# Threshold descriptions (relative to training distribution)
# ─────────────────────────────────────────────────────────────────────────────

# These descriptions correspond to the Isolation Forest decision_function output.
# score <= -0.1 → HIGH_RISK; score <= 0.0 → SUSPICIOUS; score > 0.0 → NORMAL.
# These thresholds are project-specific and experimental; they are NOT
# standardized fraud-detection thresholds.

_NORMAL_EXPLANATION = (
    "No significant behavioral anomaly detected in this telemetry bucket. "
    "All observed features are within the range seen during model training. "
    "This is an advisory signal only."
)

_ADVISORY_DISCLAIMER = (
    "This is an advisory signal only and does not constitute evidence of fraud. "
    "Anomaly scores are based on statistical patterns in non-identity telemetry "
    "and have no standardized fraud-detection meaning."
)


@dataclass
class ExplainedAnomaly:
    """Human-readable anomaly explanation with privacy-safe wording."""

    risk_level: str
    explanation: str
    feature_contributions: dict[str, str]   # feature name → narrative fragment


def generate_explanation(
    features: dict[str, float],
    risk_level: str,
    anomaly_score: float,
) -> ExplainedAnomaly:
    """Generate a privacy-safe human-readable explanation.

    Args:
        features:      Dict of feature_name → value (approved features only).
        risk_level:    "NORMAL" | "SUSPICIOUS" | "HIGH_RISK"
        anomaly_score: Raw Isolation Forest decision_function score.

    Returns:
        ExplainedAnomaly with explanation text and per-feature contributions.
    """
    contributions: dict[str, str] = {}

    if risk_level == "NORMAL":
        return ExplainedAnomaly(
            risk_level=risk_level,
            explanation=_NORMAL_EXPLANATION,
            feature_contributions={},
        )

    # Build per-feature contribution fragments
    interval = features.get("submission_interval_seconds", 0.0)
    attempts = features.get("submission_attempts", 0.0)
    auth_failures = features.get("auth_failure_count", 0.0)
    blob_size = features.get("encrypted_blob_size_bytes", 0.0)

    if interval < 5.0 and interval > 0.0:
        contributions["submission_interval_seconds"] = (
            f"unusually high submission frequency "
            f"(mean interval {interval:.1f}s, below expected range)"
        )
    elif interval == 0.0:
        contributions["submission_interval_seconds"] = (
            "submission interval unavailable or zero"
        )

    if attempts > 10:
        contributions["submission_attempts"] = (
            f"elevated submission attempt count ({int(attempts)} attempts)"
        )

    if auth_failures > 2:
        contributions["auth_failure_count"] = (
            f"repeated authentication failures ({int(auth_failures)} failures in this bucket)"
        )

    if blob_size > 0 and (blob_size < 100 or blob_size > 100_000):
        contributions["encrypted_blob_size_bytes"] = (
            f"abnormal encrypted blob size ({int(blob_size)} bytes, outside typical range)"
        )

    # Build summary narrative
    if contributions:
        feature_parts = "; ".join(contributions.values())
        summary = (
            f"Behavioral anomaly detected in telemetry bucket. "
            f"Observed signals: {feature_parts}. "
        )
    else:
        summary = (
            "Behavioral anomaly detected in telemetry bucket "
            "(statistical outlier based on feature combination). "
        )

    risk_prefix = {
        "SUSPICIOUS": "The observed pattern is statistically unusual compared to baseline.",
        "HIGH_RISK": (
            "The observed pattern is a strong statistical outlier compared to baseline. "
            "Elevated review is recommended."
        ),
    }.get(risk_level, "")

    explanation = (
        f"{summary}{risk_prefix} "
        f"(Isolation Forest anomaly score: {anomaly_score:.4f}; "
        f"project threshold: HIGH_RISK ≤ -0.1, SUSPICIOUS ≤ 0.0.) "
        f"{_ADVISORY_DISCLAIMER}"
    )

    return ExplainedAnomaly(
        risk_level=risk_level,
        explanation=explanation,
        feature_contributions=contributions,
    )
