"""
AI Engine – Isolation Forest based anomaly detector.

The model is trained once on synthetic "normal" traffic at startup.
It produces a raw anomaly score that the Decision Engine converts to a
trust score in the range 0–100.
"""
from __future__ import annotations

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import MinMaxScaler

from backend.models.feature_engineering import FEATURE_NAMES, extract_features
from backend.schemas import BehaviorEvent

# --------------------------------------------------------------------------- #
# Training data generator (synthetic normal behaviour)                        #
# --------------------------------------------------------------------------- #

_RNG = np.random.default_rng(42)


def _generate_normal_samples(n: int = 2000) -> np.ndarray:
    """
    Produce synthetic normal-user feature vectors so we can train the
    Isolation Forest without requiring a labelled dataset.

    Each column corresponds to the features defined in FEATURE_NAMES.
    """
    hour = _RNG.integers(7, 21, size=n)   # business hours logins
    hour_rad = 2 * np.pi * hour / 24

    samples = np.column_stack([
        np.sin(hour_rad),                            # login_hour_sin
        np.cos(hour_rad),                            # login_hour_cos
        _RNG.uniform(3, 8, n),                       # typing_speed  (WPM-ish)
        _RNG.uniform(1, 15, n),                      # request_frequency
        _RNG.uniform(5, 60, n),                      # session_duration
        _RNG.binomial(1, 0.02, n),                   # geo_anomaly (mostly 0, rare 1s)
        np.zeros(n),                                 # device_match_inv (known dev)
        _RNG.integers(0, 2, n),                      # failed_attempts
        np.zeros(n),                                 # burst_requests
        np.zeros(n),                                 # ip_risk_score (trusted)
    ])
    return samples.astype(np.float32)


# --------------------------------------------------------------------------- #
# AI Engine class                                                              #
# --------------------------------------------------------------------------- #

class AIEngine:
    """Wraps an Isolation Forest model and exposes a single `score` method."""

    def __init__(self) -> None:
        self._model = IsolationForest(
            n_estimators=200,
            contamination=0.05,  # expected anomaly fraction
            random_state=42,
        )
        self._scaler = MinMaxScaler()
        self._trained = False

    def train(self) -> None:
        """Train on synthetic normal data.  Called once at application startup."""
        X = _generate_normal_samples(2000)
        X_scaled = self._scaler.fit_transform(X)
        self._model.fit(X_scaled)

        # Calibrate score scaling from the actual training distribution.
        # We use the 5th percentile of training scores as the "minimum normal"
        # anchor and the 95th percentile as the "maximum normal" anchor.
        # Scores are then linearly mapped so that the 95th-pct inlier maps to
        # ~90 and deep anomalies map toward 0.
        train_scores = self._model.decision_function(X_scaled)
        self._score_p5 = float(np.percentile(train_scores, 5))
        self._score_p95 = float(np.percentile(train_scores, 95))
        self._trained = True

    def score(self, event: BehaviorEvent) -> float:
        """
        Return a trust score between 0.0 and 100.0.

        Scores are calibrated against the training distribution:
        - Data resembling normal training behaviour scores near 80-95.
        - Clear anomalies score near 0-35.
        - Borderline cases fall in 35-70.
        """
        if not self._trained:
            raise RuntimeError("AIEngine.train() must be called before scoring.")

        feature_vec = extract_features(event).reshape(1, -1)
        feature_scaled = self._scaler.transform(feature_vec)
        raw = float(self._model.decision_function(feature_scaled)[0])

        # Scale linearly using training percentiles.
        # p5  → maps to ~10  (clear anomalies score below this)
        # p95 → maps to ~90  (clear normal sessions score above this)
        lo, hi = self._score_p5, self._score_p95
        span = hi - lo if hi != lo else 1.0
        normalized = (raw - lo) / span           # 0 at p5, 1 at p95
        trust_score = 10.0 + normalized * 80.0   # scale to [10, 90] band
        trust_score = float(np.clip(trust_score, 0.0, 100.0))
        return round(trust_score, 2)


# Module-level singleton
_engine: AIEngine | None = None


def get_engine() -> AIEngine:
    global _engine
    if _engine is None:
        _engine = AIEngine()
        _engine.train()
    return _engine
