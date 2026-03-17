"""Feature engineering: convert raw BehaviorEvent into a numeric feature vector."""
from __future__ import annotations

import numpy as np

from backend.schemas import BehaviorEvent

# Feature order must stay consistent with model training
FEATURE_NAMES = [
    "login_hour_sin",      # cyclical encoding of hour
    "login_hour_cos",
    "typing_speed",
    "request_frequency",
    "session_duration",
    "geo_anomaly",
    "device_match_inv",    # inverted: 0 = trusted device
    "failed_attempts",
    "burst_requests",
    "ip_risk_score",       # derived from IP heuristic
]


def _ip_risk_score(ip: str) -> float:
    """
    Simple heuristic: private / loopback IPs score 0.0 (trusted);
    everything else scores 0.3 as a baseline unknown risk.
    A production system would query a threat-intelligence feed here.
    """
    private_prefixes = ("10.", "192.168.", "172.16.", "127.", "::1", "localhost")
    if any(ip.startswith(p) for p in private_prefixes):
        return 0.0
    return 0.3


def extract_features(event: BehaviorEvent) -> np.ndarray:
    """Return a 1-D float32 NumPy array of engineered features."""
    hour_rad = 2 * np.pi * event.login_hour / 24
    features = [
        np.sin(hour_rad),                        # login_hour_sin
        np.cos(hour_rad),                        # login_hour_cos
        float(event.typing_speed),
        float(event.request_frequency),
        float(event.session_duration),
        float(event.geo_anomaly),
        float(1 - event.device_match),           # device_match_inv
        float(event.failed_attempts),
        float(event.burst_requests),
        _ip_risk_score(event.ip_address),
    ]
    return np.array(features, dtype=np.float32)
