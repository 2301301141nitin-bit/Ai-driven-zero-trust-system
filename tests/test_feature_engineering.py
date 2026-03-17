"""Tests for the feature engineering module."""
from __future__ import annotations

import numpy as np
import pytest

from backend.models.feature_engineering import (
    FEATURE_NAMES,
    _ip_risk_score,
    extract_features,
)
from backend.schemas import BehaviorEvent


def _make_event(**kwargs) -> BehaviorEvent:
    defaults = dict(
        user_id="test_user",
        ip_address="10.0.0.1",
        login_hour=9,
        typing_speed=5.0,
        request_frequency=8.0,
        session_duration=20.0,
        geo_anomaly=0,
        device_match=1,
        failed_attempts=0,
        burst_requests=0,
    )
    defaults.update(kwargs)
    return BehaviorEvent(**defaults)


class TestIPRiskScore:
    def test_private_ip_is_zero(self):
        for ip in ["10.0.0.1", "192.168.1.5", "172.16.0.1", "127.0.0.1"]:
            assert _ip_risk_score(ip) == 0.0

    def test_public_ip_has_risk(self):
        score = _ip_risk_score("203.0.113.42")
        assert score > 0.0


class TestExtractFeatures:
    def test_output_length_matches_feature_names(self):
        event = _make_event()
        vec = extract_features(event)
        assert len(vec) == len(FEATURE_NAMES)

    def test_output_is_float32(self):
        event = _make_event()
        vec = extract_features(event)
        assert vec.dtype == np.float32

    def test_login_hour_cyclical_encoding(self):
        """Adjacent hours across midnight (23 and 0) should be encoded more similarly than opposite hours (0 and 12)."""
        event_0 = _make_event(login_hour=0)
        event_23 = _make_event(login_hour=23)
        event_12 = _make_event(login_hour=12)
        vec_0 = extract_features(event_0)
        vec_23 = extract_features(event_23)
        vec_12 = extract_features(event_12)

        # Verify cyclical proximity: 23↔0 should be closer in the encoding space than 12↔0.
        dist_0_23 = np.linalg.norm(vec_0[:2] - vec_23[:2])
        dist_0_12 = np.linalg.norm(vec_0[:2] - vec_12[:2])
        assert dist_0_23 < dist_0_12

    def test_device_match_inverted(self):
        """device_match=1 → device_match_inv=0 in the feature vector."""
        event = _make_event(device_match=1)
        vec = extract_features(event)
        idx = FEATURE_NAMES.index("device_match_inv")
        assert vec[idx] == 0.0

    def test_known_device_and_anomaly_flags(self):
        event = _make_event(geo_anomaly=1, burst_requests=1, device_match=0)
        vec = extract_features(event)
        geo_idx = FEATURE_NAMES.index("geo_anomaly")
        burst_idx = FEATURE_NAMES.index("burst_requests")
        dev_idx = FEATURE_NAMES.index("device_match_inv")
        assert vec[geo_idx] == 1.0
        assert vec[burst_idx] == 1.0
        assert vec[dev_idx] == 1.0
