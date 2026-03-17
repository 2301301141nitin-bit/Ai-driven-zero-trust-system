"""Tests for the decision engine."""
from __future__ import annotations

import pytest

from backend.models.decision_engine import (
    ALLOW_THRESHOLD,
    REAUTH_THRESHOLD,
    _apply_indicator_penalties,
    evaluate,
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


class TestIndicatorPenalties:
    def test_no_penalties_unchanged(self):
        event = _make_event()
        assert _apply_indicator_penalties(80.0, event) == 80.0

    def test_geo_anomaly_penalty(self):
        event = _make_event(geo_anomaly=1)
        score = _apply_indicator_penalties(80.0, event)
        assert score < 80.0

    def test_device_unknown_penalty(self):
        event = _make_event(device_match=0)
        score = _apply_indicator_penalties(80.0, event)
        assert score < 80.0

    def test_burst_requests_penalty(self):
        event = _make_event(burst_requests=1)
        score = _apply_indicator_penalties(80.0, event)
        assert score < 80.0

    def test_combined_penalties_floor_at_zero(self):
        event = _make_event(geo_anomaly=1, device_match=0, burst_requests=1, failed_attempts=10)
        score = _apply_indicator_penalties(80.0, event)
        assert score == 0.0

    def test_failed_attempts_penalty_triggers_at_5(self):
        event_4 = _make_event(failed_attempts=4)
        event_5 = _make_event(failed_attempts=5)
        score_4 = _apply_indicator_penalties(80.0, event_4)
        score_5 = _apply_indicator_penalties(80.0, event_5)
        assert score_4 > score_5


class TestDecisionEngine:
    def test_high_score_allows(self):
        event = _make_event()
        decision = evaluate(event, 85.0)
        assert decision.action == "ALLOW"
        assert not decision.alert

    def test_medium_score_requires_reauth(self):
        event = _make_event()
        decision = evaluate(event, 55.0)
        assert decision.action == "REQUIRE_REAUTH"
        assert not decision.alert

    def test_low_score_blocks_with_alert(self):
        event = _make_event()
        decision = evaluate(event, 20.0)
        assert decision.action == "BLOCK"
        assert decision.alert

    def test_boundary_just_above_allow(self):
        decision = evaluate(_make_event(), ALLOW_THRESHOLD + 0.1)
        assert decision.action == "ALLOW"

    def test_boundary_at_reauth(self):
        decision = evaluate(_make_event(), REAUTH_THRESHOLD)
        assert decision.action == "REQUIRE_REAUTH"

    def test_geo_anomaly_reduces_score(self):
        """geo_anomaly=1 should reduce the effective score and lower the action."""
        event_normal = _make_event(geo_anomaly=0)
        event_geo = _make_event(geo_anomaly=1)
        decision_normal = evaluate(event_normal, 85.0)
        decision_geo = evaluate(event_geo, 85.0)
        assert decision_geo.trust_score < decision_normal.trust_score

    def test_burst_requests_causes_block(self):
        """burst_requests alone on a borderline score should force a lower action."""
        event = _make_event(burst_requests=1)
        decision = evaluate(event, 80.0)
        # After burst penalty (-35), score = 45 → REQUIRE_REAUTH or BLOCK
        assert decision.action in ("REQUIRE_REAUTH", "BLOCK")

    def test_combined_attack_indicators_block(self):
        """Multiple attack indicators together must result in BLOCK + alert."""
        event = _make_event(geo_anomaly=1, burst_requests=1, device_match=0, failed_attempts=10)
        decision = evaluate(event, 90.0)
        assert decision.action == "BLOCK"
        assert decision.alert

    def test_reason_contains_anomaly_description(self):
        event = _make_event(geo_anomaly=1)
        decision = evaluate(event, 30.0)
        assert "geographic" in decision.reason.lower()

    def test_reason_contains_burst_description(self):
        event = _make_event(burst_requests=1)
        decision = evaluate(event, 30.0)
        assert "burst" in decision.reason.lower()

    def test_trust_score_returned_is_adjusted(self):
        """The returned trust_score must reflect indicator penalties."""
        event = _make_event(geo_anomaly=1)   # penalty of -30
        decision = evaluate(event, 90.0)
        assert decision.trust_score == 60.0  # 90 - 30

    def test_user_id_preserved(self):
        event = _make_event(user_id="alice")
        decision = evaluate(event, 80.0)
        assert decision.user_id == "alice"
