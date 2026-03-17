"""Tests for the AI engine."""
from __future__ import annotations

import pytest

from backend.models.ai_engine import AIEngine
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


@pytest.fixture(scope="module")
def trained_engine() -> AIEngine:
    engine = AIEngine()
    engine.train()
    return engine


class TestAIEngine:
    def test_score_in_range(self, trained_engine):
        event = _make_event()
        score = trained_engine.score(event)
        assert 0.0 <= score <= 100.0

    def test_normal_session_scores_higher_than_attack(self, trained_engine):
        normal = _make_event()
        attack = _make_event(
            ip_address="45.33.32.156",
            geo_anomaly=1,
            burst_requests=1,
            device_match=0,
            failed_attempts=10,
            request_frequency=150.0,
            typing_speed=0.0,
            login_hour=3,
        )
        score_normal = trained_engine.score(normal)
        score_attack = trained_engine.score(attack)
        assert score_normal > score_attack, (
            f"Normal score {score_normal} should exceed attack score {score_attack}"
        )

    def test_untrained_engine_raises(self):
        engine = AIEngine()
        with pytest.raises(RuntimeError, match="train"):
            engine.score(_make_event())

    def test_multiple_scores_are_deterministic(self, trained_engine):
        event = _make_event()
        scores = [trained_engine.score(event) for _ in range(5)]
        assert len(set(scores)) == 1, "Scores should be deterministic for the same input"
