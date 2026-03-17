"""Tests for the FastAPI endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)

NORMAL_PAYLOAD = {
    "user_id": "test_user",
    "ip_address": "10.0.0.1",
    "login_hour": 9,
    "typing_speed": 5.0,
    "request_frequency": 8.0,
    "session_duration": 20.0,
    "geo_anomaly": 0,
    "device_match": 1,
    "failed_attempts": 0,
    "burst_requests": 0,
}

ATTACK_PAYLOAD = {
    "user_id": "attacker",
    "ip_address": "45.33.32.156",
    "login_hour": 3,
    "typing_speed": 0.0,
    "request_frequency": 150.0,
    "session_duration": 1.0,
    "geo_anomaly": 1,
    "device_match": 0,
    "failed_attempts": 10,
    "burst_requests": 1,
}


class TestHealthEndpoint:
    def test_health_returns_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


class TestBehaviorEndpoint:
    def test_normal_session_returns_decision(self):
        resp = client.post("/api/behavior", json=NORMAL_PAYLOAD)
        assert resp.status_code == 200
        data = resp.json()
        assert "trust_score" in data
        assert "action" in data
        assert "alert" in data
        assert data["action"] in ("ALLOW", "REQUIRE_REAUTH", "BLOCK")

    def test_normal_session_score_in_range(self):
        resp = client.post("/api/behavior", json=NORMAL_PAYLOAD)
        score = resp.json()["trust_score"]
        assert 0.0 <= score <= 100.0

    def test_attack_session_triggers_block_or_reauth(self):
        resp = client.post("/api/behavior", json=ATTACK_PAYLOAD)
        assert resp.status_code == 200
        action = resp.json()["action"]
        assert action in ("BLOCK", "REQUIRE_REAUTH")

    def test_attack_combined_triggers_alert(self):
        resp = client.post("/api/behavior", json=ATTACK_PAYLOAD)
        assert resp.json()["alert"] is True

    def test_invalid_payload_returns_422(self):
        resp = client.post("/api/behavior", json={"user_id": "bad"})
        assert resp.status_code == 422

    def test_login_hour_out_of_range_returns_422(self):
        bad = {**NORMAL_PAYLOAD, "login_hour": 25}
        resp = client.post("/api/behavior", json=bad)
        assert resp.status_code == 422


class TestDashboardEndpoints:
    def test_stats_returns_dict(self):
        resp = client.get("/api/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_sessions" in data

    def test_sessions_returns_list(self):
        # Seed at least one session
        client.post("/api/behavior", json=NORMAL_PAYLOAD)
        resp = client.get("/api/dashboard/sessions")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_alerts_returns_list(self):
        # Seed an alert
        client.post("/api/behavior", json=ATTACK_PAYLOAD)
        resp = client.get("/api/dashboard/alerts")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
