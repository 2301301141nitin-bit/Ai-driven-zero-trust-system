"""
Decision Engine – converts a trust score into an access decision.

The engine uses a hybrid approach:
  1. Rule-based penalties for explicit attack indicators (hard signals)
  2. AI trust score thresholds for behavioural anomalies (soft signals)

Trust Score Bands (after penalties)
-------------------------------------
Score > 70  →  ALLOW
40 – 70     →  REQUIRE_REAUTH
< 40        →  BLOCK  (+ raise alert)
"""
from __future__ import annotations

from backend.schemas import BehaviorEvent, TrustDecision

# Thresholds (can be tuned via environment variables in a production system)
ALLOW_THRESHOLD = 70.0
REAUTH_THRESHOLD = 40.0

# Rule-based penalties applied to the AI trust score for known attack indicators
_PENALTIES = {
    "geo_anomaly": 30,       # sudden location change
    "device_unknown": 20,    # unrecognised device
    "failed_attempts_high": 25,  # >= 5 failed attempts
    "burst_requests": 35,    # bot-like flooding
}


def _apply_indicator_penalties(score: float, event: BehaviorEvent) -> float:
    """Reduce trust score for explicit attack indicators."""
    if event.geo_anomaly:
        score -= _PENALTIES["geo_anomaly"]
    if not event.device_match:
        score -= _PENALTIES["device_unknown"]
    if event.failed_attempts >= 5:
        score -= _PENALTIES["failed_attempts_high"]
    if event.burst_requests:
        score -= _PENALTIES["burst_requests"]
    return max(0.0, round(score, 2))


def _build_reason(score: float, event: BehaviorEvent) -> str:
    """Produce a human-readable explanation for the decision."""
    reasons: list[str] = []

    if score < REAUTH_THRESHOLD:
        reasons.append("trust score critically low")
    elif score < ALLOW_THRESHOLD:
        reasons.append("trust score below normal threshold")

    if event.geo_anomaly:
        reasons.append("unusual geographic location")
    if event.burst_requests:
        reasons.append("bot-like burst request pattern")
    if event.failed_attempts >= 3:
        reasons.append(f"{event.failed_attempts} failed auth attempts")
    if not event.device_match:
        reasons.append("unrecognised device")

    if not reasons:
        reasons.append("behaviour within normal profile")

    return "; ".join(reasons).capitalize()


def evaluate(event: BehaviorEvent, trust_score: float) -> TrustDecision:
    """Apply zero-trust rules and return an access decision."""
    # Apply rule-based penalties for explicit attack indicators
    adjusted_score = _apply_indicator_penalties(trust_score, event)

    if adjusted_score > ALLOW_THRESHOLD:
        action = "ALLOW"
        alert = False
    elif adjusted_score >= REAUTH_THRESHOLD:
        action = "REQUIRE_REAUTH"
        alert = False
    else:
        action = "BLOCK"
        alert = True

    reason = _build_reason(adjusted_score, event)

    return TrustDecision(
        user_id=event.user_id,
        trust_score=adjusted_score,
        action=action,
        alert=alert,
        reason=reason,
    )
