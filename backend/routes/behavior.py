"""
Behaviour monitoring route.

POST /api/behavior
  – Accept a BehaviorEvent, run it through the AI engine and decision engine,
    persist the result, and return the TrustDecision.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from backend.database import get_db
from backend.models.ai_engine import get_engine
from backend.models.decision_engine import evaluate
from backend.schemas import BehaviorEvent, TrustDecision

router = APIRouter(prefix="/api", tags=["behavior"])


@router.post("/behavior", response_model=TrustDecision)
def evaluate_behavior(event: BehaviorEvent) -> TrustDecision:
    """Evaluate a behaviour event and return an access decision."""
    try:
        engine = get_engine()
        trust_score = engine.score(event)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"AI engine error: {exc}") from exc

    decision = evaluate(event, trust_score)

    # Persist event + decision
    db = get_db()
    record = {
        "user_id": event.user_id,
        "ip_address": event.ip_address,
        "trust_score": decision.trust_score,
        "action": decision.action,
        "alert": decision.alert,
        "reason": decision.reason,
        "geo_anomaly": event.geo_anomaly,
        "burst_requests": event.burst_requests,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    db["sessions"].insert_one(record)
    if decision.alert:
        db["alerts"].insert_one(record)

    return decision
