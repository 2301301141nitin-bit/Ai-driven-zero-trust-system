"""
Dashboard route – read-only endpoints consumed by the Streamlit frontend.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from backend.database import get_db
from backend.schemas import AlertRecord, SessionSummary

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


def _clean(doc: dict) -> dict:
    """Remove non-serialisable MongoDB _id field."""
    doc.pop("_id", None)
    return doc


@router.get("/sessions", response_model=list[SessionSummary])
def get_sessions() -> list[dict[str, Any]]:
    """Return all recorded sessions (most recent first, max 200)."""
    db = get_db()
    collection = db["sessions"]
    try:
        # Prefer letting the database handle sorting and limiting when supported.
        cursor = collection.find().sort("timestamp", -1).limit(200)
        docs = [_clean(d) for d in cursor]
        return docs
    except Exception:
        # Fallback for in-memory or non-Mongo backends that don't support sort/limit.
        docs = collection.find()
        docs = [_clean(d) for d in docs]
        docs.sort(key=lambda d: d.get("timestamp", ""), reverse=True)
        return docs[:200]


@router.get("/alerts", response_model=list[AlertRecord])
def get_alerts() -> list[dict[str, Any]]:
    """Return all security alerts (most recent first, max 100)."""
    db = get_db()
    collection = db["alerts"]
    try:
        # Prefer letting the database handle sorting and limiting when supported.
        cursor = collection.find().sort("timestamp", -1).limit(100)
        docs = [_clean(d) for d in cursor]
        return docs
    except Exception:
        # Fallback for in-memory or non-Mongo backends that don't support sort/limit.
        docs = collection.find()
        docs = [_clean(d) for d in docs]
        docs.sort(key=lambda d: d.get("timestamp", ""), reverse=True)
        return docs[:100]


@router.get("/stats")
def get_stats() -> dict[str, Any]:
    """Return high-level summary statistics."""
    db = get_db()
    # Materialise to a list so we can iterate multiple times without
    # exhausting a cursor (important when backed by real MongoDB).
    sessions = list(db["sessions"].find())

    total = len(sessions)
    if total == 0:
        return {"total_sessions": 0, "blocked": 0, "reauth": 0, "allowed": 0, "alerts": 0}

    blocked = sum(1 for s in sessions if s.get("action") == "BLOCK")
    reauth = sum(1 for s in sessions if s.get("action") == "REQUIRE_REAUTH")
    allowed = sum(1 for s in sessions if s.get("action") == "ALLOW")
    alerts = db["alerts"].count_documents({})

    avg_score = sum(s.get("trust_score", 0) for s in sessions) / total

    return {
        "total_sessions": total,
        "blocked": blocked,
        "reauth": reauth,
        "allowed": allowed,
        "alerts": alerts,
        "avg_trust_score": round(avg_score, 2),
    }
