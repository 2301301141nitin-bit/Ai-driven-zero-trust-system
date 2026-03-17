"""
FastAPI application entry-point for the AI-Driven Zero Trust Security System.

Startup:
    uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.models.ai_engine import get_engine
from backend.routes.behavior import router as behavior_router
from backend.routes.dashboard import router as dashboard_router

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("BACKEND_ALLOWED_ORIGINS", "http://localhost:3000").split(",")
    if origin.strip()
]

# --------------------------------------------------------------------------- #
# Lifecycle                                                                    #
# --------------------------------------------------------------------------- #

@asynccontextmanager
async def _lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Pre-train the AI engine so the first request is not slow."""
    get_engine()
    yield


# --------------------------------------------------------------------------- #
# Application                                                                  #
# --------------------------------------------------------------------------- #

app = FastAPI(
    title="AI-Driven Zero Trust Security System",
    description=(
        "Continuous AI-based authentication using behavioural anomaly detection. "
        "Every request is scored in real-time; access is granted, flagged for "
        "re-authentication, or blocked based on a dynamic trust score."
    ),
    version="1.0.0",
    lifespan=_lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(behavior_router)
app.include_router(dashboard_router)


# --------------------------------------------------------------------------- #
# Health check                                                                 #
# --------------------------------------------------------------------------- #

@app.get("/health", tags=["health"])
def health() -> dict:
    return {"status": "ok", "service": "zero-trust-backend"}
