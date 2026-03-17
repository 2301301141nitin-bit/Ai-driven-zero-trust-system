"""Pydantic schemas for request / response models."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Incoming behavior event                                                      #
# --------------------------------------------------------------------------- #

class BehaviorEvent(BaseModel):
    user_id: str = Field(..., description="Unique user identifier")
    ip_address: str = Field(..., description="Client IP address")
    login_hour: int = Field(..., ge=0, le=23, description="Hour of login (0-23)")
    typing_speed: float = Field(..., ge=0, description="Characters per second")
    request_frequency: float = Field(..., ge=0, description="Requests per minute")
    session_duration: float = Field(..., ge=0, description="Session duration in minutes")
    geo_anomaly: int = Field(0, ge=0, le=1, description="1 if unusual geo location")
    device_match: int = Field(1, ge=0, le=1, description="1 if device matches known profile")
    failed_attempts: int = Field(0, ge=0, description="Failed auth attempts in session")
    burst_requests: int = Field(0, ge=0, le=1, description="1 if burst request pattern detected")


# --------------------------------------------------------------------------- #
# Trust evaluation response                                                    #
# --------------------------------------------------------------------------- #

class TrustDecision(BaseModel):
    user_id: str
    trust_score: float = Field(..., ge=0, le=100)
    action: Literal["ALLOW", "REQUIRE_REAUTH", "BLOCK"]
    alert: bool
    reason: str
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


# --------------------------------------------------------------------------- #
# Session summary (for dashboard)                                              #
# --------------------------------------------------------------------------- #

class SessionSummary(BaseModel):
    user_id: str
    trust_score: float
    action: str
    alert: bool
    reason: str
    timestamp: str
    ip_address: Optional[str] = None
    geo_anomaly: Optional[int] = None
    burst_requests: Optional[int] = None


# --------------------------------------------------------------------------- #
# Alert record                                                                 #
# --------------------------------------------------------------------------- #

class AlertRecord(BaseModel):
    user_id: str
    trust_score: float
    action: str
    reason: str
    timestamp: str
    ip_address: Optional[str] = None
