"""
Data simulator – generates synthetic normal user sessions and sends them
to the backend API.

Usage:
    python data/simulate_data.py --sessions 50 --api-url http://localhost:8000
"""
from __future__ import annotations

import argparse
import json
import random
import time

import httpx

# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

_RNG = random.Random(0)

USERS = [f"user_{i:03d}" for i in range(1, 11)]
PRIVATE_IPS = ["10.0.0.1", "192.168.1.1", "172.16.0.5", "127.0.0.1"]
PUBLIC_IPS = ["203.0.113.42", "198.51.100.7", "93.184.216.34"]


def _normal_session(user_id: str) -> dict:
    return {
        "user_id": user_id,
        "ip_address": _RNG.choice(PRIVATE_IPS),
        "login_hour": _RNG.randint(8, 18),
        "typing_speed": round(_RNG.uniform(4.0, 7.5), 2),
        "request_frequency": round(_RNG.uniform(2.0, 12.0), 2),
        "session_duration": round(_RNG.uniform(10.0, 45.0), 2),
        "geo_anomaly": 0,
        "device_match": 1,
        "failed_attempts": _RNG.randint(0, 1),
        "burst_requests": 0,
    }


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #

def simulate(api_url: str, n_sessions: int, delay: float) -> None:
    url = f"{api_url}/api/behavior"
    print(f"Sending {n_sessions} normal sessions to {url}…")
    for i in range(n_sessions):
        user = _RNG.choice(USERS)
        payload = _normal_session(user)
        try:
            resp = httpx.post(url, json=payload, timeout=10)
            data = resp.json()
            print(
                f"[{i+1:3d}] user={user} "
                f"score={data.get('trust_score', '?'):5.1f} "
                f"action={data.get('action', '?')}"
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[{i+1:3d}] ERROR: {exc}")
        time.sleep(delay)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate normal user sessions")
    parser.add_argument("--sessions", type=int, default=20, help="Number of sessions")
    parser.add_argument(
        "--api-url", default="http://localhost:8000", help="Backend base URL"
    )
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between requests (s)")
    args = parser.parse_args()
    simulate(args.api_url, args.sessions, args.delay)
