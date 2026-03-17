"""
Attack simulator – generates synthetic attack sessions and sends them to the
backend API to demonstrate anomaly detection.

Simulated attack types:
    1. session_hijacking – foreign IP, unknown device
    2. geo_anomaly       – sudden location change
    3. bot_flooding      – burst requests at high frequency
    4. brute_force       – many failed authentication attempts

Usage:
    python data/attack_simulator.py --attacks 20 --api-url http://localhost:8000
"""
from __future__ import annotations

import argparse
import random
import time

import httpx

_RNG = random.Random(1)

USERS = [f"user_{i:03d}" for i in range(1, 11)]
ATTACKER_IPS = ["45.33.32.156", "91.108.4.1", "1.2.3.4", "255.255.255.0"]

ATTACK_TYPES = ["session_hijacking", "geo_anomaly", "bot_flooding", "brute_force"]


def _attack_payload(attack_type: str) -> dict:
    user = _RNG.choice(USERS)
    base = {
        "user_id": user,
        "ip_address": _RNG.choice(ATTACKER_IPS),
        "login_hour": _RNG.randint(0, 23),
        "typing_speed": 0.0,
        "request_frequency": 5.0,
        "session_duration": 2.0,
        "geo_anomaly": 0,
        "device_match": 1,
        "failed_attempts": 0,
        "burst_requests": 0,
    }

    if attack_type == "session_hijacking":
        base.update({"device_match": 0, "ip_address": _RNG.choice(ATTACKER_IPS)})

    elif attack_type == "geo_anomaly":
        base.update({"geo_anomaly": 1, "ip_address": _RNG.choice(ATTACKER_IPS)})

    elif attack_type == "bot_flooding":
        base.update(
            {
                "burst_requests": 1,
                "request_frequency": round(_RNG.uniform(80, 200), 1),
                "typing_speed": 0.0,
            }
        )

    elif attack_type == "brute_force":
        base.update(
            {
                "failed_attempts": _RNG.randint(5, 15),
                "ip_address": _RNG.choice(ATTACKER_IPS),
            }
        )

    return base


def simulate_attacks(api_url: str, n_attacks: int, delay: float) -> None:
    url = f"{api_url}/api/behavior"
    print(f"Sending {n_attacks} attack sessions to {url}…\n")
    for i in range(n_attacks):
        attack_type = _RNG.choice(ATTACK_TYPES)
        payload = _attack_payload(attack_type)
        try:
            resp = httpx.post(url, json=payload, timeout=10)
            data = resp.json()
            print(
                f"[{i+1:3d}] ATTACK={attack_type:<20s} "
                f"user={payload['user_id']} "
                f"score={data.get('trust_score', '?'):5.1f} "
                f"action={data.get('action', '?')} "
                f"alert={data.get('alert', '?')}"
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[{i+1:3d}] ERROR: {exc}")
        time.sleep(delay)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate attack sessions")
    parser.add_argument("--attacks", type=int, default=10, help="Number of attacks")
    parser.add_argument(
        "--api-url", default="http://localhost:8000", help="Backend base URL"
    )
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between requests (s)")
    args = parser.parse_args()
    simulate_attacks(args.api_url, args.attacks, args.delay)
