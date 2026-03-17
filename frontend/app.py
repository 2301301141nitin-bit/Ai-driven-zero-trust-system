"""
Streamlit dashboard for the AI-Driven Zero Trust Security System.

Startup (after the backend is running):
    streamlit run frontend/app.py

The dashboard auto-refreshes every 5 seconds and shows:
  - Live trust score gauge per active user
  - Session log table
  - Attack alerts
  - Statistical charts
"""
from __future__ import annotations

import os
import time
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

API_URL = os.getenv("API_URL", "http://localhost:8000")
REFRESH_INTERVAL = 5  # seconds

# --------------------------------------------------------------------------- #
# Page configuration                                                           #
# --------------------------------------------------------------------------- #

st.set_page_config(
    page_title="Zero Trust Security Dashboard",
    page_icon="🔐",
    layout="wide",
)

# --------------------------------------------------------------------------- #
# Data fetching helpers                                                        #
# --------------------------------------------------------------------------- #


def _get(path: str) -> dict | list | None:
    try:
        resp = requests.get(f"{API_URL}{path}", timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception:  # noqa: BLE001
        return None


def fetch_stats() -> dict:
    data = _get("/api/dashboard/stats")
    return data or {}


def fetch_sessions() -> list[dict]:
    data = _get("/api/dashboard/sessions")
    return data or []


def fetch_alerts() -> list[dict]:
    data = _get("/api/dashboard/alerts")
    return data or []


# --------------------------------------------------------------------------- #
# UI helpers                                                                   #
# --------------------------------------------------------------------------- #

ACTION_COLORS = {
    "ALLOW": "#2ecc71",
    "REQUIRE_REAUTH": "#f39c12",
    "BLOCK": "#e74c3c",
}


def _score_gauge(score: float, user_id: str) -> go.Figure:
    color = (
        "#2ecc71" if score > 70 else "#f39c12" if score >= 40 else "#e74c3c"
    )
    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            title={"text": user_id, "font": {"size": 13}},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": color},
                "steps": [
                    {"range": [0, 40], "color": "#fadbd8"},
                    {"range": [40, 70], "color": "#fdebd0"},
                    {"range": [70, 100], "color": "#d5f5e3"},
                ],
                "threshold": {
                    "line": {"color": "black", "width": 2},
                    "thickness": 0.75,
                    "value": score,
                },
            },
        )
    )
    fig.update_layout(height=200, margin=dict(l=10, r=10, t=30, b=10))
    return fig


# --------------------------------------------------------------------------- #
# Main dashboard                                                               #
# --------------------------------------------------------------------------- #

def render() -> None:
    st.title("🔐 AI-Driven Zero Trust Security Dashboard")
    st.caption(
        "Continuous behavioural authentication — every session is scored "
        "in real-time. Access is dynamically allowed, flagged, or blocked."
    )

    # ---------- Stats row -------------------------------------------------- #
    stats = fetch_stats()
    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Sessions", stats.get("total_sessions", 0))
    col2.metric("✅ Allowed", stats.get("allowed", 0))
    col3.metric("⚠️ Re-Auth Required", stats.get("reauth", 0))
    col4.metric("🚫 Blocked", stats.get("blocked", 0))
    col5.metric(
        "📊 Avg Trust Score",
        f"{stats.get('avg_trust_score', 0):.1f}",
    )

    st.divider()

    sessions = fetch_sessions()
    alerts = fetch_alerts()

    # ---------- Live trust scores ------------------------------------------ #
    st.subheader("🟢 Live User Trust Scores")
    if sessions:
        # Latest score per user
        seen: set[str] = set()
        latest: list[dict] = []
        for s in sessions:
            uid = s.get("user_id", "")
            if uid not in seen:
                seen.add(uid)
                latest.append(s)
            if len(latest) >= 8:
                break

        cols = st.columns(min(len(latest), 4))
        for idx, session in enumerate(latest):
            with cols[idx % 4]:
                score = session.get("trust_score", 50)
                fig = _score_gauge(score, session.get("user_id", "?"))
                st.plotly_chart(fig, use_container_width=True)
                action = session.get("action", "")
                color = ACTION_COLORS.get(action, "#999")
                st.markdown(
                    f"<div style='text-align:center;color:{color};font-weight:bold'>"
                    f"{action}</div>",
                    unsafe_allow_html=True,
                )
    else:
        st.info("No sessions recorded yet. Run the data simulator to generate sessions.")

    st.divider()

    # ---------- Two-column layout ------------------------------------------ #
    left, right = st.columns([2, 1])

    with left:
        st.subheader("📋 Session Log")
        if sessions:
            df = pd.DataFrame(sessions)
            # Keep relevant columns
            cols_to_show = [
                c
                for c in [
                    "timestamp",
                    "user_id",
                    "trust_score",
                    "action",
                    "ip_address",
                    "reason",
                    "geo_anomaly",
                    "burst_requests",
                ]
                if c in df.columns
            ]
            df_display = df[cols_to_show].copy()
            df_display["trust_score"] = df_display["trust_score"].round(1)

            def _row_color(row: pd.Series) -> list[str]:
                action = row.get("action", "")
                bg = (
                    "background-color: #d5f5e3"
                    if action == "ALLOW"
                    else "background-color: #fdebd0"
                    if action == "REQUIRE_REAUTH"
                    else "background-color: #fadbd8"
                )
                return [bg] * len(row)

            styled = df_display.style.apply(_row_color, axis=1)
            st.dataframe(styled, use_container_width=True, height=350)
        else:
            st.info("No sessions yet.")

        # Trust score histogram
        if sessions:
            st.subheader("📊 Trust Score Distribution")
            df_hist = pd.DataFrame(sessions)
            if "trust_score" in df_hist.columns:
                fig_hist = px.histogram(
                    df_hist,
                    x="trust_score",
                    nbins=20,
                    color_discrete_sequence=["#3498db"],
                    labels={"trust_score": "Trust Score"},
                )
                fig_hist.add_vline(x=70, line_dash="dash", line_color="green",
                                   annotation_text="Allow threshold")
                fig_hist.add_vline(x=40, line_dash="dash", line_color="red",
                                   annotation_text="Block threshold")
                fig_hist.update_layout(height=280, margin=dict(t=20, b=20))
                st.plotly_chart(fig_hist, use_container_width=True)

    with right:
        # Action breakdown pie chart
        st.subheader("🥧 Decision Breakdown")
        if sessions:
            df_pie = pd.DataFrame(sessions)
            if "action" in df_pie.columns:
                counts = df_pie["action"].value_counts().reset_index()
                counts.columns = ["action", "count"]
                fig_pie = px.pie(
                    counts,
                    names="action",
                    values="count",
                    color="action",
                    color_discrete_map=ACTION_COLORS,
                    hole=0.4,
                )
                fig_pie.update_layout(height=300, margin=dict(t=20, b=20))
                st.plotly_chart(fig_pie, use_container_width=True)

        # Alerts panel
        st.subheader("🚨 Security Alerts")
        if alerts:
            for alert in alerts[:10]:
                with st.expander(
                    f"🔴 {alert.get('user_id', '?')} — "
                    f"score {alert.get('trust_score', '?')} — "
                    f"{alert.get('timestamp', '')[:19]}",
                    expanded=False,
                ):
                    st.write(f"**Action:** {alert.get('action', '?')}")
                    st.write(f"**Reason:** {alert.get('reason', '?')}")
                    st.write(f"**IP:** {alert.get('ip_address', '?')}")
        else:
            st.success("No active alerts.")

    # ---------- Auto-refresh ------------------------------------------------ #
    st.divider()
    st.caption(
        f"Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC  •  "
        f"Auto-refresh every {REFRESH_INTERVAL}s"
    )
    time.sleep(REFRESH_INTERVAL)
    st.rerun()


if __name__ == "__main__":
    render()
else:
    render()
