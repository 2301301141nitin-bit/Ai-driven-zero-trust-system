# 🔐 AI-Driven Zero Trust Security System

> **Continuous AI-based authentication** — every request is scored in real-time.  
> Access is dynamically **allowed**, **flagged for re-auth**, or **blocked** based on behavioural anomaly detection.

---

## 🧠 How It Works

Traditional security:
```
login → access granted forever 😴
```

This system:
```
login → behaviour monitored → AI scores trust dynamically → decision enforced 🔥
```

Every API call produces a **Trust Score (0–100)**. The Decision Engine maps it to an action:

| Score | Action | Description |
|-------|--------|-------------|
| > 70 | ✅ **ALLOW** | Normal behaviour |
| 40–70 | ⚠️ **REQUIRE_REAUTH** | Suspicious — challenge the user |
| < 40 | 🚫 **BLOCK + ALERT** | Attack detected — block immediately |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Streamlit Dashboard                │
│          Live scores · Alerts · Charts               │
└──────────────────────┬──────────────────────────────┘
                       │  REST
┌──────────────────────▼──────────────────────────────┐
│                  FastAPI Backend                     │
│  POST /api/behavior → AI Engine → Decision Engine   │
│  GET  /api/dashboard/sessions|alerts|stats          │
└──────────┬──────────────────┬───────────────────────┘
           │                  │
    ┌──────▼──────┐   ┌───────▼───────┐
    │  AI Engine  │   │   Database    │
    │Isolation    │   │MongoDB Atlas  │
    │Forest +     │   │(or in-memory) │
    │Calibrated   │   └───────────────┘
    │Scoring      │
    └─────────────┘
```

### Components

| Layer | Tech | Description |
|-------|------|-------------|
| **Backend** | Python · FastAPI | REST API, business logic |
| **AI Engine** | scikit-learn · Isolation Forest | Unsupervised anomaly detection |
| **Feature Engineering** | NumPy | Cyclical encoding, IP heuristics |
| **Decision Engine** | Python | Hybrid AI + rule-based scoring |
| **Frontend** | Streamlit · Plotly | Live dashboard |
| **Database** | MongoDB Atlas / in-memory | Session and alert persistence |
| **Containers** | Docker · Compose | One-command deployment |

---

## 🚀 Quick Start

### Option 1 – Docker Compose (recommended)

```bash
docker-compose up --build
```

- Backend API: http://localhost:8000
- Dashboard:   http://localhost:8501
- API docs:    http://localhost:8000/docs

### Option 2 – Local Development

**1. Install dependencies**

```bash
pip install -r backend/requirements.txt
pip install -r frontend/requirements.txt
```

**2. Start the backend**

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

**3. Start the dashboard** (new terminal)

```bash
streamlit run frontend/app.py
```

**4. Generate test data** (new terminal)

```bash
# Normal sessions
python data/simulate_data.py --sessions 30 --api-url http://localhost:8000

# Attack simulations
python data/attack_simulator.py --attacks 15 --api-url http://localhost:8000
```

---

## 📡 API Reference

### `POST /api/behavior`

Evaluate a user session and return a trust decision.

**Request body:**

```json
{
  "user_id": "alice",
  "ip_address": "10.0.0.1",
  "login_hour": 9,
  "typing_speed": 5.2,
  "request_frequency": 8.0,
  "session_duration": 20.0,
  "geo_anomaly": 0,
  "device_match": 1,
  "failed_attempts": 0,
  "burst_requests": 0
}
```

**Response:**

```json
{
  "user_id": "alice",
  "trust_score": 75.8,
  "action": "ALLOW",
  "alert": false,
  "reason": "Behaviour within normal profile",
  "timestamp": "2024-01-01T09:00:00Z"
}
```

### `GET /api/dashboard/sessions`  
Returns the latest 200 session records.

### `GET /api/dashboard/alerts`  
Returns the latest 100 security alerts.

### `GET /api/dashboard/stats`  
Returns aggregate statistics (total, allowed, reauth, blocked, avg score).

---

## 🧠 AI Engine Details

### Model: Isolation Forest

- **Algorithm:** Isolation Forest (scikit-learn)
- **Training:** Trained on 2,000 synthetic normal-behaviour samples at startup — no labelled dataset required
- **Scoring:** Calibrated against the training distribution (5th/95th percentiles) so normal sessions score ~75–90 and attacks score near 0

### Feature Vector (10 features)

| Feature | Description |
|---------|-------------|
| `login_hour_sin/cos` | Cyclical hour encoding |
| `typing_speed` | Characters per second |
| `request_frequency` | Requests per minute |
| `session_duration` | Session length in minutes |
| `geo_anomaly` | Location change detected |
| `device_match_inv` | Inverted device-match flag |
| `failed_attempts` | Auth failures this session |
| `burst_requests` | Burst pattern detected |
| `ip_risk_score` | IP reputation heuristic |

### Hybrid Scoring

The final trust score is the result of **AI anomaly detection + rule-based penalties**:

| Indicator | Score Penalty |
|-----------|---------------|
| Geographic anomaly | −30 |
| Unknown device | −20 |
| ≥5 failed attempts | −25 |
| Burst request pattern | −35 |

---

## 🔐 Simulated Attack Types

| Attack | Signals |
|--------|---------|
| **Session hijacking** | Foreign IP + unknown device |
| **Geo anomaly** | Sudden location change |
| **Bot flooding** | Burst requests + zero typing speed + high frequency |
| **Brute force** | Many failed authentication attempts |

---

## ☁️ Cloud Deployment

### AWS (EC2)

```bash
# On your EC2 instance (Ubuntu 22.04)
git clone <repo>
cd Ai-driven-zero-trust-system

# Set MongoDB Atlas URI (optional)
export MONGODB_URI="mongodb+srv://user:pass@cluster.mongodb.net/"

docker-compose up -d --build
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGODB_URI` | `""` | MongoDB connection string. Leave empty to use in-memory store. |
| `API_URL` | `http://localhost:8000` | Backend URL for the Streamlit frontend |

---

## 🧪 Running Tests

```bash
python -m pytest tests/ -v
```

39 tests covering:
- Feature engineering (cyclical encoding, IP heuristics, flag inversion)
- AI engine (score range, normal > attack, determinism, untrained guard)
- Decision engine (thresholds, penalties, boundary conditions, reasons)
- API endpoints (health, behavior, dashboard, validation)

---

## 📁 Project Structure

```
.
├── backend/
│   ├── main.py                   # FastAPI app + lifespan
│   ├── schemas.py                # Pydantic request/response models
│   ├── database.py               # MongoDB + in-memory fallback
│   ├── models/
│   │   ├── ai_engine.py          # Isolation Forest + calibrated scoring
│   │   ├── decision_engine.py    # Hybrid AI + rule-based decisions
│   │   └── feature_engineering.py # Feature extraction
│   ├── routes/
│   │   ├── behavior.py           # POST /api/behavior
│   │   └── dashboard.py          # GET /api/dashboard/*
│   └── requirements.txt
├── frontend/
│   ├── app.py                    # Streamlit dashboard
│   └── requirements.txt
├── data/
│   ├── simulate_data.py          # Normal session generator
│   └── attack_simulator.py      # Attack scenario generator
├── tests/
│   ├── test_feature_engineering.py
│   ├── test_ai_engine.py
│   ├── test_decision_engine.py
│   └── test_api.py
├── Dockerfile.backend
├── Dockerfile.frontend
└── docker-compose.yml
```