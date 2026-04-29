# HNG Anomaly Detection Engine

A real-time DDoS detection and mitigation tool built for cloud.ng (Nextcloud).
Monitors HTTP traffic, learns normal patterns, and automatically blocks anomalous IPs.

---

## Live URLs

- **Metrics Dashboard:** http://hngstagekene3.duckdns.org:8080
- **Nextcloud (IP only):** http://13.41.231.81

---

## Language Choice

**Python** — chosen for rapid development, readable code, and strong standard library
support for threading, deques, and JSON parsing. The `collections.deque` data structure
maps directly to the sliding window requirement.

---

## How the Sliding Window Works

Each IP and global traffic share a `deque` (double-ended queue).

- New requests are appended to the **right**
- On every read, entries older than 60 seconds are evicted from the **left**
- The length of the deque at any moment = request count in the last 60 seconds

```python
# Add new entry
window.append((timestamp, is_error))

# Evict old entries
while window and now - window[0][0] > 60:
    window.popleft()

# Current rate
rate = len(window)
```

No counters, no resets — the window slides naturally with time.

---

## How the Baseline Works

- **Window size:** 30 minutes of per-second counts
- **Recalculation interval:** every 60 seconds
- **Hourly slots:** traffic is bucketed by hour (0-23)
- **Preference:** current hour's data is used if it has ≥30 samples
- **Floor values:** mean never below 1.0, stddev never below 0.5
- **Output:** `effective_mean` and `effective_stddev` used by detector

The baseline never hardcodes values — it learns from actual traffic.

---

## How Detection Works

Two conditions checked per IP on every log line:

1. **Z-score:** `z = (rate - mean) / stddev` — fires if z > 3.0
2. **Rate multiplier:** fires if `rate > 5x mean`

Whichever fires first triggers a ban. For error surges (4xx/5xx rate > 3x
error baseline), thresholds are tightened by 50% for that specific IP.

Global traffic is checked every 5 seconds using the same logic.
Global anomalies send a Slack alert only — no IP block is possible.

---

## Setup Instructions

### 1. Prerequisites

```bash
# Ubuntu 22.04 on a VPS with 2 vCPU, 2GB RAM minimum
sudo apt update && sudo apt upgrade -y
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
sudo apt install docker-compose-plugin -y
```

### 2. Clone the Repository

```bash
git clone https://github.com/RichardBenjamin/hng14-Stage3.git
cd hng14-Stage3
```

### 3. Configure

```bash
nano detector/config.yaml
# Add your Slack webhook URL
```

### 4. Start the Stack

```bash
docker compose up --build -d
```

### 5. Verify

```bash
# Check all containers running
docker compose ps

# Watch detector logs
docker logs detector -f

# View dashboard
curl http://localhost:8080
```

---

## Repository Structure
detector/
main.py         — entry point, wires all components
monitor.py      — log tailing and sliding windows
baseline.py     — rolling baseline calculation
detector.py     — anomaly detection logic
blocker.py      — iptables ban/unban
unbanner.py     — scheduled ban release
notifier.py     — Slack alerts
dashboard.py    — live metrics web UI
audit.py        — structured audit logging
config.yaml     — all thresholds and settings
requirements.txt
nginx/
nginx.conf      — reverse proxy with JSON logging
docs/
architecture.png
screenshots/
README.md
docker-compose.yml


---

## GitHub Repository

https://github.com/RichardBenjamin/hng14-Stage3

---

## Blog Post

