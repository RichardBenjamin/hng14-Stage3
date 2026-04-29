# HNG Anomaly Detection Engine

A real-time DDoS detection and mitigation daemon built for cloud.ng (Nextcloud).

---

## Live URLs

| Service | URL |
|---|---|
| Metrics Dashboard | http://hngstagekene3.duckdns.org:8080 |
| Server IP | 13.41.231.81 |
| Nextcloud (IP only) | http://13.41.231.81 |

---

## GitHub Repository

https://github.com/RichardBenjamin/hng14-Stage3

---

## Blog Post

[https://shell-script-for-monitoring-login-attempts.hashnode.dev/how-i-built-a-real-time-ddos-detection-engine-from-scratch]

---

## Language Choice

Python 3.11 was chosen because:

- collections.deque maps directly to the sliding window requirement with O(1) append and popleft
- threading allows log tailer, unbanner, and dashboard to run concurrently
- json parses Nginx logs in one line
- subprocess gives direct access to iptables
- flask serves the dashboard with minimal setup
- Readable code makes detection logic easy to audit

---

## How the Sliding Window Works

Two deques are maintained:

- Per-IP window: one deque per IP storing (timestamp, is_error) tuples
- Global window: one deque for all traffic combined

Adding entries — every log line appends to the right:

    now = time.time()
    is_error = entry["status"] >= 400
    self.ip_windows[ip].append((now, is_error))
    self.global_window.append((now, is_error))

Eviction logic — old entries removed from the left before every read:

    def _evict_old_entries(self, window):
        now = time.time()
        while window and now - window[0][0] > WINDOW_SECONDS:
            window.popleft()

Because entries are added in time order, the oldest is always on the left.
len(window) at any moment gives the exact request count for the last 60 seconds.
The window slides with time. No minute boundaries, no resets, no counters.

---

## How the Baseline Works

Window size: 30-minute rolling window of per-second counts.

Recalculation interval: every 60 seconds.

    mean = sum(data) / len(data)
    variance = sum((x - mean) ** 2 for x in data) / len(data)
    stddev = math.sqrt(variance)

Hourly slots: traffic is bucketed by hour (0-23). Current hour data is preferred
when it has at least 30 samples. Falls back to full 30-minute window otherwise.

Floor values prevent division by zero and extreme sensitivity during quiet periods:

    effective_mean = max(mean, 1.0)
    effective_stddev = max(stddev, 0.5)

---

## Setup Instructions

### 1. Provision a VPS

Minimum: 2 vCPU, 2GB RAM, Ubuntu 22.04 LTS
Open ports: 22, 80, 443, 8080

### 2. SSH In

    ssh -i your-key.pem ubuntu@YOUR_SERVER_IP

### 3. Install Docker

    sudo apt update && sudo apt upgrade -y
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker ubuntu
    newgrp docker
    sudo apt install docker-compose-plugin -y

### 4. Clone the Repository

    git clone https://github.com/RichardBenjamin/hng14-Stage3.git
    cd hng14-Stage3

### 5. Configure Slack Webhook

    nano detector/config.yaml

Replace YOUR_SLACK_WEBHOOK_URL_HERE with your actual webhook URL.

### 6. Start the Stack

    docker compose up --build -d

### 7. Verify

    docker compose ps
    docker logs detector -f
    curl http://localhost:8080
    curl http://localhost

### 8. Add Trusted Domain to Nextcloud

    docker exec -u 33 -it nextcloud bash -c \
      "php /var/www/html/occ config:system:set trusted_domains 1 --value='yourdomain.duckdns.org'"

### 9. View Audit Log

    docker exec detector cat /var/log/detector/audit.log

### 10. Check Blocked IPs

    sudo iptables -L -n

---

## Repository Structure

    hng14-Stage3/
    detector/
      main.py           entry point, wires all components
      monitor.py        log tailing and sliding windows
      baseline.py       rolling baseline with hourly slots
      detector.py       Z-score and rate multiplier detection
      blocker.py        iptables ban and unban
      unbanner.py       scheduled ban release
      notifier.py       Slack alerts
      dashboard.py      Flask live metrics UI
      audit.py          structured audit log writer
      config.py         YAML config loader
      config.yaml       all thresholds and settings
      requirements.txt
      Dockerfile
    nginx/
      nginx.conf
    docs/
      architecture.png
    screenshots/
      Tool-running.png
      Ban-slack.png
      Unban-slack.png
      Global-alert-slack.png
      Iptables-banned.png
      Audit-log.png
      Baseline-graph.png
    docker-compose.yml
    README.md

---

## Detection Logic

Every log line triggers:

1. Get current IP rate from sliding window
2. Get baseline mean and stddev
3. Calculate Z-score: z = (rate - mean) / stddev
4. If z > 3.0 then ban
5. If rate > 5x mean then ban
6. If error rate > 3x error baseline then tighten thresholds for this IP
7. Every 5 seconds check global rate with same logic

Per-IP anomaly: iptables DROP rule plus Slack alert within 10 seconds
Global anomaly: Slack alert only

---

## Unban Schedule

| Offense | Duration |
|---|---|
| 1st | 10 minutes |
| 2nd | 30 minutes |
| 3rd | 2 hours |
| 4th+ | Permanent |

---

## Audit Log Format

    [2026-04-28T03:07:24] BAN 135.129.124.171 | z-score=3.32 exceeded limit=3.0 | rate=4.00 | baseline=1.25 | duration=10min
    [2026-04-28T03:17:27] UNBAN 135.129.124.171 | ban-expired | rate=0.00 | baseline=0.00 | duration=10min
    [2026-04-28T03:21:26] BASELINE_RECALC - | mean=8.62 stddev=10.45 | rate=8.62 | baseline=8.62 | duration=-
