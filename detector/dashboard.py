import time
import threading
import psutil
from flask import Flask

from config import load_config

config = load_config()

PORT = config["dashboard"]["port"]
REFRESH_SECONDS = config["dashboard"]["refresh_seconds"]

# Flask app — one instance shared across the module
app = Flask(__name__)

# These references are set by main.py after all objects are created
# Dashboard needs to read state from all components
_monitor = None
_baseline = None
_detector = None
_blocker = None
_unbanner = None
_start_time = time.time()


def init(monitor, baseline, detector, blocker, unbanner):
    """
    Called by main.py to give the dashboard references
    to all the components it needs to read from.
    """
    global _monitor, _baseline, _detector, _blocker, _unbanner
    _monitor = monitor
    _baseline = baseline
    _detector = detector
    _blocker = blocker
    _unbanner = unbanner


def _uptime():
    """
    Calculate how long the daemon has been running.
    Returns a human readable string like "4h 23m 11s"
    """
    elapsed = int(time.time() - _start_time)
    hours = elapsed // 3600
    minutes = (elapsed % 3600) // 60
    seconds = elapsed % 60
    return f"{hours}h {minutes}m {seconds}s"


def _format_ban_time(ban_time):
    """Convert a unix timestamp to a readable time string."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ban_time))


def _time_until_unban(ip, ban_registry):
    """
    Calculate how many minutes and seconds until a ban expires.
    Returns 'permanent' if the ban has no expiry.
    """
    meta = ban_registry.get(ip)
    if not meta:
        return "unknown"

    duration = meta.get("duration_minutes")
    if duration is None:
        return "permanent"

    ban_time = meta.get("ban_time", time.time())
    expires_at = ban_time + (duration * 60)
    remaining = int(expires_at - time.time())

    if remaining <= 0:
        return "expiring soon"

    mins = remaining // 60
    secs = remaining % 60
    return f"{mins}m {secs}s"


@app.route("/")
def index():
    """
    Main dashboard route.
    Collects current state from all components and
    returns a complete HTML page.
    """
    # Collect all the data we need
    mean, stddev = _baseline.get()
    global_rate = _monitor.get_global_rate()
    top_ips = _monitor.get_top_ips(10)
    banned_ips = _detector.get_banned_ips()
    ban_registry = _unbanner.get_registry()
    cpu = psutil.cpu_percent(interval=None)
    memory = psutil.virtual_memory().percent
    uptime = _uptime()

    # Build the banned IPs table rows
    banned_rows = ""
    if banned_ips:
        for entry in banned_ips:
            ip = entry["ip"]
            ban_time = _format_ban_time(entry["ban_time"])
            unban_in = _time_until_unban(ip, ban_registry)
            offense = entry["offense_count"] + 1
            banned_rows += f"""
            <tr>
                <td>{ip}</td>
                <td>{ban_time}</td>
                <td>{unban_in}</td>
                <td>{offense}</td>
            </tr>"""
    else:
        banned_rows = """
            <tr>
                <td colspan="4"
                    style="text-align:center;color:#666">
                    No IPs currently banned
                </td>
            </tr>"""

    # Build the top IPs table rows
    top_ip_rows = ""
    banned_ip_set = {entry["ip"] for entry in banned_ips}
    for rank, (ip, count) in enumerate(top_ips, 1):
        status = "🚫 BANNED" if ip in banned_ip_set else "✅ active"
        top_ip_rows += f"""
            <tr>
                <td>{rank}</td>
                <td>{ip}</td>
                <td>{count}</td>
                <td>{status}</td>
            </tr>"""

    if not top_ip_rows:
        top_ip_rows = """
            <tr>
                <td colspan="4"
                    style="text-align:center;color:#666">
                    No traffic yet
                </td>
            </tr>"""

    # Return the complete HTML page
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>HNG Anomaly Detector</title>
    <meta http-equiv="refresh" content="{REFRESH_SECONDS}">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: monospace;
            background: #0d1117;
            color: #c9d1d9;
            padding: 24px;
        }}
        h1 {{
            color: #58a6ff;
            margin-bottom: 8px;
            font-size: 22px;
        }}
        .subtitle {{
            color: #8b949e;
            font-size: 13px;
            margin-bottom: 24px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 16px;
        }}
        .card .label {{
            font-size: 11px;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }}
        .card .value {{
            font-size: 24px;
            font-weight: bold;
            color: #58a6ff;
        }}
        .card .value.warning {{ color: #f85149; }}
        .card .value.ok {{ color: #3fb950; }}
        h2 {{
            color: #8b949e;
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 12px;
            margin-top: 24px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 24px;
        }}
        th {{
            background: #21262d;
            padding: 10px 14px;
            text-align: left;
            font-size: 12px;
            color: #8b949e;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        td {{
            padding: 10px 14px;
            font-size: 13px;
            border-top: 1px solid #21262d;
        }}
        tr:hover td {{ background: #1c2128; }}
        .footer {{
            color: #484f58;
            font-size: 11px;
            margin-top: 16px;
        }}
    </style>
</head>
<body>

<h1>🛡 HNG Anomaly Detection Engine</h1>
<div class="subtitle">
    Auto-refreshes every {REFRESH_SECONDS}s &nbsp;|&nbsp;
    Last updated: {time.strftime("%H:%M:%S")}
</div>

<div class="grid">
    <div class="card">
        <div class="label">Uptime</div>
        <div class="value" style="font-size:16px">{uptime}</div>
    </div>
    <div class="card">
        <div class="label">Global req/s</div>
        <div class="value {'warning' if global_rate > mean * 3 else 'ok'}">
            {global_rate}
        </div>
    </div>
    <div class="card">
        <div class="label">Baseline Mean</div>
        <div class="value" style="font-size:18px">{mean:.2f}</div>
    </div>
    <div class="card">
        <div class="label">Baseline Stddev</div>
        <div class="value" style="font-size:18px">{stddev:.2f}</div>
    </div>
    <div class="card">
        <div class="label">CPU Usage</div>
        <div class="value {'warning' if cpu > 80 else 'ok'}">{cpu}%</div>
    </div>
    <div class="card">
        <div class="label">Memory Usage</div>
        <div class="value {'warning' if memory > 80 else 'ok'}">{memory}%</div>
    </div>
    <div class="card">
        <div class="label">Banned IPs</div>
        <div class="value {'warning' if banned_ips else 'ok'}">
            {len(banned_ips)}
        </div>
    </div>
</div>

<h2>Currently Banned IPs</h2>
<table>
    <thead>
        <tr>
            <th>IP Address</th>
            <th>Banned At</th>
            <th>Unban In</th>
            <th>Offense #</th>
        </tr>
    </thead>
    <tbody>
        {banned_rows}
    </tbody>
</table>

<h2>Top 10 Source IPs (last 60s)</h2>
<table>
    <thead>
        <tr>
            <th>#</th>
            <th>IP Address</th>
            <th>Requests</th>
            <th>Status</th>
        </tr>
    </thead>
    <tbody>
        {top_ip_rows}
    </tbody>
</table>

<div class="footer">
    HNG Anomaly Detection Engine &nbsp;|&nbsp;
    cloud.ng security tooling
</div>

</body>
</html>"""


def run():
    """
    Start the Flask web server.
    Called by main.py in a background thread.
    Runs on 0.0.0.0 so it is reachable from outside the container.
    """
    app.run(
        host="0.0.0.0",
        port=PORT,
        # debug=False is important in production
        # debug=True would start a second process and break threading
        debug=False,
        # Disable the reloader for the same reason
        use_reloader=False
    )
