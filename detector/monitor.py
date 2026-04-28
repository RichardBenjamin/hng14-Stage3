import json
import time
import os
from collections import deque, defaultdict
import threading

from config import load_config

config = load_config()

# Path to the nginx log file - comes from config.yaml
LOG_PATH = config["logging"]["nginx_log_path"]

# How far back the sliding window looks in seconds
WINDOW_SECONDS = config["thresholds"]["sliding_window_seconds"]


class TrafficMonitor:
    def __init__(self):
        # Per-IP sliding windows
        # Each key is an IP address
        # Each value is a deque of (timestamp, is_error) tuples
        # We store tuples so we can count both requests and errors
        self.ip_windows = defaultdict(deque)

        # Global sliding window
        # A single deque of (timestamp, is_error) tuples
        # Tracks all traffic regardless of IP
        self.global_window = deque()

        # Lock for thread safety
        # Multiple threads will read this data
        # The lock prevents one thread reading while another writes
        self.lock = threading.Lock()

        # Store the last 60 seconds of parsed log entries
        # Used by the dashboard to show recent activity
        self.recent_entries = deque(maxlen=1000)

    def _evict_old_entries(self, window):
        """
        Remove entries older than WINDOW_SECONDS from the left of the deque.
        This is what makes it a sliding window — old data falls off automatically.
        We only check from the left because entries are added in time order,
        so the oldest entries are always on the left side.
        """
        now = time.time()
        while window and now - window[0][0] > WINDOW_SECONDS:
            window.popleft()

    def record(self, entry):
        """
        Record one parsed log entry into both sliding windows.
        Called once per log line read from nginx.
        """
        now = time.time()

        # A request is an error if status code is 4xx or 5xx
        is_error = entry["status"] >= 400

        with self.lock:
            ip = entry["source_ip"]

            # Add this request to the per-IP window
            self.ip_windows[ip].append((now, is_error))

            # Add this request to the global window
            self.global_window.append((now, is_error))

            # Evict entries older than the window from both
            self._evict_old_entries(self.ip_windows[ip])
            self._evict_old_entries(self.global_window)

            # Keep a record of recent entries for the dashboard
            self.recent_entries.append(entry)

    def get_ip_rate(self, ip):
        """
        Return the number of requests from this IP
        in the last WINDOW_SECONDS seconds.
        """
        with self.lock:
            self._evict_old_entries(self.ip_windows[ip])
            return len(self.ip_windows[ip])

    def get_ip_error_rate(self, ip):
        """
        Return the number of error requests (4xx/5xx) from this IP
        in the last WINDOW_SECONDS seconds.
        """
        with self.lock:
            self._evict_old_entries(self.ip_windows[ip])
            return sum(1 for _, is_error in self.ip_windows[ip] if is_error)

    def get_global_rate(self):
        """
        Return the total number of requests from all IPs
        in the last WINDOW_SECONDS seconds.
        """
        with self.lock:
            self._evict_old_entries(self.global_window)
            return len(self.global_window)

    def get_top_ips(self, n=10):
        """
        Return the top N IPs by request count in the current window.
        Used by the dashboard to show the busiest IPs.
        """
        with self.lock:
            counts = {}
            for ip, window in self.ip_windows.items():
                self._evict_old_entries(window)
                if window:
                    counts[ip] = len(window)
            # Sort by count descending, return top N
            return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]


def parse_line(line):
    """
    Parse one JSON log line from nginx into a dictionary.
    Returns None if the line is not valid JSON.
    """
    line = line.strip()
    if not line:
        return None
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        # If the line is not valid JSON, skip it silently
        # This can happen if nginx is mid-write when we read
        return None


def tail_log(monitor, baseline, detector):
    """
    Continuously tail the nginx log file and process each new line.
    This function runs forever — it is the main loop of the daemon.

    Parameters:
        monitor  - the TrafficMonitor instance to record entries into
        baseline - the BaselineTracker instance to feed counts into
        detector - the AnomalyDetector instance to check each entry
    """

    # Wait for the log file to exist
    # Nginx might not have written anything yet when we start
    while not os.path.exists(LOG_PATH):
        print(f"Waiting for log file to appear at {LOG_PATH}...")
        time.sleep(2)

    print(f"Log file found. Starting to tail {LOG_PATH}")

    # Track requests per second for the baseline
    # We count how many requests arrive each second
    current_second = int(time.time())
    second_count = 0
    second_error_count = 0

    with open(LOG_PATH, "r") as f:
        # Move to the end of the file
        # We only want new lines, not lines that existed before we started
        f.seek(0, 2)

        while True:
            line = f.readline()

            if not line:
                # No new line yet — wait a short moment and try again
                # This is the tail behavior — we never stop, just wait
                time.sleep(0.05)
                continue

            entry = parse_line(line)
            if entry is None:
                continue

            # Record into the sliding windows
            monitor.record(entry)

            # Count requests per second for the baseline
            now_second = int(time.time())
            if now_second != current_second:
                # A new second has started
                # Record the previous second's count into the baseline
                baseline.record(second_count, second_error_count)
                # Reset counters for the new second
                second_count = 0
                second_error_count = 0
                current_second = now_second

            second_count += 1
            if entry["status"] >= 400:
                second_error_count += 1

            # Check this IP for anomalies
            detector.check(entry["source_ip"], monitor, baseline)
