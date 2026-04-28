import threading
import time
import math
from collections import deque, defaultdict

from config import load_config

config = load_config()

# How long to keep per-second counts in the rolling window
BASELINE_WINDOW_SECONDS = config["thresholds"]["baseline_window_minutes"] * 60

# How often to recalculate mean and stddev
RECALC_INTERVAL = config["thresholds"]["baseline_recalc_interval_seconds"]

# Minimum number of data points before we trust the baseline
MIN_SAMPLES = config["thresholds"]["min_baseline_samples"]


class BaselineTracker:
    def __init__(self):
        # Rolling window of (timestamp, count, error_count) tuples
        # Stores one entry per second for the last 30 minutes
        # Entries older than 30 minutes are evicted from the left
        self.per_second_counts = deque()

        # Per-hour slots: hour (0-23) -> list of per-second counts
        # Allows us to prefer current-hour data when enough exists
        # because 9am traffic patterns differ from 3am patterns
        self.hourly_slots = defaultdict(list)

        # Thread lock — baseline is read by detector and written
        # by the monitor loop simultaneously
        self.lock = threading.Lock()

        # Current computed baseline values
        # These start with safe floor values until enough data exists
        self.effective_mean = 1.0
        self.effective_stddev = 1.0

        # Error rate baseline — used to detect error surges
        self.error_mean = 0.1
        self.error_stddev = 0.05

        # When we last ran a recalculation
        self.last_recalc = time.time()

        # History of baseline values over time
        # Used by the dashboard to show the baseline graph
        # maxlen=200 means we keep the last 200 recalculations
        self.baseline_history = deque(maxlen=200)

    def record(self, count, error_count=0):
        """
        Record one second's worth of request counts.
        Called every second by the tail_log loop in monitor.py.
        Also triggers a recalculation every 60 seconds.
        """
        now = time.time()

        # Which hour of the day is it right now (0-23)
        current_hour = int(time.strftime("%H"))

        with self.lock:
            # Add this second's count to the rolling window
            self.per_second_counts.append((now, count, error_count))

            # Also add to the current hour's slot
            self.hourly_slots[current_hour].append(count)

            # Evict entries older than 30 minutes from the left
            # Entries are added in time order so oldest is always left
            while (self.per_second_counts and
                   now - self.per_second_counts[0][0] > BASELINE_WINDOW_SECONDS):
                self.per_second_counts.popleft()

            # Recalculate mean and stddev every 60 seconds
            if now - self.last_recalc >= RECALC_INTERVAL:
                self._recalculate(current_hour)
                self.last_recalc = now

    def _recalculate(self, current_hour):
        """
        Compute mean and standard deviation from available data.

        Prefers current hour's data if it has enough samples —
        because traffic patterns vary by time of day and the
        current hour is the most relevant comparison point.

        Falls back to the full 30-minute window if the current
        hour does not have enough data yet.
        """
        # Check if current hour has enough data to be meaningful
        hour_data = self.hourly_slots.get(current_hour, [])

        if len(hour_data) >= MIN_SAMPLES:
            # Enough current-hour data — use it
            # This gives us a time-aware baseline
            data = hour_data
        else:
            # Not enough current-hour data yet
            # Fall back to the full rolling window
            data = [count for _, count, _ in self.per_second_counts]

        if len(data) < 2:
            # Not enough data to calculate anything meaningful yet
            # Keep the current values and try again next interval
            return

        # Calculate mean — sum of all values divided by count
        mean = sum(data) / len(data)

        # Calculate variance — average of squared differences from mean
        # This measures how spread out the values are
        variance = sum((x - mean) ** 2 for x in data) / len(data)

        # Standard deviation is the square root of variance
        # It is in the same units as the original data (req/s)
        stddev = math.sqrt(variance)

        # Apply floor values — never go below these minimums
        # Prevents division by zero and extreme sensitivity
        # during very quiet traffic periods
        self.effective_mean = max(mean, 1.0)
        self.effective_stddev = max(stddev, 0.5)

        # Recalculate error baseline from the rolling window
        error_data = [e for _, _, e in self.per_second_counts]
        if error_data:
            error_mean = sum(error_data) / len(error_data)
            error_variance = sum(
                (x - error_mean) ** 2 for x in error_data
            ) / len(error_data)
            self.error_mean = max(error_mean, 0.1)
            self.error_stddev = max(math.sqrt(error_variance), 0.05)

        # Record this recalculation in history for the dashboard graph
        self.baseline_history.append({
            "time": time.strftime("%H:%M:%S"),
            "mean": round(self.effective_mean, 3),
            "stddev": round(self.effective_stddev, 3)
        })

        # Write an audit log entry for this recalculation
        # Import here to avoid circular imports at module level
        from audit import write_audit
        write_audit(
            action="BASELINE_RECALC",
            ip="-",
            condition=(f"mean={self.effective_mean:.2f} "
                      f"stddev={self.effective_stddev:.2f}"),
            rate=self.effective_mean,
            baseline=self.effective_mean,
            duration="-"
        )

    def get(self):
        """
        Return the current effective mean and stddev.
        Called by detector.py when checking each IP.
        """
        with self.lock:
            return self.effective_mean, self.effective_stddev

    def get_error_baseline(self):
        """
        Return the current error rate mean and stddev.
        Called by detector.py when checking for error surges.
        """
        with self.lock:
            return self.error_mean, self.error_stddev
