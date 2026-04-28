import time
import threading
from collections import defaultdict

from config import load_config

config = load_config()

ZSCORE_LIMIT = config["thresholds"]["zscore_limit"]
RATE_MULTIPLIER = config["thresholds"]["rate_multiplier"]
ERROR_RATE_MULTIPLIER = config["thresholds"]["error_rate_multiplier"]
GLOBAL_ZSCORE_LIMIT = config["thresholds"]["zscore_limit"]
GLOBAL_RATE_MULTIPLIER = config["thresholds"]["rate_multiplier"]


class AnomalyDetector:
    def __init__(self):
        # Per-IP state tracking
        # Stores everything we know about each IP's history
        self.ip_state = defaultdict(lambda: {
            "banned": False,          # Is this IP currently banned?
            "offense_count": 0,       # How many times has it been banned?
            "tightened": False,       # Is it in error-surge tightened mode?
            "ban_time": None,         # When was it banned?
            "last_checked": 0,        # Timestamp of last check
        })

        # Thread lock for ip_state
        self.lock = threading.Lock()

        # Reference to blocker and notifier
        # Set by main.py after all objects are created
        self.blocker = None
        self.notifier = None

        # Track when we last checked global traffic
        self.last_global_check = 0
        self.global_check_interval = 5  # Check global every 5 seconds

    def check(self, ip, monitor, baseline):
        """
        Check one IP for anomalous behavior.
        Called for every log line processed by monitor.py.

        Steps:
        1. Skip if already banned
        2. Get current rate from monitor
        3. Get baseline mean and stddev
        4. Check for error surge — tighten if needed
        5. Calculate Z-score
        6. Fire if Z-score or rate multiplier threshold exceeded
        7. Also check global traffic periodically
        """
        with self.lock:
            state = self.ip_state[ip]

            # Step 1 — Skip IPs that are already banned
            # No point checking them again until they are unbanned
            if state["banned"]:
                return

        # Step 2 — Get how many requests this IP sent in last 60 seconds
        ip_rate = monitor.get_ip_rate(ip)
        ip_error_rate = monitor.get_ip_error_rate(ip)

        # Step 3 — Get the current baseline
        mean, stddev = baseline.get()
        error_mean, error_stddev = baseline.get_error_baseline()

        # Step 4 — Check for error surge
        # If this IP's errors are 3x the baseline error rate,
        # tighten its thresholds by reducing the trigger limits
        with self.lock:
            if (error_mean > 0 and
                    ip_error_rate > ERROR_RATE_MULTIPLIER * error_mean):
                self.ip_state[ip]["tightened"] = True

            tightened = self.ip_state[ip]["tightened"]

        # When tightened, thresholds are reduced by half
        # making the detector more sensitive to this specific IP
        if tightened:
            zscore_limit = ZSCORE_LIMIT / 2
            rate_multiplier = RATE_MULTIPLIER / 2
        else:
            zscore_limit = ZSCORE_LIMIT
            rate_multiplier = RATE_MULTIPLIER

        # Step 5 — Calculate Z-score
        # How many standard deviations away from normal is this IP?
        zscore = (ip_rate - mean) / stddev

        # Step 6 — Check both conditions, whichever fires first
        condition = None

        if zscore > zscore_limit:
            condition = f"z-score={zscore:.2f} exceeded limit={zscore_limit}"

        elif ip_rate > rate_multiplier * mean:
            condition = (f"rate={ip_rate} exceeded "
                        f"{rate_multiplier}x mean={mean:.2f}")

        # If either condition fired, take action
        if condition:
            self._handle_anomaly(ip, ip_rate, mean, condition)

        # Step 7 — Check global traffic every 5 seconds
        now = time.time()
        if now - self.last_global_check >= self.global_check_interval:
            self.last_global_check = now
            self._check_global(monitor, baseline)

    def _handle_anomaly(self, ip, rate, baseline_mean, condition):
        """
        Called when an IP triggers an anomaly condition.
        Bans the IP and sends a Slack alert.
        """
        with self.lock:
            # Double-check it is not already banned
            # Another thread might have banned it between our checks
            if self.ip_state[ip]["banned"]:
                return

            # Mark as banned
            self.ip_state[ip]["banned"] = True
            self.ip_state[ip]["ban_time"] = time.time()
            offense_count = self.ip_state[ip]["offense_count"]

        # Get ban duration from the schedule in config
        ban_schedule = config["bans"]["schedule_minutes"]

        if offense_count < len(ban_schedule):
            duration_minutes = ban_schedule[offense_count]
            duration_str = f"{duration_minutes}min"
        else:
            # Exceeded all schedule entries — permanent ban
            duration_minutes = None
            duration_str = "permanent"

        # Block at the firewall level
        if self.blocker:
            self.blocker.ban(ip, duration_minutes)

        # Send Slack alert
        if self.notifier:
            self.notifier.send_ban_alert(
                ip=ip,
                condition=condition,
                rate=rate,
                baseline=baseline_mean,
                duration=duration_str
            )

        # Write to audit log
        from audit import write_audit
        write_audit(
            action="BAN",
            ip=ip,
            condition=condition,
            rate=rate,
            baseline=baseline_mean,
            duration=duration_str
        )

    def _check_global(self, monitor, baseline):
        """
        Check total traffic across all IPs for a global spike.
        A global spike means many IPs are attacking simultaneously
        so we cannot block one IP — we alert the team instead.
        """
        global_rate = monitor.get_global_rate()
        mean, stddev = baseline.get()

        zscore = (global_rate - mean) / stddev

        condition = None

        if zscore > GLOBAL_ZSCORE_LIMIT:
            condition = (f"global z-score={zscore:.2f} "
                        f"exceeded limit={GLOBAL_ZSCORE_LIMIT}")

        elif global_rate > GLOBAL_RATE_MULTIPLIER * mean:
            condition = (f"global rate={global_rate} exceeded "
                        f"{GLOBAL_RATE_MULTIPLIER}x mean={mean:.2f}")

        if condition:
            # Global anomaly — alert only, no IP-level block possible
            if self.notifier:
                self.notifier.send_global_alert(
                    condition=condition,
                    rate=global_rate,
                    baseline=mean
                )

    def mark_unbanned(self, ip):
        """
        Called by unbanner.py when a ban expires.
        Clears the banned flag and increments the offense count.
        """
        with self.lock:
            self.ip_state[ip]["banned"] = False
            self.ip_state[ip]["ban_time"] = None
            self.ip_state[ip]["offense_count"] += 1
            # Keep tightened state — if they reoffend
            # they are still under tighter scrutiny

    def get_banned_ips(self):
        """
        Return a list of currently banned IPs with their ban time.
        Used by the dashboard.
        """
        with self.lock:
            return [
                {
                    "ip": ip,
                    "ban_time": state["ban_time"],
                    "offense_count": state["offense_count"]
                }
                for ip, state in self.ip_state.items()
                if state["banned"]
            ]
