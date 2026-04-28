import threading
import time

from config import load_config
from audit import write_audit

config = load_config()

# The ban duration schedule from config
# Index 0 = first offense, index 1 = second, and so on
BAN_SCHEDULE_MINUTES = config["bans"]["schedule_minutes"]

# How often the unbanner checks for expired bans
# Every 10 seconds is frequent enough without being wasteful
CHECK_INTERVAL = 10


class Unbanner:
    def __init__(self, blocker, detector, notifier):
        # References to the other components it needs to coordinate with
        self.blocker = blocker
        self.detector = detector
        self.notifier = notifier

        # Stores ban metadata per IP
        # Key: IP address
        # Value: dict with ban_time and duration_minutes
        self.ban_registry = {}
        self.lock = threading.Lock()

    def register_ban(self, ip, duration_minutes, offense_count):
        """
        Called by detector.py immediately after a ban is issued.
        Records the ban time and duration so unbanner knows
        when to release it.

        duration_minutes=None means permanent — never unban.
        """
        with self.lock:
            self.ban_registry[ip] = {
                "ban_time": time.time(),
                "duration_minutes": duration_minutes,
                "offense_count": offense_count
            }

    def run(self):
        """
        The main loop of the unbanner.
        Runs forever in its own thread.
        Every CHECK_INTERVAL seconds it scans all registered bans
        and releases any that have expired.
        """
        print("[UNBANNER] Starting unban watcher...")

        while True:
            time.sleep(CHECK_INTERVAL)
            self._check_bans()

    def _check_bans(self):
        """
        Scan all registered bans and unban any that have expired.
        """
        now = time.time()

        # Build list of IPs to unban outside the lock
        # to keep the lock held for as short a time as possible
        to_unban = []

        with self.lock:
            for ip, meta in self.ban_registry.items():
                duration = meta["duration_minutes"]

                # Permanent ban — never expires
                if duration is None:
                    continue

                # Calculate when this ban should expire
                ban_expires_at = meta["ban_time"] + (duration * 60)

                if now >= ban_expires_at:
                    to_unban.append((ip, meta))

        # Process unbans outside the lock
        for ip, meta in to_unban:
            self._unban(ip, meta)

    def _unban(self, ip, meta):
        """
        Perform the full unban sequence for one IP:
        1. Remove the iptables rule via blocker
        2. Update detector state so it can be flagged again
        3. Send Slack notification
        4. Write audit log entry
        5. Remove from our registry
        """
        duration = meta["duration_minutes"]
        offense_count = meta["offense_count"]

        # Work out what the next ban duration would be
        # if this IP reoffends — for the Slack message
        next_offense = offense_count + 1
        if next_offense < len(BAN_SCHEDULE_MINUTES):
            next_duration = f"{BAN_SCHEDULE_MINUTES[next_offense]}min"
        else:
            next_duration = "permanent"

        # Step 1 — Remove the iptables rule
        self.blocker.unban(ip)

        # Step 2 — Update detector state
        # This clears the banned flag and increments offense count
        # so the next ban for this IP uses the next schedule slot
        self.detector.mark_unbanned(ip)

        # Step 3 — Send Slack notification
        if self.notifier:
            self.notifier.send_unban_alert(
                ip=ip,
                duration=f"{duration}min",
                offense_count=offense_count,
                next_duration=next_duration
            )

        # Step 4 — Write audit log entry
        write_audit(
            action="UNBAN",
            ip=ip,
            condition="ban-expired",
            rate=0.0,
            baseline=0.0,
            duration=f"{duration}min"
        )

        print(f"[UNBANNER] Unbanned {ip} after {duration} minutes")

        # Step 5 — Remove from our registry
        with self.lock:
            self.ban_registry.pop(ip, None)

    def get_registry(self):
        """
        Return a copy of the ban registry.
        Used by the dashboard to show ban expiry times.
        """
        with self.lock:
            return dict(self.ban_registry)
