import subprocess
import threading
import time

from config import load_config
from audit import write_audit

config = load_config()


class Blocker:
    def __init__(self):
        # Track which IPs have active iptables rules
        # Key: IP address, Value: time the ban was added
        self.active_bans = {}
        self.lock = threading.Lock()

    def ban(self, ip, duration_minutes=None):
        """
        Add an iptables DROP rule for this IP.
        If duration_minutes is provided, schedule an automatic unban.
        If duration_minutes is None, the ban is permanent.

        Uses subprocess to run the iptables command directly
        on the host — this works because the detector container
        runs with network_mode: host and NET_ADMIN capability.
        """
        with self.lock:
            # Do not add a duplicate rule if already banned
            if ip in self.active_bans:
                return

            self.active_bans[ip] = time.time()

        try:
            # Insert DROP rule at the top of the INPUT chain
            # -I INPUT puts it first so it is checked before anything else
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            print(f"[BLOCKER] Banned {ip} "
                  f"({'permanent' if duration_minutes is None else str(duration_minutes) + 'min'})")

        except subprocess.CalledProcessError as e:
            # iptables command failed — log it but do not crash
            print(f"[BLOCKER] Failed to ban {ip}: {e.stderr.decode()}")
            with self.lock:
                self.active_bans.pop(ip, None)

    def unban(self, ip):
        """
        Remove the iptables DROP rule for this IP.
        Called by unbanner.py when a ban duration expires.
        """
        with self.lock:
            if ip not in self.active_bans:
                # No active ban for this IP — nothing to remove
                return
            self.active_bans.pop(ip)

        try:
            # Delete the DROP rule — same parameters as the ban
            # but -D instead of -I
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True
            )
            print(f"[BLOCKER] Unbanned {ip}")

        except subprocess.CalledProcessError as e:
            print(f"[BLOCKER] Failed to unban {ip}: {e.stderr.decode()}")

    def is_banned(self, ip):
        """
        Check if an IP currently has an active ban.
        Used by unbanner.py to verify before attempting removal.
        """
        with self.lock:
            return ip in self.active_bans

    def get_active_bans(self):
        """
        Return a copy of the active bans dictionary.
        Used by the dashboard to display current bans.
        """
        with self.lock:
            return dict(self.active_bans)
