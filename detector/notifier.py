import requests
import time
import threading

from config import load_config

config = load_config()

WEBHOOK_URL = config["slack"]["webhook_url"]


class Notifier:
    def __init__(self):
        # Lock to prevent multiple threads sending simultaneously
        # and potentially hitting Slack rate limits
        self.lock = threading.Lock()

    def _send(self, message):
        """
        Internal method that actually sends the POST request to Slack.
        All public methods call this.

        Runs in a separate thread so it never blocks the main
        detection loop — a slow Slack API response should not
        delay processing the next log line.
        """
        def _post():
            try:
                response = requests.post(
                    WEBHOOK_URL,
                    json={"text": message},
                    timeout=5
                )
                if response.status_code != 200:
                    print(f"[NOTIFIER] Slack returned {response.status_code}: "
                          f"{response.text}")
            except requests.RequestException as e:
                # Network error — log it but do not crash the daemon
                print(f"[NOTIFIER] Failed to send Slack alert: {e}")

        # Fire the POST request in a background thread
        thread = threading.Thread(target=_post, daemon=True)
        thread.start()

    def send_ban_alert(self, ip, condition, rate, baseline, duration):
        """
        Send a Slack alert when an IP is banned.

        Parameters:
            ip        - the IP address that was banned
            condition - what triggered the ban (z-score or rate multiplier)
            rate      - the current request rate that triggered it
            baseline  - the baseline mean at the time
            duration  - how long the ban lasts
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        message = (
            f"🚨 *IP BANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Current rate:* {rate} req/s\n"
            f"*Baseline mean:* {baseline:.2f} req/s\n"
            f"*Time:* {timestamp}\n"
            f"*Ban duration:* {duration}"
        )

        print(f"[NOTIFIER] Sending ban alert for {ip}")
        self._send(message)

    def send_unban_alert(self, ip, duration, offense_count, next_duration):
        """
        Send a Slack alert when a ban expires and an IP is released.

        Parameters:
            ip            - the IP address being unbanned
            duration      - how long the ban lasted
            offense_count - how many times this IP has been banned
            next_duration - what the next ban duration will be if it reoffends
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        message = (
            f"✅ *IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Ban duration served:* {duration}\n"
            f"*Total offenses:* {offense_count}\n"
            f"*Time:* {timestamp}\n"
            f"*Next ban if reoffends:* {next_duration}"
        )

        print(f"[NOTIFIER] Sending unban alert for {ip}")
        self._send(message)

    def send_global_alert(self, condition, rate, baseline):
        """
        Send a Slack alert when global traffic spikes.
        No IP-level block is possible for global anomalies —
        this is purely informational so the team can respond manually.

        Parameters:
            condition - what triggered the alert
            rate      - the current global request rate
            baseline  - the baseline mean at the time
        """
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        message = (
            f"⚠️ *GLOBAL TRAFFIC SPIKE*\n"
            f"*Condition:* {condition}\n"
            f"*Current global rate:* {rate} req/s\n"
            f"*Baseline mean:* {baseline:.2f} req/s\n"
            f"*Time:* {timestamp}\n"
            f"*Action:* Monitor only — no IP-level block possible"
        )

        print(f"[NOTIFIER] Sending global alert")
        self._send(message)
