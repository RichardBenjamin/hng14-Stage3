import threading
import time
import sys

from config import load_config
from monitor import TrafficMonitor, tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier
import dashboard

config = load_config()


def main():
    print("=" * 55)
    print("  HNG Anomaly Detection Engine starting up...")
    print("=" * 55)

    # ── Step 1: Create all components ─────────────────────
    # Each component is one object that lives for the entire
    # lifetime of the daemon. They are created once and reused.

    print("[MAIN] Creating components...")

    # Notifier first — others need it to send alerts
    notifier = Notifier()

    # Blocker — manages iptables rules
    blocker = Blocker()

    # Monitor — sliding windows and log parsing
    monitor = TrafficMonitor()

    # Baseline — learns normal traffic patterns
    baseline = BaselineTracker()

    # Detector — anomaly detection logic
    # Receives blocker and notifier so it can act on detections
    detector = AnomalyDetector()
    detector.blocker = blocker
    detector.notifier = notifier

    # Unbanner — watches ban expiry times
    # Receives blocker, detector, and notifier so it can
    # coordinate the full unban sequence
    unbanner = Unbanner(
        blocker=blocker,
        detector=detector,
        notifier=notifier
    )

    # Give detector a reference to unbanner
    # So it can register bans for automatic expiry
    detector.unbanner = unbanner

    # ── Step 2: Patch detector to register bans ───────────
    # We need detector._handle_anomaly to also call
    # unbanner.register_ban after issuing a ban.
    # We do this by wrapping the original method.

    original_handle = detector._handle_anomaly

    def patched_handle(ip, rate, baseline_mean, condition):
        # Call the original ban logic
        original_handle(ip, rate, baseline_mean, condition)

        # After the ban is issued, register it with the unbanner
        # so it knows when to release it
        with detector.lock:
            state = detector.ip_state[ip]
            offense_count = state["offense_count"]

        ban_schedule = config["bans"]["schedule_minutes"]
        if offense_count < len(ban_schedule):
            duration_minutes = ban_schedule[offense_count]
        else:
            duration_minutes = None  # permanent

        unbanner.register_ban(
            ip=ip,
            duration_minutes=duration_minutes,
            offense_count=offense_count
        )

    detector._handle_anomaly = patched_handle

    # ── Step 3: Initialise dashboard ──────────────────────
    dashboard.init(
        monitor=monitor,
        baseline=baseline,
        detector=detector,
        blocker=blocker,
        unbanner=unbanner
    )

    print("[MAIN] All components created and wired.")

    # ── Step 4: Start background threads ──────────────────
    # Each component that needs to run continuously
    # gets its own daemon thread.
    # daemon=True means the thread stops automatically
    # when the main process exits — no cleanup needed.

    print("[MAIN] Starting background threads...")

    # Thread 1 — Log tailer
    # Reads nginx log lines and feeds them through the pipeline
    log_thread = threading.Thread(
        target=tail_log,
        args=(monitor, baseline, detector),
        daemon=True,
        name="log-tailer"
    )
    log_thread.start()
    print("[MAIN] Log tailer thread started.")

    # Thread 2 — Unbanner loop
    # Checks every 10 seconds for expired bans
    unban_thread = threading.Thread(
        target=unbanner.run,
        daemon=True,
        name="unbanner"
    )
    unban_thread.start()
    print("[MAIN] Unbanner thread started.")

    # Thread 3 — Dashboard web server
    # Serves the live metrics page on port 8080
    dashboard_thread = threading.Thread(
        target=dashboard.run,
        daemon=True,
        name="dashboard"
    )
    dashboard_thread.start()
    print("[MAIN] Dashboard thread started.")

    print("=" * 55)
    print(f"  Dashboard: http://0.0.0.0:{config['dashboard']['port']}")
    print(f"  Tailing:   {config['logging']['nginx_log_path']}")
    print(f"  Audit log: {config['logging']['audit_log_path']}")
    print("=" * 55)

    # ── Step 5: Keep the main thread alive ────────────────
    # All the real work happens in the threads above.
    # The main thread just needs to stay alive so the
    # process does not exit and kill all the daemon threads.
    # We also use this loop to print a heartbeat every
    # 60 seconds so you can confirm the daemon is running.

    try:
        while True:
            time.sleep(60)
            global_rate = monitor.get_global_rate()
            mean, stddev = baseline.get()
            banned_count = len(detector.get_banned_ips())
            print(
                f"[HEARTBEAT] "
                f"global_rate={global_rate} req/s | "
                f"mean={mean:.2f} | "
                f"stddev={stddev:.2f} | "
                f"banned={banned_count}"
            )
    except KeyboardInterrupt:
        print("\n[MAIN] Shutting down...")
        sys.exit(0)


if __name__ == "__main__":
    main()
