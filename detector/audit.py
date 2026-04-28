import os
import time
import threading

from config import load_config

config = load_config()

# Path where audit log is written — from config.yaml
AUDIT_LOG_PATH = config["logging"]["audit_log_path"]

# Lock to prevent two threads writing simultaneously
# which would corrupt log lines by interleaving them
_write_lock = threading.Lock()


def write_audit(action, ip, condition, rate, baseline, duration):
    """
    Write one structured line to the audit log.

    Called by:
        - detector.py  when a ban is issued
        - unbanner.py  when a ban expires
        - baseline.py  when baseline is recalculated

    Parameters:
        action    - BAN, UNBAN, or BASELINE_RECALC
        ip        - the IP address involved ("-" for baseline events)
        condition - what triggered the event
        rate      - the request rate at the time of the event
        baseline  - the baseline mean at the time of the event
        duration  - how long the ban lasts ("-" for baseline events)

    Output format:
        [2024-11-14T15:04:05] BAN 41.58.2.1 | z-score=14.3 | rate=187.00 | baseline=12.10 | duration=10min
    """

    # Create the log directory if it does not exist yet
    # This handles the case where the container just started
    # and the directory has not been created yet
    os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)

    # Format the timestamp in ISO 8601 format
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")

    # Build the log line following the required format exactly
    line = (
        f"[{timestamp}] {action} {ip} | "
        f"{condition} | "
        f"rate={rate:.2f} | "
        f"baseline={baseline:.2f} | "
        f"duration={duration}\n"
    )

    # Write to file with lock held
    # The lock prevents two threads writing at the same time
    # which would produce garbled lines in the log
    with _write_lock:
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(line)

    # Also print to stdout so you can see events in the
    # docker logs output when monitoring the daemon live
    print(f"[AUDIT] {line.strip()}")
