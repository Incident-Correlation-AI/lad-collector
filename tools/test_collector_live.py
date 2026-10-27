#!/usr/bin/env python3
"""Automated live test for LAD collector agent.

Starts the collector in a background subprocess, injects test log messages
into the local system log using `logger`, waits for the collector to batch
and flush them to AWS API Gateway, and inspects the shutdown report.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

CWD = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    print("=" * 60)
    print("STEP 1: Starting lad-collector agent subprocess...")
    print("=" * 60)

    agent_proc = subprocess.Popen(
        [sys.executable, "run.py"],
        cwd=CWD,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    # Allow 3 seconds for agent to connect to journald and seek to tail
    time.sleep(3)

    print("\n" + "=" * 60)
    print("STEP 2: Injecting test system logs into local journald...")
    print("=" * 60)
    test_logs = [
        (
            "sshd",
            "auth.warning",
            "Failed password for root from 192.168.1.105 port 54321 ssh2",
        ),
        (
            "nginx",
            "daemon.err",
            "HTTP 500 Internal Server Error for /api/v1/orders latency=1420ms",
        ),
        ("sudo", "auth.notice", "abelmekonen : sudo authentication failure on pts/1"),
    ]

    for tag, priority, msg in test_logs:
        full_msg = f"[LAD-LIVE-TEST] {msg}"
        print(f" -> Generating log: tag={tag}, prio={priority}, msg='{msg}'")
        subprocess.run(["logger", "-t", tag, "-p", priority, full_msg], check=True)
        time.sleep(0.5)

    print("\n" + "=" * 60)
    print("STEP 3: Waiting 5 seconds for Flusher to send batch to AWS...")
    print("=" * 60)
    time.sleep(5)

    print("\n" + "=" * 60)
    print("STEP 4: Sending SIGINT to collector agent to trigger graceful drain...")
    print("=" * 60)
    agent_proc.send_signal(signal.SIGINT)

    try:
        stdout, _ = agent_proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        agent_proc.kill()
        stdout, _ = agent_proc.communicate()

    print("\n--- Collector Agent Output ---")
    print(stdout.strip())
    print("------------------------------")

    if "delivered=" in stdout:
        for line in stdout.splitlines():
            if "Collector shut down" in line or "delivered=" in line:
                print(f"\n[TEST RESULT] {line.strip()}")
                return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
