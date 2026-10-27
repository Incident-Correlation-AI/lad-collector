#!/usr/bin/env python3
"""Attack and Anomaly Simulation Tool for LAD.

Generates realistic attack scenarios (HTTP 500 error spikes, SSH brute force bursts,
database query timeouts) matching the canonical LAD event envelope (v1.0), and
transmits them to the configured ingestion API endpoint.

Usage:
    python tools/simulate_attack.py --scenario http_5xx
    python tools/simulate_attack.py --scenario auth_burst
    python tools/simulate_attack.py --scenario db_timeout
    python tools/simulate_attack.py --endpoint https://d6l60no0kk.execute-api.eu-north-1.amazonaws.com/api/v1/events/batch --token <TOKEN>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
import uuid

DEFAULT_ENDPOINT = os.getenv(
    "LAD_COLLECTOR_ENDPOINT",
    "https://d6l60no0kk.execute-api.eu-north-1.amazonaws.com/api/v1/events/batch",
)
DEFAULT_TOKEN = os.getenv("LAD_COLLECTOR_TOKEN", "")


def generate_http_5xx_events(
    count: int = 25, host: str = "web-srv-prod-01"
) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    events = []
    for i in range(count):
        events.append(
            {
                "schema_version": "1.0",
                "event_id": f"atk-http5xx-{uuid.uuid4().hex[:12]}",
                "event_ts": now,
                "observed_ts": now,
                "host": host,
                "source": "journald",
                "service": "web-api",
                "category": "http",
                "type": "http_5xx",
                "severity": "error",
                "message": "HTTP/1.1 500 Internal Server Error POST /api/checkout upstream timeout",
                "attributes": {
                    "status_code": 500,
                    "latency_ms": 2450.0 + (i * 15.0),
                    "client_ip": f"192.168.1.{100 + (i % 10)}",
                    "request_path": "/api/checkout",
                },
            }
        )
    return events


def generate_auth_burst_events(
    count: int = 15, host: str = "auth-srv-01"
) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    events = []
    for i in range(count):
        events.append(
            {
                "schema_version": "1.0",
                "event_id": f"atk-authburst-{uuid.uuid4().hex[:12]}",
                "event_ts": now,
                "observed_ts": now,
                "host": host,
                "source": "journald",
                "service": "sshd",
                "category": "auth",
                "type": "auth_failure",
                "severity": "warning",
                "message": f"Failed password for invalid user admin from 10.0.4.{i + 1} port {40000 + i} ssh2",
                "attributes": {
                    "user": "admin",
                    "source_ip": f"10.0.4.{i + 1}",
                    "auth_method": "password",
                },
            }
        )
    return events


def generate_db_timeout_events(
    count: int = 12, host: str = "db-primary-01"
) -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    events = []
    for i in range(count):
        events.append(
            {
                "schema_version": "1.0",
                "event_id": f"atk-dbtimeout-{uuid.uuid4().hex[:12]}",
                "event_ts": now,
                "observed_ts": now,
                "host": host,
                "source": "file-database-files",
                "service": "postgres",
                "category": "db",
                "type": "database_timeout",
                "severity": "error",
                "message": "canceling statement due to statement timeout",
                "attributes": {
                    "duration_ms": 30000.0,
                    "query": "SELECT * FROM orders FOR UPDATE",
                },
            }
        )
    return events


def send_batch(endpoint: str, token: str, events: list[dict]) -> dict:
    payload = json.dumps({"events": events}).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(payload)),
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(endpoint, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8")
        print(f"HTTP Error {exc.code}: {err_body}", file=sys.stderr)
        raise
    except Exception as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=["http_5xx", "auth_burst", "db_timeout"],
        default="http_5xx",
        help="Anomaly scenario to simulate",
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help="LAD Ingestion API URL",
    )
    parser.add_argument(
        "--token",
        default=DEFAULT_TOKEN,
        help="Collector Bearer token",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=25,
        help="Number of events in the burst",
    )
    args = parser.parse_args()

    token = args.token
    if not token and os.path.exists(os.path.expanduser("~/.config/lad/dev-tokens")):
        with open(os.path.expanduser("~/.config/lad/dev-tokens")) as f:
            for line in f:
                if line.startswith("COLLECTOR_TOKEN="):
                    token = line.strip().split("=", 1)[1]
                    break

    print(f"Generating {args.count} events for scenario '{args.scenario}'...")
    if args.scenario == "http_5xx":
        events = generate_http_5xx_events(count=args.count)
    elif args.scenario == "auth_burst":
        events = generate_auth_burst_events(count=args.count)
    else:
        events = generate_db_timeout_events(count=args.count)

    print(f"Sending batch to {args.endpoint}...")
    result = send_batch(args.endpoint, token, events)
    print("Response:")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
