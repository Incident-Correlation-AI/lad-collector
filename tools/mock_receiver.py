"""Local mock ingestion API used to verify collector delivery.

Run from the directory containing ``collectors``::

    python3 -m collectors.tools.mock_receiver
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

OUTPUT_FILE = Path(__file__).resolve().parents[1] / "var" / "received_events.jsonl"


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)

        try:
            payload = json.loads(body.decode("utf-8"))
            events = payload if isinstance(payload, list) else [payload]

            OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
            with OUTPUT_FILE.open("a", encoding="utf-8") as handle:
                for event in events:
                    handle.write(json.dumps(event, ensure_ascii=False) + "\n")

            categories = Counter(
                str(event.get("category", "unknown")) for event in events
            )

            print(
                f"[{datetime.now():%H:%M:%S}] "
                f"Received {len(events)} events | "
                f"Categories: {dict(categories)} | "
                f"Saved to {OUTPUT_FILE}",
                flush=True,
            )

            response = json.dumps({"accepted": True, "count": len(events)}).encode(
                "utf-8"
            )

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        except Exception as exc:
            print(f"Request processing failed: {exc}", flush=True)
            self.send_error(400, "Could not process request")

    def log_message(self, format, *args):
        pass


def main() -> None:
    server = HTTPServer(("127.0.0.1", 8080), Handler)
    print("Mock receiver listening on http://127.0.0.1:8080")
    print(f"Saving received events to {OUTPUT_FILE}")
    server.serve_forever()


if __name__ == "__main__":
    main()
