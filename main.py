# main.py
"""LAD collector entry point.

Starts every enabled Linux or Windows source concurrently, classifies and
redacts events, buffers them, and ships them to the ingestion API with
size- and time-based flushing, retries and bounded memory.
"""

import logging
import os
import signal
import sys

from . import StreamMerger, get_stream_factories
from .core.engine import BatchSender, BoundedBuffer, Flusher, Redactor

DEFAULT_AWS_ENDPOINT = (
    "https://d6l60no0kk.execute-api.eu-north-1.amazonaws.com/api/v1/events/batch"
)


def _resolve_collector_token() -> str:
    token = os.getenv("LAD_COLLECTOR_TOKEN", "")
    if token and token != "dev-secret-token":
        return token
    tokens_file = os.path.expanduser("~/.config/lad/dev-tokens")
    if os.path.exists(tokens_file):
        try:
            with open(tokens_file, "r") as f:
                for line in f:
                    if line.startswith("COLLECTOR_TOKEN="):
                        return line.strip().split("=", 1)[1]
        except Exception:
            pass
    return token or "dev-secret-token"


# Configurable settings (override with environment variables).
API_ENDPOINT = os.getenv("LAD_COLLECTOR_ENDPOINT", DEFAULT_AWS_ENDPOINT)
AUTH_TOKEN = _resolve_collector_token()
FLUSH_INTERVAL_SECONDS = float(os.getenv("LAD_FLUSH_INTERVAL_SECONDS", "3"))
BATCH_MAX_SIZE = int(os.getenv("LAD_MAX_BATCH_EVENTS", "100"))
BUFFER_MAX_EVENTS = int(os.getenv("LAD_BUFFER_MAX_EVENTS", "2000"))
MAX_BATCH_BYTES = int(os.getenv("LAD_MAX_BATCH_BYTES", "262144"))
SEND_TIMEOUT_SECONDS = float(os.getenv("LAD_SEND_TIMEOUT_SECONDS", "10"))
SEND_RETRIES = int(os.getenv("LAD_SEND_RETRIES", "3"))


def _raise_keyboard_interrupt(signum, _frame):
    raise KeyboardInterrupt(f"signal {signum}")


def main() -> int:
    logging.info("Initializing Automated Log Anomaly Detector Collector Agent...")

    redactor = Redactor()
    buffer = BoundedBuffer(max_capacity=BUFFER_MAX_EVENTS)
    sender = BatchSender(
        endpoint=API_ENDPOINT,
        auth_token=AUTH_TOKEN,
        timeout=SEND_TIMEOUT_SECONDS,
        max_retries=SEND_RETRIES,
        max_batch_bytes=MAX_BATCH_BYTES,
    )
    flusher = Flusher(
        buffer,
        sender,
        batch_size=BATCH_MAX_SIZE,
        interval_s=FLUSH_INTERVAL_SECONDS,
    )

    if not AUTH_TOKEN:
        logging.warning(
            "LAD_COLLECTOR_TOKEN is empty; the ingestion API will likely "
            "reject submitted events."
        )

    try:
        sources = get_stream_factories(redactor)
    except Exception as exc:
        logging.critical("Failed to initialize collectors: %s", exc)
        return 1

    if not sources:
        logging.critical("No log sources are enabled; nothing to collect.")
        return 1

    merger = StreamMerger(sources)
    logging.info("Enabled sources: %s", ", ".join(merger.source_names))
    logging.info(
        "Batch limits: %d events / %d bytes; flush interval %.1fs; buffer %d events.",
        BATCH_MAX_SIZE,
        MAX_BATCH_BYTES,
        FLUSH_INTERVAL_SECONDS,
        BUFFER_MAX_EVENTS,
    )

    # Graceful shutdown for both Ctrl+C and service managers.
    signal.signal(signal.SIGINT, _raise_keyboard_interrupt)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _raise_keyboard_interrupt)

    flusher.start()
    merger.start()
    logging.info("Collector successfully running and listening for events...")

    try:
        for event in merger:
            # Defense in depth: readers already redacted the message and
            # attributes, but every event passes through the redactor again.
            buffer.add(redactor.redact_event(event))
    except KeyboardInterrupt:
        logging.info("Shutdown signal received. Draining remaining logs...")
    finally:
        merger.close()
        delivered = flusher.stop()
        logging.info(
            "Collector shut down. delivered=%d dropped=%d non_retryable=%d "
            "failed_batches=%d final_flush_ok=%s",
            flusher.sent_total,
            buffer.dropped_total,
            flusher.dropped_non_retryable,
            flusher.failed_batches,
            delivered,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
