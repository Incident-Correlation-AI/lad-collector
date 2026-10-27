import json
import logging
import os
import random
import re
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)


# ==========================================
# 1. UNIVERSAL CONTRACT MODEL
# ==========================================
@dataclass
class Event:
    schema_version: str
    event_id: str
    event_ts: str  # ISO-8601 UTC string
    observed_ts: str  # ISO-8601 UTC string
    host: str
    source: str  # "journald", "windows-eventlog", "file-database-files", ...
    service: Optional[str]
    category: str  # "auth", "network", "syslog", "service", "system", "db"
    type: str  # "auth_failure", "firewall_event", "database_deadlock", ...
    severity: str  # "info", "warning", "error", "critical"
    message: str
    attributes: Dict[str, Any]
    template: Optional[str] = None
    trace_id: Optional[str] = None
    request_id: Optional[str] = None
    depends_on: tuple = ()


# ==========================================
# 2. REDACTION LOGIC (Security Requirement)
# ==========================================
class Redactor:
    """Scans messages and attributes and masks sensitive data.

    Redaction is applied by the readers *and* again immediately before the
    event enters the buffer (defense in depth).  Attribute values are redacted
    too: Windows event data can contain command lines, script blocks and
    password fields that never appear in the rendered message.
    """

    # Keep this list ordered: broad header patterns first, then key/value
    # patterns, then high-entropy token formats.
    _SECRET_KEYS = (
        r"password|passwd|passphrase|secret(?:[_-]?key)?|client[_-]?secret|"
        r"api[_-]?key|apikey|access[_-]?key(?:[_-]?id)?|secret[_-]?access[_-]?key|"
        r"auth[_-]?token|access[_-]?token|refresh[_-]?token|id[_-]?token|"
        r"session[_-]?id|sessionid|csrf(?:[_-]?token)?|credential|"
        r"private[_-]?key|token"
    )

    _PATTERNS = (
        # Authorization headers (Bearer/Basic/...).
        (
            re.compile(r"(?i)\b(authorization)\s*[:=]\s*[^\r\n,}]+"),
            r"\1: [REDACTED]",
        ),
        # Generic bearer tokens (also appear outside an Authorization header).
        (
            re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/]+=*"),
            r"\1 [REDACTED]",
        ),
        (re.compile(r"(?i)\b((?:set-)?cookie)\s*[:=]\s*[^\r\n]+"), r"\1: [REDACTED]"),
        # key=value / "key": "value" / key: value
        (
            re.compile(
                rf'(?i)(\b(?:{_SECRET_KEYS})\b)(["\']?\s*[:=]\s*)'
                r'(?:"[^"]*"|\'[^\']*\'|\[REDACTED[^\]]*\]|[^\s,;}\]]+)'
            ),
            r"\1\2[REDACTED]",
        ),
        # PEM private keys.
        (
            re.compile(
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.DOTALL,
            ),
            "[REDACTED_PRIVATE_KEY]",
        ),
        # JWTs.
        (
            re.compile(
                r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
            ),
            "[REDACTED_JWT]",
        ),
        # AWS access key IDs.
        (
            re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{12,20}\b"),
            "[REDACTED_AWS_KEY]",
        ),
        # Inline credentials in connection URIs.
        (
            re.compile(
                r"(?i)\b(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|"
                r"amqps?|mssql)://[^:\s/@]+:[^@\s/]+@"
            ),
            r"\1://[REDACTED]@",
        ),
        # Signed URL parameters.
        (
            re.compile(
                r"(?i)\b(x-amz-signature|x-amz-credential|x-amz-security-token)"
                r"\s*[:=]\s*\S+"
            ),
            r"\1=[REDACTED]",
        ),
    )

    def __init__(
        self,
        max_message_chars: Optional[int] = None,
        max_attribute_chars: Optional[int] = None,
    ):
        self.max_message_chars = max_message_chars or int(
            os.getenv("LAD_MAX_MESSAGE_CHARS", "8192")
        )
        self.max_attribute_chars = max_attribute_chars or int(
            os.getenv("LAD_MAX_ATTRIBUTE_CHARS", "4096")
        )

    @staticmethod
    def _truncate(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[:limit] + "…[TRUNCATED]"

    def redact(self, text: str) -> str:
        if not isinstance(text, str):
            text = str(text)
        for pattern, replacement in self._PATTERNS:
            text = pattern.sub(replacement, text)
        return text

    def redact_structure(self, value: Any, _depth: int = 0) -> Any:
        """Recursively redact strings inside dict/list attributes."""
        if _depth > 8:
            return "[TRUNCATED_NESTING]"
        if value is None or isinstance(value, (bool, int, float)):
            return value
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        if isinstance(value, str):
            return self.redact(self._truncate(value, self.max_attribute_chars))
        if isinstance(value, dict):
            return {
                str(key): self.redact_structure(item, _depth + 1)
                for key, item in value.items()
            }
        if isinstance(value, (list, tuple, set)):
            return [self.redact_structure(item, _depth + 1) for item in value]
        return self.redact(self._truncate(str(value), self.max_attribute_chars))

    def redact_event(self, event: Event) -> Event:
        """Final safety net applied immediately before buffering."""
        event.message = self.redact(
            self._truncate(event.message or "", self.max_message_chars)
        )
        if event.template:
            event.template = self.redact(
                self._truncate(event.template, self.max_message_chars)
            )
        event.attributes = self.redact_structure(event.attributes)
        return event


# ==========================================
# 3. BOUNDED BUFFER (Memory Safety)
# ==========================================
class BoundedBuffer:
    """Thread-safe bounded queue.

    If the network is down and the buffer is full, the *oldest* events are
    dropped.  Delegated retries use :meth:`requeue`, which preserves the
    failed batch and drops from the opposite end instead, so a transient
    outage does not immediately discard the data being retried.
    """

    def __init__(self, max_capacity: int = 1000):
        self.max_capacity = max_capacity
        self._buffer: deque[Event] = deque()
        self._lock = threading.Lock()
        self.dropped_total: int = 0

    def add(self, event: Event) -> None:
        with self._lock:
            if len(self._buffer) >= self.max_capacity:
                self._buffer.popleft()
                self.dropped_total += 1
                if self.dropped_total % 50 == 1:
                    logging.warning(
                        "Buffer full! Total dropped events: %d", self.dropped_total
                    )
            self._buffer.append(event)

    def drain(self, max_batch: int = 100) -> List[Event]:
        with self._lock:
            count = min(max_batch, len(self._buffer))
            return [self._buffer.popleft() for _ in range(count)]

    def requeue(self, events: List[Event]) -> None:
        """Put a failed batch back at the front, preserving the oldest data."""
        if not events:
            return
        with self._lock:
            for event in reversed(events):
                self._buffer.appendleft(event)
            while len(self._buffer) > self.max_capacity:
                self._buffer.pop()  # drop the newest, keep the retry batch
                self.dropped_total += 1
        logging.warning(
            "Requeued %d events after send failure (buffer=%d, dropped_total=%d)",
            len(events),
            len(self),
            self.dropped_total,
        )

    def __len__(self) -> int:
        with self._lock:
            return len(self._buffer)


# ==========================================
# 4. HTTP SENDER (Batching + Retry + Auth)
# ==========================================
class BatchSender:
    def __init__(
        self,
        endpoint: str,
        auth_token: Optional[str] = None,
        *,
        timeout: float = 10.0,
        max_retries: int = 3,
        max_batch_bytes: int = 262144,
        base_backoff_s: float = 0.5,
        debug_payload: Optional[bool] = None,
    ):
        self.endpoint = endpoint
        self.auth_token = auth_token or ""
        self.timeout = timeout
        self.max_retries = max(1, max_retries)
        self.max_batch_bytes = max_batch_bytes
        self.base_backoff_s = base_backoff_s
        if debug_payload is None:
            debug_payload = os.getenv("LAD_DEBUG_PAYLOAD", "").strip().lower() in (
                "1",
                "true",
                "yes",
                "on",
            )
        self.debug_payload = debug_payload
        self.last_failure_retryable = True
        # Outcome of the most recent ``send_batch`` call.  A batch can be
        # split into several size-limited chunks, so some chunks may be
        # delivered while others fail; the flusher needs the exact split to
        # avoid dropping retryable data (or duplicating delivered data).
        self.undelivered_events: List[Event] = []
        self.dropped_events = 0
        self.sent_events = 0

    def _serialize(self, events: List[Event]) -> bytes:
        return json.dumps(
            {"events": [asdict(event) for event in events]},
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")

    def _chunks(self, events: List[Event]) -> List[List[Event]]:
        """Split into batches under the 256 KB contract limit."""
        chunks: List[List[Event]] = []
        current: List[Event] = []
        envelope_overhead = len(b'{"events":[]}')
        current_size = envelope_overhead

        for event in events:
            single_payload = json.dumps(
                asdict(event), separators=(",", ":"), default=str
            ).encode("utf-8")
            event_size = len(single_payload)
            if current and current_size + event_size + 1 > self.max_batch_bytes:
                chunks.append(current)
                current = []
                current_size = envelope_overhead
            if event_size + envelope_overhead > self.max_batch_bytes:
                logging.warning(
                    "Single event %s is larger than the batch limit (%d bytes); "
                    "sending it alone.",
                    event.event_id,
                    event_size,
                )
            current.append(event)
            current_size += event_size + 1

        if current:
            chunks.append(current)
        return chunks

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "LAD-Collector/1.1",
        }
        if self.auth_token:
            headers["Authorization"] = f"Bearer {self.auth_token}"
        return headers

    def _send_once(self, events: List[Event]) -> tuple[bool, bool]:
        """Return ``(success, retryable)``."""
        payload = self._serialize(events)
        if self.debug_payload:
            logging.info("Outbound payload: %s", payload.decode("utf-8", "replace"))

        request = urllib.request.Request(
            self.endpoint,
            data=payload,
            headers=self._headers(),
            method="POST",
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                status = response.status
                if 200 <= status < 300:
                    logging.info(
                        "Shipped %d events (%d bytes) with status %d.",
                        len(events),
                        len(payload),
                        status,
                    )
                    return True, False
                logging.error("Server returned unexpected status %d.", status)
                return False, status >= 500 or status in (408, 429)
        except urllib.error.HTTPError as exc:
            # 4xx means the payload/auth is wrong; retrying will not help.
            non_retryable = exc.code in (400, 401, 403, 404, 413, 422)
            logging.exception("HTTP %s: %s", exc.code, exc.reason)
            return False, not non_retryable
        except urllib.error.URLError as exc:
            logging.exception("Network error (API unreachable): %s", exc.reason)
            return False, True
        except (TimeoutError, OSError) as exc:
            logging.exception("Network timeout/error while sending: %s", exc)
            return False, True

    def send_batch(self, events: List[Event]) -> bool:
        """Send every event, retrying retryable failures with jittered backoff.

        Events are split into chunks so a large batch stays under the size
        limit.  Chunks are independent: a non-retryable failure in one chunk
        must not cause the flusher to discard the other chunks.  The outcome
        is exposed through ``undelivered_events`` (retryable failures),
        ``dropped_events`` (non-retryable failures) and ``sent_events``.
        """
        self.undelivered_events = []
        self.dropped_events = 0
        self.sent_events = 0
        if not events:
            self.last_failure_retryable = True
            return True

        all_ok = True
        for chunk in self._chunks(events):
            sent = False
            retryable_failure = False
            for attempt in range(1, self.max_retries + 1):
                success, retryable = self._send_once(chunk)
                if success:
                    sent = True
                    break
                if not retryable:
                    retryable_failure = False
                    break
                retryable_failure = True
                if attempt < self.max_retries:
                    delay = self.base_backoff_s * (2 ** (attempt - 1))
                    delay += random.uniform(0, self.base_backoff_s)
                    logging.info(
                        "Retrying batch of %d events in %.2fs (attempt %d/%d).",
                        len(chunk),
                        delay,
                        attempt + 1,
                        self.max_retries,
                    )
                    time.sleep(delay)

            if sent:
                self.sent_events += len(chunk)
                continue

            all_ok = False
            if retryable_failure:
                self.undelivered_events.extend(chunk)
                logging.error(
                    "Batch of %d events was not delivered; it will be retried.",
                    len(chunk),
                )
            else:
                self.dropped_events += len(chunk)
                logging.error(
                    "Dropping %d events after a non-retryable ingestion error.",
                    len(chunk),
                )

        # The flusher requeues ``undelivered_events`` only.  This flag is kept
        # for callers that only inspect the boolean result.
        self.last_failure_retryable = bool(self.undelivered_events)
        return all_ok


# ==========================================
# 5. BACKGROUND FLUSHER
# ==========================================
class Flusher(threading.Thread):
    """Flush by size *or* by time.

    The original loop only checked the flush conditions when a new event
    arrived, so the last events of a burst could sit in memory forever.
    """

    def __init__(
        self,
        buffer: BoundedBuffer,
        sender: BatchSender,
        *,
        batch_size: int = 100,
        interval_s: float = 3.0,
    ):
        super().__init__(name="lad-flusher", daemon=True)
        self._buffer = buffer
        self._sender = sender
        self._batch_size = batch_size
        self._interval_s = interval_s
        self._stop = threading.Event()
        self._flush_lock = threading.Lock()
        self._last_flush = time.monotonic()
        self.sent_total = 0
        self.failed_batches = 0
        self.dropped_non_retryable = 0

    def run(self) -> None:
        while not self._stop.wait(0.25):
            self.flush_if_due()

    def flush_if_due(self) -> None:
        due_by_size = len(self._buffer) >= self._batch_size
        due_by_time = (time.monotonic() - self._last_flush) >= self._interval_s
        if due_by_size or (due_by_time and len(self._buffer) > 0):
            self.flush()

    def flush(self) -> bool:
        with self._flush_lock:
            batch = self._buffer.drain(self._batch_size)
            self._last_flush = time.monotonic()
            if not batch:
                return True

            logging.info(
                "Flushing batch of %d events (buffer remaining: %d).",
                len(batch),
                len(self._buffer),
            )
            if self._sender.send_batch(batch):
                self.sent_total += len(batch)
                return True

            self.failed_batches += 1
            self.sent_total += getattr(self._sender, "sent_events", 0)
            dropped = getattr(self._sender, "dropped_events", 0)
            if dropped:
                self.dropped_non_retryable += dropped
                logging.error(
                    "Dropped %d events after a non-retryable ingestion error.",
                    dropped,
                )

            # Only requeue chunks that failed for a retryable reason.  A
            # non-retryable chunk (bad schema/auth) is dropped and counted,
            # while transient failures elsewhere in the same batch survive.
            undelivered = getattr(self._sender, "undelivered_events", None)
            if undelivered is None:
                undelivered = (
                    batch
                    if getattr(self._sender, "last_failure_retryable", True)
                    else []
                )
            if undelivered:
                self._buffer.requeue(undelivered)
            return False

    def stop(self) -> bool:
        self._stop.set()
        self.join(timeout=(self._sender.timeout * self._sender.max_retries) + 5)
        # Final drain, including events that arrived while shutting down.
        ok = True
        while len(self._buffer) > 0:
            if not self.flush():
                ok = False
                break
        return ok
