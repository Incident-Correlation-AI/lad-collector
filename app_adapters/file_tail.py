"""Rotation-aware file tailing shared by the Linux and Windows collectors.

Used for sources that are not reliably available through the native event
APIs: database server logs, syslog files and the auth/network fallbacks.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Optional

from ..core import classifier
from ..core.config import FileSourceSpec, expand_patterns
from ..core.engine import Event, Redactor


_ISO_TIMESTAMP = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[ T]"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:[.,](?P<fraction>\d{1,9}))?"
    r"\s*(?P<tz>Z|UTC|GMT|[+-]\d{2}:?\d{2}|[+-]\d{2})?"
)

# Classic RFC 3164 syslog prefix: "Oct 20 12:34:56" (year omitted).
_RFC3164_TIMESTAMP = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:[.,](?P<fraction>\d{1,6}))?"
)

# auditd records carry a Unix epoch in "msg=audit(1729425296.123:456)".
_AUDIT_EPOCH = re.compile(
    r"\bmsg=audit\((?P<seconds>\d{9,})(?:\.(?P<fraction>\d+))?:\d+\)"
)

_SEVERITY_LETTERS = {
    "F": "critical",
    "E": "error",
    "W": "warning",
    "I": "info",
    "D": "info",
    "T": "info",
}


def _local_timezone():
    # The collector host's local timezone; file logs usually omit an offset.
    # LAD_LOG_TIMEZONE=UTC (or an IANA name) overrides the host timezone.
    override = os.getenv("LAD_LOG_TIMEZONE", "").strip()
    if override:
        try:
            from zoneinfo import ZoneInfo

            return ZoneInfo(override)
        except Exception:
            pass
    return datetime.now().astimezone().tzinfo


def parse_log_timestamp(line: str) -> Optional[str]:
    """Parse a leading ISO-ish timestamp from a log line.

    Supports PostgreSQL/MySQL/SQL Server styles such as::

        2026-10-20 12:34:56.123 UTC [123] ...
        2026-10-20T12:34:56.123456Z 0 [Warning] ...

    Also supports classic syslog prefixes (``Oct 20 12:34:56``) and the
    auditd epoch form (``msg=audit(1729425296.123:456)``).

    Returns an ISO-8601 UTC string, or ``None`` when no timestamp is present.
    """
    match = _ISO_TIMESTAMP.match(line)
    if not match:
        audit_time = _parse_audit_epoch(line)
        if audit_time is not None:
            return audit_time
        return _parse_rfc3164_timestamp(line)

    fraction = (match.group("fraction") or "")[:6]
    suffix = f".{fraction}" if fraction else ""
    tz_text = match.group("tz")
    if tz_text in ("Z", "UTC", "GMT"):
        tz_text = "+00:00"
    elif tz_text and re.fullmatch(r"[+-]\d{2}", tz_text):
        tz_text = f"{tz_text}:00"
    elif tz_text and re.fullmatch(r"[+-]\d{4}", tz_text):
        tz_text = f"{tz_text[:3]}:{tz_text[3:]}"
    if not tz_text:
        tz_text = ""

    try:
        parsed = datetime.fromisoformat(
            f"{match.group('date')}T{match.group('time')}{suffix}{tz_text}"
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_local_timezone())
    return parsed.astimezone(timezone.utc).isoformat()


_MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def _parse_rfc3164_timestamp(line: str) -> Optional[str]:
    match = _RFC3164_TIMESTAMP.match(line)
    if not match:
        return None

    tzinfo = _local_timezone()
    now = datetime.now(tzinfo)
    fraction = (match.group("fraction") or "")[:6].ljust(6, "0")
    try:
        parsed = datetime(
            year=now.year,
            month=_MONTHS[match.group("month")],
            day=int(match.group("day")),
            hour=int(match.group("hour")),
            minute=int(match.group("minute")),
            second=int(match.group("second")),
            microsecond=int(fraction or "0"),
            tzinfo=tzinfo,
        )
    except (KeyError, ValueError):
        return None

    # Syslog omits the year.  A timestamp far in the future means the line is
    # from December and the collector is reading it just after New Year.
    if parsed - now > timedelta(days=1):
        try:
            parsed = parsed.replace(year=now.year - 1)
        except ValueError:
            return None
    return parsed.astimezone(timezone.utc).isoformat()


def _parse_audit_epoch(line: str) -> Optional[str]:
    match = _AUDIT_EPOCH.search(line)
    if not match:
        return None

    fraction = (match.group("fraction") or "")[:6].ljust(6, "0")
    try:
        parsed = datetime.fromtimestamp(int(match.group("seconds")), tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return parsed.replace(microsecond=int(fraction or "0")).isoformat()


def _parse_json_line(line: str) -> Optional[dict[str, Any]]:
    """Best-effort JSON log line (MongoDB and JSON-structured app logs)."""
    stripped = line.lstrip()
    if not stripped.startswith("{"):
        return None
    try:
        payload = json.loads(stripped)
    except (ValueError, TypeError):
        return None
    if not isinstance(payload, dict):
        return None

    timestamp = None
    raw_time = payload.get("t") or payload.get("timestamp") or payload.get("time")
    if isinstance(raw_time, dict):
        raw_time = raw_time.get("$date")
    if isinstance(raw_time, str):
        timestamp = parse_log_timestamp(raw_time)

    message = (
        payload.get("msg") or payload.get("message") or payload.get("short_message")
    )
    severity = None
    letter = (
        payload.get("s")
        or payload.get("error_severity")
        or payload.get("severity")
        or payload.get("level")
        or payload.get("lvl")
    )
    if isinstance(letter, str):
        normalized = letter.strip().lower()
        if (
            normalized[:1] in ("f", "e", "w", "i", "d", "t")
            and normalized[:1].upper() in _SEVERITY_LETTERS
        ):
            severity = _SEVERITY_LETTERS[normalized[:1].upper()]
        elif normalized in classifier.SEVERITY_RANK:
            severity = normalized

    return {
        "timestamp": timestamp,
        "message": str(message) if message is not None else None,
        "severity": severity,
        "payload": payload,
    }


def _infer_service(path: str, fallback: str) -> str:
    lowered = path.lower()
    for token in (
        "postgres",
        "mysql",
        "mariadb",
        "mongodb",
        "redis",
        "mssql",
        "cassandra",
        "elasticsearch",
        "clickhouse",
        "pgbouncer",
        "audit",
        "auth",
        "secure",
        "syslog",
        "messages",
    ):
        if token in lowered:
            return token
    return fallback


@dataclass
class _FileState:
    inode: int
    offset: int
    line_number: int = 0


class FileTailStream:
    """Tail one or more files matching the configured globs.

    Rotation is handled by comparing inode and size: a replaced or truncated
    file is reopened from the beginning.  New files created after startup are
    read from the beginning; files that already existed are read from the end
    unless ``LAD_FILE_TAIL_FROM_START=1``.
    """

    def __init__(
        self,
        spec: FileSourceSpec,
        redactor: Redactor,
        *,
        hostname: str,
        poll_interval: float = 1.0,
        rescan_interval: float = 30.0,
        from_start: Optional[bool] = None,
        max_line_chars: int = 65536,
    ):
        self.spec = spec
        self.redactor = redactor
        self.hostname = hostname
        self.poll_interval = poll_interval
        self.rescan_interval = rescan_interval
        self.max_line_chars = max_line_chars
        if from_start is None:
            from_start = os.getenv("LAD_FILE_TAIL_FROM_START", "").strip().lower() in (
                "1",
                "true",
                "yes",
                "on",
            )
        self.from_start = from_start

        self._patterns = expand_patterns(spec.patterns)
        self._files: list[str] = []
        self._states: dict[str, _FileState] = {}
        self._initial_paths: set[str] = set()
        self._initialized = False
        self._last_scan = 0.0
        self._warned_errors: set[tuple[str, str]] = set()

    # -- discovery ---------------------------------------------------------
    def _scan(self) -> None:
        found: list[str] = []
        for pattern in self._patterns:
            try:
                found.extend(glob.glob(pattern, recursive=True))
            except (OSError, re.error):
                self._warn_once(pattern, "invalid glob pattern")
        files = sorted({path for path in found if os.path.isfile(path)})
        if not self._initialized:
            self._initial_paths = set(files)
            self._initialized = True
        self._files = files
        self._last_scan = time.monotonic()
        if not files:
            self._warn_once(
                "|".join(self._patterns),
                f"no files currently match source '{self.spec.name}'",
            )

    def _warn_once(self, key: str, message: str) -> None:
        if (self.spec.name, key) not in self._warned_errors:
            self._warned_errors.add((self.spec.name, key))
            logging.warning("[%s] %s (%s)", self.spec.name, message, key)

    # -- tailing -----------------------------------------------------------
    def _new_state(self, path: str, size: int, inode: int) -> _FileState:
        # A file that did not exist when the collector started is new, so all
        # of its content is new.  A pre-existing file is tailed from the end
        # unless the operator asked for backfill.
        start_at_zero = self.from_start or path not in self._initial_paths
        return _FileState(inode=inode, offset=0 if start_at_zero else size)

    def _read_new(self, path: str) -> Iterator[Event]:
        try:
            stat = os.stat(path)
        except OSError:
            self._states.pop(path, None)
            return

        state = self._states.get(path)
        if state is None:
            self._states[path] = self._new_state(path, stat.st_size, stat.st_ino)
            return self._read_new(path)

        if state.inode != stat.st_ino or stat.st_size < state.offset:
            logging.info(
                "[%s] rotation detected for %s; reopening", self.spec.name, path
            )
            state = _FileState(inode=stat.st_ino, offset=0)
            self._states[path] = state

        if stat.st_size == state.offset:
            return

        try:
            handle = open(path, "rb")
        except PermissionError:
            self._warn_once(path, "permission denied (collector may need root/admin)")
            return
        except OSError as exc:
            self._warn_once(path, f"cannot open file: {exc}")
            return

        with handle:
            handle.seek(state.offset)
            while True:
                line_start = handle.tell()
                raw = handle.readline(self.max_line_chars + 1)
                if not raw:
                    break

                # An incomplete final line is left for the next poll: emitting
                # it now would split a single log record in two.
                if not raw.endswith(b"\n") and len(raw) <= self.max_line_chars:
                    handle.seek(line_start)
                    break

                if not raw.endswith(b"\n"):
                    # Oversized line: discard the remainder, keep a bounded prefix.
                    while True:
                        extra = handle.readline(65536)
                        if not extra or extra.endswith(b"\n"):
                            break

                state.offset = handle.tell()
                event = self._line_to_event(path, raw[: self.max_line_chars], state)
                if event is not None:
                    yield event

    def _line_to_event(
        self, path: str, raw: bytes, state: _FileState
    ) -> Optional[Event]:
        state.line_number += 1
        line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
        if not line.strip():
            return None

        timestamp = parse_log_timestamp(line)
        message = line
        severity_hint = None
        extra: dict[str, Any] = {}

        parsed = _parse_json_line(line)
        if parsed is not None:
            timestamp = parsed["timestamp"] or timestamp
            message = parsed["message"] or line
            severity_hint = parsed["severity"]
            extra["json"] = parsed["payload"]

        now = datetime.now(timezone.utc).isoformat()
        classification = classifier.classify_linux_record(
            message=message,
            identifier=_infer_service(path, self.spec.name),
            priority=None,
            default_category=self.spec.category,
            default_type=self.spec.default_type,
        )

        attributes: dict[str, Any] = {
            "source_file": path,
            "source_line": state.line_number,
            "log_domain": classification.log_domain,
            "timestamp_source": "log_line" if timestamp else "collector_observed",
            "collector_source": self.spec.name,
        }
        if severity_hint:
            attributes["native_severity"] = severity_hint
        attributes.update(extra)

        return Event(
            schema_version="1.0",
            event_id=str(uuid.uuid4()),
            event_ts=timestamp or now,
            observed_ts=now,
            host=self.hostname,
            source=f"file-{self.spec.name}",
            service=_infer_service(path, self.spec.name),
            category=classification.category,
            type=classification.type,
            severity=classifier.max_severity(severity_hint, classification.severity),
            message=self.redactor.redact(message),
            attributes=self.redactor.redact_structure(attributes),
        )

    def __iter__(self) -> Iterator[Event]:
        self._scan()
        while True:
            if time.monotonic() - self._last_scan >= self.rescan_interval:
                self._scan()

            produced = False
            for path in list(self._files):
                for event in self._read_new(path):
                    produced = True
                    yield event

            if not produced:
                time.sleep(self.poll_interval)
