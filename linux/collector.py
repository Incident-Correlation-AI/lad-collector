# collectors/linux/collector.py
"""Linux collector sources.

Coverage
--------
* authorization  -> journald (sshd, sudo, PAM, logind, polkit) + auth.log fallback
* network        -> journald (kernel firewall, NetworkManager, ...) + ufw log fallback
* syslog         -> journald plus /var/log/syslog, messages, rsyslog/syslog-ng
* service        -> journald systemd unit lifecycle + syslog fallback
* event log      -> audit records delivered through journald, classified as system
* database log   -> PostgreSQL/MySQL/MariaDB/MongoDB/Redis/SQL Server files

journald is read through a *single* Reader without match filters.  Filtering
per category is done by :mod:`collectors.core.classifier`, which avoids the duplicate
delivery that multiple filtered readers would cause.  Classic syslog files are
read as a fallback, or when LAD_SYSLOG_LOG_GLOBS explicitly requests them.
"""

from __future__ import annotations

import logging
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from ..app_adapters.file_tail import FileTailStream
from ..core import classifier
from ..core.config import FileSourceSpec, env_bool, env_list
from ..core.engine import Event, Redactor
from ..core.runtime import UnavailableSource
from .sources import (
    linux_database_sources,
    linux_fallback_sources,
    linux_syslog_sources,
)

_SYSLOG_FACILITIES = {
    0: "kern",
    1: "user",
    2: "mail",
    3: "daemon",
    4: "auth",
    5: "syslog",
    6: "lpr",
    7: "news",
    8: "uucp",
    9: "cron",
    10: "authpriv",
    11: "ftp",
    12: "ntp",
    13: "security",
    14: "console",
    15: "solaris-cron",
}

# Fields fetched explicitly for older systemd-python versions whose
# Reader.get_next() returns a bool instead of a dict.
_JOURNAL_KEYS = (
    "MESSAGE",
    "PRIORITY",
    "SYSLOG_IDENTIFIER",
    "SYSLOG_FACILITY",
    "_SYSTEMD_UNIT",
    "_SYSTEMD_USER_UNIT",
    "_COMM",
    "_EXE",
    "_CMDLINE",
    "_PID",
    "_UID",
    "_GID",
    "_HOSTNAME",
    "_TRANSPORT",
    "_BOOT_ID",
    "_MACHINE_ID",
    "__REALTIME_TIMESTAMP",
    "AUDIT_TYPE",
    "AUDIT_ID",
    "_AUDIT_SESSION",
    "_AUDIT_LOGINUID",
)


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _int(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    try:
        return int(_text(value))
    except (TypeError, ValueError):
        return None


def get_iso_time(systemd_timestamp: Any = None) -> str:
    """Convert a systemd realtime timestamp to an ISO-8601 UTC string."""
    if isinstance(systemd_timestamp, datetime):
        dt = systemd_timestamp
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()

    microseconds = _int(systemd_timestamp)
    if microseconds is not None:
        try:
            return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError):
            pass
    return datetime.now(timezone.utc).isoformat()


def map_priority_to_severity(priority: Any) -> str:
    """Backward-compatible wrapper around the shared severity mapping."""
    return classifier.map_journald_priority(_int(priority))


def _facility_name(value: Any) -> Optional[str]:
    number = _int(value)
    if number is None:
        return _text(value) or None
    return _SYSLOG_FACILITIES.get(number, f"facility_{number}")


def journald_available() -> bool:
    """True when systemd-python can open the local journal."""
    try:
        from systemd import journal  # noqa: F401
    except Exception:
        return False

    try:
        reader = journal.Reader()
        try:
            reader.get_next()
        finally:
            try:
                reader.close()
            except Exception:
                pass
        return True
    except Exception:
        return False


def _entry_dict(journal_reader) -> dict[str, Any]:
    """Return the current journal entry, supporting old systemd-python APIs."""
    entry = journal_reader.get_next()
    if isinstance(entry, dict):
        return entry
    if entry:
        return {key: journal_reader.get_data(key) for key in _JOURNAL_KEYS}
    return {}


def _entry_to_event(
    entry: dict[str, Any],
    redactor: Redactor,
    hostname: str,
) -> Optional[Event]:
    message = _text(entry.get("MESSAGE"))
    audit_type = _text(entry.get("AUDIT_TYPE")) or _text(entry.get("type"))
    if not message and audit_type:
        # Kernel audit records do not always carry a MESSAGE field.
        message = f"audit type={audit_type} id={_text(entry.get('AUDIT_ID'), '?')}"
    if not message:
        return None

    priority = _int(entry.get("PRIORITY"))
    identifier = _text(entry.get("SYSLOG_IDENTIFIER")) or _text(entry.get("_COMM"))
    unit = _text(entry.get("_SYSTEMD_UNIT")) or _text(entry.get("_SYSTEMD_USER_UNIT"))
    transport = _text(entry.get("_TRANSPORT"))
    facility = _facility_name(entry.get("SYSLOG_FACILITY"))

    classification = classifier.classify_linux_record(
        message=message,
        identifier=identifier,
        unit=unit,
        transport=transport,
        priority=priority,
    )

    now = datetime.now(timezone.utc).isoformat()
    attributes: dict[str, Any] = {
        "pid": _int(entry.get("_PID")),
        "uid": _int(entry.get("_UID")),
        "gid": _int(entry.get("_GID")),
        "native_priority": priority,
        "syslog_facility": facility,
        "identifier": identifier or None,
        "unit": unit or None,
        "transport": transport or None,
        "executable": _text(entry.get("_EXE")) or None,
        "cmdline": _text(entry.get("_CMDLINE")) or None,
        "boot_id": _text(entry.get("_BOOT_ID")) or None,
        "log_domain": classification.log_domain,
        "collector_source": "journald",
    }
    if audit_type:
        attributes["audit_type"] = audit_type
        attributes["audit_id"] = _text(entry.get("AUDIT_ID")) or None
        attributes["audit_session"] = _text(entry.get("_AUDIT_SESSION")) or None
    attributes = {key: value for key, value in attributes.items() if value is not None}

    return Event(
        schema_version="1.0",
        event_id=str(uuid.uuid4()),
        event_ts=get_iso_time(entry.get("__REALTIME_TIMESTAMP")),
        observed_ts=now,
        host=_text(entry.get("_HOSTNAME")) or hostname,
        source="journald",
        service=unit or identifier or None,
        category=classification.category,
        type=classification.type,
        severity=classification.severity,
        message=redactor.redact(message),
        attributes=redactor.redact_structure(attributes),
    )


def stream_journald(
    redactor: Redactor,
    *,
    hostname: Optional[str] = None,
    journal_reader=None,
) -> Iterator[Event]:
    """Tail systemd-journald and yield classified, redacted Event objects."""
    try:
        from systemd import journal
    except ImportError as exc:
        raise UnavailableSource(
            "systemd-python is not installed; install it or set "
            "LAD_LINUX_FILE_SOURCES=1 to use file based sources"
        ) from exc

    hostname = hostname or socket.gethostname()

    reader = journal_reader or journal.Reader()
    # Start strictly after the newest existing record.
    reader.seek_tail()
    reader.get_previous()

    while True:
        entry = _entry_dict(reader)
        if not entry:
            wait_result = reader.wait(0.5)
            if wait_result == "INVALIDATE":
                # Journal files rotated; re-anchor at the tail rather than spin.
                reader.seek_tail()
                reader.get_previous()
            continue

        event = _entry_to_event(entry, redactor, hostname)
        if event is not None:
            yield event


def _persistent_file_factory(
    spec: FileSourceSpec,
    redactor: Redactor,
    hostname: str,
):
    """Create the stream once so a restart resumes at the last file offset."""
    stream = FileTailStream(spec, redactor, hostname=hostname)
    return lambda: iter(stream)


def iter_linux_sources(
    redactor: Redactor,
    *,
    hostname: Optional[str] = None,
) -> list[tuple[str, Any]]:
    """Build the ``(name, factory)`` list consumed by StreamMerger.

    journald is the syslog sink on systemd hosts and covers auth/network/
    syslog/service in one pass.  Classic syslog files are added when journald
    is unavailable, when ``LAD_LINUX_FILE_SOURCES=1`` forces file sources, or
    when ``LAD_SYSLOG_LOG_GLOBS`` explicitly names files.  Database logs are
    always tailed from disk.
    """
    hostname = hostname or socket.gethostname()
    sources: list[tuple[str, Any]] = []
    journald_ok = journald_available()
    force_files = env_bool("LAD_LINUX_FILE_SOURCES", False)
    explicit_syslog = bool(env_list("LAD_SYSLOG_LOG_GLOBS"))

    if journald_ok:
        sources.append(
            (
                "journald",
                lambda: stream_journald(redactor, hostname=hostname),
            )
        )
    else:
        logging.warning(
            "journald is not available; falling back to /var/log files. "
            "Category coverage is reduced unless rsyslog or syslog-ng is "
            "writing the expected files."
        )

    if journald_ok and explicit_syslog:
        logging.warning(
            "LAD_SYSLOG_LOG_GLOBS is set while journald is available; "
            "syslog events may be delivered twice."
        )

    if not journald_ok or force_files or explicit_syslog:
        for spec in linux_syslog_sources():
            sources.append(
                (
                    spec.name,
                    _persistent_file_factory(spec, redactor, hostname),
                )
            )

    for spec in linux_database_sources():
        sources.append(
            (
                spec.name,
                _persistent_file_factory(spec, redactor, hostname),
            )
        )

    if force_files and journald_ok:
        logging.warning(
            "LAD_LINUX_FILE_SOURCES=1: file sources are enabled alongside "
            "journald; authorization/syslog events may be delivered twice."
        )

    if not journald_ok or force_files:
        for spec in linux_fallback_sources():
            sources.append(
                (
                    spec.name,
                    _persistent_file_factory(spec, redactor, hostname),
                )
            )

    return sources
