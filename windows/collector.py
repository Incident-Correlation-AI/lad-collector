# collectors/windows/collector.py
"""Windows collector sources.

Coverage
--------
* authorization  -> Security channel (4624/4625/4648/4672/47xx logon events)
* network        -> Security WFP events (5156/5157), firewall channel
* syslog         -> optional syslog relay files via LAD_SYSLOG_LOG_GLOBS
* service        -> System channel (Service Control Manager 70xx)
* event log      -> Application + System + Security channels
* database log   -> SQL Server ERRORLOG and other database server files

The modern ``EvtSubscribe``/``EvtNext`` API is used first because it supports
Operational channels and correctly resumes at the end of each channel.  If it
is unavailable, the legacy ``OpenEventLog``/``ReadEventLog`` API is used as a
fallback for the classic Application/System/Security channels.
"""

from __future__ import annotations

import logging
import re
import socket
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any, Iterator, Optional

from ..app_adapters.file_tail import FileTailStream
from ..core import classifier
from ..core.engine import Event, Redactor
from ..core.runtime import UnavailableSource
from .sources import windows_channels, windows_database_sources, windows_syslog_sources

_WIN_SYSTEM_TIME = re.compile(
    r"^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?P<tz>Z|[+-]\d{2}:\d{2})?$"
)

# ERROR_TIMEOUT / WAIT_TIMEOUT, returned by EvtNext when the poll times out.
_TIMEOUT_CODES = frozenset({258, 1460})
_ACCESS_DENIED = 5
_CHANNEL_NOT_FOUND_CODES = frozenset({15000, 15003, 15007})
_INVALID_PARAMETER = 87
# pywin32 raises this from EvtNext once a poll has timed out with no events;
# the subscription is unusable afterwards, so it must be recreated.
_INVALID_OPERATION = 4317
# After this many consecutive idle waits, probe the subscription once rather
# than trusting the signal event alone (30 x 500 ms = ~15 s).
_SAFETY_POLL_WAITS = 30


def _win_error(exc: BaseException) -> Optional[int]:
    code = getattr(exc, "winerror", None)
    if isinstance(code, int):
        return code
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], int):
        return args[0]
    return None


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


def map_win_type_to_severity(event_type: Any) -> str:
    """Backward-compatible wrapper around the shared EventType mapping."""
    return classifier.map_windows_event_type(_int(event_type))


def _parse_system_time(value: Any) -> Optional[str]:
    text = _text(value).strip()
    if not text:
        return None
    match = _WIN_SYSTEM_TIME.match(text)
    if not match:
        return None
    fraction = (match.group("fraction") or "")[:6]
    suffix = f".{fraction}" if fraction else ""
    tz_text = match.group("tz") or "Z"
    if tz_text == "Z":
        tz_text = "+00:00"
    try:
        parsed = datetime.fromisoformat(f"{match.group('base')}{suffix}{tz_text}")
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).isoformat()


def _legacy_level(event_type: Optional[int]) -> int:
    if event_type == 1:
        return 2  # error
    if event_type == 2:
        return 3  # warning
    if event_type == 16:
        return 3  # audit failure
    return 4  # information


def _close_handle(handle: Any) -> None:
    if handle is None:
        return
    try:
        handle.Close()
    except Exception:
        try:
            import win32evtlog

            win32evtlog.EvtClose(handle)
        except Exception:
            pass


def _enable_security_privilege() -> bool:
    """Enable SeSecurityPrivilege for this process.

    ``ReadEventLog`` on the Security channel requires it; administrators hold
    the privilege but Windows leaves it disabled in the token, so the legacy
    reader has to enable it explicitly or ``OpenEventLog`` fails with
    access-denied even in an elevated shell.
    """
    try:
        import win32api
        import win32con
        import win32security
    except ImportError:
        return False

    try:
        handle = win32api.GetCurrentProcess()
        token = win32security.OpenProcessToken(
            handle, win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
        )
        luid = win32security.LookupPrivilegeValue(None, win32security.SE_SECURITY_NAME)
        win32security.AdjustTokenPrivileges(
            token, False, [(luid, win32security.SE_PRIVILEGE_ENABLED)]
        )
        if win32api.GetLastError() == win32con.ERROR_NOT_ALL_ASSIGNED:
            logging.debug("SeSecurityPrivilege is not held by this token")
            return False
        return True
    except Exception as exc:  # noqa: BLE001 - best effort, caller reports access denied
        logging.debug("could not enable SeSecurityPrivilege: %s", exc)
        return False


def _parse_event_xml(xml: str) -> Optional[dict[str, Any]]:
    """Parse the XML returned by ``EvtRender(..., EvtRenderEventXml)``."""
    if not xml:
        return None
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return None

    namespace = root.tag[1:].split("}", 1)[0] if root.tag.startswith("{") else ""

    def q(tag: str) -> str:
        return f"{{{namespace}}}{tag}" if namespace else tag

    system = root.find(q("System"))
    if system is None:
        return None

    def system_text(tag: str) -> Optional[str]:
        element = system.find(q(tag))
        return (
            (element.text or "").strip()
            if element is not None and element.text
            else None
        )

    provider_element = system.find(q("Provider"))
    time_element = system.find(q("TimeCreated"))
    event_id_element = system.find(q("EventID"))

    event_id = (
        _int(event_id_element.text if event_id_element is not None else None) or 0
    )
    provider = provider_element.get("Name") if provider_element is not None else ""
    time_created = time_element.get("SystemTime") if time_element is not None else None

    data: dict[str, Any] = {}
    for index, element in enumerate(root.findall(f".//{q('EventData')}/{q('Data')}")):
        name = element.get("Name") or f"param_{index + 1}"
        data[name] = (element.text or "").strip()

    user_data = root.find(q("UserData"))
    if user_data is not None:
        for parent in list(user_data):
            parent_name = parent.tag.split("}")[-1]
            for child in list(parent):
                child_name = child.tag.split("}")[-1]
                data[f"{parent_name}.{child_name}"] = (child.text or "").strip()

    return {
        "event_id": event_id,
        "provider": provider or "",
        "channel": system_text("Channel") or "",
        "computer": system_text("Computer") or "",
        "record_id": _int(system_text("EventRecordID")),
        "level": _int(system_text("Level")),
        "task": _int(system_text("Task")),
        "opcode": _int(system_text("Opcode")),
        "keywords": system_text("Keywords"),
        "time_created": time_created,
        "data": data,
    }


def _translate_subscribe_error(exc: BaseException, channel: str) -> BaseException:
    code = _win_error(exc)
    if code == _ACCESS_DENIED:
        return UnavailableSource(
            f"access denied reading '{channel}'. Run the collector as Administrator "
            "(the Security channel requires elevation)."
        )
    if code in _CHANNEL_NOT_FOUND_CODES:
        return UnavailableSource(f"channel '{channel}' is not available on this host.")
    return exc


class WindowsEventLogStream:
    """Yield classified events from one Windows Event Log channel."""

    def __init__(
        self,
        channel: str,
        redactor: Redactor,
        *,
        category: Optional[str] = None,
        default_type: Optional[str] = None,
        hostname: Optional[str] = None,
        query: str = "*",
        batch_size: int = 64,
        poll_timeout_ms: int = 500,
    ):
        self.channel = channel
        self.redactor = redactor
        self.category = category
        self.default_type = default_type
        self.hostname = hostname or socket.gethostname()
        self.query = query
        self.batch_size = batch_size
        self.poll_timeout_ms = poll_timeout_ms
        self._metadata_cache: dict[str, Any] = {}

    # -- event construction ------------------------------------------------
    def _build_message(self, parsed: dict[str, Any]) -> str:
        provider = parsed.get("provider") or "Windows"
        event_id = parsed.get("event_id") or 0
        data = parsed.get("data") or {}
        rendered = " ".join(
            f"{key}={value}" for key, value in data.items() if value not in (None, "")
        )
        return (
            f"{provider} event {event_id}: {rendered}"
            if rendered
            else f"{provider} event {event_id}"
        )

    def _to_event(
        self,
        *,
        event_id: int,
        provider: str,
        channel: str,
        level: Optional[int],
        time_created: Optional[str],
        record_id: Optional[int],
        data: dict[str, Any],
        task: Optional[int] = None,
        opcode: Optional[int] = None,
        keywords: Optional[str] = None,
        computer: Optional[str] = None,
        native_event_type: Optional[int] = None,
        message_override: Optional[str] = None,
    ) -> Event:
        message = message_override or self._build_message(
            {
                "provider": provider,
                "event_id": event_id,
                "data": data,
            }
        )
        classification = classifier.classify_windows_event(
            event_id=event_id,
            provider=provider,
            channel=channel,
            level=level,
            message=message,
            default_category=self.category,
            default_type=self.default_type,
        )

        now = datetime.now(timezone.utc).isoformat()
        event_ts = _parse_system_time(time_created) if time_created else None
        if event_ts is None:
            event_ts = now

        if "service control manager" in (provider or "").lower():
            service = _text(data.get("param1") or data.get("ServiceName")) or provider
        else:
            service = _text(data.get("ServiceName")) or provider or None

        attributes: dict[str, Any] = {
            "native_event_id": event_id,
            "record_number": record_id,
            "channel": channel or self.channel,
            "provider": provider,
            "level": level,
            "task": task,
            "opcode": opcode,
            "keywords": keywords,
            "computer": computer or self.hostname,
            "event_data": data,
            "native_event_type": native_event_type,
            "log_domain": classification.log_domain,
            "timestamp_source": "log_line" if time_created else "collector_observed",
            "collector_source": "windows-eventlog",
        }
        attributes = {
            key: value for key, value in attributes.items() if value is not None
        }

        return Event(
            schema_version="1.0",
            event_id=str(uuid.uuid4()),
            event_ts=event_ts,
            observed_ts=now,
            host=computer or self.hostname,
            source="windows-eventlog",
            service=service or None,
            category=classification.category,
            type=classification.type,
            severity=classification.severity,
            message=self.redactor.redact(message),
            attributes=self.redactor.redact_structure(attributes),
        )

    # -- modern API --------------------------------------------------------
    def _format_modern_message(
        self, win32evtlog, event_handle, provider: str
    ) -> Optional[str]:
        """Resolve the human-readable message from the provider metadata.

        Best effort: some providers have no message table, and formatting is
        localized.  The caller falls back to the EventData rendering.
        """
        if not provider:
            return None

        metadata = self._metadata_cache.get(provider)
        if metadata is None:
            try:
                metadata = win32evtlog.EvtOpenPublisherMetadata(provider)
            except Exception:
                metadata = False
            self._metadata_cache[provider] = metadata
        if not metadata:
            return None

        try:
            formatted = win32evtlog.EvtFormatMessage(
                metadata,
                event_handle,
                getattr(win32evtlog, "EvtFormatMessageEvent", 1),
            )
        except Exception:
            return None

        if isinstance(formatted, (list, tuple)):
            text = " ".join(str(part) for part in formatted)
        else:
            text = str(formatted) if formatted else ""
        return text or None

    def _close_metadata(self) -> None:
        for metadata in self._metadata_cache.values():
            if metadata:
                _close_handle(metadata)
        self._metadata_cache.clear()

    def _subscribe(self, win32evtlog, signal: Any) -> Any:
        try:
            return win32evtlog.EvtSubscribe(
                ChannelPath=self.channel,
                Flags=win32evtlog.EvtSubscribeToFutureEvents,
                SignalEvent=signal,
                Query=self.query or "*",
            )
        except Exception as exc:
            raise _translate_subscribe_error(exc, self.channel)

    def _iter_modern(self, win32evtlog, win32event) -> Iterator[Event]:
        signal = win32event.CreateEvent(None, 0, 0, None)
        subscription = None
        try:
            subscription = self._subscribe(win32evtlog, signal)

            try:
                idle_waits = 0
                while True:
                    # Wait for the subscription's signal instead of polling with
                    # a timeout.  Once EvtNext() times out with an empty result,
                    # pywin32 leaves the subscription unusable and every later
                    # call fails with WinError 4317, which previously forced an
                    # immediate (and permanent) fallback to the legacy reader on
                    # any quiet channel.
                    safety_poll = False
                    if (
                        win32event.WaitForSingleObject(signal, self.poll_timeout_ms)
                        == win32event.WAIT_OBJECT_0
                    ):
                        idle_waits = 0
                    else:
                        idle_waits += 1
                        if idle_waits < _SAFETY_POLL_WAITS:
                            continue
                        idle_waits = 0
                        safety_poll = True

                    try:
                        handles = win32evtlog.EvtNext(subscription, self.batch_size, 0, 0)
                    except Exception as exc:
                        code = _win_error(exc)
                        if code in _TIMEOUT_CODES:
                            continue
                        if code == _INVALID_OPERATION:
                            # Recover the poisoned subscription.  The previous
                            # poll reported no pending events, so re-subscribing
                            # does not skip anything.
                            _close_handle(subscription)
                            subscription = self._subscribe(win32evtlog, signal)
                            continue
                        raise

                    if not handles and safety_poll:
                        # An empty EvtNext() poisons the subscription, so never
                        # leave one in that state after a safety poll.
                        _close_handle(subscription)
                        subscription = self._subscribe(win32evtlog, signal)

                    for handle in handles or ():
                        parsed = None
                        formatted = None
                        try:
                            xml = win32evtlog.EvtRender(
                                handle, win32evtlog.EvtRenderEventXml
                            )
                            parsed = _parse_event_xml(xml)
                            if parsed is not None:
                                formatted = self._format_modern_message(
                                    win32evtlog, handle, parsed["provider"]
                                )
                        except Exception as exc:
                            logging.debug(
                                "[%s] could not render event: %s", self.channel, exc
                            )
                            continue
                        finally:
                            _close_handle(handle)

                        if parsed is None:
                            continue
                        yield self._to_event(
                            event_id=parsed["event_id"],
                            provider=parsed["provider"],
                            channel=parsed["channel"] or self.channel,
                            level=parsed["level"],
                            time_created=parsed["time_created"],
                            record_id=parsed["record_id"],
                            data=parsed["data"],
                            task=parsed["task"],
                            opcode=parsed["opcode"],
                            keywords=parsed["keywords"],
                            computer=parsed["computer"],
                            message_override=formatted,
                        )
            finally:
                _close_handle(subscription)
                self._close_metadata()
        finally:
            _close_handle(signal)

    # -- legacy API --------------------------------------------------------
    def _iter_legacy(self, win32evtlog) -> Iterator[Event]:
        try:
            import win32evtlogutil
        except ImportError:
            win32evtlogutil = None

        if self.channel.lower() == "security":
            # ReadEventLog on the Security channel needs SeSecurityPrivilege;
            # administrators hold it but Windows keeps it disabled by default.
            _enable_security_privilege()

        try:
            handle = win32evtlog.OpenEventLog(None, self.channel)
        except Exception as exc:
            raise _translate_subscribe_error(exc, self.channel)

        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ

        try:
            oldest = win32evtlog.GetOldestEventLogRecord(handle)
            count = win32evtlog.GetNumberOfEventLogRecords(handle)
            next_record = oldest + count

            while True:
                try:
                    records = win32evtlog.ReadEventLog(handle, flags, next_record)
                except Exception as exc:
                    if _win_error(exc) != _INVALID_PARAMETER:
                        raise
                    # Reached the end (or the log was cleared/wrapped).
                    try:
                        oldest = win32evtlog.GetOldestEventLogRecord(handle)
                        count = win32evtlog.GetNumberOfEventLogRecords(handle)
                    except Exception:
                        break
                    if next_record < oldest or next_record > oldest + count:
                        next_record = oldest + count
                    time.sleep(1)
                    continue

                if not records:
                    time.sleep(1)
                    continue

                for record in records:
                    next_record = record.RecordNumber + 1
                    yield self._legacy_record_to_event(record, win32evtlogutil)
        finally:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass

    def _legacy_record_to_event(self, record, win32evtlogutil) -> Event:
        channel = self.channel
        try:
            if win32evtlogutil is not None:
                message = win32evtlogutil.SafeFormatMessage(record, channel)
            else:
                raise RuntimeError("win32evtlogutil unavailable")
        except Exception:
            inserts = [_text(value) for value in (record.StringInserts or ())]
            message = " ".join(inserts) if inserts else "No message text"

        data = {
            f"param{index + 1}": _text(value)
            for index, value in enumerate(record.StringInserts or ())
        }
        event_id = int(record.EventID) & 0xFFFF
        event_type = _int(record.EventType)
        generated = record.TimeGenerated
        if isinstance(generated, datetime):
            if generated.tzinfo is None:
                generated = generated.replace(tzinfo=timezone.utc)
            time_created = generated.astimezone(timezone.utc).isoformat()
        else:
            time_created = _text(generated) or None

        return self._to_event(
            event_id=event_id,
            provider=_text(record.SourceName),
            channel=channel,
            level=_legacy_level(event_type),
            time_created=time_created,
            record_id=_int(record.RecordNumber),
            data=data,
            native_event_type=event_type,
            message_override=message,
        )

    # -- public iterator ---------------------------------------------------
    def __iter__(self) -> Iterator[Event]:
        try:
            import win32evtlog
            import win32event
        except ImportError as exc:
            raise UnavailableSource(
                "pywin32 is not installed. Run 'pip install pywin32'."
            ) from exc

        if hasattr(win32evtlog, "EvtSubscribe"):
            try:
                yield from self._iter_modern(win32evtlog, win32event)
                return
            except UnavailableSource:
                raise
            except Exception as exc:
                logging.warning(
                    "[%s] modern Windows Event Log API failed (%s); "
                    "falling back to the legacy reader.",
                    self.channel,
                    exc,
                )

        yield from self._iter_legacy(win32evtlog)


def stream_windows_events(
    redactor: Redactor,
    channel: str = "Application",
    *,
    category: Optional[str] = None,
    default_type: Optional[str] = None,
) -> Iterator[Event]:
    """Backward-compatible entry point for a single channel."""
    return WindowsEventLogStream(
        channel,
        redactor,
        category=category,
        default_type=default_type,
    )


def iter_windows_sources(
    redactor: Redactor,
    *,
    hostname: Optional[str] = None,
) -> list[tuple[str, Any]]:
    """Build the ``(name, factory)`` list consumed by StreamMerger."""
    hostname = hostname or socket.gethostname()
    sources: list[tuple[str, Any]] = []

    channels = windows_channels()
    if any(spec.channel.lower() == "security" for spec in channels):
        logging.info(
            "Windows Security channel enabled: the collector must run as "
            "Administrator or the source will be skipped as unavailable."
        )

    for spec in channels:
        sources.append(
            (
                f"windows-{spec.channel}",
                lambda spec=spec: WindowsEventLogStream(
                    spec.channel,
                    redactor,
                    category=spec.category,
                    default_type=spec.default_type,
                    hostname=hostname,
                ),
            )
        )

    for file_spec in windows_database_sources():
        # Instantiate once so a source restart resumes at the last offset.
        stream = FileTailStream(file_spec, redactor, hostname=hostname)
        sources.append((file_spec.name, lambda stream=stream: iter(stream)))

    for file_spec in windows_syslog_sources():
        stream = FileTailStream(file_spec, redactor, hostname=hostname)
        sources.append((file_spec.name, lambda stream=stream: iter(stream)))

    return sources
