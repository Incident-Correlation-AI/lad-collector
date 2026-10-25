"""Windows channel and file-source declarations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ..core import classifier
from ..core.config import FileSourceSpec, env_bool, env_list


@dataclass(frozen=True)
class WindowsChannelSpec:
    channel: str
    category: str
    default_type: str
    default_enabled: bool = True
    env_flag: Optional[str] = None
    requires_elevation: bool = False
    description: str = ""


WINDOWS_CHANNELS: tuple[WindowsChannelSpec, ...] = (
    WindowsChannelSpec(
        channel="Security",
        category=classifier.CATEGORY_AUTH,
        default_type="authorization_event",
        requires_elevation=True,
        description="logon, privilege, account and audit-policy events",
    ),
    WindowsChannelSpec(
        channel="System",
        category=classifier.CATEGORY_SYSTEM,
        default_type="system_event",
        description="system/hardware events; Service Control Manager 70xx are "
        "reclassified as service by event ID",
    ),
    WindowsChannelSpec(
        channel="Application",
        category=classifier.CATEGORY_SYSTEM,
        default_type="system_event",
        description="application events, crashes, database providers",
    ),
    WindowsChannelSpec(
        channel="Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        category=classifier.CATEGORY_NETWORK,
        default_type="firewall_event",
        env_flag="LAD_WINDOWS_FIREWALL_EVENTS",
        description="Windows firewall allow/block events",
    ),
    WindowsChannelSpec(
        channel="Microsoft-Windows-Sysmon/Operational",
        category=classifier.CATEGORY_SYSTEM,
        default_type="sysmon_event",
        default_enabled=False,
        env_flag="LAD_WINDOWS_SYSMON",
        description="Sysmon process/network/file telemetry (if installed)",
    ),
    WindowsChannelSpec(
        channel="Microsoft-Windows-DNS-Client/Operational",
        category=classifier.CATEGORY_NETWORK,
        default_type="dns_query",
        default_enabled=False,
        env_flag="LAD_WINDOWS_DNS_CLIENT",
        description="per-process DNS queries (high volume; opt-in)",
    ),
)

# SQL Server and other database server logs on Windows are file based.
_DEFAULT_WINDOWS_DATABASE_GLOBS = (
    r"C:\Program Files\Microsoft SQL Server\*\MSSQL\Log\ERRORLOG*",
    r"C:\Program Files\Microsoft SQL Server\*\MSSQL\Log\SQLAGENT*",
    r"C:\Program Files\MySQL\*\data\*.err",
    r"C:\ProgramData\MySQL\MySQL Server*\Data\*.err",
    r"C:\Program Files\PostgreSQL\*\data\log\*.log",
    r"C:\Program Files\PostgreSQL\*\data\pg_log\*.log",
    r"C:\ProgramData\MongoDB\log\*.log",
    r"C:\Program Files\Redis\*.log",
)


def windows_database_sources() -> tuple[FileSourceSpec, ...]:
    patterns = env_list("LAD_DATABASE_LOG_GLOBS") or _DEFAULT_WINDOWS_DATABASE_GLOBS
    return (
        FileSourceSpec(
            name="database-files",
            category=classifier.CATEGORY_DB,
            default_type="database_event",
            patterns=tuple(patterns),
            prefer_file=True,
            description="SQL Server/MySQL/PostgreSQL/MongoDB error logs",
        ),
    )


def windows_syslog_sources() -> tuple[FileSourceSpec, ...]:
    """Optional file source for syslog relays running on Windows.

    Windows does not emit syslog natively, so this is opt-in: point
    LAD_SYSLOG_LOG_GLOBS at the relay's output files (Kiwi, SolarWinds,
    syslog-ng, rsyslog, etc.).
    """
    patterns = env_list("LAD_SYSLOG_LOG_GLOBS")
    if not patterns:
        return ()
    return (
        FileSourceSpec(
            name="syslog-files",
            category=classifier.CATEGORY_SYSLOG,
            default_type="syslog_message",
            patterns=tuple(patterns),
            description="syslog relay output captured on Windows",
        ),
    )


def windows_channels() -> tuple[WindowsChannelSpec, ...]:
    """Return the channels that are enabled by configuration.

    ``LAD_WINDOWS_CHANNELS`` (comma separated) replaces the default list, so a
    noisy or unavailable channel can be excluded explicitly.
    """
    explicit = env_list("LAD_WINDOWS_CHANNELS")
    if explicit:
        wanted = {channel.lower() for channel in explicit}
        return tuple(spec for spec in WINDOWS_CHANNELS if spec.channel.lower() in wanted)

    enabled = []
    for spec in WINDOWS_CHANNELS:
        if spec.env_flag:
            if env_bool(spec.env_flag, spec.default_enabled):
                enabled.append(spec)
        elif spec.default_enabled:
            enabled.append(spec)
    return tuple(enabled)
