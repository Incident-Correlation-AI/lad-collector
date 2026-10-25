"""Linux file-based source declarations.

journald is configured in :mod:`collectors.linux.collector`; this module lists
the disk sources used for database logs, syslog fallback and auth/network
fallback.
"""

from __future__ import annotations

from ..core import classifier
from ..core.config import FileSourceSpec, env_list

# Database logs are almost never forwarded to journald by default, so they are
# always tailed from disk.  Override with LAD_DATABASE_LOG_GLOBS.
_DEFAULT_DATABASE_GLOBS = (
    "/var/log/postgresql/*.log",
    "/var/log/pgsql/*.log",
    "/var/log/pgbouncer/*.log",
    "/var/log/mysql/*.log",
    "/var/log/mysql/error.log",
    "/var/log/mariadb/*.log",
    "/var/log/mongodb/*.log",
    "/var/log/redis/*.log",
    "/var/log/cassandra/*.log",
    "/var/log/elasticsearch/*.log",
    "/var/log/clickhouse-server/*.log",
    "/var/opt/mssql/log/errorlog*",
    "/var/opt/mssql/log/sqlagent*",
)

# Classic syslog files.  journald normally captures these already, so the
# file source is used when journald is unavailable, when file sources are
# forced, or when LAD_SYSLOG_LOG_GLOBS explicitly names additional files.
_DEFAULT_SYSLOG_GLOBS = (
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/rsyslog/*.log",
    "/var/log/syslog-ng/*.log",
)

_LINUX_FALLBACK_FILES = (
    FileSourceSpec(
        name="auth-file",
        category=classifier.CATEGORY_AUTH,
        default_type="authorization_event",
        patterns=("/var/log/auth.log", "/var/log/secure"),
        description="auth.log/secure fallback when journald is not available",
    ),
    FileSourceSpec(
        name="network-file",
        category=classifier.CATEGORY_NETWORK,
        default_type="network_event",
        patterns=("/var/log/ufw.log", "/var/log/firewalld", "/var/log/firewalld.log"),
        description="firewall log fallback when journald is not available",
    ),
)


def linux_database_sources() -> tuple[FileSourceSpec, ...]:
    patterns = env_list("LAD_DATABASE_LOG_GLOBS") or _DEFAULT_DATABASE_GLOBS
    return (
        FileSourceSpec(
            name="database-files",
            category=classifier.CATEGORY_DB,
            default_type="database_event",
            patterns=tuple(patterns),
            prefer_file=True,
            description="PostgreSQL/MySQL/MariaDB/MongoDB/Redis/SQL Server logs",
        ),
    )


def linux_syslog_sources() -> tuple[FileSourceSpec, ...]:
    patterns = env_list("LAD_SYSLOG_LOG_GLOBS") or _DEFAULT_SYSLOG_GLOBS
    return (
        FileSourceSpec(
            name="syslog-files",
            category=classifier.CATEGORY_SYSLOG,
            default_type="syslog_message",
            patterns=tuple(patterns),
            description="/var/log/syslog, messages, rsyslog or syslog-ng files",
        ),
    )


def linux_fallback_sources() -> tuple[FileSourceSpec, ...]:
    return _LINUX_FALLBACK_FILES
