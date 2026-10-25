"""Shared log classification used by the Linux and Windows collectors.

The event contract stores a single ``category`` per event.  The project brief
asks us to cover six log domains, which map onto contract categories as:

======================  ==============  ==========================================
Requested domain        ``category``    Typical sources
======================  ==============  ==========================================
authorization           ``auth``        sshd/sudo/PAM, Windows Security logon IDs
network                 ``network``     ufw/firewalld/nftables, WFP/firewall logs
syslog                  ``syslog``      journald/syslog, rsyslog/syslog-ng files
service                 ``service``     systemd unit lifecycle, Service Control Mgr
event log               ``system``      Windows Application/System channels
database log            ``db``          PostgreSQL/MySQL/MongoDB/SQL Server logs
======================  ==============  ==========================================

Audit records that arrive through journald (``_TRANSPORT=audit``) are kept as
``system`` / ``audit_*`` events; they are not a separate benchmark feed.

Classification is intentionally *rule based* and deterministic.  It never
inspects the network, never calls a model, and never changes the original
message.  The original source-specific data is preserved under
``attributes`` by the readers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# ---------------------------------------------------------------------------
# Contract categories
# ---------------------------------------------------------------------------
CATEGORY_AUTH = "auth"
CATEGORY_NETWORK = "network"
CATEGORY_SYSLOG = "syslog"
CATEGORY_SERVICE = "service"
CATEGORY_SYSTEM = "system"
CATEGORY_DB = "db"

VALID_CATEGORIES = (
    CATEGORY_AUTH,
    CATEGORY_NETWORK,
    CATEGORY_SYSLOG,
    CATEGORY_SERVICE,
    CATEGORY_SYSTEM,
    CATEGORY_DB,
)

# Human readable name for each contract category (used in attributes and logs).
CATEGORY_TO_LOG_DOMAIN = {
    CATEGORY_AUTH: "authorization",
    CATEGORY_NETWORK: "network",
    CATEGORY_SYSLOG: "syslog",
    CATEGORY_SERVICE: "service",
    CATEGORY_SYSTEM: "event log",
    CATEGORY_DB: "database",
}

SEVERITY_RANK = {"info": 0, "warning": 1, "error": 2, "critical": 3}
_RANK_TO_SEVERITY = {rank: severity for severity, rank in SEVERITY_RANK.items()}


def max_severity(*values: Optional[str]) -> str:
    """Return the most severe value, ignoring ``None`` / unknown values."""
    rank = 0
    for value in values:
        if not value:
            continue
        rank = max(rank, SEVERITY_RANK.get(str(value).lower(), 0))
    return _RANK_TO_SEVERITY[rank]


def normalize_severity(value: Optional[str], default: str = "info") -> str:
    if value and str(value).lower() in SEVERITY_RANK:
        return str(value).lower()
    return default


# ---------------------------------------------------------------------------
# Best-effort severity inference from free text
# ---------------------------------------------------------------------------
_CRITICAL_TEXT = re.compile(
    r"(?i)\b(critical|fatal|panic|emergency|segfault|corrupt(?:ion|ed)?|"
    r"data loss|out of memory|oom[- ]?kill(?:ed)?|disk full)\b"
)
_ERROR_TEXT = re.compile(
    r"(?i)\b(error|err|failed|failure|denied|refused|exception|traceback|"
    r"abort(?:ed)?|unable to|cannot|unreachable|no route to host|broken pipe)\b"
)
_WARNING_TEXT = re.compile(
    r"(?i)\b(warn(?:ing)?|retry(?:ing)?|deprecated|degraded|slow|throttl(?:ed|ing)|"
    r"reconnect(?:ed|ing)?|temporar(?:y|ily)|timeout|timed out)\b"
)


def infer_severity_from_text(message: str, default: str = "info") -> str:
    """Conservative keyword-based severity for sources without a native level."""
    if not message:
        return default
    if _CRITICAL_TEXT.search(message):
        return "critical"
    if _ERROR_TEXT.search(message):
        return "error"
    if _WARNING_TEXT.search(message):
        return "warning"
    return default


def map_journald_priority(priority: Optional[int]) -> str:
    """syslog priority 0..7 -> contract severity."""
    if priority is None:
        return "info"
    if priority <= 2:
        return "critical"
    if priority == 3:
        return "error"
    if priority == 4:
        return "warning"
    return "info"


def map_windows_level(level: Optional[int]) -> str:
    """Windows EVT level 1..5 -> contract severity."""
    if level == 1:
        return "critical"
    if level == 2:
        return "error"
    if level == 3:
        return "warning"
    return "info"


def map_windows_event_type(event_type: Optional[int]) -> str:
    """Classic Windows EventType -> contract severity.

    1=ERROR, 2=WARNING, 4=INFORMATION, 8=AUDIT_SUCCESS, 16=AUDIT_FAILURE.
    """
    if event_type == 1:
        return "error"
    if event_type == 2:
        return "warning"
    if event_type == 16:
        # A failed audit is an authorization signal, not necessarily critical.
        return "warning"
    return "info"


# ---------------------------------------------------------------------------
# Result object
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Classification:
    category: str
    type: str
    severity: str
    rule: str = "default"

    @property
    def log_domain(self) -> str:
        return CATEGORY_TO_LOG_DOMAIN.get(self.category, self.category)


# ---------------------------------------------------------------------------
# Linux / journald / syslog rules
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class LinuxRule:
    name: str
    category: str
    type: str
    priority: int
    exact: frozenset[str] = frozenset()
    prefixes: tuple[str, ...] = ()
    message: tuple[re.Pattern[str], ...] = ()
    transport: frozenset[str] = frozenset()

    def matches(self, identifier: str, unit: str, message: str, transport: str) -> bool:
        if transport and transport.lower() in self.transport:
            return True

        names = {n.lower() for n in (identifier, unit) if n}
        if self.exact and names & {value.lower() for value in self.exact}:
            return True
        if self.prefixes:
            lowered_prefixes = tuple(prefix.lower() for prefix in self.prefixes)
            for name in names:
                if any(name.startswith(prefix) for prefix in lowered_prefixes):
                    return True
        if self.message and message:
            return any(pattern.search(message) for pattern in self.message)
        return False


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)


_AUDIT_MESSAGE_PATTERNS = _rx(
    r"\bmsg=audit\(",
    r"\btype=(SYSCALL|EXECVE|PATH|AVC|USER_LOGIN|USER_ACCT|CONFIG_CHANGE|"
    r"SERVICE_START|SERVICE_STOP|USER_AUTH|USER_CMD|ADD_USER|DEL_USER)\b",
    r"\bauditd?\b",
)

_FIREWALL_MESSAGE_PATTERNS = _rx(
    r"\b(ufw|iptables|ip6tables|nftables|firewalld)\b",
    r"\b(DROP|REJECT|BLOCK)\b",
    r"\bIN=\S+ OUT=\S+",
    r"\b(SRC|DST)=\d{1,3}(\.\d{1,3}){3}",
    r"\b(filter|policy) (dropped|blocked|rejected)\b",
)

_LINK_MESSAGE_PATTERNS = _rx(
    r"\blink (?:is )?(?:up|down)\b",
    r"\bcarrier (?:up|down)\b",
    r"\b(interface|vlan|bridge|bond|ethernet|wlan)\b.*\b(up|down|change|state)\b",
    r"\bDHCP(?:v[46])?\b",
    r"\b(connected|disconnected) to\b.*\b(wifi|network|vpn)\b",
)

_AUTH_MESSAGE_PATTERNS = _rx(
    r"\bauthentication failure\b",
    r"\bfailed password\b",
    r"\bfailed (?:publickey|keyboard-interactive)\b",
    r"\baccepted (?:password|publickey|keyboard-interactive)\b",
    r"\binvalid user\b",
    r"\bsession (?:opened|closed) for user\b",
    r"\bnew session\b",
    r"\btoo many authentication failures\b",
    r"\baccount (?:locked|unlocked)\b",
    r"\bsudo:.*\bCOMMAND=",
    r"\bpam_unix\b",
    r"\b(?:useradd|userdel|usermod|groupadd|groupdel|passwd)\b",
)

_SERVICE_MESSAGE_PATTERNS = _rx(
    r"\b(?:Starting|Started|Stopping|Stopped|Reloading|Reloaded|"
    r"Activating|Deactivating|Deactivated)\b",
    r"\b(?:Failed to start|failed to start|Scheduled restart|"
    r"Main process exited|service .* (?:started|stopped|failed))\b",
    r"\b(?:start|stop|restart) (?:of|requested for) .*\.service\b",
)

_LINUX_RULES: tuple[LinuxRule, ...] = (
    LinuxRule(
        name="linux.audit",
        category=CATEGORY_SYSTEM,
        type="audit_event",
        priority=100,
        exact=frozenset(
            {
                "audit",
                "auditd",
                "audispd",
            }
        ),
        prefixes=("audit",),
        message=_AUDIT_MESSAGE_PATTERNS,
        transport=frozenset({"audit"}),
    ),
    LinuxRule(
        name="linux.database",
        category=CATEGORY_DB,
        type="database_event",
        priority=90,
        exact=frozenset(
            {
                "postgres",
                "postgresql",
                "mysqld",
                "mariadbd",
                "mongod",
                "mongodb",
                "redis",
                "redis-server",
                "mssql",
                "sqlservr",
                "pgbouncer",
                "patroni",
                "cassandra",
                "elasticsearch",
                "clickhouse",
                "influxd",
            }
        ),
        prefixes=(
            "postgres",
            "mysql",
            "mariadb",
            "mongod",
            "redis",
            "mssql",
            "sqlservr",
            "pgbouncer",
            "patroni",
            "cassandra",
            "elasticsearch",
            "clickhouse",
            "influxd",
        ),
    ),
    LinuxRule(
        name="linux.network",
        category=CATEGORY_NETWORK,
        type="network_event",
        priority=80,
        exact=frozenset(
            {
                "ufw",
                "firewalld",
                "firewall",
                "nft",
                "iptables",
                "ip6tables",
                "ebtables",
                "NetworkManager",
                "systemd-networkd",
                "dhclient",
                "dhcpcd",
                "wpa_supplicant",
                "connman",
                "tailscaled",
                "openvpn",
                "wireguard",
                "wg-quick",
                "pppd",
                "dnsmasq",
                "named",
                "unbound",
                "charon",
                "strongswan",
            }
        ),
        prefixes=(
            "ufw",
            "firewalld",
            "nft",
            "iptables",
            "NetworkManager",
            "systemd-networkd",
            "dhclient",
            "dhcpcd",
            "wpa_supplicant",
            "connman",
            "tailscaled",
            "openvpn",
            "wireguard",
            "wg-quick",
            "pppd",
            "dnsmasq",
            "named",
            "unbound",
            "charon",
        ),
        message=_FIREWALL_MESSAGE_PATTERNS + _LINK_MESSAGE_PATTERNS,
    ),
    LinuxRule(
        name="linux.authorization",
        category=CATEGORY_AUTH,
        type="authorization_event",
        priority=70,
        exact=frozenset(
            {
                "sshd",
                "sshd-session",
                "sudo",
                "su",
                "sulogin",
                "login",
                "systemd-logind",
                "polkitd",
                "polkit",
                "pam",
                "pam_unix",
                "gdm",
                "gdm-password",
                "lightdm",
                "sddm",
                "xrdp",
                "vsftpd",
                "dovecot",
            }
        ),
        prefixes=(
            "sshd",
            "sudo",
            "sulogin",
            "systemd-logind",
            "polkit",
            "pam",
            "gdm",
            "lightdm",
            "sddm",
            "xrdp",
            "vsftpd",
            "dovecot",
        ),
        message=_AUTH_MESSAGE_PATTERNS,
    ),
    LinuxRule(
        name="linux.service",
        category=CATEGORY_SERVICE,
        type="service_event",
        priority=60,
        exact=frozenset({"systemd", "init", "systemd-shutdown"}),
        prefixes=("systemd",),
        message=_SERVICE_MESSAGE_PATTERNS,
    ),
)

# Kernel messages are only network when the text actually looks like networking.
_KERNEL_NETWORK_PATTERNS = _FIREWALL_MESSAGE_PATTERNS + _LINK_MESSAGE_PATTERNS
_KERNEL_IDENTIFIERS = frozenset({"kernel", "kern"})

_DB_DEADLOCK = _rx(r"\bdeadlock\b", r"\bdeadlock detected\b")
_DB_SLOW = _rx(r"\bslow quer", r"\bduration: \d", r"\bquery_time\b", r"\bexceeded.*\bms\b")
_DB_CONN = _rx(
    r"\bconnection (?:refused|reset|closed|error)\b",
    r"\bcould not connect\b",
    r"\btoo many connections\b",
    r"\bmax_connections\b",
    r"\bconnection.*\b(?:timeout|timed out)\b",
)
_DB_AUTH = _rx(r"\baccess denied for user\b", r"\bauthentication failed\b", r"\bpassword authentication failed\b")
_DB_REPLICATION = _rx(r"\breplicat(?:ion|e|ing)\b", r"\bwal\b", r"\bbinlog\b")
_DB_RECOVERY = _rx(
    r"\bcrash(?:ed)?\b",
    r"\brecover(?:y|ing)\b",
    r"\bshutdown\b",
    r"\bstarting up\b",
    r"\bdatabase system is (?:ready|shutting down)\b",
)


def _refine_linux_type(category: str, message: str, fallback: str) -> str:
    text = message or ""
    lowered = text.lower()

    if category == CATEGORY_AUTH:
        if any(word in lowered for word in ("fail", "denied", "invalid", "incorrect", "locked")):
            return "auth_failure"
        if any(word in lowered for word in ("accepted", "opened", "new session", "success")):
            return "auth_success"
        return "authorization_event"

    if category == CATEGORY_NETWORK:
        if any(pattern.search(text) for pattern in _FIREWALL_MESSAGE_PATTERNS) or re.search(
            r"(?i)\b(DROP|REJECT|BLOCK)\b", text
        ):
            return "firewall_event"
        if re.search(r"(?i)\b(link (?:is )?(?:up|down)|carrier (?:up|down))\b", text):
            return "network_interface_change"
        if re.search(r"(?i)\bDHCP", text):
            return "dhcp_event"
        if re.search(r"(?i)\b(openvpn|wireguard|vpn|tunnel)\b", text):
            return "vpn_event"
        return "network_event"

    if category == CATEGORY_SERVICE:
        if re.search(r"(?i)\bfailed|failure|Main process exited", text):
            return "service_failure"
        if re.search(r"(?i)\b(Started|Starting|Activating)\b", text):
            return "service_start"
        if re.search(r"(?i)\b(Stopped|Stopping|Deactivating|Deactivated)\b", text):
            return "service_stop"
        return "service_state_change"

    if category == CATEGORY_DB:
        if any(pattern.search(text) for pattern in _DB_DEADLOCK):
            return "database_deadlock"
        if any(pattern.search(text) for pattern in _DB_SLOW):
            return "database_slow_query"
        if any(pattern.search(text) for pattern in _DB_AUTH):
            return "database_auth_failure"
        if any(pattern.search(text) for pattern in _DB_CONN):
            return "database_connection_error"
        if any(pattern.search(text) for pattern in _DB_REPLICATION):
            return "database_replication_event"
        if any(pattern.search(text) for pattern in _DB_RECOVERY):
            return "database_recovery_event"
        return "database_event"

    if category == CATEGORY_SYSTEM and fallback == "audit_event":
        return _refine_audit_type(text, fallback)

    return fallback


def _refine_audit_type(text: str, fallback: str = "audit_event") -> str:
    """Add audit-specific detail without creating a separate category."""
    match = re.search(r"\btype=([A-Z_]+)\b", text)
    if match:
        return f"audit_{match.group(1).lower()}"
    if re.search(r"(?i)\bAVC\b|\bdenied\b", text):
        return "audit_denial"
    if re.search(r"(?i)\bEXECVE\b|\bexecve\b", text):
        return "audit_exec"
    return fallback


def _refine_linux_severity(category: str, event_type: str, message: str, base: str) -> str:
    if event_type == "auth_failure":
        return "warning"
    if event_type in ("auth_success", "authorization_event"):
        return max_severity(base, "info")
    if event_type in ("service_failure", "database_deadlock", "database_connection_error",
                      "database_auth_failure", "audit_denial"):
        return max_severity(base, "error")
    if event_type in ("firewall_event", "database_slow_query", "audit_log_cleared"):
        return max_severity(base, "warning")
    if category == CATEGORY_DB:
        return max_severity(base, infer_severity_from_text(message))
    return max_severity(base, infer_severity_from_text(message))


def _base_name(value: str) -> str:
    """``postgresql@14-main.service`` -> ``postgresql``; ``sshd`` stays ``sshd``."""
    if not value:
        return ""
    name = value.strip()
    if name.endswith(".service"):
        name = name[: -len(".service")]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def classify_linux_record(
    *,
    message: str,
    identifier: str = "",
    unit: str = "",
    transport: str = "",
    priority: Optional[int] = None,
    default_category: str = CATEGORY_SYSLOG,
    default_type: str = "syslog_message",
) -> Classification:
    """Classify one journald/syslog/file record."""
    identifier = _base_name(identifier)
    unit = _base_name(unit)
    base_severity = map_journald_priority(priority)

    # A kernel message is not automatically a network message.
    if identifier in _KERNEL_IDENTIFIERS and any(
        pattern.search(message or "") for pattern in _KERNEL_NETWORK_PATTERNS
    ):
        event_type = "firewall_event" if any(
            pattern.search(message or "") for pattern in _FIREWALL_MESSAGE_PATTERNS
        ) else "network_event"
        return Classification(
            CATEGORY_NETWORK,
            event_type,
            max_severity(
                base_severity,
                infer_severity_from_text(message),
                "warning" if event_type == "firewall_event" else "info",
            ),
            "linux.kernel-network",
        )

    for rule in _LINUX_RULES:
        if rule.matches(identifier, unit, message or "", transport):
            event_type = _refine_linux_type(rule.category, message or "", rule.type)
            severity = _refine_linux_severity(rule.category, event_type, message or "", base_severity)
            return Classification(rule.category, event_type, severity, rule.name)

    severity = max_severity(base_severity, infer_severity_from_text(message or ""))
    return Classification(default_category, default_type, severity, "default")


# ---------------------------------------------------------------------------
# Windows Event Log rules
# ---------------------------------------------------------------------------
# Windows audit/security event ids.  These are normal Event Log records, not
# a separate benchmark feed: process/object/policy events stay in ``system``
# and privilege events belong to ``auth``.
# event id -> (semantic type, severity, category)
_WINDOWS_AUDIT = {
    1102: ("audit_log_cleared", "critical", CATEGORY_SYSTEM),
    104: ("audit_log_cleared", "critical", CATEGORY_SYSTEM),
    4719: ("audit_policy_change", "warning", CATEGORY_SYSTEM),
    4902: ("audit_policy_change", "warning", CATEGORY_SYSTEM),
    4906: ("audit_policy_change", "warning", CATEGORY_SYSTEM),
    4907: ("audit_policy_change", "warning", CATEGORY_SYSTEM),
    4912: ("audit_policy_change", "warning", CATEGORY_SYSTEM),
    4688: ("process_created", "info", CATEGORY_SYSTEM),
    4689: ("process_exited", "info", CATEGORY_SYSTEM),
    4656: ("audit_object_access", "info", CATEGORY_SYSTEM),
    4663: ("audit_object_access", "info", CATEGORY_SYSTEM),
    4670: ("audit_permission_change", "warning", CATEGORY_SYSTEM),
    4673: ("audit_privilege_use", "info", CATEGORY_AUTH),
    4674: ("audit_privilege_use", "info", CATEGORY_AUTH),
    4703: ("audit_privilege_change", "warning", CATEGORY_AUTH),
    4704: ("audit_privilege_change", "warning", CATEGORY_AUTH),
}

_WINDOWS_AUTH = {
    4624: ("auth_success", "info"),
    4625: ("auth_failure", "warning"),
    4634: ("auth_logoff", "info"),
    4647: ("auth_logoff", "info"),
    4648: ("explicit_credentials", "warning"),
    4672: ("special_privileges", "info"),
    4740: ("account_lockout", "warning"),
    4768: ("kerberos_tgt_request", "info"),
    4769: ("kerberos_service_ticket", "info"),
    4770: ("kerberos_ticket_renewal", "info"),
    4771: ("kerberos_failure", "warning"),
    4776: ("ntlm_auth", "info"),
    4720: ("account_created", "warning"),
    4722: ("account_enabled", "warning"),
    4723: ("password_change", "warning"),
    4724: ("password_reset", "warning"),
    4725: ("account_disabled", "warning"),
    4726: ("account_deleted", "warning"),
    4738: ("account_changed", "warning"),
    4756: ("group_member_added", "warning"),
}

_WINDOWS_NETWORK = {
    5155: ("filtering_platform_block", "warning"),
    5156: ("network_connection_allowed", "info"),
    5157: ("network_connection_blocked", "warning"),
    5447: ("firewall_filter_change", "warning"),
    5140: ("network_share_access", "info"),
    5142: ("network_share_added", "info"),
    5143: ("network_share_changed", "info"),
    5144: ("network_share_deleted", "info"),
    5145: ("network_share_object_access", "info"),
}

_WINDOWS_SERVICE = {
    7036: ("service_state_change", "info"),
    7034: ("service_crash", "error"),
    7031: ("service_crash", "error"),
    7023: ("service_error", "error"),
    7024: ("service_error", "error"),
    7000: ("service_start_failure", "error"),
    7009: ("service_timeout", "error"),
    7011: ("service_timeout", "error"),
    7016: ("service_error", "error"),
    7040: ("service_start_type_change", "warning"),
    7042: ("service_state_change", "info"),
    7045: ("service_installed", "warning"),
    4697: ("service_installed", "warning"),
}

_WINDOWS_SYSTEM = {
    41: ("unexpected_shutdown", "critical"),
    1000: ("application_crash", "error"),
    1001: ("application_crash", "error"),
    1002: ("application_hang", "error"),
    1074: ("system_shutdown", "info"),
    6005: ("eventlog_started", "info"),
    6006: ("eventlog_stopped", "info"),
    6008: ("unexpected_shutdown", "critical"),
    6013: ("system_uptime", "info"),
}

# Sysmon (optional channel): event id -> (type, category, severity)
_WINDOWS_SYSMON = {
    1: ("process_created", CATEGORY_SYSTEM, "info"),
    3: ("network_connection", CATEGORY_NETWORK, "info"),
    8: ("process_access", CATEGORY_SYSTEM, "info"),
    10: ("process_access", CATEGORY_SYSTEM, "info"),
    11: ("file_created", CATEGORY_SYSTEM, "info"),
    22: ("dns_query", CATEGORY_NETWORK, "info"),
    23: ("file_deleted", CATEGORY_SYSTEM, "info"),
}

_DATABASE_PROVIDERS = (
    "mssql",
    "sqlserver",
    "sql server",
    "mysql",
    "mariadb",
    "postgres",
    "mongodb",
    "redis",
)

_WINDOWS_CHANNEL_DEFAULTS = {
    "application": (CATEGORY_SYSTEM, "system_event"),
    "system": (CATEGORY_SYSTEM, "system_event"),
    "security": (CATEGORY_AUTH, "authorization_event"),
    "microsoft-windows-windows firewall with advanced security/firewall": (
        CATEGORY_NETWORK,
        "firewall_event",
    ),
    "microsoft-windows-dns-client/operational": (CATEGORY_NETWORK, "dns_query"),
    "microsoft-windows-sysmon/operational": (CATEGORY_SYSTEM, "sysmon_event"),
}


def classify_windows_event(
    *,
    event_id: int,
    provider: str = "",
    channel: str = "",
    level: Optional[int] = None,
    message: str = "",
    default_category: Optional[str] = None,
    default_type: Optional[str] = None,
) -> Classification:
    """Classify one Windows Event Log record."""
    provider_l = (provider or "").lower()
    channel_l = (channel or "").lower()
    base_severity = map_windows_level(level)

    # 1. Database providers win regardless of channel.
    if any(token in provider_l for token in _DATABASE_PROVIDERS):
        event_type = _refine_linux_type(CATEGORY_DB, message, "database_event")
        return Classification(
            CATEGORY_DB,
            event_type,
            max_severity(base_severity, infer_severity_from_text(message)),
            "windows.database-provider",
        )

    # 2. Sysmon (if enabled).
    if "sysmon" in provider_l or "sysmon" in channel_l:
        sysmon = _WINDOWS_SYSMON.get(event_id)
        if sysmon:
            event_type, category, severity = sysmon
            return Classification(
                category,
                event_type,
                max_severity(base_severity, severity),
                "windows.sysmon",
            )

    # 3. Audit/security Event Log records (not a separate benchmark feed).
    if event_id in _WINDOWS_AUDIT:
        event_type, severity, category = _WINDOWS_AUDIT[event_id]
        return Classification(
            category,
            event_type,
            max_severity(base_severity, severity),
            "windows.audit",
        )

    # 4. Authorization events.
    if event_id in _WINDOWS_AUTH:
        event_type, severity = _WINDOWS_AUTH[event_id]
        return Classification(
            CATEGORY_AUTH,
            event_type,
            max_severity(base_severity, severity),
            "windows.authorization",
        )

    # 5. Network events.
    if event_id in _WINDOWS_NETWORK:
        event_type, severity = _WINDOWS_NETWORK[event_id]
        return Classification(
            CATEGORY_NETWORK,
            event_type,
            max_severity(base_severity, severity),
            "windows.network",
        )

    # 6. Service lifecycle events.
    if event_id in _WINDOWS_SERVICE:
        event_type, severity = _WINDOWS_SERVICE[event_id]
        return Classification(
            CATEGORY_SERVICE,
            event_type,
            max_severity(base_severity, severity),
            "windows.service",
        )

    # 7. General system events.
    if event_id in _WINDOWS_SYSTEM:
        event_type, severity = _WINDOWS_SYSTEM[event_id]
        return Classification(
            CATEGORY_SYSTEM,
            event_type,
            max_severity(base_severity, severity),
            "windows.system",
        )

    # 8. Fall back to the channel's natural category.
    category, type_ = _WINDOWS_CHANNEL_DEFAULTS.get(channel_l, (None, None))
    category = default_category or category or CATEGORY_SYSTEM
    type_ = default_type or type_ or "system_event"

    severity = max_severity(base_severity, infer_severity_from_text(message))
    return Classification(category, type_, severity, "windows.channel-default")
