# Collector log-source coverage

This document describes what the collector subscribes to on each platform,
which contract category each domain maps to, and what must be enabled on the
host for the source to actually produce events.

## Domain → contract category

| Requested domain | `category` | Linux source | Windows source |
|---|---|---|---|
| authorization | `auth` | journald: sshd, sudo, su, PAM, logind, polkit (fallback: `/var/log/auth.log`, `/var/log/secure`) | `Security` channel: 4624/4625/4648/4672/47xx |
| network | `network` | journald: kernel firewall, NetworkManager, networkd, DHCP, VPN (fallback: ufw/firewalld files) | `Security` 5155/5156/5157/5447; `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` |
| syslog | `syslog` | journald, plus `/var/log/syslog`, `/var/log/messages`, rsyslog/syslog-ng files when journald is unavailable or `LAD_SYSLOG_LOG_GLOBS` is set | optional syslog relay files via `LAD_SYSLOG_LOG_GLOBS` (Windows has no native syslog) |
| service | `service` | journald systemd unit lifecycle (fallback: syslog) | `System`: Service Control Manager 70xx IDs (other System events stay `system`) |
| event log | `system` | audit records delivered through journald are classified as system/audit events | `Application` + `System` + `Security` channels |
| database log | `db` | PostgreSQL, MySQL/MariaDB, MongoDB, Redis, SQL Server files | SQL Server ERRORLOG, MySQL/PostgreSQL/MongoDB files + `Application` DB providers |

`syslog` is used for general Linux system/syslog messages that do not match a
more specific domain. `system` is used for the Windows Event Log and for audit
records that arrive through journald. Authentication, network, service and
database messages are reclassified into their own categories even when they
arrive through syslog/journald.

Classification is implemented in `collectors/core/classifier.py` and is rule
based (identifiers, message patterns, Windows event IDs/providers). The raw
source-specific fields are preserved under the event's `attributes`.

## Running

From the directory that contains `collectors/`:

```bash
python3 -m collectors
```

Useful development commands:

```bash
# Unit tests
python3 -m unittest discover -s collectors/tests -t . -v

# Local mock ingestion API (writes collectors/var/received_events.jsonl)
python3 -m collectors.tools.mock_receiver
```

## Host requirements

### Linux

- **journald**: `systemd-python` must be installed and the collector user must
  be able to read the journal (member of `systemd-journal`, `adm`, or root).
  On systemd hosts journald is the primary syslog source.
- **syslog files**: if journald is unavailable, rsyslog/syslog-ng must write
  `/var/log/syslog` (Debian/Ubuntu) or `/var/log/messages` (RHEL/Fedora), or
  `LAD_SYSLOG_LOG_GLOBS` must point at the actual files. Existing files are
  tailed from the end unless `LAD_FILE_TAIL_FROM_START=1`.
- **network**: kernel firewall logs (ufw/firewalld/nftables) or
  NetworkManager/networkd messages must be enabled/logged.
- **audit**: auditd is optional. Audit records that reach journald are emitted
  as `system` / `audit_*` events; there is no separate benchmark source.
- **database**: the database server must be configured to write an error log
  file (or to journald). Default globs cover the common distributions; use
  `LAD_DATABASE_LOG_GLOBS` for custom paths.

### Windows

- Run the collector **as Administrator**; the `Security` channel is not
  readable by a standard user. If elevation is missing, the source is logged
  as unavailable and the other sources keep running.
- **authorization/event log**: enable the corresponding Advanced Audit Policy
  subcategories (logon, account management, policy change, process creation,
  object access). Without audit policy, Windows does not generate these events.
- **network**: enable Windows Defender Firewall logging for dropped/allowed
  packets and/or "Audit Filtering Platform Connection" if you need WFP events.
  These are off by default.
- **syslog**: Windows does not emit syslog natively. If a syslog relay (Kiwi,
  SolarWinds, syslog-ng, rsyslog, etc.) writes files on the host, set
  `LAD_SYSLOG_LOG_GLOBS` to those files.
- **Sysmon**: optional, enabled with `LAD_WINDOWS_SYSMON=1` if the
  `Microsoft-Windows-Sysmon/Operational` channel is installed. Process/file
  events are `system`; network/DNS events are `network`.
- **database**: SQL Server must be installed with its normal `ERRORLOG` path,
  or set `LAD_DATABASE_LOG_GLOBS`.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `LAD_COLLECTOR_ENDPOINT` | `http://localhost:8080/api/v1/events/batch` | Ingestion URL |
| `LAD_COLLECTOR_TOKEN` | `dev-secret-token` (dev only) | Collector credential |
| `LAD_MAX_BATCH_EVENTS` | `100` | Events per batch |
| `LAD_MAX_BATCH_BYTES` | `262144` | Batch byte limit |
| `LAD_FLUSH_INTERVAL_SECONDS` | `3` | Time-based flush |
| `LAD_BUFFER_MAX_EVENTS` | `2000` | In-memory buffer bound |
| `LAD_SEND_TIMEOUT_SECONDS` | `10` | HTTP timeout |
| `LAD_SEND_RETRIES` | `3` | Retry attempts for retryable failures |
| `LAD_MAX_MESSAGE_CHARS` | `8192` | Message truncation limit |
| `LAD_MAX_ATTRIBUTE_CHARS` | `4096` | Per-attribute string limit |
| `LAD_DEBUG_PAYLOAD` | off | Log full outbound payloads (sensitive) |
| `LAD_DEBUG_STREAMS` | off | Include tracebacks for source failures |
| `LAD_LINUX_FILE_SOURCES` | `0` | Force Linux file sources alongside journald (may duplicate) |
| `LAD_FILE_TAIL_FROM_START` | `0` | Backfill existing files instead of tailing from the end |
| `LAD_LOG_TIMEZONE` | host timezone | Timezone for file timestamps without an offset (e.g. `UTC`) |
| `LAD_DATABASE_LOG_GLOBS` | platform defaults | Comma/semicolon separated DB log globs |
| `LAD_SYSLOG_LOG_GLOBS` | Linux defaults, empty on Windows | Comma/semicolon separated syslog file globs |
| `LAD_WINDOWS_CHANNELS` | default channel set | Explicit comma-separated channel list |
| `LAD_WINDOWS_FIREWALL_EVENTS` | `1` | Enable the Windows firewall channel |
| `LAD_WINDOWS_SYSMON` | `0` | Enable Sysmon if installed |
| `LAD_WINDOWS_DNS_CLIENT` | `0` | Enable the high-volume DNS Client channel |

## Known limitations / contract notes

- **Category values changed.** Events now use `auth`, `network`, `syslog`,
  `service`, `system`, `db`. If the ingestion schema restricts `category` or
  `source` to an enum, extend that enum (or map these values).
- **File-based syslog/DB logs are line oriented.** Multi-line stack traces are
  emitted as separate events; a proper multi-line parser is a follow-up.
- **Restart gap.** Journald/Windows subscriptions start at the tail; events
  produced while the collector is down are not replayed. File sources resume
  at their in-memory offset after a source restart, but not after a process
  restart. A persistent cursor/spool is a follow-up.
- **Duplicate risk.** `LAD_LINUX_FILE_SOURCES=1` and `LAD_SYSLOG_LOG_GLOBS`
  can read files that journald already captured. The collector warns, but does
  not deduplicate across sources.
- **Redaction is best effort.** Password/token/header/JWT/AWS-key/URI
  patterns and attribute recursion are covered, but regexes cannot guarantee
  detection of every secret format.
- **Windows runtime verification.** The Windows reader compiles and was
  exercised with synthetic event XML, but must be validated on a real Windows
  11 host (especially `EvtSubscribe`/`EvtFormatMessage` behavior and channel
  availability).
