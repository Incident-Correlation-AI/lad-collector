#!/usr/bin/env python3
"""Generate real failed-logon (4625) events on this Windows host.

The collector is pull-based: it has no listener, so logs cannot be POSTed into
it.  It reads the Windows Security/System/Application channels plus configured
log files.  This tool therefore *produces genuine Windows audit failures on the
local machine* -- failed SMB logons -- which the collector already subscribes
to and classifies as ``category=auth`` / ``type=auth_failure``.

Once the collector ships them to the ingestion API they show up in the
dashboard like any other authorization event, with no mock receiver involved.

Requirements
------------
* Windows, run from an elevated shell.  The Security channel is not readable,
  and ``auditpol`` is not writable, without administrator rights.
* Failure auditing for the "Logon" subcategory.  ``--enable-audit`` turns it
  on; without it Windows does not write 4625 events at all.

Usage (elevated PowerShell)
---------------------------
    python tools\\attack_local_auth.py --count 25 --enable-audit

The script re-launches itself elevated if you forget the elevation.
"""

from __future__ import annotations

import argparse
import csv
import ctypes
import io
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timedelta

TARGET_EVENT_ID = 4625  # An account failed to log on
DEFAULT_SERVER = r"\\127.0.0.1\IPC$"
DEFAULT_ACCOUNT = "lad-attack"
DEFAULT_PASSWORD = "definitely-not-the-password"


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated(argv: list[str]) -> bool:
    """Re-open this script in an elevated console. Returns True if launched."""
    script = os.path.abspath(sys.argv[0])
    if script.lower().endswith(".py"):
        arguments = f'"{script}" ' + " ".join(f'"{a}"' if " " in a else a for a in argv)
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, arguments, None, 1
        )
    else:
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", script, " ".join(f'"{a}"' if " " in a else a for a in argv), None, 1
        )
    return rc > 32


def _run(cmd: list[str], timeout: float = 60.0) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


# ---------------------------------------------------------------------------
# Audit policy
# ---------------------------------------------------------------------------
def logon_audit_setting() -> str | None:
    """Return the inclusion setting for the 'Logon' subcategory (CSV output)."""
    proc = _run(["auditpol", "/get", "/category:*", "/r"])
    if proc.returncode != 0 or not proc.stdout.strip():
        return None

    text = proc.stdout.lstrip("\ufeff")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return None

    fields = {name.strip().lower(): name for name in reader.fieldnames}
    subcategory = fields.get("subcategory")
    inclusion = fields.get("inclusion setting")
    if not subcategory or not inclusion:
        return None

    for row in reader:
        if (row.get(subcategory) or "").strip().lower() == "logon":
            return (row.get(inclusion) or "").strip()
    return None


def enable_logon_failure_audit() -> bool:
    proc = _run(["auditpol", "/set", "/subcategory:Logon", "/failure:enable"])
    return proc.returncode == 0


def audit_allows_failures(setting: str | None) -> bool:
    return bool(setting) and "failure" in setting.lower()


# ---------------------------------------------------------------------------
# The attack
# ---------------------------------------------------------------------------
def clear_existing_session(server: str) -> None:
    """Remove any stale connection so credentials are re-evaluated."""
    _run(["net", "use", server, "/delete", "/y"], timeout=30)


def failed_logon(server: str, account: str, password: str) -> subprocess.CompletedProcess:
    """Attempt an SMB logon with bad credentials.

    Each rejected attempt makes LSA write a 4625 audit failure to the Security
    log, which is exactly what the collector reads.
    """
    return _run(["net", "use", server, f"/user:{account}", password], timeout=30)


def count_4625(since: datetime) -> int:
    stamp = since.strftime("%Y-%m-%d %H:%M:%S")
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$s=[datetime]'{stamp}';"
        f"@(Get-WinEvent -FilterHashtable @{{LogName='Security';Id={TARGET_EVENT_ID};StartTime=$s}})"
        ".Count"
    )
    proc = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=120,
    )
    out = (proc.stdout or "").strip()
    return int(out) if out.isdigit() else 0


def sample_4625(since: datetime, limit: int = 2) -> list[str]:
    stamp = since.strftime("%Y-%m-%d %H:%M:%S")
    script = (
        "$ErrorActionPreference='SilentlyContinue';"
        f"$s=[datetime]'{stamp}';"
        f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id={TARGET_EVENT_ID};StartTime=$s}} "
        f"-MaxEvents {limit} | ForEach-Object {{ ($_.Message -replace \"`r`n\", ' ') }}"
    )
    proc = _run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=120,
    )
    lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    return [line[:200] for line in lines]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)

    parser = argparse.ArgumentParser(
        description="Produce real Windows 4625 failed-logon events for the LAD collector.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--count", type=int, default=25, help="failed logons to attempt")
    parser.add_argument(
        "--interval",
        type=float,
        default=0.05,
        help="seconds between attempts (0 = as fast as possible)",
    )
    parser.add_argument("--account", default=DEFAULT_ACCOUNT, help="account name to fail against")
    parser.add_argument("--password", default=DEFAULT_PASSWORD, help="wrong password to use")
    parser.add_argument("--server", default=DEFAULT_SERVER, help="SMB path to authenticate to")
    parser.add_argument("--unique-users", action="store_true", help="vary the account name per attempt")
    parser.add_argument("--enable-audit", action="store_true", help="enable Logon failure auditing")
    parser.add_argument("--wait", type=float, default=20.0, help="seconds to wait for events to appear")
    parser.add_argument("--no-elevate", action="store_true", help="do not re-launch as administrator")
    parser.add_argument("--dry-run", action="store_true", help="show the plan without touching anything")
    args = parser.parse_args(argv)

    if not is_windows():
        print("This tool only works on Windows (the collector reads the Windows Event Log).")
        return 1

    if not is_admin():
        if args.no_elevate:
            print("Not elevated: the Security channel cannot be read or written.")
            print("Re-run this command from an Administrator PowerShell.")
            return 2
        print("Not elevated - requesting administrator rights...")
        if relaunch_elevated(argv):
            print("Elevated console launched. Continue there.")
            return 0
        print("Elevation was refused. Re-run from an Administrator PowerShell.")
        return 2

    print("=" * 70)
    print("LAD collector - local authorization attack (Windows 4625)")
    print("=" * 70)

    setting = logon_audit_setting()
    if setting is None:
        print("Could not read the audit policy for the 'Logon' subcategory.")
        print("Continuing, but Windows may not log 4625 events.")
    else:
        print(f"Logon audit policy: {setting}")

    if setting is not None and not audit_allows_failures(setting):
        if args.enable_audit:
            print("Enabling 'Logon' failure auditing...")
            if enable_logon_failure_audit():
                setting = logon_audit_setting()
                print(f"Logon audit policy is now: {setting}")
            else:
                print("Failed to enable failure auditing; run as Administrator.")
                return 2
        else:
            print()
            print("Windows is not auditing failed logons, so no 4625 events will be")
            print("written and the collector will see nothing. Fix it with either:")
            print()
            print('    auditpol /set /subcategory:"Logon" /failure:enable')
            print()
            print("...or re-run this script with --enable-audit.")
            return 2

    if args.count < 1:
        print("--count must be at least 1.")
        return 2

    started = datetime.now() - timedelta(seconds=1)
    print(f"Target      : {args.server}")
    print(f"Attempts    : {args.count} every {args.interval:.2f}s")
    print(f"Account     : {args.account}{' (unique per attempt)' if args.unique_users else ''}")
    print(f"Expected    : {args.count} x event ID {TARGET_EVENT_ID} in the Security log")

    if args.dry_run:
        print("\nDry run: nothing was sent.")
        return 0

    clear_existing_session(args.server)
    rejected = 0
    other_errors: list[str] = []

    print()
    try:
        for index in range(1, args.count + 1):
            account = (
                f"{args.account}{random.randint(1000, 9999)}"
                if args.unique_users
                else args.account
            )
            result = failed_logon(args.server, account, args.password)
            output = f"{result.stdout or ''}{result.stderr or ''}".strip()
            if "1326" in output or "logon failure" in output.lower():
                rejected += 1
                status = "logon failure"
            else:
                other_errors.append(output.splitlines()[0] if output else f"exit {result.returncode}")
                status = other_errors[-1]
            print(f"  [{index:3d}/{args.count}] {account}: {status}")
            if index < args.count:
                time.sleep(max(0.0, args.interval))
    except KeyboardInterrupt:
        print("\nInterrupted; continuing with verification.")
    finally:
        clear_existing_session(args.server)

    print()
    print(f"Failed logons attempted: {rejected}/{args.count}")
    if other_errors:
        print(f"Unexpected results ({len(other_errors)}), first: {other_errors[0]}")
        print("Error 53/67 means SMB to localhost is unavailable; 1219 means an")
        print("existing session is using different credentials.")

    print(f"\nWaiting up to {args.wait:.0f}s for Windows to write the audit records...")
    deadline = time.monotonic() + max(0.0, args.wait)
    seen = count_4625(started)
    while seen < args.count and time.monotonic() < deadline:
        time.sleep(1)
        seen = count_4625(started)

    print(f"4625 events in the Security log since the attack started: {seen}")

    if seen == 0:
        print()
        print("No audit records were written, so there is nothing for the collector")
        print("to read. Check that logon failure auditing is enabled and that the")
        print("'Workstation' service is running.")
        return 2

    for line in sample_4625(started):
        print(f"  sample: {line}")

    print()
    print("=" * 70)
    print("Next: the elevated collector should now ship these to the ingestion API.")
    print("Look for this line in its console:")
    print()
    print(f"    Shipped {seen} events (<bytes>) with status 202.")
    print()
    print("Then check the dashboard for category=auth / type=auth_failure events.")
    print("If the collector logs 'source unavailable: access denied reading")
    print("Security', it is not elevated.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
