from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path
from threading import Event

from config import AppConfig
from model import ScanError
from reporting import existing_parent
from runtime import shutdown_signals
from scanner import IwScanner, run_command
from storage import read_summary


def _rfkill_status(device: str) -> tuple[bool, str]:
    phy = Path("/sys/class/net") / device / "phy80211"
    if not phy.exists():
        return False, "wireless phy is missing"
    entries = list(phy.glob("rfkill*"))
    if not entries:
        return False, "rfkill state is unavailable"
    for entry in entries:
        soft = (entry / "soft").read_text().strip()
        hard = (entry / "hard").read_text().strip()
        if soft != "0" or hard != "0":
            return False, f"blocked (soft={soft}, hard={hard})"
    return True, "unblocked"


def diagnose(config: AppConfig) -> int:
    failed = False

    def report(name: str, passed: bool, detail: str) -> None:
        nonlocal failed
        failed |= not passed
        print(f"{name}: {'ok' if passed else 'failed'} ({detail})")

    print(f"python: {sys.version.split()[0]}")
    tools_found = True
    for name in ("iw", "ip", "systemctl"):
        executable = shutil.which(name)
        if name in {"iw", "ip"}:
            tools_found &= executable is not None
        report(name, executable is not None, executable or "not found")
    report(
        "permissions",
        os.geteuid() == 0,
        f"effective uid={os.geteuid()}; actual scan checks wireless capabilities",
    )
    device_found = (Path("/sys/class/net") / config.device).exists()
    report("device", device_found, config.device)
    try:
        passed, detail = _rfkill_status(config.device)
        report("rfkill", passed, detail)
    except OSError as error:
        report("rfkill", False, str(error))
    try:
        parent = existing_parent(config.database_path)
        usage = shutil.disk_usage(parent)
        report("storage_space", usage.free > 0, f"{usage.free} bytes free on {parent}")
        if config.database_path.exists():
            report(
                "database_permissions",
                os.access(config.database_path, os.R_OK | os.W_OK),
                str(config.database_path),
            )
            summary = read_summary(config.database_path)
            report(
                "database_schema", bool(summary["available"]), str(config.database_path)
            )
        # Test writing and flushing without modifying the collection database.
        with tempfile.TemporaryFile(dir=parent) as stream:
            stream.write(b"survey-802.11 storage probe\n")
            stream.flush()
            os.fsync(stream.fileno())
        report("storage_write", True, str(parent))
    except (OSError, sqlite3.Error, RuntimeError) as error:
        report("storage_write", False, str(error))
    if tools_found and device_found:
        stop = Event()
        try:
            with shutdown_signals(stop):
                info = run_command(["iw", "dev", config.device, "info"], 5, stop)
                report(
                    "wireless_device",
                    True,
                    info.decode("utf-8", errors="replace").strip(),
                )
                link = run_command(["iw", "dev", config.device, "link"], 5, stop)
                report(
                    "scan_only",
                    link.strip() == b"Not connected.",
                    link.decode("utf-8", errors="replace").strip(),
                )
                scanner = IwScanner(config.device)
                scanner.prepare(stop)
                observations = scanner.scan(config.timeout_s, stop)
                report(
                    "active_scan",
                    True,
                    f"{len(observations)} observations; no data saved",
                )
        except ScanError as error:
            report("active_scan", False, str(error))
    else:
        report("active_scan", False, "required tools or device missing")
    return int(failed)
