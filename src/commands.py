from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from threading import Event
from typing import cast

import control
from config import DEFAULT_CONFIG, DEFAULT_STATUS, AppConfig, ConfigError, load_config
from runtime import Collector, shutdown_signals
from scanner import IwScanner, ScanError, run_command
from storage import read_summary


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="survey-802.11")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("collect", "validate", "status", "diagnose"):
        command = subparsers.add_parser(name)
        command.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    for name in ("start", "stop", "restart", "enable", "disable"):
        subparsers.add_parser(name)
    for name in ("collect", "status"):
        subparsers.choices[name].add_argument(
            "--status-path", type=Path, default=DEFAULT_STATUS
        )
    subparsers.choices["status"].add_argument("--json", action="store_true")
    return parser


def _existing_parent(path: Path) -> Path:
    parent = path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    return parent


def _disk_status(path: Path) -> dict[str, object]:
    files = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
    sizes = {file.name: file.stat().st_size if file.exists() else 0 for file in files}
    return {
        "path": str(path),
        "file_sizes_bytes": sizes,
        "total_size_bytes": sum(sizes.values()),
        "disk_free_bytes": shutil.disk_usage(_existing_parent(path)).free,
    }


def _status(config: AppConfig, status_path: Path, as_json: bool) -> int:
    try:
        value = json.loads(status_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("runtime status must be an object")
        runtime: dict[str, object] = cast(dict[str, object], value)
        if runtime.get("database_path") != str(config.database_path):
            raise ValueError("runtime status describes a different database")
    except (OSError, ValueError) as error:
        runtime = {"available": False, "error": str(error)}
    payload: dict[str, dict[str, object]] = {
        "service": dict(control.service_status()),
        "runtime": runtime,
        "history": read_summary(config.database_path),
        "storage": _disk_status(config.database_path),
    }
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        for section, values in payload.items():
            print(f"{section}:")
            for key, item in values.items():
                print(f"  {key}: {item}")
    return 0


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


def _diagnose(config: AppConfig) -> int:
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
        parent = _existing_parent(config.database_path)
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


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    try:
        if arguments.command in {"start", "stop", "restart", "enable", "disable"}:
            if arguments.command in {"start", "restart", "enable"}:
                load_config(DEFAULT_CONFIG)
            return control.manage(cast(control.Action, arguments.command))
        config = load_config(arguments.config)
        if arguments.command == "validate":
            print(
                f"configuration valid: device={config.device}, "
                f"interval={config.interval_s}s, timeout={config.timeout_s}s"
            )
            return 0
        if arguments.command == "status":
            return _status(config, arguments.status_path, arguments.json)
        if arguments.command == "diagnose":
            return _diagnose(config)
        stop = Event()
        with shutdown_signals(stop):
            Collector(
                config, IwScanner(config.device), arguments.status_path, stop=stop
            ).run()
        return 0
    except (
        ConfigError,
        OSError,
        RuntimeError,
        sqlite3.Error,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
