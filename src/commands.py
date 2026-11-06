from __future__ import annotations

import argparse
import logging
import sqlite3
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from threading import Event
from typing import cast

from collection.collector import Collector, shutdown_signals
from collection.scanner import IwScanner
from config import DEFAULT_CONFIG, DEFAULT_STATUS, ConfigError, load_config
from storage.backup import send_backup
from storage.history import list_ssids
from system import service
from system.diagnostics import diagnose
from system.indicator import indicate
from system.interface import prepare_interface, restore_interface
from system.status import show_status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="survey-802.11")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in (
        "collect",
        "validate",
        "status",
        "diagnose",
        "prepare-interface",
        "backup",
        "history",
    ):
        command = subparsers.add_parser(name)
        command.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers.choices["history"].description = (
        "List observed SSIDs with detection counts by scan and latest observation "
        "time, newest first (UTC)."
    )
    subparsers.add_parser("restore-interface")
    indicator = subparsers.add_parser("indicate-status")
    indicator.add_argument("--status-path", type=Path, default=DEFAULT_STATUS)
    for name in ("start", "stop", "restart", "enable", "disable"):
        subparsers.add_parser(name)
    for name in ("collect", "status"):
        subparsers.choices[name].add_argument(
            "--status-path", type=Path, default=DEFAULT_STATUS
        )
    subparsers.choices["status"].add_argument("--json", action="store_true")
    return parser


def _ssid_label(raw: bytes | None) -> str:
    if raw is None:
        return "<unknown>"
    if not raw:
        return "<hidden>"
    try:
        label = raw.decode("utf-8")
    except UnicodeDecodeError:
        return f"<hex:{raw.hex()}>"
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in label
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    try:
        if arguments.command in {"start", "stop", "restart", "enable", "disable"}:
            if arguments.command in {"start", "restart", "enable"}:
                load_config(DEFAULT_CONFIG)
            return service.manage(cast(service.Action, arguments.command))
        if arguments.command == "restore-interface":
            restore_interface()
            return 0
        if arguments.command == "indicate-status":
            stop = Event()
            with shutdown_signals(stop):
                indicate(arguments.status_path, stop)
            return 0
        config = load_config(arguments.config)
        if arguments.command == "backup":
            return send_backup(config.database_path, layout=config.database_layout)
        if arguments.command == "history":
            rows = list_ssids(config.database_path, config.database_layout)
            if not rows:
                print("No SSIDs observed.")
                return 0
            dates = [row.updated_at.isoformat(sep=" ") for row in rows]
            width = max(len("UPDATED AT (UTC)"), *(len(date) for date in dates))
            count_width = max(
                len("COUNT"), *(len(str(row.detection_count)) for row in rows)
            )
            print(f"{'UPDATED AT (UTC)':<{width}}  {'COUNT':>{count_width}}  SSID")
            for row, date in zip(rows, dates, strict=True):
                print(
                    f"{date:<{width}}  {row.detection_count:>{count_width}}  "
                    f"{_ssid_label(row.ssid_bytes)}"
                )
            return 0
        if arguments.command == "prepare-interface":
            prepare_interface(config.device)
            return 0
        if arguments.command == "validate":
            print(
                f"configuration valid: device={config.device}, "
                f"interval={config.interval_s}s, timeout={config.timeout_s}s"
            )
            return 0
        if arguments.command == "status":
            return show_status(config, arguments.status_path, arguments.json)
        if arguments.command == "diagnose":
            return diagnose(config)
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
