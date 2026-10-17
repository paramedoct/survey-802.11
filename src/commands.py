from __future__ import annotations

import argparse
import json
import logging
import sqlite3
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from threading import Event
from typing import cast

import control
from backup import send_backup
from config import DEFAULT_CONFIG, DEFAULT_STATUS, ConfigError, load_config
from diagnostics import diagnose
from history import query_history
from interface_control import prepare_interface, restore_interface
from migration import migrate
from monthly_migration import migrate_monthly
from reporting import show_status
from runtime import Collector, shutdown_signals
from scanner import IwScanner


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
        "migrate",
        "migrate-monthly",
        "history",
    ):
        command = subparsers.add_parser(name)
        command.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    subparsers.choices["migrate"].add_argument("--backup", type=Path, required=True)
    subparsers.choices["migrate"].add_argument(
        "--minimum-free-bytes", type=int, default=0
    )
    subparsers.choices["migrate-monthly"].add_argument(
        "--destination", type=Path, required=True
    )
    subparsers.choices["history"].add_argument("--bssid")
    subparsers.choices["history"].add_argument("--scan-id", type=int)
    subparsers.choices["history"].add_argument("--before-id", type=int)
    subparsers.choices["history"].add_argument("--limit", type=int, default=100)
    subparsers.add_parser("restore-interface")
    for name in ("start", "stop", "restart", "enable", "disable"):
        subparsers.add_parser(name)
    for name in ("collect", "status"):
        subparsers.choices[name].add_argument(
            "--status-path", type=Path, default=DEFAULT_STATUS
        )
    subparsers.choices["status"].add_argument("--json", action="store_true")
    return parser


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
        if arguments.command == "restore-interface":
            restore_interface()
            return 0
        config = load_config(arguments.config)
        if arguments.command == "migrate":
            migrate(
                config.database_path, arguments.backup, arguments.minimum_free_bytes
            )
            print(f"migration complete; original snapshot: {arguments.backup}")
            return 0
        if arguments.command == "migrate-monthly":
            migrate_monthly(config.database_path, arguments.destination)
            print(f"monthly migration complete: {arguments.destination}")
            return 0
        if arguments.command == "backup":
            if config.database_layout == "monthly":
                return send_backup(config.database_path, layout="monthly")
            return send_backup(config.database_path)
        if arguments.command == "history":
            rows = query_history(
                config.database_path,
                config.database_layout,
                bssid=arguments.bssid,
                scan_id=arguments.scan_id,
                before_id=arguments.before_id,
                limit=arguments.limit,
            )
            for row in rows:
                raw = row.get("ssid_bytes")
                row["ssid_bytes"] = (
                    {"hex": raw.hex()} if isinstance(raw, bytes) else None
                )
            print(json.dumps(rows, sort_keys=True))
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
