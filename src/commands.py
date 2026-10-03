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

import control
from config import DEFAULT_CONFIG, DEFAULT_STATUS, ConfigError, load_config
from diagnostics import diagnose
from reporting import show_status
from runtime import Collector, shutdown_signals
from scanner import IwScanner


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
