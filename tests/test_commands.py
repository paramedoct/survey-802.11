from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import commands
import control
from config import AppConfig
from model import Observation
from scanner import ScanError
from storage import Storage, read_summary
from tests.test_config_storage import sample_scan


class CommandTests(unittest.TestCase):
    def test_validate_and_invalid_configuration_exit_codes(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = commands.main(
                ["validate", "--config", "config/survey-802.11.example.toml"]
            )
        self.assertEqual(result, 0)
        self.assertIn("interval=60s", output.getvalue())
        with redirect_stderr(output):
            result = commands.main(["validate", "--config", "/missing.toml"])
        self.assertEqual(result, 1)

    def test_every_service_action_and_root_requirement(self) -> None:
        for action in ("start", "stop", "restart", "enable", "disable"):
            with (
                self.subTest(action=action),
                patch("commands.load_config", return_value=AppConfig()) as load,
                patch("control.os.geteuid", return_value=0),
                patch(
                    "control.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0),
                ) as run,
            ):
                self.assertEqual(commands.main([action]), 0)
                expected = ["systemctl", action]
                if action in {"enable", "disable"}:
                    expected.append("--now")
                expected.append("survey-802.11.service")
                self.assertEqual(run.call_args.args[0], expected)
                self.assertEqual(
                    load.call_count, int(action in {"start", "restart", "enable"})
                )
        with (
            patch("control.os.geteuid", return_value=1000),
            self.assertRaises(PermissionError),
        ):
            control.manage("start")
        with (
            patch("control.os.geteuid", return_value=0),
            patch(
                "control.subprocess.run",
                return_value=subprocess.CompletedProcess([], 7),
            ),
        ):
            self.assertEqual(control.manage("stop"), 7)

    def test_status_reports_history_runtime_and_wal_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "history.db"
            config = AppConfig(database_path=path)
            status = root / "status.json"
            status.write_text(
                json.dumps(
                    {
                        "database_path": str(path),
                        "last_commit_at": "recent",
                        "running": False,
                    }
                )
            )
            with Storage(path) as storage:
                storage.save(sample_scan(Observation("aa:bb:cc:dd:ee:ff", 2412)))
                storage.save(
                    replace(sample_scan(), status="timeout", error="timed out")
                )
                output = io.StringIO()
                with (
                    patch("commands.load_config", return_value=config),
                    patch(
                        "control.service_status", return_value={"ActiveState": "active"}
                    ),
                    redirect_stdout(output),
                ):
                    self.assertEqual(
                        commands.main(
                            ["status", "--status-path", str(status), "--json"]
                        ),
                        0,
                    )
                payload = json.loads(output.getvalue())
                self.assertEqual(payload["service"]["ActiveState"], "active")
                self.assertEqual(payload["history"]["successful_scans"], 1)
                self.assertEqual(payload["history"]["failed_scans"], 1)
                self.assertEqual(payload["history"]["last_error"], "timed out")
                self.assertEqual(payload["runtime"]["last_commit_at"], "recent")
                self.assertGreater(
                    payload["storage"]["file_sizes_bytes"]["history.db-wal"], 0
                )
                self.assertGreater(payload["storage"]["disk_free_bytes"], 0)

    def test_missing_or_invalid_status_does_not_create_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AppConfig(database_path=root / "nested" / "missing.db")
            for content in (
                None,
                "invalid json",
                "[]",
                '{"database_path": "/other.db"}',
            ):
                status = root / "status.json"
                if content is not None:
                    status.write_text(content)
                output = io.StringIO()
                with (
                    redirect_stdout(output),
                    patch(
                        "control.service_status",
                        return_value={"ActiveState": "inactive"},
                    ),
                ):
                    self.assertEqual(commands._status(config, status, True), 0)
                payload = json.loads(output.getvalue())
                self.assertFalse(payload["runtime"]["available"])
                self.assertFalse(payload["history"]["available"])
            self.assertFalse(config.database_path.exists())

    def test_diagnose_actual_scan_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = AppConfig(database_path=Path(directory) / "history.db")
            for failure in (False, True):
                with (
                    self.subTest(failure=failure),
                    patch("commands.shutil.which", return_value="/tool"),
                    patch("commands.os.geteuid", return_value=0),
                    patch("commands.Path.exists", return_value=True),
                    patch("commands._rfkill_status", return_value=(True, "unblocked")),
                    patch("commands.read_summary", return_value={"available": True}),
                    patch("commands.os.access", return_value=True),
                    patch(
                        "commands.run_command",
                        side_effect=[b"Interface wlan0", b"Not connected.\n"],
                    ),
                    patch("commands.IwScanner") as scanner,
                    redirect_stdout(io.StringIO()),
                ):
                    if failure:
                        scanner.return_value.scan.side_effect = ScanError(
                            "permission denied"
                        )
                    else:
                        scanner.return_value.scan.return_value = ()
                    self.assertEqual(commands._diagnose(config), int(failure))
                    scanner.return_value.prepare.assert_called_once()
                    scanner.return_value.scan.assert_called_once()

    def test_collect_storage_failure_returns_nonzero(self) -> None:
        output = io.StringIO()
        with (
            patch("commands.load_config", return_value=AppConfig()),
            patch("commands.Collector") as collector,
            redirect_stderr(output),
        ):
            collector.return_value.run.side_effect = sqlite3.OperationalError(
                "disk full"
            )
            self.assertEqual(commands.main(["collect"]), 1)
        self.assertIn("disk full", output.getvalue())

    def test_service_status_unavailable_and_properties(self) -> None:
        with patch("control.subprocess.run", side_effect=FileNotFoundError("missing")):
            self.assertIn("error", control.service_status())
        with patch(
            "control.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [], 0, "ActiveState=active\nUnitFileState=enabled\n", ""
            ),
        ):
            self.assertEqual(
                control.service_status(),
                {"ActiveState": "active", "UnitFileState": "enabled"},
            )

    def test_summary_supports_paths_with_uri_characters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "special ?# file.db"
            with Storage(path) as storage:
                storage.save(sample_scan())
            self.assertEqual(read_summary(path)["successful_scans"], 1)
            self.assertTrue(os.path.exists(path))
