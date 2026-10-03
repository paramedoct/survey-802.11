from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import commands
import reporting
from config import AppConfig
from model import Observation
from storage import Storage, read_summary
from tests.test_config_storage import sample_scan


class ReportingTests(unittest.TestCase):
    def test_status_output_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "history.db"
            status = root / "status.json"
            runtime = {"database_path": str(database), "running": False}
            status.write_text(json.dumps(runtime))
            storage = {
                "path": str(database),
                "file_sizes_bytes": {
                    "history.db": 0,
                    "history.db-wal": 0,
                    "history.db-shm": 0,
                },
                "total_size_bytes": 0,
                "disk_free_bytes": 123,
            }
            expected = {
                "service": {"ActiveState": "inactive"},
                "runtime": runtime,
                "history": {"available": False},
                "storage": storage,
            }
            for as_json in (True, False):
                output = io.StringIO()
                with (
                    self.subTest(as_json=as_json),
                    patch("control.service_status", return_value=expected["service"]),
                    patch(
                        "reporting.shutil.disk_usage",
                        return_value=SimpleNamespace(free=123),
                    ),
                    redirect_stdout(output),
                ):
                    result = reporting.show_status(
                        AppConfig(database_path=database), status, as_json
                    )
                self.assertEqual(result, 0)
                if as_json:
                    self.assertEqual(
                        output.getvalue(), json.dumps(expected, sort_keys=True) + "\n"
                    )
                else:
                    self.assertEqual(
                        output.getvalue(),
                        "service:\n  ActiveState: inactive\n"
                        f"runtime:\n  database_path: {database}\n  running: False\n"
                        "history:\n  available: False\n"
                        f"storage:\n  path: {database}\n"
                        "  file_sizes_bytes: {'history.db': 0, 'history.db-wal': 0, "
                        "'history.db-shm': 0}\n"
                        "  total_size_bytes: 0\n  disk_free_bytes: 123\n",
                    )
            self.assertFalse(database.exists())

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
                    self.assertEqual(reporting.show_status(config, status, True), 0)
                payload = json.loads(output.getvalue())
                self.assertFalse(payload["runtime"]["available"])
                self.assertFalse(payload["history"]["available"])
            self.assertFalse(config.database_path.exists())

    def test_summary_supports_paths_with_uri_characters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "special ?# file.db"
            with Storage(path) as storage:
                storage.save(sample_scan())
            self.assertEqual(read_summary(path)["successful_scans"], 1)
            self.assertTrue(os.path.exists(path))

    def test_atomic_status_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            reporting.write_status(path, {"counter": 1})
            with (
                patch("reporting.os.replace", side_effect=OSError("failure")),
                self.assertRaises(OSError),
            ):
                reporting.write_status(path, {"counter": 2})
            self.assertEqual(json.loads(path.read_text()), {"counter": 1})
            self.assertEqual(list(path.parent.iterdir()), [path])
