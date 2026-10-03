from __future__ import annotations

import sqlite3
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from config import AppConfig, ConfigError, load_config
from model import Observation, Scan
from storage import Storage


def sample_scan(*observations: Observation) -> Scan:
    return Scan(
        "wlan0",
        "2026-10-03T10:00:00+09:00",
        "2026-10-03T10:00:01+09:00",
        100,
        200,
        "test-boot",
        "success",
        observations=observations,
    )


class ConfigTests(unittest.TestCase):
    def test_example_and_defaults(self) -> None:
        self.assertEqual(
            load_config(Path("config/survey-802.11.example.toml")), AppConfig()
        )

    def test_reject_invalid_configuration(self) -> None:
        cases = (
            "version = true",
            "version = 2",
            "version = 1\nunknown = 1",
            'version = 1\n[collector]\ndevice = "bad/name"',
            'version = 1\n[collector]\ndevice = ""',
            "version = 1\n[collector]\ninterval_s = 20",
            "version = 1\n[collector]\ntimeout_s = false",
            "version = 1\n[collector]\ntimeout_s = 0",
            "version = 1\n[collector]\ninterval_s = 60.5",
            'version = 1\n[database]\npath = "relative.db"',
            'version = 1\n[database]\npath = "/"',
            "version = 1\n[database]\nunknown = 1",
            "invalid toml",
            "version = 1\ncollector = []",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            for content in cases:
                with self.subTest(content=content):
                    path.write_text(content)
                    with self.assertRaises(ConfigError):
                        load_config(path)
            with self.assertRaises(ConfigError):
                load_config(path.with_name("missing"))


class StorageTests(unittest.TestCase):
    def test_history_empty_failure_and_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            original = Observation("aa:bb:cc:dd:ee:ff", 2412, b"\xff", "\ufffd", -50.5)
            with Storage(path) as storage:
                self.assertEqual(
                    storage.connection.execute("PRAGMA foreign_keys").fetchone()[0], 1
                )
                self.assertEqual(
                    storage.connection.execute("PRAGMA synchronous").fetchone()[0], 2
                )
                self.assertEqual(
                    storage.connection.execute("PRAGMA journal_mode").fetchone()[0],
                    "wal",
                )
                storage.save(sample_scan(original))
                storage.save(sample_scan())
                storage.save(replace(sample_scan(), status="failed", error="busy"))
            with Storage(path) as storage:
                storage.save(
                    sample_scan(
                        replace(
                            original,
                            ssid_bytes=b"changed",
                            ssid_display="changed",
                            signal_dbm=-70,
                        )
                    )
                )
                rows = storage.connection.execute(
                    "SELECT ssid_bytes, signal_dbm FROM observation ORDER BY scan_id"
                ).fetchall()
                self.assertEqual(rows, [(b"\xff", -50.5), (b"changed", -70.0)])
                self.assertEqual(
                    storage.connection.execute(
                        "SELECT status FROM scan ORDER BY id"
                    ).fetchall(),
                    [("success",), ("success",), ("failed",), ("success",)],
                )

    def test_rollback_on_invalid_observation_and_disk_full(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            Storage(Path(directory) / "history.db") as storage,
        ):
            good = Observation("aa:bb:cc:dd:ee:ff", 2412)
            with self.assertRaises(sqlite3.IntegrityError):
                storage.save(sample_scan(good, replace(good, frequency_mhz=-1)))
            self.assertEqual(
                storage.connection.execute("SELECT count(*) FROM scan").fetchone()[0], 0
            )
            storage.connection.execute("PRAGMA max_page_count = 10")
            huge = replace(good, ssid_bytes=b"x" * 1_000_000)
            with self.assertRaisesRegex(sqlite3.OperationalError, "full"):
                storage.save(sample_scan(huge))
            self.assertEqual(
                storage.connection.execute("SELECT count(*) FROM scan").fetchone()[0], 0
            )
            storage.save(sample_scan(good))

    def test_reject_unknown_schema_and_partial_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            with sqlite3.connect(path) as connection:
                connection.execute("PRAGMA user_version = 99")
            with self.assertRaisesRegex(RuntimeError, "version"):
                Storage(path)
            with sqlite3.connect(path) as connection:
                connection.execute("PRAGMA user_version = 0")
                connection.execute("CREATE TABLE unrelated (id INTEGER)")
            with self.assertRaisesRegex(RuntimeError, "unversioned"):
                Storage(path)
            with (
                Storage(path.with_name("new.db")) as storage,
                self.assertRaises(ValueError),
            ):
                storage.save(
                    replace(
                        sample_scan(Observation("aa:bb:cc:dd:ee:ff", 2412)),
                        status="timeout",
                        error="timeout",
                    )
                )
