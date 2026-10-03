from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from config import AppConfig, ConfigError, load_config
from model import Observation
from storage import Storage, read_summary
from tests.helpers import sample_scan


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

    def test_migrate_nanoseconds_preserves_history_and_constraints(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            observation = Observation("aa:bb:cc:dd:ee:ff", 2412)
            with Storage(path) as storage:
                storage.save(sample_scan(observation))
                storage.connection.executescript(
                    "ALTER TABLE scan RENAME COLUMN started_monotonic_ms "
                    "TO started_monotonic_ns;"
                    "ALTER TABLE scan RENAME COLUMN finished_monotonic_ms "
                    "TO finished_monotonic_ns;"
                    "UPDATE scan SET started_monotonic_ns = 1234567890, "
                    "finished_monotonic_ns = 2345678901;"
                    "PRAGMA user_version = 1;"
                )
            self.assertEqual(read_summary(path)["successful_scans"], 1)
            for _ in range(2):
                with Storage(path) as storage:
                    self.assertEqual(
                        storage.connection.execute("PRAGMA user_version").fetchone(),
                        (2,),
                    )
                    self.assertEqual(
                        storage.connection.execute(
                            "SELECT id, started_monotonic_ms, finished_monotonic_ms "
                            "FROM scan"
                        ).fetchall(),
                        [(1, 1234, 2345)],
                    )
                    self.assertEqual(
                        storage.connection.execute(
                            "SELECT scan_id, bssid FROM observation"
                        ).fetchall(),
                        [(1, observation.bssid)],
                    )
                    self.assertEqual(
                        storage.connection.execute("PRAGMA integrity_check").fetchone(),
                        ("ok",),
                    )
                    self.assertEqual(
                        storage.connection.execute(
                            "PRAGMA foreign_key_check"
                        ).fetchall(),
                        [],
                    )
                    with self.assertRaises(sqlite3.IntegrityError):
                        storage.connection.execute(
                            "UPDATE scan SET finished_monotonic_ms = 1233"
                        )
            with Storage(path) as storage:
                self.assertEqual(storage.save(sample_scan(observation)), 2)

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
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA user_version = 99")
            with self.assertRaisesRegex(RuntimeError, "version"):
                Storage(path)
            with closing(sqlite3.connect(path)) as connection:
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
