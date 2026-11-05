from __future__ import annotations

import fcntl
import hashlib
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from model import Observation
from storage.backup import snapshot_monthly
from storage.database import MonthlyStorage, connect_readonly, month_of, read_manifest
from storage.history import summarize
from tests.helpers import observation_history, sample_scan


class MonthlyStorageTests(unittest.TestCase):
    def test_month_boundaries_clock_reversal_and_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "history"
            observation = Observation(
                "aa:bb:cc:dd:ee:ff", 2412, b"", "", -42.5, 1, "null"
            )
            scan = sample_scan(observation)
            with MonthlyStorage(root) as store:
                self.assertEqual(
                    store.save(replace(scan, started_at="2026-02-01T08:59:59+09:00")), 1
                )
                self.assertEqual(
                    store.save(replace(scan, started_at="2026-02-01T09:00:00+09:00")), 2
                )
                self.assertEqual(
                    store.save(replace(scan, started_at="2026-01-10T00:00:00Z")), 3
                )
            with MonthlyStorage(root) as store:
                self.assertEqual(store.save(scan), 4)
            self.assertEqual(
                [row["id"] for row in observation_history(root, "monthly")],
                [4, 3, 2, 1],
            )
            self.assertEqual(summarize(root, "monthly")["successful_scans"], 4)
            self.assertEqual(month_of("2026-02-01T00:30:00+01:00"), "2026-01")

    def test_null_empty_bytes_security_and_failed_scans(self) -> None:
        items = (
            Observation("aa:bb:cc:dd:ee:ff", 2412),
            Observation("aa:bb:cc:dd:ee:ff", 2437, b"", "", None, None, "null"),
            Observation(
                "aa:bb:cc:dd:ee:ff",
                2462,
                b"\x00\xff",
                "\x00\ufffd",
                -41.5,
                11,
                '{ "a": 1 }',
            ),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            with MonthlyStorage(root) as store:
                store.save(sample_scan(*items))
                store.save(replace(sample_scan(), status="timeout", error=""))
                store.save(sample_scan(*items))
            rows = observation_history(root, "monthly")
            newest = [row for row in rows if row["id"] == 3]
            self.assertEqual(len(newest), 3)
            self.assertEqual(
                [row["ssid_bytes"] for row in newest], [None, b"", b"\x00\xff"]
            )
            older = [row for row in rows if row["id"] == 2]
            self.assertEqual(
                [(row["id"], row["error"], row["bssid"]) for row in older],
                [(2, "", None)],
            )
            self.assertEqual(len([row for row in rows if row["id"] == 1]), 3)

    def test_missing_and_duplicate_history_fail(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            with MonthlyStorage(root) as store:
                store.save(replace(sample_scan(), started_at="2026-01-01T00:00:00Z"))
                store.save(replace(sample_scan(), started_at="2026-02-01T00:00:00Z"))
            with closing(sqlite3.connect(root / "2026-02.db")) as connection:
                connection.execute("UPDATE scan SET id = 1")
                connection.commit()
            with self.assertRaisesRegex(RuntimeError, "duplicate global"):
                MonthlyStorage(root)
            (root / "2026-02.db").rename(root / "preserved.db")
            with self.assertRaisesRegex(RuntimeError, "missing"):
                summarize(root, "monthly")

    def test_manifest_publish_failure_recovers_empty_file_without_deletion(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            with (
                MonthlyStorage(root) as store,
                patch(
                    "storage.database.write_manifest", side_effect=OSError("disk full")
                ),
                self.assertRaises(OSError),
            ):
                store.save(sample_scan())
            self.assertTrue((root / "2026-10.db").exists())
            with MonthlyStorage(root) as store:
                self.assertEqual(store.save(sample_scan()), 1)
            self.assertEqual(summarize(root, "monthly")["successful_scans"], 1)

    def test_abrupt_exit_preserves_commit_and_next_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            script = (
                "import os, sys; from pathlib import Path; "
                "from storage.database import MonthlyStorage; "
                "from tests.helpers import sample_scan; "
                "s = MonthlyStorage(Path(sys.argv[1])); "
                "s.save(sample_scan()); os._exit(9)"
            )
            result = subprocess.run(
                [sys.executable, "-c", script, str(root)], check=False
            )
            self.assertEqual(result.returncode, 9)
            with MonthlyStorage(root) as store:
                self.assertEqual(store.save(sample_scan()), 2)

    def test_backup_boundary_excludes_new_month_and_later_appends(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            backup = Path(directory) / "backup"
            with MonthlyStorage(root) as store:
                january = replace(
                    sample_scan(
                        Observation("aa:bb:cc:dd:ee:ff", 2412, wifi_generations=(4, 6))
                    ),
                    started_at="2026-01-01T00:00:00Z",
                )
                february = replace(january, started_at="2026-02-01T00:00:00Z")
                store.save(january)
                store.save(february)
                expected = observation_history(root, "monthly")
                appended = False

                def concurrent_read(path: Path) -> sqlite3.Connection:
                    nonlocal appended
                    if not appended:
                        appended = True
                        with (
                            (root / ".maintenance.lock").open("rb") as maintenance,
                            self.assertRaises(BlockingIOError),
                        ):
                            fcntl.flock(maintenance, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        store.save(replace(january, started_at="2026-03-01T00:00:00Z"))
                        store.save(january)
                        store.save(february)
                    return connect_readonly(path)

                with patch(
                    "storage.backup.connect_readonly", side_effect=concurrent_read
                ):
                    snapshot_monthly(root, backup)
            self.assertEqual(read_manifest(backup)["months"], ["2026-01", "2026-02"])
            self.assertEqual(
                [row["id"] for row in observation_history(backup, "monthly")], [2, 1]
            )
            self.assertEqual(observation_history(backup, "monthly"), expected)
            self.assertEqual(summarize(root, "monthly")["successful_scans"], 5)
            metadata = json.loads((backup / "backup.json").read_text())
            self.assertEqual(metadata["high_water_scan_id"], 2)
            for name, digest in metadata["sha256"].items():
                self.assertEqual(
                    hashlib.sha256((backup / name).read_bytes()).hexdigest(), digest
                )

    def test_failed_round_transaction_preserves_next_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            with MonthlyStorage(root) as store:
                good = Observation("aa:bb:cc:dd:ee:ff", 2412, b"kept", "kept")
                self.assertEqual(store.save(sample_scan(good)), 1)
                with self.assertRaises(sqlite3.IntegrityError):
                    store.save(sample_scan(good, replace(good, frequency_mhz=-1)))
                self.assertEqual(store.save(sample_scan(good)), 2)
            with MonthlyStorage(root) as restarted:
                self.assertEqual(restarted.metrics["retained_observations"], 2)

    def test_single_writer_and_timestamp_validation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            with MonthlyStorage(root) as store:
                with self.assertRaises(BlockingIOError):
                    MonthlyStorage(root)
                with self.assertRaisesRegex(ValueError, "timezone-aware"):
                    store.save(replace(sample_scan(), started_at="2026-01-01T00:00:00"))
            self.assertEqual(read_manifest(root)["months"], [])
