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

from history import query_history, summarize
from model import Observation
from monthly_backup import snapshot_monthly
from monthly_migration import migrate_monthly
from monthly_storage import MonthlyStorage, connect_readonly, month_of, read_manifest
from storage import Storage
from tests.helpers import sample_scan


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
                [row["id"] for row in query_history(root, "monthly")], [4, 3, 2, 1]
            )
            self.assertEqual(summarize(root, "monthly")["successful_scans"], 4)
            self.assertEqual(month_of("2026-02-01T00:30:00+01:00"), "2026-01")

    def test_null_empty_bytes_security_and_pagination(self) -> None:
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
            newest = query_history(root, "monthly", limit=1)
            self.assertEqual(len(newest), 3)
            self.assertEqual(
                [row["ssid_bytes"] for row in newest], [None, b"", b"\x00\xff"]
            )
            older = query_history(root, "monthly", before_id=3, limit=1)
            self.assertEqual(
                [(row["id"], row["error"], row["bssid"]) for row in older],
                [(2, "", None)],
            )
            self.assertEqual(
                len(query_history(root, "monthly", scan_id=1, bssid=items[0].bssid)), 3
            )

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
                    "monthly_storage.write_manifest", side_effect=OSError("disk full")
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
                "from monthly_storage import MonthlyStorage; "
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
                    sample_scan(Observation("aa:bb:cc:dd:ee:ff", 2412)),
                    started_at="2026-01-01T00:00:00Z",
                )
                february = replace(january, started_at="2026-02-01T00:00:00Z")
                store.save(january)
                store.save(february)
                expected = query_history(root, "monthly")
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
                    "monthly_backup.connect_readonly", side_effect=concurrent_read
                ):
                    snapshot_monthly(root, backup)
            self.assertEqual(read_manifest(backup)["months"], ["2026-01", "2026-02"])
            self.assertEqual(
                [row["id"] for row in query_history(backup, "monthly")], [2, 1]
            )
            self.assertEqual(query_history(backup, "monthly"), expected)
            self.assertEqual(summarize(root, "monthly")["successful_scans"], 5)
            metadata = json.loads((backup / "backup.json").read_text())
            self.assertEqual(metadata["high_water_scan_id"], 2)
            for name, digest in metadata["sha256"].items():
                self.assertEqual(
                    hashlib.sha256((backup / name).read_bytes()).hexdigest(), digest
                )

    def test_migration_is_lossless_and_original_remains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.db"
            target = Path(directory) / "monthly"
            observation = Observation(
                "aa:bb:cc:dd:ee:ff",
                2412,
                b"\xff\x00",
                "\ufffd\x00",
                -42.5,
                None,
                '{ "x": [] }',
            )
            with Storage(original) as store:
                store.save(
                    replace(sample_scan(observation), started_at="2026-02-01T00:00:00Z")
                )
                store.save(
                    replace(
                        sample_scan(),
                        started_at="2026-01-01T00:00:00Z",
                        status="failed",
                        error="",
                    )
                )
            before = original.read_bytes()
            expected = query_history(original)
            migrate_monthly(original, target)
            self.assertEqual(query_history(target, "monthly"), expected)
            self.assertEqual(original.read_bytes(), before)
            with MonthlyStorage(target) as store:
                self.assertEqual(store.save(sample_scan()), 3)
            with self.assertRaisesRegex(RuntimeError, "already exists"):
                migrate_monthly(original, target)

    def test_migration_failure_does_not_publish_or_modify_original(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original.db"
            target = Path(directory) / "monthly"
            with Storage(original) as store:
                store.save(sample_scan())
            before = original.read_bytes()
            with (
                patch(
                    "monthly_migration.MonthlyStorage.save",
                    side_effect=OSError("disk full"),
                ),
                self.assertRaisesRegex(
                    RuntimeError, "source unchanged; staging retained"
                ),
            ):
                migrate_monthly(original, target)
            self.assertFalse(target.exists())
            self.assertEqual(original.read_bytes(), before)
            self.assertTrue(list(Path(directory).glob(".monthly.import-*")))

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

    def test_killed_migration_keeps_original_and_can_retry(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "original.db"
            target = Path(directory) / "monthly"
            with Storage(source) as store:
                store.save(sample_scan())
                store.save(sample_scan())
            before = source.read_bytes()
            script = """
import os
import sys
from pathlib import Path
from monthly_storage import MonthlyStorage
from monthly_migration import migrate_monthly

save = MonthlyStorage.save
def interrupted(self, scan, *, scan_id=None):
    save(self, scan, scan_id=scan_id)
    os._exit(9)
MonthlyStorage.save = interrupted
migrate_monthly(Path(sys.argv[1]), Path(sys.argv[2]))
"""
            result = subprocess.run(
                [sys.executable, "-c", script, str(source), str(target)], check=False
            )
            self.assertEqual(result.returncode, 9)
            self.assertEqual(source.read_bytes(), before)
            self.assertFalse(target.exists())
            abandoned = list(Path(directory).glob(".monthly.import-*"))
            self.assertEqual(len(abandoned), 1)
            migrate_monthly(source, target)
            self.assertEqual(query_history(source), query_history(target, "monthly"))
            self.assertTrue(abandoned[0].exists())
