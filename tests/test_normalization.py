from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import migration
from model import Observation, Scan
from storage import Storage, insert_observation, read_summary
from tests.helpers import sample_scan

SCHEMA = Path("tests/fixtures/schema_v2.sql").read_text()


def originals() -> list[Scan]:
    base = Observation("aa:bb:cc:dd:ee:ff", 2412)
    values = (
        (None, None, None),
        (b"", "", "null"),
        (b"\x00\xff", "\ufffd\x00", "{}"),
        (b"\xfe", "\ufffd", "[]"),
        (b"\xff", "\ufffd", '{"a":1,"b":2}'),
        (b"\xff", "different", '{ "b":2, "a":1 }'),
        (None, "", "{}"),
        (b"", None, None),
    )
    scans = []
    for index, (raw, display, security) in enumerate((*values, values[0], values[4])):
        item = replace(
            base,
            ssid_bytes=raw,
            ssid_display=display,
            security_json=security,
            signal_dbm=-50.125 if index % 2 else None,
            channel=123 if index % 2 else None,
        )
        scans.append(sample_scan(item, replace(item, frequency_mhz=5180)))
    scans.append(sample_scan(replace(base, bssid="00:00:00:00:00:00")))
    scans.append(sample_scan())
    for status in ("failed", "timeout", "cancelled"):
        scans.append(replace(sample_scan(), status=status, error=""))
    return scans


def legacy(path: Path, scans: list[Scan]) -> None:
    with closing(sqlite3.connect(path)) as connection, connection:
        connection.executescript(SCHEMA)
        for scan in scans:
            cursor = connection.execute(
                "INSERT INTO scan (device, started_at, finished_at, "
                "started_monotonic_ms, finished_monotonic_ms, boot_id, status, error) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan.device,
                    scan.started_at,
                    scan.finished_at,
                    scan.started_monotonic_ms,
                    scan.finished_monotonic_ms,
                    scan.boot_id,
                    scan.status,
                    scan.error,
                ),
            )
            for item in scan.observations:
                connection.execute(
                    "INSERT INTO observation VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        cursor.lastrowid,
                        item.bssid,
                        item.frequency_mhz,
                        item.ssid_bytes,
                        item.ssid_display,
                        item.signal_dbm,
                        item.channel,
                        item.security_json,
                    ),
                )


def rows(connection: sqlite3.Connection) -> list[tuple[object, ...]]:
    return connection.execute(
        "SELECT * FROM observation ORDER BY scan_id, bssid, frequency_mhz"
    ).fetchall()


class NormalizationTests(unittest.TestCase):
    def test_exact_history_reversion_restart_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new.db"
            old = Path(directory) / "old.db"
            scans = originals()
            legacy(old, scans)
            with closing(sqlite3.connect(old)) as source:
                expected = rows(source)
            with Storage(path) as storage:
                for scan in scans[:5]:
                    storage.save(scan)
            with Storage(path) as storage:
                for scan in scans[5:]:
                    storage.save(scan)
                self.assertEqual(rows(storage.connection), expected)
                self.assertEqual(read_summary(path), read_summary(old))
                self.assertEqual(
                    storage.connection.execute(
                        "SELECT count(*) FROM network_name"
                    ).fetchone(),
                    (8,),
                )
                self.assertEqual(
                    storage.connection.execute(
                        "SELECT count(*) FROM observation_profile"
                    ).fetchone(),
                    (8,),
                )
                for table in (
                    "access_point",
                    "network_name",
                    "security_info",
                    "observation_profile",
                ):
                    with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                        storage.connection.execute(f"UPDATE {table} SET id = id")
                with closing(sqlite3.connect(Path(directory) / "snapshot.db")) as copy:
                    storage.connection.rollback()
                    storage.connection.backup(copy)
                    self.assertEqual(rows(copy), expected)
                    self.assertEqual(
                        copy.execute("PRAGMA integrity_check").fetchone(), ("ok",)
                    )
                    self.assertEqual(
                        copy.execute("PRAGMA foreign_key_check").fetchall(), []
                    )

    def test_atomic_migration_backup_and_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "old.db"
            backup = Path(directory) / "backup.db"
            legacy(path, originals())
            before = read_summary(path)
            migration.migrate(path, backup)
            with closing(sqlite3.connect(backup)) as source, Storage(path) as storage:
                self.assertEqual(source.execute("PRAGMA user_version").fetchone(), (2,))
                self.assertEqual(rows(source), rows(storage.connection))
                self.assertEqual(read_summary(path), before)
                self.assertEqual(storage.save(sample_scan()), len(originals()) + 1)

    def test_failure_rolls_back_schema_data_and_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "old.db"
            backup = Path(directory) / "backup.db"
            legacy(path, originals())
            insert = insert_observation
            count = 0

            def fail(
                connection: sqlite3.Connection, scan_id: int, item: Observation
            ) -> None:
                nonlocal count
                insert(connection, scan_id, item)
                count += 1
                if count == 3:
                    raise sqlite3.OperationalError("database or disk is full")

            with (
                patch("migration.insert_observation", side_effect=fail),
                self.assertRaises(sqlite3.OperationalError),
            ):
                migration.migrate(path, backup)
            with (
                closing(sqlite3.connect(path)) as source,
                closing(sqlite3.connect(backup)) as copy,
            ):
                self.assertEqual(source.execute("PRAGMA user_version").fetchone(), (2,))
                self.assertEqual(rows(source), rows(copy))
                self.assertIsNone(
                    source.execute(
                        "SELECT name FROM sqlite_master WHERE name='observation_record'"
                    ).fetchone()
                )
            migration.migrate(path, backup.with_name("retry.db"))

    def test_lock_and_existing_backup_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new.db"
            with Storage(path):
                with self.assertRaises(BlockingIOError):
                    Storage(path)
                with self.assertRaises(BlockingIOError):
                    migration.migrate(path, Path(directory) / "backup.db")
            old = Path(directory) / "old.db"
            legacy(old, originals())
            with self.assertRaises(FileExistsError):
                migration.migrate(old, path)
            with closing(sqlite3.connect(old)) as source:
                self.assertEqual(source.execute("PRAGMA user_version").fetchone(), (2,))

    def test_dictionary_and_fact_failures_leave_no_orphans(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            Storage(Path(directory) / "new.db") as storage,
        ):
            item = Observation("aa:bb:cc:dd:ee:ff", 2412, b"x", "x", security_json="{}")
            for observations in ((replace(item, security_json=""),), (item, item)):
                with self.assertRaises(sqlite3.IntegrityError):
                    storage.save(sample_scan(*observations))
                for table in (
                    "scan",
                    "access_point",
                    "network_name",
                    "security_info",
                    "observation_profile",
                    "observation_record",
                ):
                    self.assertEqual(
                        storage.connection.execute(
                            f"SELECT count(*) FROM {table}"
                        ).fetchone(),
                        (0,),
                    )
            storage.save(sample_scan(item))

    def test_process_death_before_and_after_commit(self) -> None:
        script = """
import os
import sys
from pathlib import Path
import migration
check = migration._check
calls = 0
def terminate(connection):
    global calls
    check(connection)
    calls += 1
    if calls == int(sys.argv[3]):
        os._exit(91)
migration._check = terminate
migration.migrate(Path(sys.argv[1]), Path(sys.argv[2]))
"""
        for stage, version in ((4, 2), (5, 3)):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "old.db"
                backup = Path(directory) / "backup.db"
                legacy(path, originals())
                result = subprocess.run(
                    [sys.executable, "-c", script, str(path), str(backup), str(stage)],
                    env=dict(os.environ, PYTHONPATH="src"),
                    check=False,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 91)
                with (
                    closing(sqlite3.connect(path)) as source,
                    closing(sqlite3.connect(backup)) as copy,
                ):
                    self.assertEqual(
                        source.execute("PRAGMA user_version").fetchone(), (version,)
                    )
                    self.assertEqual(rows(source), rows(copy))
                    self.assertEqual(
                        source.execute("PRAGMA integrity_check").fetchone(), ("ok",)
                    )
                    self.assertEqual(
                        source.execute("PRAGMA foreign_key_check").fetchall(), []
                    )
                if version == 2:
                    migration.migrate(path, backup.with_name("retry.db"))
