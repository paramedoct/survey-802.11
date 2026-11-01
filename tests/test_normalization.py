from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from model import Observation, Scan
from storage.database import Storage
from storage.history import summarize
from tests.helpers import sample_scan


def varied_scans() -> list[Scan]:
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


def rows(connection: sqlite3.Connection) -> list[tuple[object, ...]]:
    return connection.execute(
        "SELECT * FROM observation ORDER BY scan_id, bssid, frequency_mhz"
    ).fetchall()


class NormalizationTests(unittest.TestCase):
    def test_exact_history_restart_and_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new.db"
            scans = varied_scans()
            expected = [
                (
                    scan_id,
                    item.bssid,
                    item.frequency_mhz,
                    item.ssid_bytes,
                    item.ssid_display,
                    item.signal_dbm,
                    item.channel,
                    item.security_json,
                )
                for scan_id, scan in enumerate(scans, start=1)
                for item in scan.observations
            ]
            expected.sort(key=lambda row: (row[0], row[1], row[2]))
            with Storage(path) as storage:
                for scan in scans[:5]:
                    storage.save(scan)
            with Storage(path) as storage:
                for scan in scans[5:]:
                    storage.save(scan)
                self.assertEqual(rows(storage.connection), expected)
                self.assertEqual(summarize(path)["successful_scans"], len(scans) - 3)
                self.assertEqual(summarize(path)["failed_scans"], 3)
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

    def test_lock_is_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new.db"
            with Storage(path), self.assertRaises(BlockingIOError):
                Storage(path)

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
