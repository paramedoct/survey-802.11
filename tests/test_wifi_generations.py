from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from collection.parser import parse_scan
from model import Observation
from storage.backup import snapshot_monthly
from storage.database import (
    SCHEMA_VERSION,
    Layout,
    MonthlyStorage,
    Storage,
    connect_readonly,
    open_storage,
    read_manifest,
    write_manifest,
)
from storage.history import summarize
from tests.helpers import observation_history, sample_scan


def legacy_database(path: Path, scan_id: int = 1) -> None:
    """Build an actual v3 database independently of the current schema."""
    schema = Path(__file__).with_name("fixtures") / "schema_v3.sql"
    with closing(sqlite3.connect(path)) as connection:
        connection.executescript(schema.read_text())
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            connection.execute(
                "INSERT INTO scan VALUES "
                "(?, 'wlan0', '2026-01-01T00:00:00Z', '2026-01-01T00:00:01Z', "
                "100, 200, 'test-boot', 'success', NULL)",
                (scan_id,),
            )
            connection.execute(
                "INSERT INTO access_point VALUES (1, 'aa:bb:cc:dd:ee:ff')"
            )
            connection.execute("INSERT INTO network_name VALUES (1, X'00ff', 'legacy')")
            connection.execute("INSERT INTO security_info VALUES (1, NULL)")
            connection.execute("INSERT INTO observation_profile VALUES (1, 1, 1)")
            connection.execute(
                "INSERT INTO observation_record VALUES (?, 1, 2412, 1, -50.25, 1)",
                (scan_id,),
            )


class WifiGenerationTests(unittest.TestCase):
    def test_scan_storage_restart_and_dictionary_reuse(self) -> None:
        layouts: tuple[Layout, ...] = ("single", "monthly")
        item = parse_scan(
            b"BSS aa:bb:cc:dd:ee:ff\n\tfreq: 5180\n\tSSID: example\n"
            b"\tHT capabilities:\n\tVHT capabilities:\n\tHE capabilities:\n"
        )[0]
        for layout in layouts:
            with (
                self.subTest(layout=layout),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "history"
                with open_storage(path, layout) as storage:
                    storage.save(sample_scan(item))
                    storage.save(
                        sample_scan(replace(item, wifi_generations=(6, 4, 5, 6)))
                    )
                    storage.save(sample_scan(replace(item, wifi_generations=(4,))))
                    storage.save(sample_scan(replace(item, wifi_generations=None)))
                with open_storage(path, layout) as storage:
                    storage.save(sample_scan(item))
                rows = observation_history(path, layout)
                self.assertEqual(
                    [row["wifi_generation"] for row in rows], [6, None, 4, 6, 6]
                )
                self.assertEqual(
                    [
                        json.loads(str(row["wifi_generations_json"]))
                        if row["wifi_generations_json"] is not None
                        else None
                        for row in rows
                    ],
                    [[4, 5, 6], None, [4], [4, 5, 6], [4, 5, 6]],
                )
                source = path if layout == "single" else path / "2026-10.db"
                with closing(connect_readonly(source)) as reader:
                    self.assertEqual(
                        reader.execute("SELECT count(*) FROM wifi_info").fetchone(),
                        (2,),
                    )
                    self.assertEqual(
                        reader.execute("PRAGMA foreign_key_check").fetchall(), []
                    )

    def test_v3_single_upgrade_preserves_old_observations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            legacy_database(path)
            before = summarize(path)
            with Storage(path) as storage:
                self.assertEqual(summarize(path), before)
                self.assertEqual(
                    storage.connection.execute(
                        "SELECT ssid_bytes, signal_dbm, wifi_generations_json, "
                        "wifi_generation FROM observation"
                    ).fetchall(),
                    [(b"\x00\xff", -50.25, None, None)],
                )
                storage.save(
                    sample_scan(
                        Observation("aa:bb:cc:dd:ee:ff", 2412, wifi_generations=(4, 6))
                    )
                )
                self.assertEqual(
                    storage.connection.execute("PRAGMA user_version").fetchone(),
                    (SCHEMA_VERSION,),
                )
                self.assertEqual(
                    storage.connection.execute("PRAGMA integrity_check").fetchone(),
                    ("ok",),
                )
                self.assertEqual(
                    storage.connection.execute("PRAGMA foreign_key_check").fetchall(),
                    [],
                )
            with Storage(path):
                self.assertEqual(
                    [row["wifi_generation"] for row in observation_history(path)],
                    [6, None],
                )

    def test_failed_upgrade_rolls_back_schema_and_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            legacy_database(path)
            with (
                patch("storage.database._OBSERVATION_VIEW", "invalid sql"),
                self.assertRaises(sqlite3.OperationalError),
            ):
                Storage(path)
            with closing(connect_readonly(path)) as reader:
                self.assertEqual(reader.execute("PRAGMA user_version").fetchone(), (3,))
                self.assertEqual(
                    reader.execute("SELECT count(*) FROM observation").fetchone(), (1,)
                )
                self.assertEqual(
                    reader.execute(
                        "SELECT name FROM sqlite_master WHERE name = 'wifi_info'"
                    ).fetchall(),
                    [],
                )
                self.assertNotIn(
                    "wifi_id",
                    [
                        row[1]
                        for row in reader.execute(
                            "PRAGMA table_info(observation_record)"
                        )
                    ],
                )
            with Storage(path):
                self.assertEqual(observation_history(path)[0]["wifi_generation"], None)

    def test_v3_months_upgrade_and_backup_preserve_generations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            with MonthlyStorage(root):
                pass
            manifest = read_manifest(root)
            for scan_id, month in enumerate(("2026-01", "2026-02"), start=1):
                path = root / f"{month}.db"
                legacy_database(path, scan_id)
                with closing(sqlite3.connect(path)) as connection, connection:
                    connection.execute(
                        "CREATE TABLE monthly_identity "
                        "(collection_id TEXT NOT NULL, month TEXT NOT NULL)"
                    )
                    connection.execute(
                        "INSERT INTO monthly_identity VALUES (?, ?)",
                        (manifest["collection_id"], month),
                    )
                manifest["months"].append(month)
            write_manifest(root, manifest)
            self.assertEqual(summarize(root, "monthly")["successful_scans"], 2)
            with MonthlyStorage(root) as storage:
                rows = observation_history(root, "monthly")
                self.assertEqual([row["wifi_generation"] for row in rows], [None, None])
                for month in manifest["months"]:
                    with closing(connect_readonly(root / f"{month}.db")) as reader:
                        self.assertEqual(
                            reader.execute("PRAGMA user_version").fetchone(),
                            (SCHEMA_VERSION,),
                        )
                self.assertEqual(
                    storage.save(
                        sample_scan(
                            Observation(
                                "aa:bb:cc:dd:ee:ff", 5180, wifi_generations=(4, 5, 6, 7)
                            )
                        )
                    ),
                    3,
                )
            expected = observation_history(root, "monthly")
            backup = Path(directory) / "backup"
            snapshot_monthly(root, backup)
            self.assertEqual(observation_history(backup, "monthly"), expected)
            with MonthlyStorage(root) as storage:
                self.assertEqual(storage.save(sample_scan()), 4)
