from __future__ import annotations

import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from backup import send_backup


class BackupTests(unittest.TestCase):
    def test_live_backup_includes_wal_and_excludes_uncommitted_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "history with spaces.db"
            sent: list[Path] = []
            with closing(sqlite3.connect(database)) as writer:
                writer.execute("PRAGMA journal_mode = WAL")
                writer.execute("PRAGMA wal_autocheckpoint = 0")
                writer.execute("CREATE TABLE history (id INTEGER)")
                writer.execute("INSERT INTO history VALUES (1)")
                writer.commit()
                writer.execute("INSERT INTO history VALUES (2)")
                self.assertTrue(Path(str(database) + "-wal").exists())

                def transfer(
                    arguments: list[str], *, check: bool
                ) -> subprocess.CompletedProcess[str]:
                    self.assertFalse(check)
                    self.assertEqual(arguments[0], "/usr/bin/sz")
                    snapshot = Path(arguments[1])
                    sent.append(snapshot)
                    self.assertEqual(snapshot.name, database.name)
                    self.assertNotEqual(snapshot, database)
                    with closing(sqlite3.connect(snapshot)) as reader:
                        self.assertEqual(
                            reader.execute("SELECT * FROM history").fetchall(), [(1,)]
                        )
                        self.assertEqual(
                            reader.execute("PRAGMA integrity_check").fetchone(), ("ok",)
                        )
                        self.assertEqual(
                            reader.execute("PRAGMA journal_mode").fetchone(),
                            ("delete",),
                        )
                    # The collector can keep committing while sz sends the snapshot.
                    writer.commit()
                    return subprocess.CompletedProcess(arguments, 0)

                with (
                    patch("backup.shutil.which", return_value="/usr/bin/sz"),
                    patch("backup.subprocess.run", side_effect=transfer),
                ):
                    self.assertEqual(send_backup(database), 0)
                self.assertEqual(
                    writer.execute("SELECT * FROM history").fetchall(), [(1,), (2,)]
                )
            self.assertEqual(len(sent), 1)
            self.assertFalse(sent[0].parent.exists())

    def test_transfer_failure_is_returned_and_snapshot_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "history.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("CREATE TABLE history (id INTEGER)")
            with (
                patch("backup.shutil.which", return_value="/usr/bin/sz"),
                patch(
                    "backup.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 7),
                ) as run,
            ):
                self.assertEqual(send_backup(database), 7)
                snapshot = Path(run.call_args.args[0][1])
                self.assertFalse(snapshot.parent.exists())
                self.assertTrue(database.exists())

    def test_missing_database_is_not_created_or_sent(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("backup.shutil.which", return_value="/usr/bin/sz"),
            patch("backup.subprocess.run") as run,
        ):
            database = Path(directory) / "missing.db"
            with self.assertRaises(sqlite3.OperationalError):
                send_backup(database)
            self.assertFalse(database.exists())
            run.assert_not_called()

    def test_missing_sz_is_reported(self) -> None:
        with (
            patch("backup.shutil.which", return_value=None),
            self.assertRaisesRegex(RuntimeError, "sz is required"),
        ):
            send_backup(Path("/missing.db"))
