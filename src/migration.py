"""Explicit, atomic migration of version 2 history to normalized storage."""

from __future__ import annotations

import fcntl
import shutil
import sqlite3
from contextlib import closing
from itertools import zip_longest
from pathlib import Path

from model import Observation
from storage import create_normalized_schema, insert_observation


def _check(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise RuntimeError("database integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise RuntimeError("database foreign key check failed")


def _compare(left: sqlite3.Cursor, right: sqlite3.Cursor) -> None:
    for original, restored in zip_longest(left, right):
        if original != restored:
            raise RuntimeError("migration equivalence check failed")


def migrate(path: Path, backup: Path, minimum_free_bytes: int = 0) -> None:
    """Keep an exclusive snapshot and roll back every pre-commit failure.

    The inode lock is shared with Storage and survives path aliases. External
    SQLite writers must also be stopped; BEGIN IMMEDIATE excludes their writes.
    """
    if minimum_free_bytes < 0:
        raise RuntimeError("minimum free bytes must be nonnegative")
    with path.open("r+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with closing(sqlite3.connect(path, timeout=5)) as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version != 2:
                raise RuntimeError(
                    f"migration requires schema version 2, found {version}; "
                    "version 1 requires the previous version 2 upgrade first"
                )
            # A conservative preflight floor is not a guarantee against ENOSPC.
            size = connection.execute("PRAGMA page_count").fetchone()[0]
            size *= connection.execute("PRAGMA page_size").fetchone()[0]
            required = max(minimum_free_bytes, size * 3 + 64 * 1024 * 1024)
            if shutil.disk_usage(path.parent).free < required:
                raise RuntimeError(f"migration requires at least {required} free bytes")
            if shutil.disk_usage(backup.parent).free < size + 1024 * 1024:
                raise RuntimeError("insufficient free space for migration backup")
            connection.execute("PRAGMA foreign_keys = ON")
            if connection.execute("PRAGMA journal_mode = WAL").fetchone()[0] != "wal":
                raise RuntimeError("database does not support WAL mode")
            connection.execute("PRAGMA synchronous = FULL")
            with connection:
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute("PRAGMA user_version").fetchone()[0] != 2:
                    raise RuntimeError("database schema changed before migration")
                _check(connection)
                # Exclusive creation refuses overwriting any existing artifact.
                with backup.open("xb"):
                    pass
                with (
                    closing(sqlite3.connect(backup)) as snapshot,
                    closing(
                        sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
                    ) as reader,
                ):
                    reader.backup(snapshot, pages=256)
                    snapshot.execute("PRAGMA journal_mode = DELETE")
                    _check(snapshot)
                    connection.execute(
                        "ALTER TABLE observation RENAME TO observation_v2"
                    )
                    create_normalized_schema(connection)
                    cursor = connection.execute("SELECT * FROM observation_v2")
                    while rows := cursor.fetchmany(256):
                        for row in rows:
                            insert_observation(
                                connection, row[0], Observation(*row[1:])
                            )
                    columns = (
                        "scan_id, bssid, frequency_mhz, ssid_bytes, ssid_display, "
                        "signal_dbm, channel, security_json"
                    )
                    types = ", ".join(
                        f"typeof({column})" for column in columns.split(", ")
                    )
                    query = f"SELECT {columns}, {types} FROM {{}} ORDER BY 1, 2, 3"
                    _compare(
                        connection.execute(query.format("observation_v2")),
                        connection.execute(query.format("observation")),
                    )
                    _compare(
                        connection.execute("SELECT * FROM scan ORDER BY id"),
                        snapshot.execute("SELECT * FROM scan ORDER BY id"),
                    )
                    _check(connection)
                    connection.execute("DROP TABLE observation_v2")
                    connection.execute("PRAGMA user_version = 3")
                    _check(connection)
        with closing(sqlite3.connect(path)) as verified:
            _check(verified)
            if verified.execute("PRAGMA user_version").fetchone()[0] != 3:
                raise RuntimeError("migration version verification failed")
