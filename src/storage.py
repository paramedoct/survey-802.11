from __future__ import annotations

import fcntl
import sqlite3
from contextlib import closing
from pathlib import Path
from types import TracebackType

from model import Observation, Scan

SCHEMA_VERSION = 3
_SCHEMA = """
CREATE TABLE scan (
    id INTEGER PRIMARY KEY,
    device TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    started_monotonic_ms INTEGER NOT NULL,
    finished_monotonic_ms INTEGER NOT NULL
        CHECK (finished_monotonic_ms >= started_monotonic_ms),
    boot_id TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('success', 'failed', 'timeout', 'cancelled')),
    error TEXT,
    CHECK ((status = 'success' AND error IS NULL)
        OR (status != 'success' AND error IS NOT NULL))
);
CREATE INDEX scan_time ON scan(started_at, id);
CREATE INDEX scan_boot_time ON scan(boot_id, started_monotonic_ms, id);

"""

_NORMALIZED_SCHEMA = """
CREATE TABLE access_point (
    id INTEGER PRIMARY KEY,
    bssid TEXT NOT NULL COLLATE BINARY UNIQUE
        CHECK (length(bssid) = 17 AND bssid = lower(bssid))
);
CREATE TABLE network_name (
    id INTEGER PRIMARY KEY,
    ssid_bytes BLOB,
    ssid_display TEXT
);
CREATE UNIQUE INDEX network_name_value ON network_name (
    (ssid_bytes IS NULL), coalesce(ssid_bytes, X''),
    (ssid_display IS NULL), coalesce(ssid_display, '') COLLATE BINARY
);
CREATE TABLE security_info (
    id INTEGER PRIMARY KEY,
    security_json TEXT COLLATE BINARY
        CHECK (security_json IS NULL OR json_valid(security_json))
);
CREATE UNIQUE INDEX security_info_value ON security_info (
    (security_json IS NULL), coalesce(security_json, '') COLLATE BINARY
);
CREATE TABLE observation_profile (
    id INTEGER PRIMARY KEY,
    name_id INTEGER NOT NULL REFERENCES network_name(id),
    security_id INTEGER NOT NULL REFERENCES security_info(id),
    UNIQUE (name_id, security_id)
);
CREATE TABLE observation_record (
    scan_id INTEGER NOT NULL REFERENCES scan(id),
    ap_id INTEGER NOT NULL REFERENCES access_point(id),
    frequency_mhz INTEGER NOT NULL CHECK (frequency_mhz > 0),
    profile_id INTEGER NOT NULL REFERENCES observation_profile(id),
    signal_dbm REAL,
    channel INTEGER,
    PRIMARY KEY (scan_id, ap_id, frequency_mhz)
);
CREATE INDEX observation_record_address_time
    ON observation_record(ap_id, scan_id);
CREATE VIEW observation AS
SELECT r.scan_id, a.bssid, r.frequency_mhz,
       n.ssid_bytes, n.ssid_display, r.signal_dbm, r.channel,
       q.security_json
FROM observation_record AS r
JOIN access_point AS a ON a.id = r.ap_id
JOIN observation_profile AS p ON p.id = r.profile_id
JOIN network_name AS n ON n.id = p.name_id
JOIN security_info AS q ON q.id = p.security_id;
"""


def create_normalized_schema(connection: sqlite3.Connection) -> None:
    for statement in _NORMALIZED_SCHEMA.split(";"):
        if statement.strip():
            connection.execute(statement)
    for table in (
        "access_point",
        "network_name",
        "security_info",
        "observation_profile",
    ):
        connection.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE ON {table} "
            "BEGIN SELECT RAISE(ABORT, 'immutable dictionary'); END"
        )


def insert_observation(
    connection: sqlite3.Connection, scan_id: int, item: Observation
) -> None:
    def intern(table: str, columns: tuple[str, ...], values: tuple[object, ...]) -> int:
        # Expressions match the NULL-aware unique indexes, including empty values.
        parameters: tuple[object, ...]
        if table == "network_name":
            predicate = (
                "(ssid_bytes IS NULL) = (? IS NULL) AND "
                "coalesce(ssid_bytes, X'') = coalesce(?, X'') AND "
                "(ssid_display IS NULL) = (? IS NULL) AND "
                "coalesce(ssid_display, '') = coalesce(?, '') COLLATE BINARY"
            )
            parameters = (values[0], values[0], values[1], values[1])
        elif table == "security_info":
            predicate = (
                "(security_json IS NULL) = (? IS NULL) AND "
                "coalesce(security_json, '') = coalesce(?, '') COLLATE BINARY"
            )
            parameters = (values[0], values[0])
        else:
            predicate = " AND ".join(f"{column} IS ?" for column in columns)
            parameters = values
        row = connection.execute(
            f"SELECT id FROM {table} WHERE {predicate}", parameters
        ).fetchone()
        if row is not None:
            return int(row[0])
        cursor = connection.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})",
            values,
        )
        assert cursor.lastrowid is not None
        return cursor.lastrowid

    ap_id = intern("access_point", ("bssid",), (item.bssid,))
    name_id = intern(
        "network_name",
        ("ssid_bytes", "ssid_display"),
        (item.ssid_bytes, item.ssid_display),
    )
    security_id = intern("security_info", ("security_json",), (item.security_json,))
    profile_id = intern(
        "observation_profile", ("name_id", "security_id"), (name_id, security_id)
    )
    connection.execute(
        "INSERT INTO observation_record "
        "(scan_id, ap_id, frequency_mhz, profile_id, signal_dbm, channel) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (scan_id, ap_id, item.frequency_mhz, profile_id, item.signal_dbm, item.channel),
    )


def read_summary(path: Path) -> dict[str, object]:
    """Read durable history without creating a missing database."""
    if not path.exists():
        return {"available": False}
    with closing(
        sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    ) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version not in {1, 2, SCHEMA_VERSION}:
            raise RuntimeError(f"unsupported database schema version: {version}")
        counts = dict(
            connection.execute("SELECT status, count(*) FROM scan GROUP BY status")
        )
        last = connection.execute(
            "SELECT id, finished_at, status FROM scan ORDER BY id DESC LIMIT 1"
        ).fetchone()
        error = connection.execute(
            "SELECT finished_at, error FROM scan WHERE error IS NOT NULL "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return {
        "available": True,
        "successful_scans": counts.get("success", 0),
        "failed_scans": sum(
            counts.get(status, 0) for status in ("failed", "timeout", "cancelled")
        ),
        "counts_by_status": counts,
        "last_scan_id": last[0] if last else None,
        "last_scan_at": last[1] if last else None,
        "last_scan_status": last[2] if last else None,
        "last_error_at": error[0] if error else None,
        "last_error": error[1] if error else None,
    }


class Storage:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = path.open("a+b")
        try:
            fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self._lock.close()
            raise
        try:
            self.connection = sqlite3.connect(path, timeout=5)
            try:
                self.connection.execute("PRAGMA foreign_keys = ON")
                version = self.connection.execute("PRAGMA user_version").fetchone()[0]
                if version in {1, 2}:
                    raise RuntimeError(
                        "database migration required; stop collection and run "
                        "survey-802.11 migrate --backup PATH"
                    )
                if version not in {0, SCHEMA_VERSION}:
                    raise RuntimeError(
                        f"unsupported database schema version: {version}"
                    )
                if version == 0:
                    tables = self.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                    if tables:
                        raise RuntimeError(
                            "refusing to initialize an unversioned database"
                        )
                mode = self.connection.execute("PRAGMA journal_mode = WAL").fetchone()[
                    0
                ]
                if mode != "wal":
                    raise RuntimeError("database does not support WAL mode")
                self.connection.execute("PRAGMA synchronous = FULL")
                if version == 0:
                    with self.connection:
                        self.connection.execute("BEGIN IMMEDIATE")
                        for statement in _SCHEMA.split(";"):
                            if statement.strip():
                                self.connection.execute(statement)
                        create_normalized_schema(self.connection)
                        self.connection.execute("PRAGMA user_version = 3")
            except BaseException:
                self.connection.close()
                raise
        except BaseException:
            self._lock.close()
            raise

    def save(self, scan: Scan, *, scan_id: int | None = None) -> int:
        if scan.status != "success" and scan.observations:
            raise ValueError("incomplete scans cannot contain observations")
        with self.connection:
            columns = """device, started_at, finished_at, started_monotonic_ms,
                finished_monotonic_ms, boot_id, status, error"""
            values: tuple[object, ...] = (
                scan.device,
                scan.started_at,
                scan.finished_at,
                scan.started_monotonic_ms,
                scan.finished_monotonic_ms,
                scan.boot_id,
                scan.status,
                scan.error,
            )
            if scan_id is not None:
                columns = "id, " + columns
                values = (scan_id, *values)
            placeholders = ", ".join("?" for _ in values)
            cursor = self.connection.execute(
                f"INSERT INTO scan ({columns}) VALUES ({placeholders})",
                values,
            )
            saved_id = cursor.lastrowid if scan_id is None else scan_id
            assert saved_id is not None
            for item in scan.observations:
                insert_observation(self.connection, saved_id, item)
        return saved_id

    def close(self) -> None:
        try:
            self.connection.close()
        finally:
            self._lock.close()

    def __enter__(self) -> Storage:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
