from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from types import TracebackType

from model import Scan

SCHEMA_VERSION = 1
_SCHEMA = """
CREATE TABLE scan (
    id INTEGER PRIMARY KEY,
    device TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    started_monotonic_ns INTEGER NOT NULL,
    finished_monotonic_ns INTEGER NOT NULL
        CHECK (finished_monotonic_ns >= started_monotonic_ns),
    boot_id TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('success', 'failed', 'timeout', 'cancelled')),
    error TEXT,
    CHECK ((status = 'success' AND error IS NULL)
        OR (status != 'success' AND error IS NOT NULL))
);
CREATE TABLE observation (
    scan_id INTEGER NOT NULL REFERENCES scan(id),
    bssid TEXT NOT NULL CHECK (length(bssid) = 17 AND bssid = lower(bssid)),
    frequency_mhz INTEGER NOT NULL CHECK (frequency_mhz > 0),
    ssid_bytes BLOB,
    ssid_display TEXT,
    signal_dbm REAL,
    channel INTEGER,
    security_json TEXT CHECK (security_json IS NULL OR json_valid(security_json)),
    PRIMARY KEY (scan_id, bssid, frequency_mhz)
);
CREATE INDEX scan_time ON scan(started_at, id);
CREATE INDEX scan_boot_time ON scan(boot_id, started_monotonic_ns, id);
CREATE INDEX observation_address_time ON observation(bssid, scan_id);
PRAGMA user_version = 1;
"""


def read_summary(path: Path) -> dict[str, object]:
    """Read durable history without creating a missing database."""
    if not path.exists():
        return {"available": False}
    with closing(
        sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    ) as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version != SCHEMA_VERSION:
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
        self.connection = sqlite3.connect(path, timeout=5)
        try:
            self.connection.execute("PRAGMA foreign_keys = ON")
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in {0, SCHEMA_VERSION}:
                raise RuntimeError(f"unsupported database schema version: {version}")
            if version == 0:
                tables = self.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
                if tables:
                    raise RuntimeError("refusing to initialize an unversioned database")
            mode = self.connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]
            if mode != "wal":
                raise RuntimeError("database does not support WAL mode")
            self.connection.execute("PRAGMA synchronous = FULL")
            if version == 0:
                self.connection.executescript(
                    "BEGIN IMMEDIATE;\n" + _SCHEMA + "COMMIT;"
                )
        except BaseException:
            self.connection.close()
            raise

    def save(self, scan: Scan) -> int:
        if scan.status != "success" and scan.observations:
            raise ValueError("incomplete scans cannot contain observations")
        with self.connection:
            cursor = self.connection.execute(
                """INSERT INTO scan (
                    device, started_at, finished_at, started_monotonic_ns,
                    finished_monotonic_ns, boot_id, status, error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan.device,
                    scan.started_at,
                    scan.finished_at,
                    scan.started_monotonic_ns,
                    scan.finished_monotonic_ns,
                    scan.boot_id,
                    scan.status,
                    scan.error,
                ),
            )
            scan_id = cursor.lastrowid
            assert scan_id is not None
            self.connection.executemany(
                """INSERT INTO observation (
                    scan_id, bssid, frequency_mhz, ssid_bytes, ssid_display,
                    signal_dbm, channel, security_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
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
                    for item in scan.observations
                ),
            )
        return scan_id

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> Storage:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
