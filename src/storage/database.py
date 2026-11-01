"""Single-file and monthly storage selected by layout."""

from __future__ import annotations

import fcntl
import json
import os
import re
import sqlite3
import tempfile
import uuid
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import TracebackType
from typing import Literal, TypedDict, cast

from model import Observation, Scan

Layout = Literal["single", "monthly"]

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


class Manifest(TypedDict):
    format_version: int
    collection_id: str
    months: list[str]


def month_of(timestamp: str) -> str:
    stamp = datetime.fromisoformat(timestamp)
    if stamp.utcoffset() is None:
        raise ValueError("monthly storage requires timezone-aware timestamps")
    stamp = stamp.astimezone(UTC)
    return f"{stamp.year:04d}-{stamp.month:02d}"


@contextmanager
def file_lock(path: Path, *, exclusive: bool, create: bool = False) -> Iterator[None]:
    with path.open("a+b" if create else "rb") as stream:
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(stream, mode)
        yield


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_manifest(root: Path, manifest: Manifest) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=root, prefix=".manifest-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(manifest, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fchmod(stream.fileno(), 0o640)
            os.fsync(stream.fileno())
        os.replace(temporary, root / "manifest.json")
        sync_directory(root)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def read_manifest(root: Path, *, allow_unregistered: bool = False) -> Manifest:
    try:
        value = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"cannot read monthly manifest: {error}") from error
    if (
        not isinstance(value, dict)
        or type(value.get("format_version")) is not int
        or value.get("format_version") != 1
        or not isinstance(value.get("collection_id"), str)
        or not isinstance(value.get("months"), list)
    ):
        raise RuntimeError("invalid monthly manifest")
    months = value["months"]
    if any(
        not isinstance(month, str)
        or re.fullmatch(r"[0-9]{4}-(0[1-9]|1[0-2])", month) is None
        or month.startswith("0000-")
        for month in months
    ) or len(set(months)) != len(months):
        raise RuntimeError("invalid or duplicate manifest month")
    try:
        uuid.UUID(value["collection_id"])
    except ValueError as error:
        raise RuntimeError("invalid collection identifier") from error
    for month in months:
        if not (root / f"{month}.db").is_file():
            raise RuntimeError(f"registered monthly file is missing: {month}.db")
    extra = {path.name for path in root.glob("*.db")} - {
        f"{month}.db" for month in months
    }
    if extra and not allow_unregistered:
        raise RuntimeError(f"unregistered monthly files: {', '.join(sorted(extra))}")
    return cast(Manifest, value)


def connect_readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def check_database(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise RuntimeError("monthly database integrity check failed")
    if connection.execute("PRAGMA foreign_key_check").fetchall():
        raise RuntimeError("monthly database foreign key check failed")


def check_identity(
    connection: sqlite3.Connection, manifest: Manifest, month: str
) -> None:
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        raise RuntimeError(f"unsupported monthly database schema: {version}")
    try:
        identity = connection.execute(
            "SELECT collection_id, month FROM monthly_identity"
        ).fetchall()
    except sqlite3.Error as error:
        raise RuntimeError(f"monthly file identity is missing: {month}") from error
    if identity != [(manifest["collection_id"], month)]:
        raise RuntimeError(f"monthly file belongs to a different collection: {month}")


def inventory_high_water(root: Path, manifest: Manifest) -> int:
    maximum = 0
    for month in manifest["months"]:
        with closing(connect_readonly(root / f"{month}.db")) as reader:
            check_identity(reader, manifest, month)
            maximum = max(
                maximum,
                reader.execute("SELECT coalesce(max(id), 0) FROM scan").fetchone()[0],
            )
    return maximum


@contextmanager
def history_boundary(root: Path) -> Iterator[tuple[Manifest, int]]:
    """Block maintenance, but only briefly block append-only collection."""
    with file_lock(root / ".maintenance.lock", exclusive=False):
        with file_lock(root / ".operation.lock", exclusive=True):
            manifest = read_manifest(root)
            high_water = inventory_high_water(root, manifest)
        yield manifest, high_water


class MonthlyStorage:
    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        sync_directory(root.parent)
        self.root = root
        self._writer = (root / ".writer.lock").open("a+b")
        try:
            fcntl.flock(self._writer, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with (
                file_lock(root / ".maintenance.lock", exclusive=False, create=True),
                file_lock(root / ".operation.lock", exclusive=True, create=True),
            ):
                if not (root / "manifest.json").exists():
                    unexpected = [
                        path.name
                        for path in root.iterdir()
                        if path.name
                        not in {".writer.lock", ".maintenance.lock", ".operation.lock"}
                    ]
                    if unexpected:
                        raise RuntimeError(
                            "refusing to initialize nonempty monthly directory"
                        )
                    write_manifest(
                        root,
                        {
                            "format_version": 1,
                            "collection_id": str(uuid.uuid4()),
                            "months": [],
                        },
                    )
                self.manifest = read_manifest(root, allow_unregistered=True)
                self._recover_empty_files()
                self._check_global_ids()
                self.next_id = inventory_high_water(root, self.manifest) + 1
                self.metrics = self._load_retention()
        except BaseException:
            self._writer.close()
            raise

    def _check_global_ids(self) -> None:
        # A temporary on-disk index avoids retaining years of IDs in RAM.
        with closing(sqlite3.connect("")) as index:
            index.execute("CREATE TABLE seen (id INTEGER PRIMARY KEY)")
            for month in self.manifest["months"]:
                with closing(connect_readonly(self.root / f"{month}.db")) as reader:
                    check_identity(reader, self.manifest, month)
                    try:
                        index.executemany(
                            "INSERT INTO seen VALUES (?)",
                            reader.execute("SELECT id FROM scan"),
                        )
                    except sqlite3.IntegrityError as error:
                        raise RuntimeError(
                            "duplicate global scan identifier"
                        ) from error

    def _load_retention(self) -> dict[str, object]:
        count = 0
        first: tuple[int, str] | None = None
        last: tuple[int, str] | None = None
        for month in self.manifest["months"]:
            with closing(connect_readonly(self.root / f"{month}.db")) as reader:
                observed, first_id, last_id = reader.execute(
                    "SELECT count(*), min(scan_id), max(scan_id) "
                    "FROM observation_record"
                ).fetchone()
                count += observed
                if first_id is not None and (first is None or first_id < first[0]):
                    first = reader.execute(
                        "SELECT id, started_at FROM scan WHERE id = ?", (first_id,)
                    ).fetchone()
                if last_id is not None and (last is None or last_id > last[0]):
                    last = reader.execute(
                        "SELECT id, started_at FROM scan WHERE id = ?", (last_id,)
                    ).fetchone()
        return {
            "collection_id": self.manifest["collection_id"],
            "last_scan_id": self.next_id - 1 if self.next_id > 1 else None,
            "retained_observations": count,
            "first_observation_at": first[1] if first else None,
            "last_observation_at": last[1] if last else None,
            "growth_unknown_reason": "monthly growth estimator unavailable",
        }

    def _recover_empty_files(self) -> None:
        registered = {f"{month}.db" for month in self.manifest["months"]}
        for path in sorted(self.root.glob("*.db")):
            if path.name in registered:
                continue
            match = re.fullmatch(r"\.?([0-9]{4}-[0-9]{2})(?:\.pending)?\.db", path.name)
            if match is None:
                raise RuntimeError(f"unregistered monthly file: {path.name}")
            month = match[1]
            if re.fullmatch(
                r"[0-9]{4}-(0[1-9]|1[0-2])", month
            ) is None or month.startswith("0000-"):
                raise RuntimeError(f"invalid unregistered month: {month}")
            with Storage(path) as orphan:
                check_identity(orphan.connection, self.manifest, month)
                check_database(orphan.connection)
                if orphan.connection.execute("SELECT count(*) FROM scan").fetchone()[0]:
                    raise RuntimeError(
                        f"unregistered file contains history: {path.name}"
                    )
                orphan.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            target = self.root / f"{month}.db"
            if path != target:
                if target.exists():
                    raise RuntimeError(f"conflicting monthly creation: {month}")
                os.rename(path, target)
                sync_directory(self.root)
            self.manifest["months"].append(month)
            self.manifest["months"].sort()
            write_manifest(self.root, self.manifest)
        read_manifest(self.root)

    def _create_month(self, month: str) -> None:
        destination = self.root / f"{month}.db"
        # Preserve an interrupted creation for inspection; never overwrite it.
        staging = self.root / f".{month}.pending.db"
        if staging.exists() or destination.exists():
            raise RuntimeError(
                f"unfinished monthly creation requires inspection: {month}"
            )
        with Storage(staging) as store:
            with store.connection:
                store.connection.execute(
                    "CREATE TABLE monthly_identity "
                    "(collection_id TEXT NOT NULL, month TEXT NOT NULL)"
                )
                store.connection.execute(
                    "INSERT INTO monthly_identity VALUES (?, ?)",
                    (self.manifest["collection_id"], month),
                )
            store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            check_database(store.connection)
        with staging.open("rb") as stream:
            os.fsync(stream.fileno())
        os.rename(staging, destination)
        sync_directory(self.root)
        updated: Manifest = {
            **self.manifest,
            "months": sorted([*self.manifest["months"], month]),
        }
        write_manifest(self.root, updated)
        self.manifest = updated

    def save(self, scan: Scan) -> int:
        month = month_of(scan.started_at)
        with (
            file_lock(self.root / ".maintenance.lock", exclusive=False),
            file_lock(self.root / ".operation.lock", exclusive=True),
        ):
            current = read_manifest(self.root)
            if current != self.manifest:
                raise RuntimeError("monthly manifest changed during collection")
            if month not in self.manifest["months"]:
                self._create_month(month)
            with Storage(self.root / f"{month}.db") as store:
                check_identity(store.connection, self.manifest, month)
                saved = store.save(scan, scan_id=self.next_id)
            self.next_id = saved + 1
            self.metrics["last_scan_id"] = saved
            self.metrics["retained_observations"] = cast(
                int, self.metrics["retained_observations"]
            ) + len(scan.observations)
            if scan.observations:
                if self.metrics["first_observation_at"] is None:
                    self.metrics["first_observation_at"] = scan.started_at
                self.metrics["last_observation_at"] = scan.started_at
            return saved

    def close(self) -> None:
        self._writer.close()

    def __enter__(self) -> MonthlyStorage:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def open_storage(path: Path, layout: Layout = "single") -> Storage | MonthlyStorage:
    if layout == "single":
        return Storage(path)
    if layout == "monthly":
        return MonthlyStorage(path)
    raise ValueError(f"unsupported database layout: {layout}")
