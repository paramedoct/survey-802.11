"""Measure deterministic synthetic inputs through the production Storage API."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import platform
import sqlite3
import statistics
import tempfile
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol, cast

from model import Observation, Scan

HISTORY_SQL = """
SELECT s.started_at, o.* FROM observation AS o
JOIN scan AS s ON s.id = o.scan_id
WHERE o.bssid = ? ORDER BY o.scan_id
"""


class Store(Protocol):
    connection: sqlite3.Connection

    def save(self, scan: Scan) -> int: ...

    def close(self) -> None: ...


class Factory(Protocol):
    def __call__(self, path: Path) -> Store: ...


@dataclass(frozen=True)
class Case:
    name: str
    access_points: int = 50
    ssid_bytes: int = 16
    security_bytes: int = 128
    change_every_scans: int = 0


CASES = (
    Case("base"),
    Case("ap10", access_points=10),
    Case("ap200", access_points=200),
    Case("ssid8", ssid_bytes=8),
    Case("ssid32", ssid_bytes=32),
    Case("security64", security_bytes=64),
    Case("security512", security_bytes=512),
    Case("change60", change_every_scans=60),
    Case("change1", change_every_scans=1),
)


def make_scan(case: Case, index: int) -> Scan:
    epoch = index // case.change_every_scans if case.change_every_scans else 0
    stamp = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=index)
    observations = []
    for ap in range(case.access_points):
        name = f"{ap:04x}{epoch:04x}".ljust(case.ssid_bytes, "n")
        security = json.dumps(
            {"v": f"{epoch:08x}".ljust(case.security_bytes - 8, "s")},
            separators=(",", ":"),
        )
        observations.append(
            Observation(
                bssid=f"02:00:00:00:{ap // 256:02x}:{ap % 256:02x}",
                frequency_mhz=2412,
                ssid_bytes=name.encode(),
                ssid_display=name,
                signal_dbm=-40.0 - (index + ap) % 50,
                channel=1,
                security_json=security,
            )
        )
    return Scan(
        device="wlan0",
        started_at=stamp.isoformat(timespec="microseconds"),
        finished_at=(stamp + timedelta(seconds=2)).isoformat(timespec="microseconds"),
        started_monotonic_ms=index * 60_000,
        finished_monotonic_ms=index * 60_000 + 2_000,
        boot_id="00000000-0000-0000-0000-000000000001",
        status="success",
        observations=tuple(observations),
    )


def file_size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def measure(
    case: Case, scans: int, directory: Path, factory: Factory, history_sql: str
) -> dict[str, object]:
    path = directory / f"{case.name}.sqlite3"
    store = factory(path)
    connection = store.connection
    try:
        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        empty_bytes = file_size(path)
        settings = {
            key: connection.execute(f"PRAGMA {key}").fetchone()[0]
            for key in (
                "page_size",
                "journal_mode",
                "synchronous",
                "wal_autocheckpoint",
            )
        }
        digest = hashlib.sha256()
        peak_wal = peak_shm = peak_total = 0
        save_seconds = 0.0
        for index in range(scans):
            scan = make_scan(case, index)
            encoded = json.dumps(
                asdict(scan),
                default=lambda value: value.hex(),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            digest.update(encoded + b"\n")
            start = time.perf_counter()
            store.save(scan)
            save_seconds += time.perf_counter() - start
            wal = file_size(Path(str(path) + "-wal"))
            shm = file_size(Path(str(path) + "-shm"))
            peak_wal = max(peak_wal, wal)
            peak_shm = max(peak_shm, shm)
            peak_total = max(peak_total, file_size(path) + wal + shm)
        checkpoint = connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        if checkpoint[0] != 0:
            raise RuntimeError(f"checkpoint busy: {checkpoint}")
        durable = file_size(path)
        objects: list[dict[str, object]] = []
        dbstat_error: str | None = None
        try:
            objects = [
                {"name": name, "bytes": size, "share_percent": size / durable * 100}
                for name, size in connection.execute(
                    "SELECT name, sum(pgsize) FROM dbstat GROUP BY name ORDER BY name"
                )
            ]
        except sqlite3.OperationalError as error:
            dbstat_error = str(error)
        address = "02:00:00:00:00:00"
        plan = connection.execute("EXPLAIN QUERY PLAN " + history_sql, (address,))
        query_plan = [list(row) for row in plan]
        timings = []
        row_count = 0
        for _ in range(31):
            start = time.perf_counter()
            rows = connection.execute(history_sql, (address,)).fetchall()
            timings.append((time.perf_counter() - start) * 1000)
            row_count = len(rows)
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
        if integrity != "ok" or foreign_keys or row_count != scans:
            raise RuntimeError("database integrity or history row count check failed")
        count = scans * case.access_points
        growth = durable - empty_bytes
        return {
            "case": asdict(case),
            "input_sha256": digest.hexdigest(),
            "scans": scans,
            "observations": count,
            "schema_version": connection.execute("PRAGMA user_version").fetchone()[0],
            "settings": settings,
            "empty_database_bytes": empty_bytes,
            "durable_database_bytes": durable,
            "logical_growth_bytes": growth,
            "growth_bytes_per_observation": growth / count,
            "projected_growth_bytes_per_day": growth / scans * 1440,
            "projected_growth_bytes_per_30_days": growth / scans * 1440 * 30,
            "sampled_peak_wal_bytes": peak_wal,
            "sampled_peak_shm_bytes": peak_shm,
            "sampled_peak_total_file_bytes": peak_total,
            "save_seconds": save_seconds,
            "dbstat_objects": objects,
            "dbstat_error": dbstat_error,
            "history_first_ms": timings[0],
            "history_warm_median_ms": statistics.median(timings[1:]),
            "history_warm_p95_ms": sorted(timings[1:])[28],
            "history_rows": row_count,
            "history_query_plan": query_plan,
            "integrity_check": integrity,
        }
    finally:
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scans", type=int, default=1440)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--storage-module", default="storage")
    parser.add_argument("--history-sql", type=Path)
    args = parser.parse_args()
    if not 1 <= args.scans <= 65535:
        parser.error("scans must be between 1 and 65535")
    module = importlib.import_module(args.storage_module)
    factory = cast(Factory, module.Storage)
    history_sql = args.history_sql.read_text() if args.history_sql else HISTORY_SQL
    with tempfile.TemporaryDirectory(
        prefix="survey-storage-baseline-", dir="/tmp"
    ) as tmp:
        results = [
            measure(case, args.scans, Path(tmp), factory, history_sql) for case in CASES
        ]
    output = {
        "workload_version": 1,
        "synthetic": True,
        "interval_seconds": 60,
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "platform": platform.platform(),
        "storage_module": args.storage_module,
        "history_sql": history_sql,
        "results": results,
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
