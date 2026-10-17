"""Copy a stopped version 3 file into a validated, independent monthly set."""

from __future__ import annotations

import fcntl
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from typing import cast

from model import Observation, Scan, ScanStatus
from monthly_storage import (
    MonthlyStorage,
    check_database,
    connect_readonly,
    month_of,
    sync_directory,
)
from storage import SCHEMA_VERSION

SCAN_COLUMNS = (
    "id, device, started_at, finished_at, started_monotonic_ms, "
    "finished_monotonic_ms, boot_id, status, error"
)
OBSERVATION_COLUMNS = (
    "scan_id, bssid, frequency_mhz, ssid_bytes, ssid_display, "
    "signal_dbm, channel, security_json"
)


def _typed_columns(columns: str) -> str:
    return (
        columns
        + ", "
        + ", ".join(f"typeof({column})" for column in columns.split(", "))
    )


def _compare_scan(
    source: sqlite3.Connection, target: sqlite3.Connection, identifier: int
) -> None:
    for table, columns, key, order in (
        ("scan", SCAN_COLUMNS, "id", "id"),
        ("observation", OBSERVATION_COLUMNS, "scan_id", "bssid, frequency_mhz"),
    ):
        query = (
            f"SELECT {_typed_columns(columns)} FROM {table} "
            f"WHERE {key} = ? ORDER BY {order}"
        )
        if (
            source.execute(query, (identifier,)).fetchall()
            != target.execute(query, (identifier,)).fetchall()
        ):
            raise RuntimeError(
                f"monthly migration equivalence check failed: {identifier}"
            )


def migrate_monthly(source: Path, destination: Path) -> None:
    if destination.exists():
        raise RuntimeError("monthly destination already exists")
    if not destination.parent.is_dir():
        raise RuntimeError("monthly destination parent must already exist")
    with source.open("rb") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with closing(connect_readonly(source)) as original:
            original.execute("BEGIN")
            version = original.execute("PRAGMA user_version").fetchone()[0]
            if version != SCHEMA_VERSION:
                raise RuntimeError(
                    "monthly migration requires schema version 3; run migrate first"
                )
            check_database(original)
            staging = Path(
                tempfile.mkdtemp(
                    prefix=f".{destination.name}.import-", dir=destination.parent
                )
            )
            try:
                with MonthlyStorage(staging) as store:
                    for row in original.execute(
                        f"SELECT {SCAN_COLUMNS} FROM scan ORDER BY id"
                    ):
                        identifier = row[0]
                        observations = tuple(
                            Observation(*observation[1:])
                            for observation in original.execute(
                                f"SELECT {OBSERVATION_COLUMNS} FROM observation "
                                "WHERE scan_id = ? ORDER BY bssid, frequency_mhz",
                                (identifier,),
                            )
                        )
                        scan = Scan(
                            row[1],
                            row[2],
                            row[3],
                            row[4],
                            row[5],
                            row[6],
                            cast(ScanStatus, row[7]),
                            row[8],
                            observations,
                        )
                        store.save(scan, scan_id=identifier)
                        with closing(
                            connect_readonly(
                                staging / f"{month_of(scan.started_at)}.db"
                            )
                        ) as target:
                            _compare_scan(original, target, identifier)
                    for month in store.manifest["months"]:
                        with closing(
                            connect_readonly(staging / f"{month}.db")
                        ) as target:
                            check_database(target)
                if destination.exists():
                    raise RuntimeError("monthly destination appeared during migration")
                os.rename(staging, destination)
                sync_directory(destination.parent)
            except BaseException as error:
                raise RuntimeError(
                    "monthly migration failed; source unchanged; "
                    f"staging retained at {staging}: {error}"
                ) from error
