"""Bounded logical-growth measurements, separate from WAL file occupancy."""

from __future__ import annotations

import sqlite3
from collections import deque
from dataclasses import dataclass
from pathlib import Path

WINDOW_MS = 3_600_000
MIN_WINDOW_MS = 600_000


def database_identity(path: Path) -> str:
    stat = path.stat()
    return f"{stat.st_dev}:{stat.st_ino}"


def logical_size(connection: sqlite3.Connection) -> int:
    pages = int(connection.execute("PRAGMA page_count").fetchone()[0])
    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
    return pages * page_size


@dataclass(frozen=True)
class Sample:
    monotonic_ms: int
    logical_bytes: int
    successful_scans: int
    failed_scans: int


class StorageMetrics:
    def __init__(
        self,
        connection: sqlite3.Connection,
        path: Path,
        monotonic_ms: int,
        max_gap_ms: int = 180_000,
    ) -> None:
        # Count the underlying records once per collector start, never per status.
        count, first_id, last_id = connection.execute(
            "SELECT count(*), min(scan_id), max(scan_id) FROM observation_record"
        ).fetchone()
        self.observations = int(count)
        self.first_at = self._timestamp(connection, first_id)
        self.last_at = self._timestamp(connection, last_id)
        self.identity = database_identity(path)
        self.max_gap_ms = max_gap_ms
        self.samples: deque[Sample] = deque(maxlen=61)
        self.samples.append(Sample(monotonic_ms, logical_size(connection), 0, 0))

    @staticmethod
    def _timestamp(connection: sqlite3.Connection, scan_id: int | None) -> str | None:
        if scan_id is None:
            return None
        row = connection.execute(
            "SELECT started_at FROM scan WHERE id = ?", (scan_id,)
        ).fetchone()
        return str(row[0])

    def record(
        self,
        connection: sqlite3.Connection,
        *,
        monotonic_ms: int,
        observation_count: int,
        started_at: str,
        scan_id: int,
        successful_scans: int,
        failed_scans: int,
        success: bool,
    ) -> dict[str, object]:
        self.observations += observation_count
        if observation_count:
            if self.first_at is None:
                self.first_at = started_at
            self.last_at = started_at
        current = Sample(
            monotonic_ms, logical_size(connection), successful_scans, failed_scans
        )
        if (
            current.monotonic_ms < self.samples[-1].monotonic_ms
            or current.monotonic_ms - self.samples[-1].monotonic_ms > self.max_gap_ms
            or current.logical_bytes < self.samples[-1].logical_bytes
        ):
            self.samples.clear()
        self.samples.append(current)
        while (
            len(self.samples) > 1
            and current.monotonic_ms - self.samples[0].monotonic_ms > WINDOW_MS
        ):
            self.samples.popleft()
        first = self.samples[0]
        elapsed = current.monotonic_ms - first.monotonic_ms
        growth = current.logical_bytes - first.logical_bytes
        successes = current.successful_scans - first.successful_scans
        failures = current.failed_scans - first.failed_scans
        reason = None
        if not success:
            reason = "latest scan was not successful"
        elif elapsed < MIN_WINDOW_MS:
            reason = "less than ten minutes of measurements"
        elif successes < 10:
            reason = "fewer than ten successful scans in the measurement window"
        elif growth < 40_960:
            reason = "logical growth below 40960 bytes; page allocation is too coarse"
        rate = growth / (elapsed / 1000) if reason is None else None
        return {
            "database_identity": self.identity,
            "last_scan_id": scan_id,
            "retained_observations": self.observations,
            "first_observation_at": self.first_at,
            "last_observation_at": self.last_at,
            "logical_database_bytes": current.logical_bytes,
            "measurement_seconds": elapsed / 1000,
            "measurement_growth_bytes": growth,
            "measurement_successful_scans": successes,
            "measurement_failed_scans": failures,
            "growth_bytes_per_second": rate,
            "growth_bytes_per_day": rate * 86400 if rate is not None else None,
            "growth_unknown_reason": reason,
        }
