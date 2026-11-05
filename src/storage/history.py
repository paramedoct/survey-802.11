"""Observed SSID lists and complete retained-history summaries."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from sqlite3 import Connection

from storage.database import (
    READABLE_SCHEMA_VERSIONS,
    Layout,
    connect_readonly,
    history_boundary,
)
from storage.metrics import logical_size


@contextmanager
def sources(path: Path, layout: Layout) -> Iterator[tuple[list[Path], int, str | None]]:
    if layout == "monthly":
        with history_boundary(path) as (manifest, cutoff):
            yield (
                [path / f"{month}.db" for month in manifest["months"]],
                cutoff,
                manifest["collection_id"],
            )
    else:
        with closing(connect_readonly(path)) as reader:
            cutoff = reader.execute("SELECT coalesce(max(id), 0) FROM scan").fetchone()[
                0
            ]
        yield [path], cutoff, None


@dataclass(frozen=True)
class SsidSummary:
    ssid_bytes: bytes | None
    updated_at: datetime
    detection_count: int


def list_ssids(path: Path, layout: Layout = "single") -> list[SsidSummary]:
    """List raw SSIDs with their latest UTC time and number of detecting scans."""

    @lru_cache(maxsize=1024)
    def utc_timestamp(value: str) -> str:
        stamp = datetime.fromisoformat(value)
        if stamp.utcoffset() is None:
            raise ValueError("observation timestamps require a timezone")
        return stamp.astimezone(UTC).isoformat(timespec="microseconds")

    summaries: dict[bytes | None, SsidSummary] = {}
    with sources(path, layout) as (paths, cutoff, _):
        for source in paths:
            with closing(connect_readonly(source)) as reader:
                reader.create_function("utc_timestamp", 1, utc_timestamp)
                for raw, value, count in reader.execute(
                    "SELECT n.ssid_bytes, max(utc_timestamp(s.started_at)), "
                    "count(DISTINCT s.id) "
                    "FROM observation_record r "
                    "JOIN scan s ON s.id = r.scan_id "
                    "JOIN observation_profile p ON p.id = r.profile_id "
                    "JOIN network_name n ON n.id = p.name_id "
                    "WHERE s.id <= ? GROUP BY n.ssid_bytes",
                    (cutoff,),
                ):
                    stamp = datetime.fromisoformat(value)
                    previous = summaries.get(raw)
                    summaries[raw] = SsidSummary(
                        raw,
                        max(stamp, previous.updated_at) if previous else stamp,
                        count + (previous.detection_count if previous else 0),
                    )
    rows = list(summaries.values())
    rows.sort(key=lambda row: (row.ssid_bytes is not None, row.ssid_bytes or b""))
    rows.sort(key=lambda row: row.updated_at, reverse=True)
    return rows


type SummaryRow = tuple[int, str, str]


def _scan_summary(
    reader: Connection, cutoff: int = 2**63 - 1
) -> tuple[dict[str, int], SummaryRow | None, SummaryRow | None]:
    # The default includes every SQLite integer primary key.
    counts = dict(
        reader.execute(
            "SELECT status, count(*) FROM scan WHERE id <= ? GROUP BY status", (cutoff,)
        )
    )
    last = reader.execute(
        "SELECT id, finished_at, status FROM scan WHERE id <= ? "
        "ORDER BY id DESC LIMIT 1",
        (cutoff,),
    ).fetchone()
    error = reader.execute(
        "SELECT id, finished_at, error FROM scan WHERE id <= ? "
        "AND error IS NOT NULL ORDER BY id DESC LIMIT 1",
        (cutoff,),
    ).fetchone()
    return counts, last, error


def _summary(
    counts: dict[str, int], last: SummaryRow | None, error: SummaryRow | None
) -> dict[str, object]:
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
        "last_error_at": error[1] if error else None,
        "last_error": error[2] if error else None,
    }


def summarize(path: Path, layout: Layout = "single") -> dict[str, object]:
    if not path.exists():
        return {"available": False}
    if layout == "single":
        with closing(connect_readonly(path)) as reader:
            version = reader.execute("PRAGMA user_version").fetchone()[0]
            if version not in READABLE_SCHEMA_VERSIONS:
                raise RuntimeError(f"unsupported database schema version: {version}")
            return _summary(*_scan_summary(reader))
    with sources(path, layout) as (paths, cutoff, identity):
        counts: dict[str, int] = {}
        last: SummaryRow | None = None
        error: SummaryRow | None = None
        logical_bytes = 0
        for source in paths:
            with closing(connect_readonly(source)) as reader:
                new_counts, new_last, new_error = _scan_summary(reader, cutoff)
                for status, count in new_counts.items():
                    counts[status] = counts.get(status, 0) + count
                if new_last is not None and (last is None or new_last[0] > last[0]):
                    last = new_last
                if new_error is not None and (error is None or new_error[0] > error[0]):
                    error = new_error
                logical_bytes += logical_size(reader)
        return {
            **_summary(counts, last, error),
            "collection_id": identity,
            "logical_database_bytes": logical_bytes,
            "monthly_files": len(paths),
        }
