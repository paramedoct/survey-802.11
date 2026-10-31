"""Observed SSID lists and complete retained-history summaries."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from storage.database import Layout, connect_readonly, history_boundary, read_summary


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


def list_ssids(path: Path, layout: Layout = "single") -> list[SsidSummary]:
    """List every distinct raw SSID by its latest observation time in UTC."""

    @lru_cache(maxsize=1024)
    def utc_timestamp(value: str) -> str:
        stamp = datetime.fromisoformat(value)
        if stamp.utcoffset() is None:
            raise ValueError("observation timestamps require a timezone")
        return stamp.astimezone(UTC).isoformat(timespec="microseconds")

    latest: dict[bytes | None, datetime] = {}
    with sources(path, layout) as (paths, cutoff, _):
        for source in paths:
            with closing(connect_readonly(source)) as reader:
                reader.create_function("utc_timestamp", 1, utc_timestamp)
                for raw, value in reader.execute(
                    "SELECT n.ssid_bytes, max(utc_timestamp(s.started_at)) "
                    "FROM observation_record r "
                    "JOIN scan s ON s.id = r.scan_id "
                    "JOIN observation_profile p ON p.id = r.profile_id "
                    "JOIN network_name n ON n.id = p.name_id "
                    "WHERE s.id <= ? GROUP BY n.ssid_bytes",
                    (cutoff,),
                ):
                    stamp = datetime.fromisoformat(value)
                    if raw not in latest or stamp > latest[raw]:
                        latest[raw] = stamp
    rows = [SsidSummary(raw, stamp) for raw, stamp in latest.items()]
    rows.sort(key=lambda row: (row.ssid_bytes is not None, row.ssid_bytes or b""))
    rows.sort(key=lambda row: row.updated_at, reverse=True)
    return rows


def summarize(path: Path, layout: Layout = "single") -> dict[str, object]:
    if layout == "single":
        return read_summary(path)
    if not path.exists():
        return {"available": False}
    with sources(path, layout) as (paths, cutoff, identity):
        counts: dict[str, int] = {}
        last: tuple[int, str, str] | None = None
        error: tuple[int, str, str] | None = None
        logical_bytes = 0
        for source in paths:
            with closing(connect_readonly(source)) as reader:
                for status, count in reader.execute(
                    "SELECT status, count(*) FROM scan WHERE id <= ? GROUP BY status",
                    (cutoff,),
                ):
                    counts[status] = counts.get(status, 0) + count
                candidate = reader.execute(
                    "SELECT id, finished_at, status FROM scan WHERE id <= ? "
                    "ORDER BY id DESC LIMIT 1",
                    (cutoff,),
                ).fetchone()
                if candidate is not None and (last is None or candidate[0] > last[0]):
                    last = candidate
                candidate = reader.execute(
                    "SELECT id, finished_at, error FROM scan WHERE id <= ? "
                    "AND error IS NOT NULL ORDER BY id DESC LIMIT 1",
                    (cutoff,),
                ).fetchone()
                if candidate is not None and (error is None or candidate[0] > error[0]):
                    error = candidate
                logical_bytes += (
                    reader.execute("PRAGMA page_count").fetchone()[0]
                    * reader.execute("PRAGMA page_size").fetchone()[0]
                )
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
            "collection_id": identity,
            "logical_database_bytes": logical_bytes,
            "monthly_files": len(paths),
        }
