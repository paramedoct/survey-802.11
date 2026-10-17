"""Bounded cross-month history queries and complete retained-history summaries."""

from __future__ import annotations

import heapq
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Literal

from monthly_storage import connect_readonly, history_boundary
from storage import read_summary

Layout = Literal["single", "monthly"]


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


def query_history(
    path: Path,
    layout: Layout = "single",
    *,
    bssid: str | None = None,
    scan_id: int | None = None,
    before_id: int | None = None,
    limit: int = 100,
) -> list[dict[str, object]]:
    """Return the newest complete scans, with all their observations.

    The limit counts scans, not observations, so before_id pagination cannot
    discard observations from a partially returned scan.
    """
    if not 1 <= limit <= 10000:
        raise ValueError("history limit must be between 1 and 10000 scans")
    with sources(path, layout) as (paths, cutoff, _):
        candidates: list[int] = []
        filters = ["s.id <= ?"]
        values: list[object] = [cutoff]
        if scan_id is not None:
            filters.append("s.id = ?")
            values.append(scan_id)
        if before_id is not None:
            filters.append("s.id < ?")
            values.append(before_id)
        if bssid is not None:
            filters.append(
                "EXISTS (SELECT 1 FROM observation o "
                "WHERE o.scan_id = s.id AND o.bssid = ?)"
            )
            values.append(bssid)
        where = " AND ".join(filters)
        for source in paths:
            with closing(connect_readonly(source)) as reader:
                for (identifier,) in reader.execute(
                    f"SELECT s.id FROM scan s WHERE {where} ORDER BY s.id DESC LIMIT ?",
                    [*values, limit],
                ):
                    heapq.heappush(candidates, identifier)
                    if len(candidates) > limit:
                        heapq.heappop(candidates)
        if not candidates:
            return []
        if len(set(candidates)) != len(candidates):
            raise RuntimeError("duplicate global scan identifier")
        minimum = min(candidates)
        rows: list[dict[str, object]] = []
        for source in paths:
            with closing(connect_readonly(source)) as reader:
                reader.row_factory = sqlite3.Row
                observation_filter = " AND o.bssid = ?" if bssid is not None else ""
                query_values = [*values, minimum]
                if bssid is not None:
                    query_values.append(bssid)
                rows.extend(
                    dict(row)
                    for row in reader.execute(
                        "SELECT s.*, o.bssid, o.frequency_mhz, o.ssid_bytes, "
                        "o.ssid_display, o.signal_dbm, o.channel, o.security_json "
                        "FROM scan s LEFT JOIN observation o ON o.scan_id = s.id "
                        f"WHERE {where} AND s.id >= ?{observation_filter} "
                        "ORDER BY s.id DESC, o.bssid, o.frequency_mhz",
                        query_values,
                    )
                )
        rows.sort(
            key=lambda row: (
                -int(str(row["id"])),
                str(row["bssid"]),
                int(str(row["frequency_mhz"] or 0)),
            )
        )
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
