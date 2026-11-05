from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from model import Observation, Scan
from storage.database import Layout
from storage.history import sources


def sample_scan(*observations: Observation) -> Scan:
    return Scan(
        "wlan0",
        "2026-10-03T10:00:00+09:00",
        "2026-10-03T10:00:01+09:00",
        100,
        200,
        "test-boot",
        "success",
        observations=observations,
    )


def executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o755)


def observation_history(
    path: Path, layout: Layout = "single"
) -> list[dict[str, object]]:
    """Read complete raw history to compare storage and backup contents."""
    rows: list[dict[str, object]] = []
    with sources(path, layout) as (paths, cutoff, _):
        for source in paths:
            with closing(sqlite3.connect(source)) as reader:
                reader.row_factory = sqlite3.Row
                rows.extend(
                    dict(row)
                    for row in reader.execute(
                        "SELECT s.*, o.bssid, o.frequency_mhz, o.ssid_bytes, "
                        "o.ssid_display, o.signal_dbm, o.channel, o.security_json, "
                        "o.wifi_generations_json, o.wifi_generation "
                        "FROM scan s LEFT JOIN observation o ON o.scan_id = s.id "
                        "WHERE s.id <= ?",
                        (cutoff,),
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
