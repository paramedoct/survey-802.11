"""Measure version 2 migration, peak files and exact post-migration history."""

from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
import threading
import time
from contextlib import closing, suppress
from pathlib import Path

from storage_baseline import CASES, make_scan

from migration import migrate


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scans", type=int, default=1440)
    args = parser.parse_args()
    if args.scans < 1:
        parser.error("scans must be positive")
    schema = (
        Path(__file__).resolve().parent.parent / "tests/fixtures/schema_v2.sql"
    ).read_text()
    with tempfile.TemporaryDirectory(
        prefix="survey-migration-", dir="/tmp"
    ) as directory:
        root = Path(directory)
        path = root / "history.db"
        backup = root / "before.db"
        with closing(sqlite3.connect(path)) as connection:
            connection.executescript(schema)
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            for index in range(args.scans):
                scan = make_scan(CASES[0], index)
                with connection:
                    cursor = connection.execute(
                        "INSERT INTO scan (device, started_at, finished_at, "
                        "started_monotonic_ms, finished_monotonic_ms, boot_id, "
                        "status, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            scan.device,
                            scan.started_at,
                            scan.finished_at,
                            scan.started_monotonic_ms,
                            scan.finished_monotonic_ms,
                            scan.boot_id,
                            scan.status,
                            scan.error,
                        ),
                    )
                    connection.executemany(
                        "INSERT INTO observation VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            (
                                cursor.lastrowid,
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
        initial_bytes = path.stat().st_size
        stop = threading.Event()
        peak_files = peak_rss = 0

        def sample() -> None:
            nonlocal peak_files, peak_rss
            while True:
                total = 0
                for file in root.iterdir():
                    with suppress(FileNotFoundError):
                        total += file.stat().st_size
                peak_files = max(peak_files, total)
                for line in Path("/proc/self/status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        peak_rss = max(peak_rss, int(line.split()[1]) * 1024)
                if stop.wait(0.01):
                    break

        sampler = threading.Thread(target=sample)
        sampler.start()
        start = time.perf_counter()
        try:
            migrate(path, backup)
        finally:
            seconds = time.perf_counter() - start
            stop.set()
            sampler.join()
        migrated_bytes = path.stat().st_size
        with closing(sqlite3.connect(path)) as connection:
            free_pages = connection.execute("PRAGMA freelist_count").fetchone()[0]
            page_size = connection.execute("PRAGMA page_size").fetchone()[0]
            snapshot = root / "after.db"
            start = time.perf_counter()
            with closing(sqlite3.connect(snapshot)) as destination:
                connection.backup(destination, pages=256)
            backup_seconds = time.perf_counter() - start
            start = time.perf_counter()
            connection.execute("VACUUM")
            vacuum_seconds = time.perf_counter() - start
        output = {
            "scans": args.scans,
            "observations": args.scans * CASES[0].access_points,
            "migration_seconds_including_backup_and_validation": seconds,
            "original_bytes": initial_bytes,
            "migration_backup_bytes": backup.stat().st_size,
            "migrated_bytes_before_vacuum": migrated_bytes,
            "reusable_free_bytes": free_pages * page_size,
            "migrated_bytes_after_vacuum": path.stat().st_size,
            "sampled_peak_directory_bytes_during_migration": peak_files,
            "sampled_peak_process_rss_bytes_during_migration": peak_rss,
            "sampling_interval_seconds": 0.01,
            "normalized_backup_seconds": backup_seconds,
            "separate_vacuum_seconds": vacuum_seconds,
        }
        args.output.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
