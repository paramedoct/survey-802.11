"""Consistent monthly snapshots without pausing collection for a full backup."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from pathlib import Path

from monthly_storage import (
    check_database,
    check_identity,
    connect_readonly,
    history_boundary,
    sync_directory,
    write_manifest,
)


def snapshot_monthly(source: Path, destination: Path) -> None:
    destination.mkdir()
    with history_boundary(source) as (manifest, cutoff):
        checksums: dict[str, str] = {}
        for month in manifest["months"]:
            name = f"{month}.db"
            target = destination / name
            with (
                closing(connect_readonly(source / name)) as reader,
                closing(sqlite3.connect(target)) as snapshot,
            ):
                reader.backup(snapshot, pages=256)
                snapshot.execute("PRAGMA foreign_keys = ON")
                check_identity(snapshot, manifest, month)
                with snapshot:
                    snapshot.execute(
                        "DELETE FROM observation_record WHERE scan_id > ?", (cutoff,)
                    )
                    snapshot.execute("DELETE FROM scan WHERE id > ?", (cutoff,))
                snapshot.execute("PRAGMA journal_mode = DELETE")
                check_database(snapshot)
            with target.open("rb") as stream:
                checksums[name] = hashlib.file_digest(stream, "sha256").hexdigest()
        write_manifest(destination, manifest)
        for name in (".writer.lock", ".maintenance.lock", ".operation.lock"):
            (destination / name).touch()
        (destination / "backup.json").write_text(
            json.dumps(
                {"high_water_scan_id": cutoff, "sha256": checksums}, sort_keys=True
            )
            + "\n",
            encoding="utf-8",
        )
        sync_directory(destination)
