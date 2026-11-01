from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from contextlib import closing
from pathlib import Path

from storage.database import (
    Layout,
    check_database,
    check_identity,
    connect_readonly,
    history_boundary,
    sync_directory,
    write_manifest,
)


def send_backup(database_path: Path, *, layout: Layout = "single") -> int:
    sender = shutil.which("sz")
    if sender is None:
        raise RuntimeError("sz is required; run ./3rdparty/setup-debian.sh")
    with tempfile.TemporaryDirectory(prefix="survey-backup-") as directory:
        snapshot = Path(directory) / database_path.name
        if layout == "monthly":
            snapshot_monthly(database_path, snapshot)
            archive = Path(directory) / f"{database_path.name}.tar"
            with tarfile.open(archive, "w:") as package:
                package.add(snapshot, arcname=database_path.name)
            snapshot = archive
        else:
            # Read-only mode refuses a missing source and includes committed WAL data.
            with (
                closing(connect_readonly(database_path)) as source,
                closing(sqlite3.connect(snapshot)) as destination,
            ):
                source.backup(destination, pages=256)
                destination.execute("PRAGMA journal_mode = DELETE")
        # Inherit the terminal for the ZMODEM protocol and receiver interaction.
        return subprocess.run([sender, str(snapshot)], check=False).returncode


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
