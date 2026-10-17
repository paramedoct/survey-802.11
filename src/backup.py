from __future__ import annotations

import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
from contextlib import closing
from pathlib import Path

from history import Layout
from monthly_backup import snapshot_monthly


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
            return subprocess.run([sender, str(archive)], check=False).returncode
        # Read-only mode refuses a missing source and includes committed WAL data.
        with (
            closing(
                sqlite3.connect(database_path.resolve().as_uri() + "?mode=ro", uri=True)
            ) as source,
            closing(sqlite3.connect(snapshot)) as destination,
        ):
            source.backup(destination, pages=256)
            destination.execute("PRAGMA journal_mode = DELETE")
        # Inherit the terminal for the ZMODEM protocol and receiver interaction.
        return subprocess.run([sender, str(snapshot)], check=False).returncode
