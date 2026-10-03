from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import cast

import control
from config import AppConfig
from storage import read_summary


def write_status(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".status-", delete=False
        ) as stream:
            temporary = Path(stream.name)
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), 0o640)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def existing_parent(path: Path) -> Path:
    parent = path.parent
    while not parent.exists() and parent != parent.parent:
        parent = parent.parent
    return parent


def _disk_status(path: Path) -> dict[str, object]:
    files = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
    sizes = {file.name: file.stat().st_size if file.exists() else 0 for file in files}
    return {
        "path": str(path),
        "file_sizes_bytes": sizes,
        "total_size_bytes": sum(sizes.values()),
        "disk_free_bytes": shutil.disk_usage(existing_parent(path)).free,
    }


def show_status(config: AppConfig, status_path: Path, as_json: bool) -> int:
    try:
        value = json.loads(status_path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("runtime status must be an object")
        runtime: dict[str, object] = cast(dict[str, object], value)
        if runtime.get("database_path") != str(config.database_path):
            raise ValueError("runtime status describes a different database")
    except (OSError, ValueError) as error:
        runtime = {"available": False, "error": str(error)}
    payload: dict[str, dict[str, object]] = {
        "service": dict(control.service_status()),
        "runtime": runtime,
        "history": read_summary(config.database_path),
        "storage": _disk_status(config.database_path),
    }
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        for section, values in payload.items():
            print(f"{section}:")
            for key, item in values.items():
                print(f"  {key}: {item}")
    return 0
