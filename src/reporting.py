from __future__ import annotations

import json
import math
import os
import shutil
import sqlite3
import tempfile
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import control
from config import AppConfig
from storage import read_summary
from storage_metrics import database_identity, logical_size


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


def _growth_status(
    config: AppConfig, runtime: dict[str, object], free_bytes: int
) -> dict[str, object]:
    result: dict[str, object] = {
        "logical_database_bytes": None,
        "retained_observations": None,
        "first_observation_at": None,
        "last_observation_at": None,
        "retention_unknown_reason": "matching collector measurements unavailable",
        "growth_bytes_per_day": None,
        "estimated_days_remaining": None,
        "estimate_status": "unknown",
        "estimate_unknown_reason": "matching collector measurements unavailable",
    }
    path = config.database_path
    if not path.exists():
        return result
    with closing(
        sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    ) as connection:
        connection.execute("BEGIN")
        result["logical_database_bytes"] = logical_size(connection)
        row = connection.execute("SELECT max(id) FROM scan").fetchone()
        last_scan_id = row[0]
    raw_metrics = runtime.get("storage_metrics")
    if not isinstance(raw_metrics, dict):
        return result
    metrics = cast(dict[str, object], raw_metrics)
    if (
        metrics.get("database_identity") != database_identity(path)
        or metrics.get("last_scan_id") != last_scan_id
    ):
        result["retention_unknown_reason"] = (
            "collector measurements do not match history"
        )
        result["estimate_unknown_reason"] = result["retention_unknown_reason"]
        return result
    count = metrics.get("retained_observations")
    if type(count) is not int or count < 0:
        return result
    result["retained_observations"] = count
    result["retention_unknown_reason"] = None
    for key in (
        "first_observation_at",
        "last_observation_at",
        "measurement_seconds",
        "measurement_growth_bytes",
        "measurement_successful_scans",
        "measurement_failed_scans",
    ):
        result[key] = metrics.get(key)
    reason = None
    if runtime.get("running") is not True:
        reason = "collector is stopped"
    else:
        try:
            updated = runtime.get("updated_at")
            if not isinstance(updated, str):
                raise ValueError("missing timestamp")
            age = (datetime.now(UTC) - datetime.fromisoformat(updated)).total_seconds()
            if not 0 <= age <= max(180, config.interval_s * 2 + config.timeout_s):
                reason = "collector measurements are stale or clock moved backwards"
        except (ValueError, TypeError):
            reason = "collector measurement timestamp is invalid"
    if reason is None and metrics.get("growth_unknown_reason") is not None:
        reason = str(metrics["growth_unknown_reason"])
    rate = metrics.get("growth_bytes_per_second")
    if reason is None and (
        type(rate) not in {int, float}
        or not isinstance(rate, (int, float))
        or not math.isfinite(rate)
        or rate <= 0
    ):
        reason = "positive measured growth rate unavailable"
    result["estimate_unknown_reason"] = reason
    if reason is None:
        assert isinstance(rate, (int, float))
        result["growth_bytes_per_day"] = rate * 86400
        result["estimated_days_remaining"] = free_bytes / rate / 86400
        result["estimate_status"] = "estimate at recent measured workload"
    return result


def _disk_status(config: AppConfig, runtime: dict[str, object]) -> dict[str, object]:
    path = config.database_path
    files = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
    sizes = {file.name: file.stat().st_size if file.exists() else 0 for file in files}
    free_bytes = shutil.disk_usage(existing_parent(path)).free
    return {
        "path": str(path),
        "file_sizes_bytes": sizes,
        "total_size_bytes": sum(sizes.values()),
        "disk_free_bytes": free_bytes,
        "capacity": _growth_status(config, runtime, free_bytes),
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
        "storage": _disk_status(config, runtime),
    }
    if as_json:
        print(json.dumps(payload, sort_keys=True))
    else:
        for section, values in payload.items():
            print(f"{section}:")
            for key, item in values.items():
                print(f"  {key}: {item}")
    return 0
