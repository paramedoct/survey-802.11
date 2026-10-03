from __future__ import annotations

from pathlib import Path

from model import Observation, Scan


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
