from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ScanStatus = Literal["success", "failed", "timeout", "cancelled"]


@dataclass(frozen=True)
class Observation:
    bssid: str
    frequency_mhz: int
    ssid_bytes: bytes | None = None
    ssid_display: str | None = None
    signal_dbm: float | None = None
    channel: int | None = None
    security_json: str | None = None


@dataclass(frozen=True)
class Scan:
    device: str
    started_at: str
    finished_at: str
    started_monotonic_ns: int
    finished_monotonic_ns: int
    boot_id: str
    status: ScanStatus
    error: str | None = None
    observations: tuple[Observation, ...] = ()
