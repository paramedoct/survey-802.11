from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ScanStatus = Literal["success", "failed", "timeout", "cancelled"]


class ScanError(RuntimeError):
    def __init__(self, message: str, status: ScanStatus = "failed") -> None:
        super().__init__(message)
        self.status = status


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
    started_monotonic_ms: int
    finished_monotonic_ms: int
    boot_id: str
    status: ScanStatus
    error: str | None = None
    observations: tuple[Observation, ...] = ()
