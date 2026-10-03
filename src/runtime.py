from __future__ import annotations

import logging
import os
import signal
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from threading import Event
from types import FrameType
from typing import Protocol

from config import AppConfig
from model import Observation, Scan, ScanError, ScanStatus
from reporting import write_status as write_status
from scanner import Scanner
from storage import Storage

_LOG = logging.getLogger(__name__)


class Clock(Protocol):
    def monotonic_ns(self) -> int: ...

    def timestamp(self) -> str: ...

    def wait(self, stop: Event, seconds: float) -> None: ...


class SystemClock:
    def monotonic_ns(self) -> int:
        return time.monotonic_ns()

    def timestamp(self) -> str:
        return datetime.now().astimezone().isoformat(timespec="microseconds")

    def wait(self, stop: Event, seconds: float) -> None:
        stop.wait(seconds)


@contextmanager
def shutdown_signals(stop: Event) -> Iterator[None]:
    def handle(signum: int, frame: FrameType | None) -> None:
        stop.set()

    previous = {
        sig: signal.signal(sig, handle) for sig in (signal.SIGTERM, signal.SIGINT)
    }
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


class Collector:
    def __init__(
        self,
        config: AppConfig,
        scanner: Scanner,
        status_path: Path,
        *,
        clock: Clock | None = None,
        stop: Event | None = None,
        boot_id: str | None = None,
    ) -> None:
        self.config = config
        self.scanner = scanner
        self.status_path = status_path
        self.clock: Clock = clock if clock is not None else SystemClock()
        self.stop = stop if stop is not None else Event()
        self.boot_id = (
            boot_id
            if boot_id is not None
            else Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        )
        self.successful_scans = 0
        self.failed_scans = 0
        self.skipped_periods = 0
        self.state: dict[str, object] = {
            "pid": os.getpid(),
            "boot_id": self.boot_id,
            "database_path": str(config.database_path),
            "device": config.device,
            "started_at": self.clock.timestamp(),
            "running": True,
            "successful_scans": 0,
            "failed_scans": 0,
            "skipped_periods": 0,
            "last_scan_at": None,
            "last_commit_at": None,
            "last_error": None,
            "last_error_at": None,
            "last_scan_id": None,
        }

    def _publish(self) -> None:
        self.state["updated_at"] = self.clock.timestamp()
        self.state["successful_scans"] = self.successful_scans
        self.state["failed_scans"] = self.failed_scans
        self.state["skipped_periods"] = self.skipped_periods
        write_status(self.status_path, self.state)

    def _scan(self) -> Scan:
        started_at = self.clock.timestamp()
        started_ns = self.clock.monotonic_ns()
        status: ScanStatus = "success"
        error: str | None = None
        observations: tuple[Observation, ...] = ()
        try:
            observations = self.scanner.scan(self.config.timeout_s, self.stop)
        except ScanError as failure:
            status, error = failure.status, str(failure)
            if status != "cancelled":
                _LOG.warning("scan %s: %s", status, error)
        return Scan(
            self.config.device,
            started_at,
            self.clock.timestamp(),
            started_ns,
            self.clock.monotonic_ns(),
            self.boot_id,
            status,
            error,
            observations,
        )

    def _record_scan(self, scan: Scan) -> None:
        self.state["last_scan_at"] = scan.finished_at
        self.state["last_scan_status"] = scan.status
        self.state["last_observation_count"] = len(scan.observations)

    def _record_commit(self, scan: Scan, scan_id: int) -> None:
        self.state["last_scan_id"] = scan_id
        self.state["last_commit_at"] = self.clock.timestamp()
        if scan.status == "success":
            self.successful_scans += 1
        else:
            self.failed_scans += 1
        if scan.error is not None:
            self.state["last_error"] = scan.error
            self.state["last_error_at"] = scan.finished_at
        _LOG.info(
            "saved scan %s: %s, %s observations",
            scan_id,
            scan.status,
            len(scan.observations),
        )

    def run(self) -> None:
        try:
            self._publish()
            self.scanner.prepare(self.stop)
            with Storage(self.config.database_path) as storage:
                interval_ns = self.config.interval_s * 1_000_000_000
                deadline = self.clock.monotonic_ns()
                while not self.stop.is_set():
                    self.clock.wait(
                        self.stop,
                        max(
                            0.0, (deadline - self.clock.monotonic_ns()) / 1_000_000_000
                        ),
                    )
                    if self.stop.is_set():
                        break
                    scan = self._scan()
                    self._record_scan(scan)
                    scan_id = storage.save(scan)
                    self._record_commit(scan, scan_id)
                    deadline += interval_ns
                    now = self.clock.monotonic_ns()
                    if deadline < now:
                        skipped = (now - deadline + interval_ns - 1) // interval_ns
                        deadline += skipped * interval_ns
                        self.skipped_periods += skipped
                    self._publish()
        except ScanError as error:
            if error.status != "cancelled":
                self.state["last_error"] = str(error)
                self.state["last_error_at"] = self.clock.timestamp()
                _LOG.exception("collector startup failed")
                raise
        except Exception as error:
            self.state["last_error"] = str(error)
            self.state["last_error_at"] = self.clock.timestamp()
            _LOG.exception("collector failed")
            raise
        finally:
            self.state["running"] = False
            try:
                self._publish()
            except OSError:
                _LOG.exception("cannot publish final status")
