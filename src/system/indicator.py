from __future__ import annotations

import json
import logging
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from threading import Event, Lock, Thread
from typing import Literal

from system.service import SERVICE_NAME

_LOG = logging.getLogger(__name__)
Mode = Literal["normal", "abnormal", "default"]


def classify(
    service: Mapping[str, str],
    runtime: Mapping[str, object],
    boot_id: str,
    now_ms: int,
) -> Mode:
    if service.get("ActiveState") == "inactive" and service.get("Result") == "success":
        return "default"
    invocation = service.get("InvocationID")
    age_limit = runtime.get("stale_after_ms")
    completed = runtime.get("last_result_monotonic_ms")
    if (
        service.get("ActiveState") != "active"
        or not invocation
        or runtime.get("invocation_id") != invocation
        or runtime.get("boot_id") != boot_id
        or runtime.get("running") is not True
        or runtime.get("last_result_success") is not True
        or type(age_limit) is not int
        or type(completed) is not int
    ):
        return "abnormal"
    assert isinstance(age_limit, int) and isinstance(completed, int)
    return (
        "normal"
        if age_limit > 0 and 0 <= now_ms - completed < age_limit
        else "abnormal"
    )


def sample(status_path: Path, boot_id: str) -> Mode:
    result = subprocess.run(
        [
            "systemctl",
            "show",
            SERVICE_NAME,
            "--no-pager",
            "--property=ActiveState,Result,InvocationID",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=1,
    )
    service = dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
    # A stopped collector need not have a runtime status file.
    if service.get("ActiveState") == "inactive" and service.get("Result") == "success":
        return "default"
    value = json.loads(status_path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        return "abnormal"
    return classify(service, value, boot_id, time.monotonic_ns() // 1_000_000)


@dataclass(frozen=True)
class Snapshot:
    mode: Mode
    sampled_at: float


class Monitor:
    def __init__(self, read: Callable[[], Mode]) -> None:
        self.read = read
        self.lock = Lock()
        self.snapshot = Snapshot("abnormal", float("-inf"))

    def poll(self, stop: Event) -> None:
        previous_error: str | None = None
        while not stop.is_set():
            started = time.monotonic()
            try:
                mode = self.read()
                previous_error = None
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                mode = "abnormal"
                message = str(error)
                if message != previous_error:
                    _LOG.warning("cannot read collection status: %s", message)
                previous_error = message
            with self.lock:
                self.snapshot = Snapshot(mode, time.monotonic())
            stop.wait(max(0, 1 - (time.monotonic() - started)))

    def mode(self, now: float) -> Mode:
        with self.lock:
            snapshot = self.snapshot
        return snapshot.mode if 0 <= now - snapshot.sampled_at < 3 else "abnormal"


class Led:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.maximum = int((path / "max_brightness").read_text())
        if self.maximum <= 0:
            raise ValueError("invalid maximum LED brightness")

    @classmethod
    def discover(cls) -> Led | None:
        for name in ("ACT", "led0"):
            path = Path("/sys/class/leds") / name
            if not path.exists():
                continue
            triggers = (
                (path / "trigger").read_text().replace("[", "").replace("]", "").split()
            )
            if "actpwr" in triggers and "none" in triggers:
                return cls(path)
        return None

    def acquire(self) -> None:
        (self.path / "trigger").write_text("none\n")

    def brightness(self, on: bool) -> None:
        (self.path / "brightness").write_text(f"{self.maximum if on else 0}\n")

    def restore(self) -> None:
        (self.path / "trigger").write_text("actpwr\n")


class Pattern:
    def __init__(self) -> None:
        self.mode: Mode | None = None
        self.started = 0.0

    def output(self, mode: Mode, now: float) -> bool | None:
        if mode != self.mode:
            self.mode, self.started = mode, now
        if mode == "default":
            return None
        period = 5 if mode == "normal" else 1
        return (now - self.started) % period < 0.5


def indicate(status_path: Path, stop: Event) -> None:
    led = Led.discover()
    if led is None:
        _LOG.warning("compatible ACT LED with actpwr support unavailable")
        return
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    monitor = Monitor(lambda: sample(status_path, boot_id))
    worker = Thread(target=monitor.poll, args=(stop,), daemon=True)
    pattern = Pattern()
    previous: bool | None = None
    owned = False
    worker.start()
    try:
        while not stop.is_set():
            now = time.monotonic()
            mode = monitor.mode(now)
            output = pattern.output(mode, now)
            if output is None:
                if pattern.mode == "default" and (owned or previous is None):
                    led.restore()
                    owned = False
                    # Avoid repeatedly writing the default trigger.
                    previous = False
            else:
                if not owned:
                    led.acquire()
                    owned = True
                    previous = None
                if output != previous:
                    led.brightness(output)
                    previous = output
            stop.wait(0.05)
    finally:
        stop.set()
        worker.join(timeout=2)
        led.restore()
