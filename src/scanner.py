from __future__ import annotations

import os
import signal
import subprocess
import time
from contextlib import suppress
from threading import Event
from typing import Protocol

from model import Observation
from model import ScanError as ScanError
from scan_parser import channel_for_frequency as channel_for_frequency
from scan_parser import parse_scan as parse_scan


class Scanner(Protocol):
    def prepare(self, stop: Event) -> None: ...

    def scan(self, timeout_s: int, stop: Event) -> tuple[Observation, ...]: ...



def _terminate(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()


def run_command(arguments: list[str], timeout_s: int, stop: Event) -> bytes:
    if stop.is_set():
        raise ScanError("scan cancelled", "cancelled")
    environment = dict(os.environ, LC_ALL="C", LANG="C")
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
        )
    except OSError as error:
        raise ScanError(f"cannot execute {arguments[0]}: {error}") from error
    deadline = time.monotonic() + timeout_s
    drained = False
    try:
        while True:
            if process.poll() is None:
                if stop.is_set():
                    raise ScanError("scan cancelled", "cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ScanError(f"scan timed out after {timeout_s}s", "timeout")
            else:
                remaining = 0.2
            try:
                stdout, stderr = process.communicate(timeout=min(remaining, 0.2))
            except subprocess.TimeoutExpired:
                if stop.is_set():
                    raise ScanError("scan cancelled", "cancelled") from None
                if time.monotonic() >= deadline:
                    raise ScanError(
                        f"scan timed out after {timeout_s}s", "timeout"
                    ) from None
                continue
            drained = True
            if process.returncode:
                detail = stderr.decode("utf-8", errors="replace").strip()[:4096]
                raise ScanError(f"{arguments[0]} exited {process.returncode}: {detail}")
            if stderr.strip():
                raise ScanError(stderr.decode("utf-8", errors="replace").strip()[:4096])
            return stdout
    finally:
        if not drained:
            _terminate(process)
        else:
            process.communicate()


class IwScanner:
    def __init__(self, device: str) -> None:
        self.device = device

    def prepare(self, stop: Event) -> None:
        run_command(["ip", "link", "set", "dev", self.device, "up"], 5, stop)

    def scan(self, timeout_s: int, stop: Event) -> tuple[Observation, ...]:
        return parse_scan(
            run_command(["iw", "dev", self.device, "scan", "flush"], timeout_s, stop)
        )
