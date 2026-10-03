from __future__ import annotations

import json
import math
import os
import re
import signal
import subprocess
import time
from contextlib import suppress
from dataclasses import dataclass, field
from threading import Event
from typing import Protocol

from model import Observation, ScanStatus

_BSSID = re.compile(
    rb"BSS ([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})(?:\(on [^)]+\))?(?: -- .*)?"
)
_SIGNAL = re.compile(rb"(-?\d+)\.(-?\d+) dBm")
_SUITES = re.compile(r"(?:FT/)?IEEE 802\.1X(?:/[^ ]+)?|Use group cipher suite|[^ ]+")


class ScanError(RuntimeError):
    def __init__(self, message: str, status: ScanStatus = "failed") -> None:
        super().__init__(message)
        self.status = status


class Scanner(Protocol):
    def prepare(self, stop: Event) -> None: ...

    def scan(self, timeout_s: int, stop: Event) -> tuple[Observation, ...]: ...


def channel_for_frequency(frequency: int) -> int | None:
    if frequency == 2484:
        return 14
    if 2412 <= frequency <= 2472 and (frequency - 2407) % 5 == 0:
        return (frequency - 2407) // 5
    if 4910 <= frequency <= 4980 and frequency % 5 == 0:
        return (frequency - 4000) // 5
    if 5000 <= frequency <= 5895 and frequency % 5 == 0:
        return (frequency - 5000) // 5
    if frequency == 5935:
        return 2
    if 5955 <= frequency <= 7115 and (frequency - 5950) % 5 == 0:
        return (frequency - 5950) // 5
    return None


def _ssid(value: bytes) -> bytes:
    result = bytearray()
    offset = 0
    while offset < len(value):
        if value[offset] == 92:
            escape = value[offset : offset + 4]
            if not re.fullmatch(rb"\\x[0-9a-fA-F]{2}", escape):
                raise ScanError("invalid SSID escape")
            result.append(int(escape[2:], 16))
            offset += 4
        else:
            result.append(value[offset])
            offset += 1
    if len(result) > 32:
        raise ScanError("SSID exceeds 32 bytes")
    return bytes(result)


@dataclass
class _BSS:
    bssid: str
    frequency: int | None = None
    ssid: bytes | None = None
    signal_dbm: float | None = None
    privacy: bool | None = None
    sections: dict[str, dict[str, object]] = field(default_factory=dict)
    section: str | None = None

    def observation(self) -> Observation:
        if self.frequency is None:
            raise ScanError(f"missing frequency for {self.bssid}")
        security: dict[str, object] = dict(self.sections)
        if self.privacy is not None:
            security["privacy"] = self.privacy
        return Observation(
            self.bssid,
            self.frequency,
            self.ssid,
            None if self.ssid is None else self.ssid.decode("utf-8", errors="replace"),
            self.signal_dbm,
            channel_for_frequency(self.frequency),
            json.dumps(security, sort_keys=True) if security else None,
        )

    def parse_line(self, line: bytes) -> None:
        # Remove indentation only; SSID bytes can include interior spaces.
        value = line.lstrip(b"\t ")
        if value.startswith(b"SSID:"):
            value = value[5:]
            if value.startswith(b" "):
                value = value[1:]
            self.ssid = _ssid(value)
        elif value.startswith(b"freq:"):
            frequency = value[5:].strip()
            if not re.fullmatch(rb"[0-9]+", frequency) or int(frequency) <= 0:
                raise ScanError(f"invalid frequency for {self.bssid}")
            self.frequency = int(frequency)
        elif value.startswith(b"signal:"):
            strength = value[7:].strip()
            match = _SIGNAL.fullmatch(strength)
            if match:
                # Some iw releases print a negative fractional remainder.
                whole, fraction = match.groups()
                self.signal_dbm = float(whole + b"." + fraction.lstrip(b"-"))
                if not math.isfinite(self.signal_dbm):
                    raise ScanError("non-finite signal")
            elif re.fullmatch(rb"[0-9]+/100", strength):
                self.signal_dbm = None
            else:
                raise ScanError(f"invalid signal for {self.bssid}")
        elif value.startswith(b"capability:"):
            self.privacy = b"Privacy" in value.split()
        else:
            self._security(line, value)

    def _security(self, line: bytes, value: bytes) -> None:
        for name in ("RSN", "WPA", "WPS"):
            prefix = name.encode() + b":"
            if value.startswith(prefix):
                self.section = name.lower()
                self.sections.setdefault(self.section, {})
                value = value[len(prefix) :].strip()
                break
        else:
            if re.match(rb"^\t[^\t *]", line) and not value.startswith(b"*"):
                self.section = None
        if self.section is None or not value:
            return
        text = value.decode("ascii", errors="replace").removeprefix("* ")
        key, separator, content = text.partition(":")
        if not separator:
            details = self.sections[self.section].get("details", "")
            self.sections[self.section]["details"] = f"{details}{text}\n"
            return
        key = key.strip().lower().replace(" ", "_")
        content = content.strip()
        if key in {
            "authentication_suites",
            "pairwise_ciphers",
            "group_cipher",
            "group_mgmt_cipher",
            "group_mgmt_cipher_suite",
        }:
            self.sections[self.section][key] = _SUITES.findall(content)
        elif key == "capabilities":
            self.sections[self.section][key] = content.split()
        else:
            self.sections[self.section][key] = content


def parse_scan(output: bytes) -> tuple[Observation, ...]:
    observations: dict[tuple[str, int], Observation] = {}
    current: _BSS | None = None
    for line in output.split(b"\n"):
        if not line.strip():
            continue
        if line.startswith(b"BSS "):
            if current is not None:
                item = current.observation()
                observations[item.bssid, item.frequency_mhz] = item
            match = _BSSID.fullmatch(line)
            if match is None:
                raise ScanError("invalid BSSID header")
            current = _BSS(match[1].decode("ascii").lower())
        elif current is None or not line.startswith((b"\t", b" ")):
            raise ScanError("unexpected scan output")
        else:
            current.parse_line(line)
    if current is not None:
        item = current.observation()
        observations[item.bssid, item.frequency_mhz] = item
    return tuple(observations.values())


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
