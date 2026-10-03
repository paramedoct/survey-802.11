from __future__ import annotations

import json
import os
import signal
import sqlite3
import sys
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Timer
from unittest.mock import patch

from config import AppConfig
from model import Observation
from runtime import Collector, shutdown_signals, write_status
from scanner import IwScanner, ScanError, parse_scan, run_command
from storage import Storage


def bss(
    address: bytes = b"AA:BB:CC:DD:EE:FF",
    ssid: bytes = b"example",
    frequency: int = 2412,
) -> bytes:
    return (
        b"BSS "
        + address
        + b"(on wlan0)\n\tfreq: "
        + str(frequency).encode()
        + b"\n\tsignal: -50.25 dBm\n\tSSID: "
        + ssid
        + b"\n"
    )


class ParserTests(unittest.TestCase):
    def test_names_addresses_and_deduplication(self) -> None:
        output = (
            bss()
            + bss(b"aa:bb:cc:dd:ee:01")
            + bss(b"aa:bb:cc:dd:ee:02", b"")
            + bss(b"aa:bb:cc:dd:ee:03", rb"\xed\x95\x9c\xea\xb8\x80")
            + bss(b"aa:bb:cc:dd:ee:04", rb"\xff\x00\x5c\x20name\x20")
            + bss(ssid=b"renamed")
            + bss(frequency=2437)
        )
        items = parse_scan(output)
        self.assertEqual(len(items), 6)
        self.assertEqual(items[0].bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(items[0].ssid_bytes, b"renamed")
        self.assertEqual(items[1].ssid_bytes, b"example")
        self.assertEqual(items[2].ssid_bytes, b"")
        self.assertEqual(items[2].ssid_display, "")
        self.assertEqual(items[3].ssid_display, "\ud55c\uae00")
        self.assertEqual(items[4].ssid_bytes, b"\xff\x00\\ name ")
        self.assertEqual(items[0].signal_dbm, -50.25)
        self.assertEqual([items[0].channel, items[-1].channel], [1, 6])

    def test_security_and_missing_optional_fields(self) -> None:
        minimal = parse_scan(b"BSS aa:bb:cc:dd:ee:ff\n\tfreq: 2484\n")[0]
        self.assertIsNone(minimal.ssid_bytes)
        self.assertIsNone(minimal.signal_dbm)
        self.assertIsNone(minimal.security_json)
        self.assertEqual(minimal.channel, 14)
        secure = parse_scan(
            bss()
            + (
                b"\tcapability: ESS Privacy ShortSlotTime (0x0411)\n"
                b"\tRSN:\t * Version: 1\n"
                b"\t\t * Group cipher: CCMP\n"
                b"\t\t * Pairwise ciphers: CCMP TKIP\n"
                b"\t\t * Authentication suites: IEEE 802.1X PSK SAE\n"
                b"\t\t * Group mgmt cipher suite: AES-128-CMAC\n"
                b"\t\t * Capabilities: MFP-required MFP-capable (0x00c0)\n"
                b"\tWPA:\t * Version: 1\n"
                b"\t\t * Authentication suites: PSK\n"
                b"\tWPS:\t * Version: 1.0\n"
                b"\t\t * Wi-Fi Protected Setup State: 2 (Configured)\n"
                b"\tHT capabilities:\n\t\t * unrelated: information\n"
            )
        )[0]
        security = json.loads(secure.security_json or "{}")
        self.assertTrue(security["privacy"])
        self.assertEqual(
            security["rsn"]["authentication_suites"], ["IEEE 802.1X", "PSK", "SAE"]
        )
        self.assertEqual(security["rsn"]["pairwise_ciphers"], ["CCMP", "TKIP"])
        self.assertEqual(security["rsn"]["group_mgmt_cipher_suite"], ["AES-128-CMAC"])
        self.assertIn("MFP-required", security["rsn"]["capabilities"])
        self.assertEqual(security["wpa"]["authentication_suites"], ["PSK"])
        self.assertNotIn("unrelated", security["wps"])
        self.assertEqual(parse_scan(b""), ())
        self.assertIsNone(parse_scan(bss() + b"\tsignal: 70/100\n")[0].signal_dbm)

    def test_invalid_output_is_not_empty_success(self) -> None:
        cases = (
            b"garbage",
            b"BSS invalid\n\tfreq: 2412\n",
            b"BSS aa:bb:cc:dd:ee:ff\n\tSSID: name\n",
            bss() + b"\tfreq: nan\n",
            bss() + b"\tsignal: NaN dBm\n",
            bss(ssid=rb"broken\xzz"),
            bss(ssid=b"x" * 33),
            bss() + b"BSS invalid\n",
            bss() + b"unexpected\n",
        )
        for output in cases:
            with self.subTest(output=output), self.assertRaises(ScanError):
                parse_scan(output)


class ProcessTests(unittest.TestCase):
    def test_shell_free_locale_and_failures(self) -> None:
        self.assertEqual(
            run_command(
                [sys.executable, "-c", "import os; print(os.environ['LC_ALL'])"],
                2,
                Event(),
            ),
            b"C\n",
        )
        with self.assertRaisesRegex(ScanError, "exited 3"):
            run_command([sys.executable, "-c", "raise SystemExit(3)"], 2, Event())
        with self.assertRaisesRegex(ScanError, "cannot execute"):
            run_command(["/does/not/exist"], 2, Event())
        with self.assertRaisesRegex(ScanError, "warning"):
            run_command(
                [sys.executable, "-c", "import sys; print('warning', file=sys.stderr)"],
                2,
                Event(),
            )
        with patch("scanner.run_command", return_value=b"") as command:
            scanner = IwScanner("wlan0")
            stop = Event()
            scanner.prepare(stop)
            scanner.scan(20, stop)
            self.assertEqual(
                command.call_args_list[0].args,
                (["ip", "link", "set", "dev", "wlan0", "up"], 5, stop),
            )
            self.assertEqual(
                command.call_args_list[1].args,
                (["iw", "dev", "wlan0", "scan", "flush"], 20, stop),
            )

    def test_timeout_and_cancellation_reap_process(self) -> None:
        for cancel in (False, True):
            with (
                self.subTest(cancel=cancel),
                tempfile.TemporaryDirectory() as directory,
            ):
                pid_path = Path(directory) / "pid"
                script = (
                    "import os, pathlib, signal, sys, time; "
                    "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
                    "print('partial', flush=True); time.sleep(30)"
                )
                stop = Event()
                timer = Timer(0.3, stop.set)
                if cancel:
                    timer.start()
                try:
                    with self.assertRaises(ScanError) as context:
                        run_command(
                            [sys.executable, "-c", script, str(pid_path)], 1, stop
                        )
                    self.assertEqual(
                        context.exception.status, "cancelled" if cancel else "timeout"
                    )
                    pid = int(pid_path.read_text())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
                finally:
                    timer.cancel()
                    if cancel:
                        timer.join()


class FakeClock:
    def __init__(self) -> None:
        self.now = 0

    def monotonic_ns(self) -> int:
        return self.now

    def timestamp(self) -> str:
        return (
            datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=self.now / 1e9)
        ).isoformat()

    def wait(self, stop: Event, seconds: float) -> None:
        self.now += round(seconds * 1e9)


class FakeScanner:
    def __init__(
        self, clock: FakeClock, durations: list[int], outcomes: list[str]
    ) -> None:
        self.clock = clock
        self.durations = durations
        self.outcomes = outcomes
        self.starts: list[int] = []
        self.prepared = False

    def prepare(self, stop: Event) -> None:
        self.prepared = True

    def scan(self, timeout_s: int, stop: Event) -> tuple[Observation, ...]:
        index = len(self.starts)
        self.starts.append(self.clock.now // 1_000_000_000)
        self.clock.now += self.durations[index] * 1_000_000_000
        if index == len(self.durations) - 1:
            stop.set()
        outcome = self.outcomes[index]
        if outcome != "success":
            if outcome == "timeout":
                raise ScanError("timeout", "timeout")
            if outcome == "cancelled":
                raise ScanError("cancelled", "cancelled")
            raise ScanError("busy")
        return (Observation("aa:bb:cc:dd:ee:ff", 2412, b"test", "test", -55.0),)


@contextmanager
def simulated_collector(
    durations: list[int], outcomes: list[str]
) -> Iterator[tuple[Collector, FakeScanner, Path]]:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        clock = FakeClock()
        scanner = FakeScanner(clock, durations, outcomes)
        collector = Collector(
            AppConfig(database_path=root / "history.db"),
            scanner,
            root / "status.json",
            clock=clock,
            boot_id="test-boot",
        )
        yield collector, scanner, root


class RuntimeTests(unittest.TestCase):
    def test_immediate_scan_fixed_period_and_skips(self) -> None:
        with simulated_collector([5, 130, 2], ["success"] * 3) as (
            collector,
            scanner,
            root,
        ):
            collector.run()
            self.assertTrue(scanner.prepared)
            self.assertEqual(scanner.starts, [0, 60, 240])
            state = json.loads((root / "status.json").read_text())
            self.assertEqual(state["skipped_periods"], 2)
            self.assertEqual(state["successful_scans"], 3)
            self.assertFalse(state["running"])
            self.assertIsNotNone(state["last_commit_at"])
            with closing(sqlite3.connect(root / "history.db")) as connection:
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM observation").fetchone()[
                        0
                    ],
                    3,
                )

    def test_failure_timeout_recovery_and_cancelled_result(self) -> None:
        with simulated_collector(
            [1, 20, 1, 1], ["failed", "timeout", "success", "cancelled"]
        ) as (collector, scanner, root):
            with self.assertLogs("runtime", level="WARNING"):
                collector.run()
            self.assertEqual(scanner.starts, [0, 60, 120, 180])
            with closing(sqlite3.connect(root / "history.db")) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT status FROM scan ORDER BY id"
                    ).fetchall(),
                    [("failed",), ("timeout",), ("success",), ("cancelled",)],
                )
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM observation").fetchone()[
                        0
                    ],
                    1,
                )

    def test_storage_error_is_fatal_and_status_is_final(self) -> None:
        with simulated_collector([1], ["success"]) as (collector, _, root):
            with Storage(root / "history.db") as storage:
                storage.connection.execute(
                    "CREATE TRIGGER fail BEFORE INSERT ON observation "
                    "BEGIN SELECT RAISE(ABORT, 'storage failure'); END"
                )
            with (
                self.assertLogs("runtime", level="ERROR"),
                self.assertRaises(sqlite3.IntegrityError),
            ):
                collector.run()
            state = json.loads((root / "status.json").read_text())
            self.assertFalse(state["running"])
            self.assertIn("storage failure", state["last_error"])
            self.assertIsNotNone(state["last_scan_at"])
            self.assertEqual(state["last_scan_status"], "success")
            self.assertIsNone(state["last_commit_at"])
            with closing(sqlite3.connect(root / "history.db")) as connection:
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM scan").fetchone()[0], 0
                )

    def test_atomic_status_replacement_and_signal_restoration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            write_status(path, {"counter": 1})
            with (
                patch("runtime.os.replace", side_effect=OSError("failure")),
                self.assertRaises(OSError),
            ):
                write_status(path, {"counter": 2})
            self.assertEqual(json.loads(path.read_text()), {"counter": 1})
            self.assertEqual(list(path.parent.iterdir()), [path])
        previous = signal.getsignal(signal.SIGTERM)
        stop = Event()
        with shutdown_signals(stop):
            signal.raise_signal(signal.SIGTERM)
        self.assertTrue(stop.is_set())
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
