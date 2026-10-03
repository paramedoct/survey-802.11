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
from runtime import Collector, shutdown_signals
from scanner import IwScanner, ScanError, run_command
from storage import Storage


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
            self.assertIsNone(state["last_scan_id"])
            self.assertEqual(state["successful_scans"], 0)
            self.assertEqual(state["failed_scans"], 0)
            with closing(sqlite3.connect(root / "history.db")) as connection:
                self.assertEqual(
                    connection.execute("SELECT count(*) FROM scan").fetchone()[0], 0
                )

    def test_later_storage_error_preserves_previous_commit(self) -> None:
        for outcome in ("success", "failed", "timeout", "cancelled"):
            with (
                self.subTest(outcome=outcome),
                simulated_collector([1, 1], ["success", outcome]) as (
                    collector,
                    _,
                    root,
                ),
            ):
                with Storage(root / "history.db") as storage:
                    storage.connection.execute(
                        "CREATE TRIGGER fail BEFORE INSERT ON scan "
                        "WHEN EXISTS (SELECT 1 FROM scan) "
                        "BEGIN SELECT RAISE(ABORT, 'storage failure'); END"
                    )
                with (
                    self.assertLogs("runtime", level="WARNING"),
                    self.assertRaises(sqlite3.IntegrityError),
                ):
                    collector.run()
                state = json.loads((root / "status.json").read_text())
                self.assertFalse(state["running"])
                self.assertEqual(state["last_scan_status"], outcome)
                self.assertEqual(state["last_scan_at"], "2026-01-01T00:01:01+00:00")
                self.assertEqual(state["last_commit_at"], "2026-01-01T00:00:01+00:00")
                self.assertEqual(state["last_scan_id"], 1)
                self.assertEqual(state["successful_scans"], 1)
                self.assertEqual(state["failed_scans"], 0)
                self.assertEqual(state["last_error"], "storage failure")
                with closing(sqlite3.connect(root / "history.db")) as connection:
                    self.assertEqual(
                        connection.execute("SELECT id, status FROM scan").fetchall(),
                        [(1, "success")],
                    )

    def test_stop_before_first_scan_preserves_unset_status_fields(self) -> None:
        with simulated_collector([], []) as (collector, scanner, root):
            collector.stop.set()
            collector.run()
            self.assertEqual(scanner.starts, [])
            state = json.loads((root / "status.json").read_text())
            self.assertFalse(state["running"])
            self.assertEqual(state["successful_scans"], 0)
            self.assertEqual(state["failed_scans"], 0)
            for key in ("last_scan_id", "last_scan_at", "last_commit_at"):
                self.assertIsNone(state[key])
            self.assertNotIn("last_scan_status", state)
            self.assertNotIn("last_observation_count", state)

    def test_signal_restoration(self) -> None:
        previous = signal.getsignal(signal.SIGTERM)
        stop = Event()
        with shutdown_signals(stop):
            signal.raise_signal(signal.SIGTERM)
        self.assertTrue(stop.is_set())
        self.assertEqual(signal.getsignal(signal.SIGTERM), previous)
