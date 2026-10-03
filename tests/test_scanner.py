from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from threading import Event, Timer
from unittest.mock import patch

from scanner import IwScanner, ScanError, run_command


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
