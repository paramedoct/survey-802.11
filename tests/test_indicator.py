from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from threading import Event
from typing import NoReturn
from unittest.mock import Mock, patch

from commands import main
from system.indicator import Led, Monitor, Pattern, Snapshot, classify, indicate, sample


class IndicatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = {
            "ActiveState": "active",
            "Result": "success",
            "InvocationID": "current",
        }
        self.runtime: dict[str, object] = {
            "invocation_id": "current",
            "boot_id": "boot",
            "running": True,
            "last_result_success": True,
            "last_result_monotonic_ms": 1000,
            "stale_after_ms": 180000,
        }

    def test_current_committed_success_and_expiry(self) -> None:
        self.assertEqual(classify(self.service, self.runtime, "boot", 1000), "normal")
        self.assertEqual(classify(self.service, self.runtime, "boot", 180999), "normal")
        self.assertEqual(
            classify(self.service, self.runtime, "boot", 181000), "abnormal"
        )
        self.assertEqual(classify(self.service, self.runtime, "boot", 999), "abnormal")

    def test_invalid_or_failed_results_never_show_normal(self) -> None:
        for key, value in (
            ("invocation_id", "previous"),
            ("boot_id", "previous"),
            ("running", False),
            ("last_result_success", False),
            ("last_result_success", None),
            ("last_result_monotonic_ms", None),
            ("last_result_monotonic_ms", True),
            ("stale_after_ms", True),
            ("stale_after_ms", 0),
        ):
            with self.subTest(key=key, value=value):
                runtime = dict(self.runtime, **{key: value})
                self.assertEqual(
                    classify(self.service, runtime, "boot", 1000), "abnormal"
                )
        for key in self.runtime:
            runtime = self.runtime.copy()
            del runtime[key]
            self.assertEqual(classify(self.service, runtime, "boot", 1000), "abnormal")
        for state in ("activating", "failed", "deactivating"):
            service = dict(self.service, ActiveState=state)
            self.assertEqual(classify(service, self.runtime, "boot", 1000), "abnormal")

    def test_stopped_service_restores_default_even_without_status(self) -> None:
        service = dict(self.service, ActiveState="inactive")
        self.assertEqual(classify(service, {}, "boot", 1000), "default")
        service["Result"] = "exit-code"
        self.assertEqual(classify(service, self.runtime, "boot", 1000), "abnormal")

    def test_exact_pattern_and_transition_without_reset_on_repeated_results(
        self,
    ) -> None:
        pattern = Pattern()
        for now, on in (
            (0, True),
            (0.499, True),
            (0.5, False),
            (4.999, False),
            (5, True),
        ):
            self.assertEqual(pattern.output("normal", now), on)
        for now, on in ((6, True), (6.5, False), (7, True), (7.5, False)):
            self.assertEqual(pattern.output("abnormal", now), on)
        self.assertIsNone(pattern.output("default", 8))
        self.assertTrue(pattern.output("normal", 9))

    def test_sampling_and_missing_or_corrupt_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "status.json"
            result = subprocess.CompletedProcess(
                [], 0, "ActiveState=active\nInvocationID=current\nResult=success\n"
            )
            with patch("system.indicator.subprocess.run", return_value=result) as run:
                with self.assertRaises(OSError):
                    sample(path, "boot")
                path.write_text("invalid json")
                with self.assertRaises(ValueError):
                    sample(path, "boot")
                path.write_text("[]")
                self.assertEqual(sample(path, "boot"), "abnormal")
                path.write_text(json.dumps(self.runtime))
                with patch(
                    "system.indicator.time.monotonic_ns", return_value=1000000000
                ):
                    self.assertEqual(sample(path, "boot"), "normal")
                self.assertEqual(run.call_args.kwargs["timeout"], 1)
                result.stdout = "ActiveState=inactive\nResult=success\n"
                path.unlink()
                self.assertEqual(sample(path, "boot"), "default")

    def test_monitor_expiry_and_query_failure(self) -> None:
        stop = Event()

        def read() -> NoReturn:
            stop.set()
            raise subprocess.TimeoutExpired("systemctl", 1)

        monitor = Monitor(read)
        monitor.snapshot = Snapshot("normal", 10)
        self.assertEqual(monitor.mode(12.999), "normal")
        self.assertEqual(monitor.mode(13), "abnormal")
        with self.assertLogs("system.indicator", level="WARNING"):
            monitor.poll(stop)
        self.assertEqual(monitor.mode(monitor.snapshot.sampled_at), "abnormal")

    def test_led_control_and_default_restoration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "max_brightness").write_text("255")
            led = Led(path)
            led.acquire()
            self.assertEqual((path / "trigger").read_text(), "none\n")
            led.brightness(True)
            self.assertEqual((path / "brightness").read_text(), "255\n")
            led.brightness(False)
            self.assertEqual((path / "brightness").read_text(), "0\n")
            led.restore()
            self.assertEqual((path / "trigger").read_text(), "actpwr\n")

    def test_renderer_restores_on_io_failure(self) -> None:
        led = Mock()
        led.brightness.side_effect = OSError("read only")
        stop = Event()
        with (
            patch("system.indicator.Led.discover", return_value=led),
            patch("system.indicator.Monitor.poll"),
            self.assertRaises(OSError),
        ):
            indicate(Path("/missing"), stop)
        led.restore.assert_called_once()
        self.assertTrue(stop.is_set())

    def test_unsupported_led_does_not_require_configuration(self) -> None:
        with (
            patch("system.indicator.Led.discover", return_value=None),
            patch("commands.load_config") as load,
            self.assertLogs("system.indicator", level="WARNING"),
        ):
            self.assertEqual(main(["indicate-status"]), 0)
            load.assert_not_called()
