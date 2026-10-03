from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import diagnostics
from config import AppConfig
from model import ScanError


class DiagnosticsTests(unittest.TestCase):
    def test_failed_checks_preserve_scan_conditions_and_report_order(self) -> None:
        cases = (
            ("none", True, 0),
            ("iw", False, 1),
            ("device", False, 1),
            ("systemctl", True, 1),
            ("permissions", True, 1),
            ("rfkill", True, 1),
            ("storage", True, 1),
            ("connected", True, 1),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = AppConfig(database_path=root / "history.db")
            for failure, scans, exit_code in cases:
                output = io.StringIO()
                with (
                    self.subTest(failure=failure),
                    patch(
                        "diagnostics.shutil.which",
                        side_effect=[
                            None if name == failure else "/tool"
                            for name in ("iw", "ip", "systemctl")
                        ],
                    ),
                    patch(
                        "diagnostics.os.geteuid",
                        return_value=1000 if failure == "permissions" else 0,
                    ),
                    patch("diagnostics.Path.exists", return_value=failure != "device"),
                    patch("diagnostics.existing_parent", return_value=root),
                    patch(
                        "diagnostics._rfkill_status",
                        return_value=(failure != "rfkill", "radio state"),
                    ),
                    patch("diagnostics.read_summary", return_value={"available": True}),
                    patch("diagnostics.os.access", return_value=True),
                    patch(
                        "diagnostics.os.fsync",
                        side_effect=OSError("storage failure")
                        if failure == "storage"
                        else None,
                    ),
                    patch(
                        "diagnostics.run_command",
                        side_effect=[
                            b"Interface wlan0",
                            b"Connected"
                            if failure == "connected"
                            else b"Not connected.\n",
                        ],
                    ) as run,
                    patch("diagnostics.IwScanner") as scanner,
                    redirect_stdout(output),
                ):
                    scanner.return_value.scan.return_value = ()
                    self.assertEqual(diagnostics.diagnose(config), exit_code)
                    self.assertEqual(
                        scanner.return_value.prepare.call_count, int(scans)
                    )
                    self.assertEqual(scanner.return_value.scan.call_count, int(scans))
                    self.assertEqual(run.call_count, 2 if scans else 0)
                labels = [
                    line.partition(":")[0] for line in output.getvalue().splitlines()
                ]
                expected = [
                    "python",
                    "iw",
                    "ip",
                    "systemctl",
                    "permissions",
                    "device",
                    "rfkill",
                    "storage_space",
                ]
                if failure != "device":
                    expected += ["database_permissions", "database_schema"]
                expected += ["storage_write"]
                if scans:
                    expected += ["wireless_device", "scan_only"]
                expected += ["active_scan"]
                self.assertEqual(labels, expected)

    def test_diagnose_actual_scan_and_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config = AppConfig(database_path=Path(directory) / "history.db")
            for failure in (False, True):
                with (
                    self.subTest(failure=failure),
                    patch("diagnostics.shutil.which", return_value="/tool"),
                    patch("diagnostics.os.geteuid", return_value=0),
                    patch("diagnostics.Path.exists", return_value=True),
                    patch(
                        "diagnostics._rfkill_status", return_value=(True, "unblocked")
                    ),
                    patch("diagnostics.read_summary", return_value={"available": True}),
                    patch("diagnostics.os.access", return_value=True),
                    patch(
                        "diagnostics.run_command",
                        side_effect=[b"Interface wlan0", b"Not connected.\n"],
                    ),
                    patch("diagnostics.IwScanner") as scanner,
                    redirect_stdout(io.StringIO()),
                ):
                    if failure:
                        scanner.return_value.scan.side_effect = ScanError(
                            "permission denied"
                        )
                    else:
                        scanner.return_value.scan.return_value = ()
                    self.assertEqual(diagnostics.diagnose(config), int(failure))
                    scanner.return_value.prepare.assert_called_once()
                    scanner.return_value.scan.assert_called_once()
