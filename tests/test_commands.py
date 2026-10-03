from __future__ import annotations

import io
import sqlite3
import subprocess
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import commands
import control
from config import AppConfig


class CommandTests(unittest.TestCase):
    def test_validate_and_invalid_configuration_exit_codes(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            result = commands.main(
                ["validate", "--config", "config/survey-802.11.example.toml"]
            )
        self.assertEqual(result, 0)
        self.assertIn("interval=60s", output.getvalue())
        with redirect_stderr(output):
            result = commands.main(["validate", "--config", "/missing.toml"])
        self.assertEqual(result, 1)

    def test_every_service_action_and_root_requirement(self) -> None:
        for action in ("start", "stop", "restart", "enable", "disable"):
            with (
                self.subTest(action=action),
                patch("commands.load_config", return_value=AppConfig()) as load,
                patch("control.os.geteuid", return_value=0),
                patch(
                    "control.subprocess.run",
                    return_value=subprocess.CompletedProcess([], 0),
                ) as run,
            ):
                self.assertEqual(commands.main([action]), 0)
                expected = ["systemctl", action]
                if action in {"enable", "disable"}:
                    expected.append("--now")
                expected.append("survey-802.11.service")
                self.assertEqual(run.call_args.args[0], expected)
                self.assertEqual(
                    load.call_count, int(action in {"start", "restart", "enable"})
                )
        with (
            patch("control.os.geteuid", return_value=1000),
            self.assertRaises(PermissionError),
        ):
            control.manage("start")
        with (
            patch("control.os.geteuid", return_value=0),
            patch(
                "control.subprocess.run",
                return_value=subprocess.CompletedProcess([], 7),
            ),
        ):
            self.assertEqual(control.manage("stop"), 7)

    def test_interface_hooks_and_restore_without_configuration(self) -> None:
        with (
            patch(
                "commands.load_config", return_value=AppConfig(device="wlan1")
            ) as load,
            patch("commands.prepare_interface") as prepare,
            patch("commands.restore_interface") as restore,
        ):
            self.assertEqual(commands.main(["prepare-interface"]), 0)
            prepare.assert_called_once_with("wlan1")
            load.reset_mock()
            self.assertEqual(commands.main(["restore-interface"]), 0)
            load.assert_not_called()
            restore.assert_called_once_with()

    def test_collect_storage_failure_returns_nonzero(self) -> None:
        output = io.StringIO()
        with (
            patch("commands.load_config", return_value=AppConfig()),
            patch("commands.Collector") as collector,
            redirect_stderr(output),
        ):
            collector.return_value.run.side_effect = sqlite3.OperationalError(
                "disk full"
            )
            self.assertEqual(commands.main(["collect"]), 1)
        self.assertIn("disk full", output.getvalue())

    def test_service_status_unavailable_and_properties(self) -> None:
        with patch("control.subprocess.run", side_effect=FileNotFoundError("missing")):
            self.assertIn("error", control.service_status())
        with patch(
            "control.subprocess.run",
            return_value=subprocess.CompletedProcess(
                [], 0, "ActiveState=active\nUnitFileState=enabled\n", ""
            ),
        ):
            self.assertEqual(
                control.service_status(),
                {"ActiveState": "active", "UnitFileState": "enabled"},
            )
