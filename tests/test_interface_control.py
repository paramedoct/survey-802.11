from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from interface_control import prepare_interface, restore_interface


def result(stdout: str = "", code: int = 0) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], code, stdout, "failure" if code else "")


class InterfaceControlTests(unittest.TestCase):
    def test_start_stop_restore_original_management(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("interface_control.os.geteuid", return_value=0),
            patch("interface_control.shutil.which", return_value="/usr/bin/nmcli"),
            patch(
                "interface_control.subprocess.run",
                side_effect=[
                    result("yes\n"),
                    result(),
                    result("no\n"),
                    result(),
                    result("yes\n"),
                ],
            ) as run,
        ):
            state = Path(directory) / "state.json"
            prepare_interface("wlan1", state)
            self.assertEqual(json.loads(state.read_text())["device"], "wlan1")
            restore_interface(state)
            self.assertFalse(state.exists())
            self.assertEqual(
                [call.args[0] for call in run.call_args_list],
                [
                    [
                        "nmcli",
                        "--wait",
                        "5",
                        "--get-values",
                        "GENERAL.NM-MANAGED",
                        "device",
                        "show",
                        "wlan1",
                    ],
                    ["nmcli", "--wait", "5", "device", "set", "wlan1", "managed", "no"],
                    [
                        "nmcli",
                        "--wait",
                        "5",
                        "--get-values",
                        "GENERAL.NM-MANAGED",
                        "device",
                        "show",
                        "wlan1",
                    ],
                    [
                        "nmcli",
                        "--wait",
                        "5",
                        "device",
                        "set",
                        "wlan1",
                        "managed",
                        "yes",
                    ],
                    [
                        "nmcli",
                        "--wait",
                        "5",
                        "--get-values",
                        "GENERAL.NM-MANAGED",
                        "device",
                        "show",
                        "wlan1",
                    ],
                ],
            )
            restore_interface(state)
            self.assertEqual(run.call_count, 5)

    def test_unmanaged_or_unavailable_manager_is_unchanged(self) -> None:
        for executable, response in (
            (None, result()),
            ("nmcli", result(code=8)),
            ("nmcli", result("no\n")),
        ):
            with (
                self.subTest(executable=executable, response=response),
                tempfile.TemporaryDirectory() as directory,
                patch("interface_control.os.geteuid", return_value=0),
                patch("interface_control.shutil.which", return_value=executable),
                patch("interface_control.subprocess.run", return_value=response) as run,
            ):
                state = Path(directory) / "state.json"
                prepare_interface("wlan0", state)
                restore_interface(state)
                self.assertFalse(state.exists())
                self.assertEqual(run.call_count, int(executable is not None))

    def test_partial_startup_and_failed_restore_preserve_recovery_state(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("interface_control.os.geteuid", return_value=0),
            patch("interface_control.shutil.which", return_value="nmcli"),
            patch(
                "interface_control.subprocess.run",
                side_effect=[
                    result("yes\n"),
                    result(code=1),
                    result(code=1),
                    result(),
                    result("yes\n"),
                ],
            ),
        ):
            state = Path(directory) / "state.json"
            with self.assertRaises(RuntimeError):
                prepare_interface("wlan0", state)
            self.assertTrue(state.exists())
            with self.assertRaises(RuntimeError):
                restore_interface(state)
            self.assertTrue(state.exists())
            restore_interface(state)
            self.assertFalse(state.exists())

    def test_stale_state_restored_before_new_baseline(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("interface_control.os.geteuid", return_value=0),
            patch("interface_control.shutil.which", return_value="nmcli"),
            patch(
                "interface_control.subprocess.run",
                side_effect=[
                    result(),
                    result("yes\n"),
                    result("yes\n"),
                    result(),
                    result("no\n"),
                ],
            ) as run,
        ):
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"device": "wlan0", "managed": True}))
            prepare_interface("wlan1", state)
            self.assertEqual(
                run.call_args_list[0].args[0][-4:], ["set", "wlan0", "managed", "yes"]
            )
            self.assertEqual(json.loads(state.read_text())["device"], "wlan1")

    def test_failed_query_does_not_change_interface(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("interface_control.os.geteuid", return_value=0),
            patch("interface_control.shutil.which", return_value="nmcli"),
            patch(
                "interface_control.subprocess.run", return_value=result(code=1)
            ) as run,
        ):
            state = Path(directory) / "state.json"
            with self.assertRaises(RuntimeError):
                prepare_interface("wlan0", state)
            self.assertFalse(state.exists())
            self.assertEqual(run.call_count, 1)

    def test_restore_verifies_management_and_retains_state_on_failure(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("interface_control.os.geteuid", return_value=0),
            patch(
                "interface_control.subprocess.run",
                side_effect=[result(), result("no\n")],
            ),
        ):
            state = Path(directory) / "state.json"
            state.write_text(json.dumps({"device": "wlan0", "managed": True}))
            with self.assertRaisesRegex(RuntimeError, "not restored"):
                restore_interface(state)
            self.assertTrue(state.exists())
