from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from collections.abc import Callable
from contextlib import closing
from functools import partial
from pathlib import Path

from tests.test_installation import executable


def wait_for(predicate: Callable[[], bool], process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if predicate():
            return
        if process.poll() is not None:
            raise AssertionError(
                f"collector exited early: {process.communicate()[1]!r}"
            )
        time.sleep(0.02)
    raise AssertionError("collector did not produce the expected result")


def count_scans(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        with closing(sqlite3.connect(path)) as connection:
            return int(connection.execute("SELECT count(*) FROM scan").fetchone()[0])
    except sqlite3.OperationalError:
        return 0


def has_scans(path: Path, minimum: int) -> bool:
    return count_scans(path) >= minimum


def command_environment() -> tuple[list[str], dict[str, str]]:
    environment = dict(os.environ)
    installed_command = environment.get("SURVEY_TEST_COMMAND")
    if installed_command:
        environment.pop("PYTHONPATH", None)
        return [installed_command], environment
    environment["PYTHONPATH"] = str(Path("src").resolve())
    return [sys.executable, "-m", "commands"], environment


class PipelineTests(unittest.TestCase):
    def test_collect_signal_stop_and_restart_accumulate_history(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            executable(tools / "ip", "#!/bin/bash\nexit 0\n")
            executable(
                tools / "iw",
                """#!/bin/bash
cat <<'OUTPUT'
BSS AA:BB:CC:DD:EE:FF(on wlan0)
\tfreq: 2412
\tsignal: -45.75 dBm
\tSSID: \\xff\\x00hidden
OUTPUT
""",
            )
            database = root / "history.db"
            config = root / "config.toml"
            status = root / "status.json"
            config.write_text(f'version = 1\n[database]\npath = "{database}"\n')
            command, environment = command_environment()
            environment["PATH"] = f"{tools}:{environment['PATH']}"
            for expected in (1, 2):
                process = subprocess.Popen(
                    [
                        *command,
                        "collect",
                        "--config",
                        str(config),
                        "--status-path",
                        str(status),
                    ],
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                try:
                    wait_for(partial(has_scans, database, expected), process)
                    process.send_signal(signal.SIGTERM)
                    _, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 0, stderr.decode())
                    state = json.loads(status.read_text())
                    self.assertFalse(state["running"])
                    self.assertEqual(state["successful_scans"], 1)
                    self.assertEqual(state["last_scan_id"], expected)
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()
            with closing(sqlite3.connect(database)) as connection:
                rows = connection.execute(
                    "SELECT ssid_bytes, signal_dbm FROM observation ORDER BY scan_id"
                ).fetchall()
                self.assertEqual(rows, [(b"\xff\x00hidden", -45.75)] * 2)
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                )
                self.assertEqual(
                    connection.execute("PRAGMA foreign_key_check").fetchall(), []
                )
            result = subprocess.run(
                [
                    *command,
                    "status",
                    "--config",
                    str(config),
                    "--status-path",
                    str(status),
                    "--json",
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(
                json.loads(result.stdout)["history"]["successful_scans"], 2
            )

    def test_signal_during_scan_records_cancellation_and_reaps_child(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tools = root / "bin"
            tools.mkdir()
            pid = root / "scan.pid"
            executable(tools / "ip", "#!/bin/bash\nexit 0\n")
            executable(
                tools / "iw",
                f"""#!{sys.executable}
import os
import pathlib
import signal
import time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
pathlib.Path({str(pid)!r}).write_text(str(os.getpid()))
print('BSS aa:bb:cc:dd:ee:ff', flush=True)
time.sleep(30)
""",
            )
            database = root / "history.db"
            config = root / "config.toml"
            status = root / "status.json"
            config.write_text(f'version = 1\n[database]\npath = "{database}"\n')
            command, environment = command_environment()
            environment["PATH"] = f"{tools}:{environment['PATH']}"
            process = subprocess.Popen(
                [
                    *command,
                    "collect",
                    "--config",
                    str(config),
                    "--status-path",
                    str(status),
                ],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                wait_for(pid.exists, process)
                process.send_signal(signal.SIGTERM)
                _, stderr = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, stderr.decode())
                with self.assertRaises(ProcessLookupError):
                    os.kill(int(pid.read_text()), 0)
                with closing(sqlite3.connect(database)) as connection:
                    self.assertEqual(
                        connection.execute("SELECT status FROM scan").fetchall(),
                        [("cancelled",)],
                    )
                    self.assertEqual(
                        connection.execute(
                            "SELECT count(*) FROM observation"
                        ).fetchone()[0],
                        0,
                    )
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate()
