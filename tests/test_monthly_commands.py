from __future__ import annotations

import io
import json
import subprocess
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from threading import Event
from unittest.mock import patch

from collection.collector import Collector
from commands import main
from config import AppConfig, ConfigError, load_config
from model import Observation
from storage.backup import send_backup
from storage.database import MonthlyStorage
from storage.history import summarize
from system.status import _disk_status
from tests.helpers import observation_history, sample_scan


class StoppingScanner:
    def prepare(self, stop: Event) -> None:
        pass

    def scan(self, timeout_s: int, stop: Event) -> tuple[Observation, ...]:
        stop.set()
        return (Observation("aa:bb:cc:dd:ee:ff", 2412, b"\x00\xff", "\x00\ufffd"),)


class MonthlyCommandTests(unittest.TestCase):
    def test_configuration_and_history_command(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            config = Path(directory) / "config.toml"
            config.write_text(
                f'version = 1\n[database]\nlayout = "monthly"\npath = "{root}"\n'
            )
            self.assertEqual(load_config(config).database_layout, "monthly")
            with MonthlyStorage(root) as store:
                store.save(
                    sample_scan(
                        Observation("aa:bb:cc:dd:ee:ff", 2412, b"\xff", "\ufffd")
                    )
                )
            output = io.StringIO()
            with redirect_stdout(output):
                result = main(["history", "--config", str(config)])
            self.assertEqual(result, 0)
            self.assertIn("UPDATED AT (UTC)", output.getvalue())
            self.assertIn("COUNT", output.getvalue())
            self.assertIn("2026-10-03 01:00:00+00:00", output.getvalue())
            self.assertEqual(
                output.getvalue().splitlines()[1].split()[2:], ["1", "<hex:ff>"]
            )
            config.write_text(
                f'version = 1\n[database]\nlayout = "invalid"\npath = "{root}"\n'
            )
            with self.assertRaises(ConfigError):
                load_config(config)

    def test_collection_and_status_use_incremental_monthly_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            config = AppConfig(database_path=root, database_layout="monthly")
            status = Path(directory) / "status.json"
            collector = Collector(
                config, StoppingScanner(), status, boot_id="test-boot"
            )
            collector.run()
            state = json.loads(status.read_text())
            summary = summarize(root, "monthly")
            self.assertEqual(state["storage_metrics"]["retained_observations"], 1)
            self.assertEqual(
                state["storage_metrics"]["collection_id"], summary["collection_id"]
            )
            capacity = _disk_status(config, state)["capacity"]
            assert isinstance(capacity, dict)
            self.assertEqual(capacity["retained_observations"], 1)
            self.assertEqual(capacity["estimate_status"], "unknown")
            missing = _disk_status(config, {})["capacity"]
            assert isinstance(missing, dict)
            self.assertIsNone(missing["retained_observations"])

    def test_monthly_backup_transfers_complete_tar_and_cleans_temporary_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "monthly"
            with MonthlyStorage(root) as store:
                store.save(sample_scan())
            expected = observation_history(root, "monthly")
            sent: list[Path] = []

            def transfer(
                arguments: list[str], *, check: bool
            ) -> subprocess.CompletedProcess[str]:
                self.assertFalse(check)
                archive = Path(arguments[1])
                sent.append(archive)
                restored = Path(directory) / "restored"
                with tarfile.open(archive, "r:") as package:
                    package.extractall(restored, filter="data")
                self.assertEqual(
                    observation_history(restored / root.name, "monthly"), expected
                )
                return subprocess.CompletedProcess(arguments, returncode)

            for returncode in (0, 7):
                with (
                    self.subTest(returncode=returncode),
                    patch("storage.backup.shutil.which", return_value="/usr/bin/sz"),
                    patch("storage.backup.subprocess.run", side_effect=transfer),
                ):
                    self.assertEqual(send_backup(root, layout="monthly"), returncode)
                    self.assertFalse(sent[-1].exists())
            self.assertEqual(len(sent), 2)
            self.assertEqual(observation_history(root, "monthly"), expected)
