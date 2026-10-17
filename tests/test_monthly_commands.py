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

from backup import send_backup
from commands import main
from config import AppConfig, ConfigError, load_config
from history import query_history, summarize
from model import Observation
from monthly_storage import MonthlyStorage
from reporting import _disk_status
from runtime import Collector
from tests.helpers import sample_scan


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
                result = main(["history", "--config", str(config), "--limit", "1"])
            self.assertEqual(result, 0)
            self.assertEqual(
                json.loads(output.getvalue())[0]["ssid_bytes"], {"hex": "ff"}
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
            expected = query_history(root, "monthly")
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
                    query_history(restored / root.name, "monthly"), expected
                )
                return subprocess.CompletedProcess(arguments, 0)

            with (
                patch("backup.shutil.which", return_value="/usr/bin/sz"),
                patch("backup.subprocess.run", side_effect=transfer),
            ):
                self.assertEqual(send_backup(root, layout="monthly"), 0)
            self.assertEqual(len(sent), 1)
            self.assertFalse(sent[0].exists())
            self.assertEqual(query_history(root, "monthly"), expected)
