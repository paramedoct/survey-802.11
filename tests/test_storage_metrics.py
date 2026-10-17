from __future__ import annotations

import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from config import AppConfig
from model import Observation
from reporting import _growth_status
from storage import Storage
from storage_metrics import StorageMetrics, logical_size
from tests.helpers import sample_scan
from tests.test_runtime import simulated_collector


class StorageMetricsTests(unittest.TestCase):
    def test_collector_publishes_committed_observation_counts(self) -> None:
        with simulated_collector([1, 1, 1], ["success", "timeout", "success"]) as (
            collector,
            _,
            root,
        ):
            with self.assertLogs("runtime", level="WARNING"):
                collector.run()
            runtime = json.loads((root / "status.json").read_text())
            self.assertEqual(runtime["storage_metrics"]["retained_observations"], 2)
            result = _growth_status(collector.config, runtime, 1000)
            self.assertEqual(result["retained_observations"], 2)
            self.assertEqual(result["estimate_unknown_reason"], "collector is stopped")
            self.assertEqual(
                result["first_observation_at"], "2026-01-01T00:00:00+00:00"
            )
            self.assertEqual(result["last_observation_at"], "2026-01-01T00:02:00+00:00")

    def test_counts_existing_and_new_records_without_repeated_full_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            with Storage(path) as store:
                scan = sample_scan(Observation("aa:bb:cc:dd:ee:ff", 2412))
                store.save(scan)
                metrics = StorageMetrics(store.connection, path, 0)
                self.assertEqual(metrics.observations, 1)
                statements: list[str] = []
                store.connection.set_trace_callback(statements.append)
                scan_id = store.save(scan)
                result = metrics.record(
                    store.connection,
                    monotonic_ms=60_000,
                    observation_count=1,
                    started_at=scan.started_at,
                    scan_id=scan_id,
                    successful_scans=1,
                    failed_scans=0,
                    success=True,
                )
                self.assertEqual(result["retained_observations"], 2)
                self.assertEqual(result["first_observation_at"], scan.started_at)
                self.assertEqual(result["last_observation_at"], scan.started_at)
                self.assertFalse(any("count(" in sql.lower() for sql in statements))
                self.assertIsNone(result["growth_bytes_per_second"])

    def test_logical_size_ignores_checkpoint_and_wal_file_length(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            with Storage(path) as store:
                store.save(sample_scan(Observation("aa:bb:cc:dd:ee:ff", 2412)))
                before = logical_size(store.connection)
                wal = Path(str(path) + "-wal")
                self.assertGreater(wal.stat().st_size, 0)
                store.connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                self.assertEqual(wal.stat().st_size, 0)
                self.assertEqual(logical_size(store.connection), before)

    def test_growth_window_and_invalid_estimate_conditions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            with Storage(path) as store:
                metrics = StorageMetrics(store.connection, path, 0)
                initial_bytes = logical_size(store.connection)
                result: dict[str, object] = {}
                for index in range(1, 11):
                    with patch(
                        "storage_metrics.logical_size",
                        return_value=initial_bytes + index * 4096,
                    ):
                        result = metrics.record(
                            store.connection,
                            monotonic_ms=index * 60_000,
                            observation_count=1,
                            started_at="2026-01-01T00:00:00+00:00",
                            scan_id=index,
                            successful_scans=index,
                            failed_scans=0,
                            success=True,
                        )
                self.assertAlmostEqual(
                    float(str(result["growth_bytes_per_second"])), 40_960 / 600
                )
                self.assertEqual(result["measurement_seconds"], 600)
                with patch("storage_metrics.logical_size", return_value=initial_bytes):
                    result = metrics.record(
                        store.connection,
                        monotonic_ms=660_000,
                        observation_count=0,
                        started_at="2026-01-01T00:11:00+00:00",
                        scan_id=11,
                        successful_scans=10,
                        failed_scans=1,
                        success=False,
                    )
                self.assertIsNone(result["growth_bytes_per_second"])
                self.assertEqual(
                    result["growth_unknown_reason"], "latest scan was not successful"
                )
                self.assertEqual(result["measurement_seconds"], 0)
                with patch("storage_metrics.logical_size", return_value=initial_bytes):
                    result = metrics.record(
                        store.connection,
                        monotonic_ms=1_000_000,
                        observation_count=1,
                        started_at="2026-01-01T00:16:40+00:00",
                        scan_id=12,
                        successful_scans=11,
                        failed_scans=1,
                        success=True,
                    )
                self.assertEqual(result["measurement_seconds"], 0)
                self.assertIsNone(result["growth_bytes_per_second"])

    def test_status_validates_identity_freshness_progress_and_positive_rate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            config = AppConfig(database_path=path)
            with Storage(path) as store:
                scan = sample_scan(Observation("aa:bb:cc:dd:ee:ff", 2412))
                scan_id = store.save(scan)
                metrics = StorageMetrics(store.connection, path, 0)
                values = metrics.record(
                    store.connection,
                    monotonic_ms=60_000,
                    observation_count=0,
                    started_at=scan.started_at,
                    scan_id=scan_id,
                    successful_scans=0,
                    failed_scans=0,
                    success=True,
                )
                values["growth_bytes_per_second"] = 100
                values["growth_unknown_reason"] = None
                runtime: dict[str, object] = {
                    "running": True,
                    "updated_at": datetime.now(UTC).isoformat(),
                    "storage_metrics": values,
                }
                result = _growth_status(config, runtime, 8_640_000)
                self.assertEqual(result["retained_observations"], 1)
                self.assertEqual(result["growth_bytes_per_day"], 8_640_000)
                self.assertEqual(result["estimated_days_remaining"], 1)
                cases: list[tuple[str, object]] = [
                    ("running", False),
                    (
                        "updated_at",
                        (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
                    ),
                    (
                        "updated_at",
                        (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
                    ),
                    ("updated_at", "invalid"),
                ]
                for key, value in cases:
                    with self.subTest(key=key, value=value):
                        result = _growth_status(config, runtime | {key: value}, 100)
                        self.assertIsNone(result["estimated_days_remaining"])
                        self.assertEqual(result["retained_observations"], 1)
                        self.assertIsNotNone(result["estimate_unknown_reason"])
                for rate in (0, -1, float("nan"), float("inf"), "100", True):
                    with self.subTest(rate=rate):
                        values["growth_bytes_per_second"] = rate
                        result = _growth_status(config, runtime, 100)
                        self.assertIsNone(result["estimated_days_remaining"])
                values["database_identity"] = "different"
                result = _growth_status(config, runtime, 100)
                self.assertIsNone(result["retained_observations"])
                values["database_identity"] = metrics.identity
                store.save(scan)
                result = _growth_status(config, runtime, 100)
                self.assertIsNone(result["retained_observations"])
                self.assertIsNone(result["estimated_days_remaining"])


if __name__ == "__main__":
    unittest.main()
