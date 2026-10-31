from __future__ import annotations

import io
import sqlite3
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from commands import main
from history import Layout, list_ssids
from model import Observation
from monthly_storage import MonthlyStorage, connect_readonly
from storage import Storage
from tests.helpers import sample_scan


class HistoryTests(unittest.TestCase):
    def test_names_merge_across_addresses_and_months_by_actual_timestamp(self) -> None:
        layouts: tuple[Layout, ...] = ("single", "monthly")
        for layout in layouts:
            with (
                self.subTest(layout=layout),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "history"
                factory = MonthlyStorage if layout == "monthly" else Storage
                alpha = Observation("aa:bb:cc:dd:ee:ff", 2412, b"alpha", "alpha")
                beta = replace(
                    alpha,
                    bssid="11:22:33:44:55:66",
                    ssid_bytes=b"beta",
                    ssid_display="beta",
                )
                with factory(path) as store:
                    for stamp, observations in (
                        ("2026-01-01T00:00:00Z", (alpha, beta)),
                        (
                            "2026-02-01T08:00:00+09:00",
                            (replace(alpha, bssid="00:11:22:33:44:55"),),
                        ),
                        ("2026-02-01T00:00:00Z", (beta,)),
                        ("2026-01-20T00:00:00Z", (alpha,)),
                        ("2026-03-01T00:00:00Z", ()),
                    ):
                        store.save(
                            replace(sample_scan(*observations), started_at=stamp)
                        )
                    store.save(
                        replace(
                            sample_scan(),
                            started_at="2026-04-01T00:00:00Z",
                            status="failed",
                            error="scan failed",
                        )
                    )
                rows = list_ssids(path, layout)
                self.assertEqual([row.ssid_bytes for row in rows], [b"beta", b"alpha"])
                self.assertEqual(
                    [row.updated_at.isoformat() for row in rows],
                    ["2026-02-01T00:00:00+00:00", "2026-01-31T23:00:00+00:00"],
                )

    def test_raw_names_and_microseconds_remain_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            base = Observation("aa:bb:cc:dd:ee:ff", 2412)
            with Storage(path) as store:
                for raw in (b"\xff", b"\xfe", b"", None, b"z"):
                    store.save(
                        replace(
                            sample_scan(replace(base, ssid_bytes=raw)),
                            started_at="2026-01-01T09:00:00.000001+09:00",
                        )
                    )
                store.save(
                    replace(
                        sample_scan(replace(base, ssid_bytes=b"z")),
                        started_at="2026-01-01T00:00:00.000002Z",
                    )
                )
            rows = list_ssids(path)
            self.assertEqual(
                [row.ssid_bytes for row in rows], [b"z", None, b"", b"\xfe", b"\xff"]
            )
            self.assertEqual(rows[0].updated_at.microsecond, 2)

    def test_all_names_are_returned_and_empty_collection_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            with Storage(path) as store:
                self.assertEqual(list_ssids(path), [])
                for index in range(101):
                    store.save(
                        sample_scan(
                            Observation("aa:bb:cc:dd:ee:ff", 2412, str(index).encode())
                        )
                    )
            self.assertEqual(len(list_ssids(path)), 101)

    def test_monthly_query_excludes_appends_after_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "monthly"
            with MonthlyStorage(path) as store:
                store.save(
                    sample_scan(Observation("aa:bb:cc:dd:ee:ff", 2412, b"original"))
                )
                appended = False

                def append_then_read(source: Path) -> sqlite3.Connection:
                    nonlocal appended
                    if not appended:
                        appended = True
                        store.save(
                            sample_scan(
                                Observation("aa:bb:cc:dd:ee:ff", 2412, b"later")
                            )
                        )
                    return connect_readonly(source)

                with patch("history.connect_readonly", side_effect=append_then_read):
                    rows = list_ssids(path, "monthly")
            self.assertEqual([row.ssid_bytes for row in rows], [b"original"])

    def test_terminal_output_is_readable_and_escapes_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            config = Path(directory) / "config.toml"
            config.write_text(f'version = 1\n[database]\npath = "{path}"\n')
            with Storage(path) as store:
                for raw in (b"Cafe", b"line\n\x1b[31m", b"\xff", b"", None):
                    store.save(sample_scan(Observation("aa:bb:cc:dd:ee:ff", 2412, raw)))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["history", "--config", str(config)]), 0)
            lines = output.getvalue().splitlines()
            self.assertEqual(len(lines), 6)
            self.assertIn("UPDATED AT (UTC)", lines[0])
            self.assertIn("SSID", lines[0])
            self.assertTrue(
                all("2026-10-03 01:00:00+00:00" in line for line in lines[1:])
            )
            self.assertIn('"Cafe"', output.getvalue())
            self.assertIn(r'"line\n\u001b[31m"', output.getvalue())
            self.assertIn("<hex:ff>", output.getvalue())
            self.assertIn('"" (hidden)', output.getvalue())
            self.assertIn("<unknown>", output.getvalue())
            self.assertNotIn("\x1b", output.getvalue())

    def test_empty_terminal_output_and_old_options_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            config = Path(directory) / "config.toml"
            config.write_text(f'version = 1\n[database]\npath = "{path}"\n')
            with Storage(path):
                pass
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["history", "--config", str(config)]), 0)
            self.assertEqual(output.getvalue(), "No SSIDs observed.\n")
        for option in ("--limit", "--bssid", "--scan-id", "--before-id"):
            with (
                self.subTest(option=option),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as stopped,
            ):
                main(["history", option, "1"])
            self.assertEqual(stopped.exception.code, 2)

    def test_equivalent_timezones_merge(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "history.db"
            with Storage(path) as store:
                for stamp in ("2026-01-01T09:00:00+09:00", "2025-12-31T19:00:00-05:00"):
                    store.save(
                        replace(
                            sample_scan(
                                Observation("aa:bb:cc:dd:ee:ff", 2412, b"same")
                            ),
                            started_at=stamp,
                        )
                    )
            self.assertEqual(
                list_ssids(path)[0].updated_at, datetime(2026, 1, 1, tzinfo=UTC)
            )
