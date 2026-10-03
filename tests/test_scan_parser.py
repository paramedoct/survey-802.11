from __future__ import annotations

import json
import unittest

from model import ScanError
from scan_parser import parse_scan


def bss(
    address: bytes = b"AA:BB:CC:DD:EE:FF",
    ssid: bytes = b"example",
    frequency: int = 2412,
) -> bytes:
    return (
        b"BSS "
        + address
        + b"(on wlan0)\n\tfreq: "
        + str(frequency).encode()
        + b"\n\tsignal: -50.25 dBm\n\tSSID: "
        + ssid
        + b"\n"
    )


class ParserTests(unittest.TestCase):
    def test_names_addresses_and_deduplication(self) -> None:
        output = (
            bss()
            + bss(b"aa:bb:cc:dd:ee:01")
            + bss(b"aa:bb:cc:dd:ee:02", b"")
            + bss(b"aa:bb:cc:dd:ee:03", rb"\xed\x95\x9c\xea\xb8\x80")
            + bss(b"aa:bb:cc:dd:ee:04", rb"\xff\x00\x5c\x20name\x20")
            + bss(ssid=b"renamed")
            + bss(frequency=2437)
        )
        items = parse_scan(output)
        self.assertEqual(len(items), 6)
        self.assertEqual(items[0].bssid, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(items[0].ssid_bytes, b"renamed")
        self.assertEqual(items[1].ssid_bytes, b"example")
        self.assertEqual(items[2].ssid_bytes, b"")
        self.assertEqual(items[2].ssid_display, "")
        self.assertEqual(items[3].ssid_display, "\ud55c\uae00")
        self.assertEqual(items[4].ssid_bytes, b"\xff\x00\\ name ")
        self.assertEqual(items[0].signal_dbm, -50.25)
        self.assertEqual([items[0].channel, items[-1].channel], [1, 6])

    def test_frequency_with_zero_offset(self) -> None:
        for frequency in (b"2412", b"2412.0", b"2412.000"):
            with self.subTest(frequency=frequency):
                item = parse_scan(bss().replace(b"2412", frequency))[0]
                self.assertEqual(item.frequency_mhz, 2412)
                self.assertEqual(item.channel, 1)

    def test_invalid_frequency_skips_only_affected_access_point(self) -> None:
        for frequency in (b"0", b"0.0", b"2412.1", b"2412.", b"2412 MHz", b"nan"):
            invalid = bss().replace(b"2412", frequency)
            valid = bss(b"aa:bb:cc:dd:ee:01")
            for output in (invalid + valid, valid + invalid):
                with (
                    self.subTest(frequency=frequency, output=output),
                    self.assertLogs("scan_parser", level="WARNING"),
                ):
                    items = parse_scan(output)
                    self.assertEqual(len(items), 1)
                    self.assertEqual(items[0].bssid, "aa:bb:cc:dd:ee:01")
            with self.assertLogs("scan_parser", level="WARNING"):
                self.assertEqual(parse_scan(invalid), ())

    def test_security_and_missing_optional_fields(self) -> None:
        minimal = parse_scan(b"BSS aa:bb:cc:dd:ee:ff\n\tfreq: 2484\n")[0]
        self.assertIsNone(minimal.ssid_bytes)
        self.assertIsNone(minimal.signal_dbm)
        self.assertIsNone(minimal.security_json)
        self.assertEqual(minimal.channel, 14)
        secure = parse_scan(
            bss()
            + (
                b"\tcapability: ESS Privacy ShortSlotTime (0x0411)\n"
                b"\tRSN:\t * Version: 1\n"
                b"\t\t * Group cipher: CCMP\n"
                b"\t\t * Pairwise ciphers: CCMP TKIP\n"
                b"\t\t * Authentication suites: IEEE 802.1X PSK SAE\n"
                b"\t\t * Group mgmt cipher suite: AES-128-CMAC\n"
                b"\t\t * Capabilities: MFP-required MFP-capable (0x00c0)\n"
                b"\tWPA:\t * Version: 1\n"
                b"\t\t * Authentication suites: PSK\n"
                b"\tWPS:\t * Version: 1.0\n"
                b"\t\t * Wi-Fi Protected Setup State: 2 (Configured)\n"
                b"\tHT capabilities:\n\t\t * unrelated: information\n"
            )
        )[0]
        security = json.loads(secure.security_json or "{}")
        self.assertTrue(security["privacy"])
        self.assertEqual(
            security["rsn"]["authentication_suites"], ["IEEE 802.1X", "PSK", "SAE"]
        )
        self.assertEqual(security["rsn"]["pairwise_ciphers"], ["CCMP", "TKIP"])
        self.assertEqual(security["rsn"]["group_mgmt_cipher_suite"], ["AES-128-CMAC"])
        self.assertIn("MFP-required", security["rsn"]["capabilities"])
        self.assertEqual(security["wpa"]["authentication_suites"], ["PSK"])
        self.assertNotIn("unrelated", security["wps"])
        self.assertEqual(parse_scan(b""), ())
        self.assertIsNone(parse_scan(bss() + b"\tsignal: 70/100\n")[0].signal_dbm)

    def test_invalid_output_is_not_empty_success(self) -> None:
        cases = (
            b"garbage",
            b"BSS invalid\n\tfreq: 2412\n",
            b"BSS aa:bb:cc:dd:ee:ff\n\tSSID: name\n",
            bss() + b"\tsignal: NaN dBm\n",
            bss(ssid=rb"broken\xzz"),
            bss(ssid=b"x" * 33),
            bss() + b"BSS invalid\n",
            bss() + b"unexpected\n",
        )
        for output in cases:
            with self.subTest(output=output), self.assertRaises(ScanError):
                parse_scan(output)
