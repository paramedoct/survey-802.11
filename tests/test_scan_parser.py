from __future__ import annotations

import json
import unittest

from collection.parser import parse_scan
from model import ScanError


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
    def test_advertised_wifi_generations(self) -> None:
        for name, generation in ((b"HT", 4), (b"VHT", 5), (b"HE", 6), (b"EHT", 7)):
            for section in (b"capabilities", b"operation", b"Operation"):
                with self.subTest(name=name, section=section):
                    item = parse_scan(bss() + b"\t" + name + b" " + section + b":\n")[0]
                    self.assertEqual(item.wifi_generations, (generation,))
                    self.assertEqual(item.wifi_generation, generation)

    def test_generations_are_sorted_deduplicated_and_scoped_to_each_bss(self) -> None:
        items = parse_scan(
            bss(frequency=5180)
            + b"\tHE capabilities:\n\tHT capabilities:\n"
            + b"\tVHT capabilities:\n\tHE Operation:\n"
            + bss(frequency=2412)
            + b"\tHT capabilities:\n"
            + bss(b"00:11:22:33:44:55", frequency=5955)
            + b"\tHE capabilities:\n\tEHT capabilities:\n"
        )
        self.assertEqual(
            [item.wifi_generations for item in items], [(4, 5, 6), (4,), (6, 7)]
        )
        self.assertEqual([item.wifi_generation for item in items], [6, 4, 7])

    def test_missing_generation_information_stays_unknown(self) -> None:
        for frequency in (2412, 5180, 5955):
            with self.subTest(frequency=frequency):
                item = parse_scan(
                    bss(ssid=b"Wi-Fi 6 HT capabilities:", frequency=frequency)
                    + b"\tcapability: ESS Privacy (0x0011)\n"
                    + b"\tRSN:\t * Version: 1\n"
                    + b"\t\t * Authentication suites: SAE\n"
                    + b"\t\t * Capabilities: MFP-required (0x00c0)\n"
                )[0]
                self.assertIsNone(item.wifi_generations)
                self.assertIsNone(item.wifi_generation)

    def test_generation_sections_do_not_leak_into_security(self) -> None:
        item = parse_scan(
            bss()
            + b"\tRSN:\t * Version: 1\n"
            + b"\t\t * Authentication suites: SAE\n"
            + b"\tHE capabilities:\n\t\t * unrelated: information\n"
            + b"\tWPS:\t * Version: 1.0\n"
        )[0]
        security = json.loads(item.security_json or "{}")
        self.assertEqual(
            security["rsn"], {"version": "1", "authentication_suites": ["SAE"]}
        )
        self.assertEqual(security["wps"], {"version": "1.0"})
        self.assertEqual(item.wifi_generations, (6,))

    def test_invalid_capabilities_do_not_claim_support(self) -> None:
        item = parse_scan(
            bss()
            + b"\tHT capabilities:\n"
            + b"\tHE capabilities: <invalid: 1 byte: 00>\n"
            + b"\tEHT Operation: <invalid: no data>\n"
        )[0]
        self.assertEqual(item.wifi_generations, (4,))

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
                    self.assertLogs("collection.parser", level="WARNING"),
                ):
                    items = parse_scan(output)
                    self.assertEqual(len(items), 1)
                    self.assertEqual(items[0].bssid, "aa:bb:cc:dd:ee:01")
            with self.assertLogs("collection.parser", level="WARNING"):
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
