from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.helpers import executable


class InstallationTests(unittest.TestCase):
    def test_install_upgrade_and_remove_preserve_configuration_and_data(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / "bin"
            commands.mkdir()
            destination = root / "system"
            log = root / "commands.log"
            environment = dict(
                os.environ,
                DESTDIR=str(destination),
                PATH=f"{commands}:{os.environ['PATH']}",
                SURVEY_TEST_LOG=str(log),
                SURVEY_TEST_ACTIVE="0",
            )
            executable(commands / "id", "#!/bin/bash\necho 0\n")
            executable(
                commands / "systemctl",
                """#!/bin/bash
echo "systemctl $*" >> "$SURVEY_TEST_LOG"
if [ "$1" = is-active ]; then
  [ "$SURVEY_TEST_ACTIVE" = 1 ]
fi
""",
            )
            executable(commands / "iw", "#!/bin/bash\nexit 0\n")
            executable(commands / "ip", "#!/bin/bash\nexit 0\n")
            executable(
                commands / "python3",
                """#!/bin/bash
echo "python3 $*" >> "$SURVEY_TEST_LOG"
if [ "$1" = -m ] && [ "$2" = venv ]; then
  mkdir -p "$4/bin"
  cat > "$4/bin/pip" <<'SCRIPT'
#!/bin/bash
echo "pip $*" >> "$SURVEY_TEST_LOG"
SCRIPT
  chmod +x "$4/bin/pip"
  touch "$4/bin/survey-802.11"
fi
""",
            )
            result = subprocess.run(
                ["make"], env=environment, capture_output=True, text=True, check=True
            )
            self.assertIn("installed", result.stdout)
            installed_config = destination / "etc/survey-802.11/survey-802.11.toml"
            service = destination / "etc/systemd/system/survey-802.11.service"
            command = destination / "usr/local/bin/survey-802.11"
            self.assertTrue(service.exists())
            self.assertTrue(command.is_symlink())
            self.assertEqual(
                installed_config.read_bytes(),
                Path("config/survey-802.11.example.toml").read_bytes(),
            )
            history = log.read_text()
            self.assertNotIn("systemctl start", history)
            self.assertNotIn("systemctl enable", history)
            self.assertNotIn("systemctl stop", history)
            self.assertIn("--no-build-isolation --no-deps --no-index", history)
            installed_config.write_text("custom configuration\n")
            data = destination / "var/lib/survey-802.11/history.db"
            data.parent.mkdir(parents=True)
            data.write_bytes(b"retained database")
            environment["SURVEY_TEST_ACTIVE"] = "1"
            subprocess.run(["make"], env=environment, capture_output=True, check=True)
            self.assertEqual(installed_config.read_text(), "custom configuration\n")
            self.assertIn("systemctl stop survey-802.11.service", log.read_text())
            self.assertIn("systemctl start survey-802.11.service", log.read_text())
            subprocess.run(
                ["make", "clean"], env=environment, capture_output=True, check=True
            )
            self.assertFalse(service.exists())
            self.assertFalse(command.is_symlink())
            self.assertFalse((destination / "opt/survey-802.11").exists())
            self.assertEqual(installed_config.read_text(), "custom configuration\n")
            self.assertEqual(data.read_bytes(), b"retained database")
            self.assertIn(
                "systemctl disable --now survey-802.11.service", log.read_text()
            )

    def test_service_capabilities_and_write_boundaries(self) -> None:
        service = Path("systemd/survey-802.11.service").read_text()
        for directive in (
            "CapabilityBoundingSet=CAP_NET_ADMIN",
            "RestrictAddressFamilies=AF_NETLINK AF_UNIX",
            "ProtectSystem=strict",
            "User=root",
            "ReadWritePaths=/var/lib/survey-802.11 /run/survey-802.11",
            "Restart=on-failure",
        ):
            self.assertIn(directive, service)

    def test_make_dry_runs_and_invalid_target(self) -> None:
        for target in ([], ["clean"]):
            result = subprocess.run(
                ["make", "--dry-run", *target],
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("survey-802.11", result.stdout)
        result = subprocess.run(
            ["make", "invalid"], capture_output=True, text=True, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid", result.stderr)
