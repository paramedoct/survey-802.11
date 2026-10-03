from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

from reporting import write_status

_LOG = logging.getLogger(__name__)
DEFAULT_STATE = Path("/run/survey-802.11/interface-state.json")


def _nmcli(arguments: list[str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["nmcli", "--wait", "5", *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=7,
        env=dict(os.environ, LC_ALL="C", LANG="C"),
    )
    return result


def _require_success(result: subprocess.CompletedProcess[str]) -> None:
    if result.returncode:
        raise RuntimeError(f"nmcli failed: {result.stderr.strip()}")


def restore_interface(state_path: Path = DEFAULT_STATE) -> None:
    if os.geteuid() != 0:
        raise PermissionError("interface restoration must run as root")
    if not state_path.exists():
        return
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except ValueError as error:
        raise RuntimeError("invalid interface restoration state") from error
    if (
        not isinstance(state, dict)
        or not isinstance(state.get("device"), str)
        or state.get("managed") is not True
    ):
        raise RuntimeError("invalid interface restoration state")
    device = state["device"]
    if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", device):
        raise RuntimeError("invalid interface restoration device")
    _require_success(_nmcli(["device", "set", device, "managed", "yes"]))
    result = _nmcli(["--get-values", "GENERAL.NM-MANAGED", "device", "show", device])
    _require_success(result)
    if result.stdout.strip() != "yes":
        raise RuntimeError(f"NetworkManager management was not restored for {device}")
    state_path.unlink()
    _LOG.info("restored NetworkManager management for %s", device)


def prepare_interface(device: str, state_path: Path = DEFAULT_STATE) -> None:
    if os.geteuid() != 0:
        raise PermissionError("interface preparation must run as root")
    # Retry a previous failed restoration before saving a new baseline.
    restore_interface(state_path)
    if shutil.which("nmcli") is None:
        _LOG.info("nmcli unavailable; interface management is unchanged")
        return
    result = _nmcli(["--get-values", "GENERAL.NM-MANAGED", "device", "show", device])
    if result.returncode == 8:
        _LOG.info("NetworkManager is not running; interface management is unchanged")
        return
    _require_success(result)
    managed = result.stdout.strip()
    if managed == "no":
        return
    if managed != "yes":
        raise RuntimeError(f"unexpected NetworkManager managed state: {managed!r}")
    # Save before changing state so ExecStopPost can recover partial startup.
    write_status(state_path, {"device": device, "managed": True})
    _require_success(_nmcli(["device", "set", device, "managed", "no"]))
    result = _nmcli(["--get-values", "GENERAL.NM-MANAGED", "device", "show", device])
    _require_success(result)
    if result.stdout.strip() != "no":
        raise RuntimeError(f"NetworkManager still manages {device}")
    _LOG.info("excluded %s from NetworkManager management during collection", device)
