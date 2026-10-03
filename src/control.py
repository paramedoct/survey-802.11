from __future__ import annotations

import os
import subprocess
from typing import Literal

SERVICE_NAME = "survey-802.11.service"
Action = Literal["start", "stop", "restart", "enable", "disable"]


def manage(action: Action) -> int:
    if os.geteuid() != 0:
        raise PermissionError("service management must run as root")
    arguments = ["systemctl", action]
    if action in {"enable", "disable"}:
        arguments.append("--now")
    return subprocess.run(
        [*arguments, SERVICE_NAME], check=False, timeout=30
    ).returncode


def service_status() -> dict[str, str]:
    try:
        result = subprocess.run(
            [
                "systemctl",
                "show",
                SERVICE_NAME,
                "--no-pager",
                "--property=LoadState,ActiveState,SubState,UnitFileState,ExecMainStatus",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
            env=dict(os.environ, LC_ALL="C", LANG="C"),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"error": str(error)}
    if result.returncode:
        return {"error": result.stderr.strip()}
    return dict(
        line.split("=", 1) for line in result.stdout.splitlines() if "=" in line
    )
