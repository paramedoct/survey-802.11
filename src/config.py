from __future__ import annotations

import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import cast

DEFAULT_CONFIG = Path("/etc/survey-802.11/survey-802.11.toml")
DEFAULT_DATABASE = Path("/var/lib/survey-802.11/survey-802.11.db")
DEFAULT_STATUS = Path("/run/survey-802.11/status.json")


class ConfigError(ValueError):
    """Invalid or unreadable configuration."""


@dataclass(frozen=True)
class AppConfig:
    version: int = 1
    device: str = "wlan0"
    interval_s: int = 60
    timeout_s: int = 20
    database_path: Path = DEFAULT_DATABASE


def _table(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a table")
    return cast(dict[str, object], value)


def _keys(values: Mapping[str, object], allowed: set[str], name: str) -> None:
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ConfigError(f"unknown {name} key: {unknown[0]}")


def _seconds(values: Mapping[str, object], name: str, default: int) -> int:
    value = values.get(name, default)
    if type(value) is not int or not 1 <= value <= 86_400:
        raise ConfigError(f"{name} must be an integer between 1 and 86400")
    return value


def load_config(path: Path) -> AppConfig:
    try:
        with path.open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"cannot load {path}: {error}") from error
    _keys(raw, {"version", "collector", "database"}, "top-level")
    if type(raw.get("version")) is not int or raw["version"] != 1:
        raise ConfigError("version must be 1")
    collector = _table(raw.get("collector", {}), "collector")
    _keys(collector, {"device", "interval_s", "timeout_s"}, "collector")
    device = collector.get("device", "wlan0")
    if not isinstance(device, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,15}", device):
        raise ConfigError("device must be a Linux interface name (1 to 15 characters)")
    interval = _seconds(collector, "interval_s", 60)
    timeout = _seconds(collector, "timeout_s", 20)
    if interval <= timeout:
        raise ConfigError("interval_s must be greater than timeout_s")
    database = _table(raw.get("database", {}), "database")
    _keys(database, {"path"}, "database")
    database_path = database.get("path", str(DEFAULT_DATABASE))
    if (
        not isinstance(database_path, str)
        or "\0" in database_path
        or not Path(database_path).is_absolute()
        or Path(database_path).name in {"", ".", ".."}
    ):
        raise ConfigError("database path must be an absolute file path")
    return AppConfig(1, device, interval, timeout, Path(database_path))
