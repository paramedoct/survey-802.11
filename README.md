# survey-802.11

`survey-802.11` records wireless access point observations on a Raspberry Pi
Zero 2 W. It starts an active scan immediately, repeats it every 60 seconds,
and retains all rounds and observations in SQLite. Runtime dependencies are
Python standard library modules and the system wireless tools.

The built-in radio supports 2.4 GHz 802.11 b/g/n, as described in the
[official hardware specifications](https://www.raspberrypi.com/products/raspberry-pi-zero-2-w/).
Scanning follows the configured country, firmware and driver restrictions.
The collector does not set the country or override channel restrictions.

## Install

Requirements: Raspberry Pi OS Trixie, Python 3.13 or newer, and `make`.
Run these commands from this repository:

```bash
make setup
make
sudo editor /etc/survey-802.11/survey-802.11.toml
sudo survey-802.11 validate
```

`make setup` installs Python, its virtual environment and build tools, `iw`,
`iproute2`, and `make` using Debian packages. `make` installs the program into
`/opt/survey-802.11/venv`, links the command in `/usr/local/bin`, and installs
`survey-802.11.service`. Installation uses local build dependencies without
contacting a Python package index. Existing configuration is preserved.

The first installation does not start or enable the service. An upgrade stops
and then restarts a service that was already running. To remove the program
and service while keeping configuration and recorded data:

```bash
make clean
```

Installation, removal and dependency installation request root access using
`sudo` when needed. Their implementations are all in `makefile`.

## Prepare a dedicated scan interface

Use the built-in radio exclusively for scanning. Arrange console access or a
separate network connection before disconnecting `wlan0`; an SSH connection
using this interface will be lost.

Set the correct WLAN country using `sudo raspi-config` before reserving the
interface. Check the resulting regulatory information and radio block state:

```bash
sudo raspi-config
iw reg get
ls /sys/class/net/wlan0/phy80211/rfkill*/
```

Add `/etc/NetworkManager/conf.d/90-survey-802.11.conf` with this content:

```ini
[keyfile]
unmanaged-devices=interface-name:wlan0
```

If a deployment already has an `unmanaged-devices` list, merge this interface
into that list. NetworkManager supports configuration fragments and interface
matching through this setting; see its
[configuration reference](https://networkmanager.dev/docs/api/latest/NetworkManager.conf.html).
Reload it and confirm that the interface is unmanaged and disconnected:

```bash
sudo nmcli general reload
sudo nmcli device set wlan0 managed no
nmcli device status
iw dev wlan0 link
```

The expected link result is `Not connected.`. Ensure no other connection
manager or `wpa_supplicant` instance manages this interface. The collector
raises the interface at startup with `ip link set dev wlan0 up`; it does not
modify NetworkManager settings, connection profiles, radio blocks or country
settings. Resolve any block through the operating system before collection.

With the device prepared, diagnose it while collection is stopped, then enable
immediate collection and automatic startup on boot:

```bash
sudo survey-802.11 diagnose
sudo survey-802.11 enable
sudo survey-802.11 status
```

## Configuration and commands

The default configuration is `/etc/survey-802.11/survey-802.11.toml`:

```toml
version = 1

[collector]
device = "wlan0"
interval_s = 60
timeout_s = 20

[database]
path = "/var/lib/survey-802.11/survey-802.11.db"
```

`version` must be the integer `1`. The remaining settings have the defaults
shown above. Durations are integer seconds from 1 through 86400, and the
interval must exceed the timeout. Unknown keys, invalid interface names and
relative database paths are rejected. Configuration changes take effect on
restart.

| Command | Behavior |
| --- | --- |
| `collect` | Collect in the foreground until SIGINT or SIGTERM |
| `validate` | Validate configuration without accessing wireless hardware |
| `status` | Show service state, runtime state, durable history, file sizes and free space |
| `diagnose` | Check tools, root access, device, rfkill, storage and an actual active scan |
| `start` / `stop` / `restart` | Manage the systemd service |
| `enable` / `disable` | Enable and start, or disable and stop, the service |

`collect`, `validate`, `status` and `diagnose` accept `--config PATH`.
`collect` and `status` also accept `--status-path PATH`. `status --json` provides
structured output. Service management always uses the installed configuration
and requires root access; starting, restarting and enabling validate it first.
Diagnostic scans raise the interface and discard their results. Stop the
collector before diagnosing to avoid overlapping radio operations.

```bash
sudo survey-802.11 stop
sudo survey-802.11 diagnose
sudo survey-802.11 start
sudo survey-802.11 status --json
sudo journalctl -u survey-802.11.service -n 30 --no-pager
sudo survey-802.11 restart
```

The default runtime status file is `/run/survey-802.11/status.json`. It is
replaced atomically after each committed round and at shutdown. Runtime
counters cover the current process, while history counters cover all stored
rounds. `last_commit_at` is published only after a successful database commit;
the history section remains available when the runtime file is missing.
Runtime status can describe the previous process after an abrupt termination;
use systemd state and the recorded PID, boot identifier and update time to
interpret it. Root access is normally required to read the service's protected
state and data directories. Logs go to journald.

The service runs as root with only `CAP_NET_ADMIN`, permits `AF_NETLINK` and
`AF_UNIX`, and protects the system filesystem. Persistent writes are limited
to `/var/lib/survey-802.11`, with runtime state in `/run/survey-802.11` and a
private temporary directory. If a custom database location is required, add
a matching `ReadWritePaths` entry through `systemctl edit survey-802.11.service`
and provision the directory before restart.

## Collection and storage

Every round executes `iw dev DEVICE scan flush` without a shell and with
`LC_ALL=C`. The flush flag requests fresh results rather than repeatedly
recording the scan cache; see the
[official iw scan implementation](https://kernel.googlesource.com/pub/scm/linux/kernel/git/jberg/iw/+/refs/tags/v6.9/scan.c).
A single loop scans and commits sequentially using a monotonic schedule.
Overdue periods are skipped instead of running catch-up scans.

Scan command errors and malformed required fields produce `failed` rounds;
timeouts produce `timeout` rounds. The next scheduled round retries normally.
An empty successful scan remains `success` with no observations. On SIGINT or
SIGTERM, the collector terminates and reaps the scan process group, saving a
`cancelled` round with no partial observations. Results from a scan that has
already completed are committed before exit. Storage failures roll back the
entire round, log an error, and terminate with a failure exit code so systemd
can restart the collector.

The database uses schema version 1 (`PRAGMA user_version`), foreign keys, WAL
and `synchronous=FULL`. New databases are initialized transactionally, and
unknown versions or populated unversioned databases are rejected.

| Table | Fields |
| --- | --- |
| `scan` | `id`, `device`, `started_at`, `finished_at`, `started_monotonic_ns`, `finished_monotonic_ns`, `boot_id`, `status`, `error` |
| `observation` | `scan_id`, `bssid`, `frequency_mhz`, `ssid_bytes`, `ssid_display`, `signal_dbm`, `channel`, `security_json` |

`BSSID` is the access point address (including inputs previously called
`BSID`). It is normalized to lowercase. Each round deduplicates the
address/frequency pair, keeping the last complete occurrence. Separate
addresses with the same name remain separate observations. Address and
frequency are required; unavailable optional information is stored as `NULL`.
Signal strength is a real value in dBm and frequency is an integer in MHz.
An unspecified driver signal in arbitrary units is not converted into dBm.
Channels are derived from recognized center frequencies.

SSID bytes are reconstructed from iw's hexadecimal escapes and stored as
SQLite BLOB values. Empty hidden names remain empty bytes; missing SSID
information remains `NULL`. Display strings decode UTF-8 with replacement
characters, while the original bytes retain non-UTF-8 names and embedded NULs.
Names and signal strength are stored for every observation, preserving changes.
Security JSON records advertised privacy, RSN/WPA authentication and cipher
lists, security capabilities and WPS details when present. It does not infer
missing security information.

Wall-clock timestamps include the local timezone offset. The boot identifier
and monotonic nanoseconds allow ordering across wall-clock corrections within
one boot. `scan.id` gives database insertion order across restarts and boots.
Timestamp, boot/monotonic and address/round indexes support history queries.

No retention limit, automatic deletion or compression is applied. Check disk
space regularly; a full filesystem prevents commits and requires operator
intervention. Failure to detect an access point does not prove it is powered
off: radio conditions, scan timing, country restrictions and driver behavior
can all affect detection. Web pages, maps, raw packet capture and appearance
notifications are outside this implementation.

## Query examples

Open the database using the standard library command interface:

```bash
sudo python3 -m sqlite3 /var/lib/survey-802.11/survey-802.11.db
```

Signal and name history for one address, ordered by collection round:

```sql
SELECT s.id, s.started_at, s.boot_id, s.started_monotonic_ns,
       o.ssid_display, hex(o.ssid_bytes) AS ssid_hex,
       o.signal_dbm, o.frequency_mhz, o.channel
FROM observation AS o
JOIN scan AS s ON s.id = o.scan_id
WHERE o.bssid = 'aa:bb:cc:dd:ee:ff'
ORDER BY s.id;
```

Observations in the most recently committed round:

```sql
SELECT s.id, s.status, s.error, o.bssid, o.ssid_display,
       o.signal_dbm, o.frequency_mhz, o.security_json
FROM scan AS s
LEFT JOIN observation AS o ON o.scan_id = s.id
WHERE s.id = (SELECT max(id) FROM scan)
ORDER BY o.bssid, o.frequency_mhz;
```

The left join preserves empty successes and failures. To query another round,
replace the subquery with its integer identifier.

## Backup

Stop collection before backing up. Use SQLite's backup API to include any
remaining WAL contents in one consistent destination database. Choose an
existing destination directory and a new backup filename:

```bash
sudo survey-802.11 stop
sudo python3 - <<'PY'
import sqlite3
from contextlib import closing
from pathlib import Path

source = Path('/var/lib/survey-802.11/survey-802.11.db')
with closing(sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)) as reader:
    with closing(sqlite3.connect('/path/to/backup/survey-802.11.db')) as writer:
        reader.backup(writer)
PY
sudo survey-802.11 start
```

To restore, stop collection, preserve the existing database and any `-wal` or
`-shm` sidecars separately, restore the backup to the configured path with root
ownership and mode `0640`, and start collection. Never mix an old WAL with a
restored database.

## Development and verification

```bash
python3 -m venv --system-site-packages .venv
.venv/bin/python -m pip install -e '.[dev]'
PYTHONPATH=src .venv/bin/python -m unittest discover -v
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy --strict .
make --dry-run
make --dry-run clean
make --dry-run setup
```

Unit and integration tests cover parsing, hidden and non-UTF-8 names, security,
deduplication, invalid output, scheduling, failure recovery, process cleanup,
transaction rollback, disk-full failures, management commands, atomic status,
installation simulation and restart accumulation. Installation tests replace
system commands and stage files in a temporary directory; they do not install
or remove the host service. The collector accepts a `Scanner` protocol and a
`Clock` protocol so tests can replace hardware and time.

To test an installed command without importing collector modules from the
source tree, install a wheel and run:

```bash
.venv/bin/python -m pip install --no-build-isolation --no-deps .
SURVEY_TEST_COMMAND="$PWD/.venv/bin/survey-802.11" PYTHONPATH=src \
  .venv/bin/python -m unittest tests.test_integration -v
```

Before production use, verify these steps on the actual Raspberry Pi:

1. Keep `wlan0` unmanaged and disconnected, and run `diagnose` successfully.
2. Enable collection and confirm several 60-second rounds, including empty
   successes if no access points are visible, using status and database queries.
3. Restart the service and confirm that round identifiers and history accumulate.
4. Reboot and confirm the enabled service runs, with a new boot identifier.
5. Stop during a scan and confirm the scan child exits and SQLite integrity
   checks succeed. Confirm journald has no storage errors.

These hardware checks require the intended radio, firmware, country settings
and systemd environment; simulated tests do not establish hardware acceptance.
