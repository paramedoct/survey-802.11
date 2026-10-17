# Optional monthly storage

Monthly storage is opt-in. The default remains one SQLite file. Both layouts
retain every collected round and observation until the user explicitly deletes
data. The collection interval remains 60 seconds. Splitting files does not reduce
total logical history or automatically delete, summarize, compress, or expire it.

## Configuration and conversion

For a new collection, select a dedicated directory:

```toml
version = 1

[database]
layout = "monthly"
path = "/var/lib/survey-802.11/monthly"
```

Omitting `layout`, or specifying `layout = "single"`, keeps the original file
interface. A layout change alone does not convert existing data. To convert a
stopped schema version 3 file, retain the original single-file configuration:

```bash
sudo survey-802.11 stop
sudo survey-802.11 migrate-monthly --destination /var/lib/survey-802.11/monthly
```

First use the existing `migrate` command if the source is schema version 2. The
monthly command requires a new destination and an existing parent directory. It
copies into a sibling staging directory, preserves original scan IDs and every
field, compares SQLite values and storage types for every scan and observation,
and checks database integrity and foreign keys. Only a completely verified set is
published. The source file is never deleted or rewritten. Enough free space for
the complete new set and SQLite journals is required; a failure retains staging
for inspection and reports its path. No automatic cleanup removes this material.

After successful conversion, change the configuration to the new directory and
monthly layout, then start collection. Do not restart the old source concurrently
and later assume its new scans are in the converted set. The original configuration
and source remain usable if conversion fails. The service's filesystem permissions
must allow the chosen directory, just as for a custom single database path.

## Independent files and ordering

Each `YYYY-MM.db` contains schema version 3, its own dictionaries, the public
`scan` table and `observation` view, and a collection/month identity. A file can be
queried independently without another month's dictionaries. The original wall
clock strings and timezone offsets remain unchanged. File selection uses the
scan's start timestamp converted to UTC, including scans that finish next month.
Naive timestamps without an offset are rejected rather than guessed.

There is no permanently closed month: clock corrections can send the next scan
to an older file. Its scan ID still increases across the entire collection.
One collection writer is permitted. Startup checks for duplicate IDs using a
temporary disk-backed index and chooses one greater than the largest committed
ID across all registered files. There is no per-scan transaction across two
databases or separately committed sequence counter. Closing after each scan
also leaves file replacement to future maintenance without stale writer handles.

`manifest.json` records the collection identity and registered months. Missing
registered files, invalid identities, unknown database files, or duplicate IDs
are explicit errors. They are never interpreted as an empty collection. A new
month is initialized and synchronized before its manifest registration, and its
first scan is committed afterward. Restart can register an interrupted creation
only when the file is valid, belongs to this collection, and contains no scans.
Incomplete schemas or unregistered files with history require inspection; the
program does not overwrite or delete them. Ordinary committed scans survive an
abrupt exit and determine the next ID on restart.

Three locks have distinct purposes: `.writer.lock` excludes another collector;
`.operation.lock` coordinates short writes and collection-boundary capture;
`.maintenance.lock` allows concurrent collection and reads but reserves an
exclusive boundary for future destructive maintenance. Cooperating maintenance
must take the maintenance lock before the operation lock. Direct external SQLite
writers do not follow this protocol and must not modify an active collection.

## Queries and status

The history command runs SQL against each registered file and merges results by
global scan ID. It supports both layouts:

```bash
sudo survey-802.11 history --limit 100
sudo survey-802.11 history --bssid aa:bb:cc:dd:ee:ff --limit 100
sudo survey-802.11 history --scan-id 1440
sudo survey-802.11 history --before-id 1440 --limit 100
```

Output is JSON, newest scan first, with a default limit of 100 scans. The limit
counts scans, not individual
observations, so pagination never cuts off the remaining frequencies of a scan.
Use the smallest returned scan ID as the next `--before-id`. BSSID filtering
returns matching observations; without it, empty successes and failed scans are
also represented. Raw name bytes use an explicit hexadecimal object in JSON,
while missing bytes remain JSON null. Names, security strings, and measurements
are otherwise unchanged. Each query fixes a highest committed scan ID and file
list; later inserts do not leak into that query. Limits are 1 through 10,000 scans.
Memory includes the requested scans' observations, not the whole retained history.

The same operation is available as `history.query_history`. Existing SQL examples
work unchanged on individual files. Arbitrary SQL across unlimited attached
databases is not provided; SQLite's attachment limit would make that unreliable.

Status aggregates all registered months and chooses the last scan/error by global
ID, not filename or wall clock. Logical sizes are read from the registered files.
Retained observation counts and first/last observation times are counted once at
collector startup and updated after each committed scan. Status uses those values
only when their collection identity and last scan ID match durable history;
otherwise they are explicitly unknown. Status never recounts all observations.
Growth and remaining-days estimates are explicitly unknown for monthly mode until
a collection-aware measured estimator is implemented. Single-file estimates keep
their existing behavior. No count is converted into a deletion deadline.

## Complete backups and restore

The existing `backup` command sends one uncompressed tar archive in monthly mode.
It contains all registered months, the manifest, lock files, and `backup.json` with
the highest included scan ID and SHA-256 checksums for each database. Single-file
backup continues to send one ordinary SQLite snapshot.

Backup briefly locks operations to capture the complete file list and highest
committed scan ID, then releases that lock. It copies each database using SQLite's
online backup interface and removes rows newer than that boundary **only from the
temporary snapshot**, deleting observation records before scan rows. Thus a new
month or an append to the current or an older month cannot change the backup's
logical history. All original files and all their rows remain untouched.
Unreferenced immutable dictionary entries introduced after the boundary can remain
in the snapshot; they add some bytes but cannot add or change observations.

Holding a writer lock for the whole backup would be simpler but could delay
60-second collection as history grows. Boundary filtering avoids that delay and
keeps connection count bounded. It relies on append-only collection and a shared
maintenance lock for the snapshot duration; future deletion or file replacement
must obtain that lock exclusively. The archive is created and transferred after
snapshotting, without holding up the collector. Partial temporary backups are not
sent. A transfer error is returned and the source collection remains intact.

To restore, stop collection, preserve the existing entire directory, extract the
archive into a new directory, verify the file checksums and each database's
integrity/foreign keys, and point the configuration at the complete restored set.
Keep root ownership and appropriate directory/file permissions. Never combine
month files, manifests, or WAL files from different backups. Do not restore just
the newest month and silently omit earlier history. Starting the restored set
validates identities, missing files and duplicate IDs before any new scan.

Compression and automatic deletion are outside this feature. Its maintenance
lock is a coordination point, not an implementation of either operation.
