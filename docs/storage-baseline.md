# Storage baseline: schema v2

Measured on 2026-10-17 using **synthetic observations**, not a field database.
The collection interval remains **60 seconds** and every original observation is
retained until the user deletes it. No collector settings or production code were
changed. This is a capacity baseline, not a retention recommendation.

## Reproduce

From the repository root, using the project environment:

```bash
PYTHONPATH=src .venv/bin/python tools/storage_baseline.py --output /tmp/storage-baseline.json
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy --strict .
```

The tool creates fresh databases under a temporary directory in `/tmp`, then
removes that directory on normal completion. Only the small JSON report persists.
The recorded run is [storage-baseline-results.json](storage-baseline-results.json).
It contains input hashes, all settings, per-object sizes, query plans, timing
samples summarized as median/p95, and integrity results. `--scans` can shorten a
smoke run; use the same scan count for comparisons.

Environment: Python 3.14.4, SQLite 3.46.1, Linux 6.6.87.2 under WSL2, x86-64.
The project requires Python >=3.13. Storage uses its existing defaults: 4,096-byte
pages, WAL journal mode, synchronous FULL, and automatic checkpoints at 1,000
pages. The underlying storage medium and host cache were not controlled.

## Workload and method

Each case has 1,440 successful scans at deterministic timestamps 60 seconds apart,
representing one day. Scans are replayed immediately rather than waiting a day.
Each scan observes the same set of 10, 50, or 200 distinct addresses once at
2,412 MHz. Signal strength varies on every scan. All raw observations are inserted
through the actual `Storage.save(Scan)` implementation, with one transaction per
scan, matching `Collector._scan()` and `Collector.run()` persistence boundaries.

The baseline has 50 access points, 16-byte ASCII names, and exactly 128-byte valid
security JSON strings. Both raw and display names are populated. One factor varies
per case. Attribute-change cases change name and security content together every
60 scans or every scan, preserving their byte lengths. The JSON is deliberately a
size-controlled synthetic object, not a realistic parser-output distribution.
There are no failed scans, missing names, duplicate frequencies per address, access
point turnover, or concurrent readers. Boot identity is fixed. Unicode display
expansion, genuine security distributions, and device restarts require additional
field workloads.

After initializing and checkpointing an empty database, the tool records its size
(28,672 bytes). After insertion, another successful TRUNCATE checkpoint makes the
main file independently contain all committed data. **Logical growth** is this
final main-file size minus the empty size. It includes allocated table/index pages
and their unused space, not just encoded payload. Bytes per observation include
scan and index overhead. Daily growth equals measured growth / scans × 1,440;
30-day growth multiplies that by 30. Add the one-time empty size when estimating
total database size. These are linear projections, not an actual 30-day run;
B-tree growth and integer-width transitions can change later costs.

## Measured capacity

MiB means 1,048,576 bytes. Each non-baseline row changes only its named factor.

| Case | Bytes / observation | MiB / day | MiB / 30 days | Warm history median ms |
| --- | ---: | ---: | ---: | ---: |
| Baseline: 50 AP, name 16, security 128, unchanged | 278.70 | 19.137 | 574.102 | 1.838 |
| 10 access points | 296.96 | 4.078 | 122.344 | 1.526 |
| 200 access points | 275.91 | 75.781 | 2273.438 | 1.962 |
| Name 8 bytes | 260.04 | 17.855 | 535.664 | 1.910 |
| Name 32 bytes | 314.94 | 21.625 | 648.750 | 1.833 |
| Security JSON 64 bytes | 210.26 | 14.438 | 433.125 | 1.920 |
| Security JSON 512 bytes | 659.97 | 45.316 | 1359.492 | 2.048 |
| Attributes change every 60 scans | 278.70 | 19.137 | 574.102 | 2.002 |
| Attributes change every scan | 278.70 | 19.137 | 574.102 | 1.937 |

Repeated unchanged attributes cost the same as changed attributes of equal length
in this schema. Larger names affect both raw and display columns. Lower access
point counts distribute fixed scan overhead over fewer observations.

## Table and index allocation

Baseline final database size: 20,094,976 bytes. `dbstat` reports:

| Object | Bytes | Share of main database |
| --- | ---: | ---: |
| observation table | 14,786,560 | 73.58% |
| observation primary-key autoindex | 2,600,960 | 12.94% |
| observation_address_time index | 2,338,816 | 11.64% |
| scan table | 200,704 | 1.00% |
| scan_boot_time index | 90,112 | 0.45% |
| scan_time index | 73,728 | 0.37% |
| sqlite_schema | 4,096 | 0.02% |

Index pages account for approximately 25.40%. Full breakdowns for all cases are in
the JSON report. If SQLite lacks `dbstat`, the tool records `dbstat_error` and an
empty object list, while retaining total-size and query measurements. For future
schemas, freelist or other unassigned pages may mean object shares do not sum to
100%; the main-file size remains the capacity denominator.

## Temporary space and query timing

The baseline WAL reached 4,453,752 bytes and SHM reached 32,768 bytes when sampled
after each commit. The largest observed combined main/WAL/SHM footprint was
24,429,944 bytes. Across cases, WAL peaks ranged from 4,223,032 to 5,170,632 bytes;
SHM was 32,768 bytes. These are sampled file lengths, not filesystem allocated
blocks or guaranteed instantaneous maxima. The final checkpoint truncates WAL;
closing the last connection normally removes the sidecars. Readers holding old
snapshots can prevent checkpoints and allow substantially larger WAL files.

**Neither database growth nor peak WAL length measures physical writes.** WAL
frames can be overwritten and checkpointed repeatedly. Filesystem journaling,
device write amplification, and durability latency are not measured. The baseline
save calls took 0.292 seconds cumulatively in this environment, excluding workload
generation, hashing, query timing, and the final checkpoint. This is not a device
throughput or endurance estimate.

The representative history query returns all 1,440 observations for one address,
including original attributes and scan timestamp, in scan-id order. It uses
`observation_address_time` followed by the scan integer primary key. The first
baseline query took 2.236 ms; 30 subsequent executions had median 1.838 ms and
nearest-rank p95 2.081 ms. Timing includes fetching/materializing all rows in
Python, but excludes connection startup and result rendering. The first execution
is **not a cold-cache measurement**: the database was just written and host caches
were not flushed. Long-lived databases, concurrent readers/writers, and much
longer histories need separate measurements.

## Compare a replacement schema

Keep this workload generator unchanged. A replacement module can expose the same
`Storage(path)`, `save(Scan)`, `connection`, and `close()` interface. Supply a query
that reconstructs the same original observation history, accepting one address
parameter, if table layout changes:

```bash
PYTHONPATH=src:/tmp/candidate .venv/bin/python tools/storage_baseline.py --storage-module candidate_storage --history-sql /tmp/candidate/history.sql --output /tmp/candidate-results.json
```

Compare `workload_version`, all case parameters, scan counts, and `input_sha256`
before interpreting capacity or timing changes. Maintain equivalent journal and
durability settings; report deliberate differences explicitly. The generator
supplies equal-sized repeated attributes as well as frequent changes so shared
attribute records can be evaluated without changing the 60-second collection
interval or discarding observations. The tool checks database integrity, foreign
keys, and expected history row counts for every case. Candidate correctness also
requires checking every reconstructed field against the input; matching row
counts and hashes alone does not prove lossless storage.
