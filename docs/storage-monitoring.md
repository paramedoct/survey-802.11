# Storage capacity reporting

`survey-802.11 status` and `status --json` retain their existing options and
sections. The new `storage.capacity` object reports retained observation count,
first and last observation timestamps, logical database size, recent measured
growth, free-space duration estimates, and explicit reasons when a value is
unknown. JSON uses `null` for unknown numeric values.

The collector counts existing observation records once at startup and maintains
the count after successful commits. Status queries never recount all observations.
They compare the runtime snapshot's database file identity and latest scan ID
against the current database. Missing or mismatched snapshots produce unknown
counts, including when collection has not yet published measurements. A matching
snapshot can report retained counts after the collector stops. First and last
timestamps refer to observations in insertion/scan-ID order; they preserve the
original timestamp strings and do not claim chronological extrema after clock
changes. Empty and failed scans do not change observation timestamps or counts.

Logical size is SQLite `page_count * page_size`, including committed pages still
in WAL and free pages inside the database. Existing main-file, WAL, SHM, combined
file-size and filesystem-free-space fields remain separate. A checkpoint changes
sidecar occupancy without constituting logical data growth. None of these values
measures physical device writes.

The collector holds at most 61 samples spanning at most one hour. A rate requires
at least ten minutes, ten successful scans, and 40,960 bytes of logical growth.
The elapsed time uses the monotonic clock and includes failed-scan time; successful
and failed scan counts for the measurement window are reported. The latest scan
must succeed. Restart, clock regression, database shrinkage, or an inter-sample gap
longer than the greater of 180 seconds and twice the configured interval plus the
scan timeout resets the window. Page allocation below the threshold yields unknown
instead of an unstable or zero estimate.

Remaining days equals current filesystem free bytes divided by measured daily
logical growth. This is an estimate at the recent workload, not a retention limit
or a guarantee. Stopped collectors, missing/invalid timestamps, timestamps in the
future, and stale snapshots suppress the estimate. Staleness uses the same gap
threshold. Other processes, backups, temporary migration files, long-lived WAL
readers, changing access point density and future attributes can consume space
outside this rate. Free pages already inside the database may postpone growth;
the reporter does not extrapolate from that plateau.

The collection interval remains unchanged. No observations are removed, replaced
by summaries, or skipped by the capacity reporter. All original observations
remain retained until explicit user deletion.
