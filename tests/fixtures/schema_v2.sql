
CREATE TABLE scan (
    id INTEGER PRIMARY KEY,
    device TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    started_monotonic_ms INTEGER NOT NULL,
    finished_monotonic_ms INTEGER NOT NULL
        CHECK (finished_monotonic_ms >= started_monotonic_ms),
    boot_id TEXT NOT NULL,
    status TEXT NOT NULL
        CHECK (status IN ('success', 'failed', 'timeout', 'cancelled')),
    error TEXT,
    CHECK ((status = 'success' AND error IS NULL)
        OR (status != 'success' AND error IS NOT NULL))
);
CREATE TABLE observation (
    scan_id INTEGER NOT NULL REFERENCES scan(id),
    bssid TEXT NOT NULL CHECK (length(bssid) = 17 AND bssid = lower(bssid)),
    frequency_mhz INTEGER NOT NULL CHECK (frequency_mhz > 0),
    ssid_bytes BLOB,
    ssid_display TEXT,
    signal_dbm REAL,
    channel INTEGER,
    security_json TEXT CHECK (security_json IS NULL OR json_valid(security_json)),
    PRIMARY KEY (scan_id, bssid, frequency_mhz)
);
CREATE INDEX scan_time ON scan(started_at, id);
CREATE INDEX scan_boot_time ON scan(boot_id, started_monotonic_ms, id);
CREATE INDEX observation_address_time ON observation(bssid, scan_id);
PRAGMA user_version = 2;
