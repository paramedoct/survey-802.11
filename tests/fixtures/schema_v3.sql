
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
CREATE INDEX scan_time ON scan(started_at, id);
CREATE INDEX scan_boot_time ON scan(boot_id, started_monotonic_ms, id);


CREATE TABLE access_point (
    id INTEGER PRIMARY KEY,
    bssid TEXT NOT NULL COLLATE BINARY UNIQUE
        CHECK (length(bssid) = 17 AND bssid = lower(bssid))
);
CREATE TABLE network_name (
    id INTEGER PRIMARY KEY,
    ssid_bytes BLOB,
    ssid_display TEXT
);
CREATE UNIQUE INDEX network_name_value ON network_name (
    (ssid_bytes IS NULL), coalesce(ssid_bytes, X''),
    (ssid_display IS NULL), coalesce(ssid_display, '') COLLATE BINARY
);
CREATE TABLE security_info (
    id INTEGER PRIMARY KEY,
    security_json TEXT COLLATE BINARY
        CHECK (security_json IS NULL OR json_valid(security_json))
);
CREATE UNIQUE INDEX security_info_value ON security_info (
    (security_json IS NULL), coalesce(security_json, '') COLLATE BINARY
);
CREATE TABLE observation_profile (
    id INTEGER PRIMARY KEY,
    name_id INTEGER NOT NULL REFERENCES network_name(id),
    security_id INTEGER NOT NULL REFERENCES security_info(id),
    UNIQUE (name_id, security_id)
);
CREATE TABLE observation_record (
    scan_id INTEGER NOT NULL REFERENCES scan(id),
    ap_id INTEGER NOT NULL REFERENCES access_point(id),
    frequency_mhz INTEGER NOT NULL CHECK (frequency_mhz > 0),
    profile_id INTEGER NOT NULL REFERENCES observation_profile(id),
    signal_dbm REAL,
    channel INTEGER,
    PRIMARY KEY (scan_id, ap_id, frequency_mhz)
);
CREATE INDEX observation_record_address_time
    ON observation_record(ap_id, scan_id);
CREATE VIEW observation AS
SELECT r.scan_id, a.bssid, r.frequency_mhz,
       n.ssid_bytes, n.ssid_display, r.signal_dbm, r.channel,
       q.security_json
FROM observation_record AS r
JOIN access_point AS a ON a.id = r.ap_id
JOIN observation_profile AS p ON p.id = r.profile_id
JOIN network_name AS n ON n.id = p.name_id
JOIN security_info AS q ON q.id = p.security_id;
CREATE TRIGGER access_point_immutable BEFORE UPDATE ON access_point BEGIN SELECT RAISE(ABORT, 'immutable dictionary'); END;
CREATE TRIGGER network_name_immutable BEFORE UPDATE ON network_name BEGIN SELECT RAISE(ABORT, 'immutable dictionary'); END;
CREATE TRIGGER security_info_immutable BEFORE UPDATE ON security_info BEGIN SELECT RAISE(ABORT, 'immutable dictionary'); END;
CREATE TRIGGER observation_profile_immutable BEFORE UPDATE ON observation_profile BEGIN SELECT RAISE(ABORT, 'immutable dictionary'); END;
PRAGMA user_version = 3;
