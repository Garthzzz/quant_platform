CREATE TABLE object_blob (
    object_id TEXT PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE CHECK(length(sha256) = 64),
    bytes INTEGER NOT NULL CHECK(bytes >= 0),
    media_type TEXT NOT NULL,
    relative_blob_path TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    verification_status TEXT NOT NULL CHECK(verification_status IN ('verified','corrupt','quarantined'))
) STRICT;

CREATE TABLE source_location (
    source_location_id TEXT PRIMARY KEY,
    namespace TEXT NOT NULL,
    origin_uri TEXT NOT NULL,
    observed_path TEXT NOT NULL,
    object_id TEXT NOT NULL REFERENCES object_blob(object_id),
    observed_at TEXT NOT NULL,
    read_only INTEGER NOT NULL CHECK(read_only IN (0,1)),
    UNIQUE(namespace, origin_uri, object_id)
) STRICT;

CREATE TABLE pipeline_run (
    run_id TEXT PRIMARY KEY,
    workflow_name TEXT NOT NULL,
    workflow_version TEXT NOT NULL,
    subject_urn TEXT NOT NULL,
    input_manifest_hash TEXT NOT NULL CHECK(length(input_manifest_hash) = 64),
    idempotency_key TEXT NOT NULL UNIQUE CHECK(length(idempotency_key) = 64),
    run_status TEXT NOT NULL CHECK(run_status IN ('queued','running','waiting_external','succeeded','failed','cancelled')),
    release_status TEXT NOT NULL CHECK(release_status IN ('staging','validated','under_review','releasable','released','rejected')),
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
) STRICT;

CREATE TABLE step_execution (
    step_execution_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES pipeline_run(run_id),
    step_key TEXT NOT NULL,
    step_version TEXT NOT NULL,
    dependency_manifest_hash TEXT NOT NULL CHECK(length(dependency_manifest_hash) = 64),
    required_for_release INTEGER NOT NULL CHECK(required_for_release IN (0,1)),
    status TEXT NOT NULL CHECK(status IN ('waiting','runnable','running','succeeded','failed','blocked','skipped','cancelled')),
    output_manifest_hash TEXT CHECK(output_manifest_hash IS NULL OR length(output_manifest_hash) = 64),
    created_at TEXT NOT NULL,
    finished_at TEXT,
    UNIQUE(run_id, step_key)
) STRICT;

CREATE TABLE outbox_event (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    event_version TEXT NOT NULL,
    aggregate_urn TEXT NOT NULL,
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    payload_hash TEXT NOT NULL CHECK(length(payload_hash) = 64),
    created_at TEXT NOT NULL,
    published_at TEXT,
    UNIQUE(event_type, aggregate_urn, payload_hash)
) STRICT;

