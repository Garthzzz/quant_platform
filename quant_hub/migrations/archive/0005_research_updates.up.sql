CREATE TABLE research_update (
    update_id TEXT PRIMARY KEY CHECK(length(trim(update_id)) > 0),
    research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    activation_id TEXT NOT NULL UNIQUE
        REFERENCES research_release_activation(activation_id) ON DELETE RESTRICT,
    research_release_id TEXT NOT NULL
        REFERENCES research_release(research_release_id) ON DELETE RESTRICT,
    content_revision_id TEXT NOT NULL CHECK(length(trim(content_revision_id)) > 0),
    event_kind TEXT NOT NULL CHECK(event_kind = 'published'),
    release_revision INTEGER NOT NULL CHECK(release_revision >= 1),
    title_snapshot TEXT NOT NULL CHECK(length(trim(title_snapshot)) > 0),
    activated_at TEXT NOT NULL CHECK(length(trim(activated_at)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(research_id, content_revision_id, event_kind)
) STRICT;

CREATE INDEX research_update_recent_idx
ON research_update(activated_at DESC, update_id DESC);

CREATE TABLE research_update_annotation_event (
    annotation_event_id TEXT PRIMARY KEY CHECK(length(trim(annotation_event_id)) > 0),
    update_id TEXT NOT NULL REFERENCES research_update(update_id) ON DELETE RESTRICT,
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL UNIQUE
        CHECK(length(trim(idempotency_key)) BETWEEN 1 AND 200),
    note TEXT CHECK(note IS NULL OR length(note) <= 500),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    UNIQUE(update_id, revision)
) STRICT;

CREATE INDEX research_update_annotation_latest_idx
ON research_update_annotation_event(update_id, revision DESC);

CREATE TABLE research_update_export_checkpoint (
    export_name TEXT PRIMARY KEY CHECK(export_name = 'research_update_history.jsonl'),
    database_watermark TEXT NOT NULL CHECK(
        length(database_watermark) = 64
        AND database_watermark NOT GLOB '*[^0-9a-f]*'
    ),
    history_sha256 TEXT NOT NULL CHECK(
        length(history_sha256) = 64
        AND history_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    row_count INTEGER NOT NULL CHECK(row_count >= 0),
    exported_at TEXT NOT NULL CHECK(length(trim(exported_at)) > 0)
) STRICT;

CREATE TRIGGER research_update_no_update
BEFORE UPDATE ON research_update
BEGIN
    SELECT RAISE(ABORT, 'research update facts are append-only');
END;

CREATE TRIGGER research_update_no_delete
BEFORE DELETE ON research_update
BEGIN
    SELECT RAISE(ABORT, 'research update facts are append-only');
END;

CREATE TRIGGER research_update_annotation_no_update
BEFORE UPDATE ON research_update_annotation_event
BEGIN
    SELECT RAISE(ABORT, 'research update annotations are append-only');
END;

CREATE TRIGGER research_update_annotation_no_delete
BEFORE DELETE ON research_update_annotation_event
BEGIN
    SELECT RAISE(ABORT, 'research update annotations are append-only');
END;

CREATE TRIGGER research_update_export_checkpoint_no_delete
BEFORE DELETE ON research_update_export_checkpoint
BEGIN
    SELECT RAISE(ABORT, 'research update export checkpoint cannot be deleted');
END;
