CREATE TABLE paper_field_overlay (
    overlay_id TEXT PRIMARY KEY CHECK(length(trim(overlay_id)) > 0),
    paper_id TEXT NOT NULL REFERENCES lab_paper(paper_id) ON DELETE RESTRICT,
    paper_version_id TEXT NOT NULL REFERENCES lab_paper_version(paper_version_id) ON DELETE RESTRICT,
    field_name TEXT NOT NULL CHECK(length(trim(field_name)) > 0),
    value_text TEXT NOT NULL CHECK(length(value_text) <= 100000),
    version INTEGER NOT NULL CHECK(version >= 1),
    supersedes_overlay_id TEXT REFERENCES paper_field_overlay(overlay_id) ON DELETE RESTRICT,
    base_content_sha256 TEXT NOT NULL CHECK(
        length(base_content_sha256) = 64
        AND base_content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    actor_kind TEXT NOT NULL CHECK(actor_kind IN ('local_researcher','migration')),
    actor_display_name TEXT NOT NULL CHECK(length(trim(actor_display_name)) BETWEEN 1 AND 160),
    reason TEXT NOT NULL CHECK(length(reason) <= 2000),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(paper_id, field_name, version),
    UNIQUE(paper_id, field_name, overlay_id)
) STRICT;

CREATE INDEX paper_field_overlay_latest_idx
ON paper_field_overlay(paper_id, field_name, version DESC);

CREATE TRIGGER paper_field_overlay_no_update
BEFORE UPDATE ON paper_field_overlay
BEGIN
    SELECT RAISE(ABORT, 'paper field overlays are immutable');
END;

CREATE TRIGGER paper_field_overlay_no_delete
BEFORE DELETE ON paper_field_overlay
BEGIN
    SELECT RAISE(ABORT, 'paper field overlays are immutable');
END;

CREATE TRIGGER paper_field_overlay_version_chain
BEFORE INSERT ON paper_field_overlay
WHEN (
    (NEW.version = 1 AND NEW.supersedes_overlay_id IS NOT NULL)
    OR
    (NEW.version > 1 AND NOT EXISTS (
        SELECT 1 FROM paper_field_overlay previous
        WHERE previous.overlay_id = NEW.supersedes_overlay_id
          AND previous.paper_id = NEW.paper_id
          AND previous.field_name = NEW.field_name
          AND previous.version = NEW.version - 1
    ))
)
BEGIN
    SELECT RAISE(ABORT, 'paper field overlay version chain is invalid');
END;

CREATE TRIGGER paper_field_overlay_version_matches_paper
BEFORE INSERT ON paper_field_overlay
WHEN NOT EXISTS (
    SELECT 1 FROM lab_paper_version version
    WHERE version.paper_version_id = NEW.paper_version_id
      AND version.paper_id = NEW.paper_id
      AND version.content_sha256 = NEW.base_content_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'paper field overlay is not bound to its paper material');
END;
