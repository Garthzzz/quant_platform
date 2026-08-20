ALTER TABLE topic ADD COLUMN parent_topic_id TEXT
    REFERENCES topic(topic_id) ON DELETE RESTRICT;

ALTER TABLE topic ADD COLUMN created_by_actor_id TEXT
    REFERENCES actor(actor_id) ON DELETE RESTRICT;

ALTER TABLE topic ADD COLUMN revision INTEGER NOT NULL DEFAULT 1
    CHECK(revision >= 1);

ALTER TABLE topic ADD COLUMN updated_at TEXT NOT NULL
    DEFAULT '1970-01-01T00:00:00Z'
    CHECK(length(trim(updated_at)) > 0);

UPDATE topic SET updated_at = created_at;

CREATE INDEX topic_parent_idx
ON topic(parent_topic_id, retired_at, manual_order, topic_key);

CREATE TRIGGER topic_hierarchy_validate_insert
BEFORE INSERT ON topic
WHEN NEW.parent_topic_id IS NOT NULL
 AND (
    NEW.parent_topic_id = NEW.topic_id
    OR NOT EXISTS (
        SELECT 1
        FROM topic AS parent
        WHERE parent.topic_id = NEW.parent_topic_id
          AND parent.parent_topic_id IS NULL
          AND parent.retired_at IS NULL
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'topic parent must be an active root topic');
END;

CREATE TRIGGER topic_hierarchy_validate_update
BEFORE UPDATE OF parent_topic_id ON topic
WHEN NEW.parent_topic_id IS NOT OLD.parent_topic_id
 AND (
    NEW.parent_topic_id = NEW.topic_id
    OR (
        NEW.parent_topic_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
            FROM topic AS parent
            WHERE parent.topic_id = NEW.parent_topic_id
              AND parent.parent_topic_id IS NULL
              AND parent.retired_at IS NULL
        )
    )
    OR (
        NEW.parent_topic_id IS NOT NULL
        AND EXISTS (
            SELECT 1 FROM topic AS child
            WHERE child.parent_topic_id = NEW.topic_id
        )
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'topic hierarchy supports only root and one child level');
END;

CREATE TRIGGER topic_retirement_requires_no_active_children
BEFORE UPDATE OF retired_at ON topic
WHEN OLD.retired_at IS NULL
 AND NEW.retired_at IS NOT NULL
 AND EXISTS (
    SELECT 1
    FROM topic AS child
    WHERE child.parent_topic_id = NEW.topic_id
      AND child.retired_at IS NULL
 )
BEGIN
    SELECT RAISE(ABORT, 'topic with active children cannot be retired');
END;

CREATE TABLE topic_mutation_event (
    topic_mutation_event_id TEXT PRIMARY KEY
        CHECK(length(trim(topic_mutation_event_id)) > 0),
    topic_id TEXT NOT NULL REFERENCES topic(topic_id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL CHECK(event_kind IN ('create','update','state','retire')),
    prior_revision INTEGER CHECK(prior_revision IS NULL OR prior_revision >= 1),
    new_revision INTEGER NOT NULL CHECK(new_revision >= 1),
    old_payload_json TEXT CHECK(
        old_payload_json IS NULL OR json_valid(old_payload_json)
    ),
    new_payload_json TEXT NOT NULL CHECK(json_valid(new_payload_json)),
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    UNIQUE(topic_id, new_revision),
    CHECK(
        (event_kind = 'create'
            AND prior_revision IS NULL
            AND new_revision = 1
            AND old_payload_json IS NULL)
        OR (event_kind <> 'create'
            AND prior_revision IS NOT NULL
            AND new_revision = prior_revision + 1
            AND old_payload_json IS NOT NULL)
    )
) STRICT;

CREATE INDEX topic_mutation_event_topic_idx
ON topic_mutation_event(topic_id, new_revision, topic_mutation_event_id);

CREATE TRIGGER topic_mutation_event_validate_insert
BEFORE INSERT ON topic_mutation_event
WHEN NOT EXISTS (
    SELECT 1
    FROM topic
    WHERE topic.topic_id = NEW.topic_id
      AND topic.revision = NEW.new_revision
)
BEGIN
    SELECT RAISE(ABORT, 'topic mutation event must match the current topic revision');
END;

CREATE TRIGGER topic_mutation_event_no_update
BEFORE UPDATE ON topic_mutation_event
BEGIN
    SELECT RAISE(ABORT, 'topic mutation events are append-only');
END;

CREATE TRIGGER topic_mutation_event_no_delete
BEFORE DELETE ON topic_mutation_event
BEGIN
    SELECT RAISE(ABORT, 'topic mutation events are append-only');
END;
