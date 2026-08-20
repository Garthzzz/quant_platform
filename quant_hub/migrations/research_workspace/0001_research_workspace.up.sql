CREATE TABLE actor (
    actor_id TEXT PRIMARY KEY CHECK(length(trim(actor_id)) > 0),
    actor_kind TEXT NOT NULL CHECK(actor_kind IN (
        'zhang_zhengze','song_dingkun','other'
    )),
    display_name TEXT NOT NULL CHECK(
        length(display_name) BETWEEN 1 AND 100
        AND display_name = trim(display_name)
        AND (
            (actor_kind = 'zhang_zhengze' AND display_name = '张正泽')
            OR (actor_kind = 'song_dingkun' AND display_name = '宋定坤')
            OR (
                actor_kind = 'other'
                AND display_name NOT IN ('张正泽','宋定坤')
            )
        )
    ),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE UNIQUE INDEX actor_kind_display_name_unique
ON actor(actor_kind,display_name);

CREATE UNIQUE INDEX actor_single_zhang
ON actor(actor_kind) WHERE actor_kind='zhang_zhengze';

CREATE UNIQUE INDEX actor_single_song
ON actor(actor_kind) WHERE actor_kind='song_dingkun';

CREATE TABLE research_workspace_sync_run (
    sync_run_id TEXT PRIMARY KEY CHECK(length(trim(sync_run_id)) > 0),
    workspace_root TEXT NOT NULL CHECK(length(trim(workspace_root)) > 0),
    source_signature TEXT NOT NULL CHECK(
        length(source_signature) = 64
        AND source_signature NOT GLOB '*[^0-9a-f]*'
    ),
    started_at TEXT NOT NULL CHECK(length(trim(started_at)) > 0),
    completed_at TEXT,
    status TEXT NOT NULL CHECK(status IN ('running','completed','partial','failed')),
    discovered_count INTEGER NOT NULL DEFAULT 0 CHECK(discovered_count >= 0),
    created_count INTEGER NOT NULL DEFAULT 0 CHECK(created_count >= 0),
    updated_count INTEGER NOT NULL DEFAULT 0 CHECK(updated_count >= 0),
    moved_count INTEGER NOT NULL DEFAULT 0 CHECK(moved_count >= 0),
    missing_count INTEGER NOT NULL DEFAULT 0 CHECK(missing_count >= 0),
    restored_count INTEGER NOT NULL DEFAULT 0 CHECK(restored_count >= 0),
    issue_count INTEGER NOT NULL DEFAULT 0 CHECK(issue_count >= 0),
    issues_json TEXT NOT NULL DEFAULT '[]' CHECK(json_valid(issues_json)),
    CHECK(
        (status = 'running' AND completed_at IS NULL)
        OR (status <> 'running' AND completed_at IS NOT NULL)
    )
) STRICT;

CREATE TRIGGER research_workspace_sync_run_no_delete
BEFORE DELETE ON research_workspace_sync_run
BEGIN
    SELECT RAISE(ABORT, 'research workspace sync runs are append-only');
END;

CREATE TABLE research_workspace_node (
    node_id TEXT PRIMARY KEY CHECK(length(trim(node_id)) > 0),
    parent_node_id TEXT
        REFERENCES research_workspace_node(node_id) ON DELETE RESTRICT,
    node_kind TEXT NOT NULL CHECK(node_kind IN (
        'system','project','topic','subtopic','document'
    )),
    source_entry_kind TEXT NOT NULL CHECK(source_entry_kind IN (
        'virtual','directory','markdown'
    )),
    source_relative_path TEXT NOT NULL CHECK(length(source_relative_path) > 0),
    source_path_key TEXT NOT NULL UNIQUE CHECK(length(source_path_key) > 0),
    source_sha256 TEXT CHECK(
        source_sha256 IS NULL OR (
            length(source_sha256) = 64
            AND source_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    source_bytes INTEGER CHECK(source_bytes IS NULL OR source_bytes >= 0),
    source_mtime_ns INTEGER CHECK(source_mtime_ns IS NULL OR source_mtime_ns >= 0),
    source_state TEXT NOT NULL CHECK(source_state IN ('present','missing')),
    default_title TEXT NOT NULL CHECK(length(trim(default_title)) BETWEEN 1 AND 500),
    title_override TEXT CHECK(
        title_override IS NULL OR length(trim(title_override)) BETWEEN 1 AND 500
    ),
    default_description TEXT CHECK(
        default_description IS NULL
        OR length(trim(default_description)) BETWEEN 1 AND 8000
    ),
    description_override TEXT CHECK(
        description_override IS NULL
        OR length(trim(description_override)) BETWEEN 1 AND 8000
    ),
    lifecycle_status TEXT NOT NULL CHECK(lifecycle_status IN (
        'todo','in_progress','review','completed','archived','cancelled'
    )),
    status_note TEXT CHECK(
        status_note IS NULL OR length(trim(status_note)) BETWEEN 1 AND 4000
    ),
    sort_key INTEGER NOT NULL DEFAULT 100 CHECK(sort_key >= 0),
    research_id TEXT,
    document_id TEXT,
    published_page_url TEXT CHECK(
        published_page_url IS NULL
        OR published_page_url GLOB '/research/*'
    ),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0),
    missing_at TEXT,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    CHECK(parent_node_id IS NULL OR parent_node_id <> node_id),
    CHECK(
        (source_entry_kind = 'markdown' AND source_sha256 IS NOT NULL
            AND source_bytes IS NOT NULL AND source_mtime_ns IS NOT NULL)
        OR source_entry_kind <> 'markdown'
    ),
    CHECK(
        (source_state = 'present' AND missing_at IS NULL)
        OR (source_state = 'missing' AND missing_at IS NOT NULL)
    ),
    CHECK(
        (node_kind = 'system' AND parent_node_id IS NULL)
        OR (node_kind <> 'system' AND parent_node_id IS NOT NULL)
    )
) STRICT;

CREATE INDEX research_workspace_node_parent_idx
ON research_workspace_node(parent_node_id, sort_key, source_path_key);

CREATE INDEX research_workspace_node_status_idx
ON research_workspace_node(lifecycle_status, source_state, updated_at);

CREATE INDEX research_workspace_node_research_idx
ON research_workspace_node(research_id, document_id);

CREATE INDEX research_workspace_node_fingerprint_idx
ON research_workspace_node(source_entry_kind, source_sha256, source_state);

CREATE TRIGGER research_workspace_node_parent_insert
BEFORE INSERT ON research_workspace_node
WHEN NEW.parent_node_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM research_workspace_node
    WHERE node_id = NEW.parent_node_id
      AND node_kind <> 'document'
      AND source_state = 'present'
 )
BEGIN
    SELECT RAISE(ABORT, 'research workspace parent must be a present container node');
END;

CREATE TRIGGER research_workspace_node_parent_update
BEFORE UPDATE OF parent_node_id ON research_workspace_node
WHEN NEW.parent_node_id IS NOT OLD.parent_node_id
 AND (
    NEW.parent_node_id IS NOT NULL
    AND (
        NOT EXISTS (
            SELECT 1 FROM research_workspace_node
            WHERE node_id = NEW.parent_node_id
              AND node_kind <> 'document'
              AND source_state = 'present'
        )
        OR EXISTS (
            WITH RECURSIVE descendants(node_id) AS (
                SELECT node_id FROM research_workspace_node
                WHERE parent_node_id = OLD.node_id
                UNION ALL
                SELECT child.node_id
                FROM research_workspace_node AS child
                JOIN descendants ON child.parent_node_id = descendants.node_id
            )
            SELECT 1 FROM descendants WHERE node_id = NEW.parent_node_id
        )
    )
 )
BEGIN
    SELECT RAISE(ABORT, 'research workspace parent is invalid or cyclic');
END;

CREATE TRIGGER research_workspace_node_revision_update
BEFORE UPDATE ON research_workspace_node
WHEN NEW.node_id IS NOT OLD.node_id
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.revision <> OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'research workspace node update must preserve identity and increment revision');
END;

CREATE TRIGGER research_workspace_node_no_delete
BEFORE DELETE ON research_workspace_node
BEGIN
    SELECT RAISE(ABORT, 'research workspace nodes use audited missing/archive state');
END;

CREATE TABLE research_workspace_observation (
    observation_id TEXT PRIMARY KEY CHECK(length(trim(observation_id)) > 0),
    sync_run_id TEXT NOT NULL
        REFERENCES research_workspace_sync_run(sync_run_id) ON DELETE RESTRICT,
    node_id TEXT NOT NULL
        REFERENCES research_workspace_node(node_id) ON DELETE RESTRICT,
    source_relative_path TEXT NOT NULL CHECK(length(source_relative_path) > 0),
    source_sha256 TEXT CHECK(
        source_sha256 IS NULL OR (
            length(source_sha256) = 64
            AND source_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    source_bytes INTEGER CHECK(source_bytes IS NULL OR source_bytes >= 0),
    source_mtime_ns INTEGER CHECK(source_mtime_ns IS NULL OR source_mtime_ns >= 0),
    observed_at TEXT NOT NULL CHECK(length(trim(observed_at)) > 0),
    UNIQUE(sync_run_id, node_id)
) STRICT;

CREATE INDEX research_workspace_observation_node_idx
ON research_workspace_observation(node_id, observed_at);

CREATE TRIGGER research_workspace_observation_no_update
BEFORE UPDATE ON research_workspace_observation
BEGIN
    SELECT RAISE(ABORT, 'research workspace observations are append-only');
END;

CREATE TRIGGER research_workspace_observation_no_delete
BEFORE DELETE ON research_workspace_observation
BEGIN
    SELECT RAISE(ABORT, 'research workspace observations are append-only');
END;

CREATE TABLE research_workspace_event (
    event_id TEXT PRIMARY KEY CHECK(length(trim(event_id)) > 0),
    sync_run_id TEXT
        REFERENCES research_workspace_sync_run(sync_run_id) ON DELETE RESTRICT,
    node_id TEXT NOT NULL
        REFERENCES research_workspace_node(node_id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL CHECK(event_kind IN (
        'discovered','content_updated','moved','missing','restored',
        'metadata_updated','status_changed','comment_created',
        'comment_updated','comment_deleted'
    )),
    actor_id TEXT REFERENCES actor(actor_id) ON DELETE RESTRICT,
    prior_revision INTEGER CHECK(prior_revision IS NULL OR prior_revision >= 1),
    new_revision INTEGER NOT NULL CHECK(new_revision >= 1),
    old_value_json TEXT CHECK(old_value_json IS NULL OR json_valid(old_value_json)),
    new_value_json TEXT CHECK(new_value_json IS NULL OR json_valid(new_value_json)),
    note TEXT CHECK(note IS NULL OR length(trim(note)) BETWEEN 1 AND 4000),
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    CHECK(
        (event_kind = 'discovered' AND prior_revision IS NULL AND new_revision = 1)
        OR (event_kind <> 'discovered' AND prior_revision IS NOT NULL
            AND new_revision = prior_revision + 1)
    )
) STRICT;

CREATE INDEX research_workspace_event_node_idx
ON research_workspace_event(node_id, occurred_at, event_id);

CREATE INDEX research_workspace_event_recent_idx
ON research_workspace_event(occurred_at DESC, event_id DESC);

CREATE TRIGGER research_workspace_event_no_update
BEFORE UPDATE ON research_workspace_event
BEGIN
    SELECT RAISE(ABORT, 'research workspace events are append-only');
END;

CREATE TRIGGER research_workspace_event_no_delete
BEFORE DELETE ON research_workspace_event
BEGIN
    SELECT RAISE(ABORT, 'research workspace events are append-only');
END;

CREATE TABLE research_workspace_comment (
    comment_id TEXT PRIMARY KEY CHECK(length(trim(comment_id)) > 0),
    node_id TEXT NOT NULL
        REFERENCES research_workspace_node(node_id) ON DELETE RESTRICT,
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    body TEXT NOT NULL CHECK(length(trim(body)) BETWEEN 1 AND 8000),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    deleted_at TEXT,
    CHECK(deleted_at IS NULL OR length(trim(deleted_at)) > 0)
) STRICT;

CREATE INDEX research_workspace_comment_node_idx
ON research_workspace_comment(node_id, created_at, comment_id);

CREATE TRIGGER research_workspace_comment_revision_update
BEFORE UPDATE ON research_workspace_comment
WHEN NEW.comment_id IS NOT OLD.comment_id
  OR NEW.node_id IS NOT OLD.node_id
  OR NEW.actor_id IS NOT OLD.actor_id
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.revision <> OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'research workspace comment update must preserve identity and increment revision');
END;

CREATE TRIGGER research_workspace_comment_no_delete
BEFORE DELETE ON research_workspace_comment
BEGIN
    SELECT RAISE(ABORT, 'research workspace comments use audited soft deletion');
END;

CREATE TRIGGER research_workspace_comment_deleted_no_rewrite
BEFORE UPDATE ON research_workspace_comment
WHEN OLD.deleted_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'deleted research workspace comments are immutable');
END;

CREATE TABLE research_workspace_comment_event (
    comment_event_id TEXT PRIMARY KEY CHECK(length(trim(comment_event_id)) > 0),
    comment_id TEXT NOT NULL
        REFERENCES research_workspace_comment(comment_id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK(event_type IN ('create','update','delete')),
    old_body_hash TEXT CHECK(
        old_body_hash IS NULL OR (
            length(old_body_hash) = 64 AND old_body_hash NOT GLOB '*[^0-9a-f]*'
        )
    ),
    new_body_hash TEXT CHECK(
        new_body_hash IS NULL OR (
            length(new_body_hash) = 64 AND new_body_hash NOT GLOB '*[^0-9a-f]*'
        )
    ),
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    CHECK(
        (event_type = 'create' AND old_body_hash IS NULL AND new_body_hash IS NOT NULL)
        OR (event_type = 'update' AND old_body_hash IS NOT NULL AND new_body_hash IS NOT NULL)
        OR (event_type = 'delete' AND old_body_hash IS NOT NULL AND new_body_hash IS NULL)
    ),
    UNIQUE(comment_id, revision, event_type)
) STRICT;

CREATE TRIGGER research_workspace_comment_event_no_update
BEFORE UPDATE ON research_workspace_comment_event
BEGIN
    SELECT RAISE(ABORT, 'research workspace comment events are append-only');
END;

CREATE TRIGGER research_workspace_comment_event_no_delete
BEFORE DELETE ON research_workspace_comment_event
BEGIN
    SELECT RAISE(ABORT, 'research workspace comment events are append-only');
END;

CREATE TABLE research_workspace_command_receipt (
    receipt_id TEXT PRIMARY KEY CHECK(length(trim(receipt_id)) > 0),
    idempotency_key TEXT NOT NULL UNIQUE
        CHECK(length(trim(idempotency_key)) BETWEEN 1 AND 200),
    command_name TEXT NOT NULL CHECK(command_name IN (
        'workspace.sync','workspace.node.update',
        'workspace.comment.create','workspace.comment.update','workspace.comment.delete'
    )),
    payload_hash TEXT NOT NULL CHECK(
        length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    outcome_json TEXT NOT NULL CHECK(json_valid(outcome_json)),
    http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TRIGGER research_workspace_command_receipt_no_update
BEFORE UPDATE ON research_workspace_command_receipt
BEGIN
    SELECT RAISE(ABORT, 'research workspace command receipts are immutable');
END;

CREATE TRIGGER research_workspace_command_receipt_no_delete
BEFORE DELETE ON research_workspace_command_receipt
BEGIN
    SELECT RAISE(ABORT, 'research workspace command receipts are immutable');
END;
