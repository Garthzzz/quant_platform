CREATE TABLE research (
    research_id TEXT PRIMARY KEY CHECK(length(trim(research_id)) > 0),
    canonical_slug TEXT NOT NULL UNIQUE
        CHECK(length(canonical_slug) > 0 AND canonical_slug = trim(canonical_slug)),
    display_title TEXT NOT NULL CHECK(length(trim(display_title)) > 0),
    lifecycle_status TEXT NOT NULL
        CHECK(lifecycle_status IN ('active','historical','withdrawn_from_navigation')),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TABLE research_document (
    document_id TEXT PRIMARY KEY CHECK(length(trim(document_id)) > 0),
    research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    document_role TEXT NOT NULL CHECK(document_role IN (
        'primary','chapter','appendix','historical','slides','poster','supporting'
    )),
    slug TEXT NOT NULL CHECK(length(slug) > 0 AND slug = trim(slug)),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(research_id, slug),
    UNIQUE(document_id, research_id)
) STRICT;

CREATE INDEX research_document_research_idx
ON research_document(research_id, document_role, slug);

CREATE TABLE research_document_origin (
    origin_id TEXT PRIMARY KEY CHECK(length(trim(origin_id)) > 0),
    document_id TEXT NOT NULL REFERENCES research_document(document_id) ON DELETE RESTRICT,
    source_location_urn TEXT NOT NULL CHECK(length(trim(source_location_urn)) > 0),
    origin_kind TEXT NOT NULL CHECK(origin_kind IN (
        'archive_path','research_inbox','legacy_mapping','manual_mapping'
    )),
    mapping_status TEXT NOT NULL CHECK(mapping_status IN (
        'proposed','verified','ambiguous','rejected'
    )),
    mapping_evidence_json TEXT NOT NULL CHECK(json_valid(mapping_evidence_json)),
    first_seen_at TEXT NOT NULL CHECK(length(trim(first_seen_at)) > 0),
    UNIQUE(document_id, source_location_urn)
) STRICT;

CREATE INDEX research_document_origin_source_idx
ON research_document_origin(source_location_urn, mapping_status);

CREATE TABLE research_document_version (
    document_version_id TEXT PRIMARY KEY CHECK(length(trim(document_version_id)) > 0),
    document_id TEXT NOT NULL REFERENCES research_document(document_id) ON DELETE RESTRICT,
    object_urn TEXT NOT NULL CHECK(length(trim(object_urn)) > 0),
    content_sha256 TEXT NOT NULL CHECK(
        length(content_sha256) = 64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bytes INTEGER NOT NULL CHECK(bytes >= 0),
    encoding TEXT NOT NULL CHECK(encoding = 'utf-8'),
    source_observed_at TEXT NOT NULL CHECK(length(trim(source_observed_at)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    discovery_status TEXT NOT NULL CHECK(discovery_status IN (
        'discovered','registered','quarantined'
    )),
    parser_status TEXT NOT NULL CHECK(parser_status IN (
        'pending','succeeded','failed','quarantined'
    )),
    UNIQUE(document_id, content_sha256),
    UNIQUE(document_version_id, document_id)
) STRICT;

CREATE INDEX research_document_version_object_idx
ON research_document_version(object_urn);

CREATE INDEX research_document_version_document_idx
ON research_document_version(document_id, source_observed_at);

CREATE TRIGGER research_document_version_material_immutable
BEFORE UPDATE OF document_version_id, document_id, object_urn, content_sha256, bytes, encoding,
                 source_observed_at, created_at
ON research_document_version
WHEN NEW.document_version_id IS NOT OLD.document_version_id
  OR NEW.document_id IS NOT OLD.document_id
  OR NEW.object_urn IS NOT OLD.object_urn
  OR NEW.content_sha256 IS NOT OLD.content_sha256
  OR NEW.bytes IS NOT OLD.bytes
  OR NEW.encoding IS NOT OLD.encoding
  OR NEW.source_observed_at IS NOT OLD.source_observed_at
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'research document version material fields are immutable');
END;

CREATE TRIGGER research_document_version_no_delete
BEFORE DELETE ON research_document_version
BEGIN
    SELECT RAISE(ABORT, 'research document versions are immutable');
END;

CREATE TRIGGER research_document_version_discovery_transition
BEFORE UPDATE OF discovery_status ON research_document_version
WHEN NOT (
    NEW.discovery_status = OLD.discovery_status
    OR (OLD.discovery_status = 'discovered' AND NEW.discovery_status IN ('registered','quarantined'))
    OR (OLD.discovery_status = 'registered' AND NEW.discovery_status = 'quarantined')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid document discovery status transition');
END;

CREATE TABLE document_version_relation (
    relation_id TEXT PRIMARY KEY CHECK(length(trim(relation_id)) > 0),
    from_document_version_id TEXT NOT NULL
        REFERENCES research_document_version(document_version_id) ON DELETE RESTRICT,
    to_document_version_id TEXT NOT NULL
        REFERENCES research_document_version(document_version_id) ON DELETE RESTRICT,
    relation_kind TEXT NOT NULL CHECK(relation_kind IN (
        'supersedes','derived_from','exact_duplicate_alias','translation_of',
        'unknown_possible_lineage'
    )),
    status TEXT NOT NULL CHECK(status IN ('proposed','verified','rejected')),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    CHECK(from_document_version_id <> to_document_version_id),
    UNIQUE(from_document_version_id, to_document_version_id, relation_kind)
) STRICT;

CREATE INDEX document_version_relation_to_idx
ON document_version_relation(to_document_version_id, relation_kind, status);

CREATE TABLE research_release (
    research_release_id TEXT PRIMARY KEY CHECK(length(trim(research_release_id)) > 0),
    research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    document_manifest_hash TEXT NOT NULL CHECK(
        length(document_manifest_hash) = 64
        AND document_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    candidate_status TEXT NOT NULL CHECK(candidate_status IN (
        'staging','validated','under_review','releasable','rejected'
    )),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(research_release_id, research_id),
    UNIQUE(research_id, document_manifest_hash)
) STRICT;

CREATE INDEX research_release_research_idx
ON research_release(research_id, candidate_status, created_at);

CREATE TRIGGER research_release_insert_staging
BEFORE INSERT ON research_release
WHEN NEW.candidate_status <> 'staging'
BEGIN
    SELECT RAISE(ABORT, 'research release must begin in staging');
END;

CREATE TRIGGER research_release_material_immutable
BEFORE UPDATE ON research_release
WHEN NEW.research_release_id IS NOT OLD.research_release_id
  OR NEW.research_id IS NOT OLD.research_id
  OR NEW.document_manifest_hash IS NOT OLD.document_manifest_hash
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'research release material fields are immutable');
END;

CREATE TRIGGER research_release_candidate_transition
BEFORE UPDATE OF candidate_status ON research_release
WHEN NOT (
    NEW.candidate_status = OLD.candidate_status
    OR (OLD.candidate_status = 'staging' AND NEW.candidate_status IN ('validated','rejected'))
    OR (OLD.candidate_status = 'validated' AND NEW.candidate_status IN ('under_review','rejected'))
    OR (OLD.candidate_status = 'under_review' AND NEW.candidate_status IN ('releasable','rejected'))
)
BEGIN
    SELECT RAISE(ABORT, 'invalid research release candidate transition');
END;

CREATE TRIGGER research_release_validation_requires_manifest
BEFORE UPDATE OF candidate_status ON research_release
WHEN OLD.candidate_status = 'staging'
 AND NEW.candidate_status = 'validated'
 AND (
     (SELECT count(*) FROM research_release_item
      WHERE research_release_id = OLD.research_release_id) = 0
     OR
     (SELECT count(*) FROM research_release_item
      WHERE research_release_id = OLD.research_release_id
        AND navigation_role = 'primary') <> 1
 )
BEGIN
    SELECT RAISE(ABORT, 'validated research release requires exactly one primary document');
END;

CREATE TRIGGER research_release_activated_no_update
BEFORE UPDATE ON research_release
WHEN EXISTS (
    SELECT 1 FROM research_release_activation AS activation
    WHERE activation.research_release_id = OLD.research_release_id
)
BEGIN
    SELECT RAISE(ABORT, 'activated research release is immutable');
END;

CREATE TRIGGER research_release_no_delete
BEFORE DELETE ON research_release
BEGIN
    SELECT RAISE(ABORT, 'research releases are immutable');
END;

CREATE TABLE research_release_item (
    research_release_id TEXT NOT NULL
        REFERENCES research_release(research_release_id) ON DELETE RESTRICT,
    document_id TEXT NOT NULL REFERENCES research_document(document_id) ON DELETE RESTRICT,
    document_version_id TEXT NOT NULL
        REFERENCES research_document_version(document_version_id) ON DELETE RESTRICT,
    navigation_role TEXT NOT NULL CHECK(navigation_role IN (
        'primary','section','appendix','supporting','historical'
    )),
    sort_key INTEGER NOT NULL CHECK(sort_key >= 0),
    PRIMARY KEY(research_release_id, document_id),
    UNIQUE(research_release_id, document_version_id),
    UNIQUE(research_release_id, sort_key)
) STRICT;

CREATE INDEX research_release_item_version_idx
ON research_release_item(document_version_id);

CREATE UNIQUE INDEX research_release_one_primary
ON research_release_item(research_release_id)
WHERE navigation_role = 'primary';

CREATE TRIGGER research_release_item_validate_insert
BEFORE INSERT ON research_release_item
WHEN NOT EXISTS (
        SELECT 1
        FROM research_release AS release
        JOIN research_document AS document
          ON document.research_id = release.research_id
        JOIN research_document_version AS version
          ON version.document_id = document.document_id
        WHERE release.research_release_id = NEW.research_release_id
          AND release.candidate_status = 'staging'
          AND document.document_id = NEW.document_id
          AND version.document_version_id = NEW.document_version_id
    )
BEGIN
    SELECT RAISE(ABORT, 'release item must be a staging release version from the same research');
END;

CREATE TRIGGER research_release_item_no_update
BEFORE UPDATE ON research_release_item
BEGIN
    SELECT RAISE(ABORT, 'research release items are immutable');
END;

CREATE TRIGGER research_release_item_no_delete
BEFORE DELETE ON research_release_item
BEGIN
    SELECT RAISE(ABORT, 'research release items are immutable');
END;

CREATE TABLE research_release_activation (
    activation_id TEXT PRIMARY KEY CHECK(length(trim(activation_id)) > 0),
    research_id TEXT NOT NULL,
    research_release_id TEXT NOT NULL,
    release_snapshot_urn TEXT NOT NULL CHECK(length(trim(release_snapshot_urn)) > 0),
    decision_hash TEXT NOT NULL CHECK(
        length(decision_hash) = 64 AND decision_hash NOT GLOB '*[^0-9a-f]*'
    ),
    activated_at TEXT NOT NULL CHECK(length(trim(activated_at)) > 0),
    supersedes_activation_id TEXT UNIQUE
        REFERENCES research_release_activation(activation_id) ON DELETE RESTRICT,
    FOREIGN KEY(research_release_id, research_id)
        REFERENCES research_release(research_release_id, research_id) ON DELETE RESTRICT,
    CHECK(supersedes_activation_id IS NULL OR supersedes_activation_id <> activation_id),
    UNIQUE(research_id, release_snapshot_urn),
    UNIQUE(activation_id, research_id, research_release_id, release_snapshot_urn)
) STRICT;

CREATE INDEX research_release_activation_release_idx
ON research_release_activation(research_release_id, activated_at);

CREATE TRIGGER research_release_activation_validate_insert
BEFORE INSERT ON research_release_activation
WHEN NOT EXISTS (
        SELECT 1 FROM research_release
        WHERE research_release_id = NEW.research_release_id
          AND research_id = NEW.research_id
          AND candidate_status = 'releasable'
    )
    OR (
        NEW.supersedes_activation_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM research_release_activation
            WHERE activation_id = NEW.supersedes_activation_id
              AND research_id = NEW.research_id
        )
    )
    OR (
        EXISTS (
            SELECT 1 FROM active_research_release
            WHERE research_id = NEW.research_id
        )
        AND NOT EXISTS (
            SELECT 1 FROM active_research_release
            WHERE research_id = NEW.research_id
              AND activation_id = NEW.supersedes_activation_id
        )
    )
    OR (
        NOT EXISTS (
            SELECT 1 FROM active_research_release
            WHERE research_id = NEW.research_id
        )
        AND NEW.supersedes_activation_id IS NOT NULL
    )
BEGIN
    SELECT RAISE(ABORT, 'activation requires a releasable same-research release and predecessor');
END;

CREATE TRIGGER research_release_activation_no_update
BEFORE UPDATE ON research_release_activation
BEGIN
    SELECT RAISE(ABORT, 'research release activations are append-only');
END;

CREATE TRIGGER research_release_activation_no_delete
BEFORE DELETE ON research_release_activation
BEGIN
    SELECT RAISE(ABORT, 'research release activations are append-only');
END;

CREATE TABLE active_research_release (
    research_id TEXT PRIMARY KEY REFERENCES research(research_id) ON DELETE RESTRICT,
    activation_id TEXT NOT NULL,
    research_release_id TEXT NOT NULL,
    release_snapshot_urn TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    FOREIGN KEY(activation_id, research_id, research_release_id, release_snapshot_urn)
        REFERENCES research_release_activation(
            activation_id, research_id, research_release_id, release_snapshot_urn
        ) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER active_research_release_insert_revision
BEFORE INSERT ON active_research_release
WHEN NEW.revision <> 1
  OR NOT EXISTS (
      SELECT 1 FROM research_release_activation
      WHERE activation_id = NEW.activation_id
        AND supersedes_activation_id IS NULL
  )
BEGIN
    SELECT RAISE(ABORT, 'initial active release must be the root activation at revision one');
END;

CREATE TRIGGER active_research_release_update_revision
BEFORE UPDATE ON active_research_release
WHEN NEW.research_id IS NOT OLD.research_id
  OR NEW.revision <> OLD.revision + 1
  OR NEW.activation_id = OLD.activation_id
  OR NOT EXISTS (
      SELECT 1 FROM research_release_activation
      WHERE activation_id = NEW.activation_id
        AND supersedes_activation_id = OLD.activation_id
  )
BEGIN
    SELECT RAISE(ABORT, 'active release update must use the next activation and increment revision');
END;

CREATE TRIGGER active_research_release_no_delete
BEFORE DELETE ON active_research_release
BEGIN
    SELECT RAISE(ABORT, 'active release pointer cannot be deleted; activate an existing release to roll back');
END;

CREATE TABLE outline_node (
    node_id TEXT PRIMARY KEY CHECK(length(trim(node_id)) > 0),
    document_version_id TEXT NOT NULL
        REFERENCES research_document_version(document_version_id) ON DELETE CASCADE,
    parent_node_id TEXT REFERENCES outline_node(node_id) ON DELETE CASCADE,
    level INTEGER NOT NULL CHECK(level BETWEEN 1 AND 12),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    title_text TEXT NOT NULL CHECK(length(trim(title_text)) > 0),
    line_start INTEGER NOT NULL CHECK(line_start >= 1),
    line_end INTEGER NOT NULL CHECK(line_end >= line_start),
    byte_start INTEGER NOT NULL CHECK(byte_start >= 0),
    byte_end INTEGER NOT NULL CHECK(byte_end >= byte_start),
    anchor_id TEXT NOT NULL CHECK(length(trim(anchor_id)) > 0),
    CHECK(parent_node_id IS NULL OR parent_node_id <> node_id),
    UNIQUE(document_version_id, anchor_id),
    UNIQUE(node_id, document_version_id)
) STRICT;

CREATE INDEX outline_node_document_order_idx
ON outline_node(document_version_id, line_start, ordinal);

CREATE INDEX outline_node_parent_idx
ON outline_node(parent_node_id, ordinal);

CREATE TRIGGER outline_node_parent_version_insert
BEFORE INSERT ON outline_node
WHEN NEW.parent_node_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM outline_node AS parent
    WHERE parent.node_id = NEW.parent_node_id
      AND parent.document_version_id = NEW.document_version_id
 )
BEGIN
    SELECT RAISE(ABORT, 'outline parent must belong to the same document version');
END;

CREATE TRIGGER outline_node_parent_version_update
BEFORE UPDATE OF parent_node_id, document_version_id ON outline_node
WHEN NEW.parent_node_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM outline_node AS parent
    WHERE parent.node_id = NEW.parent_node_id
      AND parent.document_version_id = NEW.document_version_id
 )
BEGIN
    SELECT RAISE(ABORT, 'outline parent must belong to the same document version');
END;

CREATE TABLE document_projection (
    projection_id TEXT PRIMARY KEY CHECK(length(trim(projection_id)) > 0),
    document_version_id TEXT NOT NULL
        REFERENCES research_document_version(document_version_id) ON DELETE CASCADE,
    projector_version TEXT NOT NULL CHECK(length(trim(projector_version)) > 0),
    input_sha256 TEXT NOT NULL CHECK(
        length(input_sha256) = 64 AND input_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    toc_json TEXT NOT NULL CHECK(json_valid(toc_json)),
    section_index_json TEXT NOT NULL CHECK(json_valid(section_index_json)),
    rendered_object_urn TEXT CHECK(
        rendered_object_urn IS NULL OR length(trim(rendered_object_urn)) > 0
    ),
    search_revision INTEGER NOT NULL CHECK(search_revision >= 0),
    validation_manifest_hash TEXT CHECK(
        validation_manifest_hash IS NULL OR (
            length(validation_manifest_hash) = 64
            AND validation_manifest_hash NOT GLOB '*[^0-9a-f]*'
        )
    ),
    status TEXT NOT NULL CHECK(status IN ('pending','ready','failed','quarantined')),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(document_version_id, projector_version, input_sha256)
) STRICT;

CREATE TRIGGER document_projection_input_hash_insert
BEFORE INSERT ON document_projection
WHEN NOT EXISTS (
    SELECT 1 FROM research_document_version
    WHERE document_version_id = NEW.document_version_id
      AND content_sha256 = NEW.input_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'document projection input hash does not match source version');
END;

CREATE TRIGGER document_projection_input_hash_update
BEFORE UPDATE OF document_version_id, input_sha256 ON document_projection
WHEN NOT EXISTS (
    SELECT 1 FROM research_document_version
    WHERE document_version_id = NEW.document_version_id
      AND content_sha256 = NEW.input_sha256
)
BEGIN
    SELECT RAISE(ABORT, 'document projection input hash does not match source version');
END;

CREATE TABLE derived_research_metadata (
    metadata_id TEXT PRIMARY KEY CHECK(length(trim(metadata_id)) > 0),
    document_version_id TEXT
        REFERENCES research_document_version(document_version_id) ON DELETE CASCADE,
    research_release_id TEXT REFERENCES research_release(research_release_id) ON DELETE CASCADE,
    derivation_type TEXT NOT NULL CHECK(length(trim(derivation_type)) > 0),
    derivation_version TEXT NOT NULL CHECK(length(trim(derivation_version)) > 0),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    artifact_id TEXT NOT NULL CHECK(length(trim(artifact_id)) > 0),
    status TEXT NOT NULL CHECK(status IN ('proposed','validated','released','rejected')),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    CHECK((document_version_id IS NOT NULL) <> (research_release_id IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX derived_metadata_document_unique
ON derived_research_metadata(
    document_version_id, derivation_type, derivation_version, artifact_id
)
WHERE document_version_id IS NOT NULL;

CREATE UNIQUE INDEX derived_metadata_release_unique
ON derived_research_metadata(
    research_release_id, derivation_type, derivation_version, artifact_id
)
WHERE research_release_id IS NOT NULL;

CREATE TABLE document_search_projection (
    search_rowid INTEGER PRIMARY KEY,
    research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE CASCADE,
    document_version_id TEXT NOT NULL UNIQUE
        REFERENCES research_document_version(document_version_id) ON DELETE CASCADE,
    title_text TEXT NOT NULL,
    search_text TEXT NOT NULL,
    projector_version TEXT NOT NULL CHECK(length(trim(projector_version)) > 0),
    search_revision INTEGER NOT NULL CHECK(search_revision >= 1),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0)
) STRICT;

CREATE TRIGGER document_search_projection_scope_insert
BEFORE INSERT ON document_search_projection
WHEN NOT EXISTS (
    SELECT 1
    FROM research_document_version AS version
    JOIN research_document AS document ON document.document_id = version.document_id
    WHERE version.document_version_id = NEW.document_version_id
      AND document.research_id = NEW.research_id
)
BEGIN
    SELECT RAISE(ABORT, 'search projection research does not own document version');
END;

CREATE TRIGGER document_search_projection_scope_update
BEFORE UPDATE OF research_id, document_version_id ON document_search_projection
WHEN NOT EXISTS (
    SELECT 1
    FROM research_document_version AS version
    JOIN research_document AS document ON document.document_id = version.document_id
    WHERE version.document_version_id = NEW.document_version_id
      AND document.research_id = NEW.research_id
)
BEGIN
    SELECT RAISE(ABORT, 'search projection research does not own document version');
END;

CREATE VIRTUAL TABLE archive_document_fts USING fts5(
    research_id UNINDEXED,
    document_version_id UNINDEXED,
    title_text,
    search_text,
    content='document_search_projection',
    content_rowid='search_rowid',
    tokenize='unicode61 remove_diacritics 2'
);

CREATE TRIGGER document_search_projection_fts_insert
AFTER INSERT ON document_search_projection
BEGIN
    INSERT INTO archive_document_fts(
        rowid, research_id, document_version_id, title_text, search_text
    ) VALUES(
        NEW.search_rowid, NEW.research_id, NEW.document_version_id,
        NEW.title_text, NEW.search_text
    );
END;

CREATE TRIGGER document_search_projection_fts_delete
AFTER DELETE ON document_search_projection
BEGIN
    INSERT INTO archive_document_fts(
        archive_document_fts, rowid, research_id, document_version_id, title_text, search_text
    ) VALUES(
        'delete', OLD.search_rowid, OLD.research_id, OLD.document_version_id,
        OLD.title_text, OLD.search_text
    );
END;

CREATE TRIGGER document_search_projection_fts_update
AFTER UPDATE ON document_search_projection
BEGIN
    INSERT INTO archive_document_fts(
        archive_document_fts, rowid, research_id, document_version_id, title_text, search_text
    ) VALUES(
        'delete', OLD.search_rowid, OLD.research_id, OLD.document_version_id,
        OLD.title_text, OLD.search_text
    );
    INSERT INTO archive_document_fts(
        rowid, research_id, document_version_id, title_text, search_text
    ) VALUES(
        NEW.search_rowid, NEW.research_id, NEW.document_version_id,
        NEW.title_text, NEW.search_text
    );
END;

CREATE TABLE research_relation (
    relation_id TEXT PRIMARY KEY CHECK(length(trim(relation_id)) > 0),
    from_research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    to_research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    relation_type TEXT NOT NULL CHECK(length(trim(relation_type)) > 0),
    evidence_json TEXT NOT NULL CHECK(json_valid(evidence_json)),
    status TEXT NOT NULL CHECK(status IN ('proposed','verified','rejected')),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    CHECK(from_research_id <> to_research_id),
    UNIQUE(from_research_id, to_research_id, relation_type)
) STRICT;

CREATE TABLE knowledge_statement (
    statement_id TEXT PRIMARY KEY CHECK(length(trim(statement_id)) > 0),
    subject_urn TEXT NOT NULL CHECK(length(trim(subject_urn)) > 0),
    statement_kind TEXT NOT NULL CHECK(statement_kind IN (
        'source_claim','externally_verified_fact','deterministic_audit_finding',
        'model_extraction','model_inference','human_annotation'
    )),
    predicate TEXT NOT NULL CHECK(length(trim(predicate)) > 0),
    value_json TEXT NOT NULL CHECK(json_valid(value_json)),
    source_urn TEXT CHECK(source_urn IS NULL OR length(trim(source_urn)) > 0),
    locator_json TEXT CHECK(locator_json IS NULL OR json_valid(locator_json)),
    method_urn TEXT NOT NULL CHECK(length(trim(method_urn)) > 0),
    confidence REAL CHECK(confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0)),
    verification_status TEXT NOT NULL CHECK(verification_status IN (
        'unverified','corroborated','contradicted','rejected'
    )),
    conflict_group_id TEXT,
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(statement_id, subject_urn, predicate)
) STRICT;

CREATE INDEX knowledge_statement_subject_idx
ON knowledge_statement(subject_urn, predicate, verification_status);

CREATE TABLE statement_selection (
    selection_id TEXT PRIMARY KEY CHECK(length(trim(selection_id)) > 0),
    subject_urn TEXT NOT NULL,
    predicate TEXT NOT NULL,
    statement_id TEXT NOT NULL,
    selection_reason TEXT NOT NULL CHECK(length(trim(selection_reason)) > 0),
    decision_urn TEXT NOT NULL CHECK(length(trim(decision_urn)) > 0),
    projection_version TEXT NOT NULL CHECK(length(trim(projection_version)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    FOREIGN KEY(statement_id, subject_urn, predicate)
        REFERENCES knowledge_statement(statement_id, subject_urn, predicate) ON DELETE RESTRICT,
    UNIQUE(subject_urn, predicate, projection_version)
) STRICT;

CREATE INDEX statement_selection_statement_idx
ON statement_selection(statement_id);

CREATE TABLE actor (
    actor_id TEXT PRIMARY KEY CHECK(length(trim(actor_id)) > 0),
    actor_kind TEXT NOT NULL CHECK(actor_kind IN ('zhang_zhengze','song_dingkun','other')),
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
ON actor(actor_kind, display_name);

CREATE UNIQUE INDEX actor_single_zhang
ON actor(actor_kind) WHERE actor_kind = 'zhang_zhengze';

CREATE UNIQUE INDEX actor_single_song
ON actor(actor_kind) WHERE actor_kind = 'song_dingkun';

CREATE TABLE comment (
    comment_id TEXT PRIMARY KEY CHECK(length(trim(comment_id)) > 0),
    research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    body TEXT NOT NULL CHECK(length(trim(body)) BETWEEN 1 AND 10000),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    deleted_at TEXT,
    CHECK(deleted_at IS NULL OR length(trim(deleted_at)) > 0),
    UNIQUE(comment_id, revision)
) STRICT;

CREATE INDEX comment_research_created_idx
ON comment(research_id, created_at, comment_id);

CREATE INDEX comment_actor_idx
ON comment(actor_id, created_at);

CREATE TRIGGER comment_revision_update
BEFORE UPDATE ON comment
WHEN NEW.comment_id IS NOT OLD.comment_id
  OR NEW.research_id IS NOT OLD.research_id
  OR NEW.actor_id IS NOT OLD.actor_id
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.revision <> OLD.revision + 1
BEGIN
    SELECT RAISE(ABORT, 'comment update must preserve identity and increment revision');
END;

CREATE TRIGGER comment_no_delete
BEFORE DELETE ON comment
BEGIN
    SELECT RAISE(ABORT, 'comments use audited soft deletion');
END;

CREATE TRIGGER comment_deleted_no_rewrite
BEFORE UPDATE ON comment
WHEN OLD.deleted_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'deleted comments are immutable');
END;

CREATE TABLE comment_event (
    comment_event_id TEXT PRIMARY KEY CHECK(length(trim(comment_event_id)) > 0),
    comment_id TEXT NOT NULL REFERENCES comment(comment_id) ON DELETE RESTRICT,
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

CREATE TRIGGER comment_event_no_update
BEFORE UPDATE ON comment_event
BEGIN
    SELECT RAISE(ABORT, 'comment events are append-only');
END;

CREATE TRIGGER comment_event_no_delete
BEFORE DELETE ON comment_event
BEGIN
    SELECT RAISE(ABORT, 'comment events are append-only');
END;

CREATE TABLE topic (
    topic_id TEXT PRIMARY KEY CHECK(length(trim(topic_id)) > 0),
    topic_key TEXT NOT NULL UNIQUE CHECK(length(topic_key) > 0 AND topic_key = trim(topic_key)),
    title TEXT NOT NULL CHECK(length(trim(title)) > 0),
    manual_order INTEGER NOT NULL CHECK(manual_order >= 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    retired_at TEXT CHECK(retired_at IS NULL OR length(trim(retired_at)) > 0)
) STRICT;

CREATE TABLE topic_research_link (
    topic_id TEXT NOT NULL REFERENCES topic(topic_id) ON DELETE RESTRICT,
    research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    link_kind TEXT NOT NULL CHECK(link_kind IN ('primary','supporting')),
    dashboard_primary INTEGER NOT NULL CHECK(dashboard_primary IN (0,1)),
    display_rank INTEGER NOT NULL CHECK(display_rank >= 0),
    status TEXT NOT NULL CHECK(status IN ('active','inactive')),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    CHECK(dashboard_primary = 0 OR link_kind = 'primary'),
    PRIMARY KEY(topic_id, research_id)
) STRICT;

CREATE UNIQUE INDEX topic_one_active_dashboard_primary
ON topic_research_link(topic_id)
WHERE dashboard_primary = 1 AND status = 'active';

CREATE INDEX topic_research_link_research_idx
ON topic_research_link(research_id, status);

CREATE TABLE topic_state_event (
    topic_state_event_id TEXT PRIMARY KEY CHECK(length(trim(topic_state_event_id)) > 0),
    topic_id TEXT NOT NULL REFERENCES topic(topic_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('planned','paused')),
    note TEXT CHECK(note IS NULL OR length(trim(note)) > 0),
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    supersedes_event_id TEXT UNIQUE
        REFERENCES topic_state_event(topic_state_event_id) ON DELETE RESTRICT,
    CHECK(supersedes_event_id IS NULL OR supersedes_event_id <> topic_state_event_id)
) STRICT;

CREATE INDEX topic_state_event_topic_idx
ON topic_state_event(topic_id, occurred_at, topic_state_event_id);

CREATE TRIGGER topic_state_event_validate_insert
BEFORE INSERT ON topic_state_event
WHEN NEW.supersedes_event_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM topic_state_event
    WHERE topic_state_event_id = NEW.supersedes_event_id
      AND topic_id = NEW.topic_id
 )
BEGIN
    SELECT RAISE(ABORT, 'superseded topic event must belong to the same topic');
END;

CREATE TRIGGER topic_state_event_no_update
BEFORE UPDATE ON topic_state_event
BEGIN
    SELECT RAISE(ABORT, 'topic state events are append-only');
END;

CREATE TRIGGER topic_state_event_no_delete
BEFORE DELETE ON topic_state_event
BEGIN
    SELECT RAISE(ABORT, 'topic state events are append-only');
END;

CREATE TABLE research_work_state_event (
    work_state_event_id TEXT PRIMARY KEY CHECK(length(trim(work_state_event_id)) > 0),
    research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN ('planned','in_progress','paused')),
    note TEXT CHECK(note IS NULL OR length(trim(note)) > 0),
    actor_id TEXT NOT NULL REFERENCES actor(actor_id) ON DELETE RESTRICT,
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    supersedes_event_id TEXT UNIQUE
        REFERENCES research_work_state_event(work_state_event_id) ON DELETE RESTRICT,
    CHECK(supersedes_event_id IS NULL OR supersedes_event_id <> work_state_event_id)
) STRICT;

CREATE INDEX research_work_state_event_research_idx
ON research_work_state_event(research_id, occurred_at, work_state_event_id);

CREATE TRIGGER research_work_state_event_validate_insert
BEFORE INSERT ON research_work_state_event
WHEN NEW.supersedes_event_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM research_work_state_event
    WHERE work_state_event_id = NEW.supersedes_event_id
      AND research_id = NEW.research_id
 )
BEGIN
    SELECT RAISE(ABORT, 'superseded work event must belong to the same research');
END;

CREATE TRIGGER research_work_state_event_no_update
BEFORE UPDATE ON research_work_state_event
BEGIN
    SELECT RAISE(ABORT, 'research work state events are append-only');
END;

CREATE TRIGGER research_work_state_event_no_delete
BEFORE DELETE ON research_work_state_event
BEGIN
    SELECT RAISE(ABORT, 'research work state events are append-only');
END;

CREATE TABLE research_completion_decision (
    decision_id TEXT PRIMARY KEY CHECK(length(trim(decision_id)) > 0),
    research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    research_release_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK(decision IN ('completed','not_completed','revoked')),
    decision_kind TEXT NOT NULL CHECK(decision_kind IN ('human','reviewed_import')),
    supersedes_decision_id TEXT UNIQUE
        REFERENCES research_completion_decision(decision_id) ON DELETE RESTRICT,
    target_decision_id TEXT UNIQUE
        REFERENCES research_completion_decision(decision_id) ON DELETE RESTRICT,
    actor_id TEXT REFERENCES actor(actor_id) ON DELETE RESTRICT,
    review_urn TEXT CHECK(review_urn IS NULL OR length(trim(review_urn)) > 0),
    reason TEXT NOT NULL CHECK(length(trim(reason)) > 0),
    decided_at TEXT NOT NULL CHECK(length(trim(decided_at)) > 0),
    FOREIGN KEY(research_release_id, research_id)
        REFERENCES research_release(research_release_id, research_id) ON DELETE RESTRICT,
    CHECK(supersedes_decision_id IS NULL OR supersedes_decision_id <> decision_id),
    CHECK(target_decision_id IS NULL OR target_decision_id <> decision_id),
    CHECK(
        (decision = 'revoked' AND target_decision_id IS NOT NULL)
        OR (decision <> 'revoked' AND target_decision_id IS NULL)
    ),
    CHECK(
        (decision_kind = 'human' AND actor_id IS NOT NULL AND review_urn IS NULL)
        OR (decision_kind = 'reviewed_import' AND review_urn IS NOT NULL)
    )
) STRICT;

CREATE INDEX research_completion_decision_research_idx
ON research_completion_decision(research_id, decided_at, decision_id);

CREATE TRIGGER research_completion_decision_validate_insert
BEFORE INSERT ON research_completion_decision
WHEN (
        NEW.decision = 'completed'
        AND NOT EXISTS (
            SELECT 1 FROM active_research_release
            WHERE research_id = NEW.research_id
              AND research_release_id = NEW.research_release_id
        )
    )
    OR (
        NEW.supersedes_decision_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM research_completion_decision
            WHERE decision_id = NEW.supersedes_decision_id
              AND research_id = NEW.research_id
        )
    )
    OR (
        NEW.target_decision_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM research_completion_decision
            WHERE decision_id = NEW.target_decision_id
              AND research_id = NEW.research_id
              AND decision = 'completed'
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'completion decision must bind current release and same-research decisions');
END;

CREATE TRIGGER research_completion_decision_no_update
BEFORE UPDATE ON research_completion_decision
BEGIN
    SELECT RAISE(ABORT, 'research completion decisions are append-only');
END;

CREATE TRIGGER research_completion_decision_no_delete
BEFORE DELETE ON research_completion_decision
BEGIN
    SELECT RAISE(ABORT, 'research completion decisions are append-only');
END;

CREATE TABLE research_status_projection (
    research_id TEXT PRIMARY KEY REFERENCES research(research_id) ON DELETE CASCADE,
    work_status TEXT NOT NULL CHECK(work_status IN (
        'planned','in_progress','completed','paused'
    )),
    release_status TEXT NOT NULL CHECK(release_status IN (
        'unpublished','published','conflicted'
    )),
    evidence_status TEXT NOT NULL CHECK(evidence_status IN (
        'unknown','under_review','passed','failed','conflicted'
    )),
    work_source_event_id TEXT
        REFERENCES research_work_state_event(work_state_event_id) ON DELETE SET NULL,
    completion_decision_id TEXT
        REFERENCES research_completion_decision(decision_id) ON DELETE SET NULL,
    release_activation_id TEXT
        REFERENCES research_release_activation(activation_id) ON DELETE SET NULL,
    evidence_source_urn TEXT CHECK(
        evidence_source_urn IS NULL OR length(trim(evidence_source_urn)) > 0
    ),
    projection_version TEXT NOT NULL CHECK(length(trim(projection_version)) > 0),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0),
    CHECK(work_status <> 'completed' OR completion_decision_id IS NOT NULL),
    CHECK(release_status <> 'published' OR release_activation_id IS NOT NULL),
    CHECK(evidence_status = 'unknown' OR evidence_source_urn IS NOT NULL)
) STRICT;

CREATE TRIGGER research_status_projection_scope_insert
BEFORE INSERT ON research_status_projection
WHEN (
        NEW.work_source_event_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM research_work_state_event
            WHERE work_state_event_id = NEW.work_source_event_id
              AND research_id = NEW.research_id
        )
    )
    OR (
        NEW.completion_decision_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
            FROM research_completion_decision AS decision
            JOIN active_research_release AS active
              ON active.research_id = decision.research_id
             AND active.research_release_id = decision.research_release_id
            WHERE decision.decision_id = NEW.completion_decision_id
              AND decision.research_id = NEW.research_id
              AND decision.decision = 'completed'
        )
    )
    OR (
        NEW.release_activation_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM active_research_release
            WHERE research_id = NEW.research_id
              AND activation_id = NEW.release_activation_id
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'research status projection sources must match current research state');
END;

CREATE TRIGGER research_status_projection_scope_update
BEFORE UPDATE ON research_status_projection
WHEN (
        NEW.work_source_event_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM research_work_state_event
            WHERE work_state_event_id = NEW.work_source_event_id
              AND research_id = NEW.research_id
        )
    )
    OR (
        NEW.completion_decision_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1
            FROM research_completion_decision AS decision
            JOIN active_research_release AS active
              ON active.research_id = decision.research_id
             AND active.research_release_id = decision.research_release_id
            WHERE decision.decision_id = NEW.completion_decision_id
              AND decision.research_id = NEW.research_id
              AND decision.decision = 'completed'
        )
    )
    OR (
        NEW.release_activation_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM active_research_release
            WHERE research_id = NEW.research_id
              AND activation_id = NEW.release_activation_id
        )
    )
BEGIN
    SELECT RAISE(ABORT, 'research status projection sources must match current research state');
END;

CREATE TABLE topic_projection (
    topic_id TEXT PRIMARY KEY REFERENCES topic(topic_id) ON DELETE CASCADE,
    effective_state TEXT NOT NULL CHECK(effective_state IN (
        'planned','paused','completed','conflicted'
    )),
    summary TEXT,
    research_id TEXT REFERENCES research(research_id) ON DELETE SET NULL,
    page_url TEXT,
    quick_links_json TEXT NOT NULL CHECK(json_valid(quick_links_json)),
    source_kind TEXT NOT NULL CHECK(source_kind IN ('automatic','manual')),
    source_event_id TEXT REFERENCES topic_state_event(topic_state_event_id) ON DELETE SET NULL,
    projection_version TEXT NOT NULL CHECK(length(trim(projection_version)) > 0),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0),
    CHECK(
        (effective_state = 'completed'
            AND source_kind = 'automatic'
            AND summary IS NOT NULL AND length(trim(summary)) > 0
            AND research_id IS NOT NULL
            AND page_url IS NOT NULL AND length(trim(page_url)) > 0)
        OR (effective_state IN ('planned','paused','conflicted')
            AND summary IS NULL AND research_id IS NULL AND page_url IS NULL)
    ),
    CHECK(effective_state <> 'paused' OR source_kind = 'manual'),
    CHECK(source_kind <> 'manual' OR source_event_id IS NOT NULL)
) STRICT;

CREATE TRIGGER topic_projection_scope_insert
BEFORE INSERT ON topic_projection
WHEN NEW.source_event_id IS NOT NULL
     AND NOT EXISTS (
         SELECT 1 FROM topic_state_event
         WHERE topic_state_event_id = NEW.source_event_id
           AND topic_id = NEW.topic_id
     )
  OR NEW.effective_state = 'completed'
     AND NOT EXISTS (
         SELECT 1
         FROM topic_research_link AS link
         JOIN research_status_projection AS status
           ON status.research_id = link.research_id
         WHERE link.topic_id = NEW.topic_id
           AND link.research_id = NEW.research_id
           AND link.link_kind = 'primary'
           AND link.dashboard_primary = 1
           AND link.status = 'active'
           AND status.work_status = 'completed'
           AND status.release_status = 'published'
     )
BEGIN
    SELECT RAISE(ABORT, 'topic projection sources do not satisfy dashboard rules');
END;

CREATE TRIGGER topic_projection_scope_update
BEFORE UPDATE ON topic_projection
WHEN NEW.source_event_id IS NOT NULL
     AND NOT EXISTS (
         SELECT 1 FROM topic_state_event
         WHERE topic_state_event_id = NEW.source_event_id
           AND topic_id = NEW.topic_id
     )
  OR NEW.effective_state = 'completed'
     AND NOT EXISTS (
         SELECT 1
         FROM topic_research_link AS link
         JOIN research_status_projection AS status
           ON status.research_id = link.research_id
         WHERE link.topic_id = NEW.topic_id
           AND link.research_id = NEW.research_id
           AND link.link_kind = 'primary'
           AND link.dashboard_primary = 1
           AND link.status = 'active'
           AND status.work_status = 'completed'
           AND status.release_status = 'published'
     )
BEGIN
    SELECT RAISE(ABORT, 'topic projection sources do not satisfy dashboard rules');
END;

CREATE TABLE command_receipt (
    receipt_id TEXT PRIMARY KEY CHECK(length(trim(receipt_id)) > 0),
    idempotency_key TEXT NOT NULL UNIQUE CHECK(length(trim(idempotency_key)) BETWEEN 1 AND 200),
    command_name TEXT NOT NULL CHECK(length(trim(command_name)) > 0),
    payload_hash TEXT NOT NULL CHECK(
        length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    aggregate_urn TEXT NOT NULL CHECK(length(trim(aggregate_urn)) > 0),
    actor_id TEXT REFERENCES actor(actor_id) ON DELETE RESTRICT,
    outcome TEXT NOT NULL CHECK(outcome IN ('applied','rejected')),
    result_json TEXT NOT NULL CHECK(json_valid(result_json)),
    result_hash TEXT NOT NULL CHECK(
        length(result_hash) = 64 AND result_hash NOT GLOB '*[^0-9a-f]*'
    ),
    http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE INDEX command_receipt_aggregate_idx
ON command_receipt(aggregate_urn, created_at);

CREATE TRIGGER command_receipt_no_update
BEFORE UPDATE ON command_receipt
BEGIN
    SELECT RAISE(ABORT, 'command receipts are immutable');
END;

CREATE TRIGGER command_receipt_no_delete
BEFORE DELETE ON command_receipt
BEGIN
    SELECT RAISE(ABORT, 'command receipts are immutable');
END;

CREATE TABLE outbox_event (
    event_id TEXT PRIMARY KEY CHECK(length(trim(event_id)) > 0),
    event_type TEXT NOT NULL CHECK(length(trim(event_type)) > 0),
    event_version TEXT NOT NULL CHECK(length(trim(event_version)) > 0),
    aggregate_urn TEXT NOT NULL CHECK(length(trim(aggregate_urn)) > 0),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    payload_hash TEXT NOT NULL CHECK(
        length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    published_at TEXT CHECK(published_at IS NULL OR length(trim(published_at)) > 0),
    publish_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(publish_attempt_count >= 0),
    CHECK(published_at IS NULL OR publish_attempt_count >= 1),
    UNIQUE(event_type, aggregate_urn, payload_hash)
) STRICT;

CREATE INDEX outbox_event_pending_idx
ON outbox_event(created_at, event_id) WHERE published_at IS NULL;

CREATE TRIGGER outbox_event_update_guard
BEFORE UPDATE ON outbox_event
WHEN NEW.event_id IS NOT OLD.event_id
  OR NEW.event_type IS NOT OLD.event_type
  OR NEW.event_version IS NOT OLD.event_version
  OR NEW.aggregate_urn IS NOT OLD.aggregate_urn
  OR NEW.payload_json IS NOT OLD.payload_json
  OR NEW.payload_hash IS NOT OLD.payload_hash
  OR NEW.created_at IS NOT OLD.created_at
  OR NEW.publish_attempt_count < OLD.publish_attempt_count
  OR (OLD.published_at IS NOT NULL AND NEW.published_at IS NOT OLD.published_at)
BEGIN
    SELECT RAISE(ABORT, 'outbox event material is immutable and delivery state is monotonic');
END;

CREATE TRIGGER outbox_event_no_delete
BEFORE DELETE ON outbox_event
BEGIN
    SELECT RAISE(ABORT, 'outbox events are append-only');
END;

CREATE TABLE inbox_receipt (
    consumer_name TEXT NOT NULL CHECK(length(trim(consumer_name)) > 0),
    source_domain TEXT NOT NULL CHECK(length(trim(source_domain)) > 0),
    event_id TEXT NOT NULL CHECK(length(trim(event_id)) > 0),
    processed_at TEXT NOT NULL CHECK(length(trim(processed_at)) > 0),
    result_hash TEXT NOT NULL CHECK(
        length(result_hash) = 64 AND result_hash NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY(consumer_name, source_domain, event_id)
) STRICT;

CREATE INDEX inbox_receipt_event_idx
ON inbox_receipt(source_domain, event_id);

CREATE TRIGGER inbox_receipt_no_update
BEFORE UPDATE ON inbox_receipt
BEGIN
    SELECT RAISE(ABORT, 'inbox receipts are immutable');
END;

CREATE TRIGGER inbox_receipt_no_delete
BEFORE DELETE ON inbox_receipt
BEGIN
    SELECT RAISE(ABORT, 'inbox receipts are immutable');
END;
