CREATE TABLE legacy_import_run (
    import_run_id TEXT PRIMARY KEY CHECK(length(trim(import_run_id)) > 0),
    source_root TEXT NOT NULL CHECK(length(trim(source_root)) > 0),
    source_manifest_sha256 TEXT NOT NULL CHECK(
        length(source_manifest_sha256) = 64
        AND source_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK(status IN ('running','completed','failed')),
    started_at TEXT NOT NULL CHECK(length(trim(started_at)) > 0),
    finished_at TEXT,
    summary_json TEXT NOT NULL CHECK(json_valid(summary_json)),
    UNIQUE(source_root, source_manifest_sha256)
) STRICT;

CREATE TABLE lab_paper (
    paper_id TEXT PRIMARY KEY CHECK(length(trim(paper_id)) > 0),
    legacy_id TEXT UNIQUE,
    canonical_title TEXT NOT NULL CHECK(length(trim(canonical_title)) > 0),
    lifecycle_status TEXT NOT NULL CHECK(lifecycle_status IN (
        'discovered','reading','validated','published','quarantined'
    )),
    source_kind TEXT NOT NULL CHECK(source_kind IN ('legacy_proj2','paper_drop','manual')),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0)
) STRICT;

CREATE INDEX lab_paper_status_idx ON lab_paper(lifecycle_status, legacy_id);

CREATE TABLE lab_paper_version (
    paper_version_id TEXT PRIMARY KEY CHECK(length(trim(paper_version_id)) > 0),
    paper_id TEXT NOT NULL REFERENCES lab_paper(paper_id) ON DELETE RESTRICT,
    content_sha256 TEXT NOT NULL CHECK(
        length(content_sha256) = 64
        AND content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bytes INTEGER NOT NULL CHECK(bytes > 0),
    media_type TEXT NOT NULL CHECK(media_type = 'application/pdf'),
    original_filename TEXT NOT NULL CHECK(length(trim(original_filename)) > 0),
    source_location_urn TEXT NOT NULL CHECK(length(trim(source_location_urn)) > 0),
    asset_relative_path TEXT NOT NULL CHECK(
        length(trim(asset_relative_path)) > 0
        AND asset_relative_path NOT LIKE '/%'
        AND asset_relative_path NOT LIKE '%..%'
        AND instr(asset_relative_path, char(92)) = 0
    ),
    discovery_status TEXT NOT NULL CHECK(discovery_status IN (
        'registered','validated','quarantined'
    )),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(paper_id, content_sha256),
    UNIQUE(content_sha256, bytes)
) STRICT;

CREATE INDEX lab_paper_version_paper_idx
ON lab_paper_version(paper_id, discovery_status, created_at);

CREATE TRIGGER lab_paper_version_material_immutable
BEFORE UPDATE ON lab_paper_version
WHEN NEW.paper_version_id IS NOT OLD.paper_version_id
  OR NEW.paper_id IS NOT OLD.paper_id
  OR NEW.content_sha256 IS NOT OLD.content_sha256
  OR NEW.bytes IS NOT OLD.bytes
  OR NEW.media_type IS NOT OLD.media_type
  OR NEW.original_filename IS NOT OLD.original_filename
  OR NEW.source_location_urn IS NOT OLD.source_location_urn
  OR NEW.asset_relative_path IS NOT OLD.asset_relative_path
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'lab paper version material fields are immutable');
END;

CREATE TRIGGER lab_paper_version_no_delete
BEFORE DELETE ON lab_paper_version
BEGIN
    SELECT RAISE(ABORT, 'lab paper versions are immutable');
END;

CREATE TABLE reading_workflow (
    workflow_version TEXT PRIMARY KEY CHECK(length(trim(workflow_version)) > 0),
    description TEXT NOT NULL,
    phase_contract_json TEXT NOT NULL CHECK(json_valid(phase_contract_json)),
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE UNIQUE INDEX reading_workflow_one_active_idx
ON reading_workflow(active) WHERE active = 1;

CREATE TABLE reading_phase (
    phase_id TEXT PRIMARY KEY CHECK(length(trim(phase_id)) > 0),
    workflow_version TEXT NOT NULL
        REFERENCES reading_workflow(workflow_version) ON DELETE RESTRICT,
    phase_key TEXT NOT NULL CHECK(length(trim(phase_key)) > 0),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 1),
    display_name TEXT NOT NULL CHECK(length(trim(display_name)) > 0),
    required INTEGER NOT NULL CHECK(required IN (0,1)),
    UNIQUE(workflow_version, phase_key),
    UNIQUE(workflow_version, ordinal),
    UNIQUE(phase_id, workflow_version)
) STRICT;

CREATE TABLE reading_run (
    run_id TEXT PRIMARY KEY CHECK(length(trim(run_id)) > 0),
    paper_version_id TEXT NOT NULL
        REFERENCES lab_paper_version(paper_version_id) ON DELETE RESTRICT,
    workflow_version TEXT NOT NULL
        REFERENCES reading_workflow(workflow_version) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK(status IN (
        'queued','running','awaiting_review','releasable','published','failed','cancelled'
    )),
    attempt INTEGER NOT NULL CHECK(attempt >= 1),
    resume_from_phase_key TEXT,
    input_revision_sha256 TEXT NOT NULL CHECK(
        length(input_revision_sha256) = 64
        AND input_revision_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    error_code TEXT,
    error_detail TEXT,
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0),
    UNIQUE(paper_version_id, workflow_version, attempt)
) STRICT;

CREATE INDEX reading_run_status_idx ON reading_run(status, updated_at);

CREATE TABLE reading_result (
    result_id TEXT PRIMARY KEY CHECK(length(trim(result_id)) > 0),
    run_id TEXT NOT NULL REFERENCES reading_run(run_id) ON DELETE RESTRICT,
    phase_id TEXT REFERENCES reading_phase(phase_id) ON DELETE RESTRICT,
    result_kind TEXT NOT NULL CHECK(result_kind IN (
        'problem','method','experiment','limitation','synthesis','legacy_record'
    )),
    schema_version TEXT NOT NULL CHECK(length(trim(schema_version)) > 0),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    evidence_locator_json TEXT NOT NULL CHECK(json_valid(evidence_locator_json)),
    artifact_sha256 TEXT NOT NULL CHECK(
        length(artifact_sha256) = 64
        AND artifact_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_status TEXT NOT NULL CHECK(artifact_status IN (
        'draft','validated','rejected','quarantined'
    )),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(run_id, phase_id, result_kind, artifact_sha256)
) STRICT;

CREATE INDEX reading_result_run_idx ON reading_result(run_id, artifact_status);

CREATE TRIGGER reading_result_material_immutable
BEFORE UPDATE ON reading_result
BEGIN
    SELECT RAISE(ABORT, 'reading results are immutable');
END;

CREATE TRIGGER reading_result_no_delete
BEFORE DELETE ON reading_result
BEGIN
    SELECT RAISE(ABORT, 'reading results are immutable');
END;

CREATE TABLE lab_note (
    note_id TEXT PRIMARY KEY CHECK(length(trim(note_id)) > 0),
    paper_id TEXT NOT NULL REFERENCES lab_paper(paper_id) ON DELETE RESTRICT,
    content_sha256 TEXT NOT NULL CHECK(
        length(content_sha256) = 64
        AND content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bytes INTEGER NOT NULL CHECK(bytes > 0),
    source_location_urn TEXT NOT NULL CHECK(length(trim(source_location_urn)) > 0),
    snapshot_relative_path TEXT NOT NULL CHECK(
        length(trim(snapshot_relative_path)) > 0
        AND snapshot_relative_path NOT LIKE '/%'
        AND snapshot_relative_path NOT LIKE '%..%'
        AND instr(snapshot_relative_path, char(92)) = 0
    ),
    note_kind TEXT NOT NULL CHECK(note_kind IN ('legacy','system','manual')),
    template_status TEXT NOT NULL CHECK(template_status IN ('six_section','legacy','unparseable')),
    is_canonical INTEGER NOT NULL CHECK(is_canonical IN (0,1)),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(paper_id, content_sha256)
) STRICT;

CREATE UNIQUE INDEX lab_note_one_canonical_idx
ON lab_note(paper_id) WHERE is_canonical = 1;

CREATE TABLE tag_vocabulary (
    tag_id TEXT PRIMARY KEY CHECK(length(trim(tag_id)) > 0),
    layer TEXT NOT NULL CHECK(layer IN (
        'data_input','data_preprocess','method_model','method_special',
        'loss_function','training_config','pipeline_output'
    )),
    tag_text TEXT NOT NULL CHECK(length(trim(tag_text)) > 0),
    review_status TEXT NOT NULL CHECK(review_status IN ('approved','queued','rejected','merged')),
    canonical_tag_id TEXT REFERENCES tag_vocabulary(tag_id) ON DELETE RESTRICT,
    source_kind TEXT NOT NULL CHECK(source_kind IN ('legacy_vocab','legacy_record','manual')),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(layer, tag_text),
    CHECK((review_status = 'merged') = (canonical_tag_id IS NOT NULL))
) STRICT;

CREATE TABLE paper_tag (
    paper_id TEXT NOT NULL REFERENCES lab_paper(paper_id) ON DELETE RESTRICT,
    tag_id TEXT NOT NULL REFERENCES tag_vocabulary(tag_id) ON DELETE RESTRICT,
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    PRIMARY KEY(paper_id, tag_id, provenance_urn)
) WITHOUT ROWID, STRICT;

CREATE TABLE concept_component (
    component_id TEXT PRIMARY KEY CHECK(length(trim(component_id)) > 0),
    component_kind TEXT NOT NULL CHECK(component_kind IN ('tag_component','concept_block')),
    legacy_component_id TEXT NOT NULL,
    layer TEXT NOT NULL CHECK(length(trim(layer)) > 0),
    display_name TEXT NOT NULL CHECK(length(trim(display_name)) > 0),
    version INTEGER NOT NULL CHECK(version >= 1),
    automatic_payload_json TEXT NOT NULL CHECK(json_valid(automatic_payload_json)),
    curated_payload_json TEXT NOT NULL CHECK(json_valid(curated_payload_json)),
    source_revision_sha256 TEXT NOT NULL CHECK(
        length(source_revision_sha256) = 64
        AND source_revision_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK(status IN ('imported','validated','stub','retired')),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(component_kind, legacy_component_id, version)
) STRICT;

CREATE TABLE component_evidence (
    component_evidence_id TEXT PRIMARY KEY CHECK(length(trim(component_evidence_id)) > 0),
    component_id TEXT NOT NULL REFERENCES concept_component(component_id) ON DELETE RESTRICT,
    paper_id TEXT NOT NULL REFERENCES lab_paper(paper_id) ON DELETE RESTRICT,
    result_id TEXT REFERENCES reading_result(result_id) ON DELETE RESTRICT,
    evidence_kind TEXT NOT NULL CHECK(evidence_kind IN ('legacy_reference','reading_result','source_excerpt')),
    evidence_locator_json TEXT NOT NULL CHECK(json_valid(evidence_locator_json)),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(component_id, paper_id, evidence_kind, provenance_urn)
) STRICT;

CREATE TABLE architecture_blueprint (
    blueprint_id TEXT PRIMARY KEY CHECK(length(trim(blueprint_id)) > 0),
    name TEXT NOT NULL CHECK(length(trim(name)) > 0),
    objective TEXT NOT NULL,
    lifecycle_status TEXT NOT NULL CHECK(lifecycle_status IN ('draft','validated','published','retired')),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0)
) STRICT;

CREATE TABLE blueprint_version (
    blueprint_version_id TEXT PRIMARY KEY CHECK(length(trim(blueprint_version_id)) > 0),
    blueprint_id TEXT NOT NULL REFERENCES architecture_blueprint(blueprint_id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK(version >= 1),
    constraints_json TEXT NOT NULL CHECK(json_valid(constraints_json)),
    validation_status TEXT NOT NULL CHECK(validation_status IN ('pending','valid','invalid')),
    validation_report_json TEXT NOT NULL CHECK(json_valid(validation_report_json)),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(blueprint_id, version)
) STRICT;

CREATE TABLE blueprint_component (
    blueprint_version_id TEXT NOT NULL
        REFERENCES blueprint_version(blueprint_version_id) ON DELETE RESTRICT,
    component_id TEXT NOT NULL REFERENCES concept_component(component_id) ON DELETE RESTRICT,
    layer TEXT NOT NULL CHECK(length(trim(layer)) > 0),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    forced INTEGER NOT NULL CHECK(forced IN (0,1)),
    PRIMARY KEY(blueprint_version_id, layer, ordinal),
    UNIQUE(blueprint_version_id, component_id, layer)
) WITHOUT ROWID, STRICT;

CREATE TABLE compatibility_rule (
    compatibility_rule_id TEXT PRIMARY KEY CHECK(length(trim(compatibility_rule_id)) > 0),
    rule_set_version TEXT NOT NULL CHECK(length(trim(rule_set_version)) > 0),
    legacy_rule_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('hard','soft','mapping')),
    rule_json TEXT NOT NULL CHECK(json_valid(rule_json)),
    source_revision_sha256 TEXT NOT NULL CHECK(
        length(source_revision_sha256) = 64
        AND source_revision_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    active INTEGER NOT NULL CHECK(active IN (0,1)),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(rule_set_version, legacy_rule_id)
) STRICT;

CREATE TABLE legacy_record_map (
    legacy_record_map_id TEXT PRIMARY KEY CHECK(length(trim(legacy_record_map_id)) > 0),
    import_run_id TEXT NOT NULL REFERENCES legacy_import_run(import_run_id) ON DELETE RESTRICT,
    legacy_kind TEXT NOT NULL CHECK(legacy_kind IN (
        'db_row','pdf','json','note','tag_component','concept_block','compatibility_rule','blueprint'
    )),
    legacy_key TEXT NOT NULL CHECK(length(trim(legacy_key)) > 0),
    source_relative_path TEXT,
    source_sha256 TEXT CHECK(
        source_sha256 IS NULL OR (
            length(source_sha256) = 64
            AND source_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    target_kind TEXT NOT NULL CHECK(length(trim(target_kind)) > 0),
    target_id TEXT,
    import_status TEXT NOT NULL CHECK(import_status IN (
        'imported','quarantined','superseded','unmapped'
    )),
    difference_kind TEXT NOT NULL CHECK(difference_kind IN (
        'equivalent','intentional_improvement','legacy_defect_preserved','not_applicable'
    )),
    difference_json TEXT NOT NULL CHECK(json_valid(difference_json)),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(import_run_id, legacy_kind, legacy_key, source_relative_path)
) STRICT;

CREATE INDEX legacy_record_map_target_idx
ON legacy_record_map(target_kind, target_id, import_status);

CREATE TABLE quarantine_record (
    quarantine_id TEXT PRIMARY KEY CHECK(length(trim(quarantine_id)) > 0),
    import_run_id TEXT REFERENCES legacy_import_run(import_run_id) ON DELETE RESTRICT,
    paper_id TEXT REFERENCES lab_paper(paper_id) ON DELETE RESTRICT,
    source_relative_path TEXT,
    issue_code TEXT NOT NULL CHECK(length(trim(issue_code)) > 0),
    severity TEXT NOT NULL CHECK(severity IN ('error','warning','info')),
    evidence_json TEXT NOT NULL CHECK(json_valid(evidence_json)),
    disposition_status TEXT NOT NULL CHECK(disposition_status IN (
        'open','accepted_legacy','resolved','rejected'
    )),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(import_run_id, paper_id, source_relative_path, issue_code)
) STRICT;

CREATE INDEX quarantine_record_status_idx
ON quarantine_record(disposition_status, severity, issue_code);

CREATE TABLE paper_lab_event (
    event_id TEXT PRIMARY KEY CHECK(length(trim(event_id)) > 0),
    aggregate_type TEXT NOT NULL CHECK(length(trim(aggregate_type)) > 0),
    aggregate_id TEXT NOT NULL CHECK(length(trim(aggregate_id)) > 0),
    event_type TEXT NOT NULL CHECK(length(trim(event_type)) > 0),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE INDEX paper_lab_event_aggregate_idx
ON paper_lab_event(aggregate_type, aggregate_id, created_at);

CREATE TRIGGER paper_lab_event_no_update
BEFORE UPDATE ON paper_lab_event
BEGIN
    SELECT RAISE(ABORT, 'paper lab events are append-only');
END;

CREATE TRIGGER paper_lab_event_no_delete
BEFORE DELETE ON paper_lab_event
BEGIN
    SELECT RAISE(ABORT, 'paper lab events are append-only');
END;
