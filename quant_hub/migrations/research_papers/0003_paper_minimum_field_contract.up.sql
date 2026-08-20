CREATE TABLE paper_category_assertion (
    category_assertion_id TEXT PRIMARY KEY,
    paper_id TEXT NOT NULL UNIQUE REFERENCES paper(paper_id) ON DELETE RESTRICT,
    source_system TEXT NOT NULL CHECK(source_system='arxiv'),
    source_categories_json TEXT NOT NULL CHECK(
        json_valid(source_categories_json)
        AND json_type(source_categories_json)='array'
        AND json_array_length(source_categories_json) > 0
    ),
    primary_source_category TEXT NOT NULL CHECK(length(trim(primary_source_category)) > 0),
    mapping_policy_version TEXT NOT NULL CHECK(length(trim(mapping_policy_version)) > 0),
    assertion_status TEXT NOT NULL CHECK(assertion_status='verified_external'),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    asserted_at TEXT NOT NULL CHECK(length(trim(asserted_at)) > 0)
) STRICT;

CREATE TABLE paper_category_assignment_detail (
    paper_id TEXT NOT NULL,
    category_id TEXT NOT NULL,
    provenance_urn TEXT NOT NULL,
    is_primary INTEGER NOT NULL CHECK(is_primary IN (0,1)),
    category_assertion_id TEXT NOT NULL
        REFERENCES paper_category_assertion(category_assertion_id) ON DELETE RESTRICT,
    PRIMARY KEY(paper_id,category_id,provenance_urn),
    FOREIGN KEY(paper_id,category_id,provenance_urn)
        REFERENCES paper_category_assignment(paper_id,category_id,provenance_urn)
        ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX one_primary_category_per_paper_idx
ON paper_category_assignment_detail(paper_id)
WHERE is_primary=1;

CREATE TABLE paper_core_conclusion_evidence (
    conclusion_id TEXT PRIMARY KEY
        REFERENCES paper_core_conclusion(conclusion_id) ON DELETE RESTRICT,
    excerpt_id TEXT NOT NULL REFERENCES evidence_excerpt(excerpt_id) ON DELETE RESTRICT,
    claim_scope TEXT NOT NULL CHECK(claim_scope='official_abstract_verbatim'),
    verification_status TEXT NOT NULL CHECK(
        verification_status='source_verified_not_fulltext_reviewed'
    ),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    linked_at TEXT NOT NULL CHECK(length(trim(linked_at)) > 0)
) STRICT;

CREATE TABLE paper_institution_resolution (
    institution_resolution_id TEXT PRIMARY KEY,
    paper_id TEXT NOT NULL UNIQUE REFERENCES paper(paper_id) ON DELETE RESTRICT,
    resolution_status TEXT NOT NULL CHECK(resolution_status IN ('verified','unresolved')),
    institutions_json TEXT NOT NULL CHECK(
        json_valid(institutions_json) AND json_type(institutions_json)='array'
    ),
    reason_code TEXT NOT NULL CHECK(length(trim(reason_code)) > 0),
    reason_text TEXT NOT NULL CHECK(length(trim(reason_text)) > 0),
    checked_source_fields_json TEXT NOT NULL CHECK(
        json_valid(checked_source_fields_json)
        AND json_type(checked_source_fields_json)='array'
        AND json_array_length(checked_source_fields_json) > 0
    ),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    resolved_at TEXT NOT NULL CHECK(length(trim(resolved_at)) > 0),
    CHECK(
        (resolution_status='verified' AND json_array_length(institutions_json) > 0)
        OR
        (resolution_status='unresolved' AND json_array_length(institutions_json) = 0)
    )
) STRICT;

CREATE TABLE paper_reading_conclusion_binding (
    reading_run_id TEXT NOT NULL
        REFERENCES paper_reading_run(reading_run_id) ON DELETE RESTRICT,
    conclusion_id TEXT NOT NULL
        REFERENCES paper_core_conclusion(conclusion_id) ON DELETE RESTRICT,
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    linked_at TEXT NOT NULL CHECK(length(trim(linked_at)) > 0),
    PRIMARY KEY(reading_run_id,conclusion_id)
) STRICT;

CREATE TRIGGER paper_category_assertion_no_update
BEFORE UPDATE ON paper_category_assertion
BEGIN SELECT RAISE(ABORT, 'paper category assertions are immutable'); END;
CREATE TRIGGER paper_category_assertion_no_delete
BEFORE DELETE ON paper_category_assertion
BEGIN SELECT RAISE(ABORT, 'paper category assertions are immutable'); END;

CREATE TRIGGER paper_category_assignment_detail_no_update
BEFORE UPDATE ON paper_category_assignment_detail
BEGIN SELECT RAISE(ABORT, 'paper category assignment details are immutable'); END;
CREATE TRIGGER paper_category_assignment_detail_no_delete
BEFORE DELETE ON paper_category_assignment_detail
BEGIN SELECT RAISE(ABORT, 'paper category assignment details are immutable'); END;

CREATE TRIGGER paper_core_conclusion_evidence_no_update
BEFORE UPDATE ON paper_core_conclusion_evidence
BEGIN SELECT RAISE(ABORT, 'paper core conclusion evidence is immutable'); END;
CREATE TRIGGER paper_core_conclusion_evidence_no_delete
BEFORE DELETE ON paper_core_conclusion_evidence
BEGIN SELECT RAISE(ABORT, 'paper core conclusion evidence is immutable'); END;

CREATE TRIGGER paper_institution_resolution_no_update
BEFORE UPDATE ON paper_institution_resolution
BEGIN SELECT RAISE(ABORT, 'paper institution resolutions are immutable'); END;
CREATE TRIGGER paper_institution_resolution_no_delete
BEFORE DELETE ON paper_institution_resolution
BEGIN SELECT RAISE(ABORT, 'paper institution resolutions are immutable'); END;

CREATE TRIGGER paper_reading_conclusion_binding_no_update
BEFORE UPDATE ON paper_reading_conclusion_binding
BEGIN SELECT RAISE(ABORT, 'paper reading conclusion bindings are immutable'); END;
CREATE TRIGGER paper_reading_conclusion_binding_no_delete
BEFORE DELETE ON paper_reading_conclusion_binding
BEGIN SELECT RAISE(ABORT, 'paper reading conclusion bindings are immutable'); END;
