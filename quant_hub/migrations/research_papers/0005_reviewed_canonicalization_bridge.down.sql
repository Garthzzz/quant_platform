DROP TRIGGER evidence_canonicalization_state_no_delete;
DROP TRIGGER evidence_canonicalization_state_no_update;
DROP TRIGGER evidence_canonicalization_event_no_delete;
DROP TRIGGER evidence_canonicalization_event_no_update;
DROP TRIGGER evidence_associated_method_relation_no_delete;
DROP TRIGGER evidence_associated_method_relation_no_update;
DROP TRIGGER evidence_canonical_resource_attachment_no_delete;
DROP TRIGGER evidence_canonical_resource_attachment_no_update;
DROP TRIGGER evidence_canonicalization_receipt_no_delete;
DROP TRIGGER evidence_canonicalization_receipt_no_update;
DROP TRIGGER evidence_method_origin_candidate_derivation_no_delete;
DROP TRIGGER evidence_method_origin_candidate_derivation_no_update;
DROP TRIGGER evidence_fulltext_conclusion_support_no_delete;
DROP TRIGGER evidence_fulltext_conclusion_support_no_update;
DROP TRIGGER evidence_canonicalization_state_guard;
DROP TABLE evidence_canonicalization_state;
DROP TABLE evidence_canonicalization_event;
DROP TRIGGER evidence_associated_method_relation_guard;
DROP TABLE evidence_associated_method_relation;
DROP TABLE evidence_fulltext_conclusion_support;
DROP TRIGGER evidence_canonical_resource_attachment_guard;
DROP TABLE evidence_canonical_resource_attachment;
DROP TRIGGER evidence_canonicalization_receipt_eligibility_guard;
DROP TABLE evidence_canonicalization_receipt;
DROP TRIGGER evidence_method_origin_candidate_derivation_guard;
DROP TABLE evidence_method_origin_candidate_derivation;

-- A downgrade must never silently discard reviewed Crossref/local category
-- evidence.  The guard aborts the migration transaction when such rows exist.
CREATE TABLE paper_category_0005_downgrade_guard (
    incompatible_row_count INTEGER NOT NULL CHECK(incompatible_row_count=0)
) STRICT;
INSERT INTO paper_category_0005_downgrade_guard
SELECT count(*) FROM paper_category_assertion
WHERE source_system<>'arxiv' OR assertion_status<>'verified_external';
DROP TABLE paper_category_0005_downgrade_guard;

DROP TRIGGER paper_category_assignment_detail_no_delete;
DROP TRIGGER paper_category_assignment_detail_no_update;
DROP TRIGGER paper_category_assertion_no_delete;
DROP TRIGGER paper_category_assertion_no_update;
DROP INDEX one_primary_category_per_paper_idx;

ALTER TABLE paper_category_assignment_detail
RENAME TO paper_category_assignment_detail_0005;
ALTER TABLE paper_category_assertion
RENAME TO paper_category_assertion_0005;

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

INSERT INTO paper_category_assertion
SELECT * FROM paper_category_assertion_0005;

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

INSERT INTO paper_category_assignment_detail
SELECT * FROM paper_category_assignment_detail_0005;

DROP TABLE paper_category_assignment_detail_0005;
DROP TABLE paper_category_assertion_0005;

CREATE UNIQUE INDEX one_primary_category_per_paper_idx
ON paper_category_assignment_detail(paper_id)
WHERE is_primary=1;

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
