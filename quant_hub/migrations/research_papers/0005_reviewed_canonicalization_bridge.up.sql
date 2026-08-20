-- 0003 originally froze category evidence to the first arXiv-only bulk replay.
-- Reviewed canonicalization also consumes exact Crossref registry facts and
-- explicitly reviewed local material.  Rebuild the two category audit tables
-- here so every mapped display category remains linked to its source taxonomy.
DROP TRIGGER paper_category_assignment_detail_no_delete;
DROP TRIGGER paper_category_assignment_detail_no_update;
DROP TRIGGER paper_category_assertion_no_delete;
DROP TRIGGER paper_category_assertion_no_update;
DROP INDEX one_primary_category_per_paper_idx;

ALTER TABLE paper_category_assignment_detail
RENAME TO paper_category_assignment_detail_0003;
ALTER TABLE paper_category_assertion
RENAME TO paper_category_assertion_0003;

CREATE TABLE paper_category_assertion (
    category_assertion_id TEXT PRIMARY KEY,
    paper_id TEXT NOT NULL UNIQUE REFERENCES paper(paper_id) ON DELETE RESTRICT,
    source_system TEXT NOT NULL CHECK(source_system IN (
        'arxiv','crossref','reviewed'
    )),
    source_categories_json TEXT NOT NULL CHECK(
        json_valid(source_categories_json)
        AND json_type(source_categories_json)='array'
        AND json_array_length(source_categories_json) > 0
    ),
    primary_source_category TEXT NOT NULL
        CHECK(length(trim(primary_source_category)) > 0),
    mapping_policy_version TEXT NOT NULL
        CHECK(length(trim(mapping_policy_version)) > 0),
    assertion_status TEXT NOT NULL CHECK(assertion_status IN (
        'verified_external','human_reviewed'
    )),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    asserted_at TEXT NOT NULL CHECK(length(trim(asserted_at)) > 0)
) STRICT;

INSERT INTO paper_category_assertion
SELECT * FROM paper_category_assertion_0003;

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
SELECT * FROM paper_category_assignment_detail_0003;

DROP TABLE paper_category_assignment_detail_0003;
DROP TABLE paper_category_assertion_0003;

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

CREATE TABLE evidence_method_origin_candidate_derivation (
    derivation_id TEXT PRIMARY KEY,
    original_source_candidate_id TEXT NOT NULL
        CHECK(length(trim(original_source_candidate_id)) > 0),
    derived_source_candidate_id TEXT NOT NULL UNIQUE
        CHECK(length(trim(derived_source_candidate_id)) > 0),
    derived_candidate_id TEXT NOT NULL UNIQUE
        REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    identifier_scheme TEXT NOT NULL CHECK(identifier_scheme IN (
        'doi','arxiv','pmid','pmcid','report','isbn','url'
    )),
    normalized_identifier TEXT NOT NULL CHECK(
        length(trim(normalized_identifier)) > 0
        AND normalized_identifier=lower(normalized_identifier)
    ),
    rationale TEXT NOT NULL CHECK(length(trim(rationale)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(original_source_candidate_id,identifier_scheme,normalized_identifier),
    CHECK(original_source_candidate_id<>derived_source_candidate_id)
) STRICT;

CREATE TRIGGER evidence_method_origin_candidate_derivation_guard
BEFORE INSERT ON evidence_method_origin_candidate_derivation
WHEN NOT EXISTS (
    SELECT 1
    FROM paper_clue AS original_clue
    JOIN paper_clue_candidate AS original_link USING(clue_id)
    JOIN paper_candidate AS original_candidate USING(candidate_id)
    WHERE original_clue.source_candidate_id=NEW.original_source_candidate_id
      AND original_clue.entity_kind='method_or_resource_family'
      AND original_clue.resolution_status='rejected_non_paper'
      AND original_candidate.candidate_kind='non_paper_resource'
      AND original_candidate.resolution_status='rejected_non_paper'
) OR NOT EXISTS (
    SELECT 1
    FROM paper_clue AS derived_clue
    JOIN paper_clue_candidate AS derived_link USING(clue_id)
    JOIN paper_candidate AS derived_candidate USING(candidate_id)
    WHERE derived_clue.source_candidate_id=NEW.derived_source_candidate_id
      AND derived_clue.entity_kind='paper_or_scholarly_work'
      AND derived_candidate.candidate_id=NEW.derived_candidate_id
      AND derived_candidate.candidate_kind='paper'
      AND derived_candidate.resolution_status IN ('proposed','verified')
)
BEGIN
    SELECT RAISE(ABORT, 'method-origin derivation requires separate rejected-method and paper candidates');
END;

CREATE TABLE evidence_canonicalization_receipt (
    canonicalization_receipt_id TEXT PRIMARY KEY,
    manifest_schema_version TEXT NOT NULL
        CHECK(manifest_schema_version='qrh-reviewed-evidence-expansion/v1'),
    manifest_sha256 TEXT NOT NULL CHECK(
        length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    item_key TEXT NOT NULL CHECK(length(trim(item_key)) > 0),
    item_material_sha256 TEXT NOT NULL CHECK(
        length(item_material_sha256)=64 AND item_material_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    idempotency_key TEXT NOT NULL CHECK(length(trim(idempotency_key)) > 0),
    treatment TEXT NOT NULL CHECK(treatment IN (
        'formal_citation','associated_method_origin'
    )),
    source_candidate_id TEXT NOT NULL CHECK(length(trim(source_candidate_id)) > 0),
    paper_source_candidate_id TEXT NOT NULL CHECK(
        length(trim(paper_source_candidate_id)) > 0
    ),
    resolution_case_id TEXT NOT NULL
        REFERENCES evidence_resolution_case(resolution_case_id) ON DELETE RESTRICT,
    identity_decision_id TEXT NOT NULL
        REFERENCES evidence_identity_decision(identity_decision_id) ON DELETE RESTRICT,
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    resource_mode TEXT NOT NULL CHECK(resource_mode IN (
        'metadata_only','verified_local_resource'
    )),
    result_material_sha256 TEXT NOT NULL CHECK(
        length(result_material_sha256)=64
        AND result_material_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    applied_at TEXT NOT NULL CHECK(length(trim(applied_at)) > 0),
    UNIQUE(idempotency_key,item_key),
    UNIQUE(manifest_sha256,item_key)
) STRICT;

CREATE TRIGGER evidence_canonicalization_receipt_eligibility_guard
BEFORE INSERT ON evidence_canonicalization_receipt
WHEN NOT EXISTS (
    SELECT 1
    FROM evidence_resolution_case AS resolution
    JOIN evidence_resolution_state AS state USING(resolution_case_id)
    JOIN evidence_identity_decision AS decision USING(resolution_case_id)
    JOIN paper_clue_candidate AS paper_link
      ON paper_link.candidate_id=resolution.candidate_id
    JOIN paper_clue AS paper_clue USING(clue_id)
    JOIN identifier_assignment_projection AS identifier
      ON identifier.scheme=decision.identifier_scheme
     AND identifier.normalized_value=decision.normalized_identifier
    WHERE resolution.resolution_case_id=NEW.resolution_case_id
      AND state.state='identifier_verified'
      AND decision.identity_decision_id=NEW.identity_decision_id
      AND decision.decision_kind='accept_verified_identifier'
      AND paper_clue.source_candidate_id=NEW.paper_source_candidate_id
      AND identifier.paper_id=NEW.paper_id
      AND (
        (NEW.treatment='formal_citation'
         AND NEW.source_candidate_id=NEW.paper_source_candidate_id
         AND paper_clue.entity_kind='paper_or_scholarly_work')
        OR
        (NEW.treatment='associated_method_origin'
         AND NEW.source_candidate_id<>NEW.paper_source_candidate_id
         AND EXISTS (
             SELECT 1
             FROM paper_clue AS method_clue
             JOIN paper_clue_candidate AS method_link USING(clue_id)
             JOIN paper_candidate AS method_candidate USING(candidate_id)
             WHERE method_clue.source_candidate_id=NEW.source_candidate_id
               AND method_clue.entity_kind='method_or_resource_family'
               AND method_clue.resolution_status='rejected_non_paper'
               AND method_candidate.candidate_kind='non_paper_resource'
               AND method_candidate.resolution_status='rejected_non_paper'
         )
         AND EXISTS (
             SELECT 1
             FROM evidence_method_origin_candidate_derivation AS derivation
             WHERE derivation.original_source_candidate_id=NEW.source_candidate_id
               AND derivation.derived_source_candidate_id=NEW.paper_source_candidate_id
               AND derivation.derived_candidate_id=resolution.candidate_id
               AND derivation.identifier_scheme=decision.identifier_scheme
               AND derivation.normalized_identifier=decision.normalized_identifier
         ))
      )
)
BEGIN
    SELECT RAISE(ABORT, 'canonicalization requires an explicit verified identity decision and compatible reviewed treatment');
END;

CREATE TABLE evidence_canonical_resource_attachment (
    resource_attachment_id TEXT PRIMARY KEY,
    canonicalization_receipt_id TEXT NOT NULL
        REFERENCES evidence_canonicalization_receipt(canonicalization_receipt_id)
        ON DELETE RESTRICT,
    resolution_case_id TEXT NOT NULL
        REFERENCES evidence_resolution_case(resolution_case_id) ON DELETE RESTRICT,
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    resource_id TEXT NOT NULL REFERENCES paper_resource(resource_id) ON DELETE RESTRICT,
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    attached_at TEXT NOT NULL CHECK(length(trim(attached_at)) > 0),
    UNIQUE(paper_id,resource_id)
) STRICT;

CREATE TRIGGER evidence_canonical_resource_attachment_guard
BEFORE INSERT ON evidence_canonical_resource_attachment
WHEN NOT EXISTS (
    SELECT 1
    FROM evidence_canonicalization_receipt AS receipt
    JOIN evidence_resolution_case AS resolution
      ON resolution.resolution_case_id=NEW.resolution_case_id
    JOIN paper_resource AS resource ON resource.resource_id=NEW.resource_id
    WHERE receipt.canonicalization_receipt_id=NEW.canonicalization_receipt_id
      AND receipt.paper_id=NEW.paper_id
      AND receipt.resolution_case_id=NEW.resolution_case_id
      AND receipt.resource_mode='verified_local_resource'
      AND resource.verification_status='verified'
      AND resource.media_type='application/pdf'
      AND resource.rights_status IN (
          'verified_open_license','repository_distribution_only',
          'public_access_unknown_reuse'
      )
      AND (
          resource.paper_id=NEW.paper_id
          OR (
              resource.paper_id IS NULL
              AND resource.candidate_id=resolution.candidate_id
              AND EXISTS (
                  SELECT 1
                  FROM evidence_acquisition_event AS event
                  JOIN evidence_acquisition_case AS acquisition
                    USING(acquisition_case_id)
                  JOIN evidence_resource_offer AS offer USING(resource_offer_id)
                  JOIN evidence_provider_observation AS observation
                    USING(provider_observation_id)
                  JOIN evidence_provider_attempt AS attempt
                    USING(provider_attempt_id)
                  JOIN evidence_provider_request AS request
                    USING(provider_request_id)
                  WHERE event.resource_id=resource.resource_id
                    AND event.event_kind='fetch_succeeded'
                    AND event.to_state='acquired'
                    AND request.resolution_case_id=NEW.resolution_case_id
              )
          )
      )
)
BEGIN
    SELECT RAISE(ABORT, 'canonical resource attachment requires verified, rights-reviewed acquisition material');
END;

CREATE TABLE evidence_associated_method_relation (
    associated_relation_id TEXT PRIMARY KEY,
    canonicalization_receipt_id TEXT NOT NULL
        REFERENCES evidence_canonicalization_receipt(canonicalization_receipt_id)
        ON DELETE RESTRICT,
    source_candidate_id TEXT NOT NULL CHECK(length(trim(source_candidate_id)) > 0),
    ledger_entry_id TEXT NOT NULL
        REFERENCES citation_ledger_entry(ledger_entry_id) ON DELETE RESTRICT,
    citation_id TEXT NOT NULL
        REFERENCES citation_occurrence(citation_id) ON DELETE RESTRICT,
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    association_kind TEXT NOT NULL CHECK(
        association_kind='associated_method_origin'
    ),
    rationale TEXT NOT NULL CHECK(length(trim(rationale)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(ledger_entry_id,paper_id,association_kind)
) STRICT;

CREATE TRIGGER evidence_associated_method_relation_guard
BEFORE INSERT ON evidence_associated_method_relation
WHEN NOT EXISTS (
    SELECT 1
    FROM evidence_canonicalization_receipt AS receipt
    JOIN citation_ledger_entry AS ledger
      ON ledger.ledger_entry_id=NEW.ledger_entry_id
    JOIN paper_clue AS clue ON clue.clue_id=ledger.clue_id
    WHERE receipt.canonicalization_receipt_id=NEW.canonicalization_receipt_id
      AND receipt.treatment='associated_method_origin'
      AND receipt.source_candidate_id=NEW.source_candidate_id
      AND receipt.paper_id=NEW.paper_id
      AND ledger.citation_id=NEW.citation_id
      AND clue.source_candidate_id=NEW.source_candidate_id
      AND clue.resolution_status='rejected_non_paper'
)
BEGIN
    SELECT RAISE(ABORT, 'associated method relation must preserve its rejected non-paper source candidate');
END;

CREATE TABLE evidence_fulltext_conclusion_support (
    conclusion_id TEXT PRIMARY KEY
        REFERENCES paper_core_conclusion(conclusion_id) ON DELETE RESTRICT,
    resource_id TEXT NOT NULL REFERENCES paper_resource(resource_id) ON DELETE RESTRICT,
    page_number INTEGER NOT NULL CHECK(page_number >= 1),
    page_text_sha256 TEXT NOT NULL CHECK(
        length(page_text_sha256)=64 AND page_text_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    support_text_sha256 TEXT NOT NULL CHECK(
        length(support_text_sha256)=64 AND support_text_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    locator_json TEXT NOT NULL CHECK(
        json_valid(locator_json) AND json_type(locator_json)='object'
    ),
    verification_status TEXT NOT NULL
        CHECK(verification_status='reviewed_fulltext_locator'),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    linked_at TEXT NOT NULL CHECK(length(trim(linked_at)) > 0)
) STRICT;

CREATE TABLE evidence_canonicalization_event (
    canonicalization_event_id TEXT PRIMARY KEY,
    canonicalization_receipt_id TEXT NOT NULL
        REFERENCES evidence_canonicalization_receipt(canonicalization_receipt_id)
        ON DELETE RESTRICT,
    event_sequence INTEGER NOT NULL CHECK(event_sequence >= 1),
    event_kind TEXT NOT NULL CHECK(event_kind IN (
        'paper_reused','paper_created','identifier_assigned',
        'metadata_selected','institution_recorded','resource_attached',
        'reading_task_created','reading_result_recorded',
        'citation_bound','research_relation_added',
        'associated_method_linked','catalog_projected','application_committed'
    )),
    entity_urn TEXT NOT NULL CHECK(length(trim(entity_urn)) > 0),
    payload_json TEXT NOT NULL CHECK(
        json_valid(payload_json) AND json_type(payload_json)='object'
    ),
    payload_sha256 TEXT NOT NULL CHECK(
        length(payload_sha256)=64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    UNIQUE(canonicalization_receipt_id,event_sequence)
) STRICT;

CREATE TABLE evidence_canonicalization_state (
    canonicalization_receipt_id TEXT PRIMARY KEY
        REFERENCES evidence_canonicalization_receipt(canonicalization_receipt_id)
        ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state='applied'),
    revision INTEGER NOT NULL CHECK(revision=1),
    source_event_id TEXT NOT NULL UNIQUE
        REFERENCES evidence_canonicalization_event(canonicalization_event_id)
        ON DELETE RESTRICT,
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0)
) STRICT;

CREATE TRIGGER evidence_canonicalization_state_guard
BEFORE INSERT ON evidence_canonicalization_state
WHEN NOT EXISTS (
    SELECT 1
    FROM evidence_canonicalization_event AS event
    WHERE event.canonicalization_event_id=NEW.source_event_id
      AND event.canonicalization_receipt_id=NEW.canonicalization_receipt_id
      AND event.event_kind='application_committed'
)
BEGIN
    SELECT RAISE(ABORT, 'canonicalization state requires its committed audit event');
END;

CREATE TRIGGER evidence_canonicalization_receipt_no_update
BEFORE UPDATE ON evidence_canonicalization_receipt
BEGIN SELECT RAISE(ABORT, 'canonicalization receipts are immutable'); END;
CREATE TRIGGER evidence_method_origin_candidate_derivation_no_update
BEFORE UPDATE ON evidence_method_origin_candidate_derivation
BEGIN SELECT RAISE(ABORT, 'method-origin candidate derivations are immutable'); END;
CREATE TRIGGER evidence_fulltext_conclusion_support_no_update
BEFORE UPDATE ON evidence_fulltext_conclusion_support
BEGIN SELECT RAISE(ABORT, 'full-text conclusion support is immutable'); END;
CREATE TRIGGER evidence_fulltext_conclusion_support_no_delete
BEFORE DELETE ON evidence_fulltext_conclusion_support
BEGIN SELECT RAISE(ABORT, 'full-text conclusion support is immutable'); END;
CREATE TRIGGER evidence_method_origin_candidate_derivation_no_delete
BEFORE DELETE ON evidence_method_origin_candidate_derivation
BEGIN SELECT RAISE(ABORT, 'method-origin candidate derivations are immutable'); END;
CREATE TRIGGER evidence_canonicalization_receipt_no_delete
BEFORE DELETE ON evidence_canonicalization_receipt
BEGIN SELECT RAISE(ABORT, 'canonicalization receipts are immutable'); END;
CREATE TRIGGER evidence_canonical_resource_attachment_no_update
BEFORE UPDATE ON evidence_canonical_resource_attachment
BEGIN SELECT RAISE(ABORT, 'canonical resource attachments are immutable'); END;
CREATE TRIGGER evidence_canonical_resource_attachment_no_delete
BEFORE DELETE ON evidence_canonical_resource_attachment
BEGIN SELECT RAISE(ABORT, 'canonical resource attachments are immutable'); END;
CREATE TRIGGER evidence_associated_method_relation_no_update
BEFORE UPDATE ON evidence_associated_method_relation
BEGIN SELECT RAISE(ABORT, 'associated method relations are immutable'); END;
CREATE TRIGGER evidence_associated_method_relation_no_delete
BEFORE DELETE ON evidence_associated_method_relation
BEGIN SELECT RAISE(ABORT, 'associated method relations are immutable'); END;
CREATE TRIGGER evidence_canonicalization_event_no_update
BEFORE UPDATE ON evidence_canonicalization_event
BEGIN SELECT RAISE(ABORT, 'canonicalization events are append-only'); END;
CREATE TRIGGER evidence_canonicalization_event_no_delete
BEFORE DELETE ON evidence_canonicalization_event
BEGIN SELECT RAISE(ABORT, 'canonicalization events are append-only'); END;
CREATE TRIGGER evidence_canonicalization_state_no_update
BEFORE UPDATE ON evidence_canonicalization_state
BEGIN SELECT RAISE(ABORT, 'canonicalization state is immutable'); END;
CREATE TRIGGER evidence_canonicalization_state_no_delete
BEFORE DELETE ON evidence_canonicalization_state
BEGIN SELECT RAISE(ABORT, 'canonicalization state is immutable'); END;
