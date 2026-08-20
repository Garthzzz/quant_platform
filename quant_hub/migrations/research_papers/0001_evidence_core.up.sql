CREATE TABLE paper_clue (
    clue_id TEXT PRIMARY KEY,
    source_candidate_id TEXT NOT NULL UNIQUE CHECK(length(trim(source_candidate_id)) > 0),
    entity_kind TEXT NOT NULL CHECK(entity_kind IN ('paper_or_scholarly_work','method_or_resource_family')),
    domain_category TEXT,
    raw_claim_json TEXT NOT NULL CHECK(json_valid(raw_claim_json)),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    resolution_status TEXT NOT NULL CHECK(resolution_status IN (
        'unresolved','resolution_pending','externally_verified','conflicted','rejected_non_paper'
    )),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TABLE paper_candidate (
    candidate_id TEXT PRIMARY KEY,
    candidate_kind TEXT NOT NULL CHECK(candidate_kind IN ('paper','non_paper_resource')),
    title_claim TEXT,
    publication_year INTEGER CHECK(publication_year IS NULL OR publication_year BETWEEN 1400 AND 3000),
    resolution_status TEXT NOT NULL CHECK(resolution_status IN (
        'proposed','verified','conflicted','rejected_non_paper'
    )),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TABLE paper_clue_candidate (
    clue_id TEXT NOT NULL REFERENCES paper_clue(clue_id) ON DELETE RESTRICT,
    candidate_id TEXT NOT NULL REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    link_kind TEXT NOT NULL CHECK(link_kind IN ('local_claim','identifier_resolution','external_resolution')),
    evidence_json TEXT NOT NULL CHECK(json_valid(evidence_json)),
    linked_at TEXT NOT NULL CHECK(length(trim(linked_at)) > 0),
    PRIMARY KEY(clue_id,candidate_id,link_kind)
) STRICT;

CREATE TABLE external_identity_candidate (
    external_candidate_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    provider TEXT NOT NULL CHECK(length(trim(provider)) > 0),
    provider_rank INTEGER NOT NULL CHECK(provider_rank >= 1),
    provider_score REAL,
    provider_record_json TEXT NOT NULL CHECK(json_valid(provider_record_json)),
    selection_status TEXT NOT NULL CHECK(selection_status IN ('not_selected','rejected')),
    identity_decision TEXT NOT NULL CHECK(length(trim(identity_decision)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    observed_at TEXT NOT NULL CHECK(length(trim(observed_at)) > 0),
    UNIQUE(candidate_id,provider,provider_rank,provenance_urn)
) STRICT;

CREATE TABLE external_assertion (
    external_assertion_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    assertion_kind TEXT NOT NULL CHECK(length(trim(assertion_kind)) > 0),
    field_name TEXT NOT NULL CHECK(length(trim(field_name)) > 0),
    value_json TEXT NOT NULL CHECK(json_valid(value_json)),
    verification_status TEXT NOT NULL CHECK(length(trim(verification_status)) > 0),
    selection_status TEXT NOT NULL CHECK(selection_status IN (
        'not_canonicalized_by_this_preprocess','not_selected','selected_by_strong_identifier'
    )),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    asserted_at TEXT NOT NULL CHECK(length(trim(asserted_at)) > 0)
) STRICT;

CREATE TABLE evidence_import_receipt (
    import_receipt_id TEXT PRIMARY KEY,
    package_schema_version TEXT NOT NULL CHECK(length(trim(package_schema_version)) > 0),
    input_manifest_hash TEXT NOT NULL CHECK(
        length(input_manifest_hash)=64 AND input_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    artifact_manifest_hash TEXT NOT NULL CHECK(
        length(artifact_manifest_hash)=64 AND artifact_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    candidate_count INTEGER NOT NULL CHECK(candidate_count >= 0),
    ledger_entry_count INTEGER NOT NULL CHECK(ledger_entry_count >= 0),
    unlinked_entry_count INTEGER NOT NULL CHECK(unlinked_entry_count >= 0),
    external_candidate_count INTEGER NOT NULL CHECK(external_candidate_count >= 0),
    resource_count INTEGER NOT NULL CHECK(resource_count >= 0),
    validation_status TEXT NOT NULL CHECK(validation_status='passed'),
    report_json TEXT NOT NULL CHECK(json_valid(report_json)),
    imported_at TEXT NOT NULL CHECK(length(trim(imported_at)) > 0),
    UNIQUE(input_manifest_hash,artifact_manifest_hash)
) STRICT;

CREATE TABLE paper (
    paper_id TEXT PRIMARY KEY,
    canonical_urn TEXT NOT NULL UNIQUE CHECK(length(trim(canonical_urn)) > 0),
    creation_event_id TEXT NOT NULL UNIQUE CHECK(length(trim(creation_event_id)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TABLE metadata_assertion (
    assertion_id TEXT PRIMARY KEY,
    paper_id TEXT REFERENCES paper(paper_id) ON DELETE RESTRICT,
    candidate_id TEXT REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    field_name TEXT NOT NULL CHECK(field_name IN (
        'title','abstract','publication_date','publication_year','venue','publisher',
        'volume','issue','pages','author','institution','external_url','license','report_number'
    )),
    value_json TEXT NOT NULL CHECK(json_valid(value_json)),
    assertion_status TEXT NOT NULL CHECK(assertion_status IN ('claimed','verified','conflicted','rejected')),
    source_kind TEXT NOT NULL CHECK(source_kind IN ('archive_local','publisher','repository','registry','manual_review')),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    asserted_at TEXT NOT NULL CHECK(length(trim(asserted_at)) > 0),
    CHECK(paper_id IS NOT NULL OR candidate_id IS NOT NULL)
) STRICT;

CREATE TABLE paper_identifier_assertion (
    identifier_assertion_id TEXT PRIMARY KEY,
    paper_id TEXT REFERENCES paper(paper_id) ON DELETE RESTRICT,
    candidate_id TEXT REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    scheme TEXT NOT NULL CHECK(scheme IN ('doi','arxiv','pmid','pmcid','report','isbn','url')),
    raw_value TEXT NOT NULL CHECK(length(trim(raw_value)) > 0),
    normalized_value TEXT NOT NULL CHECK(
        length(trim(normalized_value)) > 0 AND normalized_value = lower(normalized_value)
    ),
    assertion_status TEXT NOT NULL CHECK(assertion_status IN ('claimed','verified','conflicted','rejected')),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    asserted_at TEXT NOT NULL CHECK(length(trim(asserted_at)) > 0),
    CHECK(paper_id IS NOT NULL OR candidate_id IS NOT NULL)
) STRICT;

CREATE INDEX paper_identifier_lookup_idx
ON paper_identifier_assertion(scheme,normalized_value,assertion_status);

CREATE TABLE paper_identity_event (
    identity_event_id TEXT PRIMARY KEY,
    event_kind TEXT NOT NULL CHECK(event_kind IN (
        'paper_created','identifier_assigned','identifier_reassigned','papers_merged','paper_split'
    )),
    from_paper_id TEXT REFERENCES paper(paper_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    to_paper_id TEXT REFERENCES paper(paper_id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    scheme TEXT CHECK(scheme IS NULL OR scheme IN ('doi','arxiv','pmid','pmcid','report','isbn','url')),
    normalized_value TEXT CHECK(
        normalized_value IS NULL OR (
            length(trim(normalized_value)) > 0 AND normalized_value = lower(normalized_value)
        )
    ),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    CHECK(
        (event_kind = 'paper_created' AND from_paper_id IS NULL AND to_paper_id IS NOT NULL)
        OR (event_kind = 'identifier_assigned' AND from_paper_id IS NULL AND to_paper_id IS NOT NULL
            AND scheme IS NOT NULL AND normalized_value IS NOT NULL)
        OR (event_kind = 'identifier_reassigned' AND from_paper_id IS NOT NULL AND to_paper_id IS NOT NULL
            AND from_paper_id <> to_paper_id AND scheme IS NOT NULL AND normalized_value IS NOT NULL)
        OR (event_kind = 'papers_merged' AND from_paper_id IS NOT NULL AND to_paper_id IS NOT NULL
            AND from_paper_id <> to_paper_id)
        OR (event_kind = 'paper_split' AND from_paper_id IS NOT NULL AND to_paper_id IS NOT NULL
            AND from_paper_id <> to_paper_id)
    )
) STRICT;

CREATE TABLE identifier_assignment_projection (
    scheme TEXT NOT NULL CHECK(scheme IN ('doi','arxiv','pmid','pmcid','report','isbn','url')),
    normalized_value TEXT NOT NULL CHECK(
        length(trim(normalized_value)) > 0 AND normalized_value = lower(normalized_value)
    ),
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    source_event_id TEXT NOT NULL UNIQUE REFERENCES paper_identity_event(identity_event_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0),
    PRIMARY KEY(scheme,normalized_value)
) STRICT;

CREATE TRIGGER identifier_assignment_projection_validate_insert
BEFORE INSERT ON identifier_assignment_projection
WHEN NOT EXISTS (
    SELECT 1 FROM paper_identity_event
    WHERE identity_event_id=NEW.source_event_id
      AND event_kind IN ('identifier_assigned','identifier_reassigned')
      AND scheme=NEW.scheme
      AND normalized_value=NEW.normalized_value
      AND to_paper_id=NEW.paper_id
) OR NEW.revision <> 1
BEGIN
    SELECT RAISE(ABORT, 'identifier assignment requires a matching identity event and revision 1');
END;

CREATE TRIGGER identifier_assignment_projection_validate_update
BEFORE UPDATE ON identifier_assignment_projection
WHEN NEW.scheme <> OLD.scheme
  OR NEW.normalized_value <> OLD.normalized_value
  OR NEW.revision <> OLD.revision + 1
  OR NOT EXISTS (
      SELECT 1 FROM paper_identity_event
      WHERE identity_event_id=NEW.source_event_id
        AND event_kind='identifier_reassigned'
        AND scheme=NEW.scheme
        AND normalized_value=NEW.normalized_value
        AND from_paper_id=OLD.paper_id
        AND to_paper_id=NEW.paper_id
  )
BEGIN
    SELECT RAISE(ABORT, 'identifier reassignment requires a matching append-only identity event');
END;

CREATE TRIGGER identifier_assignment_projection_no_delete
BEFORE DELETE ON identifier_assignment_projection
BEGIN
    SELECT RAISE(ABORT, 'identifier assignment projection cannot be deleted');
END;

CREATE TABLE canonical_metadata_selection (
    selection_id TEXT PRIMARY KEY,
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    field_name TEXT NOT NULL CHECK(length(trim(field_name)) > 0),
    assertion_id TEXT NOT NULL REFERENCES metadata_assertion(assertion_id) ON DELETE RESTRICT,
    supersedes_selection_id TEXT REFERENCES canonical_metadata_selection(selection_id) ON DELETE RESTRICT,
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    selected_at TEXT NOT NULL CHECK(length(trim(selected_at)) > 0),
    UNIQUE(paper_id,field_name,selection_id)
) STRICT;

CREATE TABLE paper_category (
    category_id TEXT PRIMARY KEY,
    category_key TEXT NOT NULL UNIQUE CHECK(length(trim(category_key)) > 0),
    display_name TEXT NOT NULL CHECK(length(trim(display_name)) > 0)
) STRICT;

CREATE TABLE paper_category_assignment (
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    category_id TEXT NOT NULL REFERENCES paper_category(category_id) ON DELETE RESTRICT,
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    assigned_at TEXT NOT NULL CHECK(length(trim(assigned_at)) > 0),
    PRIMARY KEY(paper_id,category_id,provenance_urn)
) STRICT;

CREATE TABLE person (
    person_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL CHECK(length(trim(display_name)) > 0),
    orcid TEXT UNIQUE CHECK(orcid IS NULL OR length(trim(orcid)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0)
) STRICT;

CREATE TABLE organization (
    organization_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL CHECK(length(trim(display_name)) > 0),
    ror_id TEXT UNIQUE CHECK(ror_id IS NULL OR length(trim(ror_id)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0)
) STRICT;

CREATE TABLE paper_authorship (
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    person_id TEXT NOT NULL REFERENCES person(person_id) ON DELETE RESTRICT,
    author_order INTEGER NOT NULL CHECK(author_order >= 1),
    role TEXT NOT NULL DEFAULT 'author' CHECK(role IN ('author','editor')),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    PRIMARY KEY(paper_id,author_order),
    UNIQUE(paper_id,person_id,role)
) STRICT;

CREATE TABLE person_affiliation_assertion (
    affiliation_id TEXT PRIMARY KEY,
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    person_id TEXT NOT NULL REFERENCES person(person_id) ON DELETE RESTRICT,
    organization_id TEXT NOT NULL REFERENCES organization(organization_id) ON DELETE RESTRICT,
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    assertion_status TEXT NOT NULL CHECK(assertion_status IN ('claimed','verified','conflicted')),
    asserted_at TEXT NOT NULL CHECK(length(trim(asserted_at)) > 0)
) STRICT;

CREATE TABLE paper_external_link (
    external_link_id TEXT PRIMARY KEY,
    paper_id TEXT REFERENCES paper(paper_id) ON DELETE RESTRICT,
    candidate_id TEXT REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    link_kind TEXT NOT NULL CHECK(link_kind IN ('landing','doi','repository','publisher_pdf','code','data')),
    url TEXT NOT NULL CHECK(length(trim(url)) > 0),
    verification_status TEXT NOT NULL CHECK(verification_status IN ('claimed','verified','failed','blocked')),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    asserted_at TEXT NOT NULL CHECK(length(trim(asserted_at)) > 0),
    CHECK(paper_id IS NOT NULL OR candidate_id IS NOT NULL)
) STRICT;

CREATE TABLE fetch_attempt (
    fetch_attempt_id TEXT PRIMARY KEY,
    source_request_id TEXT NOT NULL UNIQUE CHECK(length(trim(source_request_id)) > 0),
    subject_urn TEXT NOT NULL CHECK(length(trim(subject_urn)) > 0),
    paper_id TEXT REFERENCES paper(paper_id) ON DELETE RESTRICT,
    candidate_id TEXT REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    requested_url TEXT NOT NULL CHECK(length(trim(requested_url)) > 0),
    redirect_chain_json TEXT NOT NULL CHECK(json_valid(redirect_chain_json)),
    final_url TEXT,
    http_status INTEGER CHECK(http_status IS NULL OR http_status BETWEEN 100 AND 599),
    response_mime TEXT,
    response_bytes INTEGER CHECK(response_bytes IS NULL OR response_bytes >= 0),
    response_sha256 TEXT CHECK(response_sha256 IS NULL OR (
        length(response_sha256)=64 AND response_sha256 NOT GLOB '*[^0-9a-f]*'
    )),
    request_identity_hash TEXT NOT NULL CHECK(
        length(request_identity_hash)=64 AND request_identity_hash NOT GLOB '*[^0-9a-f]*'
    ),
    rights_status TEXT NOT NULL CHECK(rights_status IN (
        'verified_open_license','repository_distribution_only','public_access_unknown_reuse',
        'not_open_access','license_blocked','unknown'
    )),
    legal_basis TEXT NOT NULL CHECK(length(trim(legal_basis)) > 0),
    result_status TEXT NOT NULL CHECK(result_status IN (
        'succeeded','http_failed','network_failed','license_blocked','invalid_content','not_attempted'
    )),
    error_class TEXT,
    error_detail TEXT,
    attempted_at TEXT NOT NULL CHECK(length(trim(attempted_at)) > 0),
    CHECK(
        (result_status='succeeded' AND final_url IS NOT NULL AND http_status BETWEEN 200 AND 299
         AND response_mime IS NOT NULL AND response_bytes IS NOT NULL AND response_sha256 IS NOT NULL)
        OR result_status<>'succeeded'
    )
) STRICT;

CREATE TABLE paper_resource (
    resource_id TEXT PRIMARY KEY,
    paper_id TEXT REFERENCES paper(paper_id) ON DELETE RESTRICT,
    candidate_id TEXT REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    fetch_attempt_id TEXT NOT NULL UNIQUE REFERENCES fetch_attempt(fetch_attempt_id) ON DELETE RESTRICT,
    resource_kind TEXT NOT NULL CHECK(resource_kind IN ('paper_pdf','supplement','source_archive')),
    media_type TEXT NOT NULL CHECK(length(trim(media_type)) > 0),
    content_sha256 TEXT NOT NULL CHECK(
        length(content_sha256)=64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bytes INTEGER NOT NULL CHECK(bytes >= 0),
    relative_path TEXT NOT NULL UNIQUE CHECK(
        length(trim(relative_path)) > 0
        AND substr(relative_path,1,1) <> '/'
        AND instr(relative_path,'\\') = 0
        AND instr(relative_path,'..') = 0
        AND instr(relative_path,':') = 0
    ),
    rights_status TEXT NOT NULL CHECK(rights_status IN (
        'verified_open_license','repository_distribution_only','public_access_unknown_reuse'
    )),
    verification_status TEXT NOT NULL CHECK(verification_status IN ('verified','quarantined')),
    acquired_at TEXT NOT NULL CHECK(length(trim(acquired_at)) > 0),
    CHECK(paper_id IS NOT NULL OR candidate_id IS NOT NULL)
) STRICT;

CREATE TABLE paper_analysis (
    analysis_id TEXT PRIMARY KEY,
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    analysis_kind TEXT NOT NULL CHECK(analysis_kind IN ('metadata_review','reading_note','method_review')),
    analysis_text TEXT NOT NULL CHECK(length(trim(analysis_text)) > 0),
    fact_status TEXT NOT NULL CHECK(fact_status IN ('source_fact','model_inference','human_reviewed')),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TABLE paper_core_conclusion (
    conclusion_id TEXT PRIMARY KEY,
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    conclusion_text TEXT NOT NULL CHECK(length(trim(conclusion_text)) > 0),
    fact_status TEXT NOT NULL CHECK(fact_status IN ('source_claim','model_inference','human_reviewed')),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TABLE evidence_excerpt (
    excerpt_id TEXT PRIMARY KEY,
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    resource_id TEXT REFERENCES paper_resource(resource_id) ON DELETE RESTRICT,
    excerpt_text TEXT NOT NULL CHECK(length(trim(excerpt_text)) > 0),
    locator_json TEXT NOT NULL CHECK(json_valid(locator_json)),
    excerpt_sha256 TEXT NOT NULL CHECK(
        length(excerpt_sha256)=64 AND excerpt_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TABLE paper_reading_task (
    reading_task_id TEXT PRIMARY KEY,
    paper_id TEXT NOT NULL UNIQUE REFERENCES paper(paper_id) ON DELETE RESTRICT,
    resource_id TEXT NOT NULL UNIQUE REFERENCES paper_resource(resource_id) ON DELETE RESTRICT,
    abstract_excerpt_id TEXT NOT NULL UNIQUE REFERENCES evidence_excerpt(excerpt_id) ON DELETE RESTRICT,
    input_snapshot_hash TEXT NOT NULL CHECK(
        length(input_snapshot_hash)=64 AND input_snapshot_hash NOT GLOB '*[^0-9a-f]*'
    ),
    objective_text TEXT NOT NULL CHECK(length(trim(objective_text)) > 0),
    required_outputs_json TEXT NOT NULL CHECK(json_valid(required_outputs_json)),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TABLE paper_reading_run (
    reading_run_id TEXT PRIMARY KEY,
    reading_task_id TEXT NOT NULL REFERENCES paper_reading_task(reading_task_id) ON DELETE RESTRICT,
    attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
    idempotency_key TEXT NOT NULL UNIQUE CHECK(length(trim(idempotency_key)) > 0),
    worker_kind TEXT NOT NULL CHECK(worker_kind IN ('codex','human','external')),
    input_snapshot_hash TEXT NOT NULL CHECK(
        length(input_snapshot_hash)=64 AND input_snapshot_hash NOT GLOB '*[^0-9a-f]*'
    ),
    result_status TEXT NOT NULL CHECK(result_status IN ('succeeded','failed')),
    analysis_payload_json TEXT CHECK(
        analysis_payload_json IS NULL OR json_valid(analysis_payload_json)
    ),
    failure_json TEXT CHECK(failure_json IS NULL OR json_valid(failure_json)),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    completed_at TEXT NOT NULL CHECK(length(trim(completed_at)) > 0),
    UNIQUE(reading_task_id,attempt_number),
    CHECK(
        (result_status='succeeded' AND analysis_payload_json IS NOT NULL AND failure_json IS NULL)
        OR (result_status='failed' AND analysis_payload_json IS NULL AND failure_json IS NOT NULL)
    )
) STRICT;

CREATE TABLE citation_occurrence (
    citation_id TEXT PRIMARY KEY CHECK(
        length(citation_id)=56 AND substr(citation_id,1,4)='cit_'
        AND substr(citation_id,5) NOT GLOB '*[^a-z2-7]*'
    ),
    document_sha256 TEXT NOT NULL CHECK(
        length(document_sha256)=64 AND document_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    locator_kind TEXT NOT NULL CHECK(locator_kind IN (
        'utf8_bytes','pdf_extracted_page_line','source_locator_claim'
    )),
    locator_json TEXT NOT NULL CHECK(json_valid(locator_json)),
    line_start INTEGER NOT NULL CHECK(line_start >= 1),
    line_end INTEGER NOT NULL CHECK(line_end >= line_start),
    byte_start INTEGER CHECK(byte_start IS NULL OR byte_start >= 0),
    byte_end INTEGER CHECK(byte_end IS NULL OR byte_end > 0),
    raw_marker_text TEXT NOT NULL,
    raw_marker_sha256 TEXT NOT NULL CHECK(
        length(raw_marker_sha256)=64 AND raw_marker_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    context_text TEXT NOT NULL,
    context_sha256 TEXT NOT NULL CHECK(
        length(context_sha256)=64 AND context_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    occurrence_kind TEXT NOT NULL CHECK(occurrence_kind IN (
        'strong_identifier','formal_reference','textual_mention','method_or_resource_name'
    )),
    locator_status TEXT NOT NULL CHECK(locator_status IN (
        'valid','source_only','unresolved'
    )),
    status_reason TEXT NOT NULL CHECK(length(trim(status_reason)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    CHECK(
        (locator_kind='utf8_bytes' AND byte_start IS NOT NULL AND byte_end > byte_start)
        OR (locator_kind<>'utf8_bytes' AND byte_start IS NULL AND byte_end IS NULL)
    )
) STRICT;

CREATE TABLE citation_ledger_entry (
    ledger_entry_id TEXT PRIMARY KEY CHECK(length(trim(ledger_entry_id)) > 0),
    citation_id TEXT NOT NULL REFERENCES citation_occurrence(citation_id) ON DELETE RESTRICT,
    clue_id TEXT REFERENCES paper_clue(clue_id) ON DELETE RESTRICT,
    research_urn TEXT NOT NULL CHECK(length(trim(research_urn)) > 0),
    archive_release_urn TEXT NOT NULL CHECK(length(trim(archive_release_urn)) > 0),
    document_version_urn TEXT NOT NULL CHECK(length(trim(document_version_urn)) > 0),
    source_object_urn TEXT NOT NULL CHECK(length(trim(source_object_urn)) > 0),
    source_path TEXT NOT NULL CHECK(length(trim(source_path)) > 0),
    canonical_path TEXT NOT NULL CHECK(length(trim(canonical_path)) > 0),
    locator_claim TEXT NOT NULL CHECK(length(trim(locator_claim)) > 0),
    occurrence_type TEXT NOT NULL CHECK(length(trim(occurrence_type)) > 0),
    candidate_link_method TEXT NOT NULL CHECK(length(trim(candidate_link_method)) > 0),
    evidence_strength TEXT NOT NULL CHECK(length(trim(evidence_strength)) > 0),
    identifier_claim TEXT NOT NULL,
    entry_status TEXT NOT NULL CHECK(entry_status IN (
        'resolved','source_only','unresolved','conflicted','rejected_non_paper'
    )),
    entry_reason TEXT NOT NULL CHECK(length(trim(entry_reason)) > 0),
    raw_payload_json TEXT NOT NULL CHECK(json_valid(raw_payload_json)),
    imported_at TEXT NOT NULL CHECK(length(trim(imported_at)) > 0)
) STRICT;

CREATE INDEX citation_research_order_idx
ON citation_ledger_entry(research_urn,document_version_urn,ledger_entry_id,clue_id);

CREATE INDEX citation_source_locator_idx
ON citation_occurrence(document_sha256,locator_kind,byte_start,byte_end,raw_marker_sha256);

CREATE TABLE citation_binding (
    binding_id TEXT PRIMARY KEY,
    ledger_entry_id TEXT NOT NULL REFERENCES citation_ledger_entry(ledger_entry_id) ON DELETE RESTRICT,
    paper_id TEXT REFERENCES paper(paper_id) ON DELETE RESTRICT,
    binding_status TEXT NOT NULL CHECK(binding_status IN (
        'resolved','source_only','unresolved','conflicted','rejected_non_paper'
    )),
    rationale TEXT NOT NULL CHECK(length(trim(rationale)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    CHECK((binding_status='resolved' AND paper_id IS NOT NULL) OR
          (binding_status<>'resolved' AND paper_id IS NULL))
) STRICT;

CREATE TABLE citation_binding_event (
    binding_event_id TEXT PRIMARY KEY,
    ledger_entry_id TEXT NOT NULL REFERENCES citation_ledger_entry(ledger_entry_id) ON DELETE RESTRICT,
    binding_id TEXT NOT NULL REFERENCES citation_binding(binding_id) ON DELETE RESTRICT,
    event_kind TEXT NOT NULL CHECK(event_kind IN ('binding_created','binding_revised')),
    supersedes_event_id TEXT REFERENCES citation_binding_event(binding_event_id) ON DELETE RESTRICT,
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    UNIQUE(ledger_entry_id,binding_id)
) STRICT;

CREATE TABLE citation_binding_projection (
    ledger_entry_id TEXT PRIMARY KEY REFERENCES citation_ledger_entry(ledger_entry_id) ON DELETE RESTRICT,
    binding_id TEXT NOT NULL UNIQUE REFERENCES citation_binding(binding_id) ON DELETE RESTRICT,
    source_event_id TEXT NOT NULL UNIQUE REFERENCES citation_binding_event(binding_event_id) ON DELETE RESTRICT,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0)
) STRICT;

CREATE TRIGGER citation_binding_projection_validate_insert
BEFORE INSERT ON citation_binding_projection
WHEN NEW.revision <> 1 OR NOT EXISTS (
    SELECT 1 FROM citation_binding_event
    WHERE binding_event_id=NEW.source_event_id
      AND ledger_entry_id=NEW.ledger_entry_id
      AND binding_id=NEW.binding_id
      AND event_kind='binding_created'
      AND supersedes_event_id IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'citation binding projection requires its creation event');
END;

CREATE TRIGGER citation_binding_projection_validate_update
BEFORE UPDATE ON citation_binding_projection
WHEN NEW.ledger_entry_id <> OLD.ledger_entry_id
  OR NEW.revision <> OLD.revision + 1
  OR NOT EXISTS (
      SELECT 1 FROM citation_binding_event
      WHERE binding_event_id=NEW.source_event_id
        AND ledger_entry_id=NEW.ledger_entry_id
        AND binding_id=NEW.binding_id
        AND event_kind='binding_revised'
        AND supersedes_event_id=OLD.source_event_id
  )
BEGIN
    SELECT RAISE(ABORT, 'citation binding revision requires a matching append-only event');
END;

CREATE TRIGGER citation_binding_projection_no_delete
BEFORE DELETE ON citation_binding_projection
BEGIN
    SELECT RAISE(ABORT, 'citation binding projection cannot be deleted');
END;

CREATE TABLE research_paper_relation (
    relation_id TEXT PRIMARY KEY,
    research_urn TEXT NOT NULL CHECK(length(trim(research_urn)) > 0),
    document_version_urn TEXT NOT NULL CHECK(length(trim(document_version_urn)) > 0),
    ledger_entry_id TEXT NOT NULL REFERENCES citation_ledger_entry(ledger_entry_id) ON DELETE RESTRICT,
    citation_id TEXT NOT NULL REFERENCES citation_occurrence(citation_id) ON DELETE RESTRICT,
    paper_id TEXT NOT NULL REFERENCES paper(paper_id) ON DELETE RESTRICT,
    relation_kind TEXT NOT NULL CHECK(relation_kind IN (
        'formal_reference','supports','contrasts','method_uses','mentions'
    )),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(ledger_entry_id,paper_id,relation_kind)
) STRICT;

CREATE TABLE paper_catalog_projection (
    paper_id TEXT PRIMARY KEY REFERENCES paper(paper_id) ON DELETE RESTRICT,
    title TEXT NOT NULL CHECK(length(trim(title)) > 0),
    publication_date TEXT,
    authors_json TEXT NOT NULL CHECK(json_valid(authors_json)),
    institutions_json TEXT NOT NULL CHECK(json_valid(institutions_json)),
    categories_json TEXT NOT NULL CHECK(json_valid(categories_json)),
    core_conclusions_json TEXT NOT NULL CHECK(json_valid(core_conclusions_json)),
    external_links_json TEXT NOT NULL CHECK(json_valid(external_links_json)),
    local_resources_json TEXT NOT NULL CHECK(json_valid(local_resources_json)),
    verification_status TEXT NOT NULL CHECK(verification_status IN ('verified','conflicted','partial')),
    projection_revision INTEGER NOT NULL CHECK(projection_revision >= 1),
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0)
) STRICT;

CREATE TABLE paper_inventory_export (
    export_id TEXT PRIMARY KEY,
    source_snapshot_hash TEXT NOT NULL CHECK(
        length(source_snapshot_hash)=64 AND source_snapshot_hash NOT GLOB '*[^0-9a-f]*'
    ),
    format_version TEXT NOT NULL CHECK(length(trim(format_version)) > 0),
    content_sha256 TEXT NOT NULL CHECK(
        length(content_sha256)=64 AND content_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bytes INTEGER NOT NULL CHECK(bytes >= 0),
    relative_path TEXT NOT NULL CHECK(
        length(trim(relative_path)) > 0 AND substr(relative_path,1,1) <> '/'
        AND instr(relative_path,'\\')=0 AND instr(relative_path,'..')=0
    ),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(source_snapshot_hash,format_version)
) STRICT;

CREATE TABLE outbox_event (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL CHECK(length(trim(event_type)) > 0),
    event_version TEXT NOT NULL CHECK(length(trim(event_version)) > 0),
    aggregate_urn TEXT NOT NULL CHECK(length(trim(aggregate_urn)) > 0),
    payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
    payload_hash TEXT NOT NULL CHECK(
        length(payload_hash)=64 AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    published_at TEXT,
    publish_attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(publish_attempt_count >= 0)
) STRICT;

CREATE TABLE inbox_receipt (
    consumer_name TEXT NOT NULL CHECK(length(trim(consumer_name)) > 0),
    source_domain TEXT NOT NULL CHECK(length(trim(source_domain)) > 0),
    event_id TEXT NOT NULL CHECK(length(trim(event_id)) > 0),
    processed_at TEXT NOT NULL CHECK(length(trim(processed_at)) > 0),
    result_hash TEXT NOT NULL CHECK(
        length(result_hash)=64 AND result_hash NOT GLOB '*[^0-9a-f]*'
    ),
    PRIMARY KEY(consumer_name,source_domain,event_id)
) STRICT;

CREATE TRIGGER paper_validate_creation_event
BEFORE INSERT ON paper
WHEN NOT EXISTS (
    SELECT 1 FROM paper_identity_event
    WHERE identity_event_id=NEW.creation_event_id
      AND event_kind='paper_created'
      AND to_paper_id=NEW.paper_id
)
BEGIN
    SELECT RAISE(ABORT, 'paper requires a prior matching creation event');
END;

CREATE TRIGGER paper_identity_event_no_update BEFORE UPDATE ON paper_identity_event
BEGIN SELECT RAISE(ABORT, 'paper identity events are append-only'); END;
CREATE TRIGGER paper_identity_event_no_delete BEFORE DELETE ON paper_identity_event
BEGIN SELECT RAISE(ABORT, 'paper identity events are append-only'); END;

CREATE TRIGGER paper_no_update BEFORE UPDATE ON paper
BEGIN SELECT RAISE(ABORT, 'paper identity is immutable'); END;
CREATE TRIGGER paper_no_delete BEFORE DELETE ON paper
BEGIN SELECT RAISE(ABORT, 'paper identity is immutable'); END;

CREATE TRIGGER clue_no_update BEFORE UPDATE ON paper_clue
BEGIN SELECT RAISE(ABORT, 'paper clues are immutable'); END;
CREATE TRIGGER clue_no_delete BEFORE DELETE ON paper_clue
BEGIN SELECT RAISE(ABORT, 'paper clues are immutable'); END;
CREATE TRIGGER candidate_no_update BEFORE UPDATE ON paper_candidate
BEGIN SELECT RAISE(ABORT, 'paper candidates are immutable'); END;
CREATE TRIGGER candidate_no_delete BEFORE DELETE ON paper_candidate
BEGIN SELECT RAISE(ABORT, 'paper candidates are immutable'); END;
CREATE TRIGGER clue_candidate_no_update BEFORE UPDATE ON paper_clue_candidate
BEGIN SELECT RAISE(ABORT, 'clue candidate links are immutable'); END;
CREATE TRIGGER clue_candidate_no_delete BEFORE DELETE ON paper_clue_candidate
BEGIN SELECT RAISE(ABORT, 'clue candidate links are immutable'); END;
CREATE TRIGGER external_identity_candidate_no_update BEFORE UPDATE ON external_identity_candidate
BEGIN SELECT RAISE(ABORT, 'external identity candidates are immutable and never auto-selected'); END;
CREATE TRIGGER external_identity_candidate_no_delete BEFORE DELETE ON external_identity_candidate
BEGIN SELECT RAISE(ABORT, 'external identity candidates are immutable and never auto-selected'); END;
CREATE TRIGGER external_assertion_no_update BEFORE UPDATE ON external_assertion
BEGIN SELECT RAISE(ABORT, 'external assertions are immutable'); END;
CREATE TRIGGER external_assertion_no_delete BEFORE DELETE ON external_assertion
BEGIN SELECT RAISE(ABORT, 'external assertions are immutable'); END;
CREATE TRIGGER import_receipt_no_update BEFORE UPDATE ON evidence_import_receipt
BEGIN SELECT RAISE(ABORT, 'evidence import receipts are immutable'); END;
CREATE TRIGGER import_receipt_no_delete BEFORE DELETE ON evidence_import_receipt
BEGIN SELECT RAISE(ABORT, 'evidence import receipts are immutable'); END;
CREATE TRIGGER metadata_assertion_no_update BEFORE UPDATE ON metadata_assertion
BEGIN SELECT RAISE(ABORT, 'metadata assertions are immutable'); END;
CREATE TRIGGER metadata_assertion_no_delete BEFORE DELETE ON metadata_assertion
BEGIN SELECT RAISE(ABORT, 'metadata assertions are immutable'); END;
CREATE TRIGGER identifier_assertion_no_update BEFORE UPDATE ON paper_identifier_assertion
BEGIN SELECT RAISE(ABORT, 'identifier assertions are immutable'); END;
CREATE TRIGGER identifier_assertion_no_delete BEFORE DELETE ON paper_identifier_assertion
BEGIN SELECT RAISE(ABORT, 'identifier assertions are immutable'); END;
CREATE TRIGGER metadata_selection_no_update BEFORE UPDATE ON canonical_metadata_selection
BEGIN SELECT RAISE(ABORT, 'canonical metadata selections are append-only'); END;
CREATE TRIGGER metadata_selection_no_delete BEFORE DELETE ON canonical_metadata_selection
BEGIN SELECT RAISE(ABORT, 'canonical metadata selections are append-only'); END;
CREATE TRIGGER fetch_attempt_no_update BEFORE UPDATE ON fetch_attempt
BEGIN SELECT RAISE(ABORT, 'fetch attempts are append-only'); END;
CREATE TRIGGER fetch_attempt_no_delete BEFORE DELETE ON fetch_attempt
BEGIN SELECT RAISE(ABORT, 'fetch attempts are append-only'); END;
CREATE TRIGGER resource_no_update BEFORE UPDATE ON paper_resource
BEGIN SELECT RAISE(ABORT, 'paper resources are immutable'); END;
CREATE TRIGGER resource_no_delete BEFORE DELETE ON paper_resource
BEGIN SELECT RAISE(ABORT, 'paper resources are immutable'); END;
CREATE TRIGGER analysis_no_update BEFORE UPDATE ON paper_analysis
BEGIN SELECT RAISE(ABORT, 'paper analyses are immutable'); END;
CREATE TRIGGER analysis_no_delete BEFORE DELETE ON paper_analysis
BEGIN SELECT RAISE(ABORT, 'paper analyses are immutable'); END;
CREATE TRIGGER conclusion_no_update BEFORE UPDATE ON paper_core_conclusion
BEGIN SELECT RAISE(ABORT, 'paper conclusions are immutable'); END;
CREATE TRIGGER conclusion_no_delete BEFORE DELETE ON paper_core_conclusion
BEGIN SELECT RAISE(ABORT, 'paper conclusions are immutable'); END;
CREATE TRIGGER excerpt_no_update BEFORE UPDATE ON evidence_excerpt
BEGIN SELECT RAISE(ABORT, 'evidence excerpts are immutable'); END;
CREATE TRIGGER excerpt_no_delete BEFORE DELETE ON evidence_excerpt
BEGIN SELECT RAISE(ABORT, 'evidence excerpts are immutable'); END;
CREATE TRIGGER reading_task_no_update BEFORE UPDATE ON paper_reading_task
BEGIN SELECT RAISE(ABORT, 'paper reading tasks are immutable'); END;
CREATE TRIGGER reading_task_no_delete BEFORE DELETE ON paper_reading_task
BEGIN SELECT RAISE(ABORT, 'paper reading tasks are immutable'); END;
CREATE TRIGGER reading_run_no_update BEFORE UPDATE ON paper_reading_run
BEGIN SELECT RAISE(ABORT, 'paper reading runs are append-only'); END;
CREATE TRIGGER reading_run_no_delete BEFORE DELETE ON paper_reading_run
BEGIN SELECT RAISE(ABORT, 'paper reading runs are append-only'); END;
CREATE TRIGGER citation_no_update BEFORE UPDATE ON citation_occurrence
BEGIN SELECT RAISE(ABORT, 'citation occurrences are immutable'); END;
CREATE TRIGGER citation_no_delete BEFORE DELETE ON citation_occurrence
BEGIN SELECT RAISE(ABORT, 'citation occurrences are immutable'); END;
CREATE TRIGGER citation_ledger_entry_no_update BEFORE UPDATE ON citation_ledger_entry
BEGIN SELECT RAISE(ABORT, 'citation ledger entries are immutable'); END;
CREATE TRIGGER citation_ledger_entry_no_delete BEFORE DELETE ON citation_ledger_entry
BEGIN SELECT RAISE(ABORT, 'citation ledger entries are immutable'); END;
CREATE TRIGGER binding_no_update BEFORE UPDATE ON citation_binding
BEGIN SELECT RAISE(ABORT, 'citation bindings are immutable'); END;
CREATE TRIGGER binding_no_delete BEFORE DELETE ON citation_binding
BEGIN SELECT RAISE(ABORT, 'citation bindings are immutable'); END;
CREATE TRIGGER binding_event_no_update BEFORE UPDATE ON citation_binding_event
BEGIN SELECT RAISE(ABORT, 'citation binding events are append-only'); END;
CREATE TRIGGER binding_event_no_delete BEFORE DELETE ON citation_binding_event
BEGIN SELECT RAISE(ABORT, 'citation binding events are append-only'); END;
CREATE TRIGGER relation_no_update BEFORE UPDATE ON research_paper_relation
BEGIN SELECT RAISE(ABORT, 'research paper relations are immutable'); END;
CREATE TRIGGER relation_no_delete BEFORE DELETE ON research_paper_relation
BEGIN SELECT RAISE(ABORT, 'research paper relations are immutable'); END;
CREATE TRIGGER export_no_update BEFORE UPDATE ON paper_inventory_export
BEGIN SELECT RAISE(ABORT, 'inventory exports are immutable'); END;
CREATE TRIGGER export_no_delete BEFORE DELETE ON paper_inventory_export
BEGIN SELECT RAISE(ABORT, 'inventory exports are immutable'); END;
CREATE TRIGGER inbox_no_update BEFORE UPDATE ON inbox_receipt
BEGIN SELECT RAISE(ABORT, 'inbox receipts are immutable'); END;
CREATE TRIGGER inbox_no_delete BEFORE DELETE ON inbox_receipt
BEGIN SELECT RAISE(ABORT, 'inbox receipts are immutable'); END;

CREATE TRIGGER outbox_payload_immutable
BEFORE UPDATE ON outbox_event
WHEN NEW.event_id<>OLD.event_id OR NEW.event_type<>OLD.event_type
  OR NEW.event_version<>OLD.event_version OR NEW.aggregate_urn<>OLD.aggregate_urn
  OR NEW.payload_json<>OLD.payload_json OR NEW.payload_hash<>OLD.payload_hash
  OR NEW.created_at<>OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'outbox event payload is immutable');
END;

CREATE TRIGGER outbox_no_delete BEFORE DELETE ON outbox_event
BEGIN SELECT RAISE(ABORT, 'outbox events cannot be deleted'); END;
