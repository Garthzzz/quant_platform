CREATE TABLE evidence_resolution_case (
    resolution_case_id TEXT PRIMARY KEY,
    candidate_id TEXT NOT NULL REFERENCES paper_candidate(candidate_id) ON DELETE RESTRICT,
    input_snapshot_hash TEXT NOT NULL CHECK(
        length(input_snapshot_hash)=64 AND input_snapshot_hash NOT GLOB '*[^0-9a-f]*'
    ),
    input_claim_json TEXT NOT NULL CHECK(
        json_valid(input_claim_json) AND json_type(input_claim_json)='object'
    ),
    policy_version TEXT NOT NULL CHECK(length(trim(policy_version)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(candidate_id,input_snapshot_hash)
) STRICT;

CREATE TABLE evidence_resolution_event (
    resolution_event_id TEXT PRIMARY KEY,
    resolution_case_id TEXT NOT NULL
        REFERENCES evidence_resolution_case(resolution_case_id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL CHECK(length(trim(idempotency_key)) > 0),
    event_kind TEXT NOT NULL CHECK(event_kind IN (
        'case_opened','resolution_started','provider_cycle_completed',
        'provider_cycle_failed','retry_scheduled','identity_decided','resolution_blocked'
    )),
    from_state TEXT CHECK(from_state IS NULL OR from_state IN (
        'queued','resolving','awaiting_review','identifier_verified',
        'unresolved','conflicted','retryable_error','blocked'
    )),
    to_state TEXT NOT NULL CHECK(to_state IN (
        'queued','resolving','awaiting_review','identifier_verified',
        'unresolved','conflicted','retryable_error','blocked'
    )),
    reason_code TEXT NOT NULL CHECK(length(trim(reason_code)) > 0),
    reason_detail TEXT NOT NULL CHECK(length(trim(reason_detail)) > 0),
    evidence_refs_json TEXT NOT NULL CHECK(
        json_valid(evidence_refs_json) AND json_type(evidence_refs_json)='array'
    ),
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    UNIQUE(resolution_case_id,idempotency_key)
) STRICT;

CREATE TRIGGER evidence_resolution_event_transition_guard
BEFORE INSERT ON evidence_resolution_event
WHEN NOT (
    (NEW.from_state IS NULL AND NEW.to_state='queued' AND NEW.event_kind='case_opened')
    OR (NEW.from_state='queued' AND NEW.to_state='resolving'
        AND NEW.event_kind='resolution_started')
    OR (NEW.from_state='queued' AND NEW.to_state='blocked'
        AND NEW.event_kind='resolution_blocked')
    OR (NEW.from_state='resolving'
        AND NEW.to_state IN ('awaiting_review','unresolved','conflicted')
        AND NEW.event_kind='provider_cycle_completed')
    OR (NEW.from_state='resolving' AND NEW.to_state='retryable_error'
        AND NEW.event_kind='provider_cycle_failed')
    OR (NEW.from_state='resolving' AND NEW.to_state='blocked'
        AND NEW.event_kind='resolution_blocked')
    OR (NEW.from_state='retryable_error' AND NEW.to_state='resolving'
        AND NEW.event_kind='retry_scheduled')
    OR (NEW.from_state='retryable_error' AND NEW.to_state='blocked'
        AND NEW.event_kind='resolution_blocked')
    OR (NEW.from_state='awaiting_review'
        AND NEW.to_state IN ('identifier_verified','unresolved','conflicted','blocked')
        AND NEW.event_kind='identity_decided')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid evidence resolution state transition');
END;

CREATE TABLE evidence_resolution_state (
    resolution_case_id TEXT PRIMARY KEY
        REFERENCES evidence_resolution_case(resolution_case_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN (
        'queued','resolving','awaiting_review','identifier_verified',
        'unresolved','conflicted','retryable_error','blocked'
    )),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    source_event_id TEXT NOT NULL UNIQUE
        REFERENCES evidence_resolution_event(resolution_event_id) ON DELETE RESTRICT,
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0)
) STRICT;

CREATE TRIGGER evidence_resolution_state_validate_insert
BEFORE INSERT ON evidence_resolution_state
WHEN NEW.revision<>1 OR NOT EXISTS (
    SELECT 1 FROM evidence_resolution_event
    WHERE resolution_event_id=NEW.source_event_id
      AND resolution_case_id=NEW.resolution_case_id
      AND from_state IS NULL
      AND to_state=NEW.state
      AND event_kind='case_opened'
)
BEGIN
    SELECT RAISE(ABORT, 'resolution state requires its case-opened event');
END;

CREATE TRIGGER evidence_resolution_state_validate_update
BEFORE UPDATE ON evidence_resolution_state
WHEN NEW.resolution_case_id<>OLD.resolution_case_id
  OR NEW.revision<>OLD.revision+1
  OR NOT EXISTS (
      SELECT 1 FROM evidence_resolution_event
      WHERE resolution_event_id=NEW.source_event_id
        AND resolution_case_id=NEW.resolution_case_id
        AND from_state=OLD.state
        AND to_state=NEW.state
  )
BEGIN
    SELECT RAISE(ABORT, 'resolution state update requires the next matching event');
END;

CREATE TRIGGER evidence_resolution_state_no_delete
BEFORE DELETE ON evidence_resolution_state
BEGIN SELECT RAISE(ABORT, 'resolution state cannot be deleted'); END;

CREATE TABLE evidence_provider_request (
    provider_request_id TEXT PRIMARY KEY,
    resolution_case_id TEXT NOT NULL
        REFERENCES evidence_resolution_case(resolution_case_id) ON DELETE RESTRICT,
    provider TEXT NOT NULL CHECK(provider IN ('crossref','arxiv')),
    operation TEXT NOT NULL CHECK(operation IN ('identifier_lookup','metadata_search')),
    request_method TEXT NOT NULL CHECK(request_method='GET'),
    request_url TEXT NOT NULL CHECK(
        request_url LIKE 'https://%' AND length(request_url) <= 4000
    ),
    request_headers_json TEXT NOT NULL CHECK(
        json_valid(request_headers_json) AND json_type(request_headers_json)='object'
    ),
    query_context_json TEXT NOT NULL CHECK(
        json_valid(query_context_json) AND json_type(query_context_json)='object'
    ),
    request_fingerprint TEXT NOT NULL CHECK(
        length(request_fingerprint)=64 AND request_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(resolution_case_id,request_fingerprint)
) STRICT;

CREATE INDEX evidence_provider_request_case_idx
ON evidence_provider_request(resolution_case_id,provider,operation);

CREATE TABLE evidence_provider_attempt (
    provider_attempt_id TEXT PRIMARY KEY,
    provider_request_id TEXT NOT NULL
        REFERENCES evidence_provider_request(provider_request_id) ON DELETE RESTRICT,
    attempt_number INTEGER NOT NULL CHECK(attempt_number >= 1),
    idempotency_key TEXT NOT NULL CHECK(length(trim(idempotency_key)) > 0),
    result_status TEXT NOT NULL CHECK(result_status IN (
        'succeeded','http_failed','network_failed','invalid_response','not_attempted'
    )),
    final_url TEXT CHECK(final_url IS NULL OR final_url LIKE 'https://%'),
    redirect_chain_json TEXT NOT NULL CHECK(
        json_valid(redirect_chain_json) AND json_type(redirect_chain_json)='array'
    ),
    http_status INTEGER CHECK(http_status IS NULL OR http_status BETWEEN 100 AND 599),
    response_mime TEXT,
    response_bytes INTEGER CHECK(response_bytes IS NULL OR response_bytes >= 0),
    response_sha256 TEXT CHECK(response_sha256 IS NULL OR (
        length(response_sha256)=64 AND response_sha256 NOT GLOB '*[^0-9a-f]*'
    )),
    response_headers_json TEXT NOT NULL CHECK(
        json_valid(response_headers_json) AND json_type(response_headers_json)='object'
    ),
    request_identity_hash TEXT NOT NULL CHECK(
        length(request_identity_hash)=64 AND request_identity_hash NOT GLOB '*[^0-9a-f]*'
    ),
    error_class TEXT,
    error_detail TEXT,
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    completed_at TEXT NOT NULL CHECK(length(trim(completed_at)) > 0),
    UNIQUE(provider_request_id,attempt_number),
    UNIQUE(provider_request_id,idempotency_key),
    CHECK(
        (result_status='succeeded' AND http_status BETWEEN 200 AND 299
         AND final_url IS NOT NULL AND response_mime IS NOT NULL
         AND response_bytes IS NOT NULL AND response_sha256 IS NOT NULL)
        OR result_status<>'succeeded'
    )
) STRICT;

CREATE TABLE evidence_provider_observation (
    provider_observation_id TEXT PRIMARY KEY,
    provider_attempt_id TEXT NOT NULL
        REFERENCES evidence_provider_attempt(provider_attempt_id) ON DELETE RESTRICT,
    provider TEXT NOT NULL CHECK(provider IN ('crossref','arxiv')),
    provider_record_id TEXT NOT NULL CHECK(length(trim(provider_record_id)) > 0),
    provider_rank INTEGER NOT NULL CHECK(provider_rank >= 1),
    provider_score REAL,
    record_json TEXT NOT NULL CHECK(
        json_valid(record_json) AND json_type(record_json)='object'
    ),
    record_sha256 TEXT NOT NULL CHECK(
        length(record_sha256)=64 AND record_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    metadata_json TEXT NOT NULL CHECK(
        json_valid(metadata_json) AND json_type(metadata_json)='object'
    ),
    normalized_identifiers_json TEXT NOT NULL CHECK(
        json_valid(normalized_identifiers_json)
        AND json_type(normalized_identifiers_json)='array'
    ),
    match_basis TEXT NOT NULL CHECK(match_basis IN (
        'source_identifier_exact','metadata_candidate_only','identifier_mismatch'
    )),
    identity_effect TEXT NOT NULL CHECK(identity_effect IN (
        'strong_identifier_verified','review_required','conflicted','none'
    )),
    canonicalization_status TEXT NOT NULL
        CHECK(canonicalization_status='not_canonicalized'),
    rationale TEXT NOT NULL CHECK(length(trim(rationale)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    observed_at TEXT NOT NULL CHECK(length(trim(observed_at)) > 0),
    UNIQUE(provider_attempt_id,provider_record_id,provider_rank),
    CHECK(
        (match_basis='source_identifier_exact'
         AND identity_effect='strong_identifier_verified')
        OR (match_basis='metadata_candidate_only'
            AND identity_effect='review_required')
        OR (match_basis='identifier_mismatch'
            AND identity_effect='conflicted')
    )
) STRICT;

CREATE TRIGGER evidence_provider_observation_provider_guard
BEFORE INSERT ON evidence_provider_observation
WHEN NOT EXISTS (
    SELECT 1
    FROM evidence_provider_attempt AS attempt
    JOIN evidence_provider_request AS request USING(provider_request_id)
    WHERE attempt.provider_attempt_id=NEW.provider_attempt_id
      AND attempt.result_status='succeeded'
      AND request.provider=NEW.provider
)
BEGIN
    SELECT RAISE(ABORT, 'provider observation requires a successful matching request');
END;

CREATE TABLE evidence_resource_offer (
    resource_offer_id TEXT PRIMARY KEY,
    provider_observation_id TEXT NOT NULL
        REFERENCES evidence_provider_observation(provider_observation_id) ON DELETE RESTRICT,
    provider TEXT NOT NULL CHECK(provider IN ('crossref','arxiv')),
    resource_kind TEXT NOT NULL CHECK(resource_kind IN (
        'paper_pdf','supplement','source_archive'
    )),
    source_kind TEXT NOT NULL CHECK(source_kind IN (
        'official_repository','publisher_link','registry_link'
    )),
    url TEXT NOT NULL CHECK(url LIKE 'https://%' AND length(url) <= 4000),
    media_type TEXT NOT NULL CHECK(length(trim(media_type)) > 0),
    rights_hint TEXT NOT NULL CHECK(rights_hint IN (
        'verified_open_license','repository_distribution_only',
        'public_access_unknown_reuse','not_open_access','license_blocked','unknown'
    )),
    license_evidence_json TEXT NOT NULL CHECK(
        json_valid(license_evidence_json) AND json_type(license_evidence_json)='object'
    ),
    canonicalization_effect TEXT NOT NULL CHECK(canonicalization_effect='none'),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    observed_at TEXT NOT NULL CHECK(length(trim(observed_at)) > 0),
    UNIQUE(provider_observation_id,resource_kind,url)
) STRICT;

CREATE TABLE evidence_identity_decision (
    identity_decision_id TEXT PRIMARY KEY,
    resolution_case_id TEXT NOT NULL
        REFERENCES evidence_resolution_case(resolution_case_id) ON DELETE RESTRICT,
    provider_observation_id TEXT
        REFERENCES evidence_provider_observation(provider_observation_id) ON DELETE RESTRICT,
    decision_kind TEXT NOT NULL CHECK(decision_kind IN (
        'accept_verified_identifier','mark_unresolved','mark_conflicted','block'
    )),
    identifier_scheme TEXT CHECK(identifier_scheme IS NULL OR identifier_scheme IN (
        'doi','arxiv','pmid','pmcid','report','isbn','url'
    )),
    normalized_identifier TEXT,
    authority_kind TEXT NOT NULL CHECK(authority_kind IN (
        'deterministic_strong_identifier_policy','human_review'
    )),
    policy_version TEXT NOT NULL CHECK(length(trim(policy_version)) > 0),
    rationale TEXT NOT NULL CHECK(length(trim(rationale)) > 0),
    evidence_refs_json TEXT NOT NULL CHECK(
        json_valid(evidence_refs_json) AND json_type(evidence_refs_json)='array'
    ),
    canonicalization_effect TEXT NOT NULL CHECK(canonicalization_effect='none'),
    idempotency_key TEXT NOT NULL CHECK(length(trim(idempotency_key)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    decided_at TEXT NOT NULL CHECK(length(trim(decided_at)) > 0),
    UNIQUE(resolution_case_id,idempotency_key),
    CHECK(
        (decision_kind='accept_verified_identifier'
         AND provider_observation_id IS NOT NULL
         AND identifier_scheme IS NOT NULL
         AND normalized_identifier IS NOT NULL
         AND length(trim(normalized_identifier)) > 0)
        OR
        (decision_kind<>'accept_verified_identifier'
         AND identifier_scheme IS NULL AND normalized_identifier IS NULL)
    )
) STRICT;

CREATE TRIGGER evidence_identity_decision_case_guard
BEFORE INSERT ON evidence_identity_decision
WHEN NEW.provider_observation_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM evidence_provider_observation AS observation
    JOIN evidence_provider_attempt AS attempt USING(provider_attempt_id)
    JOIN evidence_provider_request AS request USING(provider_request_id)
    WHERE observation.provider_observation_id=NEW.provider_observation_id
      AND request.resolution_case_id=NEW.resolution_case_id
)
BEGIN
    SELECT RAISE(ABORT, 'identity decision observation belongs to another resolution case');
END;

CREATE TABLE evidence_rights_assessment (
    rights_assessment_id TEXT PRIMARY KEY,
    resource_offer_id TEXT NOT NULL
        REFERENCES evidence_resource_offer(resource_offer_id) ON DELETE RESTRICT,
    decision TEXT NOT NULL CHECK(decision IN (
        'approved_for_local_storage','metadata_only','review_required','blocked'
    )),
    rights_status TEXT NOT NULL CHECK(rights_status IN (
        'verified_open_license','repository_distribution_only',
        'public_access_unknown_reuse','not_open_access','license_blocked','unknown'
    )),
    authority_kind TEXT NOT NULL CHECK(authority_kind IN (
        'deterministic_rights_policy','human_review'
    )),
    policy_version TEXT NOT NULL CHECK(length(trim(policy_version)) > 0),
    legal_basis TEXT NOT NULL CHECK(length(trim(legal_basis)) > 0),
    evidence_json TEXT NOT NULL CHECK(
        json_valid(evidence_json) AND json_type(evidence_json)='object'
    ),
    supersedes_assessment_id TEXT
        REFERENCES evidence_rights_assessment(rights_assessment_id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL CHECK(length(trim(idempotency_key)) > 0),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    assessed_at TEXT NOT NULL CHECK(length(trim(assessed_at)) > 0),
    UNIQUE(resource_offer_id,idempotency_key),
    CHECK(
        decision<>'approved_for_local_storage'
        OR rights_status IN ('verified_open_license','repository_distribution_only')
    )
) STRICT;

CREATE TRIGGER evidence_rights_assessment_supersedes_guard
BEFORE INSERT ON evidence_rights_assessment
WHEN NEW.supersedes_assessment_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM evidence_rights_assessment AS superseded
    WHERE superseded.rights_assessment_id=NEW.supersedes_assessment_id
      AND superseded.resource_offer_id=NEW.resource_offer_id
)
BEGIN
    SELECT RAISE(ABORT, 'rights reassessment must supersede the same resource offer');
END;

CREATE TABLE evidence_acquisition_case (
    acquisition_case_id TEXT PRIMARY KEY,
    resource_offer_id TEXT NOT NULL
        REFERENCES evidence_resource_offer(resource_offer_id) ON DELETE RESTRICT,
    rights_assessment_id TEXT NOT NULL UNIQUE
        REFERENCES evidence_rights_assessment(rights_assessment_id) ON DELETE RESTRICT,
    input_snapshot_hash TEXT NOT NULL CHECK(
        length(input_snapshot_hash)=64 AND input_snapshot_hash NOT GLOB '*[^0-9a-f]*'
    ),
    provenance_urn TEXT NOT NULL CHECK(length(trim(provenance_urn)) > 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(resource_offer_id,input_snapshot_hash)
) STRICT;

CREATE TRIGGER evidence_acquisition_case_rights_guard
BEFORE INSERT ON evidence_acquisition_case
WHEN NOT EXISTS (
    SELECT 1 FROM evidence_rights_assessment
    WHERE rights_assessment_id=NEW.rights_assessment_id
      AND resource_offer_id=NEW.resource_offer_id
)
BEGIN
    SELECT RAISE(ABORT, 'acquisition case requires an assessment of its resource offer');
END;

CREATE TABLE evidence_acquisition_event (
    acquisition_event_id TEXT PRIMARY KEY,
    acquisition_case_id TEXT NOT NULL
        REFERENCES evidence_acquisition_case(acquisition_case_id) ON DELETE RESTRICT,
    idempotency_key TEXT NOT NULL CHECK(length(trim(idempotency_key)) > 0),
    event_kind TEXT NOT NULL CHECK(event_kind IN (
        'case_opened','fetch_started','fetch_retried','fetch_succeeded',
        'fetch_failed_retryable','fetch_invalid_content','fetch_blocked'
    )),
    from_state TEXT CHECK(from_state IS NULL OR from_state IN (
        'rights_review','ready','fetching','acquired','retryable_error',
        'invalid_content','blocked'
    )),
    to_state TEXT NOT NULL CHECK(to_state IN (
        'rights_review','ready','fetching','acquired','retryable_error',
        'invalid_content','blocked'
    )),
    fetch_attempt_id TEXT REFERENCES fetch_attempt(fetch_attempt_id) ON DELETE RESTRICT,
    resource_id TEXT REFERENCES paper_resource(resource_id) ON DELETE RESTRICT,
    reason_code TEXT NOT NULL CHECK(length(trim(reason_code)) > 0),
    reason_detail TEXT NOT NULL CHECK(length(trim(reason_detail)) > 0),
    evidence_refs_json TEXT NOT NULL CHECK(
        json_valid(evidence_refs_json) AND json_type(evidence_refs_json)='array'
    ),
    occurred_at TEXT NOT NULL CHECK(length(trim(occurred_at)) > 0),
    UNIQUE(acquisition_case_id,idempotency_key),
    CHECK(
        (event_kind='fetch_succeeded' AND fetch_attempt_id IS NOT NULL AND resource_id IS NOT NULL)
        OR (event_kind<>'fetch_succeeded' AND resource_id IS NULL)
    )
) STRICT;

CREATE TRIGGER evidence_acquisition_event_transition_guard
BEFORE INSERT ON evidence_acquisition_event
WHEN NOT (
    (NEW.from_state IS NULL
     AND NEW.to_state IN ('rights_review','ready','blocked')
     AND NEW.event_kind='case_opened')
    OR (NEW.from_state='ready' AND NEW.to_state='fetching'
        AND NEW.event_kind='fetch_started')
    OR (NEW.from_state='fetching' AND NEW.to_state='acquired'
        AND NEW.event_kind='fetch_succeeded')
    OR (NEW.from_state='fetching' AND NEW.to_state='retryable_error'
        AND NEW.event_kind='fetch_failed_retryable')
    OR (NEW.from_state='fetching' AND NEW.to_state='invalid_content'
        AND NEW.event_kind='fetch_invalid_content')
    OR (NEW.from_state='fetching' AND NEW.to_state='blocked'
        AND NEW.event_kind='fetch_blocked')
    OR (NEW.from_state='retryable_error' AND NEW.to_state='fetching'
        AND NEW.event_kind='fetch_retried')
    OR (NEW.from_state='retryable_error' AND NEW.to_state='blocked'
        AND NEW.event_kind='fetch_blocked')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid evidence acquisition state transition');
END;

CREATE TRIGGER evidence_acquisition_open_rights_guard
BEFORE INSERT ON evidence_acquisition_event
WHEN NEW.event_kind='case_opened' AND NOT EXISTS (
    SELECT 1
    FROM evidence_acquisition_case AS acquisition
    JOIN evidence_rights_assessment AS rights
      ON rights.rights_assessment_id=acquisition.rights_assessment_id
    WHERE acquisition.acquisition_case_id=NEW.acquisition_case_id
      AND (
        (rights.decision='approved_for_local_storage' AND NEW.to_state='ready')
        OR (rights.decision='review_required' AND NEW.to_state='rights_review')
        OR (rights.decision IN ('metadata_only','blocked') AND NEW.to_state='blocked')
      )
)
BEGIN
    SELECT RAISE(ABORT, 'acquisition initial state must reflect its rights decision');
END;

CREATE TRIGGER evidence_acquisition_fetch_subject_guard
BEFORE INSERT ON evidence_acquisition_event
WHEN NEW.fetch_attempt_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM evidence_acquisition_case AS acquisition
    JOIN evidence_resource_offer AS offer USING(resource_offer_id)
    JOIN evidence_provider_observation AS observation USING(provider_observation_id)
    JOIN evidence_provider_attempt AS provider_attempt USING(provider_attempt_id)
    JOIN evidence_provider_request AS provider_request USING(provider_request_id)
    JOIN evidence_resolution_case AS resolution
      ON resolution.resolution_case_id=provider_request.resolution_case_id
    JOIN evidence_rights_assessment AS rights
      ON rights.rights_assessment_id=acquisition.rights_assessment_id
    JOIN fetch_attempt AS fetch ON fetch.fetch_attempt_id=NEW.fetch_attempt_id
    WHERE acquisition.acquisition_case_id=NEW.acquisition_case_id
      AND fetch.candidate_id=resolution.candidate_id
      AND fetch.requested_url=offer.url
      AND fetch.rights_status=rights.rights_status
)
BEGIN
    SELECT RAISE(ABORT, 'acquisition fetch attempt belongs to another candidate');
END;

CREATE TRIGGER evidence_acquisition_success_material_guard
BEFORE INSERT ON evidence_acquisition_event
WHEN NEW.event_kind='fetch_succeeded' AND NOT EXISTS (
    SELECT 1
    FROM paper_resource AS resource
    JOIN fetch_attempt AS fetch USING(fetch_attempt_id)
    WHERE resource.resource_id=NEW.resource_id
      AND resource.fetch_attempt_id=NEW.fetch_attempt_id
      AND resource.verification_status='verified'
      AND fetch.result_status='succeeded'
)
BEGIN
    SELECT RAISE(ABORT, 'acquisition success requires a verified resource and fetch audit');
END;

CREATE TRIGGER evidence_acquisition_failure_material_guard
BEFORE INSERT ON evidence_acquisition_event
WHEN NEW.event_kind IN ('fetch_failed_retryable','fetch_invalid_content') AND NOT EXISTS (
    SELECT 1 FROM fetch_attempt
    WHERE fetch_attempt_id=NEW.fetch_attempt_id
      AND (
        (NEW.event_kind='fetch_failed_retryable'
         AND result_status IN ('http_failed','network_failed'))
        OR (NEW.event_kind='fetch_invalid_content' AND result_status='invalid_content')
      )
)
BEGIN
    SELECT RAISE(ABORT, 'acquisition failure state must match its fetch audit');
END;

CREATE TABLE evidence_acquisition_state (
    acquisition_case_id TEXT PRIMARY KEY
        REFERENCES evidence_acquisition_case(acquisition_case_id) ON DELETE RESTRICT,
    state TEXT NOT NULL CHECK(state IN (
        'rights_review','ready','fetching','acquired','retryable_error',
        'invalid_content','blocked'
    )),
    revision INTEGER NOT NULL CHECK(revision >= 1),
    source_event_id TEXT NOT NULL UNIQUE
        REFERENCES evidence_acquisition_event(acquisition_event_id) ON DELETE RESTRICT,
    updated_at TEXT NOT NULL CHECK(length(trim(updated_at)) > 0)
) STRICT;

CREATE TRIGGER evidence_acquisition_state_validate_insert
BEFORE INSERT ON evidence_acquisition_state
WHEN NEW.revision<>1 OR NOT EXISTS (
    SELECT 1 FROM evidence_acquisition_event
    WHERE acquisition_event_id=NEW.source_event_id
      AND acquisition_case_id=NEW.acquisition_case_id
      AND from_state IS NULL
      AND to_state=NEW.state
      AND event_kind='case_opened'
)
BEGIN
    SELECT RAISE(ABORT, 'acquisition state requires its case-opened event');
END;

CREATE TRIGGER evidence_acquisition_state_validate_update
BEFORE UPDATE ON evidence_acquisition_state
WHEN NEW.acquisition_case_id<>OLD.acquisition_case_id
  OR NEW.revision<>OLD.revision+1
  OR NOT EXISTS (
      SELECT 1 FROM evidence_acquisition_event
      WHERE acquisition_event_id=NEW.source_event_id
        AND acquisition_case_id=NEW.acquisition_case_id
        AND from_state=OLD.state
        AND to_state=NEW.state
  )
BEGIN
    SELECT RAISE(ABORT, 'acquisition state update requires the next matching event');
END;

CREATE TRIGGER evidence_acquisition_state_no_delete
BEFORE DELETE ON evidence_acquisition_state
BEGIN SELECT RAISE(ABORT, 'acquisition state cannot be deleted'); END;

CREATE TRIGGER evidence_resolution_case_no_update BEFORE UPDATE ON evidence_resolution_case
BEGIN SELECT RAISE(ABORT, 'resolution cases are immutable'); END;
CREATE TRIGGER evidence_resolution_case_no_delete BEFORE DELETE ON evidence_resolution_case
BEGIN SELECT RAISE(ABORT, 'resolution cases are immutable'); END;
CREATE TRIGGER evidence_resolution_event_no_update BEFORE UPDATE ON evidence_resolution_event
BEGIN SELECT RAISE(ABORT, 'resolution events are append-only'); END;
CREATE TRIGGER evidence_resolution_event_no_delete BEFORE DELETE ON evidence_resolution_event
BEGIN SELECT RAISE(ABORT, 'resolution events are append-only'); END;
CREATE TRIGGER evidence_provider_request_no_update BEFORE UPDATE ON evidence_provider_request
BEGIN SELECT RAISE(ABORT, 'provider requests are immutable'); END;
CREATE TRIGGER evidence_provider_request_no_delete BEFORE DELETE ON evidence_provider_request
BEGIN SELECT RAISE(ABORT, 'provider requests are immutable'); END;
CREATE TRIGGER evidence_provider_attempt_no_update BEFORE UPDATE ON evidence_provider_attempt
BEGIN SELECT RAISE(ABORT, 'provider attempts are append-only'); END;
CREATE TRIGGER evidence_provider_attempt_no_delete BEFORE DELETE ON evidence_provider_attempt
BEGIN SELECT RAISE(ABORT, 'provider attempts are append-only'); END;
CREATE TRIGGER evidence_provider_observation_no_update BEFORE UPDATE ON evidence_provider_observation
BEGIN SELECT RAISE(ABORT, 'provider observations are immutable and never auto-selected'); END;
CREATE TRIGGER evidence_provider_observation_no_delete BEFORE DELETE ON evidence_provider_observation
BEGIN SELECT RAISE(ABORT, 'provider observations are immutable and never auto-selected'); END;
CREATE TRIGGER evidence_resource_offer_no_update BEFORE UPDATE ON evidence_resource_offer
BEGIN SELECT RAISE(ABORT, 'resource offers are immutable'); END;
CREATE TRIGGER evidence_resource_offer_no_delete BEFORE DELETE ON evidence_resource_offer
BEGIN SELECT RAISE(ABORT, 'resource offers are immutable'); END;
CREATE TRIGGER evidence_identity_decision_no_update BEFORE UPDATE ON evidence_identity_decision
BEGIN SELECT RAISE(ABORT, 'identity decisions are append-only'); END;
CREATE TRIGGER evidence_identity_decision_no_delete BEFORE DELETE ON evidence_identity_decision
BEGIN SELECT RAISE(ABORT, 'identity decisions are append-only'); END;
CREATE TRIGGER evidence_rights_assessment_no_update BEFORE UPDATE ON evidence_rights_assessment
BEGIN SELECT RAISE(ABORT, 'rights assessments are append-only'); END;
CREATE TRIGGER evidence_rights_assessment_no_delete BEFORE DELETE ON evidence_rights_assessment
BEGIN SELECT RAISE(ABORT, 'rights assessments are append-only'); END;
CREATE TRIGGER evidence_acquisition_case_no_update BEFORE UPDATE ON evidence_acquisition_case
BEGIN SELECT RAISE(ABORT, 'acquisition cases are immutable'); END;
CREATE TRIGGER evidence_acquisition_case_no_delete BEFORE DELETE ON evidence_acquisition_case
BEGIN SELECT RAISE(ABORT, 'acquisition cases are immutable'); END;
CREATE TRIGGER evidence_acquisition_event_no_update BEFORE UPDATE ON evidence_acquisition_event
BEGIN SELECT RAISE(ABORT, 'acquisition events are append-only'); END;
CREATE TRIGGER evidence_acquisition_event_no_delete BEFORE DELETE ON evidence_acquisition_event
BEGIN SELECT RAISE(ABORT, 'acquisition events are append-only'); END;
