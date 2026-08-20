CREATE TABLE release_candidate (
    candidate_id TEXT PRIMARY KEY CHECK(length(trim(candidate_id)) > 0),
    domain TEXT NOT NULL CHECK(domain IN ('archive','evidence','paper_lab')),
    subject_urn TEXT NOT NULL CHECK(length(trim(subject_urn)) > 0),
    subject_version_urn TEXT NOT NULL CHECK(length(trim(subject_version_urn)) > 0),
    artifact_manifest_hash TEXT NOT NULL CHECK(
        length(artifact_manifest_hash) = 64
        AND artifact_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    source_snapshot_hash TEXT NOT NULL CHECK(
        length(source_snapshot_hash) = 64
        AND source_snapshot_hash NOT GLOB '*[^0-9a-f]*'
    ),
    requirements_manifest_hash TEXT NOT NULL CHECK(
        length(requirements_manifest_hash) = 64
        AND requirements_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    projection_revision TEXT NOT NULL CHECK(length(trim(projection_revision)) > 0),
    status TEXT NOT NULL CHECK(status IN (
        'staging','validated','under_review','releasable','released','rejected'
    )),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(domain, subject_urn, subject_version_urn)
) STRICT;

CREATE TRIGGER release_candidate_insert_staging
BEFORE INSERT ON release_candidate
WHEN NEW.status <> 'staging'
BEGIN
    SELECT RAISE(ABORT, 'release candidate must begin in staging');
END;

CREATE TRIGGER release_candidate_material_immutable
BEFORE UPDATE ON release_candidate
WHEN NEW.candidate_id IS NOT OLD.candidate_id
  OR NEW.domain IS NOT OLD.domain
  OR NEW.subject_urn IS NOT OLD.subject_urn
  OR NEW.subject_version_urn IS NOT OLD.subject_version_urn
  OR NEW.artifact_manifest_hash IS NOT OLD.artifact_manifest_hash
  OR NEW.source_snapshot_hash IS NOT OLD.source_snapshot_hash
  OR NEW.requirements_manifest_hash IS NOT OLD.requirements_manifest_hash
  OR NEW.projection_revision IS NOT OLD.projection_revision
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'release candidate material fields are immutable');
END;

CREATE TRIGGER release_candidate_status_transition
BEFORE UPDATE OF status ON release_candidate
WHEN NOT (
    NEW.status = OLD.status
    OR (OLD.status = 'staging' AND NEW.status IN ('validated','rejected'))
    OR (OLD.status = 'validated' AND NEW.status IN ('under_review','rejected'))
    OR (OLD.status = 'under_review' AND NEW.status IN ('releasable','rejected'))
    OR (OLD.status = 'releasable' AND NEW.status = 'released')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid release candidate status transition');
END;

CREATE TRIGGER release_candidate_no_delete
BEFORE DELETE ON release_candidate
BEGIN
    SELECT RAISE(ABORT, 'release candidates are immutable');
END;

CREATE TABLE release_decision (
    decision_id TEXT PRIMARY KEY CHECK(length(trim(decision_id)) > 0),
    candidate_id TEXT NOT NULL UNIQUE
        REFERENCES release_candidate(candidate_id) ON DELETE RESTRICT,
    deterministic_gate_hash TEXT NOT NULL CHECK(
        length(deterministic_gate_hash) = 64
        AND deterministic_gate_hash NOT GLOB '*[^0-9a-f]*'
    ),
    review_set_hash TEXT NOT NULL CHECK(
        length(review_set_hash) = 64
        AND review_set_hash NOT GLOB '*[^0-9a-f]*'
    ),
    reconciliation_hash TEXT NOT NULL CHECK(
        length(reconciliation_hash) = 64
        AND reconciliation_hash NOT GLOB '*[^0-9a-f]*'
    ),
    verdict TEXT NOT NULL CHECK(verdict IN ('pass','fail')),
    decision_hash TEXT NOT NULL UNIQUE CHECK(
        length(decision_hash) = 64
        AND decision_hash NOT GLOB '*[^0-9a-f]*'
    ),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TRIGGER release_decision_validate_insert
BEFORE INSERT ON release_decision
WHEN NOT EXISTS (
    SELECT 1 FROM release_candidate
    WHERE candidate_id = NEW.candidate_id AND status = 'under_review'
)
BEGIN
    SELECT RAISE(ABORT, 'release decision requires an under-review candidate');
END;

CREATE TRIGGER release_decision_no_update
BEFORE UPDATE ON release_decision
BEGIN
    SELECT RAISE(ABORT, 'release decisions are append-only');
END;

CREATE TRIGGER release_decision_no_delete
BEFORE DELETE ON release_decision
BEGIN
    SELECT RAISE(ABORT, 'release decisions are append-only');
END;

CREATE TABLE release_snapshot (
    snapshot_id TEXT PRIMARY KEY CHECK(length(trim(snapshot_id)) > 0),
    snapshot_urn TEXT NOT NULL UNIQUE CHECK(length(trim(snapshot_urn)) > 0),
    candidate_id TEXT NOT NULL REFERENCES release_candidate(candidate_id) ON DELETE RESTRICT,
    decision_id TEXT NOT NULL REFERENCES release_decision(decision_id) ON DELETE RESTRICT,
    decision_hash TEXT NOT NULL CHECK(
        length(decision_hash) = 64 AND decision_hash NOT GLOB '*[^0-9a-f]*'
    ),
    domain TEXT NOT NULL CHECK(domain IN ('archive','evidence','paper_lab')),
    subject_urn TEXT NOT NULL CHECK(length(trim(subject_urn)) > 0),
    subject_version_urn TEXT NOT NULL CHECK(length(trim(subject_version_urn)) > 0),
    artifact_manifest_hash TEXT NOT NULL CHECK(
        length(artifact_manifest_hash) = 64
        AND artifact_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    source_snapshot_hash TEXT NOT NULL CHECK(
        length(source_snapshot_hash) = 64
        AND source_snapshot_hash NOT GLOB '*[^0-9a-f]*'
    ),
    requirements_manifest_hash TEXT NOT NULL CHECK(
        length(requirements_manifest_hash) = 64
        AND requirements_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    projection_revision TEXT NOT NULL CHECK(length(trim(projection_revision)) > 0),
    issuance_key TEXT NOT NULL CHECK(
        length(issuance_key) = 64 AND issuance_key NOT GLOB '*[^0-9a-f]*'
    ),
    issued_at TEXT NOT NULL CHECK(length(trim(issued_at)) > 0),
    UNIQUE(decision_id, issuance_key)
) STRICT;

CREATE TRIGGER release_snapshot_validate_insert
BEFORE INSERT ON release_snapshot
WHEN NOT EXISTS (
    SELECT 1
    FROM release_decision AS decision
    JOIN release_candidate AS candidate USING(candidate_id)
    WHERE decision.decision_id = NEW.decision_id
      AND decision.candidate_id = NEW.candidate_id
      AND decision.decision_hash = NEW.decision_hash
      AND decision.verdict = 'pass'
      AND candidate.status IN ('releasable','released')
      AND candidate.domain = NEW.domain
      AND candidate.subject_urn = NEW.subject_urn
      AND candidate.subject_version_urn = NEW.subject_version_urn
      AND candidate.artifact_manifest_hash = NEW.artifact_manifest_hash
      AND candidate.source_snapshot_hash = NEW.source_snapshot_hash
      AND candidate.requirements_manifest_hash = NEW.requirements_manifest_hash
      AND candidate.projection_revision = NEW.projection_revision
)
BEGIN
    SELECT RAISE(ABORT, 'release snapshot does not match a PASS candidate decision');
END;

CREATE TRIGGER release_snapshot_no_update
BEFORE UPDATE ON release_snapshot
BEGIN
    SELECT RAISE(ABORT, 'release snapshots are append-only');
END;

CREATE TRIGGER release_snapshot_no_delete
BEFORE DELETE ON release_snapshot
BEGIN
    SELECT RAISE(ABORT, 'release snapshots are append-only');
END;
