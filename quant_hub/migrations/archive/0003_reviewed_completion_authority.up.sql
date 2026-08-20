CREATE TABLE research_completion_review_consumption (
    decision_id TEXT PRIMARY KEY
        REFERENCES research_completion_decision(decision_id) ON DELETE RESTRICT,
    research_id TEXT NOT NULL,
    research_release_id TEXT NOT NULL,
    certificate_urn TEXT NOT NULL UNIQUE CHECK(length(trim(certificate_urn)) > 0),
    certificate_hash TEXT NOT NULL CHECK(
        length(certificate_hash) = 64
        AND certificate_hash NOT GLOB '*[^0-9a-f]*'
    ),
    subject_urn TEXT NOT NULL CHECK(length(trim(subject_urn)) > 0),
    subject_version_urn TEXT NOT NULL CHECK(length(trim(subject_version_urn)) > 0),
    artifact_manifest_hash TEXT NOT NULL CHECK(
        length(artifact_manifest_hash) = 64
        AND artifact_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    requirements_manifest_hash TEXT NOT NULL CHECK(
        length(requirements_manifest_hash) = 64
        AND requirements_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    consumed_at TEXT NOT NULL CHECK(length(trim(consumed_at)) > 0),
    FOREIGN KEY(research_release_id, research_id)
        REFERENCES research_release_candidate_identity(research_release_id, research_id)
        ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER research_completion_review_consumption_validate_insert
BEFORE INSERT ON research_completion_review_consumption
WHEN NOT EXISTS (
        SELECT 1
        FROM research_completion_decision AS decision
        JOIN research_release_candidate_identity AS identity
          ON identity.research_release_id = decision.research_release_id
         AND identity.research_id = decision.research_id
        WHERE decision.decision_id = NEW.decision_id
          AND decision.research_id = NEW.research_id
          AND decision.research_release_id = NEW.research_release_id
          AND decision.decision = 'completed'
          AND decision.decision_kind = 'reviewed_import'
          AND decision.review_urn = NEW.certificate_urn
          AND identity.subject_urn = NEW.subject_urn
          AND identity.subject_version_urn = NEW.subject_version_urn
          AND identity.artifact_manifest_hash = NEW.artifact_manifest_hash
    )
BEGIN
    SELECT RAISE(ABORT, 'review certificate consumption does not match the completion candidate');
END;

CREATE TRIGGER research_completion_review_consumption_no_update
BEFORE UPDATE ON research_completion_review_consumption
BEGIN
    SELECT RAISE(ABORT, 'completion review consumptions are append-only');
END;

CREATE TRIGGER research_completion_review_consumption_no_delete
BEFORE DELETE ON research_completion_review_consumption
BEGIN
    SELECT RAISE(ABORT, 'completion review consumptions are append-only');
END;
