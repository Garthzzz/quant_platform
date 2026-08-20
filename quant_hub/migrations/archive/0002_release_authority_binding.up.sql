CREATE TABLE research_release_candidate_identity (
    research_release_id TEXT PRIMARY KEY
        REFERENCES research_release(research_release_id) ON DELETE RESTRICT,
    research_id TEXT NOT NULL REFERENCES research(research_id) ON DELETE RESTRICT,
    release_key TEXT NOT NULL CHECK(length(trim(release_key)) > 0),
    subject_urn TEXT NOT NULL CHECK(length(trim(subject_urn)) > 0),
    subject_version_urn TEXT NOT NULL UNIQUE CHECK(length(trim(subject_version_urn)) > 0),
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
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(research_id, release_key),
    UNIQUE(research_release_id, research_id)
) STRICT;

CREATE TRIGGER research_release_candidate_identity_validate_insert
BEFORE INSERT ON research_release_candidate_identity
WHEN NOT EXISTS (
    SELECT 1 FROM research_release
    WHERE research_release_id = NEW.research_release_id
      AND research_id = NEW.research_id
      AND document_manifest_hash = NEW.artifact_manifest_hash
      AND candidate_status = 'staging'
)
BEGIN
    SELECT RAISE(ABORT, 'release candidate identity must match a staging archive release');
END;

CREATE TRIGGER research_release_candidate_identity_no_update
BEFORE UPDATE ON research_release_candidate_identity
BEGIN
    SELECT RAISE(ABORT, 'release candidate identity is immutable');
END;

CREATE TRIGGER research_release_candidate_identity_no_delete
BEFORE DELETE ON research_release_candidate_identity
BEGIN
    SELECT RAISE(ABORT, 'release candidate identity is immutable');
END;

CREATE TABLE research_release_authority_consumption (
    activation_id TEXT PRIMARY KEY,
    research_id TEXT NOT NULL,
    research_release_id TEXT NOT NULL,
    platform_candidate_id TEXT NOT NULL CHECK(length(trim(platform_candidate_id)) > 0),
    release_snapshot_urn TEXT NOT NULL UNIQUE CHECK(length(trim(release_snapshot_urn)) > 0),
    decision_hash TEXT NOT NULL CHECK(
        length(decision_hash) = 64 AND decision_hash NOT GLOB '*[^0-9a-f]*'
    ),
    consumed_at TEXT NOT NULL CHECK(length(trim(consumed_at)) > 0),
    FOREIGN KEY(research_release_id, research_id)
        REFERENCES research_release_candidate_identity(research_release_id, research_id)
        ON DELETE RESTRICT,
    FOREIGN KEY(activation_id, research_id, research_release_id, release_snapshot_urn)
        REFERENCES research_release_activation(
            activation_id, research_id, research_release_id, release_snapshot_urn
        ) ON DELETE RESTRICT
) STRICT;

CREATE INDEX research_release_authority_candidate_idx
ON research_release_authority_consumption(platform_candidate_id, consumed_at);

CREATE TRIGGER research_release_authority_consumption_no_update
BEFORE UPDATE ON research_release_authority_consumption
BEGIN
    SELECT RAISE(ABORT, 'release authority consumptions are append-only');
END;

CREATE TRIGGER research_release_authority_consumption_no_delete
BEFORE DELETE ON research_release_authority_consumption
BEGIN
    SELECT RAISE(ABORT, 'release authority consumptions are append-only');
END;
