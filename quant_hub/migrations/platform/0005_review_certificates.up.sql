CREATE TABLE review_certificate (
    certificate_id TEXT PRIMARY KEY CHECK(length(trim(certificate_id)) > 0),
    certificate_urn TEXT NOT NULL UNIQUE CHECK(length(trim(certificate_urn)) > 0),
    gate_name TEXT NOT NULL CHECK(length(trim(gate_name)) > 0),
    gate_version TEXT NOT NULL CHECK(length(trim(gate_version)) > 0),
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
    review_artifact_hash TEXT NOT NULL CHECK(
        length(review_artifact_hash) = 64
        AND review_artifact_hash NOT GLOB '*[^0-9a-f]*'
    ),
    review_set_hash TEXT NOT NULL CHECK(
        length(review_set_hash) = 64
        AND review_set_hash NOT GLOB '*[^0-9a-f]*'
    ),
    reviewer_identity_hash TEXT NOT NULL CHECK(
        length(reviewer_identity_hash) = 64
        AND reviewer_identity_hash NOT GLOB '*[^0-9a-f]*'
    ),
    verdict TEXT NOT NULL CHECK(verdict = 'pass'),
    issuance_key TEXT NOT NULL UNIQUE CHECK(
        length(issuance_key) = 64
        AND issuance_key NOT GLOB '*[^0-9a-f]*'
    ),
    certificate_hash TEXT NOT NULL UNIQUE CHECK(
        length(certificate_hash) = 64
        AND certificate_hash NOT GLOB '*[^0-9a-f]*'
    ),
    issued_at TEXT NOT NULL CHECK(length(trim(issued_at)) > 0),
    UNIQUE(gate_name, gate_version, subject_urn, subject_version_urn, issuance_key)
) STRICT;

CREATE INDEX review_certificate_subject_idx
ON review_certificate(gate_name, subject_urn, subject_version_urn, issued_at);

CREATE TRIGGER review_certificate_no_update
BEFORE UPDATE ON review_certificate
BEGIN
    SELECT RAISE(ABORT, 'review certificates are append-only');
END;

CREATE TRIGGER review_certificate_no_delete
BEFORE DELETE ON review_certificate
BEGIN
    SELECT RAISE(ABORT, 'review certificates are append-only');
END;
