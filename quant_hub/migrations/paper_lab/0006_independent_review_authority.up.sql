CREATE TABLE reading_review_authority_input (
    certificate_urn TEXT PRIMARY KEY CHECK(length(trim(certificate_urn)) > 0),
    certificate_hash TEXT NOT NULL UNIQUE CHECK(
        length(certificate_hash) = 64
        AND certificate_hash NOT GLOB '*[^0-9a-f]*'
    ),
    run_id TEXT NOT NULL REFERENCES reading_run(run_id) ON DELETE RESTRICT,
    run_artifact_hash TEXT NOT NULL CHECK(
        length(run_artifact_hash) = 64
        AND run_artifact_hash NOT GLOB '*[^0-9a-f]*'
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
    authority_id TEXT NOT NULL CHECK(length(trim(authority_id)) > 0),
    authority_key_hash TEXT NOT NULL CHECK(
        length(authority_key_hash) = 64
        AND authority_key_hash NOT GLOB '*[^0-9a-f]*'
    ),
    public_modulus_hex TEXT NOT NULL CHECK(
        length(public_modulus_hex) >= 512
        AND public_modulus_hex NOT GLOB '*[^0-9a-f]*'
    ),
    public_exponent INTEGER NOT NULL CHECK(public_exponent >= 3),
    review_decision_id TEXT NOT NULL CHECK(length(trim(review_decision_id)) > 0),
    reviewed_at TEXT NOT NULL CHECK(length(trim(reviewed_at)) > 0),
    authority_input_json TEXT NOT NULL CHECK(json_valid(authority_input_json)),
    authority_input_sha256 TEXT NOT NULL UNIQUE CHECK(
        length(authority_input_sha256) = 64
        AND authority_input_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    signature_hex TEXT NOT NULL CHECK(
        length(signature_hex) >= 512
        AND signature_hex NOT GLOB '*[^0-9a-f]*'
    ),
    signature_sha256 TEXT NOT NULL UNIQUE CHECK(
        length(signature_sha256) = 64
        AND signature_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    registered_at TEXT NOT NULL CHECK(length(trim(registered_at)) > 0),
    UNIQUE(run_id, review_decision_id),
    UNIQUE(run_id, authority_input_sha256)
) STRICT;

CREATE INDEX reading_review_authority_run_idx
ON reading_review_authority_input(run_id, registered_at);

CREATE TRIGGER reading_review_authority_input_no_update
BEFORE UPDATE ON reading_review_authority_input
BEGIN
    SELECT RAISE(ABORT, 'reading review authority inputs are immutable');
END;

CREATE TRIGGER reading_review_authority_input_no_delete
BEFORE DELETE ON reading_review_authority_input
BEGIN
    SELECT RAISE(ABORT, 'reading review authority inputs are immutable');
END;
