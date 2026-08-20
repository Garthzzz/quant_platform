DROP TRIGGER IF EXISTS reading_run_release_update_requires_review;
DROP TRIGGER IF EXISTS reading_run_release_insert_requires_review;

CREATE TABLE reading_review_receipt (
    run_id TEXT PRIMARY KEY REFERENCES reading_run(run_id) ON DELETE RESTRICT,
    certificate_urn TEXT NOT NULL UNIQUE CHECK(length(trim(certificate_urn)) > 0),
    certificate_hash TEXT NOT NULL CHECK(
        length(certificate_hash) = 64
        AND certificate_hash NOT GLOB '*[^0-9a-f]*'
    ),
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
    consumed_at TEXT NOT NULL CHECK(length(trim(consumed_at)) > 0)
) STRICT;

CREATE TRIGGER reading_review_receipt_no_update
BEFORE UPDATE ON reading_review_receipt
BEGIN
    SELECT RAISE(ABORT, 'reading review receipts are immutable');
END;

CREATE TRIGGER reading_review_receipt_no_delete
BEFORE DELETE ON reading_review_receipt
BEGIN
    SELECT RAISE(ABORT, 'reading review receipts are immutable');
END;

CREATE TRIGGER reading_run_release_insert_requires_certificate
BEFORE INSERT ON reading_run
WHEN NEW.status IN ('releasable', 'published')
BEGIN
    SELECT RAISE(ABORT, 'reading release requires a consumed review certificate');
END;

CREATE TRIGGER reading_run_release_update_requires_certificate
BEFORE UPDATE OF status ON reading_run
WHEN NEW.status IN ('releasable', 'published')
 AND NEW.status IS NOT OLD.status
 AND NOT EXISTS (
     SELECT 1
     FROM reading_review_receipt receipt
     JOIN paper_lab_event event
       ON event.aggregate_type = 'reading_run'
      AND event.aggregate_id = receipt.run_id
      AND event.event_type = 'reading_reviewed'
     WHERE receipt.run_id = NEW.run_id
       AND json_extract(event.payload_json, '$.verdict') = 'pass'
       AND json_extract(event.payload_json, '$.certificate_urn') = receipt.certificate_urn
       AND json_extract(event.payload_json, '$.certificate_hash') = receipt.certificate_hash
       AND json_extract(event.payload_json, '$.run_artifact_hash') = receipt.run_artifact_hash
       AND json_extract(event.payload_json, '$.requirements_manifest_hash') = receipt.requirements_manifest_hash
       AND json_extract(event.payload_json, '$.review_artifact_hash') = receipt.review_artifact_hash
       AND json_extract(event.payload_json, '$.review_set_hash') = receipt.review_set_hash
       AND json_extract(event.payload_json, '$.reviewer_identity_hash') = receipt.reviewer_identity_hash
 )
BEGIN
    SELECT RAISE(ABORT, 'reading release requires a consumed review certificate');
END;
