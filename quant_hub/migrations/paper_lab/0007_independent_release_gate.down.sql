DROP TRIGGER IF EXISTS reading_run_release_update_requires_certificate;

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
