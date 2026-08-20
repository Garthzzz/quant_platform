DROP TRIGGER IF EXISTS reading_run_release_update_requires_certificate;
DROP TRIGGER IF EXISTS reading_run_release_insert_requires_certificate;
DROP TRIGGER IF EXISTS reading_review_receipt_no_delete;
DROP TRIGGER IF EXISTS reading_review_receipt_no_update;
DROP TABLE IF EXISTS reading_review_receipt;

CREATE TRIGGER reading_run_release_insert_requires_review
BEFORE INSERT ON reading_run
WHEN NEW.status IN ('releasable', 'published')
 AND NOT EXISTS (
     SELECT 1 FROM paper_lab_event event
     WHERE event.aggregate_type = 'reading_run'
       AND event.aggregate_id = NEW.run_id
       AND event.event_type = 'reading_reviewed'
       AND json_extract(event.payload_json, '$.verdict') = 'pass'
 )
BEGIN
    SELECT RAISE(ABORT, 'reading release requires an independent pass review event');
END;

CREATE TRIGGER reading_run_release_update_requires_review
BEFORE UPDATE OF status ON reading_run
WHEN NEW.status IN ('releasable', 'published')
 AND NEW.status IS NOT OLD.status
 AND NOT EXISTS (
     SELECT 1 FROM paper_lab_event event
     WHERE event.aggregate_type = 'reading_run'
       AND event.aggregate_id = NEW.run_id
       AND event.event_type = 'reading_reviewed'
       AND json_extract(event.payload_json, '$.verdict') = 'pass'
 )
BEGIN
    SELECT RAISE(ABORT, 'reading release requires an independent pass review event');
END;
