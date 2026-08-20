-- Historical JSON is imported evidence, not an independent review decision.
-- Repair any legacy run that an earlier importer allowed to bypass review.
UPDATE lab_paper
SET lifecycle_status = 'validated'
WHERE lifecycle_status = 'published'
  AND EXISTS (
      SELECT 1
      FROM lab_paper_version version
      JOIN reading_run run ON run.paper_version_id = version.paper_version_id
      JOIN reading_result result ON result.run_id = run.run_id
      WHERE version.paper_id = lab_paper.paper_id
        AND result.result_kind = 'legacy_record'
        AND run.status IN ('releasable', 'published')
        AND NOT EXISTS (
            SELECT 1 FROM paper_lab_event event
            WHERE event.aggregate_type = 'reading_run'
              AND event.aggregate_id = run.run_id
              AND event.event_type = 'reading_reviewed'
              AND json_extract(event.payload_json, '$.verdict') = 'pass'
        )
  )
  AND NOT EXISTS (
      SELECT 1
      FROM lab_paper_version version
      JOIN reading_run run ON run.paper_version_id = version.paper_version_id
      WHERE version.paper_id = lab_paper.paper_id
        AND run.status = 'published'
        AND EXISTS (
            SELECT 1 FROM paper_lab_event event
            WHERE event.aggregate_type = 'reading_run'
              AND event.aggregate_id = run.run_id
              AND event.event_type = 'reading_reviewed'
              AND json_extract(event.payload_json, '$.verdict') = 'pass'
        )
  );

UPDATE reading_run
SET status = 'awaiting_review'
WHERE status IN ('releasable', 'published')
  AND EXISTS (
      SELECT 1 FROM reading_result result
      WHERE result.run_id = reading_run.run_id
        AND result.result_kind = 'legacy_record'
  )
  AND NOT EXISTS (
      SELECT 1 FROM paper_lab_event event
      WHERE event.aggregate_type = 'reading_run'
        AND event.aggregate_id = reading_run.run_id
        AND event.event_type = 'reading_reviewed'
        AND json_extract(event.payload_json, '$.verdict') = 'pass'
  );

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
