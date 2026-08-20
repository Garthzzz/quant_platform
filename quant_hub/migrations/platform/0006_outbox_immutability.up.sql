CREATE TRIGGER outbox_event_material_immutable
BEFORE UPDATE ON outbox_event
WHEN NEW.event_id IS NOT OLD.event_id
  OR NEW.event_type IS NOT OLD.event_type
  OR NEW.event_version IS NOT OLD.event_version
  OR NEW.aggregate_urn IS NOT OLD.aggregate_urn
  OR NEW.payload_json IS NOT OLD.payload_json
  OR NEW.payload_hash IS NOT OLD.payload_hash
  OR NEW.created_at IS NOT OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'outbox event material fields are immutable');
END;

CREATE TRIGGER outbox_event_no_delete
BEFORE DELETE ON outbox_event
BEGIN
    SELECT RAISE(ABORT, 'outbox events are append-only');
END;
