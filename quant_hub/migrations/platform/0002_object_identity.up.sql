CREATE TRIGGER object_blob_identity_insert
BEFORE INSERT ON object_blob
WHEN NEW.object_id <> 'obj_sha256_' || NEW.sha256
BEGIN
    SELECT RAISE(ABORT, 'object_id does not match sha256');
END;

CREATE TRIGGER object_blob_identity_update
BEFORE UPDATE OF object_id, sha256 ON object_blob
WHEN NEW.object_id <> 'obj_sha256_' || NEW.sha256
BEGIN
    SELECT RAISE(ABORT, 'object_id does not match sha256');
END;

