CREATE TEMP TABLE qrh_object_registry_migration_guard (
    invalid INTEGER NOT NULL CHECK(invalid = 0)
) STRICT;

INSERT INTO qrh_object_registry_migration_guard(invalid)
SELECT 1
FROM object_blob
WHERE length(sha256) <> 64
   OR sha256 GLOB '*[^0-9a-f]*'
   OR object_id <> 'obj_sha256_' || sha256
   OR relative_blob_path <>
      substr(sha256, 1, 2) || '/' ||
      substr(sha256, 3, 2) || '/' ||
      sha256 || '.blob'
LIMIT 1;

DROP TABLE qrh_object_registry_migration_guard;

CREATE TRIGGER object_blob_registry_insert
BEFORE INSERT ON object_blob
WHEN length(NEW.sha256) <> 64
     OR NEW.sha256 GLOB '*[^0-9a-f]*'
     OR NEW.object_id <> 'obj_sha256_' || NEW.sha256
     OR NEW.relative_blob_path <>
        substr(NEW.sha256, 1, 2) || '/' ||
        substr(NEW.sha256, 3, 2) || '/' ||
        NEW.sha256 || '.blob'
BEGIN
    SELECT RAISE(ABORT, 'object registry identity is not canonical');
END;

CREATE TRIGGER object_blob_registry_update
BEFORE UPDATE OF object_id, sha256, bytes, media_type, relative_blob_path, created_at ON object_blob
WHEN NEW.object_id <> OLD.object_id
     OR NEW.sha256 <> OLD.sha256
     OR NEW.bytes <> OLD.bytes
     OR NEW.media_type <> OLD.media_type
     OR NEW.relative_blob_path <> OLD.relative_blob_path
     OR NEW.created_at <> OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'object registry material fields are immutable');
END;
