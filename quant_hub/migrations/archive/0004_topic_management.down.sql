DROP TRIGGER IF EXISTS topic_mutation_event_no_delete;
DROP TRIGGER IF EXISTS topic_mutation_event_no_update;
DROP TRIGGER IF EXISTS topic_mutation_event_validate_insert;
DROP INDEX IF EXISTS topic_mutation_event_topic_idx;
DROP TABLE IF EXISTS topic_mutation_event;

DROP TRIGGER IF EXISTS topic_retirement_requires_no_active_children;
DROP TRIGGER IF EXISTS topic_hierarchy_validate_update;
DROP TRIGGER IF EXISTS topic_hierarchy_validate_insert;
DROP INDEX IF EXISTS topic_parent_idx;

ALTER TABLE topic DROP COLUMN updated_at;
ALTER TABLE topic DROP COLUMN revision;
ALTER TABLE topic DROP COLUMN created_by_actor_id;
ALTER TABLE topic DROP COLUMN parent_topic_id;
