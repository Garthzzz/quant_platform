ALTER TABLE research_workspace_node
ADD COLUMN default_research_question TEXT
CHECK(
    default_research_question IS NULL
    OR length(trim(default_research_question)) BETWEEN 1 AND 8000
);

ALTER TABLE research_workspace_node
ADD COLUMN research_question_override TEXT
CHECK(
    research_question_override IS NULL
    OR length(trim(research_question_override)) BETWEEN 1 AND 8000
);

ALTER TABLE research_workspace_node
ADD COLUMN default_research_content TEXT
CHECK(
    default_research_content IS NULL
    OR length(trim(default_research_content)) BETWEEN 1 AND 20000
);

ALTER TABLE research_workspace_node
ADD COLUMN research_content_override TEXT
CHECK(
    research_content_override IS NULL
    OR length(trim(research_content_override)) BETWEEN 1 AND 20000
);

UPDATE research_workspace_node
SET lifecycle_status='completed',
    revision=revision + 1
WHERE node_kind='project'
  AND source_state='present'
  AND lifecycle_status <> 'completed';
