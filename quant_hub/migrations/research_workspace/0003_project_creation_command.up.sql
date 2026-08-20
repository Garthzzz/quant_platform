DROP TRIGGER research_workspace_command_receipt_no_delete;
DROP TRIGGER research_workspace_command_receipt_no_update;

ALTER TABLE research_workspace_command_receipt
RENAME TO research_workspace_command_receipt_before_project_creation;

CREATE TABLE research_workspace_command_receipt (
    receipt_id TEXT PRIMARY KEY CHECK(length(trim(receipt_id)) > 0),
    idempotency_key TEXT NOT NULL UNIQUE
        CHECK(length(trim(idempotency_key)) BETWEEN 1 AND 200),
    command_name TEXT NOT NULL CHECK(command_name IN (
        'workspace.sync','workspace.project.create','workspace.node.update',
        'workspace.comment.create','workspace.comment.update','workspace.comment.delete'
    )),
    payload_hash TEXT NOT NULL CHECK(
        length(payload_hash) = 64 AND payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    outcome_json TEXT NOT NULL CHECK(json_valid(outcome_json)),
    http_status INTEGER NOT NULL CHECK(http_status BETWEEN 100 AND 599),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

INSERT INTO research_workspace_command_receipt(
    receipt_id,idempotency_key,command_name,payload_hash,
    outcome_json,http_status,created_at
)
SELECT
    receipt_id,idempotency_key,command_name,payload_hash,
    outcome_json,http_status,created_at
FROM research_workspace_command_receipt_before_project_creation;

DROP TABLE research_workspace_command_receipt_before_project_creation;

CREATE TRIGGER research_workspace_command_receipt_no_update
BEFORE UPDATE ON research_workspace_command_receipt
BEGIN
    SELECT RAISE(ABORT, 'research workspace command receipts are immutable');
END;

CREATE TRIGGER research_workspace_command_receipt_no_delete
BEFORE DELETE ON research_workspace_command_receipt
BEGIN
    SELECT RAISE(ABORT, 'research workspace command receipts are immutable');
END;
