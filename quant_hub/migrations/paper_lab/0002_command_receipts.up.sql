CREATE TABLE paper_lab_command_receipt (
    idempotency_key TEXT PRIMARY KEY CHECK(
        length(idempotency_key) BETWEEN 8 AND 128
        AND idempotency_key NOT GLOB '*[^A-Za-z0-9._:-]*'
    ),
    command_kind TEXT NOT NULL CHECK(length(trim(command_kind)) > 0),
    request_sha256 TEXT NOT NULL CHECK(
        length(request_sha256) = 64
        AND request_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    response_json TEXT NOT NULL CHECK(json_valid(response_json)),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0)
) STRICT;

CREATE TRIGGER paper_lab_command_receipt_no_update
BEFORE UPDATE ON paper_lab_command_receipt
BEGIN
    SELECT RAISE(ABORT, 'paper lab command receipts are append-only');
END;

CREATE TRIGGER paper_lab_command_receipt_no_delete
BEFORE DELETE ON paper_lab_command_receipt
BEGIN
    SELECT RAISE(ABORT, 'paper lab command receipts are append-only');
END;
