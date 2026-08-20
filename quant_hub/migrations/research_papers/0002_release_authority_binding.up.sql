CREATE TABLE evidence_release (
    evidence_release_id TEXT PRIMARY KEY,
    subject_urn TEXT NOT NULL CHECK(length(trim(subject_urn)) > 0),
    subject_version_urn TEXT NOT NULL UNIQUE CHECK(length(trim(subject_version_urn)) > 0),
    artifact_manifest_hash TEXT NOT NULL CHECK(
        length(artifact_manifest_hash)=64 AND artifact_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    source_snapshot_hash TEXT NOT NULL CHECK(
        length(source_snapshot_hash)=64 AND source_snapshot_hash NOT GLOB '*[^0-9a-f]*'
    ),
    requirements_manifest_hash TEXT NOT NULL CHECK(
        length(requirements_manifest_hash)=64 AND requirements_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    projection_revision TEXT NOT NULL CHECK(length(trim(projection_revision)) > 0),
    candidate_status TEXT NOT NULL DEFAULT 'staging' CHECK(candidate_status IN (
        'staging','validated','under_review','releasable','released','rejected'
    )),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    UNIQUE(subject_urn,artifact_manifest_hash)
) STRICT;

CREATE TRIGGER evidence_release_starts_staging
BEFORE INSERT ON evidence_release
WHEN NEW.candidate_status <> 'staging'
BEGIN
    SELECT RAISE(ABORT, 'evidence release must begin in staging');
END;

CREATE TRIGGER evidence_release_material_immutable
BEFORE UPDATE ON evidence_release
WHEN NEW.evidence_release_id<>OLD.evidence_release_id
  OR NEW.subject_urn<>OLD.subject_urn
  OR NEW.subject_version_urn<>OLD.subject_version_urn
  OR NEW.artifact_manifest_hash<>OLD.artifact_manifest_hash
  OR NEW.source_snapshot_hash<>OLD.source_snapshot_hash
  OR NEW.requirements_manifest_hash<>OLD.requirements_manifest_hash
  OR NEW.projection_revision<>OLD.projection_revision
  OR NEW.created_at<>OLD.created_at
BEGIN
    SELECT RAISE(ABORT, 'evidence release material is immutable');
END;

CREATE TRIGGER evidence_release_status_transition
BEFORE UPDATE OF candidate_status ON evidence_release
WHEN NOT (
    (OLD.candidate_status='staging' AND NEW.candidate_status IN ('validated','rejected'))
    OR (OLD.candidate_status='validated' AND NEW.candidate_status IN ('under_review','rejected'))
    OR (OLD.candidate_status='under_review' AND NEW.candidate_status IN ('releasable','rejected'))
    OR (OLD.candidate_status='releasable' AND NEW.candidate_status='released')
    OR OLD.candidate_status=NEW.candidate_status
)
BEGIN
    SELECT RAISE(ABORT, 'invalid evidence release status transition');
END;

CREATE TRIGGER evidence_release_no_delete
BEFORE DELETE ON evidence_release
BEGIN SELECT RAISE(ABORT, 'evidence releases cannot be deleted'); END;

CREATE TABLE evidence_release_item (
    evidence_release_id TEXT NOT NULL REFERENCES evidence_release(evidence_release_id) ON DELETE RESTRICT,
    item_kind TEXT NOT NULL CHECK(item_kind IN (
        'paper','citation','resource','inventory_export','catalog_projection','fetch_ledger'
    )),
    item_urn TEXT NOT NULL CHECK(length(trim(item_urn)) > 0),
    item_hash TEXT NOT NULL CHECK(
        length(item_hash)=64 AND item_hash NOT GLOB '*[^0-9a-f]*'
    ),
    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
    created_at TEXT NOT NULL CHECK(length(trim(created_at)) > 0),
    PRIMARY KEY(evidence_release_id,item_kind,item_urn),
    UNIQUE(evidence_release_id,ordinal)
) STRICT;

CREATE TRIGGER evidence_release_item_staging_only
BEFORE INSERT ON evidence_release_item
WHEN NOT EXISTS (
    SELECT 1 FROM evidence_release
    WHERE evidence_release_id=NEW.evidence_release_id AND candidate_status='staging'
)
BEGIN
    SELECT RAISE(ABORT, 'release items can only be added while staging');
END;

CREATE TRIGGER evidence_release_item_no_update
BEFORE UPDATE ON evidence_release_item
BEGIN SELECT RAISE(ABORT, 'evidence release items are immutable'); END;
CREATE TRIGGER evidence_release_item_no_delete
BEFORE DELETE ON evidence_release_item
BEGIN SELECT RAISE(ABORT, 'evidence release items are immutable'); END;

CREATE TABLE platform_certificate_receipt (
    certificate_receipt_id TEXT PRIMARY KEY,
    evidence_release_id TEXT NOT NULL REFERENCES evidence_release(evidence_release_id) ON DELETE RESTRICT,
    release_snapshot_urn TEXT NOT NULL UNIQUE CHECK(length(trim(release_snapshot_urn)) > 0),
    platform_candidate_id TEXT NOT NULL CHECK(length(trim(platform_candidate_id)) > 0),
    platform_decision_id TEXT NOT NULL CHECK(length(trim(platform_decision_id)) > 0),
    decision_hash TEXT NOT NULL CHECK(
        length(decision_hash)=64 AND decision_hash NOT GLOB '*[^0-9a-f]*'
    ),
    verdict TEXT NOT NULL CHECK(verdict='pass'),
    domain TEXT NOT NULL CHECK(domain='evidence'),
    subject_urn TEXT NOT NULL CHECK(length(trim(subject_urn)) > 0),
    subject_version_urn TEXT NOT NULL CHECK(length(trim(subject_version_urn)) > 0),
    artifact_manifest_hash TEXT NOT NULL CHECK(
        length(artifact_manifest_hash)=64 AND artifact_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    source_snapshot_hash TEXT NOT NULL CHECK(
        length(source_snapshot_hash)=64 AND source_snapshot_hash NOT GLOB '*[^0-9a-f]*'
    ),
    requirements_manifest_hash TEXT NOT NULL CHECK(
        length(requirements_manifest_hash)=64 AND requirements_manifest_hash NOT GLOB '*[^0-9a-f]*'
    ),
    projection_revision TEXT NOT NULL CHECK(length(trim(projection_revision)) > 0),
    certificate_payload_hash TEXT NOT NULL CHECK(
        length(certificate_payload_hash)=64 AND certificate_payload_hash NOT GLOB '*[^0-9a-f]*'
    ),
    received_at TEXT NOT NULL CHECK(length(trim(received_at)) > 0)
) STRICT;

CREATE TRIGGER platform_certificate_receipt_validate_insert
BEFORE INSERT ON platform_certificate_receipt
WHEN NOT EXISTS (
    SELECT 1 FROM evidence_release
    WHERE evidence_release_id=NEW.evidence_release_id
      AND candidate_status IN ('releasable','released')
      AND subject_urn=NEW.subject_urn
      AND subject_version_urn=NEW.subject_version_urn
      AND artifact_manifest_hash=NEW.artifact_manifest_hash
      AND source_snapshot_hash=NEW.source_snapshot_hash
      AND requirements_manifest_hash=NEW.requirements_manifest_hash
      AND projection_revision=NEW.projection_revision
)
BEGIN
    SELECT RAISE(ABORT, 'platform certificate does not exactly match a releasable evidence candidate');
END;

CREATE TRIGGER platform_certificate_receipt_no_update
BEFORE UPDATE ON platform_certificate_receipt
BEGIN SELECT RAISE(ABORT, 'platform certificate receipts are append-only'); END;
CREATE TRIGGER platform_certificate_receipt_no_delete
BEFORE DELETE ON platform_certificate_receipt
BEGIN SELECT RAISE(ABORT, 'platform certificate receipts are append-only'); END;

CREATE TABLE evidence_release_activation (
    activation_id TEXT PRIMARY KEY,
    subject_urn TEXT NOT NULL CHECK(length(trim(subject_urn)) > 0),
    evidence_release_id TEXT NOT NULL REFERENCES evidence_release(evidence_release_id) ON DELETE RESTRICT,
    certificate_receipt_id TEXT NOT NULL UNIQUE
        REFERENCES platform_certificate_receipt(certificate_receipt_id) ON DELETE RESTRICT,
    release_snapshot_urn TEXT NOT NULL UNIQUE CHECK(length(trim(release_snapshot_urn)) > 0),
    decision_hash TEXT NOT NULL CHECK(
        length(decision_hash)=64 AND decision_hash NOT GLOB '*[^0-9a-f]*'
    ),
    activated_at TEXT NOT NULL CHECK(length(trim(activated_at)) > 0),
    supersedes_activation_id TEXT REFERENCES evidence_release_activation(activation_id) ON DELETE RESTRICT,
    UNIQUE(activation_id,subject_urn,evidence_release_id,release_snapshot_urn)
) STRICT;

CREATE TRIGGER evidence_release_activation_validate_insert
BEFORE INSERT ON evidence_release_activation
WHEN NOT EXISTS (
    SELECT 1
    FROM platform_certificate_receipt AS receipt
    JOIN evidence_release AS release
      ON release.evidence_release_id=receipt.evidence_release_id
    WHERE receipt.certificate_receipt_id=NEW.certificate_receipt_id
      AND receipt.evidence_release_id=NEW.evidence_release_id
      AND receipt.release_snapshot_urn=NEW.release_snapshot_urn
      AND receipt.decision_hash=NEW.decision_hash
      AND receipt.subject_urn=NEW.subject_urn
      AND receipt.verdict='pass'
      AND receipt.domain='evidence'
      AND release.candidate_status IN ('releasable','released')
)
BEGIN
    SELECT RAISE(ABORT, 'activation requires a matching unconsumed PASS certificate receipt');
END;

CREATE TRIGGER evidence_release_activation_no_update
BEFORE UPDATE ON evidence_release_activation
BEGIN SELECT RAISE(ABORT, 'evidence release activations are append-only'); END;
CREATE TRIGGER evidence_release_activation_no_delete
BEFORE DELETE ON evidence_release_activation
BEGIN SELECT RAISE(ABORT, 'evidence release activations are append-only'); END;

CREATE TABLE active_evidence_release (
    subject_urn TEXT PRIMARY KEY,
    activation_id TEXT NOT NULL UNIQUE,
    evidence_release_id TEXT NOT NULL,
    release_snapshot_urn TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL CHECK(revision >= 1),
    FOREIGN KEY(activation_id,subject_urn,evidence_release_id,release_snapshot_urn)
        REFERENCES evidence_release_activation(
            activation_id,subject_urn,evidence_release_id,release_snapshot_urn
        ) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER active_evidence_release_validate_insert
BEFORE INSERT ON active_evidence_release
WHEN NEW.revision<>1 OR NOT EXISTS (
    SELECT 1 FROM evidence_release_activation
    WHERE activation_id=NEW.activation_id
      AND subject_urn=NEW.subject_urn
      AND evidence_release_id=NEW.evidence_release_id
      AND release_snapshot_urn=NEW.release_snapshot_urn
      AND supersedes_activation_id IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'initial active evidence release requires a root activation');
END;

CREATE TRIGGER active_evidence_release_validate_update
BEFORE UPDATE ON active_evidence_release
WHEN NEW.subject_urn<>OLD.subject_urn
  OR NEW.revision<>OLD.revision+1
  OR NOT EXISTS (
      SELECT 1 FROM evidence_release_activation
      WHERE activation_id=NEW.activation_id
        AND subject_urn=NEW.subject_urn
        AND evidence_release_id=NEW.evidence_release_id
        AND release_snapshot_urn=NEW.release_snapshot_urn
        AND supersedes_activation_id=OLD.activation_id
  )
BEGIN
    SELECT RAISE(ABORT, 'active evidence release update requires the next activation');
END;

CREATE TRIGGER active_evidence_release_no_delete
BEFORE DELETE ON active_evidence_release
BEGIN SELECT RAISE(ABORT, 'active evidence release cannot be deleted'); END;
