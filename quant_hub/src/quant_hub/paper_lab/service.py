from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any, Literal
from urllib.parse import quote

from quant_hub.config import Settings
from quant_hub.platform.db import (
    connection_is_read_only,
    immediate_transaction,
    utc_now,
)
from quant_hub.platform.reviews import ReviewAuthority, ReviewCertificateMismatch
from .contracts import EDITABLE_PAPER_FIELDS
from .database import initialize_paper_lab_database, paper_lab_connection
from .identity import stable_public_id
from .importer import LegacyProj2Importer, _canonical_json, _copy_verified, _sha256_file
from .scanner import PaperDropScanner, ScanCandidate, ScanReport
from .projection import ComponentProjector, ProjectionReport
from .reviewer import verify_independent_review_certificate


@dataclass(frozen=True, slots=True)
class RegistrationOutcome:
    paper_id: str
    paper_version_id: str
    created: bool
    status: str


@dataclass(frozen=True, slots=True)
class RunOutcome:
    run_id: str
    status: str
    attempt: int


@dataclass(frozen=True, slots=True)
class BlueprintValidation:
    valid: bool
    errors: tuple[dict[str, object], ...]
    warnings: tuple[dict[str, object], ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class PaperLabIdempotencyConflict(RuntimeError):
    pass


class PaperFieldVersionConflict(RuntimeError):
    pass


_EVIDENCE_LOCATOR_KEYS = {
    "paper_version_id", "content_sha256", "page", "locator", "excerpt",
}


def _result_material_sha256(payload_json: str, evidence_json: str) -> str:
    return hashlib.sha256((payload_json + "\0" + evidence_json).encode("utf-8")).hexdigest()


def _validate_evidence_locators(
    evidence_locators: object,
    *,
    paper_version_id: str,
    content_sha256: str,
) -> list[dict[str, object]]:
    if not isinstance(evidence_locators, list) or not (1 <= len(evidence_locators) <= 200):
        raise ValueError("reading phase requires 1..200 evidence locators")
    normalized: list[dict[str, object]] = []
    seen: set[tuple[int, str]] = set()
    for item in evidence_locators:
        if not isinstance(item, dict) or set(item) != _EVIDENCE_LOCATOR_KEYS:
            raise ValueError("evidence locator must contain only the complete binding fields")
        if item["paper_version_id"] != paper_version_id:
            raise ValueError("evidence locator paper_version_id does not match the run")
        if item["content_sha256"] != content_sha256:
            raise ValueError("evidence locator content_sha256 does not match the run")
        page = item["page"]
        if isinstance(page, bool) or not isinstance(page, int) or not (1 <= page <= 100000):
            raise ValueError("evidence locator page is invalid")
        locator = item["locator"]
        if locator != f"pdf-page:{page}":
            raise ValueError("evidence locator/page binding is invalid")
        excerpt = item["excerpt"]
        if not isinstance(excerpt, str) or not excerpt.strip() or len(excerpt) > 4000:
            raise ValueError("evidence locator excerpt is invalid")
        key = (page, excerpt.strip())
        if key in seen:
            raise ValueError("duplicate evidence locator")
        seen.add(key)
        normalized.append({
            "paper_version_id": paper_version_id,
            "content_sha256": content_sha256,
            "page": page,
            "locator": locator,
            "excerpt": excerpt.strip(),
        })
    return normalized


@dataclass(frozen=True, slots=True)
class ReviewMaterial:
    gate_name: str
    gate_version: str
    subject_urn: str
    subject_version_urn: str
    run_artifact_hash: str
    requirements_manifest_hash: str


class PaperLabService:
    def __init__(self, settings: Settings):
        self.settings = settings

    def initialize(self) -> list[int]:
        applied = initialize_paper_lab_database(self.settings)
        now = utc_now()
        with paper_lab_connection(self.settings) as connection:
            if connection_is_read_only(connection):
                return applied
            with immediate_transaction(connection):
                LegacyProj2Importer._bootstrap_workflow(connection, now)
        return applied

    def rebuild_components(self) -> ProjectionReport:
        return ComponentProjector(self.settings).rebuild()

    def scan(self) -> ScanReport:
        return PaperDropScanner(self.settings).scan()

    def register_candidate(self, candidate_id: str) -> RegistrationOutcome:
        report = self.scan()
        candidate = next((item for item in report.candidates if item.candidate_id == candidate_id), None)
        if candidate is None:
            raise KeyError(f"paper drop candidate not found: {candidate_id}")
        return self._register_drop(candidate)

    def register_all(self) -> list[RegistrationOutcome]:
        report = self.scan()
        return [self._register_drop(item) for item in report.candidates]

    def _register_drop(self, candidate: ScanCandidate) -> RegistrationOutcome:
        source = self.settings.paper_lab_drop_root / candidate.original_filename
        current_digest, current_size = _sha256_file(source)
        if (current_digest, current_size) != (candidate.content_sha256, candidate.bytes):
            raise RuntimeError("paper drop changed after discovery; rescan required")
        destination = (
            self.settings.paper_lab_asset_root
            / current_digest[:2]
            / f"{current_digest}.pdf"
        )
        _copy_verified(source, destination, current_digest, current_size)
        paper_id = stable_public_id("labpaper", "paper_drop", current_digest)
        version_id = stable_public_id("labver", paper_id, current_digest)
        now = utc_now()
        lifecycle = "discovered" if candidate.status == "discovered" else "quarantined"
        discovery = "registered" if candidate.status == "discovered" else "quarantined"
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                existed = connection.execute(
                    "SELECT 1 FROM lab_paper WHERE paper_id=?", (paper_id,)
                ).fetchone() is not None
                connection.execute(
                    """
                    INSERT INTO lab_paper(
                        paper_id,legacy_id,canonical_title,lifecycle_status,
                        source_kind,created_at,updated_at
                    ) VALUES(?,NULL,?,?, 'paper_drop',?,?)
                    ON CONFLICT(paper_id) DO UPDATE SET updated_at=excluded.updated_at
                    """,
                    (paper_id, candidate.title_hint, lifecycle, now, now),
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO lab_paper_version(
                        paper_version_id,paper_id,content_sha256,bytes,media_type,
                        original_filename,source_location_urn,asset_relative_path,
                        discovery_status,created_at
                    ) VALUES(?,?,?,?,'application/pdf',?,?,?,?,?)
                    """,
                    (
                        version_id,
                        paper_id,
                        current_digest,
                        current_size,
                        candidate.original_filename,
                        f"qrh:paper-drop:{quote(candidate.original_filename)}",
                        f"{current_digest[:2]}/{current_digest}.pdf",
                        discovery,
                        now,
                    ),
                )
                self._event(
                    connection,
                    "lab_paper",
                    paper_id,
                    "paper_drop_registered",
                    {"candidate": candidate.to_dict(), "created": not existed},
                    now,
                )
        return RegistrationOutcome(paper_id, version_id, not existed, lifecycle)

    def queue_reading(self, paper_id: str, *, resume: bool = False) -> RunOutcome:
        self.initialize()
        now = utc_now()
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                version = connection.execute(
                    """
                    SELECT paper_version_id,content_sha256
                    FROM lab_paper_version
                    WHERE paper_id=?
                    ORDER BY created_at DESC,paper_version_id DESC LIMIT 1
                    """,
                    (paper_id,),
                ).fetchone()
                if version is None:
                    raise KeyError(f"paper not found or has no version: {paper_id}")
                latest = connection.execute(
                    """
                    SELECT run_id,status,attempt,resume_from_phase_key,input_revision_sha256
                    FROM reading_run
                    WHERE paper_version_id=? AND workflow_version='paper-reading/v1'
                    ORDER BY attempt DESC LIMIT 1
                    """,
                    (version["paper_version_id"],),
                ).fetchone()
                if latest is not None and latest["status"] in {
                    "queued", "running", "awaiting_review", "releasable", "published"
                }:
                    return RunOutcome(latest["run_id"], latest["status"], int(latest["attempt"]))
                if resume and latest is not None and latest["status"] != "failed":
                    raise RuntimeError(f"run cannot resume from status: {latest['status']}")
                attempt = 1 if latest is None else int(latest["attempt"]) + 1
                resume_phase = latest["resume_from_phase_key"] if resume and latest else None
                inherited_results: list[sqlite3.Row] = []
                if resume and latest is not None:
                    if latest["input_revision_sha256"] != version["content_sha256"]:
                        raise RuntimeError("resume input revision differs from the immutable paper version")
                    phases = connection.execute(
                        """
                        SELECT phase_id,phase_key,ordinal FROM reading_phase
                        WHERE workflow_version='paper-reading/v1' AND required=1
                        ORDER BY ordinal
                        """
                    ).fetchall()
                    phase_keys = [row["phase_key"] for row in phases]
                    if resume_phase is None:
                        expected_predecessors: list[str] = []
                    else:
                        if resume_phase not in phase_keys:
                            raise RuntimeError("resume_from_phase_key is not in the active workflow")
                        expected_predecessors = phase_keys[:phase_keys.index(resume_phase)]
                    inherited_results = connection.execute(
                        """
                        SELECT result.*,phase.phase_key,phase.ordinal
                        FROM reading_result AS result
                        JOIN reading_phase AS phase ON phase.phase_id=result.phase_id
                        WHERE result.run_id=? AND result.artifact_status='validated'
                        ORDER BY phase.ordinal,result.created_at,result.result_id
                        """,
                        (latest["run_id"],),
                    ).fetchall()
                    observed = [row["phase_key"] for row in inherited_results]
                    if observed != expected_predecessors:
                        raise RuntimeError(
                            "resume lineage does not contain exactly the successful predecessor phases"
                        )
                    for row in inherited_results:
                        if row["result_kind"] != row["phase_key"]:
                            raise RuntimeError("resume lineage result kind/phase mismatch")
                        try:
                            payload_value = json.loads(row["payload_json"])
                            evidence_value = json.loads(row["evidence_locator_json"])
                        except json.JSONDecodeError as error:
                            raise RuntimeError("resume lineage contains invalid JSON") from error
                        if not isinstance(payload_value, dict):
                            raise RuntimeError("resume lineage payload is not an object")
                        try:
                            normalized_evidence = _validate_evidence_locators(
                                evidence_value,
                                paper_version_id=version["paper_version_id"],
                                content_sha256=version["content_sha256"],
                            )
                        except ValueError as error:
                            raise RuntimeError(
                                "resume lineage evidence is not bound to the immutable input"
                            ) from error
                        if (
                            _canonical_json(payload_value) != row["payload_json"]
                            or _canonical_json(normalized_evidence)
                            != row["evidence_locator_json"]
                            or _result_material_sha256(
                                row["payload_json"], row["evidence_locator_json"]
                            ) != row["artifact_sha256"]
                        ):
                            raise RuntimeError("resume lineage result material/hash is invalid")
                run_id = stable_public_id(
                    "labrun", version["paper_version_id"], "paper-reading/v1", str(attempt),
                )
                connection.execute(
                    """
                    INSERT INTO reading_run(
                        run_id,paper_version_id,workflow_version,status,attempt,
                        resume_from_phase_key,input_revision_sha256,error_code,error_detail,
                        created_at,updated_at
                    ) VALUES(?,?,'paper-reading/v1','queued',?,?,?,NULL,NULL,?,?)
                    """,
                    (
                        run_id, version["paper_version_id"], attempt, resume_phase,
                        version["content_sha256"], now, now,
                    ),
                )
                inherited_audit: list[dict[str, object]] = []
                for source_result in inherited_results:
                    result_id = stable_public_id(
                        "labresult",
                        run_id,
                        "inherited",
                        source_result["result_id"],
                        source_result["artifact_sha256"],
                    )
                    connection.execute(
                        """
                        INSERT INTO reading_result(
                            result_id,run_id,phase_id,result_kind,schema_version,payload_json,
                            evidence_locator_json,artifact_sha256,artifact_status,created_at
                        ) VALUES(?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            result_id,
                            run_id,
                            source_result["phase_id"],
                            source_result["result_kind"],
                            source_result["schema_version"],
                            source_result["payload_json"],
                            source_result["evidence_locator_json"],
                            source_result["artifact_sha256"],
                            source_result["artifact_status"],
                            now,
                        ),
                    )
                    lineage = {
                        "source_run_id": latest["run_id"],
                        "source_result_id": source_result["result_id"],
                        "target_result_id": result_id,
                        "phase_key": source_result["phase_key"],
                        "artifact_sha256": source_result["artifact_sha256"],
                        "source_input_revision_sha256": latest["input_revision_sha256"],
                        "target_input_revision_sha256": version["content_sha256"],
                    }
                    inherited_audit.append(lineage)
                    self._event(
                        connection,
                        "reading_run",
                        run_id,
                        "reading_phase_inherited",
                        lineage,
                        now,
                    )
                connection.execute(
                    "UPDATE lab_paper SET lifecycle_status='reading',updated_at=? WHERE paper_id=?",
                    (now, paper_id),
                )
                self._event(
                    connection, "reading_run", run_id, "reading_queued",
                    {
                        "paper_id": paper_id,
                        "attempt": attempt,
                        "resume": resume,
                        "resume_from_phase_key": resume_phase,
                        "source_run_id": latest["run_id"] if resume and latest else None,
                        "input_revision_sha256": version["content_sha256"],
                        "inherited_results": inherited_audit,
                    },
                    now,
                )
        return RunOutcome(run_id, "queued", attempt)

    def claim_run(self, run_id: str) -> RunOutcome:
        now = utc_now()
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                changed = connection.execute(
                    "UPDATE reading_run SET status='running',updated_at=? WHERE run_id=? AND status='queued'",
                    (now, run_id),
                ).rowcount
                row = connection.execute(
                    "SELECT status,attempt FROM reading_run WHERE run_id=?", (run_id,)
                ).fetchone()
                if row is None:
                    raise KeyError(run_id)
                if changed != 1 and row["status"] != "running":
                    raise RuntimeError(f"run is not claimable: {row['status']}")
                self._event(connection, "reading_run", run_id, "reading_claimed", {}, now)
                return RunOutcome(run_id, row["status"], int(row["attempt"]))

    def submit_phase(
        self,
        run_id: str,
        phase_key: str,
        result_kind: Literal["problem", "method", "experiment", "limitation", "synthesis"],
        payload: dict[str, object],
        evidence_locators: list[dict[str, object]],
    ) -> str:
        now = utc_now()
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                run = connection.execute(
                    """
                    SELECT run.workflow_version,run.status,run.paper_version_id,
                           run.input_revision_sha256,version.content_sha256
                    FROM reading_run AS run
                    JOIN lab_paper_version AS version
                      ON version.paper_version_id=run.paper_version_id
                    WHERE run.run_id=?
                    """,
                    (run_id,),
                ).fetchone()
                if run is None:
                    raise KeyError(run_id)
                if run["status"] != "running":
                    raise RuntimeError(f"run does not accept results: {run['status']}")
                if result_kind != phase_key:
                    raise ValueError("result_kind must match phase_key")
                if run["input_revision_sha256"] != run["content_sha256"]:
                    raise RuntimeError("run input revision is not the immutable paper content")
                phase = connection.execute(
                    "SELECT phase_id,ordinal FROM reading_phase WHERE workflow_version=? AND phase_key=?",
                    (run["workflow_version"], phase_key),
                ).fetchone()
                if phase is None:
                    raise ValueError(f"unknown phase: {phase_key}")
                expected_phase = connection.execute(
                    """
                    SELECT phase_key FROM reading_phase
                    WHERE workflow_version=? AND required=1 AND phase_id NOT IN (
                        SELECT phase_id FROM reading_result
                        WHERE run_id=? AND artifact_status='validated' AND phase_id IS NOT NULL
                    ) ORDER BY ordinal LIMIT 1
                    """,
                    (run["workflow_version"], run_id),
                ).fetchone()
                if expected_phase is None or expected_phase["phase_key"] != phase_key:
                    expected_key = expected_phase["phase_key"] if expected_phase else None
                    raise ValueError(f"phase is out of sequence; expected {expected_key!r}")
                if not isinstance(payload, dict):
                    raise ValueError("reading phase payload must be an object")
                normalized_evidence = _validate_evidence_locators(
                    evidence_locators,
                    paper_version_id=run["paper_version_id"],
                    content_sha256=run["content_sha256"],
                )
                canonical_payload = _canonical_json(payload)
                canonical_evidence = _canonical_json(normalized_evidence)
                digest = _result_material_sha256(canonical_payload, canonical_evidence)
                result_id = stable_public_id("labresult", run_id, phase["phase_id"], result_kind, digest)
                connection.execute(
                    """
                    INSERT OR IGNORE INTO reading_result(
                        result_id,run_id,phase_id,result_kind,schema_version,payload_json,
                        evidence_locator_json,artifact_sha256,artifact_status,created_at
                    ) VALUES(?,?,?,?, 'paper-reading-result/v1',?,?,?,'validated',?)
                    """,
                    (
                        result_id, run_id, phase["phase_id"], result_kind,
                        canonical_payload, canonical_evidence, digest, now,
                    ),
                )
                required = int(connection.execute(
                    "SELECT count(*) FROM reading_phase WHERE workflow_version=? AND required=1",
                    (run["workflow_version"],),
                ).fetchone()[0])
                completed = int(connection.execute(
                    """
                    SELECT count(DISTINCT rr.phase_id)
                    FROM reading_result rr
                    JOIN reading_phase rp ON rp.phase_id=rr.phase_id
                    WHERE rr.run_id=? AND rr.artifact_status='validated' AND rp.required=1
                    """,
                    (run_id,),
                ).fetchone()[0])
                if completed == required:
                    status = "awaiting_review"
                    resume_key = None
                else:
                    next_phase = connection.execute(
                        """
                        SELECT phase_key FROM reading_phase
                        WHERE workflow_version=? AND required=1 AND phase_id NOT IN (
                            SELECT phase_id FROM reading_result
                            WHERE run_id=? AND artifact_status='validated' AND phase_id IS NOT NULL
                        ) ORDER BY ordinal LIMIT 1
                        """,
                        (run["workflow_version"], run_id),
                    ).fetchone()
                    status = "running"
                    resume_key = next_phase["phase_key"] if next_phase else None
                connection.execute(
                    "UPDATE reading_run SET status=?,resume_from_phase_key=?,updated_at=? WHERE run_id=?",
                    (status, resume_key, now, run_id),
                )
                self._event(
                    connection, "reading_run", run_id, "reading_phase_submitted",
                    {
                        "phase_key": phase_key,
                        "result_id": result_id,
                        "artifact_sha256": digest,
                        "input_revision_sha256": run["input_revision_sha256"],
                        "status": status,
                    },
                    now,
                )
        return result_id

    @staticmethod
    def _review_material_from_connection(
        connection: sqlite3.Connection, run_id: str,
    ) -> ReviewMaterial:
        run = connection.execute(
            "SELECT workflow_version,input_revision_sha256 FROM reading_run WHERE run_id=?",
            (run_id,),
        ).fetchone()
        if run is None:
            raise KeyError(run_id)
        results = [dict(row) for row in connection.execute(
            """
            SELECT phase.phase_key,phase.ordinal,result.result_kind,
                   result.artifact_sha256,result.schema_version
            FROM reading_result result
            JOIN reading_phase phase ON phase.phase_id=result.phase_id
            WHERE result.run_id=? AND result.artifact_status='validated'
            ORDER BY phase.ordinal,result.result_kind,result.result_id
            """,
            (run_id,),
        ).fetchall()]
        requirements = [dict(row) for row in connection.execute(
            """
            SELECT phase_key,ordinal,display_name,required
            FROM reading_phase WHERE workflow_version=? ORDER BY ordinal
            """,
            (run["workflow_version"],),
        ).fetchall()]
        artifact_payload = _canonical_json({
            "schema_version": "paper-lab-run-artifact/v1",
            "run_id": run_id,
            "workflow_version": run["workflow_version"],
            "input_revision_sha256": run["input_revision_sha256"],
            "results": results,
        })
        requirements_payload = _canonical_json({
            "schema_version": "paper-lab-review-requirements/v1",
            "workflow_version": run["workflow_version"],
            "phases": requirements,
            "required_release_state": "independent_pass_certificate",
        })
        artifact_hash = hashlib.sha256(artifact_payload.encode("utf-8")).hexdigest()
        requirements_hash = hashlib.sha256(requirements_payload.encode("utf-8")).hexdigest()
        return ReviewMaterial(
            gate_name="paper_lab_reading",
            gate_version="1",
            subject_urn=f"qrh:paper-lab:reading-run:{run_id}",
            subject_version_urn=(
                f"qrh:paper-lab:reading-run-version:{run_id}:"
                f"{artifact_hash}:{requirements_hash}"
            ),
            run_artifact_hash=artifact_hash,
            requirements_manifest_hash=requirements_hash,
        )

    def review_material(self, run_id: str) -> ReviewMaterial:
        with paper_lab_connection(self.settings) as connection:
            return self._review_material_from_connection(connection, run_id)

    def review_run(
        self,
        run_id: str,
        *,
        verdict: Literal["pass", "reject"],
        reason: str,
        certificate_urn: str | None = None,
    ) -> RunOutcome:
        if not reason.strip():
            raise ValueError("review reason is required")
        certificate = None
        expected_material = self.review_material(run_id)
        if verdict == "pass":
            if not certificate_urn:
                raise ReviewCertificateMismatch("pass review requires a review certificate")
            certificate = ReviewAuthority(self.settings).verify_certificate(
                certificate_urn,
                gate_name=expected_material.gate_name,
                gate_version=expected_material.gate_version,
                subject_urn=expected_material.subject_urn,
                subject_version_urn=expected_material.subject_version_urn,
                artifact_manifest_hash=expected_material.run_artifact_hash,
                requirements_manifest_hash=expected_material.requirements_manifest_hash,
            )
            verify_independent_review_certificate(self.settings, run_id, certificate)
        now = utc_now()
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                run = connection.execute(
                    "SELECT status,attempt FROM reading_run WHERE run_id=?", (run_id,)
                ).fetchone()
                if run is None:
                    raise KeyError(run_id)
                if run["status"] != "awaiting_review":
                    raise RuntimeError(f"run is not awaiting review: {run['status']}")
                status = "releasable" if verdict == "pass" else "failed"
                material = self._review_material_from_connection(connection, run_id)
                if material != expected_material:
                    raise ReviewCertificateMismatch("reading run material changed during review")
                event_payload: dict[str, object] = {"verdict": verdict, "reason": reason}
                if verdict == "pass":
                    assert certificate is not None
                    connection.execute(
                        """
                        INSERT INTO reading_review_receipt(
                            run_id,certificate_urn,certificate_hash,run_artifact_hash,
                            requirements_manifest_hash,review_artifact_hash,review_set_hash,
                            reviewer_identity_hash,consumed_at
                        ) VALUES(?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            run_id, certificate.certificate_urn, certificate.certificate_hash,
                            material.run_artifact_hash, material.requirements_manifest_hash,
                            certificate.spec.review_artifact_hash,
                            certificate.spec.review_set_hash,
                            certificate.spec.reviewer_identity_hash,
                            now,
                        ),
                    )
                    event_payload.update({
                        "certificate_urn": certificate.certificate_urn,
                        "certificate_hash": certificate.certificate_hash,
                        "run_artifact_hash": material.run_artifact_hash,
                        "requirements_manifest_hash": material.requirements_manifest_hash,
                        "review_artifact_hash": certificate.spec.review_artifact_hash,
                        "review_set_hash": certificate.spec.review_set_hash,
                        "reviewer_identity_hash": certificate.spec.reviewer_identity_hash,
                    })
                self._event(
                    connection, "reading_run", run_id, "reading_reviewed", event_payload, now,
                )
                connection.execute(
                    "UPDATE reading_run SET status=?,error_code=?,error_detail=?,updated_at=? WHERE run_id=?",
                    (
                        status,
                        None if verdict == "pass" else "review_rejected",
                        None if verdict == "pass" else reason,
                        now,
                        run_id,
                    ),
                )
                return RunOutcome(run_id, status, int(run["attempt"]))

    def fail_run(self, run_id: str, error_code: str, error_detail: str) -> RunOutcome:
        if not error_code.strip() or not error_detail.strip():
            raise ValueError("execution failure requires code and detail")
        now = utc_now()
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                run = connection.execute(
                    "SELECT status,attempt FROM reading_run WHERE run_id=?", (run_id,)
                ).fetchone()
                if run is None:
                    raise KeyError(run_id)
                if run["status"] not in {"queued", "running"}:
                    raise RuntimeError(f"run cannot fail from status: {run['status']}")
                connection.execute(
                    """
                    UPDATE reading_run
                    SET status='failed',error_code=?,error_detail=?,updated_at=?
                    WHERE run_id=?
                    """,
                    (error_code.strip(), error_detail.strip()[:4000], now, run_id),
                )
                self._event(
                    connection, "reading_run", run_id, "reading_execution_failed",
                    {"error_code": error_code.strip(), "error_detail": error_detail.strip()[:4000]},
                    now,
                )
                return RunOutcome(run_id, "failed", int(run["attempt"]))

    def publish_run(self, run_id: str) -> RunOutcome:
        with paper_lab_connection(self.settings) as connection:
            preflight = connection.execute(
                """
                SELECT run.status,receipt.certificate_urn,receipt.certificate_hash,
                       receipt.run_artifact_hash,receipt.requirements_manifest_hash,
                       receipt.review_artifact_hash,receipt.review_set_hash,
                       receipt.reviewer_identity_hash
                FROM reading_run AS run
                LEFT JOIN reading_review_receipt AS receipt ON receipt.run_id=run.run_id
                WHERE run.run_id=?
                """,
                (run_id,),
            ).fetchone()
        if preflight is None:
            raise KeyError(run_id)
        if preflight["status"] != "releasable":
            raise RuntimeError(f"run is not releasable: {preflight['status']}")
        if not preflight["certificate_urn"]:
            raise ReviewCertificateMismatch("releasable run has no review certificate receipt")
        material = self.review_material(run_id)
        certificate = ReviewAuthority(self.settings).verify_certificate(
            preflight["certificate_urn"],
            gate_name=material.gate_name,
            gate_version=material.gate_version,
            subject_urn=material.subject_urn,
            subject_version_urn=material.subject_version_urn,
            artifact_manifest_hash=material.run_artifact_hash,
            requirements_manifest_hash=material.requirements_manifest_hash,
        )
        verify_independent_review_certificate(self.settings, run_id, certificate)
        receipt_material = (
            preflight["certificate_hash"],
            preflight["run_artifact_hash"],
            preflight["requirements_manifest_hash"],
            preflight["review_artifact_hash"],
            preflight["review_set_hash"],
            preflight["reviewer_identity_hash"],
        )
        certificate_material = (
            certificate.certificate_hash,
            material.run_artifact_hash,
            material.requirements_manifest_hash,
            certificate.spec.review_artifact_hash,
            certificate.spec.review_set_hash,
            certificate.spec.reviewer_identity_hash,
        )
        if receipt_material != certificate_material:
            raise ReviewCertificateMismatch(
                "review receipt differs from the independently signed certificate"
            )
        now = utc_now()
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                run = connection.execute(
                    """
                    SELECT rr.status,rr.attempt,lp.paper_id,receipt.certificate_urn
                    FROM reading_run rr
                    JOIN lab_paper_version lpv ON lpv.paper_version_id=rr.paper_version_id
                    JOIN lab_paper lp ON lp.paper_id=lpv.paper_id
                    LEFT JOIN reading_review_receipt AS receipt ON receipt.run_id=rr.run_id
                    WHERE rr.run_id=?
                    """,
                    (run_id,),
                ).fetchone()
                if run is None:
                    raise KeyError(run_id)
                if run["status"] != "releasable":
                    raise RuntimeError(f"run is not releasable: {run['status']}")
                if run["certificate_urn"] != certificate.certificate_urn:
                    raise ReviewCertificateMismatch("review certificate changed during publish")
                if self._review_material_from_connection(connection, run_id) != material:
                    raise ReviewCertificateMismatch("reading run material changed during publish")
                connection.execute(
                    "UPDATE reading_run SET status='published',updated_at=? WHERE run_id=?",
                    (now, run_id),
                )
                connection.execute(
                    "UPDATE lab_paper SET lifecycle_status='published',updated_at=? WHERE paper_id=?",
                    (now, run["paper_id"]),
                )
                self._event(connection, "reading_run", run_id, "reading_published", {}, now)
                return RunOutcome(run_id, "published", int(run["attempt"]))

    def list_papers(
        self,
        *,
        rating: str | None = None,
        model: str | None = None,
        market: str | None = None,
        after: int | None = None,
        before: int | None = None,
        source: str | None = None,
        keyword: str | None = None,
        status: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[dict[str, object]]:
        if limit < 1 or limit > 1000 or offset < 0:
            raise ValueError("invalid pagination")
        filters = {
            "rating": rating,
            "model_type": model,
            "asset_market": market,
            "source_type": source,
        }
        rows: list[dict[str, object]] = []
        with paper_lab_connection(self.settings) as connection:
            db_rows = connection.execute(
                """
                SELECT lp.paper_id,lp.legacy_id,lp.canonical_title,lp.lifecycle_status,
                       rr.payload_json,lpv.paper_version_id,lpv.asset_relative_path,
                       run.status AS reading_status,run.attempt AS reading_attempt
                FROM lab_paper lp
                JOIN lab_paper_version lpv ON lpv.paper_id=lp.paper_id
                LEFT JOIN reading_run run ON run.paper_version_id=lpv.paper_version_id
                  AND run.attempt=(
                    SELECT max(run2.attempt) FROM reading_run run2
                    WHERE run2.paper_version_id=lpv.paper_version_id
                  )
                LEFT JOIN reading_result rr ON rr.run_id=run.run_id AND rr.result_kind='legacy_record'
                WHERE lpv.created_at=(
                    SELECT max(v2.created_at) FROM lab_paper_version v2 WHERE v2.paper_id=lp.paper_id
                )
                ORDER BY CASE WHEN lp.legacy_id GLOB '[0-9]*' THEN CAST(lp.legacy_id AS INTEGER) ELSE 2147483647 END,
                         lp.canonical_title
                """
            ).fetchall()
            overlay_rows = connection.execute(
                """
                SELECT overlay.paper_id,overlay.field_name,overlay.value_text,
                       overlay.version,overlay.overlay_id
                FROM paper_field_overlay AS overlay
                JOIN (
                    SELECT paper_id,field_name,max(version) AS version
                    FROM paper_field_overlay GROUP BY paper_id,field_name
                ) AS latest
                  ON latest.paper_id=overlay.paper_id
                 AND latest.field_name=overlay.field_name
                 AND latest.version=overlay.version
                ORDER BY overlay.paper_id,overlay.field_name
                """
            ).fetchall()
        overlays: defaultdict[str, dict[str, sqlite3.Row]] = defaultdict(dict)
        for overlay in overlay_rows:
            overlays[overlay["paper_id"]][overlay["field_name"]] = overlay
        for row in db_rows:
            payload = json.loads(row["payload_json"]) if row["payload_json"] else {}
            item: dict[str, object] = {
                **payload,
                "paper_id": row["paper_id"],
                "legacy_id": row["legacy_id"],
                "title": row["canonical_title"],
                "source_title": row["canonical_title"],
                "lifecycle_status": row["lifecycle_status"],
                "paper_version_id": row["paper_version_id"],
                "asset_relative_path": row["asset_relative_path"],
                "reading_status": row["reading_status"],
                "reading_attempt": row["reading_attempt"],
                "field_overlay_versions": {},
                "field_overlay_ids": {},
            }
            for field_name, overlay in overlays[row["paper_id"]].items():
                item[field_name] = overlay["value_text"]
                item["field_overlay_versions"][field_name] = overlay["version"]  # type: ignore[index]
                item["field_overlay_ids"][field_name] = overlay["overlay_id"]  # type: ignore[index]
            if status and status not in {
                row["lifecycle_status"],
                row["reading_status"],
                str(item.get("status") or ""),
            }:
                continue
            try:
                start_year = int(item["start_year"])
            except (KeyError, TypeError, ValueError):
                start_year = None
            try:
                end_year = int(item["end_year"])
            except (KeyError, TypeError, ValueError):
                end_year = None
            if after is not None and (start_year is None or start_year < after):
                continue
            if before is not None and (end_year is None or end_year > before):
                continue
            if any(value and value.casefold() not in str(item.get(field) or "").casefold() for field, value in filters.items()):
                continue
            if keyword:
                haystack = "\n".join(
                    str(value) for key, value in item.items()
                    if key not in {"field_overlay_versions", "field_overlay_ids"}
                ).casefold()
                if keyword.casefold() not in haystack:
                    continue
            rows.append(item)
        return rows[offset:offset + limit]

    def paper_detail(self, paper_id: str) -> dict[str, object]:
        rows = [row for row in self.list_papers(limit=1000) if row["paper_id"] == paper_id]
        if not rows:
            raise KeyError(paper_id)
        result = rows[0]
        with paper_lab_connection(self.settings) as connection:
            result["notes"] = [dict(row) for row in connection.execute(
                "SELECT * FROM lab_note WHERE paper_id=? ORDER BY is_canonical DESC,created_at",
                (paper_id,),
            ).fetchall()]
            result["quarantine"] = [dict(row) for row in connection.execute(
                "SELECT * FROM quarantine_record WHERE paper_id=? ORDER BY severity,issue_code",
                (paper_id,),
            ).fetchall()]
        return result

    def save_paper_field(
        self,
        paper_id: str,
        field_name: str,
        value: object,
        *,
        expected_version: int,
        actor_display_name: str,
        reason: str,
        idempotency_key: str,
    ) -> dict[str, object]:
        if field_name not in EDITABLE_PAPER_FIELDS:
            raise ValueError("paper field is not editable")
        value_text = str(value)
        if len(value_text) > 100000:
            raise ValueError("paper field value exceeds 100000 characters")
        if expected_version < 0:
            raise ValueError("expected_version must be non-negative")
        actor = actor_display_name.strip()
        if not actor or len(actor) > 160:
            raise ValueError("actor_display_name is invalid")
        if len(reason) > 2000:
            raise ValueError("reason is too long")
        request = {
            "command": "save_paper_field",
            "paper_id": paper_id,
            "field_name": field_name,
            "value": value_text,
            "expected_version": expected_version,
            "actor_display_name": actor,
            "reason": reason,
        }
        request_payload = _canonical_json(request)
        request_hash = hashlib.sha256(request_payload.encode("utf-8")).hexdigest()
        now = utc_now()
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                receipt = connection.execute(
                    """
                    SELECT command_kind,request_sha256,response_json
                    FROM paper_lab_command_receipt WHERE idempotency_key=?
                    """,
                    (idempotency_key,),
                ).fetchone()
                if receipt is not None:
                    if (
                        receipt["command_kind"] != "save_paper_field"
                        or receipt["request_sha256"] != request_hash
                    ):
                        raise PaperLabIdempotencyConflict(
                            "idempotency key was already used for a different command"
                        )
                    response = json.loads(receipt["response_json"])
                    response["replayed"] = True
                    return response
                material = connection.execute(
                    """
                    SELECT paper.paper_id,version.paper_version_id,version.content_sha256
                    FROM lab_paper AS paper
                    JOIN lab_paper_version AS version ON version.paper_id=paper.paper_id
                    WHERE paper.paper_id=?
                    ORDER BY version.created_at DESC,version.paper_version_id DESC LIMIT 1
                    """,
                    (paper_id,),
                ).fetchone()
                if material is None:
                    raise KeyError(paper_id)
                previous = connection.execute(
                    """
                    SELECT overlay_id,version FROM paper_field_overlay
                    WHERE paper_id=? AND field_name=? ORDER BY version DESC LIMIT 1
                    """,
                    (paper_id, field_name),
                ).fetchone()
                current_version = int(previous["version"]) if previous else 0
                if current_version != expected_version:
                    raise PaperFieldVersionConflict(
                        f"paper field version changed: expected {expected_version}, current {current_version}"
                    )
                version = current_version + 1
                overlay_id = stable_public_id(
                    "laboverlay", paper_id, field_name, str(version), request_hash
                )
                connection.execute(
                    """
                    INSERT INTO paper_field_overlay(
                        overlay_id,paper_id,paper_version_id,field_name,value_text,version,
                        supersedes_overlay_id,base_content_sha256,actor_kind,
                        actor_display_name,reason,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,'local_researcher',?,?,?)
                    """,
                    (
                        overlay_id, paper_id, material["paper_version_id"], field_name,
                        value_text, version, previous["overlay_id"] if previous else None,
                        material["content_sha256"], actor, reason, now,
                    ),
                )
                self._event(
                    connection,
                    "lab_paper",
                    paper_id,
                    "paper_field_overlay_saved",
                    {
                        "overlay_id": overlay_id,
                        "paper_id": paper_id,
                        "paper_version_id": material["paper_version_id"],
                        "field_name": field_name,
                        "value": value_text,
                        "version": version,
                        "supersedes_overlay_id": previous["overlay_id"] if previous else None,
                        "base_content_sha256": material["content_sha256"],
                        "request_sha256": request_hash,
                        "request": request,
                    },
                    now,
                )
                response = {
                    "paper_id": paper_id,
                    "paper_version_id": material["paper_version_id"],
                    "overlay_id": overlay_id,
                    "field_name": field_name,
                    "value": value_text,
                    "version": version,
                    "replayed": False,
                }
                connection.execute(
                    """
                    INSERT INTO paper_lab_command_receipt(
                        idempotency_key,command_kind,request_sha256,response_json,created_at
                    ) VALUES(?,'save_paper_field',?,?,?)
                    """,
                    (idempotency_key, request_hash, _canonical_json(response), now),
                )
        return response

    def validate_blueprint(self, components: list[dict[str, object]]) -> BlueprintValidation:
        errors: list[dict[str, object]] = []
        warnings: list[dict[str, object]] = []
        with paper_lab_connection(self.settings) as connection:
            component_rows: dict[str, sqlite3.Row] = {}
            for item in components:
                component_id = str(item.get("component_id") or "")
                row = connection.execute(
                    "SELECT * FROM concept_component WHERE component_id=?", (component_id,)
                ).fetchone()
                if row is None:
                    errors.append({"code": "component_not_found", "component_id": component_id})
                else:
                    component_rows[component_id] = row
            rules = [json.loads(row["rule_json"]) for row in connection.execute(
                "SELECT rule_json FROM compatibility_rule WHERE active=1 ORDER BY legacy_rule_id"
            ).fetchall()]
        if errors:
            return BlueprintValidation(False, tuple(errors), tuple(warnings))
        ordered = sorted(components, key=lambda item: (int(item.get("layer_order", 0)), int(item.get("ordinal", 0))))
        upstream: set[str] = set()
        selected_legacy: set[str] = set()
        by_layer: defaultdict[str, list[str]] = defaultdict(list)
        for item in ordered:
            row = component_rows[str(item["component_id"])]
            payload = json.loads(row["automatic_payload_json"])
            selected_legacy.add(row["legacy_component_id"])
            layer = str(item.get("layer") or row["layer"])
            by_layer[layer].append(row["legacy_component_id"])
            inputs = set(payload.get("input_types") or [])
            if upstream and inputs and not (upstream & inputs):
                target = warnings if bool(item.get("forced")) else errors
                target.append({
                    "code": "type_incompatible",
                    "component_id": item["component_id"],
                    "upstream_outputs": sorted(upstream),
                    "input_types": sorted(inputs),
                })
            outputs = set(payload.get("output_types") or [])
            if outputs:
                upstream = outputs
        for rule in rules:
            trigger = rule.get("trigger_block")
            if trigger not in selected_legacy:
                continue
            severity = rule.get("severity", "soft")
            target = errors if severity == "hard" else warnings
            for layer in rule.get("incompatible_layers", []):
                if by_layer.get(layer):
                    target.append({"code": rule.get("id"), "layer": layer})
            required = rule.get("required_upstream_output_type")
            if required and not any(
                required in (json.loads(row["automatic_payload_json"]).get("output_types") or [])
                for row in component_rows.values()
            ):
                target.append({"code": rule.get("id"), "required_type": required})
            compatible_losses = set(rule.get("compatible_loss_blocks") or [])
            if compatible_losses and not (compatible_losses & selected_legacy):
                target.append({"code": rule.get("id"), "compatible_loss_blocks": sorted(compatible_losses)})
        return BlueprintValidation(not errors, tuple(errors), tuple(warnings))

    def save_blueprint(
        self,
        name: str,
        objective: str,
        components: list[dict[str, object]],
        *,
        blueprint_id: str | None = None,
        idempotency_key: str,
    ) -> dict[str, object]:
        if not name.strip():
            raise ValueError("blueprint name is required")
        validation = self.validate_blueprint(components)
        now = utc_now()
        bp_id = blueprint_id or stable_public_id("labblueprint", name, now)
        request_payload = _canonical_json({
            "name": name.strip(),
            "objective": objective,
            "components": components,
            "blueprint_id": blueprint_id,
        })
        request_hash = hashlib.sha256(request_payload.encode("utf-8")).hexdigest()
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                receipt = connection.execute(
                    "SELECT request_sha256,response_json FROM paper_lab_command_receipt WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                if receipt is not None:
                    if receipt["request_sha256"] != request_hash:
                        raise PaperLabIdempotencyConflict(
                            "idempotency key was already used for a different blueprint command"
                        )
                    replayed = json.loads(receipt["response_json"])
                    replayed["replayed"] = True
                    return replayed
                current = connection.execute(
                    "SELECT max(version) FROM blueprint_version WHERE blueprint_id=?", (bp_id,)
                ).fetchone()[0]
                version = int(current or 0) + 1
                connection.execute(
                    """
                    INSERT INTO architecture_blueprint(
                        blueprint_id,name,objective,lifecycle_status,created_at,updated_at
                    ) VALUES(?,?,?,'draft',?,?)
                    ON CONFLICT(blueprint_id) DO UPDATE SET
                        name=excluded.name,objective=excluded.objective,updated_at=excluded.updated_at
                    """,
                    (bp_id, name.strip(), objective, now, now),
                )
                version_id = stable_public_id("labblueprintver", bp_id, str(version))
                connection.execute(
                    """
                    INSERT INTO blueprint_version(
                        blueprint_version_id,blueprint_id,version,constraints_json,
                        validation_status,validation_report_json,created_at
                    ) VALUES(?,?,?,'{}',?,?,?)
                    """,
                    (
                        version_id, bp_id, version, "valid" if validation.valid else "invalid",
                        _canonical_json(validation.to_dict()), now,
                    ),
                )
                for item in components:
                    connection.execute(
                        """
                        INSERT INTO blueprint_component(
                            blueprint_version_id,component_id,layer,ordinal,forced
                        ) VALUES(?,?,?,?,?)
                        """,
                        (
                            version_id, str(item["component_id"]), str(item["layer"]),
                            int(item.get("ordinal", 0)), int(bool(item.get("forced"))),
                        ),
                    )
                self._event(
                    connection, "architecture_blueprint", bp_id, "blueprint_version_saved",
                    {
                        "version_id": version_id,
                        "validation": validation.to_dict(),
                        # reviewed-runtime resume 需要把可变蓝图行、组件集合与
                        # command receipt 的 request hash 形成可重放闭包。
                        "request_sha256": request_hash,
                        "request": json.loads(request_payload),
                    },
                    now,
                )
                response = {
                    "blueprint_id": bp_id,
                    "blueprint_version_id": version_id,
                    "version": version,
                    "validation": validation.to_dict(),
                    "replayed": False,
                }
                connection.execute(
                    """
                    INSERT INTO paper_lab_command_receipt(
                        idempotency_key,command_kind,request_sha256,response_json,created_at
                    ) VALUES(?,'save_blueprint',?,?,?)
                    """,
                    (idempotency_key, request_hash, _canonical_json(response), now),
                )
        return response

    @staticmethod
    def _event(
        connection: sqlite3.Connection,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: object,
        now: str,
    ) -> None:
        event_payload = _canonical_json(payload)
        event_id = stable_public_id(
            "labevent", aggregate_type, aggregate_id, event_type, event_payload, now,
        )
        connection.execute(
            """
            INSERT INTO paper_lab_event(
                event_id,aggregate_type,aggregate_id,event_type,payload_json,created_at
            ) VALUES(?,?,?,?,?,?)
            """,
            (event_id, aggregate_type, aggregate_id, event_type, event_payload, now),
        )
