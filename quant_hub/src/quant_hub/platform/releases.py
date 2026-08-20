from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3

from quant_hub.config import Settings
from quant_hub.ids import new_public_id, sha256_hex

from .db import connect_database, immediate_transaction, utc_now
from .migrations import migrate_up
from .workflow import canonical_json


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DOMAIN_RE = re.compile(r"^(archive|evidence|paper_lab)$")


class ReleaseAuthorityError(RuntimeError):
    """platform release authority 无法证明或消费候选时的 fail-closed 错误。"""


class ReleaseCertificateMismatch(ReleaseAuthorityError):
    pass


def _hash(value: str, field: str) -> str:
    if not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{field} must be lowercase SHA-256 hex")
    return value


def _text(value: str, field: str) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{field} must be non-empty and trimmed")
    return value


@dataclass(frozen=True, slots=True)
class ReleaseCandidateSpec:
    domain: str
    subject_urn: str
    subject_version_urn: str
    artifact_manifest_hash: str
    source_snapshot_hash: str
    projection_revision: str
    requirements_manifest_hash: str

    def __post_init__(self) -> None:
        if not _DOMAIN_RE.fullmatch(self.domain):
            raise ValueError("release domain is not supported")
        _text(self.subject_urn, "subject_urn")
        _text(self.subject_version_urn, "subject_version_urn")
        _hash(self.artifact_manifest_hash, "artifact_manifest_hash")
        _hash(self.source_snapshot_hash, "source_snapshot_hash")
        _text(self.projection_revision, "projection_revision")
        _hash(self.requirements_manifest_hash, "requirements_manifest_hash")


@dataclass(frozen=True, slots=True)
class CandidateRegistration:
    candidate_id: str
    spec: ReleaseCandidateSpec
    status: str
    created: bool


@dataclass(frozen=True, slots=True)
class ReleaseDecision:
    decision_id: str
    candidate_id: str
    decision_hash: str
    verdict: str
    created: bool


@dataclass(frozen=True, slots=True)
class ReleaseCertificate:
    snapshot_id: str
    snapshot_urn: str
    candidate_id: str
    decision_id: str
    decision_hash: str
    spec: ReleaseCandidateSpec
    issuance_key: str
    issued_at: str
    created: bool


def _spec_from_row(row: sqlite3.Row) -> ReleaseCandidateSpec:
    return ReleaseCandidateSpec(
        domain=str(row["domain"]),
        subject_urn=str(row["subject_urn"]),
        subject_version_urn=str(row["subject_version_urn"]),
        artifact_manifest_hash=str(row["artifact_manifest_hash"]),
        source_snapshot_hash=str(row["source_snapshot_hash"]),
        projection_revision=str(row["projection_revision"]),
        requirements_manifest_hash=str(row["requirements_manifest_hash"]),
    )


def _decision_hash(
    row: sqlite3.Row,
    *,
    deterministic_gate_hash: str,
    review_set_hash: str,
    reconciliation_hash: str,
    verdict: str,
) -> str:
    payload = {
        "schema_version": "platform-release-decision/v2-requirements-bound",
        "candidate_id": str(row["candidate_id"]),
        "domain": str(row["domain"]),
        "subject_urn": str(row["subject_urn"]),
        "subject_version_urn": str(row["subject_version_urn"]),
        "artifact_manifest_hash": str(row["artifact_manifest_hash"]),
        "source_snapshot_hash": str(row["source_snapshot_hash"]),
        "requirements_manifest_hash": str(row["requirements_manifest_hash"]),
        "projection_revision": str(row["projection_revision"]),
        "deterministic_gate_hash": deterministic_gate_hash,
        "review_set_hash": review_set_hash,
        "reconciliation_hash": reconciliation_hash,
        "verdict": verdict,
    }
    return sha256_hex(canonical_json(payload).encode("utf-8"))


class ReleaseAuthority:
    """签发并核验 platform release certificate；目标域只能消费已登记 PASS 快照。"""

    def __init__(self, settings: Settings):
        self.settings = settings

    def initialize(self) -> list[int]:
        connection = connect_database(self.settings.database_path)
        try:
            return migrate_up(connection, self.settings.migration_root)
        finally:
            connection.close()

    def register_candidate(self, spec: ReleaseCandidateSpec) -> CandidateRegistration:
        self.initialize()
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                row = connection.execute(
                    """
                    SELECT * FROM release_candidate
                    WHERE domain=? AND subject_urn=? AND subject_version_urn=?
                    """,
                    (spec.domain, spec.subject_urn, spec.subject_version_urn),
                ).fetchone()
                created = row is None
                if row is None:
                    candidate_id = new_public_id("cand")
                    connection.execute(
                        """
                        INSERT INTO release_candidate(
                            candidate_id,domain,subject_urn,subject_version_urn,
                            artifact_manifest_hash,source_snapshot_hash,
                            requirements_manifest_hash,projection_revision,status,created_at
                        ) VALUES(?,?,?,?,?,?,?,?,'staging',?)
                        """,
                        (
                            candidate_id,
                            spec.domain,
                            spec.subject_urn,
                            spec.subject_version_urn,
                            spec.artifact_manifest_hash,
                            spec.source_snapshot_hash,
                            spec.requirements_manifest_hash,
                            spec.projection_revision,
                            utc_now(),
                        ),
                    )
                    status = "staging"
                else:
                    candidate_id = str(row["candidate_id"])
                    actual = (
                        str(row["artifact_manifest_hash"]),
                        str(row["source_snapshot_hash"]),
                        str(row["requirements_manifest_hash"]),
                        str(row["projection_revision"]),
                    )
                    expected = (
                        spec.artifact_manifest_hash,
                        spec.source_snapshot_hash,
                        spec.requirements_manifest_hash,
                        spec.projection_revision,
                    )
                    if actual != expected:
                        raise ReleaseAuthorityError(
                            "subject version is already bound to different release material"
                        )
                    status = str(row["status"])
                return CandidateRegistration(candidate_id, spec, status, created)
        finally:
            connection.close()

    def record_decision(
        self,
        candidate_id: str,
        *,
        deterministic_gate_hash: str,
        review_set_hash: str,
        reconciliation_hash: str,
        verdict: str,
    ) -> ReleaseDecision:
        _hash(deterministic_gate_hash, "deterministic_gate_hash")
        _hash(review_set_hash, "review_set_hash")
        _hash(reconciliation_hash, "reconciliation_hash")
        if verdict not in {"pass", "fail"}:
            raise ValueError("verdict must be pass or fail")
        self.initialize()
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                candidate = connection.execute(
                    "SELECT * FROM release_candidate WHERE candidate_id=?",
                    (candidate_id,),
                ).fetchone()
                if candidate is None:
                    raise ReleaseAuthorityError("release candidate does not exist")
                expected_hash = _decision_hash(
                    candidate,
                    deterministic_gate_hash=deterministic_gate_hash,
                    review_set_hash=review_set_hash,
                    reconciliation_hash=reconciliation_hash,
                    verdict=verdict,
                )
                existing = connection.execute(
                    "SELECT * FROM release_decision WHERE candidate_id=?",
                    (candidate_id,),
                ).fetchone()
                if existing is not None:
                    actual = (
                        str(existing["deterministic_gate_hash"]),
                        str(existing["review_set_hash"]),
                        str(existing["reconciliation_hash"]),
                        str(existing["verdict"]),
                        str(existing["decision_hash"]),
                    )
                    expected = (
                        deterministic_gate_hash,
                        review_set_hash,
                        reconciliation_hash,
                        verdict,
                        expected_hash,
                    )
                    if actual != expected:
                        raise ReleaseAuthorityError(
                            "release candidate already has a different immutable decision"
                        )
                    return ReleaseDecision(
                        str(existing["decision_id"]),
                        candidate_id,
                        expected_hash,
                        verdict,
                        False,
                    )
                status = str(candidate["status"])
                if status == "staging":
                    connection.execute(
                        "UPDATE release_candidate SET status='validated' WHERE candidate_id=?",
                        (candidate_id,),
                    )
                    status = "validated"
                if status == "validated":
                    connection.execute(
                        "UPDATE release_candidate SET status='under_review' WHERE candidate_id=?",
                        (candidate_id,),
                    )
                    status = "under_review"
                if status != "under_review":
                    raise ReleaseAuthorityError(
                        f"candidate cannot receive a decision from status {status!r}"
                    )
                decision_id = new_public_id("rdec")
                connection.execute(
                    """
                    INSERT INTO release_decision(
                        decision_id,candidate_id,deterministic_gate_hash,review_set_hash,
                        reconciliation_hash,verdict,decision_hash,created_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        decision_id,
                        candidate_id,
                        deterministic_gate_hash,
                        review_set_hash,
                        reconciliation_hash,
                        verdict,
                        expected_hash,
                        utc_now(),
                    ),
                )
                connection.execute(
                    "UPDATE release_candidate SET status=? WHERE candidate_id=?",
                    ("releasable" if verdict == "pass" else "rejected", candidate_id),
                )
                return ReleaseDecision(
                    decision_id, candidate_id, expected_hash, verdict, True
                )
        finally:
            connection.close()

    def decision_for_candidate(self, candidate_id: str) -> ReleaseDecision | None:
        """Return an already sealed decision after recomputing its integrity hash.

        A reviewed domain candidate can be packaged into more than one unified
        delivery without mutating its original decision.  Callers may reuse a
        valid PASS decision and issue a new, packaging-specific snapshot; they
        must not replace the immutable review tuple with a later deployment gate.
        """

        self.initialize()
        connection = connect_database(self.settings.database_path)
        try:
            row = connection.execute(
                """
                SELECT decision.*,candidate.*
                FROM release_decision AS decision
                JOIN release_candidate AS candidate USING(candidate_id)
                WHERE decision.candidate_id=?
                """,
                (candidate_id,),
            ).fetchone()
            if row is None:
                return None
            expected_hash = _decision_hash(
                row,
                deterministic_gate_hash=str(row["deterministic_gate_hash"]),
                review_set_hash=str(row["review_set_hash"]),
                reconciliation_hash=str(row["reconciliation_hash"]),
                verdict=str(row["verdict"]),
            )
            if expected_hash != str(row["decision_hash"]):
                raise ReleaseAuthorityError("stored release decision hash is invalid")
            return ReleaseDecision(
                str(row["decision_id"]),
                candidate_id,
                expected_hash,
                str(row["verdict"]),
                False,
            )
        finally:
            connection.close()

    def issue_snapshot(
        self,
        decision_id: str,
        *,
        requirements_manifest_hash: str,
        issuance_key: str,
    ) -> ReleaseCertificate:
        _hash(requirements_manifest_hash, "requirements_manifest_hash")
        _hash(issuance_key, "issuance_key")
        self.initialize()
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                row = connection.execute(
                    """
                    SELECT decision.*,candidate.*
                    FROM release_decision AS decision
                    JOIN release_candidate AS candidate USING(candidate_id)
                    WHERE decision.decision_id=?
                    """,
                    (decision_id,),
                ).fetchone()
                if row is None:
                    raise ReleaseAuthorityError("release decision does not exist")
                if requirements_manifest_hash != row["requirements_manifest_hash"]:
                    raise ReleaseAuthorityError(
                        "release requirements differ from the reviewed candidate"
                    )
                if row["verdict"] != "pass" or row["status"] not in (
                    "releasable",
                    "released",
                ):
                    raise ReleaseAuthorityError("only a PASS releasable decision can be issued")
                expected_decision_hash = _decision_hash(
                    row,
                    deterministic_gate_hash=str(row["deterministic_gate_hash"]),
                    review_set_hash=str(row["review_set_hash"]),
                    reconciliation_hash=str(row["reconciliation_hash"]),
                    verdict=str(row["verdict"]),
                )
                if expected_decision_hash != row["decision_hash"]:
                    raise ReleaseAuthorityError("stored release decision hash is invalid")
                existing = connection.execute(
                    "SELECT * FROM release_snapshot WHERE decision_id=? AND issuance_key=?",
                    (decision_id, issuance_key),
                ).fetchone()
                if existing is not None:
                    if existing["requirements_manifest_hash"] != requirements_manifest_hash:
                        raise ReleaseAuthorityError(
                            "issuance key is already bound to different requirements"
                        )
                    return self._certificate(existing, row, created=False)
                snapshot_id = new_public_id("rsnp")
                snapshot_urn = f"qrh:release_snapshot:{snapshot_id}"
                issued_at = utc_now()
                connection.execute(
                    """
                    INSERT INTO release_snapshot(
                        snapshot_id,snapshot_urn,candidate_id,decision_id,decision_hash,
                        domain,subject_urn,subject_version_urn,artifact_manifest_hash,
                        source_snapshot_hash,requirements_manifest_hash,projection_revision,
                        issuance_key,issued_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        snapshot_id,
                        snapshot_urn,
                        row["candidate_id"],
                        decision_id,
                        row["decision_hash"],
                        row["domain"],
                        row["subject_urn"],
                        row["subject_version_urn"],
                        row["artifact_manifest_hash"],
                        row["source_snapshot_hash"],
                        requirements_manifest_hash,
                        row["projection_revision"],
                        issuance_key,
                        issued_at,
                    ),
                )
                if row["status"] == "releasable":
                    connection.execute(
                        "UPDATE release_candidate SET status='released' WHERE candidate_id=?",
                        (row["candidate_id"],),
                    )
                payload = {
                    "snapshot_urn": snapshot_urn,
                    "candidate_id": str(row["candidate_id"]),
                    "decision_id": decision_id,
                    "decision_hash": str(row["decision_hash"]),
                    "domain": str(row["domain"]),
                    "subject_urn": str(row["subject_urn"]),
                    "subject_version_urn": str(row["subject_version_urn"]),
                    "artifact_manifest_hash": str(row["artifact_manifest_hash"]),
                    "source_snapshot_hash": str(row["source_snapshot_hash"]),
                    "requirements_manifest_hash": requirements_manifest_hash,
                    "projection_revision": str(row["projection_revision"]),
                    "issuance_key": issuance_key,
                }
                payload_json = canonical_json(payload)
                connection.execute(
                    """
                    INSERT INTO outbox_event(
                        event_id,event_type,event_version,aggregate_urn,payload_json,
                        payload_hash,created_at,published_at
                    ) VALUES(?,'PlatformReleaseSnapshotIssued','1',?,?,?,?,NULL)
                    """,
                    (
                        new_public_id("evt"),
                        snapshot_urn,
                        payload_json,
                        sha256_hex(payload_json.encode("utf-8")),
                        issued_at,
                    ),
                )
                snapshot = connection.execute(
                    "SELECT * FROM release_snapshot WHERE snapshot_id=?",
                    (snapshot_id,),
                ).fetchone()
                assert snapshot is not None
                return self._certificate(snapshot, row, created=True)
        finally:
            connection.close()

    @staticmethod
    def _certificate(
        snapshot: sqlite3.Row, candidate_decision: sqlite3.Row, *, created: bool
    ) -> ReleaseCertificate:
        spec = _spec_from_row(snapshot)
        return ReleaseCertificate(
            snapshot_id=str(snapshot["snapshot_id"]),
            snapshot_urn=str(snapshot["snapshot_urn"]),
            candidate_id=str(snapshot["candidate_id"]),
            decision_id=str(snapshot["decision_id"]),
            decision_hash=str(snapshot["decision_hash"]),
            spec=spec,
            issuance_key=str(snapshot["issuance_key"]),
            issued_at=str(snapshot["issued_at"]),
            created=created,
        )

    def verify_snapshot(
        self,
        snapshot_urn: str,
        decision_hash: str,
        expected: ReleaseCandidateSpec,
    ) -> ReleaseCertificate:
        _text(snapshot_urn, "snapshot_urn")
        _hash(decision_hash, "decision_hash")
        self.initialize()
        connection = connect_database(self.settings.database_path)
        try:
            row = connection.execute(
                """
                SELECT snapshot.*,decision.deterministic_gate_hash,
                       decision.review_set_hash,decision.reconciliation_hash,
                       decision.verdict,candidate.status
                FROM release_snapshot AS snapshot
                JOIN release_decision AS decision USING(decision_id)
                JOIN release_candidate AS candidate USING(candidate_id)
                WHERE snapshot.snapshot_urn=?
                """,
                (snapshot_urn,),
            ).fetchone()
            if row is None:
                raise ReleaseCertificateMismatch("release snapshot is not registered")
            if snapshot_urn != f"qrh:release_snapshot:{row['snapshot_id']}":
                raise ReleaseCertificateMismatch("release snapshot URN is not canonical")
            actual_spec = _spec_from_row(row)
            if actual_spec != expected:
                raise ReleaseCertificateMismatch(
                    "release snapshot does not match the expected candidate material"
                )
            if row["decision_hash"] != decision_hash:
                raise ReleaseCertificateMismatch("release decision hash does not match")
            if row["verdict"] != "pass" or row["status"] != "released":
                raise ReleaseCertificateMismatch("release snapshot is not a released PASS")
            recomputed = _decision_hash(
                row,
                deterministic_gate_hash=str(row["deterministic_gate_hash"]),
                review_set_hash=str(row["review_set_hash"]),
                reconciliation_hash=str(row["reconciliation_hash"]),
                verdict=str(row["verdict"]),
            )
            if recomputed != decision_hash:
                raise ReleaseCertificateMismatch("release decision material is corrupt")
            return self._certificate(row, row, created=False)
        finally:
            connection.close()
