from __future__ import annotations

from dataclasses import dataclass
import json
import re
import sqlite3

from quant_hub.config import Settings
from quant_hub.ids import new_public_id, sha256_hex
from quant_hub.platform.db import connect_database, immediate_transaction, utc_now
from quant_hub.platform.migrations import migrate_up


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GATE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,79}$")


class ReviewCertificateError(RuntimeError):
    pass


class ReviewCertificateMismatch(ReviewCertificateError):
    pass


@dataclass(frozen=True, slots=True)
class ReviewCertificateSpec:
    gate_name: str
    gate_version: str
    subject_urn: str
    subject_version_urn: str
    artifact_manifest_hash: str
    requirements_manifest_hash: str
    review_artifact_hash: str
    review_set_hash: str
    reviewer_identity_hash: str

    def validate(self) -> None:
        if not _GATE.fullmatch(self.gate_name):
            raise ValueError("review gate name is not canonical")
        if not self.gate_version.strip() or len(self.gate_version) > 80:
            raise ValueError("review gate version is required")
        if not self.subject_urn.strip() or not self.subject_version_urn.strip():
            raise ValueError("review subject identity is required")
        for value in (
            self.artifact_manifest_hash,
            self.requirements_manifest_hash,
            self.review_artifact_hash,
            self.review_set_hash,
            self.reviewer_identity_hash,
        ):
            if not _SHA256.fullmatch(value):
                raise ValueError("review certificate hashes must be lowercase SHA-256")


@dataclass(frozen=True, slots=True)
class ReviewCertificate:
    certificate_id: str
    certificate_urn: str
    certificate_hash: str
    issuance_key: str
    issued_at: str
    spec: ReviewCertificateSpec


def _canonical_payload(spec: ReviewCertificateSpec, issuance_key: str, issued_at: str) -> bytes:
    return (
        json.dumps(
            {
                "schema_version": "qrh-review-certificate/v1",
                "gate_name": spec.gate_name,
                "gate_version": spec.gate_version,
                "subject_urn": spec.subject_urn,
                "subject_version_urn": spec.subject_version_urn,
                "artifact_manifest_hash": spec.artifact_manifest_hash,
                "requirements_manifest_hash": spec.requirements_manifest_hash,
                "review_artifact_hash": spec.review_artifact_hash,
                "review_set_hash": spec.review_set_hash,
                "reviewer_identity_hash": spec.reviewer_identity_hash,
                "verdict": "pass",
                "issuance_key": issuance_key,
                "issued_at": issued_at,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def review_certificate_material_hash(
    spec: ReviewCertificateSpec, issuance_key: str, issued_at: str
) -> str:
    """Return the canonical hash used by both issuance and offline verification."""

    spec.validate()
    if not _SHA256.fullmatch(issuance_key):
        raise ValueError("review issuance key must be a lowercase SHA-256")
    if not issued_at.strip():
        raise ValueError("review certificate issuance time is required")
    return sha256_hex(_canonical_payload(spec, issuance_key, issued_at))


class ReviewAuthority:
    """签发并核验绑定冻结 subject/version/artifact 的 PASS review certificate。"""

    def __init__(self, settings: Settings):
        self.settings = settings
        settings.ensure_runtime_directories()
        connection = connect_database(settings.database_path)
        try:
            migrate_up(connection, settings.migration_root)
        finally:
            connection.close()

    @staticmethod
    def _from_row(row: sqlite3.Row) -> ReviewCertificate:
        return ReviewCertificate(
            certificate_id=str(row["certificate_id"]),
            certificate_urn=str(row["certificate_urn"]),
            certificate_hash=str(row["certificate_hash"]),
            issuance_key=str(row["issuance_key"]),
            issued_at=str(row["issued_at"]),
            spec=ReviewCertificateSpec(
                gate_name=str(row["gate_name"]),
                gate_version=str(row["gate_version"]),
                subject_urn=str(row["subject_urn"]),
                subject_version_urn=str(row["subject_version_urn"]),
                artifact_manifest_hash=str(row["artifact_manifest_hash"]),
                requirements_manifest_hash=str(row["requirements_manifest_hash"]),
                review_artifact_hash=str(row["review_artifact_hash"]),
                review_set_hash=str(row["review_set_hash"]),
                reviewer_identity_hash=str(row["reviewer_identity_hash"]),
            ),
        )

    @staticmethod
    def _verify_material(certificate: ReviewCertificate) -> None:
        try:
            expected = review_certificate_material_hash(
                certificate.spec,
                certificate.issuance_key,
                certificate.issued_at,
            )
        except ValueError as error:
            raise ReviewCertificateMismatch(str(error)) from error
        if expected != certificate.certificate_hash:
            raise ReviewCertificateMismatch("review certificate hash does not match material")
        expected_urn = f"qrh:review-certificate:{certificate.certificate_id}"
        if certificate.certificate_urn != expected_urn:
            raise ReviewCertificateMismatch("review certificate URN is not canonical")

    def issue_pass_certificate(
        self,
        spec: ReviewCertificateSpec,
        *,
        issuance_key: str,
    ) -> ReviewCertificate:
        spec.validate()
        if not _SHA256.fullmatch(issuance_key):
            raise ValueError("review issuance key must be a lowercase SHA-256")
        connection = connect_database(self.settings.database_path)
        try:
            with immediate_transaction(connection):
                existing = connection.execute(
                    "SELECT * FROM review_certificate WHERE issuance_key=?",
                    (issuance_key,),
                ).fetchone()
                if existing is not None:
                    certificate = self._from_row(existing)
                    self._verify_material(certificate)
                    if certificate.spec != spec:
                        raise ReviewCertificateMismatch(
                            "review issuance key is already bound to different material"
                        )
                    return certificate
                certificate_id = new_public_id("rvc")
                issued_at = utc_now()
                certificate_hash = review_certificate_material_hash(
                    spec, issuance_key, issued_at
                )
                certificate_urn = f"qrh:review-certificate:{certificate_id}"
                connection.execute(
                    """
                    INSERT INTO review_certificate(
                        certificate_id,certificate_urn,gate_name,gate_version,
                        subject_urn,subject_version_urn,artifact_manifest_hash,
                        requirements_manifest_hash,review_artifact_hash,review_set_hash,
                        reviewer_identity_hash,verdict,issuance_key,certificate_hash,issued_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,'pass',?,?,?)
                    """,
                    (
                        certificate_id,
                        certificate_urn,
                        spec.gate_name,
                        spec.gate_version,
                        spec.subject_urn,
                        spec.subject_version_urn,
                        spec.artifact_manifest_hash,
                        spec.requirements_manifest_hash,
                        spec.review_artifact_hash,
                        spec.review_set_hash,
                        spec.reviewer_identity_hash,
                        issuance_key,
                        certificate_hash,
                        issued_at,
                    ),
                )
            certificate = ReviewCertificate(
                certificate_id=certificate_id,
                certificate_urn=certificate_urn,
                certificate_hash=certificate_hash,
                issuance_key=issuance_key,
                issued_at=issued_at,
                spec=spec,
            )
            self._verify_material(certificate)
            return certificate
        finally:
            connection.close()

    def verify_certificate(
        self,
        certificate_urn: str,
        *,
        gate_name: str,
        gate_version: str,
        subject_urn: str,
        subject_version_urn: str,
        artifact_manifest_hash: str,
        requirements_manifest_hash: str,
    ) -> ReviewCertificate:
        connection = connect_database(self.settings.database_path)
        try:
            row = connection.execute(
                "SELECT * FROM review_certificate WHERE certificate_urn=?",
                (certificate_urn,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise ReviewCertificateMismatch("review certificate is not registered")
        certificate = self._from_row(row)
        self._verify_material(certificate)
        expected = (
            gate_name,
            gate_version,
            subject_urn,
            subject_version_urn,
            artifact_manifest_hash,
            requirements_manifest_hash,
        )
        actual = (
            certificate.spec.gate_name,
            certificate.spec.gate_version,
            certificate.spec.subject_urn,
            certificate.spec.subject_version_urn,
            certificate.spec.artifact_manifest_hash,
            certificate.spec.requirements_manifest_hash,
        )
        if actual != expected:
            raise ReviewCertificateMismatch(
                "review certificate does not match the active subject/version material"
            )
        return certificate


__all__ = [
    "ReviewAuthority",
    "ReviewCertificate",
    "ReviewCertificateError",
    "ReviewCertificateMismatch",
    "ReviewCertificateSpec",
    "review_certificate_material_hash",
]
