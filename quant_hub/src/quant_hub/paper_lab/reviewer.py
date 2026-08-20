from __future__ import annotations

from dataclasses import asdict
import hashlib
import hmac
import json
import os
import re
from typing import Any

from quant_hub.config import Settings
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.reviews import (
    ReviewAuthority,
    ReviewCertificate,
    ReviewCertificateMismatch,
    ReviewCertificateSpec,
)
from .database import paper_lab_connection


_AUTHORITY = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")
_TRUST_ENV = "QRH_PAPER_LAB_REVIEWER_RSA_KEYS"
_SPEC_KEYS = set(ReviewCertificateSpec.__dataclass_fields__)
_INPUT_KEYS = {
    "schema_version",
    "authority_id",
    "run_id",
    "review_decision_id",
    "reviewed_at",
    "verdict",
    "certificate_spec",
}


class ReviewerAuthorityError(ReviewCertificateMismatch):
    pass


def canonical_reviewer_authority_input(payload: dict[str, object]) -> bytes:
    return (
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def reviewer_authority_key_hash(
    authority_id: str,
    public_modulus_hex: str,
    public_exponent: int,
) -> str:
    identity = {
        "schema_version": "paper-lab-reviewer-rsa-key/v1",
        "authority_id": authority_id,
        "algorithm": "rsassa-pkcs1-v1_5-sha256",
        "public_modulus_hex": public_modulus_hex,
        "public_exponent": public_exponent,
    }
    return hashlib.sha256(canonical_reviewer_authority_input(identity)).hexdigest()


def _validated_public_key(modulus_hex: object, exponent: object) -> tuple[str, int, int]:
    if not isinstance(modulus_hex, str) or not modulus_hex:
        raise ReviewerAuthorityError("reviewer public modulus is missing")
    if modulus_hex != modulus_hex.casefold() or any(c not in "0123456789abcdef" for c in modulus_hex):
        raise ReviewerAuthorityError("reviewer public modulus must be lowercase hexadecimal")
    try:
        modulus = int(modulus_hex, 16)
    except ValueError as error:
        raise ReviewerAuthorityError("reviewer public modulus is invalid") from error
    if modulus.bit_length() < 2048 or modulus % 2 == 0:
        raise ReviewerAuthorityError("reviewer RSA key must be at least 2048-bit and odd")
    canonical_modulus = f"{modulus:x}"
    if canonical_modulus != modulus_hex:
        raise ReviewerAuthorityError("reviewer public modulus is not canonical")
    if isinstance(exponent, bool) or not isinstance(exponent, int) or exponent < 3 or exponent % 2 == 0:
        raise ReviewerAuthorityError("reviewer public exponent is invalid")
    return canonical_modulus, exponent, modulus


def _verify_rsa_signature(payload: bytes, signature_hex: object, modulus: int, exponent: int) -> str:
    byte_length = (modulus.bit_length() + 7) // 8
    if (
        not isinstance(signature_hex, str)
        or len(signature_hex) != byte_length * 2
        or signature_hex != signature_hex.casefold()
        or any(c not in "0123456789abcdef" for c in signature_hex)
    ):
        raise ReviewerAuthorityError("reviewer signature is not canonical for the trusted RSA key")
    signature = int(signature_hex, 16)
    if signature >= modulus:
        raise ReviewerAuthorityError("reviewer signature is outside the RSA modulus")
    digest_info = _SHA256_DIGEST_INFO + hashlib.sha256(payload).digest()
    padding_length = byte_length - len(digest_info) - 3
    if padding_length < 8:
        raise ReviewerAuthorityError("reviewer RSA key is too short")
    expected = b"\x00\x01" + (b"\xff" * padding_length) + b"\x00" + digest_info
    observed = pow(signature, exponent, modulus).to_bytes(byte_length, "big")
    if not hmac.compare_digest(expected, observed):
        raise ReviewerAuthorityError("reviewer authority signature is invalid")
    return hashlib.sha256(bytes.fromhex(signature_hex)).hexdigest()


def _spec_from_payload(value: object) -> ReviewCertificateSpec:
    if not isinstance(value, dict) or set(value) != _SPEC_KEYS:
        raise ReviewerAuthorityError("review certificate spec contract mismatch")
    try:
        spec = ReviewCertificateSpec(**value)
        spec.validate()
    except (AttributeError, TypeError, ValueError) as error:
        raise ReviewerAuthorityError(f"review certificate spec is invalid: {error}") from error
    return spec


def _parse_authority_input(value: object) -> tuple[dict[str, object], ReviewCertificateSpec]:
    if not isinstance(value, dict) or set(value) != _INPUT_KEYS:
        raise ReviewerAuthorityError("reviewer authority input contract mismatch")
    if value.get("schema_version") != "paper-lab-presigned-review/v1":
        raise ReviewerAuthorityError("unsupported reviewer authority input schema")
    if value.get("verdict") != "pass":
        raise ReviewerAuthorityError("only an independently signed PASS can authorize release")
    authority_id = value.get("authority_id")
    if not isinstance(authority_id, str) or not _AUTHORITY.fullmatch(authority_id):
        raise ReviewerAuthorityError("reviewer authority_id is invalid")
    for key in ("run_id", "review_decision_id", "reviewed_at"):
        item = value.get(key)
        if not isinstance(item, str) or not item.strip() or len(item) > 256:
            raise ReviewerAuthorityError(f"reviewer authority input {key} is invalid")
    spec = _spec_from_payload(value.get("certificate_spec"))
    if spec.subject_urn != f"qrh:paper-lab:reading-run:{value['run_id']}":
        raise ReviewerAuthorityError("reviewer authority input is not bound to its Paper Lab run")
    return value, spec


def _trusted_key(authority_id: str) -> tuple[str, int, int]:
    raw = os.environ.get(_TRUST_ENV)
    if not raw:
        raise ReviewerAuthorityError(
            f"trusted reviewer keys are not configured in {_TRUST_ENV}"
        )
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as error:
        raise ReviewerAuthorityError("trusted reviewer key registry is invalid JSON") from error
    if not isinstance(document, dict) or authority_id not in document:
        raise ReviewerAuthorityError("reviewer authority is not in the trusted key registry")
    entry = document[authority_id]
    if not isinstance(entry, dict) or set(entry) != {"public_modulus_hex", "public_exponent"}:
        raise ReviewerAuthorityError("trusted reviewer key entry is invalid")
    return _validated_public_key(entry["public_modulus_hex"], entry["public_exponent"])


class PaperLabReviewerAuthority:
    """Registrar for a reviewer-produced, RSA-signed PASS input.

    The Paper Lab producer never calls this with review hashes.  An independent
    reviewer signs the complete run/artifact/requirements decision, and this
    registrar records that immutable input before the service may consume the
    resulting platform certificate URN.
    """

    def __init__(self, settings: Settings):
        self.settings = settings

    def register_presigned_pass_certificate(self, document: object) -> ReviewCertificate:
        if not isinstance(document, dict) or set(document) != {"authority_input", "signature_hex"}:
            raise ReviewerAuthorityError("presigned reviewer document contract mismatch")
        authority_input, spec = _parse_authority_input(document["authority_input"])
        authority_id = str(authority_input["authority_id"])
        modulus_hex, exponent, modulus = _trusted_key(authority_id)
        key_hash = reviewer_authority_key_hash(authority_id, modulus_hex, exponent)
        if spec.reviewer_identity_hash != key_hash:
            raise ReviewerAuthorityError(
                "reviewer_identity_hash is not the trusted authority key identity"
            )
        signed_payload = canonical_reviewer_authority_input(authority_input)
        input_sha256 = hashlib.sha256(signed_payload).hexdigest()
        signature_sha256 = _verify_rsa_signature(
            signed_payload,
            document["signature_hex"],
            modulus,
            exponent,
        )

        # Import lazily to keep the service's verification dependency acyclic.
        from .service import PaperLabService

        material = PaperLabService(self.settings).review_material(str(authority_input["run_id"]))
        expected = (
            material.gate_name,
            material.gate_version,
            material.subject_urn,
            material.subject_version_urn,
            material.run_artifact_hash,
            material.requirements_manifest_hash,
        )
        actual = (
            spec.gate_name,
            spec.gate_version,
            spec.subject_urn,
            spec.subject_version_urn,
            spec.artifact_manifest_hash,
            spec.requirements_manifest_hash,
        )
        if actual != expected:
            raise ReviewerAuthorityError("presigned reviewer input does not match active run material")

        certificate = ReviewAuthority(self.settings).issue_pass_certificate(
            spec,
            issuance_key=input_sha256,
        )
        now = utc_now()
        authority_json = signed_payload[:-1].decode("utf-8")
        receipt_values = (
            certificate.certificate_urn,
            certificate.certificate_hash,
            str(authority_input["run_id"]),
            spec.artifact_manifest_hash,
            spec.requirements_manifest_hash,
            spec.review_artifact_hash,
            spec.review_set_hash,
            spec.reviewer_identity_hash,
            authority_id,
            key_hash,
            modulus_hex,
            exponent,
            str(authority_input["review_decision_id"]),
            str(authority_input["reviewed_at"]),
            authority_json,
            input_sha256,
            str(document["signature_hex"]),
            signature_sha256,
            now,
        )
        with paper_lab_connection(self.settings) as connection:
            with immediate_transaction(connection):
                connection.execute(
                    """
                    INSERT OR IGNORE INTO reading_review_authority_input(
                        certificate_urn,certificate_hash,run_id,run_artifact_hash,
                        requirements_manifest_hash,review_artifact_hash,review_set_hash,
                        reviewer_identity_hash,authority_id,authority_key_hash,
                        public_modulus_hex,public_exponent,review_decision_id,reviewed_at,
                        authority_input_json,authority_input_sha256,signature_hex,
                        signature_sha256,registered_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    receipt_values,
                )
                stored = connection.execute(
                    "SELECT * FROM reading_review_authority_input WHERE certificate_urn=?",
                    (certificate.certificate_urn,),
                ).fetchone()
                immutable_columns = (
                    "certificate_urn", "certificate_hash", "run_id",
                    "run_artifact_hash", "requirements_manifest_hash",
                    "review_artifact_hash", "review_set_hash",
                    "reviewer_identity_hash", "authority_id", "authority_key_hash",
                    "public_modulus_hex", "public_exponent", "review_decision_id",
                    "reviewed_at", "authority_input_json", "authority_input_sha256",
                    "signature_hex", "signature_sha256",
                )
                if stored is None or any(
                    stored[key] != value
                    for key, value in zip(immutable_columns, receipt_values[:-1])
                ):
                    raise ReviewerAuthorityError(
                        "review authority input already exists with different material"
                    )
        return certificate


def verify_independent_review_certificate(
    settings: Settings,
    run_id: str,
    certificate: ReviewCertificate,
) -> None:
    with paper_lab_connection(settings) as connection:
        row = connection.execute(
            "SELECT * FROM reading_review_authority_input WHERE certificate_urn=?",
            (certificate.certificate_urn,),
        ).fetchone()
    if row is None:
        raise ReviewerAuthorityError(
            "PASS certificate lacks an independent reviewer authority input"
        )
    try:
        authority_input_value: Any = json.loads(row["authority_input_json"])
    except json.JSONDecodeError as error:
        raise ReviewerAuthorityError("stored reviewer authority input is invalid JSON") from error
    authority_input, spec = _parse_authority_input(authority_input_value)
    canonical = canonical_reviewer_authority_input(authority_input)
    modulus_hex, exponent, modulus = _validated_public_key(
        row["public_modulus_hex"], row["public_exponent"]
    )
    trusted_modulus_hex, trusted_exponent, trusted_modulus = _trusted_key(
        row["authority_id"]
    )
    if (
        modulus_hex != trusted_modulus_hex
        or exponent != trusted_exponent
        or modulus != trusted_modulus
    ):
        raise ReviewerAuthorityError(
            "stored reviewer key is not the currently trusted authority key"
        )
    key_hash = reviewer_authority_key_hash(row["authority_id"], modulus_hex, exponent)
    signature_sha256 = _verify_rsa_signature(
        canonical,
        row["signature_hex"],
        modulus,
        exponent,
    )
    expected = (
        certificate.certificate_urn,
        certificate.certificate_hash,
        run_id,
        certificate.spec.artifact_manifest_hash,
        certificate.spec.requirements_manifest_hash,
        certificate.spec.review_artifact_hash,
        certificate.spec.review_set_hash,
        certificate.spec.reviewer_identity_hash,
        str(authority_input["authority_id"]),
        key_hash,
        hashlib.sha256(canonical).hexdigest(),
        signature_sha256,
        spec,
    )
    actual = (
        row["certificate_urn"],
        row["certificate_hash"],
        row["run_id"],
        row["run_artifact_hash"],
        row["requirements_manifest_hash"],
        row["review_artifact_hash"],
        row["review_set_hash"],
        row["reviewer_identity_hash"],
        row["authority_id"],
        row["authority_key_hash"],
        row["authority_input_sha256"],
        row["signature_sha256"],
        certificate.spec,
    )
    if actual != expected or certificate.issuance_key != row["authority_input_sha256"]:
        raise ReviewerAuthorityError(
            "independent reviewer authority input does not bind the active certificate/run material"
        )
    if not _SHA256.fullmatch(row["authority_key_hash"]):
        raise ReviewerAuthorityError("stored reviewer authority key hash is invalid")


__all__ = [
    "PaperLabReviewerAuthority",
    "ReviewerAuthorityError",
    "canonical_reviewer_authority_input",
    "reviewer_authority_key_hash",
    "verify_independent_review_certificate",
]
