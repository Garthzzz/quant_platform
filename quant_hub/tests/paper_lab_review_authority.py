from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
import os
from unittest.mock import patch

from quant_hub.ids import stable_sha256
from quant_hub.paper_lab.reviewer import (
    PaperLabReviewerAuthority,
    canonical_reviewer_authority_input,
    reviewer_authority_key_hash,
)
from quant_hub.platform.reviews import ReviewCertificateSpec


AUTHORITY_ID = "paper-lab-test-independent-reviewer"
PUBLIC_EXPONENT = 65537
PUBLIC_MODULUS = int(
    "8d97329c355f12b775d439e47f8d67b8272380709dd1e42aebca1f5cc3c7dbdc"
    "5ba601f137bd68845381a452f845ce444f7e39bc8810c0efa22e15731879e8d5"
    "df80bd305916724eb5af9e7c3249a440b5d7bac50de655ee6f708ca2033934d3"
    "3c6d391a434f99fcdd0118dbdb233d301c678a5fb5affcd8d0800afd70766cfc"
    "edc20296633c7104e5ad99afe19c0b5cfb50e0f893e8f88bb89f5245d8d96e"
    "ea9cced52fb5b7d43a109630274d88c2fcabf307f80a030e759902aef29dcaad"
    "474b07e4dc604f575d1c68f2f80b8243645399335ca94420196bb7b98991b226"
    "17272541e901eb545e44ee8977a82b3d3512d46f1613acb204535847dbb90c493f",
    16,
)
PRIVATE_EXPONENT = int(
    "42c8ce565fd6383dd09609b87d71753aa73b5799c6d6f988452f511bb03cd4b7"
    "5b8331e7552341e9287a3dc7e4d30837b047197493b95347b477882681a4feede"
    "23e16fe7706df63c0ced5323f85fcb38911f8467a07eb004c100a4560bfdaeac"
    "7d5bcd96666657b9fc2a4b70ee5d036a12f35556f9d52e5f17273bc970f44d8"
    "5483a66ee28371f31aff64791c33dae36de83479199ef816b648974f58bea5c7b"
    "b2259ea499ab6f5ca0b3a307f82ad8046383083c228be45f14825f85c1c5ca8f"
    "e26ddbcb93ab8f1ed84d048d516a867ad9e4c72af63e2c53c984f4a483ac0a58"
    "a86616771665f846ef2f02382069745390a3f9438c58210be94db55eb0ee21",
    16,
)
_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def _signature(payload: bytes) -> str:
    byte_length = (PUBLIC_MODULUS.bit_length() + 7) // 8
    digest_info = _DIGEST_INFO + hashlib.sha256(payload).digest()
    encoded = (
        b"\x00\x01"
        + b"\xff" * (byte_length - len(digest_info) - 3)
        + b"\x00"
        + digest_info
    )
    value = pow(int.from_bytes(encoded, "big"), PRIVATE_EXPONENT, PUBLIC_MODULUS)
    return value.to_bytes(byte_length, "big").hex()


def trusted_key_environment() -> str:
    return json.dumps({
        AUTHORITY_ID: {
            "public_modulus_hex": f"{PUBLIC_MODULUS:x}",
            "public_exponent": PUBLIC_EXPONENT,
        }
    })


def build_presigned_document(service, run_id: str, *, artifact_hash: str | None = None):
    material = service.review_material(run_id)
    identity = reviewer_authority_key_hash(
        AUTHORITY_ID, f"{PUBLIC_MODULUS:x}", PUBLIC_EXPONENT
    )
    spec = ReviewCertificateSpec(
        gate_name=material.gate_name,
        gate_version=material.gate_version,
        subject_urn=material.subject_urn,
        subject_version_urn=material.subject_version_urn,
        artifact_manifest_hash=artifact_hash or material.run_artifact_hash,
        requirements_manifest_hash=material.requirements_manifest_hash,
        review_artifact_hash=stable_sha256(
            "paper-lab-test-review-artifact/v2", run_id
        ),
        review_set_hash=stable_sha256(
            "paper-lab-test-review-set/v2", material.run_artifact_hash
        ),
        reviewer_identity_hash=identity,
    )
    authority_input = {
        "schema_version": "paper-lab-presigned-review/v1",
        "authority_id": AUTHORITY_ID,
        "run_id": run_id,
        "review_decision_id": stable_sha256(
            "paper-lab-test-review-decision/v1", run_id, spec.artifact_manifest_hash
        ),
        "reviewed_at": "2026-07-15T00:00:00Z",
        "verdict": "pass",
        "certificate_spec": asdict(spec),
    }
    return {
        "authority_input": authority_input,
        "signature_hex": _signature(canonical_reviewer_authority_input(authority_input)),
    }


def register_presigned_test_certificate(settings, service, run_id: str):
    document = build_presigned_document(service, run_id)
    with patch.dict(
        os.environ,
        {"QRH_PAPER_LAB_REVIEWER_RSA_KEYS": trusted_key_environment()},
    ):
        return PaperLabReviewerAuthority(settings).register_presigned_pass_certificate(document)
