from __future__ import annotations

import copy
import unittest

from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256
from quant_hub.ops.local_runtime_qualification_evidence import (
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
    LocalRuntimeQualificationAggregateEvidence,
    LocalRuntimeQualificationEvidenceError,
    build_local_runtime_qualification_evidence,
    parse_local_runtime_qualification_evidence_bytes,
    validate_local_runtime_qualification_evidence,
)


def _payload() -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
        "scope": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
        "attempt_id": "attempt-formal-1",
        "nonce": "deployment-nonce-1",
        "operation": "activation",
        "role": "candidate",
        "start_nonce": "start-nonce-1",
    }
    for index, field in enumerate(
        (
            "state_identity_sha256",
            "authorization_sha256",
            "release_compatibility_sha256",
            "release_closure_sha256",
            "production_state_before_order_sha256",
            "production_state_after_order_sha256",
            "scm_before_after_sha256",
            "endpoint_before_after_sha256",
            "writer_before_after_sha256",
            "canary_request_sha256",
            "canary_result_sha256",
            "canary_database_order_sha256",
            "runtime_tooling_manifest_sha256",
            "controller_tooling_observation_sha256",
        ),
        start=1,
    ):
        payload[field] = f"{index:x}" * 64
    return payload


class LocalRuntimeQualificationEvidenceTests(unittest.TestCase):
    def test_roundtrip_is_canonical_persistent_non_authority(self) -> None:
        document = build_local_runtime_qualification_evidence(_payload())
        evidence = LocalRuntimeQualificationAggregateEvidence.from_document(
            document
        )
        replay = parse_local_runtime_qualification_evidence_bytes(
            evidence.canonical_bytes()
        )
        self.assertEqual(evidence.canonical_bytes(), replay.canonical_bytes())
        self.assertEqual(document["aggregate_sha256"], replay.aggregate_sha256)
        self.assertEqual(
            "observation_evidence_only_not_authority",
            replay.as_dict()["scope"],
        )
        for forbidden in ("qualify", "consume", "authorization", "is_qualified"):
            self.assertNotIn(forbidden, dir(replay))

    def test_schema_enum_and_exact_type_matrix_fail_closed(self) -> None:
        valid = build_local_runtime_qualification_evidence(_payload())
        cases: dict[str, object] = {}
        for field in valid:
            changed = copy.deepcopy(valid)
            changed.pop(field)
            cases["missing-" + field] = changed
        extra = copy.deepcopy(valid)
        extra["qualified"] = True
        cases["extra-qualified"] = extra
        for field, value in (
            ("operation", "promote"),
            ("role", "active"),
            ("nonce", "bad nonce"),
            ("start_nonce", True),
            ("authorization_sha256", True),
            ("state_identity_sha256", "0" * 63),
        ):
            changed = copy.deepcopy(valid)
            changed[field] = value
            cases[field] = changed
        bootstrap = _payload()
        bootstrap["operation"] = "bootstrap_first_pair"
        bootstrap["role"] = "candidate"
        cases["bootstrap-role"] = {
            **bootstrap,
            "aggregate_sha256": identity_sha256(bootstrap),
        }
        for label, value in cases.items():
            with self.subTest(label=label), self.assertRaises(
                LocalRuntimeQualificationEvidenceError
            ):
                validate_local_runtime_qualification_evidence(value)

    def test_fully_resigned_semantic_mutations_are_rejected(self) -> None:
        for field, value in (
            ("scope", "deployment_authority"),
            ("schema_version", "qrh-local-runtime-qualification-evidence/v2"),
            ("operation", "rollback-now"),
            ("role", "baseline"),
        ):
            payload = _payload()
            payload[field] = value
            document = dict(payload)
            document["aggregate_sha256"] = identity_sha256(document)
            with self.subTest(field=field), self.assertRaises(
                LocalRuntimeQualificationEvidenceError
            ):
                validate_local_runtime_qualification_evidence(document)

    def test_noncanonical_duplicate_nan_and_trailing_bytes_are_rejected(self) -> None:
        document = build_local_runtime_qualification_evidence(_payload())
        raw = canonical_bytes(document)
        for changed in (
            raw + b"\n",
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b"[]",
            b"\xff",
        ):
            with self.subTest(changed=changed[:20]), self.assertRaises(
                LocalRuntimeQualificationEvidenceError
            ):
                parse_local_runtime_qualification_evidence_bytes(changed)


if __name__ == "__main__":
    unittest.main()
