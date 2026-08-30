from __future__ import annotations

import copy
import hashlib
import json
import unittest

from quant_hub.ops import local_exact_runtime_canary_evidence as module
from quant_hub.ops.local_exact_runtime_canary_evidence import (
    EXACT_RUNTIME_CANARY_EVIDENCE_SCOPE,
    EXACT_RUNTIME_CANARY_REQUEST_SCOPE,
    EXACT_RUNTIME_CANARY_RESULT,
    ExactRuntimeCanaryEvidence,
    ExactRuntimeCanaryEvidenceError,
    ExactRuntimeCanaryRequest,
    build_exact_runtime_canary_evidence,
    build_exact_runtime_canary_request,
    parse_exact_runtime_canary_evidence_bytes,
    parse_exact_runtime_canary_request_bytes,
)
from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _request_payload() -> dict[str, object]:
    attempt = "attempt-canary-1"
    role = "candidate"
    databases = []
    for index, (name, filename) in enumerate(
        (
            ("comments", "comments.sqlite3"),
            ("research_workspace", "research_workspace.sqlite3"),
        ),
        start=1,
    ):
        databases.append(
            {
                "database_name": name,
                "relative_path": (
                    f"tmp/deployment-attempts/{attempt}-deployment-nonce-1/"
                    f"runtime-canary/{role}/state/"
                    f"{filename}"
                ),
                "source_seal_sha256": _hash(f"{name}-source"),
                "isolated_copy_evidence_sha256": _hash(f"{name}-copy"),
                "compatibility_evidence_sha256": _hash(f"{name}-compat"),
                "initial_consistent_bytes": index * 4096,
                "initial_consistent_sha256": _hash(f"{name}-initial"),
            }
        )
    return {
        "schema_version": module.EXACT_RUNTIME_CANARY_REQUEST_SCHEMA,
        "scope": EXACT_RUNTIME_CANARY_REQUEST_SCOPE,
        "attempt_id": attempt,
        "nonce": "deployment-nonce-1",
        "operation": "activation",
        "role": role,
        "start_nonce": "start-nonce-1",
        "authorization_sha256": _hash("authorization"),
        "scm_identity_sha256": _hash("scm"),
        "state_identity_sha256": _hash("state"),
        "release": {
            "release_id": "release-canary-1",
            "release_path": r"D:\quant\quant_platform\releases\release-canary-1",
            "manifest_sha256": _hash("manifest"),
        },
        "databases": databases,
    }


def _request() -> ExactRuntimeCanaryRequest:
    return ExactRuntimeCanaryRequest.from_document(
        build_exact_runtime_canary_request(_request_payload())
    )


def _result_payload(request: ExactRuntimeCanaryRequest) -> dict[str, object]:
    request_document = request.as_dict()
    challenge_nonce = "ab" * 24
    databases = []
    for request_database in request_document["databases"]:
        name = request_database["database_name"]
        challenge_id = "canary-" + hashlib.sha256(
            f"{request.request_sha256}:{challenge_nonce}:{name}".encode("utf-8")
        ).hexdigest()[:32]
        family = "archive_comments" if name == "comments" else "workspace_comments"
        databases.append(
            {
                "database_name": name,
                "request_database_sha256": request_database[
                    "request_database_sha256"
                ],
                "initial_consistent_bytes": request_database[
                    "initial_consistent_bytes"
                ],
                "initial_consistent_sha256": request_database[
                    "initial_consistent_sha256"
                ],
                "initial_schema_sha256": _hash(f"{name}-schema-before"),
                "initial_business_summary_sha256": _hash(
                    f"{name}-business-before"
                ),
                "challenge": {
                    "challenge_id": challenge_id,
                    "insert_rowcount": 1,
                    "cas_applied_rowcount": 1,
                    "stale_cas_rowcount": 0,
                    "readback_revision": 1,
                    "append_only_event_count": 1,
                    "event_update_outcome": "rejected_by_trigger",
                    "event_delete_outcome": "rejected_by_trigger",
                },
                "business_probe": {
                    "family": family,
                    "create_rowcount": 1,
                    "idempotent_replay_rowcount": 0,
                    "edit_rowcount": 1,
                    "stale_edit_rowcount": 0,
                    "soft_delete_rowcount": 1,
                    "stale_delete_rowcount": 0,
                    "final_revision": 3,
                    "event_count": 3,
                    "receipt_count": 3,
                    "deleted_row_count": 1,
                },
                "final_integrity_check": "ok",
                "final_quick_check": "ok",
                "final_foreign_key_violation_count": 0,
                "final_schema_sha256": _hash(f"{name}-schema-after"),
                "final_business_summary_sha256": _hash(
                    f"{name}-business-after"
                ),
                "final_consistent_bytes": int(
                    request_database["initial_consistent_bytes"]
                )
                + 4096,
                "final_consistent_sha256": _hash(f"{name}-final"),
                "final_members": ["main"],
            }
        )
    return {
        "challenge_nonce": challenge_nonce,
        "writer_lease_claim": {
            "lease_id": "lease-canary-1",
            "lease_nonce": "cd" * 24,
            "lease_epoch": 7,
            "lease_record_sha256": _hash("lease-record"),
            "authority": "claim_not_independently_observed",
        },
        "databases": databases,
    }


def _evidence(request: ExactRuntimeCanaryRequest) -> dict[str, object]:
    return build_exact_runtime_canary_evidence(
        _result_payload(request), request=request
    )


def _resign_request(document: dict[str, object]) -> None:
    databases = document["databases"]
    for database in databases:
        database.pop("request_database_sha256", None)
        database["request_database_sha256"] = identity_sha256(database)
    document["database_order_sha256"] = identity_sha256(
        [
            {
                "database_name": database["database_name"],
                "request_database_sha256": database["request_database_sha256"],
            }
            for database in databases
        ]
    )
    document.pop("request_sha256", None)
    document["request_sha256"] = identity_sha256(document)


def _resign_evidence(document: dict[str, object]) -> None:
    databases = document["databases"]
    for database in databases:
        challenge = database["challenge"]
        challenge.pop("challenge_sha256", None)
        challenge["challenge_sha256"] = identity_sha256(challenge)
        probe = database["business_probe"]
        probe.pop("business_probe_sha256", None)
        probe["business_probe_sha256"] = identity_sha256(probe)
        database.pop("database_evidence_sha256", None)
        database["database_evidence_sha256"] = identity_sha256(database)
    document["database_order_sha256"] = identity_sha256(
        [
            {
                "database_name": database["database_name"],
                "database_evidence_sha256": database["database_evidence_sha256"],
            }
            for database in databases
        ]
    )
    document.pop("evidence_sha256", None)
    document["evidence_sha256"] = identity_sha256(document)


class ExactRuntimeCanaryEvidenceTest(unittest.TestCase):
    def test_valid_request_and_result_remain_persistent_nonqualification(self) -> None:
        request = _request()
        evidence_document = _evidence(request)
        evidence = ExactRuntimeCanaryEvidence.from_document(
            evidence_document, request=request
        )
        self.assertEqual(EXACT_RUNTIME_CANARY_REQUEST_SCOPE, request.as_dict()["scope"])
        self.assertEqual(EXACT_RUNTIME_CANARY_EVIDENCE_SCOPE, evidence.as_dict()["scope"])
        self.assertEqual(EXACT_RUNTIME_CANARY_RESULT, evidence.as_dict()["result"])
        self.assertEqual(evidence_document, evidence.as_dict())
        changed = evidence.as_dict()
        changed["qualified"] = True
        self.assertNotEqual(changed, evidence.as_dict())

    def test_request_binds_exact_database_order_path_and_role(self) -> None:
        valid = _request().as_dict()
        cases = {
            "reordered": lambda d: d["databases"].reverse(),
            "path": lambda d: d["databases"][0].__setitem__(
                "relative_path",
                "tmp/deployment-attempts/attempt-canary-1-deployment-nonce-1/"
                "runtime-canary/prior/state/comments.sqlite3",
            ),
            "role": lambda d: d.__setitem__("role", "prior"),
            "extra": lambda d: d.__setitem__("qualified", True),
            "database_alias": lambda d: d["databases"][0].__setitem__(
                "database_name", "Comments"
            ),
        }
        for label, mutate in cases.items():
            changed = copy.deepcopy(valid)
            mutate(changed)
            _resign_request(changed)
            with self.subTest(label=label), self.assertRaises(
                ExactRuntimeCanaryEvidenceError
            ):
                ExactRuntimeCanaryRequest.from_document(changed)

    def test_request_fully_resigned_numeric_aliases_fail_closed(self) -> None:
        valid = _request().as_dict()
        for value in (True, 0, -1, 1 << 63):
            changed = copy.deepcopy(valid)
            changed["databases"][0]["initial_consistent_bytes"] = value
            _resign_request(changed)
            with self.subTest(value=value), self.assertRaises(
                ExactRuntimeCanaryEvidenceError
            ):
                ExactRuntimeCanaryRequest.from_document(changed)

    def test_evidence_is_exact_bound_to_typed_request(self) -> None:
        request = _request()
        valid = _evidence(request)
        cases = {
            "request_hash": lambda d: d.__setitem__(
                "request_sha256", _hash("foreign-request")
            ),
            "role": lambda d: d.__setitem__("role", "prior"),
            "release": lambda d: d["release"].__setitem__(
                "manifest_sha256", _hash("foreign-manifest")
            ),
            "database_request": lambda d: d["databases"][0].__setitem__(
                "request_database_sha256", _hash("foreign-database")
            ),
            "wal_sidecar": lambda d: d["databases"][0].__setitem__(
                "final_members", ["main", "wal"]
            ),
            "wal_shm_sidecars": lambda d: d["databases"][0].__setitem__(
                "final_members", ["main", "wal", "shm"]
            ),
            "self_qualification": lambda d: d.__setitem__("qualified", True),
        }
        for label, mutate in cases.items():
            changed = copy.deepcopy(valid)
            mutate(changed)
            _resign_evidence(changed)
            with self.subTest(label=label), self.assertRaises(
                ExactRuntimeCanaryEvidenceError
            ):
                ExactRuntimeCanaryEvidence.from_document(changed, request=request)

    def test_fully_resigned_boolean_rowcounts_are_rejected(self) -> None:
        request = _request()
        valid = _evidence(request)
        paths = (
            ("challenge", "insert_rowcount"),
            ("challenge", "stale_cas_rowcount"),
            ("business_probe", "create_rowcount"),
            ("business_probe", "stale_edit_rowcount"),
            (None, "final_foreign_key_violation_count"),
            (None, "final_consistent_bytes"),
        )
        for parent, field in paths:
            changed = copy.deepcopy(valid)
            target = changed["databases"][0]
            if parent is not None:
                target = target[parent]
            target[field] = True
            _resign_evidence(changed)
            with self.subTest(parent=parent, field=field), self.assertRaises(
                ExactRuntimeCanaryEvidenceError
            ):
                ExactRuntimeCanaryEvidence.from_document(changed, request=request)

    def test_lease_epoch_exact_uint64_domain(self) -> None:
        request = _request()
        valid = _evidence(request)
        for value, accepted in (
            (1, True),
            ((1 << 64) - 1, True),
            (True, False),
            (0, False),
            (1 << 64, False),
        ):
            changed = copy.deepcopy(valid)
            changed["writer_lease_claim"]["lease_epoch"] = value
            _resign_evidence(changed)
            with self.subTest(value=value, accepted=accepted):
                if accepted:
                    ExactRuntimeCanaryEvidence.from_document(changed, request=request)
                else:
                    with self.assertRaises(ExactRuntimeCanaryEvidenceError):
                        ExactRuntimeCanaryEvidence.from_document(changed, request=request)

    def test_challenge_identity_and_business_write_are_not_boolean_claims(self) -> None:
        request = _request()
        valid = _evidence(request)
        cases = {
            "challenge_id": lambda d: d["databases"][0]["challenge"].__setitem__(
                "challenge_id", "canary-" + "0" * 32
            ),
            "same_final_bytes": lambda d: d["databases"][0].__setitem__(
                "final_consistent_sha256",
                d["databases"][0]["initial_consistent_sha256"],
            ),
            "same_business": lambda d: d["databases"][0].__setitem__(
                "final_business_summary_sha256",
                d["databases"][0]["initial_business_summary_sha256"],
            ),
            "writer_authority": lambda d: d["writer_lease_claim"].__setitem__(
                "authority", "writer_qualified"
            ),
        }
        for label, mutate in cases.items():
            changed = copy.deepcopy(valid)
            mutate(changed)
            _resign_evidence(changed)
            with self.subTest(label=label), self.assertRaises(
                ExactRuntimeCanaryEvidenceError
            ):
                ExactRuntimeCanaryEvidence.from_document(changed, request=request)

    def test_strict_byte_parsers_reject_duplicates_nan_and_noncanonical(self) -> None:
        request = _request()
        request_raw = canonical_bytes(request.as_dict())
        parsed_request = parse_exact_runtime_canary_request_bytes(request_raw)
        evidence = ExactRuntimeCanaryEvidence.from_document(
            _evidence(request), request=request
        )
        parsed_evidence = parse_exact_runtime_canary_evidence_bytes(
            canonical_bytes(evidence.as_dict()), request=parsed_request
        )
        self.assertEqual(evidence.as_dict(), parsed_evidence.as_dict())

        duplicate = request_raw.replace(
            b'{"attempt_id"', b'{"attempt_id":"duplicate","attempt_id"', 1
        )
        nonfinite = request_raw.replace(b"4096", b"NaN", 1)
        pretty = json.dumps(request.as_dict(), ensure_ascii=False).encode("utf-8")
        for label, raw in (
            ("duplicate", duplicate),
            ("nonfinite", nonfinite),
            ("noncanonical", pretty),
        ):
            with self.subTest(label=label), self.assertRaises(
                ExactRuntimeCanaryEvidenceError
            ):
                parse_exact_runtime_canary_request_bytes(raw)

    def test_public_surface_has_no_live_or_formal_upgrade(self) -> None:
        self.assertEqual(
            {
                "EXACT_RUNTIME_CANARY_EVIDENCE_SCHEMA",
                "EXACT_RUNTIME_CANARY_EVIDENCE_SCOPE",
                "EXACT_RUNTIME_CANARY_REQUEST_SCHEMA",
                "EXACT_RUNTIME_CANARY_REQUEST_SCOPE",
                "EXACT_RUNTIME_CANARY_RESULT",
                "ExactRuntimeCanaryEvidence",
                "ExactRuntimeCanaryEvidenceError",
                "ExactRuntimeCanaryRequest",
                "build_exact_runtime_canary_evidence",
                "build_exact_runtime_canary_request",
                "parse_exact_runtime_canary_evidence_bytes",
                "parse_exact_runtime_canary_request_bytes",
                "validate_exact_runtime_canary_evidence",
                "validate_exact_runtime_canary_request",
            },
            set(module.__all__),
        )
        forbidden = {
            "qualify",
            "qualified",
            "from_mapping",
            "load_exact_d",
            "observe",
            "run_canary",
            "writer_handle",
        }
        for cls in (ExactRuntimeCanaryRequest, ExactRuntimeCanaryEvidence):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(forbidden.isdisjoint(dir(cls)))


if __name__ == "__main__":
    unittest.main()
