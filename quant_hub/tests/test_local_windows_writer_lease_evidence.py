from __future__ import annotations

import copy
import unittest

from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256
from quant_hub.ops.local_windows_endpoint_evidence import (
    WindowsEndpointEvidenceError,
    WindowsEndpointObservationEvidence,
)
from quant_hub.ops.local_windows_writer_lease_evidence import (
    WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA,
    WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE,
    WRITER_LEASE_RECORD_SCHEMA,
    WRITER_LOCK_FINAL_PATH,
    WRITER_LOCK_RELATIVE_PATH,
    WindowsWriterLeaseEvidenceError,
    WindowsWriterLeaseObservationEvidence,
    validate_windows_writer_lease_observation,
    validate_writer_lease_record,
)
from tests.test_local_windows_endpoint_evidence import (
    _evidence as endpoint_document,
    _rehash as rehash_endpoint,
    _scm_evidence,
)


def _seal(value: dict[str, object], field: str) -> None:
    value.pop(field, None)
    value[field] = identity_sha256(value)


def _lease_id(record: dict[str, object]) -> str:
    return "lease-" + identity_sha256(
        {
            "attempt_id": record["attempt_id"],
            "nonce": record["nonce"],
            "role": record["role"],
            "start_nonce": record["start_nonce"],
            "lease_nonce": record["lease_nonce"],
            "lease_epoch": record["lease_epoch"],
        }
    )[:32]


def _record(
    *,
    handle_value: object = 512,
    volume_serial_number: object = 987654321,
    lease_epoch: object = 7,
) -> dict[str, object]:
    holder: dict[str, object] = {
        "service_name": "QuantResearchHub",
        "host_pid": 4100,
        "host_creation_time_100ns": 100_000,
        "child_pid": 4200,
        "child_creation_time_100ns": 100_100,
    }
    _seal(holder, "holder_identity_sha256")
    lock: dict[str, object] = {
        "relative_path": WRITER_LOCK_RELATIVE_PATH,
        "final_path": WRITER_LOCK_FINAL_PATH,
        "handle_value": handle_value,
        "volume_serial_number": volume_serial_number,
        "file_id": "12" * 16,
        "desired_access": "GENERIC_READ|GENERIC_WRITE",
        "share_mode": "FILE_SHARE_READ",
        "creation_disposition": "OPEN_ALWAYS",
    }
    _seal(lock, "lock_identity_sha256")
    record: dict[str, object] = {
        "schema_version": WRITER_LEASE_RECORD_SCHEMA,
        "attempt_id": "attempt-1",
        "nonce": "deployment-nonce-1",
        "operation": "activation",
        "role": "candidate",
        "start_nonce": "start-nonce-1",
        "authorization_sha256": "b" * 64,
        "scm_identity_sha256": "c" * 64,
        "state_identity_sha256": "d" * 64,
        "release": {
            "release_id": "release-r1",
            "release_path": "D:\\quant\\quant_platform\\releases\\release-r1",
            "manifest_sha256": "a" * 64,
        },
        "lease_id": "temporary",
        "lease_nonce": "34" * 24,
        "lease_epoch": lease_epoch,
        "holder": holder,
        "lock": lock,
    }
    record["lease_id"] = _lease_id(record)
    _seal(record, "lease_record_sha256")
    return record


def _endpoint_for_record(record: dict[str, object]) -> dict[str, object]:
    document = endpoint_document()
    probe = document["probe"]
    assert type(probe) is dict
    response = probe["response"]
    assert type(response) is dict
    response["writer_lease"] = {
        "lease_id": record["lease_id"],
        "lease_nonce": record["lease_nonce"],
        "lease_epoch": record["lease_epoch"],
        "lease_record_sha256": record["lease_record_sha256"],
        "authority": "claim_not_independently_observed",
    }
    rehash_endpoint(document)
    return document


def _kernel(
    record: dict[str, object],
    *,
    source_pid: object = 4200,
    conflict_error: object = 32,
) -> dict[str, object]:
    lock = record["lock"]
    assert type(lock) is dict
    kernel: dict[str, object] = {
        "source_process_pid": source_pid,
        "source_process_creation_time_100ns": 100_100,
        "source_handle_value": lock["handle_value"],
        "duplicate_final_path": lock["final_path"],
        "duplicate_volume_serial_number": lock["volume_serial_number"],
        "duplicate_file_id": lock["file_id"],
        "duplicate_close_result": "closed_before_conflict_probe",
        "conflict_open_result": "sharing_violation",
        "conflict_open_error_code": conflict_error,
    }
    _seal(kernel, "kernel_observation_sha256")
    return kernel


def _observation(
    record: dict[str, object],
    endpoint: dict[str, object],
    *,
    kernel: dict[str, object] | None = None,
) -> dict[str, object]:
    scm = _scm_evidence().as_dict()
    kernel = kernel or _kernel(record)
    document: dict[str, object] = {
        "schema_version": WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA,
        "evidence_scope": WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE,
        "scm_process_evidence_sha256": scm["evidence_sha256"],
        "endpoint_evidence_sha256": endpoint["evidence_sha256"],
        "attempt_id": "attempt-1",
        "nonce": "deployment-nonce-1",
        "operation": "activation",
        "role": "candidate",
        "start_nonce": "start-nonce-1",
        "state_identity_sha256": "d" * 64,
        "release": copy.deepcopy(scm["release"]),
        "lease_record": copy.deepcopy(record),
        "kernel_lock_observation": kernel,
        "observation_aggregate_sha256": identity_sha256(
            [
                {"name": "scm_process", "sha256": scm["evidence_sha256"]},
                {"name": "endpoint", "sha256": endpoint["evidence_sha256"]},
                {
                    "name": "lease_record",
                    "sha256": record["lease_record_sha256"],
                },
                {
                    "name": "kernel_lock",
                    "sha256": kernel["kernel_observation_sha256"],
                },
            ]
        ),
        "result": "writer_lease_observed_not_canary_qualified",
    }
    _seal(document, "evidence_sha256")
    return document


class WindowsWriterLeaseEvidenceTests(unittest.TestCase):
    def valid_material(
        self,
        *,
        handle_value: object = 512,
        volume_serial_number: object = 987654321,
        lease_epoch: object = 7,
        source_pid: object = 4200,
        conflict_error: object = 32,
    ) -> tuple[
        object,
        WindowsEndpointObservationEvidence,
        dict[str, object],
        dict[str, object],
    ]:
        scm = _scm_evidence()
        record = _record(
            handle_value=handle_value,
            volume_serial_number=volume_serial_number,
            lease_epoch=lease_epoch,
        )
        endpoint_raw = _endpoint_for_record(record)
        endpoint = WindowsEndpointObservationEvidence.from_document(
            endpoint_raw, scm
        )
        document = _observation(
            record,
            endpoint_raw,
            kernel=_kernel(
                record, source_pid=source_pid, conflict_error=conflict_error
            ),
        )
        return scm, endpoint, record, document

    def test_valid_record_and_observation_remain_non_qualified(self) -> None:
        scm, endpoint, record, document = self.valid_material()
        validated_record = validate_writer_lease_record(record, scm, endpoint)
        self.assertEqual(record, validated_record)
        evidence = WindowsWriterLeaseObservationEvidence.from_document(
            document, scm, endpoint
        )
        self.assertEqual(WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE, evidence.as_dict()["evidence_scope"])
        self.assertEqual(
            "writer_lease_observed_not_canary_qualified",
            evidence.as_dict()["result"],
        )
        self.assertEqual(canonical_bytes(document), evidence.canonical_bytes())

    def test_endpoint_claim_must_bind_exact_record(self) -> None:
        scm, endpoint, record, _document = self.valid_material()
        changed = copy.deepcopy(record)
        changed["lease_nonce"] = "56" * 24
        changed["lease_id"] = _lease_id(changed)
        _seal(changed, "lease_record_sha256")
        with self.assertRaises(WindowsWriterLeaseEvidenceError):
            validate_writer_lease_record(changed, scm, endpoint)

    def test_record_identity_cannot_be_relabelled_and_resigned(self) -> None:
        scm, endpoint, record, _document = self.valid_material()
        changed = copy.deepcopy(record)
        changed["attempt_id"] = "other-attempt"
        changed["lease_id"] = _lease_id(changed)
        _seal(changed, "lease_record_sha256")
        with self.assertRaises(WindowsWriterLeaseEvidenceError):
            validate_writer_lease_record(changed, scm, endpoint)

    def test_closed_schema_rejects_missing_and_extra_fields(self) -> None:
        scm, endpoint, record, document = self.valid_material()
        for target, field in (
            (record, "operation"),
            (record["holder"], "host_pid"),
            (record["lock"], "share_mode"),
            (document, "result"),
            (document["kernel_lock_observation"], "duplicate_close_result"),
        ):
            assert type(target) is dict
            changed = copy.deepcopy(target)
            changed.pop(field)
            if target is record:
                candidate = changed
                call = lambda: validate_writer_lease_record(candidate, scm, endpoint)
            else:
                candidate_document = copy.deepcopy(document)
                if target is record["holder"]:
                    candidate_document["lease_record"]["holder"] = changed  # type: ignore[index]
                elif target is record["lock"]:
                    candidate_document["lease_record"]["lock"] = changed  # type: ignore[index]
                elif target is document:
                    candidate_document = changed
                else:
                    candidate_document["kernel_lock_observation"] = changed
                call = lambda candidate_document=candidate_document: validate_windows_writer_lease_observation(
                    candidate_document, scm, endpoint
                )
            with self.subTest(field=field), self.assertRaises(WindowsWriterLeaseEvidenceError):
                call()
        extra = copy.deepcopy(document)
        extra["qualified"] = True
        with self.assertRaises(WindowsWriterLeaseEvidenceError):
            validate_windows_writer_lease_observation(extra, scm, endpoint)

    def test_fully_resigned_boolean_numeric_aliases_are_rejected(self) -> None:
        cases = (
            {"handle_value": True},
            {"volume_serial_number": True},
            {"lease_epoch": True},
            {"source_pid": True},
            {"conflict_error": True},
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(
                (WindowsWriterLeaseEvidenceError, WindowsEndpointEvidenceError)
            ):
                scm, endpoint, _record_value, document = self.valid_material(**case)
                validate_windows_writer_lease_observation(document, scm, endpoint)

    def test_exact_integer_one_is_not_confused_with_boolean(self) -> None:
        scm, endpoint, record, document = self.valid_material(
            handle_value=1,
            volume_serial_number=1,
            lease_epoch=1,
        )
        validate_writer_lease_record(record, scm, endpoint)
        validate_windows_writer_lease_observation(document, scm, endpoint)

    def test_persisted_handle_domain_rejects_zero_and_64_bit_sentinel(self) -> None:
        for value in (0, -1, (1 << 64) - 1, 1 << 64):
            with self.subTest(value=value), self.assertRaises(
                WindowsWriterLeaseEvidenceError
            ):
                scm, endpoint, _record_value, document = self.valid_material(
                    handle_value=value
                )
                validate_windows_writer_lease_observation(document, scm, endpoint)

    def test_duplicate_identity_and_conflict_fence_must_match_record(self) -> None:
        scm, endpoint, _record_value, document = self.valid_material()
        for field, value in (
            ("duplicate_final_path", "D:\\quant\\quant_platform\\state\\other.lock"),
            ("duplicate_volume_serial_number", 123),
            ("duplicate_file_id", "ab" * 16),
            ("duplicate_close_result", "still_open"),
            ("conflict_open_result", "opened"),
            ("conflict_open_error_code", 5),
        ):
            changed = copy.deepcopy(document)
            kernel = changed["kernel_lock_observation"]
            assert type(kernel) is dict
            kernel[field] = value
            _seal(kernel, "kernel_observation_sha256")
            changed["observation_aggregate_sha256"] = identity_sha256(
                [
                    {"name": "scm_process", "sha256": changed["scm_process_evidence_sha256"]},
                    {"name": "endpoint", "sha256": changed["endpoint_evidence_sha256"]},
                    {
                        "name": "lease_record",
                        "sha256": changed["lease_record"]["lease_record_sha256"],  # type: ignore[index]
                    },
                    {"name": "kernel_lock", "sha256": kernel["kernel_observation_sha256"]},
                ]
            )
            _seal(changed, "evidence_sha256")
            with self.subTest(field=field), self.assertRaises(
                WindowsWriterLeaseEvidenceError
            ):
                validate_windows_writer_lease_observation(changed, scm, endpoint)

    def test_upstream_types_are_exact_and_persistent_bytes_do_not_grant_authority(self) -> None:
        scm, endpoint, _record_value, document = self.valid_material()
        with self.assertRaises(WindowsWriterLeaseEvidenceError):
            validate_windows_writer_lease_observation(document, object(), endpoint)  # type: ignore[arg-type]
        with self.assertRaises(WindowsWriterLeaseEvidenceError):
            validate_windows_writer_lease_observation(document, scm, object())  # type: ignore[arg-type]
        evidence = WindowsWriterLeaseObservationEvidence.from_document(
            document, scm, endpoint
        )
        public = set(dir(evidence))
        self.assertFalse(
            public
            & {
                "qualify",
                "qualified",
                "canary",
                "write",
                "open_handle",
                "handle",
                "close_upstream",
            }
        )


if __name__ == "__main__":
    unittest.main()
