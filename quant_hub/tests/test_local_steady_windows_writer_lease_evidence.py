from __future__ import annotations

from copy import deepcopy
import unittest

from quant_hub.ops.local_release_identity import identity_sha256
from quant_hub.ops import local_windows_endpoint_observer as endpoint_observer
from quant_hub.ops import local_windows_writer_lease_observer as writer_observer
from quant_hub.ops.local_steady_windows_endpoint_evidence import (
    SteadyWindowsEndpointObservationEvidence,
)
from quant_hub.ops.local_steady_windows_writer_lease_evidence import (
    STEADY_WRITER_LEASE_RECORD_SCHEMA,
    SteadyWindowsWriterLeaseObservationEvidence,
    validate_steady_writer_lease_record,
)
from quant_hub.ops.local_windows_writer_lease_evidence import (
    WRITER_LEASE_RECORD_FINAL_PATH,
    WRITER_LEASE_RECORD_RELATIVE_PATH,
    WRITER_LOCK_FINAL_PATH,
    WRITER_LOCK_RELATIVE_PATH,
    WindowsWriterLeaseEvidenceError,
)
from tests.test_local_windows_endpoint_observer import (
    _FakeSteadyEndpointApi,
    _scm_evidence,
    _steady_scm_evidence,
)


def _self_hash(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = identity_sha256(value)
    return value


class SteadyWindowsWriterLeaseEvidenceTests(unittest.TestCase):
    challenge = "1" * 48

    def materialize(self) -> tuple[object, object, dict[str, object]]:
        scm = _steady_scm_evidence()
        lease_nonce = "d" * 48
        holder = _self_hash(
            {
                "service_name": "QuantResearchHub",
                "host_pid": 4100,
                "host_creation_time_100ns": 100_000,
                "child_pid": 4200,
                "child_creation_time_100ns": 100_100,
            },
            "holder_identity_sha256",
        )
        lock = _self_hash(
            {
                "relative_path": WRITER_LOCK_RELATIVE_PATH,
                "final_path": WRITER_LOCK_FINAL_PATH,
                "handle_value": 441,
                "volume_serial_number": 51,
                "file_id": "ab" * 16,
                "desired_access": "GENERIC_READ|GENERIC_WRITE",
                "share_mode": "FILE_SHARE_READ",
                "creation_disposition": "OPEN_ALWAYS",
            },
            "lock_identity_sha256",
        )
        record: dict[str, object] = {
            "schema_version": STEADY_WRITER_LEASE_RECORD_SCHEMA,
            "authority_kind": "steady_active",
            "runtime_state_kind": "steady_current",
            "boot_nonce": "1" * 48,
            "active_release_sha256": "2" * 64,
            "binding_sha256": "3" * 64,
            "retention_aggregate_sha256": "4" * 64,
            "state_identity_sha256": "5" * 64,
            "tooling_sha256": "6" * 64,
            "receipt_lineage_aggregate_sha256": "7" * 64,
            "legacy_c_live_fence_aggregate_sha256": "8" * 64,
            "authorization_sha256": "9" * 64,
            "scm_identity_sha256": "a" * 64,
            "release": {
                "release_id": "release-r1",
                "release_path": "D:\\quant\\quant_platform\\releases\\release-r1",
                "manifest_sha256": "b" * 64,
            },
            "lease_id": "pending",
            "lease_nonce": lease_nonce,
            "lease_epoch": 1,
            "holder": holder,
            "lock": lock,
            "job_identity_sha256": "e" * 64,
            "admission_binding_sha256": "f" * 64,
        }
        from quant_hub.ops import local_steady_windows_writer_lease_evidence as contract

        record["lease_id"] = contract._expected_lease_id(record)
        _self_hash(record, "lease_record_sha256")

        api = _FakeSteadyEndpointApi()
        api.lease_id = str(record["lease_id"])
        api.lease_nonce = lease_nonce
        api.lease_epoch = 1
        api.lease_record_sha256 = str(record["lease_record_sha256"])
        collected = endpoint_observer._WindowsSteadyEndpointObservationRunner(
            api=api
        ).observe(lambda: scm, challenge=self.challenge)
        endpoint_document = endpoint_observer._build_steady_evidence_document(
            collected,
            challenge=self.challenge,
            _authority_token=endpoint_observer._API_TOKEN,
        )
        endpoint = SteadyWindowsEndpointObservationEvidence.from_document(
            endpoint_document, scm
        )
        return scm, endpoint, record

    def test_record_and_kernel_observation_form_tagged_v2_not_authority(self) -> None:
        scm, endpoint, record = self.materialize()
        validated = validate_steady_writer_lease_record(
            record, scm, endpoint
        )
        self.assertEqual(record, validated)
        kernel = _self_hash(
            {
                "source_process_pid": 4200,
                "source_process_creation_time_100ns": 100_100,
                "source_handle_value": 441,
                "duplicate_final_path": WRITER_LOCK_FINAL_PATH,
                "duplicate_volume_serial_number": 51,
                "duplicate_file_id": "ab" * 16,
                "duplicate_close_result": "closed_before_conflict_probe",
                "conflict_open_result": "sharing_violation",
                "conflict_open_error_code": 32,
            },
            "kernel_observation_sha256",
        )
        collected = writer_observer._CollectedSteadyWriterLeaseObservation(
            scm_evidence=scm,
            endpoint_evidence=endpoint,
            lease_record=record,
            kernel_observation=kernel,
        )
        document = writer_observer._build_steady_evidence_document(
            collected, _authority_token=writer_observer._API_TOKEN
        )
        evidence = SteadyWindowsWriterLeaseObservationEvidence.from_document(
            document, scm, endpoint
        ).as_dict()
        self.assertEqual(
            "qrh-windows-writer-lease-observation/v2",
            evidence["schema_version"],
        )
        self.assertEqual("steady_active", evidence["authority_kind"])
        self.assertEqual("steady_current", evidence["runtime_state_kind"])
        self.assertEqual(
            "steady_writer_lease_observed_not_admission_qualified",
            evidence["result"],
        )
        self.assertNotIn("attempt_id", evidence)
        self.assertNotIn("nonce", evidence)

        drift = deepcopy(record)
        drift["job_identity_sha256"] = "1" * 64
        from quant_hub.ops import local_steady_windows_writer_lease_evidence as contract

        drift["lease_id"] = contract._expected_lease_id(drift)
        _self_hash(drift, "lease_record_sha256")
        with self.assertRaisesRegex(
            WindowsWriterLeaseEvidenceError, "job/admission"
        ):
            validate_steady_writer_lease_record(drift, scm, endpoint)
        with self.assertRaises(WindowsWriterLeaseEvidenceError):
            validate_steady_writer_lease_record(  # type: ignore[arg-type]
                record, _scm_evidence(), endpoint
            )

    def test_fixed_paths_remain_exact_d(self) -> None:
        self.assertEqual(
            r"D:\quant\quant_platform\state\writer_authority.lock",
            WRITER_LOCK_FINAL_PATH,
        )
        self.assertEqual(
            r"D:\quant\quant_platform\state\writer_lease.json",
            WRITER_LEASE_RECORD_FINAL_PATH,
        )
        self.assertEqual("state/writer_authority.lock", WRITER_LOCK_RELATIVE_PATH)
        self.assertEqual(
            "state/writer_lease.json",
            WRITER_LEASE_RECORD_RELATIVE_PATH,
        )


if __name__ == "__main__":
    unittest.main()
