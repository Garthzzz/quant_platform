from __future__ import annotations

import copy
import inspect
import pickle
from pathlib import Path
import unittest

from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256
from quant_hub.ops.local_steady_runtime_identity import ExactSteadyRuntimeIdentity
from quant_hub.ops.local_steady_windows_writer_lease_evidence import (
    STEADY_WRITER_LEASE_RECORD_SCHEMA,
)
from quant_hub.ops.local_windows_writer_lease_holder import (
    ExactRuntimeLeaseIdentity,
    LockedSteadyWindowsWriterLease,
    LockedWindowsWriterLease,
    ProductionWindowsWriterLeaseHolder,
    WindowsWriterLeaseHolderError,
    _FileIdentity,
    _ProcessIdentity,
    _previous_epoch,
    _steady_lease_record,
)


def _identity() -> ExactSteadyRuntimeIdentity:
    return ExactSteadyRuntimeIdentity(
        authority_kind="steady_active",
        runtime_state_kind="steady_current",
        boot_nonce="0" * 48,
        active_release_sha256="1" * 64,
        binding_sha256="2" * 64,
        retention_aggregate_sha256="3" * 64,
        state_identity_sha256="4" * 64,
        release_id="release-steady-1",
        manifest_sha256="5" * 64,
        tooling_sha256="6" * 64,
        receipt_lineage_aggregate_sha256="7" * 64,
        legacy_c_live_fence_aggregate_sha256="8" * 64,
    )


def _record() -> dict[str, object]:
    return _steady_lease_record(
        _identity(),
        _ProcessIdentity(
            host_pid=101,
            host_creation_time_100ns=1001,
            child_pid=202,
            child_creation_time_100ns=1002,
        ),
        _FileIdentity(
            final_path=r"D:\quant\quant_platform\state\writer_authority.lock",
            volume_serial_number=42,
            file_id="a" * 32,
            size=0,
        ),
        handle=303,
        lease_nonce="9" * 48,
        lease_epoch=7,
        job_identity_sha256="b" * 64,
        admission_binding_sha256="c" * 64,
    )


class SteadyWindowsWriterLeaseHolderTests(unittest.TestCase):
    def test_v2_record_is_closed_and_can_seed_only_the_next_epoch(self) -> None:
        record = _record()
        self.assertEqual(STEADY_WRITER_LEASE_RECORD_SCHEMA, record["schema_version"])
        self.assertEqual("steady_active", record["authority_kind"])
        self.assertEqual("steady_current", record["runtime_state_kind"])
        self.assertEqual(
            7,
            _previous_epoch(
                canonical_bytes(record),
                expected_lock_path=Path(
                    r"D:\quant\quant_platform\state\writer_authority.lock"
                ),
            ),
        )
        serialized = canonical_bytes(record).decode("utf-8")
        for forbidden in (
            "attempt_id",
            "deployment_nonce",
            '"operation"',
            '"role"',
            "start_nonce",
        ):
            self.assertNotIn(forbidden, serialized)

    def test_resigned_alias_extra_hash_and_lease_id_tampering_are_rejected(self) -> None:
        cases: list[dict[str, object]] = []
        extra = copy.deepcopy(_record())
        extra["attempt_id"] = "forged-attempt"
        extra["lease_record_sha256"] = identity_sha256(
            {key: value for key, value in extra.items() if key != "lease_record_sha256"}
        )
        cases.append(extra)
        wrong_kind = copy.deepcopy(_record())
        wrong_kind["authority_kind"] = "transient_candidate"
        wrong_kind["lease_record_sha256"] = identity_sha256(
            {key: value for key, value in wrong_kind.items() if key != "lease_record_sha256"}
        )
        cases.append(wrong_kind)
        wrong_id = copy.deepcopy(_record())
        wrong_id["lease_id"] = "steady-lease-forged"
        wrong_id["lease_record_sha256"] = identity_sha256(
            {key: value for key, value in wrong_id.items() if key != "lease_record_sha256"}
        )
        cases.append(wrong_id)
        invalid_hash = copy.deepcopy(_record())
        invalid_hash["admission_binding_sha256"] = "not-a-hash"
        invalid_hash["lease_record_sha256"] = identity_sha256(
            {key: value for key, value in invalid_hash.items() if key != "lease_record_sha256"}
        )
        cases.append(invalid_hash)
        for record in cases:
            with self.subTest(record=record), self.assertRaises(
                WindowsWriterLeaseHolderError
            ):
                _previous_epoch(
                    canonical_bytes(record),
                    expected_lock_path=Path(
                        r"D:\quant\quant_platform\state\writer_authority.lock"
                    ),
                )

    def test_transient_and_steady_live_lease_types_are_not_interchangeable(self) -> None:
        self.assertIsNot(LockedWindowsWriterLease, LockedSteadyWindowsWriterLease)
        self.assertNotIsInstance(
            object.__new__(LockedSteadyWindowsWriterLease),
            LockedWindowsWriterLease,
        )
        with self.assertRaises(TypeError):
            class Forged(LockedSteadyWindowsWriterLease):
                pass
        uninitialized = object.__new__(LockedSteadyWindowsWriterLease)
        with self.assertRaises(TypeError):
            pickle.dumps(uninitialized)
        with self.assertRaises(TypeError):
            copy.copy(uninitialized)

    def test_product_steady_acquisition_requires_the_exact_live_gate(self) -> None:
        parameters = inspect.signature(
            ProductionWindowsWriterLeaseHolder.acquire_steady_exact_d
        ).parameters
        self.assertEqual(["self", "gate"], list(parameters))
        self.assertEqual(
            "LockedExactRuntimeAdmissionGate",
            parameters["gate"].annotation,
        )
        transient = ExactRuntimeLeaseIdentity(
            attempt_id="attempt-1",
            nonce="nonce-1",
            operation="activation",
            role="candidate",
            start_nonce="start-1",
            release_id="release-1",
            manifest_sha256="d" * 64,
            state_identity_sha256="e" * 64,
        )
        holder = object.__new__(ProductionWindowsWriterLeaseHolder)
        with self.assertRaises(TypeError):
            holder.acquire_steady_exact_d(transient)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
