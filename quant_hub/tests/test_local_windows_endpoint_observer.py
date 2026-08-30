from __future__ import annotations

import copy
import ctypes
import inspect
import os
import pickle
import socket
import unittest
from unittest import mock

from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256
from quant_hub.ops.local_windows_endpoint_evidence import EXACT_RUNTIME_ENDPOINT_SCHEMA
from quant_hub.ops import local_windows_endpoint_observer as subject
from quant_hub.ops.local_windows_scm_process_evidence import (
    WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
    WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    WindowsScmProcessObservationEvidence,
)
from quant_hub.ops.local_steady_windows_scm_process_evidence import (
    STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
    STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    SteadyWindowsScmProcessObservationEvidence,
)
from quant_hub.ops.local_steady_windows_endpoint_evidence import (
    STEADY_EXACT_RUNTIME_ENDPOINT_SCHEMA,
    SteadyWindowsEndpointObservationEvidence,
)


def _with_hash(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = identity_sha256(value)
    return value


def _scm_evidence(
    *,
    host_pid: int = 4100,
    host_creation_time: int = 100_000,
    child_pid: int = 4200,
    child_creation_time: int = 100_100,
) -> WindowsScmProcessObservationEvidence:
    document: dict[str, object] = {
        "schema_version": WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
        "evidence_scope": WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
        "attempt_id": "attempt-1",
        "nonce": "deployment-nonce-1",
        "operation": "activation",
        "authorization_phase": "candidate_start_authorized",
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
        "service": {
            "service_name": "QuantResearchHub",
            "status": {"process_id": host_pid},
        },
        "host": {"pid": host_pid, "creation_time_100ns": host_creation_time},
        "child": {"pid": child_pid, "creation_time_100ns": child_creation_time},
        "direct_child_topology": {},
        "observation_aggregate_sha256": "e" * 64,
        "result": "identity_observed_not_writer_qualified",
    }
    _with_hash(document, "evidence_sha256")
    return WindowsScmProcessObservationEvidence(canonical_bytes(document))


def _endpoint_response(
    challenge: str,
    *,
    host_pid: object = 4100,
    host_creation_time: object = 100_000,
    child_pid: int = 4200,
    child_creation_time: object = 100_100,
    authority: str = "claim_not_independently_observed",
) -> dict[str, object]:
    return _with_hash(
        {
            "schema_version": EXACT_RUNTIME_ENDPOINT_SCHEMA,
            "status": "identity_claim_only",
            "probe_challenge": challenge,
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
            "service": {
                "service_name": "QuantResearchHub",
                "host_pid": host_pid,
                "host_creation_time_100ns": host_creation_time,
            },
            "child": {
                "child_pid": child_pid,
                "child_creation_time_100ns": child_creation_time,
            },
            "listener": {"local_address": "0.0.0.0", "local_port": 8765},
            "writer_lease": {
                "lease_id": "lease-attempt-1-candidate",
                "lease_nonce": "lease-nonce-1",
                "lease_epoch": 1,
                "lease_record_sha256": "f" * 64,
                "authority": authority,
            },
        },
        "endpoint_claim_sha256",
    )


def _steady_scm_evidence() -> SteadyWindowsScmProcessObservationEvidence:
    document: dict[str, object] = {
        "schema_version": STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
        "evidence_scope": STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
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
        "service": {
            "service_name": "QuantResearchHub",
            "status": {"process_id": 4100},
        },
        "host": {"pid": 4100, "creation_time_100ns": 100_000},
        "child": {"pid": 4200, "creation_time_100ns": 100_100},
        "direct_child_topology": {},
        "observation_aggregate_sha256": "c" * 64,
        "result": "steady_identity_observed_not_writer_qualified",
    }
    _with_hash(document, "evidence_sha256")
    return SteadyWindowsScmProcessObservationEvidence(
        canonical_bytes(document)
    )


def _steady_endpoint_response(
    challenge: str,
    *,
    lease_id: str = "steady-lease-1",
    lease_nonce: str = "d" * 48,
    lease_epoch: int = 1,
    lease_record_sha256: str = "d" * 64,
) -> dict[str, object]:
    return _with_hash(
        {
            "schema_version": STEADY_EXACT_RUNTIME_ENDPOINT_SCHEMA,
            "status": "steady_identity_claim_only",
            "probe_challenge": challenge,
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
            "service": {
                "service_name": "QuantResearchHub",
                "host_pid": 4100,
                "host_creation_time_100ns": 100_000,
            },
            "child": {
                "child_pid": 4200,
                "child_creation_time_100ns": 100_100,
            },
            "listener": {"local_address": "0.0.0.0", "local_port": 8765},
            "writer_lease": {
                "lease_id": lease_id,
                "lease_nonce": lease_nonce,
                "lease_epoch": lease_epoch,
                "lease_record_sha256": lease_record_sha256,
                "authority": "claim_not_independently_observed",
            },
            "job_identity_sha256": "e" * 64,
            "admission_binding_sha256": "f" * 64,
            "admission_state": "closed_pending_promotion",
        },
        "endpoint_claim_sha256",
    )


class _FakeEndpointApi:
    def __init__(self) -> None:
        self.calls: list[object] = []
        self.listener_sequences: list[tuple[subject._Ipv4Listener, ...]] = []
        self.response_child_pid = 4200
        self.response_host_pid: object = 4100
        self.response_host_creation_time: object = 100_000
        self.response_child_creation_time: object = 100_100
        self.response_authority = "claim_not_independently_observed"
        self.response_challenge: str | None = None
        self.noncanonical = False
        self.listener_owner: object = 4200

    def query_ipv4_listeners(self) -> tuple[subject._Ipv4Listener, ...]:
        self.calls.append("listeners")
        if self.listener_sequences:
            return self.listener_sequences.pop(0)
        return (subject._Ipv4Listener("0.0.0.0", 8765, 2, self.listener_owner),)  # type: ignore[arg-type]

    def probe_endpoint(self, challenge: str) -> subject._HttpProbe:
        self.calls.append(("probe", challenge))
        response = _endpoint_response(
            self.response_challenge or challenge,
            host_pid=self.response_host_pid,
            host_creation_time=self.response_host_creation_time,
            child_pid=self.response_child_pid,
            child_creation_time=self.response_child_creation_time,
            authority=self.response_authority,
        )
        body = canonical_bytes(response)
        if self.noncanonical:
            body += b"\n"
        return subject._HttpProbe(200, "application/json", body, response)


class _FakeSteadyEndpointApi(_FakeEndpointApi):
    def __init__(self) -> None:
        super().__init__()
        self.lease_id = "steady-lease-1"
        self.lease_nonce = "d" * 48
        self.lease_epoch = 1
        self.lease_record_sha256 = "d" * 64

    def probe_endpoint(self, challenge: str) -> subject._HttpProbe:
        self.calls.append(("probe", challenge))
        response = _steady_endpoint_response(
            challenge,
            lease_id=self.lease_id,
            lease_nonce=self.lease_nonce,
            lease_epoch=self.lease_epoch,
            lease_record_sha256=self.lease_record_sha256,
        )
        body = canonical_bytes(response)
        return subject._HttpProbe(200, "application/json", body, response)


class WindowsEndpointObserverTests(unittest.TestCase):
    challenge = "1" * 48

    def test_test_only_adapter_exercises_bracketed_algorithm_without_evidence_surface(self) -> None:
        api = _FakeEndpointApi()
        adapter = subject._TestOnlyWindowsEndpointObserverAdapter.for_test_only(api=api)
        observation = adapter.observe_test_only(_scm_evidence(), challenge=self.challenge)
        self.assertEqual(
            "test_only_windows_endpoint_observation_not_evidence",
            observation.scope,
        )
        self.assertFalse(hasattr(observation, "build_evidence"))
        self.assertNotIn("_TestOnlyWindowsEndpointObserverAdapter", subject.__all__)
        self.assertEqual(
            [
                "listeners",
                ("probe", self.challenge),
                "listeners",
                "listeners",
                ("probe", self.challenge),
                "listeners",
            ],
            api.calls,
        )
        with self.assertRaises(TypeError):
            pickle.dumps(observation)

    def test_steady_v2_adapter_and_evidence_are_tagged_observation_only(self) -> None:
        api = _FakeSteadyEndpointApi()
        adapter = subject._TestOnlyWindowsEndpointObserverAdapter.for_test_only(
            api=api
        )
        scm = _steady_scm_evidence()
        observation = adapter.observe_steady_test_only(
            scm, challenge=self.challenge
        )
        self.assertEqual(
            "test_only_steady_windows_endpoint_observation_not_evidence",
            observation.scope,
        )
        self.assertFalse(hasattr(observation, "build_evidence"))
        with self.assertRaises(TypeError):
            pickle.dumps(observation)
        collected = subject._WindowsSteadyEndpointObservationRunner(
            api=api
        ).observe(lambda: scm, challenge=self.challenge)
        document = subject._build_steady_evidence_document(
            collected,
            challenge=self.challenge,
            _authority_token=subject._API_TOKEN,
        )
        evidence = SteadyWindowsEndpointObservationEvidence.from_document(
            document, scm
        ).as_dict()
        self.assertEqual(
            "qrh-windows-endpoint-observation/v2",
            evidence["schema_version"],
        )
        self.assertEqual("steady_active", evidence["authority_kind"])
        self.assertEqual("steady_current", evidence["runtime_state_kind"])
        self.assertEqual(
            "steady_endpoint_observed_not_writer_qualified",
            evidence["result"],
        )
        self.assertNotIn("attempt_id", evidence)
        self.assertNotIn("nonce", evidence)
        with self.assertRaises(subject.WindowsEndpointObserverError):
            adapter.observe_steady_test_only(  # type: ignore[arg-type]
                _scm_evidence(), challenge=self.challenge
            )

    def test_listener_must_be_unique_wildcard_and_owned_by_scm_child(self) -> None:
        invalid_rows = (
            (),
            (
                subject._Ipv4Listener("0.0.0.0", 8765, 2, 4200),
                subject._Ipv4Listener("127.0.0.1", 8765, 2, 4200),
            ),
            (subject._Ipv4Listener("127.0.0.1", 8765, 2, 4200),),
            (subject._Ipv4Listener("0.0.0.0", 8765, 2, 9999),),
            (subject._Ipv4Listener("0.0.0.0", 8765, 5, 4200),),
        )
        for rows in invalid_rows:
            with self.subTest(rows=rows):
                api = _FakeEndpointApi()
                api.listener_sequences = [rows]
                adapter = subject._TestOnlyWindowsEndpointObserverAdapter.for_test_only(api=api)
                with self.assertRaises(subject.WindowsEndpointObserverError):
                    adapter.observe_test_only(_scm_evidence(), challenge=self.challenge)

    def test_listener_or_scm_identity_drift_across_http_probe_is_rejected(self) -> None:
        api = _FakeEndpointApi()
        api.listener_sequences = [
            (subject._Ipv4Listener("0.0.0.0", 8765, 2, 4200),),
            (subject._Ipv4Listener("0.0.0.0", 8765, 2, 4201),),
        ]
        adapter = subject._TestOnlyWindowsEndpointObserverAdapter.for_test_only(api=api)
        with self.assertRaises(subject.WindowsEndpointObserverError):
            adapter.observe_test_only(_scm_evidence(), challenge=self.challenge)

        provider_values = iter((_scm_evidence(), _scm_evidence(child_pid=4201)))
        runner = subject._WindowsEndpointObservationRunner(api=_FakeEndpointApi())
        with self.assertRaisesRegex(subject.WindowsEndpointObserverError, "漂移"):
            runner.observe(lambda: next(provider_values), challenge=self.challenge)

    def test_response_must_be_canonical_and_bind_challenge_process_and_non_authority(self) -> None:
        cases = (
            ("response_challenge", "2" * 48, "challenge"),
            ("response_child_pid", 9999, "child"),
            ("response_authority", "writer_qualified", "不得自授"),
            ("noncanonical", True, "canonical"),
        )
        for attribute, value, message in cases:
            with self.subTest(attribute=attribute):
                api = _FakeEndpointApi()
                setattr(api, attribute, value)
                adapter = subject._TestOnlyWindowsEndpointObserverAdapter.for_test_only(api=api)
                with self.assertRaisesRegex(subject.WindowsEndpointObserverError, message):
                    adapter.observe_test_only(_scm_evidence(), challenge=self.challenge)

    def test_shared_runner_rejects_bool_aliases_and_accepts_exact_integer_one(self) -> None:
        cases = (
            ("response_host_pid", {"host_pid": 1}),
            ("response_host_creation_time", {"host_creation_time": 1}),
            ("response_child_pid", {"child_pid": 1}),
            ("response_child_creation_time", {"child_creation_time": 1}),
            ("listener_owner", {"child_pid": 1}),
        )
        for attribute, identity in cases:
            with self.subTest(attribute=attribute):
                api = _FakeEndpointApi()
                if "child_pid" in identity:
                    api.listener_owner = identity["child_pid"]
                    if attribute != "response_child_pid":
                        api.response_child_pid = identity["child_pid"]
                if "host_pid" in identity:
                    api.response_host_pid = identity["host_pid"]
                if "host_creation_time" in identity:
                    api.response_host_creation_time = identity["host_creation_time"]
                if "child_creation_time" in identity:
                    api.response_child_creation_time = identity["child_creation_time"]
                setattr(api, attribute, True)
                adapter = subject._TestOnlyWindowsEndpointObserverAdapter.for_test_only(api=api)
                with self.assertRaises(subject.WindowsEndpointObserverError):
                    adapter.observe_test_only(
                        _scm_evidence(**identity),
                        challenge=self.challenge,
                    )

                exact_api = _FakeEndpointApi()
                if "child_pid" in identity:
                    exact_api.listener_owner = identity["child_pid"]
                    exact_api.response_child_pid = identity["child_pid"]
                if "host_pid" in identity:
                    exact_api.response_host_pid = identity["host_pid"]
                if "host_creation_time" in identity:
                    exact_api.response_host_creation_time = identity["host_creation_time"]
                if "child_creation_time" in identity:
                    exact_api.response_child_creation_time = identity["child_creation_time"]
                exact = subject._TestOnlyWindowsEndpointObserverAdapter.for_test_only(
                    api=exact_api
                ).observe_test_only(
                    _scm_evidence(**identity),
                    challenge=self.challenge,
                )
                self.assertEqual(
                    "test_only_windows_endpoint_observation_not_evidence",
                    exact.scope,
                )

    def test_strict_json_rejects_duplicate_fields_and_nonfinite_constants(self) -> None:
        with self.assertRaisesRegex(subject.WindowsEndpointObserverError, "重复"):
            subject._strict_json_object(b'{"a":1,"a":1}')
        with self.assertRaisesRegex(subject.WindowsEndpointObserverError, "非有限"):
            subject._strict_json_object(b'{"a":NaN}')

    def test_mib_ipv4_owner_pid_parser_uses_network_port_and_ctypes_offsets(self) -> None:
        offset = subject._MIB_TCPTABLE_OWNER_PID_ONE.table.offset
        row_size = ctypes.sizeof(subject._MIB_TCPROW_OWNER_PID)
        raw = bytearray(offset + row_size)
        raw[: ctypes.sizeof(subject.wintypes.DWORD)] = (1).to_bytes(
            ctypes.sizeof(subject.wintypes.DWORD), "little"
        )
        row = subject._MIB_TCPROW_OWNER_PID.from_buffer(raw, offset)
        row.dwState = 2
        row.dwLocalAddr = 0
        row.dwLocalPort = socket.htons(8765)
        row.dwOwningPid = 4200
        self.assertEqual(
            (subject._Ipv4Listener("0.0.0.0", 8765, 2, 4200),),
            subject._parse_ipv4_listener_table(bytes(raw)),
        )
        raw[0 : ctypes.sizeof(subject.wintypes.DWORD)] = (2).to_bytes(
            ctypes.sizeof(subject.wintypes.DWORD), "little"
        )
        with self.assertRaisesRegex(subject.WindowsEndpointObserverError, "row count"):
            subject._parse_ipv4_listener_table(bytes(raw))
        row.dwLocalPort = (1 << 16) | socket.htons(8765)
        raw[0 : ctypes.sizeof(subject.wintypes.DWORD)] = (1).to_bytes(
            ctypes.sizeof(subject.wintypes.DWORD), "little"
        )
        with self.assertRaisesRegex(subject.WindowsEndpointObserverError, "高位"):
            subject._parse_ipv4_listener_table(bytes(raw))

    def test_production_surface_is_noarg_exact_type_sealed_and_rejects_fake_loader(self) -> None:
        self.assertEqual({}, dict(inspect.signature(subject.ProductionWindowsEndpointObserver.load_exact_d).parameters))
        self.assertEqual(
            ["self", "scm_observation"],
            list(inspect.signature(subject.ProductionWindowsEndpointObserver.observe).parameters),
        )
        self.assertEqual(
            ["self", "scm_observation"],
            list(
                inspect.signature(
                    subject.ProductionWindowsEndpointObserver.observe_steady
                ).parameters
            ),
        )
        with mock.patch.object(
            subject._ProductionWindowsEndpointApi,
            "load_exact_d",
            return_value=_FakeEndpointApi(),
        ):
            with self.assertRaisesRegex(TypeError, "fake API"):
                subject.ProductionWindowsEndpointObserver.load_exact_d()
        uninitialized = object.__new__(subject._ProductionWindowsEndpointApi)
        with mock.patch.object(
            subject._ProductionWindowsEndpointApi,
            "load_exact_d",
            return_value=uninitialized,
        ):
            with self.assertRaisesRegex(subject.WindowsEndpointObserverError, "来源未闭合"):
                subject.ProductionWindowsEndpointObserver.load_exact_d()
        with self.assertRaisesRegex(TypeError, "非产品 API"):
            subject.LockedWindowsEndpointObservation(
                api=_FakeEndpointApi(),
                scm_observation=object(),  # type: ignore[arg-type]
                _construction_token=subject._LIVE_TOKEN,
            )
        if os.name == "nt":
            api = subject._ProductionWindowsEndpointApi.load_exact_d()
            observer = subject.ProductionWindowsEndpointObserver(
                api=api,
                _construction_token=subject._OBSERVER_TOKEN,
            )
            with self.assertRaises(TypeError):
                api.get_extended_tcp_table = object()
            with self.assertRaises(TypeError):
                observer._api = _FakeEndpointApi()
            with self.assertRaises(TypeError):
                pickle.dumps(observer)

    def test_production_observe_rejects_persistent_or_test_only_upstream(self) -> None:
        if os.name != "nt":
            self.skipTest("production loader 只允许 Windows")
        observer = subject.ProductionWindowsEndpointObserver.load_exact_d()
        with self.assertRaisesRegex(subject.WindowsEndpointObserverError, "exact live SCM"):
            observer.observe(_scm_evidence())  # type: ignore[arg-type]
        test_only = subject._TestOnlyWindowsEndpointObserverAdapter.for_test_only(
            api=_FakeEndpointApi()
        ).observe_test_only(_scm_evidence(), challenge=self.challenge)
        with self.assertRaisesRegex(subject.WindowsEndpointObserverError, "exact live SCM"):
            observer.observe(test_only)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
