from __future__ import annotations

import inspect
import json
from pathlib import Path
import threading
import unittest
from unittest.mock import PropertyMock, patch

from quant_hub.ops.local_exact_runtime_admission import (
    LockedExactRuntimeAdmissionGate,
    LockedTransientRuntimeAdmissionGate,
    _AdmissionStateCore,
    _CORE_TOKEN,
)
from quant_hub.ops.local_exact_runtime_import_closure import (
    _LockedExactRuntimeImportClosure,
)
from quant_hub.ops.local_exact_runtime_server import (
    _SteadyAdmissionWsgiGate,
    _TransientAdmissionWsgiGate,
    _steady_endpoint_claim,
    serve_steady_exact_runtime,
)
from quant_hub.ops.local_release_identity import identity_sha256
from quant_hub.ops.local_steady_runtime_identity import ExactSteadyRuntimeIdentity
from quant_hub.ops.local_steady_windows_endpoint_evidence import (
    STEADY_EXACT_RUNTIME_ENDPOINT_SCHEMA,
)
from quant_hub.ops.local_windows_writer_lease_holder import (
    LockedSteadyWindowsWriterLease,
    _FileIdentity,
    _ProcessIdentity,
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


def _gate() -> LockedExactRuntimeAdmissionGate:
    identity = _identity()
    process = {
        "host_pid": 101,
        "host_creation_time_100ns": 1001,
        "child_pid": 202,
        "child_creation_time_100ns": 1002,
    }
    job = identity_sha256(
        {
            "schema_version": "qrh-steady-service-job-identity/v1",
            "boot_nonce": identity.boot_nonce,
            "scm_identity_sha256": identity.scm_identity_sha256,
            **process,
        }
    )
    admission = identity_sha256(
        {
            "schema_version": "qrh-steady-admission-binding/v1",
            "boot_nonce": identity.boot_nonce,
            "state_identity_sha256": identity.state_identity_sha256,
            "release": dict(identity.release_ref),
            "job_identity_sha256": job,
        }
    )
    gate = object.__new__(LockedExactRuntimeAdmissionGate)
    object.__setattr__(gate, "_sealed", False)
    object.__setattr__(gate, "_identity", identity)
    object.__setattr__(gate, "_process_identity", process)
    object.__setattr__(gate, "_job_identity_sha256", job)
    object.__setattr__(gate, "_admission_binding_sha256", admission)
    object.__setattr__(
        gate,
        "_core",
        _AdmissionStateCore(admission, job, lambda _reason: None, token=_CORE_TOKEN),
    )
    object.__setattr__(gate, "_thread", threading.current_thread())
    object.__setattr__(gate, "_sealed", True)
    return gate


def _record(gate: LockedExactRuntimeAdmissionGate) -> dict[str, object]:
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
        job_identity_sha256=gate.job_identity_sha256,
        admission_binding_sha256=gate.admission_binding_sha256,
    )


def _probe_environ(**updates: object) -> dict[str, object]:
    environ: dict[str, object] = {
        "REQUEST_METHOD": "GET",
        "RAW_URI": "/deploymentz",
        "REQUEST_URI": "/deploymentz",
        "PATH_INFO": "/deploymentz",
        "QUERY_STRING": "",
        "HTTP_HOST": "127.0.0.1:8765",
        "REMOTE_ADDR": "127.0.0.1",
        "HTTP_X_QUANT_HUB_ENDPOINT_CHALLENGE": "d" * 48,
        "CONTENT_LENGTH": "",
        "CONTENT_TYPE": "",
    }
    environ.update(updates)
    return environ


class SteadyExactRuntimeServerTests(unittest.TestCase):
    def test_transient_outer_gate_never_admits_business(self) -> None:
        gate = object.__new__(LockedTransientRuntimeAdmissionGate)
        calls: list[dict[str, object]] = []
        statuses: list[str] = []

        def application(environ: dict[str, object], start_response: object):
            calls.append(environ)
            start_response(
                "200 OK",
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", "11"),
                    ("Cache-Control", "no-store"),
                ],
            )
            return [b"application"]

        wrapper = _TransientAdmissionWsgiGate(application, gate)
        business = _probe_environ(
            RAW_URI="/api/v1/research",
            REQUEST_URI="/api/v1/research",
            PATH_INFO="/api/v1/research",
        )
        response = wrapper(
            business, lambda status, _headers: statuses.append(status)
        )
        self.assertEqual([], calls)
        self.assertEqual(["503 Service Unavailable"], statuses)
        self.assertEqual("starting_not_admitted", json.loads(response[0])["code"])

        statuses.clear()
        self.assertEqual(
            [b"application"],
            wrapper(_probe_environ(), lambda status, _headers: statuses.append(status)),
        )
        canary = _probe_environ(
            REQUEST_METHOD="POST",
            RAW_URI="/deployment-canaryz",
            REQUEST_URI="/deployment-canaryz",
            PATH_INFO="/deployment-canaryz",
            CONTENT_TYPE="application/json",
            CONTENT_LENGTH="32",
        )
        self.assertEqual(
            [b"application"],
            wrapper(canary, lambda status, _headers: statuses.append(status)),
        )
        self.assertEqual(2, len(calls))

    def test_outer_gate_rejects_business_before_flask_and_allows_exact_probe(self) -> None:
        gate = _gate()
        calls: list[dict[str, object]] = []
        statuses: list[str] = []

        def application(environ: dict[str, object], start_response: object):
            calls.append(environ)
            start_response(
                "200 OK",
                [
                    ("Content-Type", "application/json"),
                    ("Content-Length", "11"),
                    ("Cache-Control", "no-store"),
                ],
            )
            return [b"application"]

        wrapper = _SteadyAdmissionWsgiGate(application, gate)
        response = wrapper(
            _probe_environ(
                RAW_URI="/api/v1/research",
                REQUEST_URI="/api/v1/research",
                PATH_INFO="/api/v1/research",
            ),
            lambda status, _headers: statuses.append(status),
        )
        self.assertEqual([], calls)
        self.assertEqual(["503 Service Unavailable"], statuses)
        self.assertEqual("starting_not_admitted", json.loads(response[0])["code"])

        statuses.clear()
        self.assertEqual(
            [b"application"],
            wrapper(
                _probe_environ(),
                lambda status, _headers: statuses.append(status),
            ),
        )
        self.assertEqual(1, len(calls))
        self.assertEqual(["200 OK"], statuses)

    def test_closed_gate_rejects_probe_aliases_before_application(self) -> None:
        gate = _gate()
        calls: list[object] = []
        wrapper = _SteadyAdmissionWsgiGate(
            lambda environ, start: calls.append((environ, start)), gate
        )
        cases = (
            _probe_environ(RAW_URI="/Deploymentz", PATH_INFO="/Deploymentz"),
            _probe_environ(RAW_URI="/deploymentz?x=1", QUERY_STRING="x=1"),
            _probe_environ(HTTP_X_FORWARDED_FOR="127.0.0.1"),
            _probe_environ(REMOTE_ADDR="::1"),
            _probe_environ(REQUEST_METHOD="POST"),
        )
        for environ in cases:
            statuses: list[str] = []
            with self.subTest(environ=environ):
                wrapper(environ, lambda status, _headers: statuses.append(status))
                self.assertEqual(["503 Service Unavailable"], statuses)
        self.assertEqual([], calls)

    def test_admitted_gate_allows_business_application(self) -> None:
        gate = _gate()
        object.__setattr__(gate._core, "_state", "admitted")  # noqa: SLF001
        calls: list[object] = []
        wrapper = _SteadyAdmissionWsgiGate(
            lambda environ, _start: calls.append(environ) or [b"ok"], gate
        )
        environ = _probe_environ(
            RAW_URI="/api/v1/research",
            REQUEST_URI="/api/v1/research",
            PATH_INFO="/api/v1/research",
        )
        self.assertEqual([b"ok"], wrapper(environ, lambda *_args: None))
        self.assertEqual([environ], calls)

    def test_steady_endpoint_binds_v2_writer_gate_and_one_ready_ack(self) -> None:
        gate = _gate()
        record = _record(gate)
        lease = object.__new__(LockedSteadyWindowsWriterLease)
        closure = object.__new__(_LockedExactRuntimeImportClosure)
        claim = {
            "lease_id": record["lease_id"],
            "lease_nonce": record["lease_nonce"],
            "lease_epoch": record["lease_epoch"],
            "lease_record_sha256": record["lease_record_sha256"],
            "authority": "claim_not_independently_observed",
        }
        with patch.object(
            LockedSteadyWindowsWriterLease,
            "_canary_checkpoint",
            return_value=(record, Path(r"D:\quant\quant_platform"), object()),
        ), patch.object(
            LockedSteadyWindowsWriterLease,
            "lease_claim",
            new_callable=PropertyMock,
            return_value=claim,
        ), patch.object(
            _LockedExactRuntimeImportClosure, "checkpoint", return_value=None
        ):
            closed = _steady_endpoint_claim(lease, gate, "d" * 48, closure)
            self.assertEqual(
                STEADY_EXACT_RUNTIME_ENDPOINT_SCHEMA,
                closed["schema_version"],
            )
            self.assertEqual("closed_pending_promotion", closed["admission_state"])
            self.assertEqual(
                identity_sha256(
                    {
                        key: value
                        for key, value in closed.items()
                        if key != "endpoint_claim_sha256"
                    }
                ),
                closed["endpoint_claim_sha256"],
            )
            gate._core.accept_prepare(  # noqa: SLF001
                gate.admission_binding_sha256.encode("ascii")
            )
            ready = _steady_endpoint_claim(lease, gate, "e" * 48, closure)
            self.assertEqual("ack_pending", ready["admission_state"])
            self.assertIsNotNone(
                gate._core.ready_ack_binding_sha256  # noqa: SLF001
            )

    def test_product_steady_server_signature_is_exact(self) -> None:
        self.assertEqual(
            ["lease", "gate", "closure"],
            list(inspect.signature(serve_steady_exact_runtime).parameters),
        )


if __name__ == "__main__":
    unittest.main()
