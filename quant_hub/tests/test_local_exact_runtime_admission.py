from __future__ import annotations

from collections import deque
import inspect
import threading
import unittest

from quant_hub.ops.local_exact_runtime_admission import (
    ExactRuntimeAdmissionError,
    LockedTransientRuntimeAdmissionGate,
    ProductionExactRuntimeAdmissionGate,
    ProductionTransientRuntimeAdmissionGate,
    _AdmissionStateCore,
    _CORE_TOKEN,
    _PipeFrameReader,
    _TRANSIENT_GATE_TOKEN,
    _run_protocol,
    build_commit_frame,
    build_prepare_frame,
)
from quant_hub.ops.local_windows_writer_lease_holder import (
    ExactRuntimeLeaseIdentity,
)


class ExactRuntimeAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.binding = "1" * 64
        self.job = "2" * 64
        self.fatals: list[str] = []
        self.core = _AdmissionStateCore(
            self.binding,
            self.job,
            self.fatals.append,
            token=_CORE_TOKEN,
        )

    @staticmethod
    def _reader(chunks: list[bytes]) -> _PipeFrameReader:
        pending = deque(chunks)
        return _PipeFrameReader(lambda: pending.popleft() if pending else b"")

    def test_prepare_ready_commit_eof_is_the_only_admitted_sequence(self) -> None:
        challenge = "3" * 48
        ready_holder: list[str] = []

        def chunks():
            yield build_prepare_frame(self.binding)
            while not ready_holder:
                threading.Event().wait(0.001)
            yield build_commit_frame(self.binding, ready_holder[0])
            yield b""

        iterator = iter(chunks())
        reader = _PipeFrameReader(lambda: next(iterator))
        thread = threading.Thread(target=_run_protocol, args=(reader, self.core))
        thread.start()
        for _ in range(1000):
            if self.core.state == "ack_pending":
                break
            threading.Event().wait(0.001)
        self.assertEqual("ack_pending", self.core.state)
        ready_holder.append(self.core.acknowledge_ready(challenge))
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual("admitted", self.core.state)
        self.assertEqual([], self.fatals)

    def test_commit_without_fresh_ready_ack_is_fatal_and_never_admitted(self) -> None:
        self.core.accept_prepare(self.binding.encode("ascii"))
        self.core.accept_commit(self.binding.encode("ascii"), ("4" * 64).encode("ascii"))
        self.assertEqual("ack_pending", self.core.state)
        self.assertEqual(1, len(self.fatals))

    def test_ready_ack_is_exact_one_shot_and_requires_ack_pending(self) -> None:
        with self.assertRaises(ExactRuntimeAdmissionError):
            self.core.acknowledge_ready("3" * 48)
        self.core.accept_prepare(self.binding.encode("ascii"))
        first = self.core.acknowledge_ready("3" * 48)
        self.assertEqual(64, len(first))
        with self.assertRaises(ExactRuntimeAdmissionError):
            self.core.acknowledge_ready("3" * 48)

    def test_truncated_extra_foreign_and_eof_before_commit_are_rejected(self) -> None:
        cases = (
            [build_prepare_frame(self.binding)[:-1], b""],
            [b"OTHER " + self.binding.encode("ascii") + b"\n", b""],
            [build_prepare_frame("5" * 64), b""],
            [build_prepare_frame(self.binding), b""],
        )
        for chunks in cases:
            fatals: list[str] = []
            core = _AdmissionStateCore(
                self.binding, self.job, fatals.append, token=_CORE_TOKEN
            )
            with self.subTest(chunks=chunks), self.assertRaises(
                ExactRuntimeAdmissionError
            ):
                _run_protocol(self._reader(chunks), core)
            self.assertNotEqual("admitted", core.state)

    def test_product_loader_and_frame_builders_have_closed_signatures(self) -> None:
        self.assertEqual(
            [],
            list(inspect.signature(ProductionExactRuntimeAdmissionGate.load_from_service_stdin).parameters),
        )
        self.assertEqual(
            build_prepare_frame(self.binding),
            b"qrh-steady-admission-prepare/v1 " + self.binding.encode() + b"\n",
        )
        with self.assertRaises(ExactRuntimeAdmissionError):
            build_commit_frame("bad", "4" * 64)

    def test_transient_gate_is_permanently_closed_and_bytes_are_fatal(self) -> None:
        identity = ExactRuntimeLeaseIdentity(
            attempt_id="attempt-transient-gate",
            nonce="deployment-transient-gate",
            operation="activation",
            role="candidate",
            start_nonce="start-transient-gate",
            state_identity_sha256="6" * 64,
            release_id="release-transient-gate",
            manifest_sha256="7" * 64,
        )
        fatals: list[str] = []
        gate = LockedTransientRuntimeAdmissionGate(
            identity,
            {
                "host_pid": 101,
                "host_creation_time_100ns": 1_000,
                "child_pid": 102,
                "child_creation_time_100ns": 2_000,
            },
            self._reader([b"forbidden\n"]),
            fatals.append,
            token=_TRANSIENT_GATE_TOKEN,
        )
        gate._thread.join(timeout=2)
        self.assertFalse(gate._thread.is_alive())
        self.assertEqual("closed_pending_promotion", gate.state)
        self.assertEqual(1, len(fatals))
        self.assertIn("forbidden bytes", fatals[0])
        self.assertRegex(gate.job_identity_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(gate.admission_binding_sha256, r"^[0-9a-f]{64}$")
        self.assertFalse(hasattr(gate, "acknowledge_ready"))
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    ProductionTransientRuntimeAdmissionGate.load_from_service_stdin
                ).parameters
            ),
        )


if __name__ == "__main__":
    unittest.main()
