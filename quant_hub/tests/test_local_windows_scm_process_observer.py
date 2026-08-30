from __future__ import annotations

from contextlib import contextmanager
import ctypes
import inspect
import os
from pathlib import Path
import pickle
import shutil
import subprocess
from typing import Iterator
import unittest
from unittest.mock import patch

from quant_hub.ops.local_deployment_persistence import (
    DeploymentLockBusy,
    LocalDeploymentPersistenceError,
    LockedWindowsScmProcessHandleTracking,
    LockedWindowsSteadyScmProcessHandleTracking,
    LockedWindowsSteadyWriterLeaseHandleTracking,
    UnsafeLocalPath,
)
from quant_hub.ops import local_steady_legacy_c_fence as legacy_c_fence_module
from quant_hub.ops import local_steady_receipt_lineage as receipt_lineage_module
from quant_hub.ops import local_steady_start_authorization as steady_start_module
from quant_hub.ops.local_windows_scm_process_observer import (
    LIVE_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    LockedWindowsScmProcessObservation,
    ProductionWindowsScmProcessObserver,
    WindowsScmProcessObserverError,
    _FileProbe,
    _ProcessEntry,
    _ProcessProbe,
    _ProductionWindowsApi,
    _ServiceConfig,
    _ServiceStatus,
    _TEST_ONLY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    _TestOnlyWindowsScmProcessObservation,
    _TestOnlySteadyWindowsScmProcessObservation,
    _TestOnlyWindowsScmProcessObserverAdapter,
    _HKEY_LOCAL_MACHINE,
    _PRODUCTION_API_TOKEN,
    _build_steady_production_evidence_document,
    _predefined_hkey,
    _predefined_hkey_for_pointer_bits,
)
from quant_hub.ops.local_steady_windows_scm_process_evidence import (
    SteadyWindowsScmProcessObservationEvidence,
)
from tests.test_local_deployment_persistence import (
    PersistenceFixture,
    history_to,
    journal,
    release,
)
from tests import test_local_deployment_persistence as persistence_tests


class _FixedObserverApi:
    def __init__(self, inputs: object, *, mutation: str | None = None):
        self.service_executable = str(inputs.service_executable)
        self.child_executable = str(inputs.child_executable)
        self.python_class = str(inputs.python_class)
        self.child_argv = tuple(inputs.child_argv)
        self.mutation = mutation
        self._process_handles = iter((104, 107))
        self._file_handles = iter((105, 108))
        self._snapshot_handles = iter((106, 109, *range(110, 160)))
        self._created_snapshot_handles: list[int] = []
        self._status_calls = 0
        self._snapshot_calls = 0
        self._process_calls: dict[int, int] = {}
        self._file_calls: dict[int, int] = {}
        self._host_file_handle = 105

    def open_scm_manager_w(self, *arguments: object) -> int:
        del arguments
        return 101

    def open_service_w(self, *arguments: object) -> int:
        del arguments
        return 102

    def reg_open_key_ex_w(self, *arguments: object) -> int:
        output = arguments[-1]
        ctypes.cast(output, ctypes.POINTER(ctypes.c_void_p)).contents.value = 103
        return 0

    def open_process(self, *arguments: object) -> int:
        del arguments
        return next(self._process_handles)

    def create_file_w(self, *arguments: object) -> int:
        del arguments
        handle = next(self._file_handles)
        if self.mutation == "known_invalid_host_file" and handle == 105:
            invalid = ctypes.c_void_p(-1).value
            assert type(invalid) is int
            return invalid
        return handle

    def create_toolhelp32_snapshot(self, *arguments: object) -> int:
        del arguments
        handle = next(self._snapshot_handles)
        self._created_snapshot_handles.append(handle)
        return handle

    def query_service_config(self, handle: int) -> _ServiceConfig:
        if handle != 102:
            raise AssertionError("wrong service handle")
        return _ServiceConfig(
            16,
            2,
            1,
            subprocess.list2cmdline([self.service_executable]),
            "LocalSystem",
        )

    def query_service_status(self, handle: int) -> _ServiceStatus:
        if handle != 102:
            raise AssertionError("wrong service handle")
        self._status_calls += 1
        pid = 4200 if self.mutation == "service_pid_drift" and self._status_calls == 2 else 4100
        return _ServiceStatus(4, 1, 0, 0, 0, 0, pid, 0)

    def query_python_class(self, handle: int) -> str:
        if handle != 103:
            raise AssertionError("wrong registry handle")
        return self.python_class

    def query_process(self, handle: int, expected_pid: int) -> _ProcessProbe:
        expected_handle = 104 if expected_pid == 4100 else 107
        if handle != expected_handle:
            raise AssertionError("wrong process handle")
        count = self._process_calls.get(expected_pid, 0) + 1
        self._process_calls[expected_pid] = count
        live = True
        if expected_pid == 4100:
            creation = (
                1_400_001
                if self.mutation == "host_creation_drift" and count == 2
                else 1_400_000
            )
            executable = self.service_executable
            argv = (self.service_executable,)
        else:
            creation = 1_400_100
            executable = self.child_executable
            argv = self.child_argv
            if self.mutation == "child_argv_mismatch":
                argv = argv[:-1]
            if self.mutation == "post_topology_child_exit" and count >= 4:
                live = False
        return _ProcessProbe(
            expected_pid,
            creation,
            executable,
            subprocess.list2cmdline(list(argv)),
            live,
        )

    def enumerate_processes(self, snapshot_handle: int) -> tuple[_ProcessEntry, ...]:
        self._snapshot_calls += 1
        if (
            not self._created_snapshot_handles
            or snapshot_handle != self._created_snapshot_handles[-1]
        ):
            raise AssertionError("wrong snapshot handle")
        entries = [_ProcessEntry(4100, 720), _ProcessEntry(4101, 4100)]
        if self.mutation == "second_snapshot_extra_child" and self._snapshot_calls == 2:
            entries.append(_ProcessEntry(4102, 4100))
        if self.mutation == "live_extra_child" and self._snapshot_calls >= 3:
            entries.append(_ProcessEntry(4102, 4100))
        if self.mutation == "live_child_missing" and self._snapshot_calls >= 3:
            entries = [_ProcessEntry(4100, 720)]
        if self.mutation == "live_child_replaced" and self._snapshot_calls >= 3:
            entries = [_ProcessEntry(4100, 720), _ProcessEntry(4102, 4100)]
        if self.mutation == "live_host_missing" and self._snapshot_calls >= 3:
            entries = [_ProcessEntry(4101, 4100)]
        return tuple(entries)

    def query_file(self, handle: int) -> _FileProbe:
        count = self._file_calls.get(handle, 0) + 1
        self._file_calls[handle] = count
        if handle == self._host_file_handle:
            path = self.service_executable
            file_hash = "2" * 64
            if self.mutation == "host_file_drift" and count == 2:
                file_hash = "4" * 64
        elif handle == 108:
            path = self.child_executable
            file_hash = "3" * 64
        else:
            raise AssertionError("wrong file handle")
        return _FileProbe(path, "1" * 64, file_hash)


class WindowsScmProcessObserverTests(PersistenceFixture):
    def setUp(self) -> None:
        super().setUp()
        self.r_minus_1 = release(
            "release-r-minus-1",
            self.payloads["release-r-minus-1"],
            "8",
            include_migrations=True,
        )
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r1 = release(
            "release-r1",
            self.payloads["release-r1"],
            "a",
            include_migrations=True,
        )
        for document in (self.r_minus_1, self.r0, self.r1):
            self.materialize(document)

    @contextmanager
    def bound_input(self, suffix: str) -> Iterator[tuple[object, object, object]]:
        attempt = f"windows-observer-{suffix}"
        nonce = f"nonce-windows-observer-{suffix}"
        first = journal(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            operation="activation",
            attempt=attempt,
            nonce=nonce,
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            try:
                yield lock, workspace, inputs
            finally:
                self.assertEqual(
                    set(), workspace._windows_scm_process_handle_tracking
                )
                closures.close()
                workspace.close()

    @contextmanager
    def close_recording(self) -> Iterator[list[int]]:
        closed: list[int] = []

        def close_slot(
            tracking: LockedWindowsScmProcessHandleTracking, slot: object
        ) -> None:
            del tracking
            handle = slot.value
            if type(handle) is not int:
                raise AssertionError("observer fake slot 不含 exact int handle")
            closed.append(handle)
            slot.value = None
            slot.phase = "closed"

        with patch.object(
            LockedWindowsScmProcessHandleTracking,
            "_close_slot_owned",
            new=close_slot,
        ):
            yield closed

    @contextmanager
    def steady_close_recording(self) -> Iterator[list[int]]:
        closed: list[int] = []

        def close_slot(
            tracking: LockedWindowsSteadyScmProcessHandleTracking,
            slot: object,
        ) -> None:
            del tracking
            handle = slot.value
            if type(handle) is not int:
                raise AssertionError("steady observer fake slot 缺 exact int handle")
            closed.append(handle)
            slot.value = None
            slot.phase = "closed"

        with patch.object(
            LockedWindowsSteadyScmProcessHandleTracking,
            "_close_slot_owned",
            new=close_slot,
        ):
            yield closed

    @contextmanager
    def bound_steady_input(
        self,
    ) -> Iterator[tuple[object, object, object]]:
        tooling_adapter = (
            persistence_tests.RetentionContractTests.materialize_exact_tooling(
                self
            )
        )
        shutil.rmtree(
            self.persistence.layout.releases / self.r1["release_id"]
        )
        self.write_pair(self.r0, self.r_minus_1)
        persistence_tests.RetentionContractTests.materialize_steady_receipt_lineage(
            self,
            active_release=self.r0,
            prior_release=self.r_minus_1,
        )
        legacy_adapter = (
            legacy_c_fence_module._TestOnlySteadyLegacyCPrelaunchObserverAdapter.for_test_only(
                {
                    "services": [],
                    "processes": [],
                    "listeners": [],
                }
            )
        )
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            facts = self.persistence.lock_steady_pair_static_facts(lock, workspace)
            closures = self.persistence.lock_steady_release_closures(
                lock, workspace, facts
            )
            tooling = tooling_adapter.observe_steady_test_only(
                workspace, facts, closures
            )
            lineage = (
                receipt_lineage_module._TestOnlySteadyReceiptLineageObserverAdapter.for_test_only().observe_test_only(
                    workspace, facts, closures, tooling
                )
            )
            fence = legacy_adapter.observe_test_only(
                workspace, facts, closures, tooling, lineage
            )
            authorizer = (
                steady_start_module._TestOnlyExactSteadyStartAuthorizerAdapter.for_test_only()
            )
            authorization = authorizer.authorize_test_only(
                workspace, facts, closures, tooling, lineage, fence
            )
            inputs = authorizer.bind_scm_process_observation_input_test_only(
                workspace, authorization, closures
            )
            yield lock, workspace, inputs
            self.assertEqual(
                set(), workspace._steady_windows_scm_process_handle_tracking
            )
            self.assertEqual(
                set(), workspace._steady_windows_writer_lease_handle_tracking
            )

    @staticmethod
    def load_with(
        api: _FixedObserverApi,
    ) -> _TestOnlyWindowsScmProcessObserverAdapter:
        return _TestOnlyWindowsScmProcessObserverAdapter.for_test_only(api=api)

    def test_public_loader_and_live_observation_are_closed_process_local_surfaces(
        self,
    ) -> None:
        self.assertEqual(
            (), tuple(inspect.signature(ProductionWindowsScmProcessObserver.load_exact_d).parameters)
        )
        self.assertEqual(
            ("self", "persistence", "lock", "workspace", "inputs"),
            tuple(inspect.signature(ProductionWindowsScmProcessObserver.observe).parameters),
        )
        fake = object()
        with patch.object(
            _ProductionWindowsApi, "load_exact_d", return_value=fake
        ), self.assertRaisesRegex(TypeError, "fake"):
            ProductionWindowsScmProcessObserver.load_exact_d()
        uninitialized = object.__new__(_ProductionWindowsApi)
        with patch.object(
            _ProductionWindowsApi, "load_exact_d", return_value=uninitialized
        ), self.assertRaises(WindowsScmProcessObserverError):
            ProductionWindowsScmProcessObserver.load_exact_d()
        with self.close_recording() as closed, self.bound_input("valid") as (
            lock,
            workspace,
            inputs,
        ):
            observer = self.load_with(_FixedObserverApi(inputs))
            with self.assertRaises(TypeError):
                ProductionWindowsScmProcessObserver.load_exact_d(api=object())  # type: ignore[call-arg]
            with self.assertRaises(TypeError):
                pickle.dumps(observer)
            observation = observer.observe_test_only(
                self.persistence, lock, workspace, inputs
            )
            self.assertIs(type(observation), _TestOnlyWindowsScmProcessObservation)
            self.assertEqual(
                _TEST_ONLY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
                observation.scope,
            )
            self.assertFalse(hasattr(observation, "__dict__"))
            self.assertEqual(
                {"close", "scope", "validate_live_for_test_only"},
                {name for name in dir(observation) if not name.startswith("_")},
            )
            for forbidden in (
                "build_evidence",
                "from_document",
                "from_mapping",
                "as_dict",
                "raw_handle",
                "writer_lease",
                "qualify",
            ):
                self.assertFalse(hasattr(observation, forbidden))
            self.assertFalse(hasattr(observation._collected, "document"))
            with self.assertRaises(TypeError):
                pickle.dumps(observation)
            observation.close()
            self.assertEqual(
                [106, 109, 110, 108, 107, 105, 104, 103, 102, 101],
                closed,
            )
            with self.assertRaises(UnsafeLocalPath):
                observation.validate_live_for_test_only()

    @unittest.skipUnless(os.name == "nt", "steady tooling/live namespace 仅支持 Windows")
    def test_steady_overload_uses_distinct_input_tracking_and_live_observation(
        self,
    ) -> None:
        self.assertEqual(
            ("self", "persistence", "lock", "workspace", "inputs"),
            tuple(
                inspect.signature(
                    ProductionWindowsScmProcessObserver.observe_steady
                ).parameters
            ),
        )
        with self.steady_close_recording() as closed, self.bound_steady_input() as (
            lock,
            workspace,
            inputs,
        ):
            observer = self.load_with(_FixedObserverApi(inputs))
            observation = observer.observe_steady_test_only(
                self.persistence, lock, workspace, inputs
            )
            self.assertIs(
                type(observation), _TestOnlySteadyWindowsScmProcessObservation
            )
            self.assertIs(
                type(observation._collected.tracking),
                LockedWindowsSteadyScmProcessHandleTracking,
            )
            self.assertEqual(
                "windows_steady_scm_process_handle_tracking_only",
                observation._collected.tracking.scope,
            )
            self.assertEqual(
                "test_only_steady_windows_scm_process_observation_not_evidence",
                observation.scope,
            )
            for forbidden in (
                "attempt_id",
                "nonce",
                "operation",
                "role",
                "start_nonce",
                "build_evidence",
                "qualify",
                "__dict__",
            ):
                self.assertFalse(hasattr(observation, forbidden), forbidden)
            with self.assertRaises(TypeError):
                pickle.dumps(observation)
            document = _build_steady_production_evidence_document(
                inputs,
                observation._collected,
                _authority_token=_PRODUCTION_API_TOKEN,
            )
            evidence = SteadyWindowsScmProcessObservationEvidence.from_document(
                document, inputs
            )
            evidence_document = evidence.as_dict()
            self.assertEqual(
                "qrh-windows-scm-process-observation/v2",
                evidence_document["schema_version"],
            )
            self.assertEqual("steady_active", evidence_document["authority_kind"])
            self.assertEqual("steady_current", evidence_document["runtime_state_kind"])
            self.assertEqual(workspace.boot_nonce, evidence_document["boot_nonce"])
            self.assertEqual(
                "steady_identity_observed_not_writer_qualified",
                evidence_document["result"],
            )
            self.assertNotIn("attempt_id", evidence_document)
            self.assertNotIn("nonce", evidence_document)
            writer_tracking = (
                self.persistence.prepare_windows_steady_writer_lease_handle_tracking(
                    lock,
                    workspace,
                    observation._collected.tracking,
                )
            )
            with self.assertRaises(DeploymentLockBusy):
                self.persistence.prepare_windows_writer_lease_handle_tracking(  # type: ignore[arg-type]
                    lock,
                    workspace,
                    observation._collected.tracking,
                )
            self.assertIs(
                type(writer_tracking),
                LockedWindowsSteadyWriterLeaseHandleTracking,
            )
            self.assertEqual(
                "windows_steady_writer_lease_handle_tracking_only",
                writer_tracking.scope,
            )
            self.assertFalse(hasattr(writer_tracking, "attempt_id"))
            self.assertFalse(hasattr(writer_tracking, "nonce"))
            writer_tracking.close()
            observation.close()
            self.assertEqual(
                [106, 109, 110, 108, 107, 105, 104, 103, 102, 101],
                closed,
            )

    def test_predefined_hkey_uses_long_to_pointer_signed_extension(self) -> None:
        pointer_bits = ctypes.sizeof(ctypes.c_void_p) * 8
        for raw in (0x80000000, 0x80000001, 0x80000002, 0x80000003):
            with self.subTest(raw=hex(raw), pointer_bits=pointer_bits):
                expected = ctypes.c_void_p(ctypes.c_int32(raw).value).value
                self.assertIs(type(expected), int)
                self.assertEqual(expected, _predefined_hkey(raw))
                self.assertEqual(raw, _predefined_hkey_for_pointer_bits(raw, 32))
                self.assertEqual(
                    raw | 0xFFFFFFFF00000000,
                    _predefined_hkey_for_pointer_bits(raw, 64),
                )
        self.assertEqual(_predefined_hkey(0x80000002), _HKEY_LOCAL_MACHINE)
        if os.name == "nt":
            import winreg
            from ctypes import wintypes

            self.assertEqual(int(winreg.HKEY_LOCAL_MACHINE), _HKEY_LOCAL_MACHINE)
            self.assertEqual(
                int(winreg.HKEY_LOCAL_MACHINE),
                wintypes.HANDLE(_HKEY_LOCAL_MACHINE).value,
            )

    def test_production_surfaces_are_immutable_and_test_adapter_is_not_exported(
        self,
    ) -> None:
        class FakeForeignFunction:
            argtypes: tuple[object, ...] | None = None
            restype: object | None = None

            def __call__(self, *arguments: object) -> object:
                del arguments
                raise AssertionError("binding test 不得调用 fake system export")

        class FakeLibrary:
            def __init__(self) -> None:
                self.functions: dict[str, FakeForeignFunction] = {}

            def __getattr__(self, name: str) -> FakeForeignFunction:
                return self.functions.setdefault(name, FakeForeignFunction())

        libraries = (FakeLibrary(), FakeLibrary(), FakeLibrary())
        with patch.object(os, "name", "nt"), patch.object(
            ctypes,
            "WinDLL",
            side_effect=libraries,
            create=True,
        ):
            api = _ProductionWindowsApi.load_exact_d()
        self.assertIs(type(api), _ProductionWindowsApi)
        with self.assertRaisesRegex(TypeError, "不可替换"):
            api.open_process = object()
        with patch.object(
            _ProductionWindowsApi,
            "load_exact_d",
            return_value=api,
        ):
            observer = ProductionWindowsScmProcessObserver.load_exact_d()
        with self.assertRaisesRegex(TypeError, "不可替换"):
            observer._api = object()
        with self.assertRaises(TypeError):
            pickle.dumps(observer)
        live = object.__new__(LockedWindowsScmProcessObservation)
        object.__setattr__(live, "_sealed", True)
        with self.assertRaisesRegex(TypeError, "不可替换"):
            live._api = object()
        import quant_hub.ops.local_windows_scm_process_observer as module

        self.assertNotIn(
            "_TestOnlyWindowsScmProcessObserverAdapter", module.__all__
        )
        self.assertNotIn("_TestOnlyWindowsScmProcessObservation", module.__all__)
        self.assertNotEqual(
            type(_TestOnlyWindowsScmProcessObserverAdapter.for_test_only(api=object())),
            ProductionWindowsScmProcessObserver,
        )

    def test_double_observation_drift_fails_and_closes_all_nine_handles(self) -> None:
        for mutation in (
            "service_pid_drift",
            "second_snapshot_extra_child",
            "host_creation_drift",
            "host_file_drift",
            "child_argv_mismatch",
        ):
            with self.subTest(mutation=mutation), self.close_recording() as closed, self.bound_input(
                mutation
            ) as (lock, workspace, inputs):
                observer = self.load_with(
                    _FixedObserverApi(inputs, mutation=mutation)
                )
                with self.assertRaises(WindowsScmProcessObserverError):
                    observer.observe_test_only(
                        self.persistence, lock, workspace, inputs
                    )
                self.assertEqual(
                    [106, 109, 108, 107, 105, 104, 103, 102, 101],
                    closed,
                )
                workspace._assert_live()

    def test_known_invalid_file_handle_is_never_closed_and_partial_is_recovered(
        self,
    ) -> None:
        with self.close_recording() as closed, self.bound_input("known-invalid") as (
            lock,
            workspace,
            inputs,
        ):
            observer = self.load_with(
                _FixedObserverApi(inputs, mutation="known_invalid_host_file")
            )
            with self.assertRaises(WindowsScmProcessObserverError) as caught:
                observer.observe_test_only(
                    self.persistence, lock, workspace, inputs
                )
            self.assertIsInstance(
                caught.exception.__cause__, LocalDeploymentPersistenceError
            )
            self.assertEqual([104, 103, 102, 101], closed)
            workspace._assert_live()

    def test_evidence_build_rechecks_live_service_process_and_file_identity(self) -> None:
        for mutation in (
            "service_pid_drift",
            "host_creation_drift",
            "host_file_drift",
        ):
            with self.subTest(mutation=mutation), self.close_recording(), self.bound_input(
                f"build-{mutation}"
            ) as (lock, workspace, inputs):
                api = _FixedObserverApi(inputs)
                observation = self.load_with(api).observe_test_only(
                    self.persistence, lock, workspace, inputs
                )
                api.mutation = mutation
                if mutation == "service_pid_drift":
                    api._status_calls = 1
                elif mutation == "host_creation_drift":
                    api._process_calls[4100] = 1
                else:
                    api._file_calls[105] = 1
                with self.assertRaises(WindowsScmProcessObserverError):
                    observation.validate_live_for_test_only()
                api.mutation = None
                observation.close()

    def test_live_validation_uses_fresh_tracked_snapshot_for_topology(self) -> None:
        for mutation in (
            "live_extra_child",
            "live_child_missing",
            "live_child_replaced",
            "live_host_missing",
            "post_topology_child_exit",
        ):
            with self.subTest(mutation=mutation), self.close_recording() as closed, self.bound_input(
                f"topology-{mutation}"
            ) as (lock, workspace, inputs):
                api = _FixedObserverApi(inputs)
                observation = self.load_with(api).observe_test_only(
                    self.persistence, lock, workspace, inputs
                )
                api.mutation = mutation
                with self.assertRaises(WindowsScmProcessObserverError):
                    observation.validate_live_for_test_only()
                self.assertEqual(3, api._snapshot_calls)
                self.assertEqual([106, 109, 110], closed)
                api.mutation = None
                observation.close()
                self.assertEqual(
                    [106, 109, 110, 108, 107, 105, 104, 103, 102, 101],
                    closed,
                )


if __name__ == "__main__":
    unittest.main()
