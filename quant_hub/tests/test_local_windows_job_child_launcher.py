from __future__ import annotations

import ast
import ctypes
import inspect
import os
from pathlib import Path
import pickle
import threading
import unittest
from unittest.mock import patch

from ctypes import wintypes

from quant_hub.ops import local_windows_job_child_launcher as launcher_module
from quant_hub.ops.local_steady_runtime_identity import ExactSteadyRuntimeIdentity
from quant_hub.ops.local_service_transient_journal_start_fence import (
    LockedServiceTransientJournalStartFence,
)
from quant_hub.ops.local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity

from quant_hub.ops.local_steady_start_authorization import (
    LockedExactSteadyStartAuthorization,
)
from quant_hub.ops.local_windows_job_child_launcher import (
    LockedServiceChildLaunchLifecycle,
    LockedServiceChildLifetime,
    LockedTransientServiceChildLifetime,
    ProductionWindowsJobChildLauncher,
    WindowsJobChildLauncherError,
    WindowsJobChildOwnerCrashRequired,
)
from quant_hub.ops.local_windows_exact_runtime_process_fence import (
    ProductionWindowsExactRuntimeProcessFence,
)


class WindowsJobChildLauncherTests(unittest.TestCase):
    @staticmethod
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

    def test_product_loader_and_launch_signature_are_closed(self) -> None:
        self.assertEqual(
            [],
            list(inspect.signature(ProductionWindowsJobChildLauncher.load_exact_d).parameters),
        )
        parameters = inspect.signature(
            ProductionWindowsJobChildLauncher.launch_steady
        ).parameters
        self.assertEqual(["self", "authorization"], list(parameters))
        self.assertEqual(
            "LockedExactSteadyStartAuthorization",
            parameters["authorization"].annotation,
        )
        if os.name == "nt":
            try:
                loaded = ProductionWindowsJobChildLauncher.load_exact_d()
            except WindowsJobChildLauncherError as error:
                self.assertIn("outer Job is incompatible", str(error))
                return
            self.assertIs(type(loaded), ProductionWindowsJobChildLauncher)
            self.assertGreaterEqual(loaded._api._platform_floor[2], 14393)

    def test_product_source_uses_creation_time_job_and_no_popen_fallback(self) -> None:
        source = Path(inspect.getfile(ProductionWindowsJobChildLauncher)).read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        self.assertIn("CreateProcessW", attributes)
        self.assertIn("UpdateProcThreadAttribute", attributes)
        self.assertIn("IsProcessInJob", attributes)
        self.assertIn("ResumeThread", attributes)
        self.assertNotIn("Popen", attributes)
        self.assertIn("AssignProcessToJobObject", attributes)
        self.assertIn("TerminateProcess", attributes)
        self.assertIn("_PROC_THREAD_ATTRIBUTE_JOB_LIST", source)
        self.assertIn("_PROC_THREAD_ATTRIBUTE_HANDLE_LIST", source)
        self.assertIn("_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", source)
        launch_source = inspect.getsource(
            ProductionWindowsJobChildLauncher._launch
        )
        self.assertLess(
            launch_source.index("api.CreateProcessW"),
            launch_source.index("api.AssignProcessToJobObject"),
        )
        self.assertLess(
            launch_source.index("api.AssignProcessToJobObject"),
            launch_source.index("api.ResumeThread"),
        )

    def test_exact_capabilities_reject_subclass_pickle_and_mapping(self) -> None:
        for exact in (LockedServiceChildLaunchLifecycle, LockedServiceChildLifetime):
            with self.subTest(exact=exact), self.assertRaises(TypeError):
                class Forged(exact):  # type: ignore[misc,valid-type]
                    pass
            with self.subTest(exact=exact), self.assertRaises(TypeError):
                pickle.dumps(object.__new__(exact))
        launcher = object.__new__(ProductionWindowsJobChildLauncher)
        with self.assertRaises(TypeError):
            launcher.launch_steady({})  # type: ignore[arg-type]
        with self.assertRaises(WindowsJobChildLauncherError):
            launcher.launch_steady(
                object.__new__(LockedExactSteadyStartAuthorization)
            )

    def test_fake_win32_launch_binds_job_and_exact_inherited_handles_before_resume(
        self,
    ) -> None:
        calls: list[object] = []
        attributes: dict[int, tuple[int, ...]] = {}
        closed: list[int] = []

        def value(handle: object) -> int:
            return int(getattr(handle, "value", handle) or 0)

        def create_pipe(read: object, write: object, *_: object) -> bool:
            calls.append("CreatePipe")
            ctypes.cast(read, ctypes.POINTER(wintypes.HANDLE))[0] = 102
            ctypes.cast(write, ctypes.POINTER(wintypes.HANDLE))[0] = 103
            return True

        def initialize(pointer: object, *_args: object) -> bool:
            size_pointer = _args[-1]
            ctypes.cast(size_pointer, ctypes.POINTER(ctypes.c_size_t))[0] = 256
            calls.append("InitializeAttributesSize" if pointer is None else "InitializeAttributes")
            if pointer is None:
                ctypes.set_last_error(launcher_module._ERROR_INSUFFICIENT_BUFFER)
            return pointer is not None

        def final_path(
            handle: object, output: object, capacity: object, _flags: object
        ) -> int:
            observed = value(handle)
            observed_path = (
                str(launcher_module._LOG_PATH)
                if observed == 104
                else self._identity().pycache_prefix
            )
            self.assertLess(len(observed_path), int(capacity))
            output.value = observed_path
            return len(observed_path)

        def file_information(
            _handle: object,
            information_class: object,
            output: object,
            _size: object,
        ) -> bool:
            if int(information_class) == launcher_module._FILE_STANDARD_INFO_CLASS:
                standard = ctypes.cast(
                    output, ctypes.POINTER(launcher_module._FILE_STANDARD_INFO)
                ).contents
                standard.NumberOfLinks = 1
                standard.EndOfFile = 0
                standard.DeletePending = False
                standard.Directory = False
            elif int(information_class) == launcher_module._FILE_ATTRIBUTE_TAG_INFO_CLASS:
                attributes_value = ctypes.cast(
                    output,
                    ctypes.POINTER(launcher_module._FILE_ATTRIBUTE_TAG_INFO),
                ).contents
                attributes_value.FileAttributes = launcher_module._FILE_ATTRIBUTE_NORMAL
                attributes_value.ReparseTag = 0
            else:
                self.fail("unexpected file information class")
            return True

        def update(
            _list: object,
            _flags: object,
            attribute: object,
            values: object,
            size: object,
            *_rest: object,
        ) -> bool:
            attribute_value = int(getattr(attribute, "value", attribute))
            count = int(getattr(size, "value", size)) // ctypes.sizeof(
                wintypes.HANDLE
            )
            observed = ctypes.cast(
                values, ctypes.POINTER(wintypes.HANDLE * count)
            ).contents
            attributes[attribute_value] = tuple(value(item) for item in observed)
            calls.append(("UpdateAttribute", attribute_value))
            return True

        create_flags: list[int] = []
        startup_facts: list[tuple[int, int, int]] = []
        sentinel_writes: list[bytes] = []

        def write_file(
            handle: object,
            buffer: object,
            count: object,
            written: object,
            _overlapped: object,
        ) -> bool:
            size = int(count)
            if value(handle) == 107:
                sentinel_writes.append(ctypes.string_at(buffer, size))
            ctypes.cast(written, ctypes.POINTER(wintypes.DWORD))[0] = size
            return True

        def create_process(
            _application: object,
            _command: object,
            _process_security: object,
            _thread_security: object,
            inherit: object,
            flags: object,
            _environment: object,
            _cwd: object,
            startup: object,
            output: object,
        ) -> bool:
            calls.append("CreateProcessW")
            self.assertTrue(bool(inherit))
            create_flags.append(int(flags))
            startup_value = ctypes.cast(
                startup, ctypes.POINTER(launcher_module._STARTUPINFOW)
            ).contents
            startup_facts.append(
                (
                    value(startup_value.hStdInput),
                    value(startup_value.hStdOutput),
                    value(startup_value.hStdError),
                )
            )
            process = ctypes.cast(
                output, ctypes.POINTER(launcher_module._PROCESS_INFORMATION)
            ).contents
            process.hProcess = 105
            process.hThread = 106
            process.dwProcessId = 901
            process.dwThreadId = 902
            return True

        def is_in_job(_process: object, job: object, output: object) -> bool:
            calls.append(("IsProcessInJob", value(job)))
            ctypes.cast(output, ctypes.POINTER(wintypes.BOOL))[0] = True
            return True

        def process_times(handle: object, creation: object, *_rest: object) -> bool:
            raw = value(handle)
            observed = 1_000 if raw == ctypes.c_void_p(-1).value else 2_000
            target = ctypes.cast(
                creation, ctypes.POINTER(launcher_module._FILETIME)
            ).contents
            target.low = observed
            target.high = 0
            return True

        def duplicate(
            _source_process: object,
            source: object,
            _target_process: object,
            *_rest: object,
        ) -> bool:
            closed.append(value(source))
            return True

        def exit_code(_process: object, output: object) -> bool:
            ctypes.cast(output, ctypes.POINTER(wintypes.DWORD))[0] = (
                launcher_module._STILL_ACTIVE
            )
            return True

        fake_api = object.__new__(launcher_module._ProductionJobApi)
        object.__setattr__(fake_api, "_sealed", False)
        api_values = {
            "CreateJobObjectW": lambda *_: calls.append("CreateJobObjectW") or 101,
            "SetInformationJobObject": lambda *_: calls.append("SetJobLimits") or True,
            "CreatePipe": create_pipe,
            "SetHandleInformation": lambda *args: calls.append(
                ("SetHandleInformation", value(args[0]), int(args[2]))
            ) or True,
            "CreateFileW": lambda path, *_: calls.append("CreateFileW") or (
                104 if str(path) == str(launcher_module._LOG_PATH) else 107
            ),
            "SetFilePointerEx": lambda *_: True,
            "FlushFileBuffers": lambda *_: True,
            "GetFinalPathNameByHandleW": final_path,
            "GetFileInformationByHandleEx": file_information,
            "InitializeProcThreadAttributeList": initialize,
            "UpdateProcThreadAttribute": update,
            "DeleteProcThreadAttributeList": lambda *_: calls.append("DeleteAttributes"),
            "CreateProcessW": create_process,
            "ResumeThread": lambda handle: calls.append(("ResumeThread", value(handle))) or 1,
            "IsProcessInJob": is_in_job,
            "GetProcessTimes": process_times,
            "GetCurrentProcess": lambda: ctypes.c_void_p(-1).value,
            "GetCurrentProcessId": lambda: 900,
            "DuplicateHandle": duplicate,
            "TerminateJobObject": lambda *_: True,
            "WaitForSingleObject": lambda *_: launcher_module._WAIT_TIMEOUT,
            "GetExitCodeProcess": exit_code,
            "WriteFile": write_file,
            "_kernel32": object(),
            "_ntdll": object(),
            "RtlGetVersion": lambda *_: 0,
            "IsWow64Process2": lambda *_: True,
            "_platform_floor": (10, 0, 19045, 0x8664, 64),
            "_host_in_outer_job": False,
        }
        for name, item in api_values.items():
            object.__setattr__(fake_api, name, item)
        object.__setattr__(fake_api, "_sealed", True)

        class LiveOwner:
            @staticmethod
            def _assert_live() -> None:
                return None

        lifecycle = object.__new__(LockedServiceChildLaunchLifecycle)
        lifecycle_values = {
            "_api": fake_api,
            "_workspace": LiveOwner(),
            "_authorization": LiveOwner(),
            "_identity": self._identity(),
            "_handles": {
                "job": 0,
                "admission_read": 0,
                "admission_write": 0,
                "log": 0,
                "pycache_sentinel": 0,
                "process": 0,
                "thread": 0,
            },
            "_attribute_buffer": None,
            "_attribute_initialized": False,
            "_process_id": 0,
            "_host_creation_time_100ns": 0,
            "_child_creation_time_100ns": 0,
            "_job_identity_sha256": "",
            "_admission_binding_sha256": "",
            "_owner_thread": threading.get_ident(),
            "_state": "launching",
            "_sealed": True,
        }
        for name, item in lifecycle_values.items():
            object.__setattr__(lifecycle, name, item)
        launcher = object.__new__(ProductionWindowsJobChildLauncher)
        object.__setattr__(launcher, "_api", fake_api)
        object.__setattr__(launcher, "_sealed", True)

        with patch.dict(launcher_module.os.environ, {"SystemRoot": r"C:\Windows"}):
            launcher._launch(lifecycle)

        self.assertEqual("live", lifecycle._state)
        self.assertEqual((102, 104), attributes[launcher_module._PROC_THREAD_ATTRIBUTE_HANDLE_LIST])
        self.assertEqual((101,), attributes[launcher_module._PROC_THREAD_ATTRIBUTE_JOB_LIST])
        self.assertEqual([(102, 104, 104)], startup_facts)
        self.assertEqual([107, 102, 106], closed)
        self.assertEqual(1, len(sentinel_writes))
        self.assertIn(b'"boot_nonce":"' + b"0" * 48 + b'"', sentinel_writes[0])
        self.assertEqual(0, lifecycle._handles["admission_read"])
        self.assertEqual(0, lifecycle._handles["thread"])
        self.assertEqual(103, lifecycle._handles["admission_write"])
        self.assertEqual(105, lifecycle._handles["process"])
        self.assertEqual(101, lifecycle._handles["job"])
        self.assertEqual(901, lifecycle.process_id)
        self.assertEqual(2_000, lifecycle.child_creation_time_100ns)
        self.assertRegex(lifecycle.job_identity_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(lifecycle.admission_binding_sha256, r"^[0-9a-f]{64}$")
        self.assertTrue(create_flags[0] & launcher_module._CREATE_SUSPENDED)
        self.assertTrue(create_flags[0] & launcher_module._EXTENDED_STARTUPINFO_PRESENT)
        self.assertLess(calls.index("CreateJobObjectW"), calls.index("CreateProcessW"))
        self.assertLess(
            calls.index("CreateProcessW"),
            next(index for index, item in enumerate(calls) if isinstance(item, tuple) and item[0] == "ResumeThread"),
        )

    def test_close_source_false_retires_all_numeric_authority(self) -> None:
        api = object.__new__(launcher_module._ProductionJobApi)
        object.__setattr__(api, "_sealed", False)
        values = {
            "DuplicateHandle": lambda *_: False,
            "GetCurrentProcess": lambda: ctypes.c_void_p(-1).value,
            "_kernel32": object(),
            "_ntdll": object(),
            "_platform_floor": (10, 0, 19045, 0x8664, 64),
            "_host_in_outer_job": False,
        }
        for slot in launcher_module._ProductionJobApi.__slots__:
            object.__setattr__(api, slot, values.get(slot, lambda *_: True))
        object.__setattr__(api, "_sealed", True)
        lifecycle = object.__new__(LockedServiceChildLaunchLifecycle)
        for name, value in {
            "_api": api,
            "_handles": {
                "job": 101,
                "admission_read": 0,
                "admission_write": 0,
                "log": 0,
                "pycache_sentinel": 0,
                "process": 0,
                "thread": 0,
            },
            "_state": "launching",
            "_sealed": True,
        }.items():
            object.__setattr__(lifecycle, name, value)
        with self.assertRaises(WindowsJobChildOwnerCrashRequired):
            lifecycle._close_handle("job")
        self.assertEqual("owner_crash_only", lifecycle._state)
        self.assertTrue(all(value == 0 for value in lifecycle._handles.values()))

    def test_owner_crash_lifetime_cannot_be_closed_by_repeated_cleanup(self) -> None:
        class Api:
            @staticmethod
            def TerminateJobObject(*_args: object) -> bool:
                return False

        def lifecycle() -> LockedServiceChildLaunchLifecycle:
            observed = object.__new__(LockedServiceChildLaunchLifecycle)
            transient_fence = object.__new__(
                LockedServiceTransientJournalStartFence
            )
            for name, value in {
                "_api": Api(),
                "_authorization": transient_fence,
                "_handles": {
                    "job": 101,
                    "admission_read": 0,
                    "admission_write": 0,
                    "log": 0,
                    "pycache_sentinel": 0,
                    "process": 102,
                    "thread": 0,
                },
                "_state": "promoted",
                "_sealed": True,
            }.items():
                object.__setattr__(observed, name, value)
            return observed

        for admission_state in (
            "promotion_pending_admission",
            "prepare_sent",
            "commit_sent_waiting_observation",
            "admitted",
        ):
            with self.subTest(admission_state=admission_state):
                steady_lifecycle = lifecycle()
                steady = object.__new__(LockedServiceChildLifetime)
                for name, value in {
                    "_lifecycle": steady_lifecycle,
                    "_owner_thread": threading.get_ident(),
                    "_state": admission_state,
                    "_sealed": True,
                }.items():
                    object.__setattr__(steady, name, value)
                with self.assertRaises(WindowsJobChildOwnerCrashRequired):
                    steady.terminate()
                self.assertEqual("owner_crash_only", steady_lifecycle._state)
                self.assertEqual("owner_crash_only", steady._state)
                with self.assertRaises(WindowsJobChildOwnerCrashRequired):
                    steady.terminate()
                self.assertEqual("owner_crash_only", steady._state)

        transient_lifecycle = lifecycle()
        transient = object.__new__(LockedTransientServiceChildLifetime)
        for name, value in {
            "_lifecycle": transient_lifecycle,
            "_owner_thread": threading.get_ident(),
            "_state": "live",
            "_sealed": True,
        }.items():
            object.__setattr__(transient, name, value)
        with self.assertRaises(WindowsJobChildOwnerCrashRequired):
            transient.terminate()
        self.assertEqual("owner_crash_only", transient_lifecycle._state)
        self.assertEqual("owner_crash_only", transient._state)
        with self.assertRaises(WindowsJobChildOwnerCrashRequired):
            transient.terminate()
        self.assertEqual("owner_crash_only", transient._state)

    def test_terminate_waits_reproves_absence_then_closes_handles(self) -> None:
        events: list[object] = []

        def exit_code(_process: object, output: object) -> bool:
            events.append("exit-code")
            ctypes.cast(output, ctypes.POINTER(wintypes.DWORD))[0] = 7
            return True

        def duplicate(
            _source_process: object,
            source: object,
            _target_process: object,
            *_rest: object,
        ) -> bool:
            events.append(("close", int(getattr(source, "value", source) or 0)))
            return True

        api = object.__new__(launcher_module._ProductionJobApi)
        object.__setattr__(api, "_sealed", False)
        values = {
            "TerminateJobObject": lambda *_: events.append("terminate") or True,
            "WaitForSingleObject": lambda *_: events.append("wait")
            or launcher_module._WAIT_OBJECT_0,
            "GetExitCodeProcess": exit_code,
            "DuplicateHandle": duplicate,
            "GetCurrentProcess": lambda: ctypes.c_void_p(-1).value,
            "_kernel32": object(),
            "_ntdll": object(),
            "_platform_floor": (10, 0, 19045, 0x8664, 64),
            "_host_in_outer_job": False,
        }
        for slot in launcher_module._ProductionJobApi.__slots__:
            object.__setattr__(api, slot, values.get(slot, lambda *_: True))
        object.__setattr__(api, "_sealed", True)
        lifecycle = object.__new__(LockedServiceChildLaunchLifecycle)
        for name, value in {
            "_api": api,
            "_handles": {
                "job": 101,
                "admission_read": 0,
                "admission_write": 0,
                "log": 0,
                "pycache_sentinel": 0,
                "process": 102,
                "thread": 0,
            },
            "_attribute_buffer": None,
            "_attribute_initialized": False,
            "_process_id": 901,
            "_child_creation_time_100ns": 2_000,
            "_state": "live",
            "_sealed": True,
        }.items():
            object.__setattr__(lifecycle, name, value)

        class Reprove:
            def assert_absent_after_termination(self, observed: object) -> str:
                if observed is not lifecycle:
                    raise AssertionError("wrong lifecycle")
                events.append("reprove")
                return "f" * 64

        with patch.object(
            ProductionWindowsExactRuntimeProcessFence,
            "load_exact_d",
            return_value=Reprove(),
        ):
            lifecycle._close_all(terminate=True)
        self.assertEqual(
            ["terminate", "wait", "exit-code", "reprove"], events[:4]
        )
        self.assertEqual([("close", 102), ("close", 101)], events[4:])
        self.assertTrue(all(value == 0 for value in lifecycle._handles.values()))

    def test_transient_launch_cleanup_owner_crash_overrides_primary_error(self) -> None:
        identity = ExactRuntimeLeaseIdentity(
            attempt_id="attempt-launch-cleanup",
            nonce="deployment-launch-cleanup",
            operation="activation",
            role="candidate",
            start_nonce="start-launch-cleanup",
            state_identity_sha256="1" * 64,
            release_id="release-launch-cleanup",
            manifest_sha256="2" * 64,
        )
        fence = object.__new__(LockedServiceTransientJournalStartFence)
        for name, value in {
            "_identity": identity,
            "_owner_thread": threading.get_ident(),
            "_state": "live",
            "_sealed": True,
        }.items():
            object.__setattr__(fence, name, value)
        cleanup = WindowsJobChildOwnerCrashRequired(
            "injected terminate outcome unknown"
        )

        class Lifecycle:
            _state = "launching"
            _handles = {"process": 105}

            @staticmethod
            def _close_transient(*, terminate: bool) -> None:
                if not terminate:
                    raise AssertionError("live process cleanup must terminate")
                raise cleanup

        class PrimaryFence:
            @staticmethod
            def assert_absent_before_launch(_lifecycle: object) -> str:
                raise RuntimeError("injected ordinary prelaunch failure")

        launcher = object.__new__(ProductionWindowsJobChildLauncher)
        object.__setattr__(launcher, "_api", object())
        object.__setattr__(launcher, "_sealed", True)
        with patch.object(
            launcher_module,
            "LockedServiceChildLaunchLifecycle",
            return_value=Lifecycle(),
        ), patch.object(
            ProductionWindowsExactRuntimeProcessFence,
            "load_exact_d",
            return_value=PrimaryFence(),
        ):
            with self.assertRaises(WindowsJobChildOwnerCrashRequired) as raised:
                launcher.launch_transient(fence)
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)
        self.assertIn("ordinary prelaunch", str(raised.exception.__cause__))

    def test_steady_launch_cleanup_owner_crash_overrides_primary_error(self) -> None:
        identity = self._identity()
        authorization = object.__new__(LockedExactSteadyStartAuthorization)
        object.__setattr__(authorization, "_state", "live")
        cleanup = WindowsJobChildOwnerCrashRequired(
            "injected steady close outcome unknown"
        )

        class Lifecycle:
            _state = "launching"
            _workspace = object()

            @staticmethod
            def _close_from_workspace(_workspace: object) -> None:
                raise cleanup

        class PrimaryFence:
            @staticmethod
            def assert_absent_before_launch(_lifecycle: object) -> str:
                raise RuntimeError("injected steady ordinary prelaunch failure")

        plan = {
            "service": {"start_arguments": list(identity.service_start_arguments)},
            "child": {"argv": list(identity.child_argv)},
        }
        launcher = object.__new__(ProductionWindowsJobChildLauncher)
        object.__setattr__(launcher, "_api", object())
        object.__setattr__(launcher, "_sealed", True)
        with patch.object(
            LockedExactSteadyStartAuthorization,
            "_assert_live",
            return_value=(plan, {}),
        ), patch.object(
            launcher_module,
            "LockedServiceChildLaunchLifecycle",
            return_value=Lifecycle(),
        ), patch.object(
            ProductionWindowsExactRuntimeProcessFence,
            "load_exact_d",
            return_value=PrimaryFence(),
        ):
            with self.assertRaises(WindowsJobChildOwnerCrashRequired) as raised:
                launcher.launch_steady(authorization)
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)
        self.assertIn("steady ordinary", str(raised.exception.__cause__))


if __name__ == "__main__":
    unittest.main()
