from __future__ import annotations

import ctypes
from ctypes import wintypes
import inspect
import pickle
import threading
import unittest
from unittest.mock import patch

from quant_hub.ops import local_windows_job_child_launcher as launcher_module
from quant_hub.ops.local_exact_runtime_admission import (
    build_commit_frame,
    build_prepare_frame,
)
from quant_hub.ops.local_steady_admission_authorization import (
    LockedSteadyAdmissionCommitAuthorization,
    LockedSteadyAdmissionPrepareAuthorization,
    ProductionSteadyAdmissionAuthorityFactory,
)
from quant_hub.ops.local_windows_job_child_launcher import (
    LockedServiceChildLaunchLifecycle,
    LockedServiceChildLifetime,
    WindowsJobChildLauncherError,
)


class _Live:
    @staticmethod
    def _assert_live() -> None:
        return None


class _Tracking:
    @staticmethod
    def _assert_context() -> None:
        return None


class _Writer:
    _tracking = _Tracking()


class _Workspace:
    def __init__(self) -> None:
        self._steady_admission_authorizations: set[object] = set()

    @staticmethod
    def _assert_live() -> None:
        return None


def _fake_api(writes: list[bytes], closed: list[int]) -> object:
    def write_file(
        _handle: object,
        buffer: object,
        count: object,
        written: object,
        _overlapped: object,
    ) -> bool:
        size = int(count)
        writes.append(ctypes.string_at(buffer, size))
        ctypes.cast(written, ctypes.POINTER(wintypes.DWORD))[0] = size
        return True

    def duplicate(
        _source_process: object,
        source: object,
        _target_process: object,
        *_rest: object,
    ) -> bool:
        closed.append(int(getattr(source, "value", source) or 0))
        return True

    api = object.__new__(launcher_module._ProductionJobApi)
    object.__setattr__(api, "_sealed", False)
    values = {
        "WriteFile": write_file,
        "DuplicateHandle": duplicate,
        "GetCurrentProcess": lambda: ctypes.c_void_p(-1).value,
        "TerminateJobObject": lambda *_: True,
        "DeleteProcThreadAttributeList": lambda *_: None,
        "_kernel32": object(),
        "_ntdll": object(),
        "_platform_floor": (10, 0, 19045, 0x8664, 64),
        "_host_in_outer_job": False,
    }
    for slot in launcher_module._ProductionJobApi.__slots__:
        object.__setattr__(api, slot, values.get(slot, lambda *_: True))
    object.__setattr__(api, "_sealed", True)
    return api


class SteadyAdmissionAuthorizationTests(unittest.TestCase):
    def test_factory_surface_and_exact_types_are_closed(self) -> None:
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    ProductionSteadyAdmissionAuthorityFactory.load_exact_d
                ).parameters
            ),
        )
        self.assertIs(
            type(ProductionSteadyAdmissionAuthorityFactory.load_exact_d()),
            ProductionSteadyAdmissionAuthorityFactory,
        )
        for exact in (
            LockedSteadyAdmissionPrepareAuthorization,
            LockedSteadyAdmissionCommitAuthorization,
        ):
            with self.subTest(exact=exact), self.assertRaises(TypeError):
                class Derived(exact):  # type: ignore[misc,valid-type]
                    pass

            with self.subTest(exact=exact), self.assertRaises(TypeError):
                pickle.dumps(object.__new__(exact))

    def test_lifetime_writes_exact_prepare_commit_then_closes_pipe(self) -> None:
        writes: list[bytes] = []
        closed: list[int] = []
        api = _fake_api(writes, closed)
        workspace = _Workspace()
        lifecycle = object.__new__(LockedServiceChildLaunchLifecycle)
        lifecycle_values = {
            "_api": api,
            "_workspace": workspace,
            "_authorization": _Live(),
            "_identity": object(),
            "_handles": {
                "job": 101,
                "admission_read": 0,
                "admission_write": 103,
                "log": 104,
                "pycache_sentinel": 0,
                "process": 105,
                "thread": 0,
            },
            "_attribute_buffer": None,
            "_attribute_initialized": False,
            "_process_id": 901,
            "_host_creation_time_100ns": 1_000,
            "_child_creation_time_100ns": 2_000,
            "_job_identity_sha256": "a" * 64,
            "_admission_binding_sha256": "b" * 64,
            "_owner_thread": threading.get_ident(),
            "_state": "live",
            "_sealed": True,
        }
        for name, value in lifecycle_values.items():
            object.__setattr__(lifecycle, name, value)
        lifetime = LockedServiceChildLifetime(
            lifecycle,
            chain_aggregate_sha256="c" * 64,
            token=launcher_module._LIFETIME_TOKEN,
        )
        object.__setattr__(lifecycle, "_state", "promoted")

        prepare = object.__new__(LockedSteadyAdmissionPrepareAuthorization)
        prepare_values = {
            "_workspace": workspace,
            "_lifetime": lifetime,
            "_authorization": _Live(),
            "_scm": _Live(),
            "_endpoint": _Live(),
            "_writer": _Writer(),
            "_chain_aggregate_sha256": "c" * 64,
            "_owner_thread": threading.get_ident(),
            "_state": "live",
            "_sealed": True,
        }
        for name, value in prepare_values.items():
            object.__setattr__(prepare, name, value)
        workspace._steady_admission_authorizations.add(prepare)
        lifetime.prepare_admission_after_promotion(prepare)
        self.assertEqual("prepared", prepare._state)
        self.assertEqual("prepare_sent", lifetime._state)
        self.assertEqual("a" * 64, lifetime.job_identity_sha256)
        self.assertEqual("b" * 64, lifetime.admission_binding_sha256)

        workspace._steady_admission_authorizations.remove(prepare)
        commit = object.__new__(LockedSteadyAdmissionCommitAuthorization)
        commit_values = {
            "_workspace": workspace,
            "_lifetime": lifetime,
            "_authorization": _Live(),
            "_scm": _Live(),
            "_endpoint": _Live(),
            "_writer": _Writer(),
            "_ready_ack_binding_sha256": "d" * 64,
            "_ready_chain_aggregate_sha256": "e" * 64,
            "_owner_thread": threading.get_ident(),
            "_state": "live",
            "_sealed": True,
        }
        for name, value in commit_values.items():
            object.__setattr__(commit, name, value)
        workspace._steady_admission_authorizations.add(commit)
        lifetime.commit_admission_after_ready_ack(commit)

        self.assertEqual(
            [
                build_prepare_frame("b" * 64),
                build_commit_frame("b" * 64, "d" * 64),
            ],
            writes,
        )
        self.assertEqual([103], closed)
        self.assertEqual(0, lifecycle._handles["admission_write"])
        self.assertEqual("commit_sent", commit._state)
        self.assertEqual("commit_sent_waiting_observation", lifetime._state)
        with self.assertRaises(WindowsJobChildLauncherError):
            lifetime._mark_admitted_after_observation(token=object())
        lifetime._mark_admitted_after_observation(
            token=launcher_module._ADMISSION_CONFIRM_TOKEN
        )
        self.assertEqual("admitted", lifetime._state)

    def test_write_failure_terminates_whole_job_and_never_advances(self) -> None:
        writes: list[bytes] = []
        closed: list[int] = []
        api = _fake_api(writes, closed)
        object.__setattr__(api, "_sealed", False)

        def partial(
            _handle: object,
            _buffer: object,
            count: object,
            written: object,
            _overlapped: object,
        ) -> bool:
            ctypes.cast(written, ctypes.POINTER(wintypes.DWORD))[0] = int(count) - 1
            return True

        object.__setattr__(api, "WriteFile", partial)
        object.__setattr__(api, "_sealed", True)
        lifecycle = object.__new__(LockedServiceChildLaunchLifecycle)
        for name, value in {
            "_api": api,
            "_handles": {
                "job": 101,
                "admission_read": 0,
                "admission_write": 103,
                "log": 104,
                "pycache_sentinel": 0,
                "process": 105,
                "thread": 0,
            },
            "_attribute_buffer": None,
            "_attribute_initialized": False,
            "_state": "promoted",
            "_sealed": True,
        }.items():
            object.__setattr__(lifecycle, name, value)
        lifetime = object.__new__(LockedServiceChildLifetime)
        for name, value in {
            "_lifecycle": lifecycle,
            "_chain_aggregate_sha256": "c" * 64,
            "_state": "promotion_pending_admission",
            "_owner_thread": threading.get_ident(),
            "_sealed": True,
        }.items():
            object.__setattr__(lifetime, name, value)
        with patch.object(
            LockedServiceChildLaunchLifecycle,
            "_wait_and_reprove_absence",
            return_value=None,
        ), self.assertRaises(WindowsJobChildLauncherError):
            lifetime._write_frame(build_prepare_frame("b" * 64))
        self.assertEqual("closed", lifetime._state)
        self.assertTrue(all(value == 0 for value in lifecycle._handles.values()))


if __name__ == "__main__":
    unittest.main()
