from __future__ import annotations

import ctypes
from ctypes import wintypes
import inspect
import pickle
import unittest
from unittest.mock import patch

from quant_hub.ops import local_deployment_persistence as persistence_module
from quant_hub.ops.local_deployment_persistence import (
    DeploymentLockBusy,
    LocalDeploymentPersistence,
    LocalDeploymentPersistenceError,
    LockedWindowsWriterLeaseHandleTracking,
    UnsafeLocalPath,
)
from tests.test_local_deployment_persistence import (
    PersistenceFixture,
    history_to,
    journal,
    release,
)


def _populate_scm_tracking(tracking) -> None:
    for index, (label, family) in enumerate(
        persistence_module._WINDOWS_SCM_PROCESS_HANDLE_SLOT_FAMILIES,
        start=101,
    ):
        if label in persistence_module._WINDOWS_SCM_PROCESS_REUSABLE_SNAPSHOT_SLOTS:
            with patch.object(
                persistence_module.CrashReleasedFileLock,
                "_windows_duplicate_close_source_call",
                return_value=True,
            ):
                tracking._capture_reusable_snapshot_handle(
                    label, lambda value=index: value
                )
                tracking._release_reusable_snapshot_handle(label)
        else:
            tracking._capture_returned_handle(
                label, family, lambda value=index: value
            )
    tracking._seal_acquisition()


class WindowsWriterLeaseTrackingTests(PersistenceFixture):
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

    def prepare(self, *, attempt: str):
        nonce = "nonce-" + attempt
        first = journal(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            operation="activation",
            attempt=attempt,
            nonce=nonce,
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        lock = self.persistence.global_lock()
        lock.__enter__()
        workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
        closures = self.persistence.lock_exact_release_closures(lock, workspace)
        authorization = self.persistence.lock_exact_transient_start_authorization(
            lock, workspace, "candidate"
        )
        inputs = self.persistence.bind_exact_scm_process_observation_input(
            lock, workspace, authorization, closures
        )
        scm = self.persistence.prepare_windows_scm_process_handle_tracking(
            lock, workspace, inputs
        )
        _populate_scm_tracking(scm)
        writer = self.persistence.prepare_windows_writer_lease_handle_tracking(
            lock, workspace, scm
        )
        return lock, workspace, closures, scm, writer

    @staticmethod
    def cleanup(lock, workspace, closures, scm, writer) -> None:
        with patch.object(
            persistence_module.CrashReleasedFileLock,
            "_windows_duplicate_close_source_call",
            return_value=True,
        ), patch.object(
            persistence_module.LockedWindowsScmProcessHandleTracking,
            "_windows_close_scm_handle_call",
            return_value=None,
        ), patch.object(
            persistence_module.LockedWindowsScmProcessHandleTracking,
            "_windows_close_registry_handle_call",
            return_value=None,
        ):
            writer.close()
            scm.close()
        closures.close()
        workspace.close()
        lock.__exit__(None, None, None)

    def test_facade_registers_before_syscall_and_surface_is_closed(self) -> None:
        self.assertEqual(
            {"self", "lock", "workspace", "scm_tracking"},
            set(
                inspect.signature(
                    LocalDeploymentPersistence.prepare_windows_writer_lease_handle_tracking
                ).parameters
            ),
        )
        material = self.prepare(attempt="writer-tracking-surface")
        lock, workspace, closures, scm, writer = material
        try:
            self.assertIn(
                writer, workspace._windows_writer_lease_handle_tracking
            )
            self.assertEqual(
                "windows_writer_lease_handle_tracking_only", writer.scope
            )
            with self.assertRaises(DeploymentLockBusy):
                self.persistence.prepare_windows_writer_lease_handle_tracking(
                    lock, workspace, scm
                )
            with self.assertRaises(TypeError):
                pickle.dumps(writer)
            with self.assertRaises(TypeError):
                class Forged(LockedWindowsWriterLeaseHandleTracking):
                    pass
            for name in (
                "as_dict",
                "document",
                "handle",
                "handles",
                "raw_handle",
                "writer_lease",
                "qualified",
                "evidence",
            ):
                self.assertFalse(hasattr(writer, name), name)
            with self.assertRaisesRegex(DeploymentLockBusy, "不得先关闭"):
                scm.close()
        finally:
            self.cleanup(*material)

    def test_reusable_record_duplicate_and_conflict_slots_close_exactly(self) -> None:
        material = self.prepare(attempt="writer-tracking-slots")
        _lock, _workspace, _closures, _scm, writer = material
        closed: list[int] = []

        def duplicate(
            source_process: int,
            source_handle: int,
            target_process: int,
            output: object,
            desired_access: int,
            inherit: bool,
            options: int,
        ) -> int:
            self.assertEqual((301, 302, 303, 0, False, 2), (
                source_process,
                source_handle,
                target_process,
                desired_access,
                inherit,
                options,
            ))
            pointer = ctypes.cast(output, ctypes.POINTER(wintypes.HANDLE))
            pointer.contents.value = 402
            return 1

        try:
            with patch.object(
                persistence_module.CrashReleasedFileLock,
                "_windows_duplicate_close_source_call",
                side_effect=lambda handle: closed.append(handle) or True,
            ):
                writer._capture_reusable_returned_handle(
                    "lease_record_before", lambda: 401
                )
                self.assertEqual(401, writer._borrow_handle("lease_record_before"))
                writer._release_reusable_handle("lease_record_before")

                writer._capture_reusable_duplicate_handle(
                    duplicate, 301, 302, 303, 0, False, 2
                )
                self.assertEqual(
                    402, writer._borrow_handle("duplicated_writer_lock")
                )
                writer._release_reusable_handle("duplicated_writer_lock")

                error = writer._capture_expected_conflict(
                    lambda: ctypes.c_void_p(-1).value,
                    lambda: 32,
                )
                self.assertEqual(32, error)

                writer._capture_reusable_returned_handle(
                    "lease_record_after", lambda: 403
                )
                writer._release_reusable_handle("lease_record_after")
            self.assertEqual([401, 402, 403], closed)
            self.assertTrue(
                all(
                    slot.phase == "reusable_prepared" and slot.value is None
                    for slot in writer._slots
                )
            )
        finally:
            self.cleanup(*material)

    def test_duplicate_output_is_registered_before_wrapper_error(self) -> None:
        material = self.prepare(attempt="writer-tracking-output")
        _lock, _workspace, _closures, _scm, writer = material

        def output_then_raise(*arguments: object) -> int:
            output = arguments[3]
            pointer = ctypes.cast(output, ctypes.POINTER(wintypes.HANDLE))
            pointer.contents.value = 501
            raise RuntimeError("after output")

        try:
            with self.assertRaisesRegex(
                LocalDeploymentPersistenceError, "已登记"
            ):
                writer._capture_reusable_duplicate_handle(
                    output_then_raise, 301, 302, 303, 0, False, 2
                )
            slot = writer._slot("duplicated_writer_lock")
            self.assertEqual(("returned", 501), (slot.phase, slot.value))
        finally:
            self.cleanup(*material)

    def test_unexpected_conflict_success_is_closed_before_failure(self) -> None:
        material = self.prepare(attempt="writer-tracking-conflict-success")
        _lock, _workspace, _closures, _scm, writer = material
        closed: list[int] = []
        try:
            with patch.object(
                persistence_module.CrashReleasedFileLock,
                "_windows_duplicate_close_source_call",
                side_effect=lambda handle: closed.append(handle) or True,
            ), self.assertRaisesRegex(
                LocalDeploymentPersistenceError, "意外打开成功"
            ):
                writer._capture_expected_conflict(lambda: 601, lambda: 0)
            self.assertEqual([601], closed)
            slot = writer._slot("unexpected_conflict_handle")
            self.assertEqual(("reusable_prepared", None), (slot.phase, slot.value))
        finally:
            self.cleanup(*material)

    def test_invalid_slot_and_error_aliases_fail_closed(self) -> None:
        material = self.prepare(attempt="writer-tracking-alias")
        _lock, _workspace, _closures, _scm, writer = material
        try:
            slot = writer._slot("unexpected_conflict_handle")
            for value in (False, True, -2, 1 << 65):
                with self.subTest(returned=value), patch.object(
                    LockedWindowsWriterLeaseHandleTracking,
                    "_retire_numeric_authority",
                    side_effect=LocalDeploymentPersistenceError("retired"),
                ) as returned_retire, self.assertRaisesRegex(
                    LocalDeploymentPersistenceError, "retired"
                ):
                    writer._commit_returned_value(
                        slot, value, failure_is_reusable=True
                    )
                returned_retire.assert_called_once()
                slot.value = None
                slot.phase = "reusable_prepared"
            with patch.object(
                LockedWindowsWriterLeaseHandleTracking,
                "_retire_numeric_authority",
                side_effect=LocalDeploymentPersistenceError("retired"),
            ) as retire, self.assertRaisesRegex(
                LocalDeploymentPersistenceError, "retired"
            ):
                writer._capture_expected_conflict(
                    lambda: ctypes.c_void_p(-1).value,
                    lambda: True,
                )
            retire.assert_called_once()
        finally:
            self.cleanup(*material)


if __name__ == "__main__":
    unittest.main()
