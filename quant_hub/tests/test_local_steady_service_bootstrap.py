from __future__ import annotations

import ast
import inspect
from pathlib import Path
import pickle
import threading
import unittest
from unittest.mock import patch

from quant_hub.ops.local_steady_service_bootstrap import (
    LockedProductionSteadyServiceBootSession,
    ProductionSteadyServiceBootstrap,
)
from quant_hub.ops import local_steady_service_bootstrap as bootstrap_module
from quant_hub.ops.local_windows_job_child_launcher import (
    WindowsJobChildOwnerCrashRequired,
)


class SteadyServiceBootstrapTests(unittest.TestCase):
    def test_product_loader_and_begin_are_zero_argument(self) -> None:
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    ProductionSteadyServiceBootstrap.load_exact_d
                ).parameters
            ),
        )
        self.assertEqual(
            ["self"],
            list(
                inspect.signature(
                    ProductionSteadyServiceBootstrap.begin_prelaunch
                ).parameters
            ),
        )
        self.assertIs(
            type(ProductionSteadyServiceBootstrap.load_exact_d()),
            ProductionSteadyServiceBootstrap,
        )

    def test_session_is_exact_nonserializable(self) -> None:
        with self.assertRaises(TypeError):
            class Derived(LockedProductionSteadyServiceBootSession):
                pass

        with self.assertRaises(TypeError):
            pickle.dumps(object.__new__(LockedProductionSteadyServiceBootSession))

    def test_source_keeps_lock_until_post_commit_confirmation(self) -> None:
        source = Path(
            inspect.getfile(LockedProductionSteadyServiceBootSession)
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        attributes = {
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
        }
        self.assertNotIn("Popen", attributes)
        method = inspect.getsource(
            LockedProductionSteadyServiceBootSession.complete_after_running
        )
        self.assertLess(
            method.index("promote_job_to_service_lifetime"),
            method.index("prepare_admission_after_promotion"),
        )
        self.assertLess(
            method.index("prepare_admission_after_promotion"),
            method.index("authorize_commit_after_ready_ack"),
        )
        self.assertLess(
            method.index("authorize_commit_after_ready_ack"),
            method.index("commit_admission_after_ready_ack"),
        )
        self.assertLess(
            method.index("commit_admission_after_ready_ack"),
            method.index("confirm_admitted_after_commit"),
        )
        self.assertLess(
            method.index("confirm_admitted_after_commit"),
            method.index("self._workspace.close()"),
        )
        self.assertLess(
            method.index("self._workspace.close()"),
            method.index("self._lock.release()"),
        )
        after_promotion = method[method.index("prepare = admissions.promote") :]
        self.assertLess(
            after_promotion.index("lifetime = prepare.service_lifetime"),
            after_promotion.index("self._assert_continue()"),
        )

    def test_abort_does_not_release_b2_after_owner_crash_unknown(self) -> None:
        class Workspace:
            _state = "live"

            @staticmethod
            def close() -> None:
                raise WindowsJobChildOwnerCrashRequired("close unknown")

        class Lock:
            held = True
            released = False

            def release(self) -> None:
                self.released = True

        lock = Lock()
        session = object.__new__(LockedProductionSteadyServiceBootSession)
        for name, value in {
            "_workspace": Workspace(),
            "_lock": lock,
            "_owner_thread": threading.get_ident(),
            "_stop_requested": threading.Event(),
            "_state": "running_chain",
            "_sealed": True,
        }.items():
            object.__setattr__(session, name, value)
        with self.assertRaises(WindowsJobChildOwnerCrashRequired):
            session.abort()
        self.assertFalse(lock.released)
        self.assertEqual("running_chain", session._state)

    def test_running_chain_owner_crash_skips_abort_and_keeps_b2(self) -> None:
        events: list[str] = []

        class Workspace:
            _state = "live"

            @staticmethod
            def close() -> None:
                events.append("workspace-close")

        class Lock:
            held = True

            def release(self) -> None:
                events.append("b2-release")
                self.held = False

        class Lifetime:
            _state = "promotion_pending_admission"

            @staticmethod
            def prepare_admission_after_promotion(_prepare: object) -> None:
                raise RuntimeError("ordinary admission failure")

            def terminate(self) -> None:
                events.append("terminate-owner-crash")
                self._state = "owner_crash_only"
                raise WindowsJobChildOwnerCrashRequired(
                    "injected terminate outcome unknown"
                )

        lifetime = Lifetime()
        lock = Lock()
        session = object.__new__(LockedProductionSteadyServiceBootSession)
        for name, value in {
            "_persistence": object(),
            "_lock": lock,
            "_workspace": Workspace(),
            "_authorization": object(),
            "_scm_input": object(),
            "_lifecycle": object(),
            "_owner_thread": threading.get_ident(),
            "_stop_requested": threading.Event(),
            "_state": "child_resumed_start_pending",
            "_sealed": True,
        }.items():
            object.__setattr__(session, name, value)

        class Observer:
            @classmethod
            def load_exact_d(cls):
                return cls()

            @staticmethod
            def observe_steady(*_args: object) -> object:
                return object()

        class Admissions:
            @classmethod
            def load_exact_d(cls):
                return cls()

            @staticmethod
            def promote_job_to_service_lifetime(*_args: object) -> object:
                class Prepare:
                    service_lifetime = lifetime

                return Prepare()

        with patch.object(
            bootstrap_module, "ProductionWindowsScmProcessObserver", Observer
        ), patch.object(
            bootstrap_module, "ProductionWindowsEndpointObserver", Observer
        ), patch.object(
            bootstrap_module, "ProductionWindowsWriterLeaseObserver", Observer
        ), patch.object(
            bootstrap_module,
            "ProductionSteadyAdmissionAuthorityFactory",
            Admissions,
        ):
            with self.assertRaises(WindowsJobChildOwnerCrashRequired):
                session.complete_after_running()
        self.assertEqual(["terminate-owner-crash"], events)
        self.assertTrue(lock.held)
        self.assertEqual("running_chain", session._state)

    def test_begin_prelaunch_cleanup_owner_crash_keeps_b2(self) -> None:
        events: list[str] = []

        class FakePath:
            def __init__(self, value: str) -> None:
                self.value = value

            def __truediv__(self, part: str) -> "FakePath":
                return FakePath(f"{self.value}/{part}")

            def __str__(self) -> str:
                return self.value

            @staticmethod
            def mkdir(*_args: object, **_kwargs: object) -> None:
                return None

        class Lock:
            held = False

            def acquire(self) -> None:
                events.append("b2-acquire")
                self.held = True

            def release(self) -> None:
                events.append("b2-release")
                self.held = False

        class Workspace:
            _state = "live"

            @staticmethod
            def close() -> None:
                events.append("workspace-close-owner-crash")
                raise WindowsJobChildOwnerCrashRequired(
                    "injected workspace close outcome unknown"
                )

        lock = Lock()
        workspace = Workspace()

        class Persistence:
            @staticmethod
            def global_lock() -> Lock:
                return lock

            @staticmethod
            def bind_steady_boot_workspace(_lock: Lock) -> Workspace:
                return workspace

            @staticmethod
            def lock_steady_pair_static_facts(
                _lock: Lock, _workspace: Workspace
            ) -> object:
                events.append("ordinary-primary")
                raise RuntimeError("injected ordinary prelaunch failure")

        bootstrap = ProductionSteadyServiceBootstrap.load_exact_d()
        with patch.object(bootstrap_module, "Path", FakePath), patch.object(
            bootstrap_module, "validate_production_vm_write_path", return_value=None
        ), patch.object(
            bootstrap_module, "ensure_no_reparse_components", return_value=None
        ), patch.object(
            bootstrap_module.LocalDeploymentPersistence,
            "production",
            return_value=Persistence(),
        ):
            with self.assertRaises(WindowsJobChildOwnerCrashRequired) as raised:
                bootstrap.begin_prelaunch()
        self.assertIsInstance(raised.exception.__cause__, RuntimeError)
        self.assertEqual(
            [
                "b2-acquire",
                "ordinary-primary",
                "workspace-close-owner-crash",
            ],
            events,
        )
        self.assertTrue(lock.held)

    def test_stop_signal_revokes_chain_without_touching_kernel_owner(self) -> None:
        session = object.__new__(LockedProductionSteadyServiceBootSession)
        signal = threading.Event()
        object.__setattr__(session, "_stop_requested", signal)
        session.request_stop()
        self.assertTrue(signal.is_set())
        with self.assertRaisesRegex(Exception, "stop requested"):
            session._assert_continue()

    def test_stop_immediately_after_promotion_terminates_before_b2_release(self) -> None:
        events: list[str] = []

        class Workspace:
            _state = "live"

            def close(self) -> None:
                events.append("workspace-close")
                self._state = "closed"

        class Lock:
            held = True

            def release(self) -> None:
                events.append("b2-release")
                self.held = False

        class Lifetime:
            _state = "promotion_pending_admission"

            def terminate(self) -> None:
                events.append("job-terminate-wait-reprove")
                self._state = "closed"

        lifetime = Lifetime()
        session = object.__new__(LockedProductionSteadyServiceBootSession)
        for name, value in {
            "_persistence": object(),
            "_lock": Lock(),
            "_workspace": Workspace(),
            "_authorization": object(),
            "_scm_input": object(),
            "_lifecycle": object(),
            "_owner_thread": threading.get_ident(),
            "_stop_requested": threading.Event(),
            "_state": "child_resumed_start_pending",
            "_sealed": True,
        }.items():
            object.__setattr__(session, name, value)

        class Observer:
            @classmethod
            def load_exact_d(cls):
                return cls()

            @staticmethod
            def observe_steady(*_args):
                return object()

        class Admissions:
            @classmethod
            def load_exact_d(cls):
                return cls()

            @staticmethod
            def promote_job_to_service_lifetime(*_args):
                session.request_stop()

                class Prepare:
                    service_lifetime = lifetime

                return Prepare()

        with patch.object(
            bootstrap_module, "ProductionWindowsScmProcessObserver", Observer
        ), patch.object(
            bootstrap_module, "ProductionWindowsEndpointObserver", Observer
        ), patch.object(
            bootstrap_module, "ProductionWindowsWriterLeaseObserver", Observer
        ), patch.object(
            bootstrap_module,
            "ProductionSteadyAdmissionAuthorityFactory",
            Admissions,
        ):
            with self.assertRaisesRegex(Exception, "stop requested"):
                session.complete_after_running()
        self.assertEqual(
            ["job-terminate-wait-reprove", "workspace-close", "b2-release"],
            events,
        )


if __name__ == "__main__":
    unittest.main()
