from __future__ import annotations

import inspect
import os
from pathlib import Path
from pathlib import PurePosixPath
import pickle
import tempfile
import unittest
from unittest import mock

from quant_hub.ops import local_exact_runtime_controller_tooling_observer as observer
from quant_hub.ops import local_exact_runtime_tooling as contract
from quant_hub.ops.local_exact_runtime_canary_input import (
    LockedExactRuntimeCanaryInput,
)
from quant_hub.ops.local_exact_runtime_tooling_scanner import (
    EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH,
    TestOnlyExactRuntimeToolingAdapter,
)


def _path(root: Path, relative: str) -> Path:
    return root.joinpath(*PurePosixPath(relative).parts)


class ExactRuntimeControllerToolingObserverContractTests(unittest.TestCase):
    def test_product_surface_is_noarg_exact_sealed_and_non_serializable(self) -> None:
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    observer.ProductionExactRuntimeControllerToolingObserver.load_exact_d
                ).parameters
            ),
        )
        self.assertEqual(
            ["self", "canary"],
            list(
                inspect.signature(
                    observer.ProductionExactRuntimeControllerToolingObserver.observe
                ).parameters
            ),
        )
        product = observer.ProductionExactRuntimeControllerToolingObserver.load_exact_d()
        with self.assertRaises(TypeError):
            product.observe(object())  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            pickle.dumps(product)
        with self.assertRaises(TypeError):
            product._scanner = object()  # type: ignore[attr-defined]
        with self.assertRaises(TypeError):
            type(
                "ForgedControllerToolingObserver",
                (observer.ProductionExactRuntimeControllerToolingObserver,),
                {},
            )
        with self.assertRaises(TypeError):
            type(
                "ForgedLockedControllerToolingObservation",
                (observer.LockedExactRuntimeControllerToolingObservation,),
                {},
            )
        forged = object.__new__(
            observer.LockedExactRuntimeControllerToolingObservation
        )
        with self.assertRaises(TypeError):
            pickle.dumps(forged)
        with self.assertRaisesRegex(TypeError, "provenance"):
            observer.LockedExactRuntimeControllerToolingObservation(
                object(), object(), token=object()  # type: ignore[arg-type]
            )
        self.assertNotIn(
            "_TestOnlyExactRuntimeControllerToolingObserverAdapter",
            observer.__all__,
        )

    def test_product_registers_with_canary_before_acquisition_and_cleans_failure(self) -> None:
        canary = object.__new__(LockedExactRuntimeCanaryInput)
        object.__setattr__(canary, "_state", "live")
        object.__setattr__(canary, "_controller_tooling_observation", None)
        product = observer.ProductionExactRuntimeControllerToolingObserver.load_exact_d()
        registered = False

        def fail_after_registration(core) -> None:
            nonlocal registered
            del core
            registered = (
                type(canary._controller_tooling_observation)  # noqa: SLF001
                is observer.LockedExactRuntimeControllerToolingObservation
            )
            raise observer.ExactRuntimeControllerToolingObserverError(
                "fixture acquisition failure"
            )

        with mock.patch.object(
            observer._LiveToolingCore,
            "acquire",
            autospec=True,
            side_effect=fail_after_registration,
        ), self.assertRaisesRegex(
            observer.ExactRuntimeControllerToolingObserverError,
            "fixture acquisition failure",
        ):
            product.observe(canary)
        self.assertTrue(registered)
        self.assertIsNone(canary._controller_tooling_observation)  # noqa: SLF001


@unittest.skipUnless(os.name == "nt", "真实 Windows read guard/namespace monitor 测试")
class ExactRuntimeControllerToolingObserverWindowsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="qrh-controller-tooling-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        for _field, logical_name, relative in contract._BINARY_PATHS:
            path = _path(self.root, relative)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((logical_name + "-binary\n").encode("utf-8"))
        for logical_name, relative in contract._KEY_FILES:
            path = _path(
                self.root,
                contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH + "/" + relative,
            )
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((logical_name + "\n").encode("utf-8"))
        self.package = _path(
            self.root, contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH
        )
        self.extra = self.package / "app.py"
        self.extra.write_bytes(b"application\n")
        tooling = TestOnlyExactRuntimeToolingAdapter.for_test_only(self.root)
        manifest = tooling.build_claim()
        manifest_path = _path(
            self.root, EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH
        )
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(manifest.canonical_bytes())
        self.adapter = (
            observer._TestOnlyExactRuntimeControllerToolingObserverAdapter.for_test_only(
                self.root
            )
        )

    def test_live_evidence_rechecks_exact_manifest_and_close_revokes(self) -> None:
        live = self.adapter.observe_test_only()
        evidence = live.build_evidence()
        document = evidence.as_dict()
        self.assertEqual(
            "controller_tooling_live_observed_not_qualified",
            document["scope"],
        )
        self.assertGreaterEqual(document["checkpoint_generation"], 2)
        with self.assertRaises(OSError):
            self.extra.write_bytes(b"blocked while live\n")
        live.close()
        with self.assertRaises(
            observer.ExactRuntimeControllerToolingObserverError
        ):
            live.build_evidence()
        self.extra.write_bytes(b"write allowed after close\n")

    def test_add_delete_aba_is_detected_by_overlapped_namespace_monitor(self) -> None:
        live = self.adapter.observe_test_only()
        added = self.package / "aba.py"
        added.write_bytes(b"temporary\n")
        added.unlink()
        with self.assertRaisesRegex(
            observer.ExactRuntimeControllerToolingObserverError,
            "checkpoint",
        ):
            live.build_evidence()

    def test_persistent_new_member_revokes_live_observation(self) -> None:
        live = self.adapter.observe_test_only()
        added = self.package / "third.py"
        added.write_bytes(b"third\n")
        with self.assertRaisesRegex(
            observer.ExactRuntimeControllerToolingObserverError,
            "checkpoint",
        ):
            live.build_evidence()

    def test_mismatched_persisted_manifest_releases_all_acquired_guards(self) -> None:
        manifest_path = _path(
            self.root, EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH
        )
        raw = manifest_path.read_bytes()
        manifest_path.write_bytes(raw[:-1] + b"\n")
        with self.assertRaises(
            observer.ExactRuntimeControllerToolingObserverError
        ):
            self.adapter.observe_test_only()
        self.extra.write_bytes(b"construction cleanup released guard\n")
        manifest_path.write_bytes(raw)

    def test_real_core_close_unknown_is_irreversible_and_keeps_canary_reserved(
        self,
    ) -> None:
        class WorkspaceProbe:
            def __init__(self) -> None:
                self.released = False

            def _close_runtime_canary_input_public(self, canary) -> None:
                canary._close_from_workspace(self)
                self.released = True

        workspace = WorkspaceProbe()
        canary = object.__new__(LockedExactRuntimeCanaryInput)
        object.__setattr__(canary, "_state", "live")
        object.__setattr__(canary, "_workspace", workspace)
        object.__setattr__(canary, "_live_observation", None)
        object.__setattr__(canary, "_controller_tooling_observation", None)
        core = observer._LiveToolingCore(self.adapter._scanner)  # noqa: SLF001
        live = observer.LockedExactRuntimeControllerToolingObservation(
            core,
            canary,
            token=observer._OBSERVATION_TOKEN,  # noqa: SLF001
        )
        core.acquire()
        original_close_resource = observer._LiveToolingCore._close_resource
        injected = False

        def close_then_report_unknown(owner, resource):
            nonlocal injected
            result = original_close_resource(owner, resource)
            if resource is not None and not injected:
                injected = True
                return RuntimeError("fixture post-close outcome unknown")
            return result

        with mock.patch.object(
            observer._LiveToolingCore,
            "_close_resource",
            autospec=True,
            side_effect=close_then_report_unknown,
        ), self.assertRaisesRegex(
            observer.ExactRuntimeControllerToolingObserverError,
            "结果不明",
        ):
            live.close()
        self.assertTrue(injected)
        self.assertEqual("owner_crash_only", core._state)  # noqa: SLF001
        self.assertIs(
            live,
            canary._controller_tooling_observation,  # noqa: SLF001
        )

        with self.assertRaisesRegex(
            observer.ExactRuntimeControllerToolingObserverError,
            "不可判定",
        ):
            live.close()
        self.assertEqual("owner_crash_only", core._state)  # noqa: SLF001
        self.assertIs(
            live,
            canary._controller_tooling_observation,  # noqa: SLF001
        )
        with self.assertRaisesRegex(
            observer.ExactRuntimeControllerToolingObserverError,
            "不可判定",
        ):
            canary.close()
        self.assertFalse(workspace.released)
        self.assertIs(
            live,
            canary._controller_tooling_observation,  # noqa: SLF001
        )


if __name__ == "__main__":
    unittest.main()
