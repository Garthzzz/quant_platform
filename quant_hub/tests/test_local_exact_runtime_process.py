from __future__ import annotations

import ast
import inspect
from pathlib import Path
import unittest
from unittest.mock import patch

from quant_hub.ops import local_exact_runtime_process as subject
from quant_hub.ops.local_exact_runtime_admission import LockedExactRuntimeAdmissionGate
from quant_hub.ops.local_windows_writer_lease_holder import (
    LockedSteadyWindowsWriterLease,
    LockedWindowsWriterLease,
)


class _Closure:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def activate(self) -> None:
        self.calls.append("activate")

    def assert_application_sources(self) -> None:
        self.calls.append("sources")

    def close(self) -> None:
        self.calls.append("close")


class ExactRuntimeProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lease = object.__new__(LockedWindowsWriterLease)
        self.closure = _Closure()

    def test_closure_precedes_server_and_is_closed_after_success(self) -> None:
        observed: list[str] = []

        def serve(lease: object, closure: object) -> int:
            self.assertIs(self.lease, lease)
            self.assertIs(self.closure, closure)
            observed.extend(self.closure.calls)
            observed.append("serve")
            return 0

        with patch.object(
            subject.ProductionExactRuntimeImportClosure,
            "load_exact_d",
            return_value=self.closure,
        ), patch(
            "quant_hub.ops.local_exact_runtime_server.serve_exact_runtime",
            side_effect=serve,
        ):
            self.assertEqual(0, subject.run_exact_runtime(self.lease))
        self.assertEqual(["activate", "sources", "serve"], observed)
        self.assertEqual(
            ["activate", "sources", "close"], self.closure.calls
        )

    def test_server_failure_still_closes_import_closure(self) -> None:
        with patch.object(
            subject.ProductionExactRuntimeImportClosure,
            "load_exact_d",
            return_value=self.closure,
        ), patch(
            "quant_hub.ops.local_exact_runtime_server.serve_exact_runtime",
            side_effect=RuntimeError("server failed"),
        ):
            with self.assertRaisesRegex(RuntimeError, "server failed"):
                subject.run_exact_runtime(self.lease)
        self.assertEqual(
            ["activate", "sources", "close"], self.closure.calls
        )

    def test_closure_close_failure_retires_writer_until_process_exit(self) -> None:
        retired = []

        def fail_close() -> None:
            self.closure.calls.append("close")
            raise RuntimeError("closure close failed")

        self.closure.close = fail_close  # type: ignore[method-assign]
        with patch.object(
            subject.ProductionExactRuntimeImportClosure,
            "load_exact_d",
            return_value=self.closure,
        ), patch(
            "quant_hub.ops.local_exact_runtime_server.serve_exact_runtime",
            return_value=0,
        ), patch.object(
            LockedWindowsWriterLease,
            "_retire_to_owner_crash_only",
            lambda lease: retired.append(lease),
        ):
            with self.assertRaisesRegex(RuntimeError, "closure close failed"):
                subject.run_exact_runtime(self.lease)
        self.assertEqual([self.lease], retired)
        self.assertEqual(["activate", "sources", "close"], self.closure.calls)

    def test_closure_construction_failure_retires_writer_before_entry_finally(self) -> None:
        retired = []
        with patch.object(
            subject.ProductionExactRuntimeImportClosure,
            "load_exact_d",
            side_effect=RuntimeError("closure construction failed"),
        ), patch.object(
            LockedWindowsWriterLease,
            "_retire_to_owner_crash_only",
            lambda lease: retired.append(lease),
        ):
            with self.assertRaisesRegex(RuntimeError, "construction failed"):
                subject.run_exact_runtime(self.lease)
        self.assertEqual([self.lease], retired)

    def test_exact_signature_and_no_application_top_level_import(self) -> None:
        self.assertEqual(
            ["lease"], list(inspect.signature(subject.run_exact_runtime).parameters)
        )
        source = Path(subject.__file__).read_text("utf-8")
        tree = ast.parse(source)
        top_imports = {
            alias.name
            for node in tree.body
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertTrue(
            {
                "quant_hub.app",
                "quant_hub.config",
                "quant_hub.archive",
                "quant_hub.collaboration",
                "quant_hub.research_workspace",
                "quant_hub.platform.db",
            }.isdisjoint(top_imports)
        )
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue({"exec", "eval", "compile"}.isdisjoint(calls))

    def test_steady_closure_precedes_server_and_preserves_distinct_types(self) -> None:
        steady_lease = object.__new__(LockedSteadyWindowsWriterLease)
        gate = object.__new__(LockedExactRuntimeAdmissionGate)
        observed: list[str] = []

        def serve(lease: object, admission: object, closure: object) -> int:
            self.assertIs(steady_lease, lease)
            self.assertIs(gate, admission)
            self.assertIs(self.closure, closure)
            observed.extend(self.closure.calls)
            observed.append("serve-steady")
            return 0

        with patch.object(
            subject.ProductionExactRuntimeImportClosure,
            "load_steady_exact_d",
            return_value=self.closure,
        ), patch(
            "quant_hub.ops.local_exact_runtime_server.serve_steady_exact_runtime",
            side_effect=serve,
        ):
            self.assertEqual(
                0, subject.run_steady_exact_runtime(steady_lease, gate)
            )
        self.assertEqual(
            ["activate", "sources", "serve-steady"], observed
        )
        self.assertEqual(
            ["activate", "sources", "close"], self.closure.calls
        )

    def test_steady_process_rejects_transient_or_mapping_role_confusion(self) -> None:
        steady_lease = object.__new__(LockedSteadyWindowsWriterLease)
        gate = object.__new__(LockedExactRuntimeAdmissionGate)
        with self.assertRaises(TypeError):
            subject.run_steady_exact_runtime(self.lease, gate)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            subject.run_steady_exact_runtime(steady_lease, {})  # type: ignore[arg-type]
        self.assertEqual(
            ["lease", "gate"],
            list(inspect.signature(subject.run_steady_exact_runtime).parameters),
        )


if __name__ == "__main__":
    unittest.main()
