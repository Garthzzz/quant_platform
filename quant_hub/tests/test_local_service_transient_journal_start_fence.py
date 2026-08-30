from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path
import pickle
import threading
import unittest
from unittest.mock import patch

from quant_hub.ops import local_service_transient_journal_start_fence as fence_module
from quant_hub.ops.local_service_transient_journal_start_fence import (
    ServiceTransientJournalStartFenceError,
    ServiceTransientJournalStartFenceOwnerCrashRequired,
    _validate_qualification_artifact,
    LockedServiceTransientJournalStartFence,
    ProductionServiceTransientJournalStartFence,
)
from quant_hub.ops.local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity
from quant_hub.ops.local_release_identity import canonical_bytes
from quant_hub.ops.local_runtime_qualification_evidence import (
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
    build_local_runtime_qualification_evidence,
)


class ServiceTransientJournalStartFenceTests(unittest.TestCase):
    @staticmethod
    def _qualification(*, attempt: str, role: str) -> tuple[bytes, str]:
        operation = "bootstrap_first_pair" if role == "baseline" else "activation"
        payload = {
            "schema_version": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
            "scope": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
            "attempt_id": attempt,
            "nonce": "nonce-1",
            "operation": operation,
            "role": role,
            "start_nonce": "start-1",
        }
        for index, field in enumerate(
            (
                "state_identity_sha256",
                "authorization_sha256",
                "release_compatibility_sha256",
                "release_closure_sha256",
                "production_state_before_order_sha256",
                "production_state_after_order_sha256",
                "scm_before_after_sha256",
                "endpoint_before_after_sha256",
                "writer_before_after_sha256",
                "canary_request_sha256",
                "canary_result_sha256",
                "canary_database_order_sha256",
                "runtime_tooling_manifest_sha256",
                "controller_tooling_observation_sha256",
            ),
            start=1,
        ):
            payload[field] = f"{index:064x}"
        document = build_local_runtime_qualification_evidence(payload)
        return canonical_bytes(document), str(document["aggregate_sha256"])

    def test_product_signatures_are_fixed_and_closed(self) -> None:
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    ProductionServiceTransientJournalStartFence.load_exact_d
                ).parameters
            ),
        )
        parameters = inspect.signature(
            ProductionServiceTransientJournalStartFence.pin_exact_identity
        ).parameters
        self.assertEqual(["self", "identity"], list(parameters))

    def test_product_source_is_existing_only_and_has_four_ordered_cuts(self) -> None:
        source_path = Path(inspect.getfile(ProductionServiceTransientJournalStartFence))
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        calls = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertIn("CreateFileW", calls)
        self.assertIn("ReadFile", calls)
        self.assertIn("FindFirstFileW", calls)
        self.assertIn("DuplicateHandle", calls)
        self.assertNotIn("mkdir", calls)
        self.assertNotIn("write_text", calls)
        self.assertNotIn("write_bytes", calls)
        self.assertNotIn("replace", calls)
        self.assertNotIn("unlink", calls)
        self.assertNotIn("LocalDeploymentPersistence", source)
        self.assertIn("_OPEN_EXISTING", source)
        self.assertNotIn("_CREATE_NEW", source)
        checkpoints = [
            source.index("def checkpoint_before_create_job"),
            source.index("def checkpoint_before_create_process"),
            source.index("def checkpoint_before_resume"),
            source.index("def checkpoint_after_resume_and_consume"),
        ]
        self.assertEqual(checkpoints, sorted(checkpoints))

    def test_exact_fence_rejects_subclass_pickle_and_mapping(self) -> None:
        with self.assertRaises(TypeError):
            class Forged(LockedServiceTransientJournalStartFence):  # type: ignore[misc]
                pass

        with self.assertRaises(TypeError):
            pickle.dumps(object.__new__(LockedServiceTransientJournalStartFence))
        factory = object.__new__(ProductionServiceTransientJournalStartFence)
        with self.assertRaises(TypeError):
            factory.pin_exact_identity({})  # type: ignore[arg-type]
        self.assertFalse(hasattr(LockedServiceTransientJournalStartFence, "identity"))
        self.assertFalse(
            hasattr(LockedServiceTransientJournalStartFence, "fence_sha256")
        )

    def test_reserved_qualification_aliases_and_current_role_are_rejected(self) -> None:
        raw, _aggregate = self._qualification(attempt="attempt-1", role="candidate")
        document = json.loads(raw)
        for name in (
            "renamed.json",
            "RUNTIME-QUALIFICATION-CANDIDATE.JSON",
        ):
            with self.subTest(name=name), self.assertRaises(
                ServiceTransientJournalStartFenceError
            ):
                _validate_qualification_artifact(
                    name=name,
                    raw=raw,
                    document=document,
                    directory_attempt="attempt-1",
                    history=(),
                    current_attempt="attempt-1",
                    current_role="candidate",
                )
        with self.assertRaisesRegex(
            ServiceTransientJournalStartFenceError, "already exists"
        ):
            _validate_qualification_artifact(
                name="runtime-qualification-candidate.json",
                raw=raw,
                document=document,
                directory_attempt="attempt-1",
                history=(),
                current_attempt="attempt-1",
                current_role="candidate",
            )

    def test_reserved_schema_or_scope_only_alias_is_rejected(self) -> None:
        for document in (
            {"schema_version": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA},
            {"scope": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE},
        ):
            raw = canonical_bytes(document)
            with self.subTest(document=document), self.assertRaisesRegex(
                ServiceTransientJournalStartFenceError, "malformed"
            ):
                _validate_qualification_artifact(
                    name="ordinary-evidence.json",
                    raw=raw,
                    document=document,
                    directory_attempt="attempt-1",
                    history=(),
                    current_attempt="attempt-1",
                    current_role="candidate",
                )

    def test_foreign_role_requires_exact_historical_verified_hash(self) -> None:
        raw, aggregate = self._qualification(attempt="attempt-1", role="prior")
        document = json.loads(raw)
        arguments = {
            "name": "runtime-qualification-prior.json",
            "raw": raw,
            "document": document,
            "directory_attempt": "attempt-1",
            "current_attempt": "attempt-1",
            "current_role": "candidate",
        }
        with self.assertRaisesRegex(
            ServiceTransientJournalStartFenceError, "verified revision"
        ):
            _validate_qualification_artifact(history=(), **arguments)
        _validate_qualification_artifact(
            history=(
                {
                    "phase": "prior_verified",
                    "evidence_hashes": {
                        "prior_runtime_qualification_sha256": aggregate
                    },
                },
            ),
            **arguments,
        )

    def test_constructor_cleanup_owner_crash_overrides_primary_error(self) -> None:
        api = object.__new__(fence_module._ExistingOnlyApi)
        identity = ExactRuntimeLeaseIdentity(
            attempt_id="attempt-cleanup",
            nonce="deployment-cleanup",
            operation="activation",
            role="candidate",
            start_nonce="start-cleanup",
            state_identity_sha256="1" * 64,
            release_id="release-cleanup",
            manifest_sha256="2" * 64,
        )
        primary = RuntimeError("primary pin failure")
        cleanup = ServiceTransientJournalStartFenceOwnerCrashRequired(
            "pin close outcome unknown"
        )
        with patch.object(
            LockedServiceTransientJournalStartFence,
            "_pin_initial_state",
            side_effect=primary,
        ), patch.object(
            LockedServiceTransientJournalStartFence,
            "_close_all",
            side_effect=cleanup,
        ):
            with self.assertRaises(
                ServiceTransientJournalStartFenceOwnerCrashRequired
            ) as raised:
                LockedServiceTransientJournalStartFence(
                    api, identity, token=fence_module._FENCE_TOKEN
                )
        self.assertIs(primary, raised.exception.__cause__)

    def test_checkpoint_preserves_owner_crash_only_state(self) -> None:
        fence = object.__new__(LockedServiceTransientJournalStartFence)
        pin = fence_module._PinnedExisting(
            fence_module._PRODUCTION_ROOT,
            101,
            True,
            (1, 2, 3, 4, 5),
            None,
        )
        for name, value in {
            "_pins": {"root": pin},
            "_directory_snapshots": {"root": ()},
            "_owner_thread": threading.get_ident(),
            "_state": "live",
            "_checkpoint_index": 0,
            "_sealed": True,
        }.items():
            object.__setattr__(fence, name, value)
        with patch.object(
            LockedServiceTransientJournalStartFence,
            "_file_identity",
            return_value=pin.identity,
        ), patch.object(
            LockedServiceTransientJournalStartFence,
            "_enumerate",
            side_effect=ServiceTransientJournalStartFenceOwnerCrashRequired(
                "FindClose unknown"
            ),
        ):
            with self.assertRaises(
                ServiceTransientJournalStartFenceOwnerCrashRequired
            ):
                fence._checkpoint(0)
        self.assertEqual("owner_crash_only", fence._state)

    def test_launcher_places_all_journal_cuts_around_kernel_launch(self) -> None:
        from quant_hub.ops.local_windows_job_child_launcher import (
            ProductionWindowsJobChildLauncher,
        )

        source = Path(inspect.getfile(ProductionWindowsJobChildLauncher)).read_text(
            encoding="utf-8"
        )
        launch_transient = source[
            source.index("    def launch_transient(") :
            source.index("    def launch_steady(")
        ]
        launch_kernel = source[
            source.index("    def _launch(") : source.index("\n\n__all__")
        ]
        self.assertLess(
            launch_transient.index("checkpoint_before_create_job"),
            launch_transient.index("self._launch(lifecycle)"),
        )
        self.assertLess(
            launch_kernel.index("checkpoint_before_create_process"),
            launch_kernel.index("api.CreateProcessW("),
        )
        self.assertLess(
            launch_kernel.index("api.CreateProcessW("),
            launch_kernel.index("checkpoint_before_resume"),
        )
        self.assertLess(
            launch_kernel.index("checkpoint_before_resume"),
            launch_kernel.index("api.ResumeThread("),
        )
        self.assertLess(
            launch_kernel.index("api.ResumeThread("),
            launch_kernel.index("checkpoint_after_resume_and_consume"),
        )


if __name__ == "__main__":
    unittest.main()
