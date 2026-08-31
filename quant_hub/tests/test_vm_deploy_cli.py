from __future__ import annotations

from contextlib import ExitStack, closing
from dataclasses import replace
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from quant_hub.ops.deployment import CandidateValidationError, DeploymentFailed
from quant_hub.ops import local_release_identity as local_identity
from quant_hub.ops.local_deployment_persistence import (
    LocalDeploymentPersistence,
    _SafeRoot,
)
from quant_hub.ops import vm_deploy_cli as vm_deploy_module
from quant_hub.ops.service_entry import ServiceEntryError, resolve_context
from quant_hub.ops.release_identity import manifest_sha256
from quant_hub.ops.vm_deploy_cli import (
    VMDeployCLIError,
    WindowsServiceRuntime,
    apply_publish,
    verify_runtime_environment,
)
from quant_hub.ops.vm_boundary import declared_production_vm_write_set
from quant_hub.runtime_seal import read_json

from tests.test_deployment_controller import (
    DeploymentFixture,
    write_partial,
)
from tests.test_local_deployment_persistence import (
    history_to as local_history_to,
    journal as local_journal,
    migration_bytes as local_migration_bytes,
    release as local_release,
)


CANDIDATE_HASH = "9" * 64
ENVIRONMENT = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "TEMP": r"D:\quant\quant_platform\tmp\deployment-cli",
    "TMP": r"D:\quant\quant_platform\tmp\deployment-cli",
}


def windows_runtime(root: Path) -> WindowsServiceRuntime:
    return WindowsServiceRuntime(
        root=root,
        service_name="QuantResearchHub",
        base_url="http://127.0.0.1:8765",
        listen_host="0.0.0.0",
        port=8765,
        critical_paths=("/login",),
        writer_authority="D-active",
        service_entry_relative_path=(
            "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py"
        ),
        application_source_relative_path="runtime_contract/code/src",
        archive_root_relative_path="reference/archive",
        var_root_relative_path="runtime",
        migration_root_relative_path="runtime_contract/migrations/platform",
        access_password_digest_path="state/viewer_access_password.digest",
        session_key_path="state/viewer_secret.key",
        comment_database_path="state/comments.sqlite3",
        workspace_database_path="state/research_workspace.sqlite3",
    )


class Hooks:
    allow_legacy_deployment_test_only = True

    def __init__(
        self,
        *,
        health: bool = True,
        candidate_health: bool = True,
        candidate_browser: bool = True,
        candidate_api: bool = True,
        candidate_resource: bool = True,
    ) -> None:
        self.health = health
        self.candidate_health = candidate_health
        self.candidate_browser = candidate_browser
        self.candidate_api = candidate_api
        self.candidate_resource = candidate_resource
        self.started: list[str] = []
        self.stopped: list[str] = []

    def state_compatibility_probe(self, _release) -> bool:
        return True

    def candidate_probe(self, _path: Path, identity):
        return {
            "schema_version": "qrh-candidate-probe-evidence/v1",
            "release_id": identity["release_id"],
            "manifest_sha256": identity["manifest_sha256"],
            "snapshot_id": identity["snapshot_id"],
            "transport": "loopback_isolated",
            "writer_authority": "candidate-checkpoint-isolated",
            "health": self.candidate_health,
            "browser": self.candidate_browser,
            "api": self.candidate_api,
            "resource": self.candidate_resource,
            "state_isolated": True,
            "active_unchanged": True,
            "cleaned": True,
        }

    def start_release(self, path: Path, _active) -> bool:
        self.started.append(path.name)
        return True

    def stop_release(self, path: Path) -> None:
        self.stopped.append(path.name)

    def post_activation_probe(self, _path: Path, _active):
        return {
            "health": self.health,
            "critical_functions": True,
            "writer_fence": True,
        }


class VMDeployCLITests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "bootstrap boundary is Windows-only")
    def test_bootstrap_boundary_excludes_observer_powershell_from_legacy_scan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            runtime = windows_runtime(Path(directory).resolve())
            observed_commands: list[str] = []

            def completed(command, **_kwargs):
                observed_commands.append(command[-1])
                return mock.Mock(returncode=0, stdout=b"[]", stderr=b"")

            with mock.patch.object(
                WindowsServiceRuntime,
                "_query_service_state",
                return_value="STOPPED",
            ), mock.patch(
                "quant_hub.ops.vm_deploy_cli.subprocess.run", side_effect=completed
            ):
                evidence = runtime.observe_bootstrap_boundary()

        self.assertEqual([], evidence["ingress"]["listener_pids"])
        self.assertEqual([], evidence["legacy_c_writer"]["process_pids"])
        self.assertEqual(2, len(observed_commands))
        self.assertIn("$_.ProcessId -ne $PID", observed_commands[1])

    def test_candidate_live_sqlite_pin_blocks_path_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "comments.sqlite3"
            replacement = root / "replacement.sqlite3"
            source.write_bytes(b"source")
            replacement.write_bytes(b"replacement")
            with vm_deploy_module._pin_live_candidate_sqlite_members(source):
                with self.assertRaises(PermissionError):
                    os.replace(replacement, source)
            os.replace(replacement, source)
            self.assertEqual(b"replacement", source.read_bytes())

    def test_candidate_live_sqlite_pin_rejects_new_absent_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "comments.sqlite3"
            source.write_bytes(b"source")
            with self.assertRaisesRegex(Exception, "namespace changed"):
                with vm_deploy_module._pin_live_candidate_sqlite_members(source):
                    Path(str(source) + "-wal").write_bytes(b"new-sidecar")

    def test_candidate_tree_members_remain_pinned_for_child_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            tree = root / "candidate"
            tree.mkdir()
            member = tree / "entry.py"
            member.write_bytes(b"print('fixed')\n")
            replacement = root / "replacement.py"
            replacement.write_bytes(b"print('replacement')\n")
            safe_root = _SafeRoot(root, allow_posix_test_only=True)
            with ExitStack() as stack:
                pinned = vm_deploy_module._pin_candidate_tree(
                    stack,
                    safe_root=safe_root,
                    tree_root=tree,
                )
                self.assertEqual((member,), pinned)
                with self.assertRaises(PermissionError):
                    os.replace(replacement, member)
            os.replace(replacement, member)
            self.assertIn(b"replacement", member.read_bytes())

    def test_test_service_root_rejects_production_d_aliases_before_read(self) -> None:
        aliases = (
            Path(r"D:\quant\quant_platform"),
            Path(r"D:\quant\quant_platform\."),
            Path(r"D:\quant\quant_platform\child\.."),
            Path(r"d:/QUANT/quant_PLATFORM"),
        )
        with mock.patch(
            "quant_hub.ops.service_entry._regular",
            side_effect=AssertionError("service filesystem read must not run"),
        ):
            for alias in aliases:
                with self.subTest(alias=str(alias)), self.assertRaisesRegex(
                    ServiceEntryError, "cannot target production D root"
                ):
                    resolve_context(
                        alias,
                        expected_release_id="release-r1",
                        expected_manifest_sha256="a" * 64,
                        allow_test_root=True,
                    )

    def test_foreign_hooks_cannot_reach_legacy_controller_on_production_d(self) -> None:
        with mock.patch(
            "quant_hub.ops.vm_deploy_cli.DeploymentController"
        ) as legacy:
            with self.assertRaisesRegex(
                VMDeployCLIError, "internally constructed"
            ):
                apply_publish(
                    vm_root=Path(r"D:\quant\quant_platform"),
                    release_id="release-escape",
                    release_manifest_sha256="a" * 64,
                    publish_candidate_sha256=CANDIDATE_HASH,
                    deployment_mode="activate",
                    deployment_attempt_id="escape-attempt",
                    hooks=Hooks(),
                    root_verifier=lambda _path: Path(
                        r"D:\quant\quant_platform"
                    ),
                    environment=ENVIRONMENT,
                )
        legacy.assert_not_called()

    def test_production_candidate_rejects_shadowed_or_custom_runtime_before_root(self) -> None:
        runtime = windows_runtime(self.fixture.root)
        with self.assertRaises(AttributeError):
            object.__setattr__(
                runtime,
                "candidate_probe",
                lambda *_args, **_kwargs: {
                    "schema_version": "qrh-candidate-probe-evidence/v1"
                },
            )
        custom_popen = replace(
            windows_runtime(self.fixture.root),
            candidate_popen_factory=lambda *_args, **_kwargs: object(),
        )
        with mock.patch(
            "quant_hub.ops.vm_deploy_cli.verify_production_root",
            side_effect=AssertionError("production root must remain untouched"),
        ), mock.patch(
            "quant_hub.ops.local_deployment_persistence."
            "LocalDeploymentPersistence.production",
            side_effect=AssertionError("persistence must remain untouched"),
        ):
            aliases = (
                Path(r"D:\quant\quant_platform"),
                Path(r"D:\quant\quant_platform\."),
                Path(r"D:\quant\quant_platform\child\.."),
                Path(r"d:/QUANT/quant_PLATFORM"),
            )
            for injected in (runtime, custom_popen):
                for alias in aliases:
                    with self.subTest(
                        injected=injected, alias=str(alias)
                    ), self.assertRaisesRegex(
                        VMDeployCLIError, "internally constructed"
                    ):
                        apply_publish(
                            vm_root=alias,
                            release_id="release-shadowed-candidate",
                            release_manifest_sha256="a" * 64,
                            publish_candidate_sha256=CANDIDATE_HASH,
                            deployment_mode="candidate_only",
                            hooks=injected,
                        )

    @unittest.skipUnless(os.name == "nt", "production provenance is Windows-only")
    def test_product_windows_runtime_method_shadow_is_structurally_impossible(self) -> None:
        document = {
            "schema_version": "qrh-vm-deploy-runtime/v1",
            "service_name": "QuantResearchHub",
            "base_url": "http://127.0.0.1:8765",
            "listen_host": "0.0.0.0",
            "port": 8765,
            "critical_paths": [
                "/login", "/api/v1/research", "/api/v1/dashboard"
            ],
            "writer_authority": "D-active",
            "service_entry_relative_path": "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            "application_source_relative_path": "runtime_contract/code/src",
            "archive_root_relative_path": "reference/archive",
            "var_root_relative_path": "runtime",
            "migration_root_relative_path": "runtime_contract/migrations/platform",
            "access_password_digest_path": "state/viewer_access_password.digest",
            "session_key_path": "state/viewer_secret.key",
            "comment_database_path": "state/comments.sqlite3",
            "workspace_database_path": "state/research_workspace.sqlite3",
            "write_paths": list(declared_production_vm_write_set().values()),
        }
        with mock.patch(
            "quant_hub.ops.vm_deploy_cli.read_json", return_value=document
        ):
            runtime = WindowsServiceRuntime.load(Path(r"D:\quant\quant_platform"))
        for method_name in (
            "stop_exact_transient",
            "ensure_steady_exact",
            "observe_bootstrap_boundary",
            "candidate_probe",
        ):
            with self.subTest(method_name=method_name), self.assertRaises(AttributeError):
                object.__setattr__(
                    runtime,
                    method_name,
                    lambda *_args, **_kwargs: None,
                )
        with self.assertRaises(AttributeError):
            _ = runtime.__dict__
        WindowsServiceRuntime._assert_production_provenance(runtime)

    def test_default_production_activation_calls_only_exact_v4_controller(self) -> None:
        runtime = windows_runtime(self.fixture.root)
        exact = mock.Mock()
        exact.activate_successor.return_value = {
            "schema_version": "qrh-vm-deploy-result/v2",
            "status": "activated",
            "release_id": "release-exact-r1",
            "release_manifest_sha256": "a" * 64,
            "activation_receipt_id": "activation-exact-attempt",
        }
        with mock.patch(
            "quant_hub.ops.local_exact_deployment_controller."
            "ProductionExactDeploymentController.load_exact_d",
            return_value=exact,
        ), mock.patch(
            "quant_hub.ops.vm_deploy_cli.verify_existing_vm_write_path",
            return_value=Path(r"D:\quant\quant_platform"),
        ), mock.patch.object(
            WindowsServiceRuntime, "load", return_value=runtime,
        ), mock.patch(
            "quant_hub.ops.vm_deploy_cli.verify_runtime_environment",
        ), mock.patch(
            "quant_hub.ops.vm_deploy_cli.DeploymentController",
        ) as legacy:
            result = apply_publish(
                vm_root=Path(r"D:\quant\quant_platform"),
                release_id="release-exact-r1",
                release_manifest_sha256="a" * 64,
                publish_candidate_sha256=CANDIDATE_HASH,
                deployment_mode="activate",
                deployment_attempt_id="exact-attempt",
                hooks=None,
            )
        legacy.assert_not_called()
        exact.activate_successor.assert_called_once_with(
            release_id="release-exact-r1",
            expected_manifest_sha256="a" * 64,
            attempt_id="exact-attempt",
        )
        self.assertEqual("activation-exact-attempt", result["evidence_id"])

    def test_rollback_prior_cli_exposes_only_attempt_and_exact_d_root(self) -> None:
        exact = mock.Mock()
        exact.rollback_to_prior.return_value = {
            "schema_version": "qrh-vm-deploy-result/v2",
            "status": "rolled_back",
            "release_id": "release-r0",
            "release_manifest_sha256": "a" * 64,
            "attempt_id": "rollback-r1-to-r0",
            "terminal_journal_sha256": "b" * 64,
            "rollback_receipt_id": "rollback-rollback-r1-to-r0",
        }
        exact_root = Path(r"D:\quant\quant_platform")
        with mock.patch(
            "quant_hub.ops.vm_deploy_cli.verify_production_root",
            return_value=exact_root,
        ) as verify, mock.patch(
            "quant_hub.ops.local_exact_deployment_controller."
            "ProductionExactDeploymentController.load_exact_d",
            return_value=exact,
        ):
            result = vm_deploy_module.rollback_prior(
                vm_root=exact_root,
                deployment_attempt_id="rollback-r1-to-r0",
            )
        verify.assert_called_once_with(exact_root)
        exact.rollback_to_prior.assert_called_once_with(
            attempt_id="rollback-r1-to-r0"
        )
        self.assertEqual("rolled_back", result["status"])

        with mock.patch(
            "quant_hub.ops.vm_deploy_cli.verify_production_root",
            return_value=exact_root,
        ), mock.patch(
            "quant_hub.ops.vm_deploy_cli.capture_vm_write_snapshot",
            return_value=object(),
        ) as capture, mock.patch(
            "quant_hub.ops.vm_deploy_cli.rollback_prior",
            return_value=result,
        ) as rollback, mock.patch(
            "quant_hub.ops.vm_deploy_cli.finalize_vm_write_audit",
        ) as audit, mock.patch("builtins.print"):
            code = vm_deploy_module.main(
                [
                    "rollback-prior",
                    "--vm-root",
                    str(exact_root),
                    "--deployment-attempt-id",
                    "rollback-r1-to-r0",
                    "--json",
                ]
            )
        self.assertEqual(0, code)
        capture.assert_called_once_with(exact_root)
        rollback.assert_called_once_with(
            vm_root=exact_root,
            deployment_attempt_id="rollback-r1-to-r0",
        )
        audit.assert_called_once_with(
            exact_root,
            mock.ANY,
            operation="rollback-prior",
            outcome="succeeded",
        )

    def test_exact_stop_and_steady_start_require_observed_terminal_states(self) -> None:
        runtime = windows_runtime(self.fixture.root)
        with mock.patch.object(
            WindowsServiceRuntime, "_service", autospec=True, return_value=True
        ) as service, mock.patch.object(
            WindowsServiceRuntime,
            "_query_service_state",
            autospec=True,
            side_effect=["STOP_PENDING", "STOPPED"],
        ), mock.patch("quant_hub.ops.vm_deploy_cli.time.sleep"):
            runtime.stop_exact_transient()
        service.assert_called_once_with(runtime, "stop", allow_failure=True)

        with mock.patch.object(
            WindowsServiceRuntime, "_service", autospec=True, return_value=True
        ) as service, mock.patch.object(
            WindowsServiceRuntime,
            "_query_service_state",
            autospec=True,
            return_value="RUNNING",
        ), mock.patch.object(
            WindowsServiceRuntime,
            "_get",
            autospec=True,
            return_value=(200, b"ready"),
        ):
            self.assertTrue(runtime.start_steady_exact())
        service.assert_called_once_with(runtime, "start")

    def test_exact_steady_ensure_reuses_only_matching_running_identity(self) -> None:
        runtime = windows_runtime(self.fixture.root)
        manifest = self.fixture.finalize(
            "release-steady", commit_character="d"
        )
        final = self.fixture.controller.release_path("release-steady")
        release = {
            "release_id": "release-steady",
            "release_path": str(final),
            "manifest_sha256": manifest_sha256(manifest),
        }
        with mock.patch.object(
            WindowsServiceRuntime,
            "_query_service_state",
            autospec=True,
            return_value="RUNNING",
        ), mock.patch.object(
            WindowsServiceRuntime,
            "_deployment_identity",
            autospec=True,
            return_value=(True, True),
        ) as observed, mock.patch.object(
            WindowsServiceRuntime, "_service", autospec=True
        ) as service:
            self.assertTrue(runtime.ensure_steady_exact(release))
        service.assert_not_called()
        observed.assert_called_once()

    def test_exact_steady_ensure_restarts_wrong_running_identity(self) -> None:
        runtime = windows_runtime(self.fixture.root)
        manifest = self.fixture.finalize(
            "release-steady-restart", commit_character="e"
        )
        final = self.fixture.controller.release_path("release-steady-restart")
        release = {
            "release_id": "release-steady-restart",
            "release_path": str(final),
            "manifest_sha256": manifest_sha256(manifest),
        }
        with mock.patch.object(
            WindowsServiceRuntime,
            "_query_service_state",
            autospec=True,
            side_effect=["RUNNING", "RUNNING", "STOPPED", "RUNNING"],
        ), mock.patch.object(
            WindowsServiceRuntime,
            "_deployment_identity",
            autospec=True,
            side_effect=[(False, False), (True, True)],
        ), mock.patch.object(
            WindowsServiceRuntime,
            "_service",
            autospec=True,
            return_value=True,
        ) as service, mock.patch.object(
            WindowsServiceRuntime,
            "start_steady_exact",
            autospec=True,
            return_value=True,
        ), mock.patch("quant_hub.ops.vm_deploy_cli.time.sleep"):
            self.assertTrue(runtime.ensure_steady_exact(release))
        service.assert_called_once_with(runtime, "stop", allow_failure=True)

    def test_legacy_start_callback_is_sealed_before_scm(self) -> None:
        prior = self.fixture.finalize("release-prior", commit_character="a")
        candidate = self.fixture.finalize("release-next", commit_character="b")
        self.fixture.seed_prior(prior)
        runtime = WindowsServiceRuntime(
            root=self.fixture.root, service_name="QuantResearchHub",
            base_url="http://127.0.0.1:8765", listen_host="0.0.0.0", port=8765,
            critical_paths=("/login",), writer_authority="D-active",
            service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            application_source_relative_path="runtime_contract/code/src",
            archive_root_relative_path="reference/archive", var_root_relative_path="runtime",
            migration_root_relative_path="runtime_contract/migrations/platform",
            access_password_digest_path="state/viewer_access_password.digest",
            session_key_path="state/viewer_secret.key", comment_database_path="state/comments.sqlite3",
            workspace_database_path="state/research_workspace.sqlite3",
        )
        starts = []

        def service(_runtime, action, *, allow_failure=False, start_authorization=None):
            if action == "start":
                starts.append(start_authorization)
            return True

        with mock.patch.object(
            WindowsServiceRuntime, "_service", autospec=True, side_effect=service
        ):
            with self.assertRaises(DeploymentFailed):
                self.fixture.controller.activate(
                    candidate_release_id="release-next",
                    deployment_attempt_id="runtime-start-auth",
                    start_release=runtime.start_release,
                    stop_release=runtime.stop_release,
                    post_activation_probe=lambda _path, _active: {
                        "health": False, "critical_functions": True, "writer_fence": True,
                    },
                )
        self.assertEqual([], starts)

    def test_exact_transient_start_consumes_live_v4_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            persistence = LocalDeploymentPersistence.for_test_only(
                Path(temporary).resolve(), allow_posix_test_only=True
            )
            candidate = local_release("release-exact-r1", b"candidate", "a")
            first = local_journal(
                None,
                candidate,
                operation="bootstrap_first_pair",
                attempt="exact-start-attempt",
                nonce="exact-start-deployment-nonce",
            )
            history = local_history_to(first, "candidate_start_authorized")
            lock = persistence.global_lock()
            lock.acquire()
            workspace = None
            try:
                for revision in history:
                    persistence.journals.append(revision, lock=lock)
                workspace = persistence.bind_attempt_workspace(
                    lock,
                    "exact-start-attempt",
                    "exact-start-deployment-nonce",
                )
                authorization = (
                    persistence.lock_exact_transient_start_authorization(
                        lock, workspace, "baseline"
                    )
                )
                runtime = WindowsServiceRuntime(
                    root=Path(temporary).resolve(),
                    service_name="QuantResearchHub",
                    base_url="http://127.0.0.1:8765",
                    listen_host="0.0.0.0",
                    port=8765,
                    critical_paths=("/login",),
                    writer_authority="D-active",
                    service_entry_relative_path=(
                        "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py"
                    ),
                    application_source_relative_path="runtime_contract/code/src",
                    archive_root_relative_path="reference/archive",
                    var_root_relative_path="runtime",
                    migration_root_relative_path=(
                        "runtime_contract/migrations/platform"
                    ),
                    access_password_digest_path=(
                        "state/viewer_access_password.digest"
                    ),
                    session_key_path="state/viewer_secret.key",
                    comment_database_path="state/comments.sqlite3",
                    workspace_database_path="state/research_workspace.sqlite3",
                )
                calls: list[tuple[str, object, object]] = []

                def service(
                    _runtime,
                    action,
                    *,
                    allow_failure=False,
                    start_authorization=None,
                    exact_start_arguments=None,
                ):
                    calls.append(
                        (action, start_authorization, exact_start_arguments)
                    )
                    return True

                with mock.patch.object(
                    WindowsServiceRuntime,
                    "_service",
                    autospec=True,
                    side_effect=service,
                ):
                    self.assertTrue(runtime.start_exact_transient(authorization))
                self.assertEqual("stop", calls[0][0])
                self.assertEqual("start", calls[1][0])
                self.assertIsNone(calls[1][1])
                exact_arguments = calls[1][2]
                self.assertIsInstance(exact_arguments, tuple)
                self.assertEqual("exact-runtime", exact_arguments[0])
                self.assertIn("exact-start-attempt", exact_arguments)
                self.assertNotIn("pending-activation", exact_arguments)
            finally:
                if workspace is not None:
                    workspace.close()
                if lock.held:
                    lock.release()

    def setUp(self) -> None:
        self.fixture = DeploymentFixture()
        self.addCleanup(self.fixture.close)
        self.verify_root = lambda _path: self.fixture.root

    def apply(self, **arguments):
        return apply_publish(
            vm_root=self.fixture.root,
            publish_candidate_sha256=CANDIDATE_HASH,
            hooks=arguments.pop("hooks", Hooks()),
            root_verifier=self.verify_root,
            environment=ENVIRONMENT,
            **arguments,
        )

    def test_candidate_only_finalizes_and_writes_event_without_receipt_or_active_change(self) -> None:
        release = write_partial(
            self.fixture.controller,
            "release-candidate",
            {"app/main.py": b"candidate\n"},
            commit_character="c",
        )
        result = self.apply(
            release_id="release-candidate",
            release_manifest_sha256=manifest_sha256(release),
            deployment_mode="candidate_only",
        )
        self.assertEqual("candidate_validated", result["status"])
        self.assertEqual("candidate_validation_event", result["evidence_type"])
        self.assertFalse(self.fixture.controller.layout.active.exists())
        self.assertEqual([], list(self.fixture.controller.layout.audit_receipts.glob("*.json")))
        event = read_json(
            self.fixture.controller.layout.audit_events / f"{result['evidence_id']}.json"
        )
        self.assertEqual("evidence_only", event["authority"])
        self.assertEqual("candidate_validation_completed", event["kind"])
        self.assertFalse(event["fields"]["receipt_created"])
        self.assertTrue(event["fields"]["probe_evidence"]["cleaned"])
        self.assertEqual(
            "loopback_isolated",
            event["fields"]["probe_evidence"]["transport"],
        )

    def test_candidate_only_rejects_failed_isolated_runtime_probe(self) -> None:
        release = write_partial(
            self.fixture.controller,
            "release-candidate-bad-runtime",
            {"app/main.py": b"candidate\n"},
            commit_character="c",
        )
        for hooks in (
            Hooks(candidate_health=False),
            Hooks(candidate_browser=False),
            Hooks(candidate_api=False),
            Hooks(candidate_resource=False),
        ):
            with self.subTest(hooks=hooks), self.assertRaisesRegex(
                CandidateValidationError, "isolated candidate probe"
            ):
                self.apply(
                    release_id="release-candidate-bad-runtime",
                    release_manifest_sha256=manifest_sha256(release),
                    deployment_mode="candidate_only",
                    hooks=hooks,
                )
        self.assertFalse(self.fixture.controller.layout.active.exists())
        self.assertEqual([], list(self.fixture.controller.layout.audit_receipts.glob("*.json")))
        self.assertEqual([], list(
            self.fixture.controller.layout.audit_events.glob(
                "candidate_validation_completed-*.json"
            )
        ))

    def test_exact_v2_candidate_only_probes_incoming_without_finalizing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            persistence = LocalDeploymentPersistence.for_test_only(root)
            manifest = local_release(
                "release-v2-candidate",
                b"candidate-v2",
                "a",
                include_migrations=True,
            )
            partial = (
                persistence.layout.incoming
                / "release-v2-candidate.partial"
            )
            for item in manifest["inventory"]["files"]:
                relative = str(item["path"])
                target = partial.joinpath(*relative.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(
                    b"candidate-v2"
                    if relative == "app/payload.bin"
                    else local_migration_bytes(
                        "release-v2-candidate", relative
                    )
                )
            (partial / "release_manifest.json").write_bytes(
                local_identity.canonical_bytes(manifest)
            )
            runtime = replace(
                windows_runtime(root),
                allow_test_root=True,
            )
            manifest_hash = local_identity.identity_sha256(manifest)
            (
                persistence.layout.control / "deployment_runtime.json"
            ).write_text("{}\n", encoding="utf-8")
            resolved_release, _active, resolved_manifest, _runtime = (
                resolve_context(
                    root,
                    expected_release_id="release-v2-candidate",
                    expected_manifest_sha256=manifest_hash,
                    allow_test_root=True,
                    candidate_probe=True,
                    candidate_release_root=partial,
                )
            )
            self.assertEqual(partial.resolve(), resolved_release)
            self.assertEqual(manifest, resolved_manifest)
            probe = {
                "schema_version": "qrh-candidate-probe-evidence/v1",
                "release_id": "release-v2-candidate",
                "manifest_sha256": manifest_hash,
                "snapshot_id": manifest["content"]["snapshot_id"],
                "transport": "loopback_isolated",
                "writer_authority": "candidate-checkpoint-isolated",
                "health": True,
                "browser": True,
                "api": True,
                "resource": True,
                "state_isolated": True,
                "active_unchanged": True,
                "cleaned": True,
            }
            with mock.patch.object(
                WindowsServiceRuntime,
                "candidate_probe",
                autospec=True,
                return_value=probe,
            ) as candidate_probe:
                result = apply_publish(
                    vm_root=root,
                    release_id="release-v2-candidate",
                    release_manifest_sha256=manifest_hash,
                    publish_candidate_sha256=CANDIDATE_HASH,
                    deployment_mode="candidate_only",
                    hooks=runtime,
                    root_verifier=lambda _path: root,
                    environment=ENVIRONMENT,
                )
            self.assertEqual("candidate_validated", result["status"])
            candidate_probe.assert_called_once()
            self.assertEqual(partial, candidate_probe.call_args.args[1])
            self.assertTrue(partial.is_dir())
            self.assertFalse(
                (persistence.layout.releases / "release-v2-candidate").exists()
            )
            self.assertIsNone(persistence.read_active_release())
            self.assertEqual((), persistence.read_local_receipts())
            event = persistence.layout.events / f"{result['evidence_id']}.json"
            self.assertTrue(event.is_file())

    def test_activation_returns_local_pair_receipt(self) -> None:
        prior = self.fixture.finalize("release-prior", commit_character="a")
        candidate = self.fixture.finalize("release-next", commit_character="b")
        self.fixture.seed_prior(prior)
        hooks = Hooks()
        result = self.apply(
            release_id="release-next",
            release_manifest_sha256=manifest_sha256(candidate),
            deployment_mode="activate",
            deployment_attempt_id="publish-activate",
            hooks=hooks,
        )
        self.assertEqual("activated", result["status"])
        self.assertEqual("activation_receipt", result["evidence_type"])
        receipt = read_json(
            self.fixture.controller.layout.audit_receipts / f"{result['evidence_id']}.json"
        )
        self.assertEqual("activation", receipt["receipt_type"])
        active, _ = self.fixture.controller.read_active()
        self.assertEqual("release-next", active["release_id"])

    def test_failed_probe_only_creates_failure_receipt_and_rolls_back(self) -> None:
        prior = self.fixture.finalize("release-prior", commit_character="a")
        candidate = self.fixture.finalize("release-next", commit_character="b")
        self.fixture.seed_prior(prior)
        with self.assertRaises(DeploymentFailed) as caught:
            self.apply(
                release_id="release-next",
                release_manifest_sha256=manifest_sha256(candidate),
                deployment_mode="activate",
                deployment_attempt_id="publish-fail",
                hooks=Hooks(health=False),
            )
        failure = read_json(
            self.fixture.controller.layout.audit_receipts
            / f"{caught.exception.result.receipt_id}.json"
        )
        self.assertEqual("failure", failure["receipt_type"])
        receipts = [
            read_json(path)["receipt_type"]
            for path in self.fixture.controller.layout.audit_receipts.glob("*.json")
        ]
        self.assertEqual(["failure"], receipts)
        active, _ = self.fixture.controller.read_active()
        self.assertEqual("release-prior", active["release_id"])

    def test_wrong_expected_manifest_fails_before_switch_or_terminal_receipt(self) -> None:
        prior = self.fixture.finalize("release-prior", commit_character="a")
        candidate = self.fixture.finalize("release-next", commit_character="b")
        self.fixture.seed_prior(prior)
        with self.assertRaisesRegex(CandidateValidationError, "manifest hash differs"):
            self.apply(
                release_id="release-next",
                release_manifest_sha256="8" * 64,
                deployment_mode="activate",
                deployment_attempt_id="publish-wrong-hash",
            )
        active, _ = self.fixture.controller.read_active()
        self.assertEqual("release-prior", active["release_id"])
        receipts = [
            read_json(path)["receipt_type"]
            for path in self.fixture.controller.layout.audit_receipts.glob("*.json")
        ]
        self.assertEqual([], receipts)

    def test_candidate_only_rejects_activation_authorization(self) -> None:
        release = self.fixture.finalize("release-candidate", commit_character="c")
        with self.assertRaisesRegex(VMDeployCLIError, "cannot carry"):
            self.apply(
                release_id="release-candidate",
                release_manifest_sha256=manifest_sha256(release),
                deployment_mode="candidate_only",
                deployment_attempt_id="attempt-not-allowed",
            )

    def test_runtime_environment_rejects_c_temp_or_bytecode(self) -> None:
        with self.assertRaises(VMDeployCLIError):
            verify_runtime_environment(
                Path(r"D:\quant\quant_platform"),
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "TEMP": r"C:\Temp",
                    "TMP": r"D:\quant\quant_platform\tmp",
                },
            )
        with self.assertRaisesRegex(VMDeployCLIError, "PYTHONPYCACHEPREFIX"):
            verify_runtime_environment(
                Path(r"D:\quant\quant_platform"),
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "TEMP": r"D:\quant\quant_platform\tmp\deploy",
                    "TMP": r"D:\quant\quant_platform\tmp\deploy",
                    "PYTHONPYCACHEPREFIX": r"C:\Temp\pycache",
                },
            )

    def test_runtime_config_requires_the_exact_closed_production_write_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            control = root / "control"
            control.mkdir()
            value = {
                "schema_version": "qrh-vm-deploy-runtime/v1",
                "service_name": "QuantResearchHub",
                "base_url": "http://127.0.0.1:8765",
                "listen_host": "0.0.0.0",
                "port": 8765,
                "critical_paths": [
                    "/login", "/api/v1/research", "/api/v1/dashboard"
                ],
                "writer_authority": "D-active",
                "service_entry_relative_path": "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
                "application_source_relative_path": "runtime_contract/code/src",
                "archive_root_relative_path": "reference/archive",
                "var_root_relative_path": "runtime",
                "migration_root_relative_path": "runtime_contract/migrations/platform",
                "access_password_digest_path": "state/viewer_access_password.digest",
                "session_key_path": "state/viewer_secret.key",
                "comment_database_path": "state/comments.sqlite3",
                "workspace_database_path": "state/research_workspace.sqlite3",
                "write_paths": list(declared_production_vm_write_set().values()),
            }
            path = control / "deployment_runtime.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            runtime = WindowsServiceRuntime.load(root)
            self.assertEqual(set(value["write_paths"]), {str(item) for item in runtime.write_paths})

            for replacement in (
                r"C:\temp",
                r"D:\quant",
                r"D:\quant\quant_platform_sibling\logs",
                r"D:\quant\quant_platform\reference",
            ):
                invalid = json.loads(json.dumps(value))
                invalid["write_paths"][-1] = replacement
                path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.subTest(replacement=replacement), self.assertRaises(
                    VMDeployCLIError
                ):
                    WindowsServiceRuntime.load(root)

            invalid = json.loads(json.dumps(value))
            invalid["writer_authority"] = "C-legacy"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(VMDeployCLIError, "writer authority"):
                WindowsServiceRuntime.load(root)

    def test_v39_state_compatibility_real_shape_and_closed_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            state.mkdir()
            for name, version in (
                ("comments.sqlite3", 2),
                ("research_workspace.sqlite3", 3),
            ):
                with closing(sqlite3.connect(state / name)) as connection:
                    connection.execute(f"PRAGMA user_version={version}")
                    connection.commit()
            runtime = WindowsServiceRuntime(
                root=root,
                service_name="QuantResearchHub",
                base_url="http://127.0.0.1:8765",
                listen_host="0.0.0.0",
                port=8765,
                critical_paths=("/",),
                writer_authority="D-active",
                service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
                application_source_relative_path="runtime_contract/code/src",
                archive_root_relative_path="reference/archive",
                var_root_relative_path="runtime",
                migration_root_relative_path="runtime_contract/migrations/platform",
                access_password_digest_path="state/viewer_access_password.digest",
                session_key_path="state/viewer_secret.key",
                comment_database_path="state/comments.sqlite3",
                workspace_database_path="state/research_workspace.sqlite3",
            )
            real_v39_shape = {
                "state": {
                    "compatibility": {
                        "comments": {"read": [1, 2], "write": [1, 2]},
                        "research_workspace": {
                            "read": [1, 2, 3],
                            "write": [1, 2, 3],
                        },
                        "rollback_policy": "expand_only_no_down_migration",
                    }
                }
            }
            self.assertTrue(runtime.state_compatibility_probe(real_v39_shape))
            self.assertFalse(any(state.glob("*.sqlite3-wal")))
            self.assertFalse(any(state.glob("*.sqlite3-shm")))

            wrong_policy = json.loads(json.dumps(real_v39_shape))
            wrong_policy["state"]["compatibility"]["rollback_policy"] = "down_migrate"
            self.assertFalse(runtime.state_compatibility_probe(wrong_policy))
            unknown = json.loads(json.dumps(real_v39_shape))
            unknown["state"]["compatibility"]["workspace"] = unknown["state"][
                "compatibility"
            ]["research_workspace"]
            self.assertFalse(runtime.state_compatibility_probe(unknown))
            missing = json.loads(json.dumps(real_v39_shape))
            del missing["state"]["compatibility"]["research_workspace"]
            self.assertFalse(runtime.state_compatibility_probe(missing))

    def test_online_copy_allows_normal_wal_writer_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "comments.sqlite3"
            destination = root / "candidate.sqlite3"
            with closing(sqlite3.connect(source)) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("CREATE TABLE comment (id INTEGER PRIMARY KEY, body TEXT)")
                connection.execute("INSERT INTO comment(body) VALUES ('before')")
                connection.commit()
                before = WindowsServiceRuntime._sqlite_source_identity(source)
                self.assertIn("-wal", {row[0] for row in before})
                with mock.patch.object(
                    WindowsServiceRuntime,
                    "_sqlite_source_identity",
                    return_value=before,
                ) as identity:
                    WindowsServiceRuntime._online_copy(source, destination)
                # A live WAL source is protected by SQLite's snapshot backup,
                # not by requiring all production bytes to stop changing.
                identity.assert_called_once_with(source)
            with closing(sqlite3.connect(destination)) as copied:
                self.assertEqual(
                    [("before",)], copied.execute("SELECT body FROM comment").fetchall()
                )
        with self.assertRaises(VMDeployCLIError):
            verify_runtime_environment(
                Path(r"D:\quant\quant_platform"),
                {
                    "PYTHONDONTWRITEBYTECODE": "0",
                    "TEMP": r"D:\quant\quant_platform\tmp",
                    "TMP": r"D:\quant\quant_platform\tmp",
                },
            )


if __name__ == "__main__":
    unittest.main()
