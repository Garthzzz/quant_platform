from __future__ import annotations

from copy import deepcopy
from contextlib import closing
import hashlib
from pathlib import Path
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.collaboration.comment_store import initialize_comment_store
from quant_hub.ops import local_release_identity as identity
from quant_hub.ops.local_deployment_persistence import (
    LocalDeploymentPersistence,
    RetentionPlanningError,
)
from quant_hub.ops.local_deployment_runtime import (
    ProductionWindowsDeploymentRuntime,
    TestOnlyWindowsDeploymentRuntimeAdapter as RuntimeAdapter,
)
from quant_hub.ops.local_exact_deployment_controller import (
    ExactDeploymentControllerError,
    ProductionExactDeploymentController,
)
from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_up

from tests.test_local_deployment_persistence import (
    active,
    binding,
    bootstrap_receipt,
    history_to,
    journal,
    migration_bytes,
    release,
    release_cleanup_target,
    transition_receipt,
)


class ExactDeploymentControllerTests(unittest.TestCase):
    @staticmethod
    def _materialize(
        directory: Path,
        manifest: dict[str, object],
        payload: bytes,
    ) -> None:
        for item in manifest["inventory"]["files"]:  # type: ignore[index]
            relative = str(item["path"])
            target = directory.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(
                payload
                if relative == "app/payload.bin"
                else migration_bytes(str(manifest["release_id"]), relative)
            )
        (directory / "release_manifest.json").write_bytes(
            identity.canonical_bytes(manifest)
        )

    def test_object_new_fake_controller_is_rejected_before_any_dependency_use(self) -> None:
        fake = object.__new__(ProductionExactDeploymentController)
        for operation in ("bootstrap", "activate"):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                ExactDeploymentControllerError, "not a live factory instance"
            ):
                if operation == "bootstrap":
                    fake.bootstrap_first_pair(
                        release_id="release-r0",
                        expected_manifest_sha256="a" * 64,
                        attempt_id="bootstrap-r0",
                    )
                else:
                    fake.activate_successor(
                        release_id="release-r1",
                        expected_manifest_sha256="b" * 64,
                        attempt_id="activate-r1",
                    )

    def test_bootstrap_preflight_expands_legacy_comments_before_strict_seal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            persistence = LocalDeploymentPersistence.for_test_only(
                root, allow_posix_test_only=(os.name != "nt")
            )
            comments = persistence.layout.state / "comments.sqlite3"
            initialize_comment_store(comments)
            with closing(sqlite3.connect(comments, isolation_level=None)) as connection:
                connection.execute("DROP TABLE comment_target")
                connection.execute("DROP TABLE comment_target_schema")
            migration_root = (
                Path(__file__).resolve().parents[1]
                / "migrations"
                / "research_workspace"
            )
            workspace_database = (
                persistence.layout.state / "research_workspace.sqlite3"
            )
            connection = connect_database(workspace_database)
            try:
                self.assertEqual([1, 2, 3], migrate_up(connection, migration_root))
            finally:
                connection.close()
            runtime = RuntimeAdapter.for_test_only(
                root,
                migration_root=migration_root,
                allow_posix_test_only=(os.name != "nt"),
            )
            r0 = release(
                "release-bootstrap-r0", b"baseline", "8", include_migrations=True
            )
            self._materialize(
                persistence.layout.incoming / "release-bootstrap-r0.partial",
                r0,
                b"baseline",
            )
            controller = ProductionExactDeploymentController.for_test_only(
                persistence=persistence,
                service=object(),
            )
            lock = persistence.global_lock()
            workspace = None
            lock.acquire()
            try:
                candidate = persistence.inspect_exact_incoming_candidate(
                    lock=lock,
                    release_id="release-bootstrap-r0",
                    expected_manifest_sha256=identity.identity_sha256(r0),
                )
                intent, compatibility = controller._initial_bootstrap_journal(
                    lock=lock,
                    attempt="bootstrap-legacy-comments",
                    nonce="bootstrap-legacy-comments-nonce",
                    candidate_manifest=candidate,
                )
                latest = persistence.journals.append(intent, lock=lock)
                persistence.finalize_exact_incoming_candidate(
                    lock=lock,
                    release_id="release-bootstrap-r0",
                    expected_manifest_sha256=identity.identity_sha256(r0),
                )
                workspace = persistence.bind_attempt_workspace(
                    lock,
                    "bootstrap-legacy-comments",
                    "bootstrap-legacy-comments-nonce",
                )
                with patch.object(
                    ProductionWindowsDeploymentRuntime,
                    "load_exact_d",
                    return_value=runtime,
                ):
                    latest = controller._append_preflight_and_state(
                        lock=lock,
                        workspace=workspace,
                        latest=latest,
                        compatibility_documents=compatibility,
                        candidate_manifest=candidate,
                    )
                self.assertEqual("state_expand_applied", latest["phase"])
                self.assertEqual(
                    ["comments", "research_workspace"],
                    [item["name"] for item in latest["database_seals"]],
                )
                with closing(sqlite3.connect(comments)) as connection:
                    self.assertEqual(
                        [(3,)],
                        connection.execute(
                            "SELECT version FROM comment_target_schema"
                        ).fetchall(),
                    )
            finally:
                if workspace is not None and workspace._state != "closed":
                    workspace.close()
                if lock.held:
                    lock.release()

    def test_rollback_intent_and_success_derive_only_the_retained_pair(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            persistence = LocalDeploymentPersistence.for_test_only(
                root, allow_posix_test_only=True
            )
            prior = release(
                "release-prior", b"prior", "8", include_migrations=True
            )
            current = release(
                "release-current", b"current", "9", include_migrations=True
            )
            for manifest, payload in (
                (prior, b"prior"),
                (current, b"current"),
            ):
                self._materialize(
                    persistence.layout.releases / str(manifest["release_id"]),
                    manifest,
                    payload,
                )
            current_receipt = transition_receipt(
                current, prior, attempt="activate-current"
            )
            controller = object.__new__(ProductionExactDeploymentController)
            object.__setattr__(controller, "_persistence", persistence)
            object.__setattr__(controller, "_service", object())
            object.__setattr__(controller, "_sealed", True)
            lock = persistence.global_lock()
            lock.acquire()
            workspace = None
            try:
                persistence.cas_active_release(
                    lock=lock, expected=None, desired=active(current)
                )
                original_binding = binding(current, prior)
                persistence.cas_local_prior_binding(
                    lock=lock,
                    expected=None,
                    desired=original_binding,
                )
                persistence.commit_local_receipt(
                    lock=lock, receipt=current_receipt
                )
                with patch(
                    "quant_hub.ops.local_exact_deployment_controller._now",
                    return_value="2026-08-26T10:02:00+08:00",
                ):
                    intent, documents, candidate = (
                        controller._initial_rollback_journal(
                            lock=lock,
                            attempt="rollback-current",
                            nonce="rollback-current-nonce",
                        )
                    )
                self.assertEqual("rollback", intent["operation"])
                self.assertEqual(
                    intent["original_pair"]["prior"], intent["candidate"]
                )
                self.assertEqual(
                    {
                        "active": intent["candidate"],
                        "prior": intent["original_pair"]["active"],
                    },
                    intent["target_pair"],
                )
                self.assertEqual([], intent["cleanup_targets"])
                self.assertIsNone(
                    intent["reserved_receipt_ids"]["activation"]
                )
                self.assertEqual(
                    "rollback-rollback-current",
                    intent["reserved_receipt_ids"]["rollback"],
                )
                self.assertEqual(prior, candidate)
                self.assertEqual(
                    ["rollback", "rollback"],
                    [document["operation"] for document in documents],
                )
                finish_intent = journal(
                    current,
                    current,
                    original_prior=prior,
                    operation="rollback",
                    attempt="rollback-current",
                    nonce="rollback-current-nonce",
                )
                history = history_to(
                    finish_intent, "binding_cas_committed"
                )
                for revision in history:
                    persistence.journals.append(revision, lock=lock)
                persistence.cas_active_release(
                    lock=lock,
                    expected=active(current),
                    desired=active(prior),
                )
                persistence.cas_local_prior_binding(
                    lock=lock,
                    expected=original_binding,
                    desired=finish_intent["binding_cas"]["desired_binding"],
                )
                workspace = persistence.bind_attempt_workspace(
                    lock,
                    "rollback-current",
                    "rollback-current-nonce",
                )
                closed = controller._finish_success(
                    lock=lock, workspace=workspace
                )
                rollback_receipts = [
                    record.value
                    for record in persistence.read_local_receipts()
                    if record.value["schema_version"]
                    == identity.ROLLBACK_RECEIPT_SCHEMA
                ]
                self.assertEqual(1, len(rollback_receipts))
                self.assertEqual(
                    "rollback_to_prior", rollback_receipts[0]["operation"]
                )
                self.assertEqual("rolled_back", rollback_receipts[0]["result"]["status"])
                self.assertEqual(
                    "rollback", closed["terminal_receipt"]["kind"]
                )
                self.assertEqual(
                    ["release-current", "release-prior"],
                    sorted(
                        item.release_id
                        for item in persistence.release_inventory()
                    ),
                )
            finally:
                if workspace is not None and workspace._state != "closed":
                    workspace.close()
                if lock.held:
                    lock.release()

    def test_bootstrap_successor_intent_precedes_exact_candidate_finalize(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            persistence = LocalDeploymentPersistence.for_test_only(
                root, allow_posix_test_only=True
            )
            r0_payload = b"baseline"
            r1_payload = b"successor"
            r0 = release(
                "release-r0", r0_payload, "8", include_migrations=True
            )
            r1 = release(
                "release-r1", r1_payload, "9", include_migrations=True
            )
            self._materialize(
                persistence.layout.releases / "release-r0",
                r0,
                r0_payload,
            )
            self._materialize(
                persistence.layout.incoming / "release-r1.partial",
                r1,
                r1_payload,
            )
            bootstrap = journal(
                None,
                r0,
                operation="bootstrap_first_pair",
                attempt="bootstrap-r0",
                nonce="bootstrap-r0-nonce",
            )
            receipt = bootstrap_receipt(r0, attempt="bootstrap-r0")
            lock = persistence.global_lock()
            lock.acquire()
            try:
                for revision in history_to(
                    bootstrap,
                    "terminal_receipt_committed",
                    receipt=receipt,
                ):
                    persistence.journals.append(revision, lock=lock)
                persistence.commit_local_receipt(lock=lock, receipt=receipt)
                persistence.cas_active_release(
                    lock=lock,
                    expected=None,
                    desired=active(r0),
                )
                bootstrap_proof = (
                    persistence.inspect_closed_bootstrap_baseline(
                        lock=lock,
                        release_id="release-r0",
                        manifest_sha256=identity.identity_sha256(r0),
                    )
                )
                self.assertIsNotNone(bootstrap_proof)
                self.assertEqual(
                    "closed_non_ingress", bootstrap_proof["status"]
                )
                steady = persistence.bind_steady_boot_workspace(lock)
                try:
                    with self.assertRaisesRegex(
                        RetentionPlanningError, "non-null R1/R0 binding"
                    ):
                        persistence.lock_steady_pair_static_facts(lock, steady)
                finally:
                    steady.close()

                candidate_hash = identity.identity_sha256(r1)
                candidate = persistence.inspect_exact_incoming_candidate(
                    lock=lock,
                    release_id="release-r1",
                    expected_manifest_sha256=candidate_hash,
                )
                controller = object.__new__(ProductionExactDeploymentController)
                object.__setattr__(controller, "_persistence", persistence)
                object.__setattr__(controller, "_service", object())
                object.__setattr__(controller, "_sealed", True)
                intent, compatibility = controller._initial_ordinary_journal(
                    lock=lock,
                    attempt="activate-r1",
                    nonce="activate-r1-nonce",
                    candidate_manifest=candidate,
                )
                self.assertIsNone(
                    intent["binding_cas"]["expected_binding_sha256"]
                )
                self.assertEqual([], intent["cleanup_targets"])
                self.assertEqual(2, len(compatibility))
                persistence.journals.append(intent, lock=lock)
                finalized = persistence.finalize_exact_incoming_candidate(
                    lock=lock,
                    release_id="release-r1",
                    expected_manifest_sha256=candidate_hash,
                )
                self.assertEqual(candidate, finalized)
                self.assertFalse(
                    (persistence.layout.incoming / "release-r1.partial").exists()
                )
                self.assertTrue(
                    (persistence.layout.releases / "release-r1").is_dir()
                )
                self.assertEqual(2, len(persistence.release_inventory()))
            finally:
                if lock.held:
                    lock.release()

    def test_bootstrap_intent_and_pointer_cas_are_durable_and_replayable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            persistence = LocalDeploymentPersistence.for_test_only(
                root, allow_posix_test_only=True
            )
            payload = b"v39-r0"
            r0 = release(
                "release-v39-r0", payload, "8", include_migrations=True
            )
            self._materialize(
                persistence.layout.incoming / "release-v39-r0.partial",
                r0,
                payload,
            )
            controller = object.__new__(ProductionExactDeploymentController)
            object.__setattr__(controller, "_persistence", persistence)
            object.__setattr__(controller, "_service", object())
            object.__setattr__(controller, "_sealed", True)
            lock = persistence.global_lock()
            lock.acquire()
            workspace = None
            try:
                candidate_hash = identity.identity_sha256(r0)
                candidate = persistence.inspect_exact_incoming_candidate(
                    lock=lock,
                    release_id="release-v39-r0",
                    expected_manifest_sha256=candidate_hash,
                )
                with patch(
                    "quant_hub.ops.local_exact_deployment_controller._now",
                    return_value="2026-08-26T10:00:00+08:00",
                ):
                    intent, documents = controller._initial_bootstrap_journal(
                        lock=lock,
                        attempt="bootstrap-v39-r0",
                        nonce="bootstrap-v39-r0-nonce",
                        candidate_manifest=candidate,
                    )
                self.assertIsNone(intent["original_pair"])
                self.assertEqual(2, len(documents))
                persistence.journals.append(intent, lock=lock)
                persistence.finalize_exact_incoming_candidate(
                    lock=lock,
                    release_id="release-v39-r0",
                    expected_manifest_sha256=candidate_hash,
                )
                root_revision = deepcopy(intent)
                root_revision["revision"] = 1
                root_revision["phase"] = "root_preflight_verified"
                root_revision["previous_journal_sha256"] = intent[
                    "journal_sha256"
                ]
                root_revision["timestamps"]["updated_at"] = (
                    "2026-08-26T10:01:00+08:00"
                )
                root_revision["evidence_hashes"][
                    "root_preflight_sha256"
                ] = "a" * 64
                root_revision.pop("journal_sha256")
                root_revision["journal_sha256"] = identity.identity_sha256(
                    root_revision
                )
                persistence.journals.append(root_revision, lock=lock)
                state_revision = deepcopy(root_revision)
                state_revision["revision"] = 2
                state_revision["phase"] = "state_expand_applied"
                state_revision["previous_journal_sha256"] = root_revision[
                    "journal_sha256"
                ]
                state_revision["timestamps"]["updated_at"] = (
                    "2026-08-26T10:02:00+08:00"
                )
                state_revision["database_seals"] = [
                    {
                        "name": document["database_name"],
                        "seal_sha256": (
                            "b" * 64
                            if document["database_name"] == "comments"
                            else "c" * 64
                        ),
                        "compatibility_manifest_sha256": document[
                            "evidence_sha256"
                        ],
                    }
                    for document in documents
                ]
                state_revision["evidence_hashes"][
                    "state_compatibility_sha256"
                ] = state_revision["state_plan"]["compatibility_sha256"]
                state_revision.pop("journal_sha256")
                state_revision["journal_sha256"] = identity.identity_sha256(
                    state_revision
                )
                persistence.journals.append(state_revision, lock=lock)
                workspace = persistence.bind_attempt_workspace(
                    lock,
                    "bootstrap-v39-r0",
                    "bootstrap-v39-r0-nonce",
                )
                first = persistence.commit_bootstrap_pointer_cas(
                    lock=lock, workspace=workspace
                )
                self.assertIn(first.outcome, {"swapped", "already_desired"})
                latest = persistence.journals.replay("bootstrap-v39-r0")[-1]
                self.assertEqual("pointer_cas_committed", latest["phase"])
                self.assertEqual(active(r0), persistence.read_active_release().value)
                self.assertIsNone(persistence.read_local_prior_binding())
                replay = persistence.commit_bootstrap_pointer_cas(
                    lock=lock, workspace=workspace
                )
                self.assertEqual("already_desired", replay.outcome)
                for filename in (
                    "comments.sqlite3",
                    "research_workspace.sqlite3",
                ):
                    (persistence.layout.state / filename).write_bytes(
                        ("bootstrap-state-" + filename).encode("ascii")
                    )

                class BootstrapFailureService:
                    @staticmethod
                    def stop_exact_transient():
                        return None

                    @staticmethod
                    def observe_bootstrap_boundary():
                        ingress = {
                            "scm_state": "STOPPED",
                            "listen_host": "0.0.0.0",
                            "port": 8765,
                            "listener_pids": [],
                        }
                        legacy = {
                            "legacy_roots": [
                                r"C:\quant_platform",
                                r"C:\quant_platform_data",
                            ],
                            "process_pids": [],
                            "status": "fenced",
                        }
                        evidence = {
                            "schema_version": (
                                "qrh-bootstrap-boundary-observation/v1"
                            ),
                            "ingress": ingress,
                            "legacy_c_writer": legacy,
                            "ingress_closed_sha256": (
                                identity.identity_sha256(ingress)
                            ),
                            "legacy_c_writer_fence_sha256": (
                                identity.identity_sha256(legacy)
                            ),
                        }
                        evidence["evidence_sha256"] = (
                            identity.identity_sha256(evidence)
                        )
                        return evidence

                object.__setattr__(
                    controller, "_service", BootstrapFailureService()
                )
                failure_authorization = (
                    persistence.commit_bootstrap_failure_authorization(
                        lock=lock, workspace=workspace
                    )
                )
                advanced_state = {}
                for filename in (
                    "comments.sqlite3",
                    "research_workspace.sqlite3",
                ):
                    path = persistence.layout.state / filename
                    advanced_state[filename] = path.read_bytes() + b"-legacy-advanced"
                    path.write_bytes(advanced_state[filename])
                workspace.close()
                workspace = None
                lock.release()

                def fresh(service):
                    return ProductionExactDeploymentController.for_test_only(
                        persistence=persistence,
                        service=service,
                    )

                class CrashAfterStop(BootstrapFailureService):
                    @staticmethod
                    def stop_exact_transient():
                        raise RuntimeError("crash after bootstrap stop")

                with patch.object(
                    ProductionExactDeploymentController,
                    "_qualify_and_stop",
                    side_effect=AssertionError("bootstrap forward path re-entered"),
                ) as qualify:
                    with self.assertRaisesRegex(
                        RuntimeError, "crash after bootstrap stop"
                    ):
                        fresh(CrashAfterStop()).bootstrap_first_pair(
                            release_id="release-v39-r0",
                            expected_manifest_sha256=candidate_hash,
                            attempt_id="bootstrap-v39-r0",
                        )
                    qualify.assert_not_called()
                self.assertEqual(
                    active(r0), persistence.read_active_release().value
                )

                class CrashAfterRestore(BootstrapFailureService):
                    @staticmethod
                    def observe_bootstrap_boundary():
                        raise RuntimeError("crash after bootstrap restore")

                with patch.object(
                    ProductionExactDeploymentController,
                    "_qualify_and_stop",
                    side_effect=AssertionError("bootstrap forward path re-entered"),
                ) as qualify:
                    with self.assertRaisesRegex(
                        RuntimeError, "crash after bootstrap restore"
                    ):
                        fresh(CrashAfterRestore()).bootstrap_first_pair(
                            release_id="release-v39-r0",
                            expected_manifest_sha256=candidate_hash,
                            attempt_id="bootstrap-v39-r0",
                        )
                    qualify.assert_not_called()
                self.assertIsNone(persistence.read_active_release())
                self.assertIsNone(persistence.read_local_prior_binding())

                class AdvanceDuringBoundary(BootstrapFailureService):
                    @staticmethod
                    def observe_bootstrap_boundary():
                        path = persistence.layout.state / "comments.sqlite3"
                        advanced_state["comments.sqlite3"] += b"-during-fence"
                        path.write_bytes(advanced_state["comments.sqlite3"])
                        return BootstrapFailureService.observe_bootstrap_boundary()

                with patch.object(
                    ProductionExactDeploymentController,
                    "_qualify_and_stop",
                    side_effect=AssertionError("bootstrap forward path re-entered"),
                ) as qualify:
                    with self.assertRaisesRegex(
                        ExactDeploymentControllerError,
                        "drifted around boundary observation",
                    ):
                        fresh(AdvanceDuringBoundary()).bootstrap_first_pair(
                            release_id="release-v39-r0",
                            expected_manifest_sha256=candidate_hash,
                            attempt_id="bootstrap-v39-r0",
                        )
                    qualify.assert_not_called()

                with patch.object(
                    ProductionExactDeploymentController,
                    "_qualify_and_stop",
                    side_effect=AssertionError("bootstrap forward path re-entered"),
                ) as qualify, patch.object(
                    ProductionExactDeploymentController,
                    "_commit_bootstrap_failure_terminal",
                    side_effect=RuntimeError(
                        "crash after bootstrap boundary observation"
                    ),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "crash after bootstrap boundary observation",
                    ):
                        fresh(BootstrapFailureService()).bootstrap_first_pair(
                            release_id="release-v39-r0",
                            expected_manifest_sha256=candidate_hash,
                            attempt_id="bootstrap-v39-r0",
                        )
                    qualify.assert_not_called()

                with patch.object(
                    ProductionExactDeploymentController,
                    "_qualify_and_stop",
                    side_effect=AssertionError("bootstrap forward path re-entered"),
                ) as qualify:
                    with self.assertRaisesRegex(
                        ExactDeploymentControllerError, "failure_receipt"
                    ):
                        fresh(BootstrapFailureService()).bootstrap_first_pair(
                            release_id="release-v39-r0",
                            expected_manifest_sha256=candidate_hash,
                            attempt_id="bootstrap-v39-r0",
                        )
                    qualify.assert_not_called()
                terminal = persistence.journals.replay("bootstrap-v39-r0")[-1]
                self.assertEqual("failure_receipt_committed", terminal["phase"])
                self.assertFalse(
                    (persistence.layout.releases / "release-v39-r0").exists()
                )
                for filename, expected in advanced_state.items():
                    self.assertEqual(
                        expected,
                        (persistence.layout.state / filename).read_bytes(),
                    )
                failure = [
                    record.value
                    for record in persistence.read_local_receipts()
                    if record.value["schema_version"]
                    == identity.FAILURE_RECEIPT_SCHEMA
                ]
                self.assertEqual(1, len(failure))
                self.assertEqual("bootstrap_first_pair", failure[0]["operation"])
                state_observation = failure[0]["restoration_evidence"][
                    "current_d_state_identity_observation"
                ]
                self.assertEqual(
                    "current_d_state_preserved_after_legacy_writer_fence",
                    state_observation["status"],
                )
                self.assertEqual(
                    failure_authorization["authorization_sha256"],
                    state_observation["failure_authorization_sha256"],
                )
                self.assertEqual(
                    failure_authorization["production_state_order_sha256"],
                    state_observation["authorized_state_order_sha256"],
                )
                self.assertNotEqual(
                    state_observation["authorized_state_order_sha256"],
                    state_observation["preserved_state_order_sha256"],
                )
                with patch.object(
                    ProductionExactDeploymentController,
                    "_qualify_and_stop",
                    side_effect=AssertionError("bootstrap forward path re-entered"),
                ) as qualify:
                    with self.assertRaisesRegex(
                        ExactDeploymentControllerError, "failure_receipt"
                    ):
                        fresh(BootstrapFailureService()).bootstrap_first_pair(
                            release_id="release-v39-r0",
                            expected_manifest_sha256=candidate_hash,
                            attempt_id="bootstrap-v39-r0",
                        )
                    qualify.assert_not_called()
            finally:
                if workspace is not None and workspace._state != "closed":
                    workspace.close()
                if lock.held:
                    lock.release()

    def test_cleanup_planned_removes_only_old_prior_release_closure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            persistence = LocalDeploymentPersistence.for_test_only(
                root, allow_posix_test_only=True
            )
            old = release("release-old", b"old", "7", include_migrations=True)
            r0 = release("release-r0", b"active", "8", include_migrations=True)
            r1 = release("release-r1", b"next", "9", include_migrations=True)
            for manifest, payload in (
                (old, b"old"),
                (r0, b"active"),
                (r1, b"next"),
            ):
                self._materialize(
                    persistence.layout.releases / str(manifest["release_id"]),
                    manifest,
                    payload,
                )
            target = release_cleanup_target(old)
            first = journal(
                r0,
                r1,
                original_prior=old,
                cleanup_targets=[target],
                attempt="activate-next",
                nonce="activate-next-nonce",
            )
            receipt = transition_receipt(r1, r0, attempt="activate-next")
            lock = persistence.global_lock()
            lock.acquire()
            try:
                for revision in history_to(
                    first,
                    "cleanup_planned",
                    receipt=receipt,
                ):
                    persistence.journals.append(revision, lock=lock)
                persistence.commit_local_receipt(lock=lock, receipt=receipt)
                persistence.cas_active_release(
                    lock=lock,
                    expected=None,
                    desired=active(r1),
                )
                persistence.cas_local_prior_binding(
                    lock=lock,
                    expected=None,
                    desired=binding(r1, r0),
                )
                removed = persistence.execute_retention_cleanup(
                    lock=lock,
                    receipts=[receipt],
                )
                self.assertEqual((target,), removed)
                self.assertFalse(
                    (persistence.layout.releases / "release-old").exists()
                )
                self.assertEqual(
                    ["release-r0", "release-r1"],
                    sorted(item.release_id for item in persistence.release_inventory()),
                )
            finally:
                if lock.held:
                    lock.release()

    def test_failure_restores_original_pair_and_commits_one_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            persistence = LocalDeploymentPersistence.for_test_only(
                root, allow_posix_test_only=True
            )
            r0 = release(
                "release-r0", b"baseline", "8", include_migrations=True
            )
            r1 = release(
                "release-r1", b"candidate", "9", include_migrations=True
            )
            self._materialize(
                persistence.layout.releases / "release-r0", r0, b"baseline"
            )
            self._materialize(
                persistence.layout.releases / "release-r1", r1, b"candidate"
            )
            for name in ("comments.sqlite3", "research_workspace.sqlite3"):
                (persistence.layout.state / name).write_bytes(
                    f"state-{name}".encode("ascii")
                )
            bootstrap = journal(
                None,
                r0,
                operation="bootstrap_first_pair",
                attempt="bootstrap-r0",
                nonce="bootstrap-r0-nonce",
            )
            bootstrap_done = bootstrap_receipt(r0, attempt="bootstrap-r0")
            failed = journal(
                r0,
                r1,
                attempt="activate-r1",
                nonce="activate-r1-nonce",
            )
            lock = persistence.global_lock()
            lock.acquire()
            try:
                for revision in history_to(
                    bootstrap,
                    "terminal_receipt_committed",
                    receipt=bootstrap_done,
                ):
                    persistence.journals.append(revision, lock=lock)
                persistence.commit_local_receipt(
                    lock=lock, receipt=bootstrap_done
                )
                for revision in history_to(
                    failed, "candidate_start_authorized"
                ):
                    persistence.journals.append(revision, lock=lock)
                persistence.cas_active_release(
                    lock=lock, expected=None, desired=active(r1)
                )
                workspace = persistence.bind_attempt_workspace(
                    lock, "activate-r1", "activate-r1-nonce"
                )

                class Service:
                    @staticmethod
                    def ensure_steady_exact(_release_ref):
                        raise AssertionError(
                            "bootstrap R0 must never enter ordinary steady"
                        )

                    @staticmethod
                    def stop_exact_transient():
                        return None

                    @staticmethod
                    def observe_bootstrap_boundary():
                        ingress = {
                            "scm_state": "STOPPED",
                            "listen_host": "0.0.0.0",
                            "port": 8765,
                            "listener_pids": [],
                        }
                        legacy = {
                            "legacy_roots": [
                                r"C:\quant_platform",
                                r"C:\quant_platform_data",
                            ],
                            "process_pids": [],
                            "status": "fenced",
                        }
                        evidence = {
                            "schema_version": (
                                "qrh-bootstrap-boundary-observation/v1"
                            ),
                            "ingress": ingress,
                            "legacy_c_writer": legacy,
                            "ingress_closed_sha256": (
                                identity.identity_sha256(ingress)
                            ),
                            "legacy_c_writer_fence_sha256": (
                                identity.identity_sha256(legacy)
                            ),
                        }
                        evidence["evidence_sha256"] = (
                            identity.identity_sha256(evidence)
                        )
                        return evidence

                controller = object.__new__(
                    ProductionExactDeploymentController
                )
                object.__setattr__(controller, "_persistence", persistence)
                object.__setattr__(controller, "_service", Service())
                object.__setattr__(controller, "_sealed", True)
                with patch.object(
                    ProductionExactDeploymentController,
                    "_commit_pre_ingress_activation_failure_terminal",
                    side_effect=RuntimeError(
                        "crash after pre-ingress boundary"
                    ),
                ):
                    with self.assertRaisesRegex(
                        RuntimeError, "crash after pre-ingress boundary"
                    ):
                        controller._restore_and_commit_failure(
                            lock=lock,
                            workspace=workspace,
                            attempt_id="activate-r1",
                            cause=RuntimeError(
                                "candidate qualification failed"
                            ),
                        )
                workspace = None
                if lock.held:
                    lock.release()
                fresh = ProductionExactDeploymentController.for_test_only(
                    persistence=persistence,
                    service=Service(),
                )
                with patch.object(
                    ProductionExactDeploymentController,
                    "_qualify_and_stop",
                    side_effect=AssertionError(
                        "pre-ingress forward path re-entered"
                    ),
                ) as qualify:
                    with self.assertRaisesRegex(
                        ExactDeploymentControllerError, "failure_receipt"
                    ):
                        fresh.activate_successor(
                            release_id="release-r1",
                            expected_manifest_sha256=(
                                identity.identity_sha256(r1)
                            ),
                            attempt_id="activate-r1",
                        )
                    qualify.assert_not_called()
                latest = persistence.journals.replay("activate-r1")[-1]
                self.assertEqual("failure_receipt_committed", latest["phase"])
                self.assertEqual(active(r0), persistence.read_active_release().value)
                self.assertIsNone(persistence.read_local_prior_binding())
                failures = [
                    record.value
                    for record in persistence.read_local_receipts()
                    if record.value["schema_version"]
                    == identity.FAILURE_RECEIPT_SCHEMA
                ]
                self.assertEqual(1, len(failures))
                self.assertEqual(
                    "candidate_start_authorized", failures[0]["failed_phase"]
                )
                recovery_marker = (
                    persistence.layout.journals
                    / "activate-r1.evidence"
                    / "failure-steady-recovery-authorization.json"
                )
                self.assertFalse(recovery_marker.exists())
                self.assertTrue(
                    (
                        persistence.layout.journals
                        / "activate-r1.evidence"
                        / "failure-selection-authorization.json"
                    ).is_file()
                )
                self.assertFalse(
                    (persistence.layout.releases / "release-r1").exists()
                )
                self.assertEqual(
                    ["release-r0"],
                    [item.release_id for item in persistence.release_inventory()],
                )
                lock.acquire()
                self.assertFalse(
                    persistence.cleanup_failed_candidate(
                        lock=lock, attempt_id="activate-r1"
                    )
                )
                legacy_digest = hashlib.sha256(
                    identity.canonical_bytes(
                        {
                            "attempt": "activate-r1",
                            "candidate": failed["candidate"],
                        }
                    )
                ).hexdigest()[:48]
                legacy_quarantine = (
                    persistence.layout.temporary
                    / "failure-release-cleanup"
                    / f"failure-{legacy_digest}.partial"
                )
                self._materialize(legacy_quarantine, r1, b"candidate")
                self.assertTrue(
                    persistence.cleanup_failed_candidate(
                        lock=lock, attempt_id="activate-r1"
                    )
                )
                self.assertFalse(legacy_quarantine.exists())
                self.assertFalse((persistence.layout.temporary / "f").exists())
                self.assertFalse(legacy_quarantine.parent.exists())
                (persistence.layout.temporary / "f").mkdir()
                legacy_quarantine.parent.mkdir()
                self.assertFalse(
                    persistence.cleanup_failed_candidate(
                        lock=lock, attempt_id="activate-r1"
                    )
                )
                self.assertFalse((persistence.layout.temporary / "f").exists())
                self.assertFalse(legacy_quarantine.parent.exists())
            finally:
                if lock.held:
                    lock.release()

    def test_fresh_replay_after_failure_marker_never_reenters_forward_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            persistence = LocalDeploymentPersistence.for_test_only(
                root, allow_posix_test_only=True
            )
            r0 = release(
                "release-r0", b"baseline", "8", include_migrations=True
            )
            old = release(
                "release-old", b"prior", "7", include_migrations=True
            )
            r1 = release(
                "release-r1", b"candidate", "9", include_migrations=True
            )
            self._materialize(
                persistence.layout.releases / "release-r0", r0, b"baseline"
            )
            self._materialize(
                persistence.layout.releases / "release-old", old, b"prior"
            )
            self._materialize(
                persistence.layout.releases / "release-r1", r1, b"candidate"
            )
            for name in ("comments.sqlite3", "research_workspace.sqlite3"):
                (persistence.layout.state / name).write_bytes(
                    f"state-{name}".encode("ascii")
                )
            bootstrap = journal(
                None,
                r0,
                operation="bootstrap_first_pair",
                attempt="bootstrap-r0",
                nonce="bootstrap-r0-nonce",
            )
            bootstrap_done = bootstrap_receipt(r0, attempt="bootstrap-r0")
            failed = journal(
                r0,
                r1,
                original_prior=old,
                attempt="activate-r1",
                nonce="activate-r1-nonce",
            )
            lock = persistence.global_lock()
            lock.acquire()
            workspace = None
            try:
                for revision in history_to(
                    bootstrap,
                    "terminal_receipt_committed",
                    receipt=bootstrap_done,
                ):
                    persistence.journals.append(revision, lock=lock)
                persistence.commit_local_receipt(
                    lock=lock, receipt=bootstrap_done
                )
                for revision in history_to(
                    failed, "candidate_start_authorized"
                ):
                    persistence.journals.append(revision, lock=lock)
                persistence.cas_active_release(
                    lock=lock, expected=None, desired=active(r1)
                )
                persistence.cas_local_prior_binding(
                    lock=lock,
                    expected=None,
                    desired=binding(r0, old),
                )
                workspace = persistence.bind_attempt_workspace(
                    lock, "activate-r1", "activate-r1-nonce"
                )
                persistence.commit_failure_selection_authorization(
                    lock=lock, workspace=workspace
                )
                persistence.restore_original_control_for_failure(
                    lock=lock, workspace=workspace
                )
                workspace.close()
                workspace = None
            finally:
                if workspace is not None and workspace._state != "closed":
                    workspace.close()
                if lock.held:
                    lock.release()

            expected_hash = identity.identity_sha256(r1)

            class CrashAfterMarker:
                @staticmethod
                def ensure_steady_exact(_release_ref):
                    raise RuntimeError("crash after durable marker")

            class CrashAfterEnsure:
                @staticmethod
                def ensure_steady_exact(_release_ref):
                    return True

                @staticmethod
                def observe_steady_exact(_release_ref):
                    raise RuntimeError("crash after steady ensure")

            class CompleteRecovery:
                @staticmethod
                def ensure_steady_exact(_release_ref):
                    return True

                @staticmethod
                def observe_steady_exact(release_ref):
                    observed = {
                        "schema_version": "qrh-exact-steady-observation/v1",
                        "scm_state": "RUNNING",
                        "writer_authority": "D-active",
                        "release": release_ref,
                        "snapshot_id": "8" * 64,
                        "endpoint_response_sha256": "7" * 64,
                    }
                    observed["evidence_sha256"] = (
                        identity.identity_sha256(observed)
                    )
                    return observed

            def controller(service):
                return ProductionExactDeploymentController.for_test_only(
                    persistence=persistence,
                    service=service,
                )

            for service, message in (
                (CrashAfterMarker(), "crash after durable marker"),
                (CrashAfterEnsure(), "crash after steady ensure"),
            ):
                with self.subTest(cut=message), patch.object(
                    ProductionExactDeploymentController,
                    "_qualify_and_stop",
                    side_effect=AssertionError("forward path re-entered"),
                ) as qualify:
                    with self.assertRaisesRegex(RuntimeError, message):
                        controller(service).activate_successor(
                            release_id="release-r1",
                            expected_manifest_sha256=expected_hash,
                            attempt_id="activate-r1",
                        )
                    qualify.assert_not_called()

            with patch.object(
                ProductionExactDeploymentController,
                "_qualify_and_stop",
                side_effect=AssertionError("forward path re-entered"),
            ) as qualify, patch.object(
                ProductionExactDeploymentController,
                "_commit_failure_terminal",
                side_effect=RuntimeError("crash after steady observe"),
            ):
                with self.assertRaisesRegex(
                    RuntimeError, "crash after steady observe"
                ):
                    controller(CompleteRecovery()).activate_successor(
                        release_id="release-r1",
                        expected_manifest_sha256=expected_hash,
                        attempt_id="activate-r1",
                    )
                qualify.assert_not_called()

            with patch.object(
                ProductionExactDeploymentController,
                "_qualify_and_stop",
                side_effect=AssertionError("forward path re-entered"),
            ) as qualify:
                with self.assertRaisesRegex(
                    ExactDeploymentControllerError, "failure_receipt"
                ):
                    controller(CompleteRecovery()).activate_successor(
                        release_id="release-r1",
                        expected_manifest_sha256=expected_hash,
                        attempt_id="activate-r1",
                    )
                qualify.assert_not_called()
            terminal = persistence.journals.replay("activate-r1")[-1]
            self.assertEqual("failure_receipt_committed", terminal["phase"])
            self.assertEqual(active(r0), persistence.read_active_release().value)
            self.assertFalse(
                (persistence.layout.releases / "release-r1").exists()
            )


if __name__ == "__main__":
    unittest.main()
