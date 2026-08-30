from __future__ import annotations

from contextlib import closing
import hashlib
import inspect
from pathlib import Path
import pickle
import sqlite3
import unittest

from quant_hub.collaboration.comment_store import initialize_comment_store
from quant_hub.config import Settings
from quant_hub.ops import local_exact_runtime_canary_input as input_module
from quant_hub.ops import local_exact_runtime_canary_runner as runner_module
from quant_hub.ops import local_windows_writer_lease_holder as holder_module
from quant_hub.ops.local_deployment_runtime import (
    TestOnlyWindowsDeploymentRuntimeAdapter as RuntimeAdapter,
)
from quant_hub.ops.local_exact_release_compatibility import (
    build_exact_release_compatibility_evidence,
    plan_exact_release_compatibility,
)
from quant_hub.ops.local_exact_runtime_canary_input import (
    LockedExactRuntimeCanaryInput,
    ProductionExactRuntimeCanaryInputProducer,
)
from quant_hub.ops.local_exact_runtime_canary_evidence import (
    ExactRuntimeCanaryEvidence,
    build_exact_runtime_canary_evidence,
)
from quant_hub.ops.local_exact_runtime_canary_observer import (
    ProductionExactRuntimeCanaryTransport,
)
from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256
from quant_hub.ops.local_windows_writer_lease_holder import (
    ExactRuntimeLeaseIdentity,
)
from quant_hub.research_workspace.service import ResearchWorkspace
from tests.test_local_deployment_persistence import (
    PersistenceFixture,
    advance_one,
    journal,
    release,
    seal,
    state_identity,
)
from tests.helpers import install_public_archive_presentation


_BUSINESS_TABLES = {
    "comments": (
        "actor",
        "command_receipt",
        "comment",
        "comment_event",
        "comment_target",
        "legacy_import_run",
        "outbox_event",
        "progress_command_receipt",
        "progress_topic",
        "progress_topic_event",
    ),
    "research_workspace": (
        "actor",
        "research_workspace_command_receipt",
        "research_workspace_comment",
        "research_workspace_comment_event",
        "research_workspace_event",
        "research_workspace_node",
        "research_workspace_observation",
        "research_workspace_sync_run",
    ),
}


class ExactRuntimeCanaryInputTests(PersistenceFixture):
    def setUp(self) -> None:
        super().setUp()
        install_public_archive_presentation(self)

    def migration_root(self) -> Path:
        return Path(__file__).resolve().parents[1] / "migrations" / "research_workspace"

    def exact_release(self, release_id: str, character: str) -> dict[str, object]:
        document = release(
            release_id,
            self.payloads[release_id],
            character,
            include_migrations=True,
        )
        actual = {
            f"migrations/research_workspace/{path.name}": path.read_bytes()
            for path in self.migration_root().iterdir()
            if path.is_file()
        }
        for item in document["inventory"]["files"]:
            relative = str(item["path"])
            if relative in actual:
                item["bytes"] = len(actual[relative])
                item["sha256"] = hashlib.sha256(actual[relative]).hexdigest()
        document["resources"]["inventory_sha256"] = identity_sha256(
            document["inventory"]
        )
        return document

    def materialize_exact(self, document: dict[str, object]) -> None:
        release_root = self.persistence.layout.releases / str(document["release_id"])
        actual = {
            f"migrations/research_workspace/{path.name}": path.read_bytes()
            for path in self.migration_root().iterdir()
            if path.is_file()
        }
        for item in document["inventory"]["files"]:
            relative = str(item["path"])
            target = release_root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = (
                self.payloads[str(document["release_id"])]
                if relative == "app/payload.bin"
                else actual[relative]
            )
            target.write_bytes(raw)
        (release_root / "release_manifest.json").write_bytes(
            canonical_bytes(document)
        )

    def create_state_database(self, database: str) -> None:
        path = self.persistence.layout.state / (
            "comments.sqlite3"
            if database == "comments"
            else "research_workspace.sqlite3"
        )
        if database == "comments":
            initialize_comment_store(path)
            return
        project = self.root / "canary-fixture-project"
        var = self.root / "canary-fixture-var"
        settings = Settings(
            project_root=project,
            archive_root=project / "reference" / "archive",
            var_root=var,
            database_path=var / "db" / "platform.sqlite3",
            object_root=var / "objects",
            migration_root=(
                Path(__file__).resolve().parents[1] / "migrations" / "platform"
            ),
        )
        settings.archive_root.mkdir(parents=True)
        document = (
            settings.research_workspace_root
            / "01_canary_project"
            / "01_canary_document.md"
        )
        document.parent.mkdir(parents=True)
        document.write_text("# Canary document\n\nfixture\n", encoding="utf-8")
        workspace = ResearchWorkspace(settings, database_path=path)
        workspace.sync()
        self.assertTrue(workspace.tree()["items"])

    def install_activation(self) -> tuple[str, str]:
        attempt = "attempt-canary-input"
        nonce = "nonce-canary-input"
        prior = self.exact_release("release-r0", "9")
        candidate = self.exact_release("release-r1", "a")
        self.materialize_exact(prior)
        self.materialize_exact(candidate)
        planned = plan_exact_release_compatibility(
            operation="activation",
            attempt_id=attempt,
            nonce=nonce,
            state_identity_sha256=state_identity()["identity_sha256"],
            candidate_manifest=candidate,
            prior_manifest=prior,
        )
        first = journal(
            prior,
            candidate,
            attempt=attempt,
            nonce=nonce,
        )
        first["state_plan"]["compatibility_sha256"] = planned.aggregate_sha256
        seal(first, "journal_sha256")
        self.append_history([first])
        with self.persistence.global_lock() as lock:
            planning_workspace = self.persistence.bind_attempt_workspace(
                lock, attempt, nonce
            )
            planning_closures = self.persistence.lock_exact_release_closures(
                lock, planning_workspace
            )
            compatibility = build_exact_release_compatibility_evidence(
                planning_closures
            )
            by_name = {
                document["database_name"]: document["evidence_sha256"]
                for document in compatibility.documents
            }
            planning_closures.close()
            planning_workspace.close()
        root_verified = advance_one(first)
        state_applied = advance_one(root_verified)
        state_applied["database_seals"] = [
            {
                "name": name,
                "seal_sha256": str(index + 1) * 64,
                "compatibility_manifest_sha256": by_name[name],
            }
            for index, name in enumerate(
                ("comments", "research_workspace")
            )
        ]
        seal(state_applied, "journal_sha256")
        remaining = [root_verified, state_applied]
        while remaining[-1]["phase"] != "candidate_start_authorized":
            remaining.append(advance_one(remaining[-1]))
        self.append_history(remaining)
        self.create_state_database("comments")
        self.create_state_database("research_workspace")
        return attempt, nonce

    def producer(self):
        runtime = RuntimeAdapter.for_test_only(
            self.root,
            migration_root=self.migration_root(),
            allow_posix_test_only=True,
        )
        return input_module._TestOnlyExactRuntimeCanaryInputProducerAdapter.for_test_only(
            runtime
        )

    def result_evidence(
        self,
        canary: LockedExactRuntimeCanaryInput,
        *,
        challenge_nonce: str = "a" * 48,
    ) -> ExactRuntimeCanaryEvidence:
        request = canary.request
        databases = []
        for index, request_database in enumerate(request.as_dict()["databases"]):
            name = str(request_database["database_name"])
            challenge = {
                "challenge_id": "canary-"
                + hashlib.sha256(
                    f"{request.request_sha256}:{challenge_nonce}:{name}".encode()
                ).hexdigest()[:32],
                "insert_rowcount": 1,
                "cas_applied_rowcount": 1,
                "stale_cas_rowcount": 0,
                "readback_revision": 1,
                "append_only_event_count": 1,
                "event_update_outcome": "rejected_by_trigger",
                "event_delete_outcome": "rejected_by_trigger",
            }
            business = {
                "family": (
                    "archive_comments"
                    if name == "comments"
                    else "workspace_comments"
                ),
                "create_rowcount": 1,
                "idempotent_replay_rowcount": 0,
                "edit_rowcount": 1,
                "stale_edit_rowcount": 0,
                "soft_delete_rowcount": 1,
                "stale_delete_rowcount": 0,
                "final_revision": 3,
                "event_count": 3,
                "receipt_count": 3,
                "deleted_row_count": 1,
            }
            databases.append(
                {
                    "database_name": name,
                    "request_database_sha256": request_database[
                        "request_database_sha256"
                    ],
                    "initial_consistent_bytes": request_database[
                        "initial_consistent_bytes"
                    ],
                    "initial_consistent_sha256": request_database[
                        "initial_consistent_sha256"
                    ],
                    "initial_schema_sha256": str(index + 1) * 64,
                    "initial_business_summary_sha256": str(index + 3) * 64,
                    "challenge": challenge,
                    "business_probe": business,
                    "final_integrity_check": "ok",
                    "final_quick_check": "ok",
                    "final_foreign_key_violation_count": 0,
                    "final_schema_sha256": str(index + 5) * 64,
                    "final_business_summary_sha256": str(index + 7) * 64,
                    "final_consistent_bytes": int(
                        request_database["initial_consistent_bytes"]
                    )
                    + 4096,
                    "final_consistent_sha256": str(index + 8) * 64,
                    "final_members": ["main"],
                }
            )
        document = build_exact_runtime_canary_evidence(
            {
                "challenge_nonce": challenge_nonce,
                "writer_lease_claim": {
                    "lease_id": "lease-canary-input",
                    "lease_nonce": "b" * 48,
                    "lease_epoch": 1,
                    "lease_record_sha256": "c" * 64,
                    "authority": "claim_not_independently_observed",
                },
                "databases": databases,
            },
            request=request,
        )
        return ExactRuntimeCanaryEvidence.from_document(document, request=request)

    def test_two_live_sources_materialize_guard_and_create_only_request(self) -> None:
        attempt, nonce = self.install_activation()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            canary = self.producer().produce(
                self.persistence,
                lock,
                workspace,
                authorization,
                closures,
            )
            self.assertIs(type(canary), LockedExactRuntimeCanaryInput)
            self.assertEqual(
                "exact_runtime_canary_input_live_only", canary.scope
            )
            request = canary.request.as_dict()
            self.assertEqual(
                ["comments", "research_workspace"],
                [item["database_name"] for item in request["databases"]],
            )
            self.assertIn(f"{attempt}-{nonce}", request["databases"][0]["relative_path"])
            request_path = (
                self.persistence.layout.temporary
                / "deployment-attempts"
                / f"{attempt}-{nonce}"
                / "runtime-canary"
                / "candidate"
                / "request.json"
            )
            self.assertEqual(canary.request.canonical_bytes(), request_path.read_bytes())
            for database in ("comments", "research_workspace"):
                seal_document = canary.source_seal(database).as_dict()
                copy_document = canary.copy_evidence(database).as_dict()
                request_database = next(
                    item for item in request["databases"]
                    if item["database_name"] == database
                )
                self.assertEqual(
                    seal_document["seal_sha256"],
                    request_database["source_seal_sha256"],
                )
                self.assertEqual(
                    copy_document["evidence_sha256"],
                    request_database["isolated_copy_evidence_sha256"],
                )
            with self.assertRaises(TypeError):
                pickle.dumps(canary)
            copied_comments = request_path.parent / "state" / "comments.sqlite3"
            with closing(sqlite3.connect(copied_comments, isolation_level=None)) as writer:
                writer.execute(
                    "INSERT INTO actor VALUES(?,?,?,?)",
                    (
                        "canary-actor",
                        "other",
                        "Canary Actor",
                        "2026-08-28T00:00:00Z",
                    ),
                )
            canary.checkpoint_live()
            canary.close()
            closures.close()
            workspace.close()

    def test_product_surface_has_no_evidence_or_path_injection(self) -> None:
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    ProductionExactRuntimeCanaryInputProducer.load_exact_d
                ).parameters
            ),
        )
        self.assertEqual(
            [
                "self",
                "persistence",
                "lock",
                "workspace",
                "authorization",
                "closures",
            ],
            list(
                inspect.signature(
                    ProductionExactRuntimeCanaryInputProducer.produce
                ).parameters
            ),
        )
        self.assertNotIn(
            "_TestOnlyExactRuntimeCanaryInputProducerAdapter",
            input_module.__all__,
        )
        self.assertEqual(
            {
                "ExactRuntimeCanaryInputError",
                "LockedExactRuntimeCanaryInput",
                "ProductionExactRuntimeCanaryInputProducer",
            },
            set(input_module.__all__),
        )
        with self.assertRaises(TypeError):
            self.producer().produce(  # type: ignore[call-arg]
                persistence=self.persistence,
                lock=object(),
                workspace=object(),
                authorization=object(),
                closures=object(),
                path=self.root,
            )

    def test_lock_release_revokes_input_before_upstream_resources(self) -> None:
        attempt, nonce = self.install_activation()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            canary = self.producer().produce(
                self.persistence,
                lock,
                workspace,
                authorization,
                closures,
            )
            self.assertEqual("live", canary._state)  # noqa: SLF001
            self.assertTrue(workspace._runtime_canary_inputs)  # noqa: SLF001
        self.assertEqual("closed", canary._state)  # noqa: SLF001
        self.assertEqual("closed", workspace._state)  # noqa: SLF001
        self.assertEqual("closed", closures._state)  # noqa: SLF001
        self.assertFalse(workspace._runtime_canary_inputs)  # noqa: SLF001

    def test_request_replacement_revokes_live_checkpoint(self) -> None:
        attempt, nonce = self.install_activation()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            canary = self.producer().produce(
                self.persistence,
                lock,
                workspace,
                authorization,
                closures,
            )
            request_path = (
                self.persistence.layout.temporary
                / "deployment-attempts"
                / f"{attempt}-{nonce}"
                / "runtime-canary"
                / "candidate"
                / "request.json"
            )
            request_path.write_bytes(b"{}")
            with self.assertRaisesRegex(Exception, "request"):
                canary.checkpoint_live()

    def test_result_requires_one_way_observation_then_remains_live(self) -> None:
        attempt, nonce = self.install_activation()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            canary = self.producer().produce(
                self.persistence, lock, workspace, authorization, closures
            )
            evidence = self.result_evidence(canary)
            result_path = (
                self.persistence.layout.temporary
                / "deployment-attempts"
                / f"{attempt}-{nonce}"
                / "runtime-canary"
                / "candidate"
                / "result.json"
            )
            owner = ProductionExactRuntimeCanaryTransport.load_exact_d()
            canary._begin_result_observation(owner)  # noqa: SLF001
            result_path.write_bytes(evidence.canonical_bytes())
            canary._commit_result_observation(owner, evidence)  # noqa: SLF001
            self.assertEqual("live_result", canary._state)  # noqa: SLF001
            canary.checkpoint_live()
            self.assertEqual(
                "exact_runtime_canary_input_live_only", canary.scope
            )
            result_path.write_bytes(evidence.canonical_bytes() + b"\n")
            with self.assertRaisesRegex(Exception, "result"):
                canary.checkpoint_live()
            self.assertEqual("result_revoked", canary._state)  # noqa: SLF001
            result_path.write_bytes(evidence.canonical_bytes())
            with self.assertRaisesRegex(Exception, "关闭"):
                canary.checkpoint_live()
            canary.close()

    def test_unobserved_result_revokes_without_repair(self) -> None:
        attempt, nonce = self.install_activation()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            canary = self.producer().produce(
                self.persistence, lock, workspace, authorization, closures
            )
            result_path = (
                self.persistence.layout.temporary
                / "deployment-attempts"
                / f"{attempt}-{nonce}"
                / "runtime-canary"
                / "candidate"
                / "result.json"
            )
            result_path.write_bytes(b"{}")
            with self.assertRaisesRegex(Exception, "namespace"):
                canary.checkpoint_live()
            self.assertEqual("result_revoked", canary._state)  # noqa: SLF001
            result_path.unlink()
            with self.assertRaisesRegex(Exception, "关闭"):
                canary.checkpoint_live()
            canary.close()

    def test_result_created_during_failed_observation_is_ambiguous(self) -> None:
        attempt, nonce = self.install_activation()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            canary = self.producer().produce(
                self.persistence, lock, workspace, authorization, closures
            )
            result_path = (
                self.persistence.layout.temporary
                / "deployment-attempts"
                / f"{attempt}-{nonce}"
                / "runtime-canary"
                / "candidate"
                / "result.json"
            )
            owner = ProductionExactRuntimeCanaryTransport.load_exact_d()
            canary._begin_result_observation(owner)  # noqa: SLF001
            result_path.write_bytes(b"{}")
            with self.assertRaisesRegex(Exception, "ambiguous"):
                canary._abort_result_observation(owner)  # noqa: SLF001
            self.assertEqual("result_revoked", canary._state)  # noqa: SLF001
            canary.close()

    def test_same_root_producer_runner_result_and_input_checkpoint(self) -> None:
        attempt, nonce = self.install_activation()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            canary = self.producer().produce(
                self.persistence, lock, workspace, authorization, closures
            )
            request = canary.request.as_dict()
            release_document = request["release"]
            identity = ExactRuntimeLeaseIdentity(
                attempt_id=str(request["attempt_id"]),
                nonce=str(request["nonce"]),
                operation=str(request["operation"]),
                role=str(request["role"]),
                start_nonce=str(request["start_nonce"]),
                state_identity_sha256=str(request["state_identity_sha256"]),
                release_id=str(release_document["release_id"]),
                manifest_sha256=str(release_document["manifest_sha256"]),
            )
            self.assertEqual(
                request["authorization_sha256"], identity.authorization_sha256
            )
            self.assertEqual(request["scm_identity_sha256"], identity.scm_identity_sha256)
            (self.root / "tmp" / "service").mkdir(exist_ok=True)
            lease = holder_module._TestOnlyWindowsWriterLeaseHolderAdapter.load().acquire(
                self.root, identity
            )
            try:
                owner = ProductionExactRuntimeCanaryTransport.load_exact_d()
                canary._begin_result_observation(owner)  # noqa: SLF001
                evidence = (
                    runner_module._TestOnlyExactRuntimeCanaryRunnerAdapter.for_test_only().run(
                        lease, "ab" * 24
                    )
                )
                role_root = (
                    self.root
                    / "tmp"
                    / "deployment-attempts"
                    / f"{attempt}-{nonce}"
                    / "runtime-canary"
                    / "candidate"
                )
                self.assertEqual(
                    {"request.json", "result.json", "state", "tmp"},
                    {item.name for item in role_root.iterdir()},
                )
                self.assertEqual(
                    {"comments.sqlite3", "research_workspace.sqlite3"},
                    {item.name for item in role_root.joinpath("state").iterdir()},
                )
                self.assertFalse(tuple(role_root.joinpath("tmp").iterdir()))
                canary._commit_result_observation(owner, evidence)  # noqa: SLF001
                canary.checkpoint_live()
                for request_database in request["databases"]:
                    relative = str(request_database["relative_path"])
                    self.assertTrue(relative.startswith("tmp/deployment-attempts/"))
                    self.assertTrue(self.root.joinpath(*relative.split("/")).is_file())
                result_path = (
                    self.root
                    / "tmp"
                    / "deployment-attempts"
                    / f"{attempt}-{nonce}"
                    / "runtime-canary"
                    / "candidate"
                    / "result.json"
                )
                self.assertEqual(evidence.canonical_bytes(), result_path.read_bytes())
                self.assertFalse(tuple(result_path.parent.joinpath("state").glob("*.sqlite3-*")))
            finally:
                lease.close()
            canary.close()


if __name__ == "__main__":
    unittest.main()
