from __future__ import annotations

from contextlib import closing
import hashlib
import inspect
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.collaboration.comment_store import initialize_comment_store
from quant_hub.ops.local_deployment_persistence import LocalDeploymentPersistence
from quant_hub.ops.local_deployment_runtime import (
    IsolatedCopyResult,
    LocalDeploymentRuntimeError,
    ProductionWindowsDeploymentRuntime,
    TestOnlyWindowsDeploymentRuntimeAdapter as RuntimeAdapter,
    _resolve_product_workspace_migration_root,
)
from quant_hub.ops.local_runtime_evidence import (
    DeploymentCanaryEvidence,
    IsolatedSqliteCopyEvidence,
    StateDatabaseSeal,
)
from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_up


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


class LocalDeploymentRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.persistence = LocalDeploymentPersistence.for_test_only(
            self.root,
            allow_posix_test_only=(os.name != "nt"),
        )
        self.migration_root = (
            Path(__file__).resolve().parents[1]
            / "migrations"
            / "research_workspace"
        )
        self.runtime = RuntimeAdapter.for_test_only(
            self.root,
            migration_root=self.migration_root,
            allow_posix_test_only=(os.name != "nt"),
        )
        initialize_comment_store(self.root / "state" / "comments.sqlite3")
        workspace_path = self.root / "state" / "research_workspace.sqlite3"
        connection = connect_database(workspace_path)
        try:
            self.assertEqual([1, 2, 3], migrate_up(connection, self.migration_root))
        finally:
            connection.close()

    def compatibility(self, database: str, *, operation: str = "activate_successor"):
        version = 2 if database == "comments" else 3
        return self.runtime.compatibility_manifest(
            operation=operation,
            database_name=database,
            candidate_release_id="release-r1",
            candidate_release_manifest_sha256=digest("r1"),
            candidate_read_versions=[version],
            candidate_write_versions=[version],
            prior_release_id="release-r0",
            prior_release_manifest_sha256=digest("r0"),
            prior_read_versions=[version],
            prior_write_versions=[version],
        )

    def seal(self, database: str, *, attempt: str = "attempt-b3") -> StateDatabaseSeal:
        return self.runtime.seal_database(
            attempt_id=attempt,
            nonce="nonce-b3",
            operation="activate_successor",
            database_name=database,
            state_identity_sha256=digest("state"),
            compatibility_manifest=self.compatibility(database),
        )

    def test_product_factory_is_no_arg_fixed_d_and_test_type_is_separate(self) -> None:
        self.assertEqual({}, inspect.signature(ProductionWindowsDeploymentRuntime.load_exact_d).parameters)
        production_root = Path(r"D:\quant\quant_platform")
        if production_root.is_dir():
            product = ProductionWindowsDeploymentRuntime.load_exact_d()
            self.assertIsInstance(product, ProductionWindowsDeploymentRuntime)
            targets = (product, self.runtime)
        else:
            with self.assertRaises(LocalDeploymentRuntimeError):
                ProductionWindowsDeploymentRuntime.load_exact_d()
            targets = (self.runtime,)
        self.assertNotIsInstance(self.runtime, ProductionWindowsDeploymentRuntime)
        for target in targets:
            for leaked in ("root", "path", "environment", "config", "hook", "runtime"):
                self.assertFalse(hasattr(target, leaked))
        source = inspect.getsource(inspect.getmodule(ProductionWindowsDeploymentRuntime))
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv", source)

    def test_product_factory_translates_absent_exact_d_to_domain_error(self) -> None:
        with patch.object(Path, "resolve", side_effect=FileNotFoundError("absent")):
            with self.assertRaisesRegex(
                LocalDeploymentRuntimeError,
                "exact Windows D root",
            ):
                ProductionWindowsDeploymentRuntime.load_exact_d()
        with self.assertRaises(LocalDeploymentRuntimeError):
            RuntimeAdapter.for_test_only(  # type: ignore[arg-type]
                str(self.root)
            )

    def test_product_migration_layout_resolver_requires_exactly_one_complete_layout(self) -> None:
        project = self.root / "layout-project"
        module_file = project / "src" / "quant_hub" / "ops" / "runtime.py"
        module_file.parent.mkdir(parents=True)
        module_file.write_bytes(b"runtime\n")
        source_layout = project / "migrations" / "research_workspace"
        installed_layout = (
            project / "src" / "quant_hub" / "migrations" / "research_workspace"
        )

        with self.assertRaisesRegex(LocalDeploymentRuntimeError, "absent or ambiguous"):
            _resolve_product_workspace_migration_root(module_file)

        source_layout.mkdir(parents=True)
        for path in self.migration_root.iterdir():
            if path.is_file():
                shutil.copyfile(path, source_layout / path.name)
        self.assertEqual(
            source_layout.resolve(),
            _resolve_product_workspace_migration_root(module_file),
        )

        installed_layout.mkdir(parents=True)
        for path in self.migration_root.iterdir():
            if path.is_file():
                shutil.copyfile(path, installed_layout / path.name)
        with self.assertRaisesRegex(LocalDeploymentRuntimeError, "absent or ambiguous"):
            _resolve_product_workspace_migration_root(module_file)
        shutil.rmtree(source_layout)
        self.assertEqual(
            installed_layout.resolve(),
            _resolve_product_workspace_migration_root(module_file),
        )

    def test_bootstrap_compatibility_seals_current_state_without_a_prior(self) -> None:
        for database, version in (("comments", 2), ("research_workspace", 3)):
            compatibility = self.runtime.compatibility_manifest(
                operation="bootstrap_first_pair",
                database_name=database,
                candidate_release_id="release-r0",
                candidate_release_manifest_sha256=digest("r0"),
                candidate_read_versions=[version],
                candidate_write_versions=[version],
                prior_release_id=None,
                prior_release_manifest_sha256=None,
                prior_read_versions=None,
                prior_write_versions=None,
            )
            self.assertEqual(
                {"status": "absent"},
                compatibility.as_dict()["prior_compatibility"],
            )
            seal = self.runtime.seal_database(
                attempt_id="bootstrap-r0",
                nonce="bootstrap-r0-nonce",
                operation="bootstrap_first_pair",
                database_name=database,
                state_identity_sha256=digest("state"),
                compatibility_manifest=compatibility,
            )
            self.assertEqual(
                "bootstrap_first_pair", seal.as_dict()["operation"]
            )

    def test_main_only_seals_are_read_only_and_user_version_is_observation(self) -> None:
        for database, logical_version in (("comments", 2), ("research_workspace", 3)):
            path = self.root / "state" / (
                "comments.sqlite3" if database == "comments" else "research_workspace.sqlite3"
            )
            before = path.read_bytes()
            before_info = path.stat()
            sidecars_before = {
                suffix: Path(str(path) + suffix).exists()
                for suffix in ("-wal", "-shm", "-journal")
            }
            with (
                patch(
                    "quant_hub.platform.db.connect_database",
                    side_effect=AssertionError("sealer must not call connect_database"),
                ),
                patch(
                    "quant_hub.collaboration.comment_store.initialize_comment_store",
                    side_effect=AssertionError("sealer must not initialize comments"),
                ),
                patch(
                    "quant_hub.research_workspace.database.initialize_research_workspace_database",
                    side_effect=AssertionError("sealer must not initialize workspace"),
                ),
            ):
                seal = self.seal(database)
            document = seal.as_dict()
            self.assertEqual(
                "diagnostic_only_unresolved_release_closure",
                document["qualification_scope"],
            )
            self.assertEqual("main_only_immutable", document["open_mode"])
            self.assertEqual(0, document["raw_user_version"])
            self.assertEqual(logical_version, document["logical_schema"]["logical_version"])
            self.assertEqual("ok", document["integrity_check"])
            self.assertEqual("ok", document["quick_check"])
            self.assertEqual(before, path.read_bytes())
            after_info = path.stat()
            self.assertEqual(
                (before_info.st_dev, before_info.st_ino, before_info.st_size, before_info.st_mtime_ns),
                (after_info.st_dev, after_info.st_ino, after_info.st_size, after_info.st_mtime_ns),
            )
            self.assertEqual(
                sidecars_before,
                {
                    suffix: Path(str(path) + suffix).exists()
                    for suffix in ("-wal", "-shm", "-journal")
                },
            )

    def test_wal_triplet_seal_preserves_exact_members(self) -> None:
        if os.name != "nt":
            self.skipTest("formal WAL guard uses real Windows share-mode handles")
        path = self.root / "state" / "comments.sqlite3"
        staging = self.root / "tmp" / "wal-source.sqlite3"
        initialize_comment_store(staging)
        with closing(sqlite3.connect(staging, isolation_level=None)) as writer:
            self.assertEqual(
                "wal",
                str(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0]).casefold(),
            )
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute(
                "INSERT INTO actor VALUES('wal_actor','other','WAL Actor','2000-01-01T00:00:00Z')"
            )
            for suffix in ("", "-wal", "-shm"):
                shutil.copyfile(Path(str(staging) + suffix), Path(str(path) + suffix))
        members = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
        self.assertTrue(all(member.is_file() for member in members))
        before = [(member.stat(), member.read_bytes()) for member in members]
        seal = self.seal("comments", attempt="attempt-wal")
        self.assertEqual("wal_triplet_read_only", seal.as_dict()["open_mode"])
        after = [(member.stat(), member.read_bytes()) for member in members]
        for (before_info, before_bytes), (after_info, after_bytes) in zip(
            before, after, strict=True
        ):
            self.assertEqual(before_bytes, after_bytes)
            self.assertEqual(
                (
                    before_info.st_dev,
                    before_info.st_ino,
                    before_info.st_size,
                    before_info.st_mtime_ns,
                ),
                (
                    after_info.st_dev,
                    after_info.st_ino,
                    after_info.st_size,
                    after_info.st_mtime_ns,
                ),
            )

    def test_unfenced_wal_writer_is_rejected_before_sqlite_reader_can_mutate_shm(self) -> None:
        if os.name != "nt":
            self.skipTest("formal writer-fence guard uses real Windows share-mode handles")
        path = self.root / "state" / "comments.sqlite3"
        with closing(sqlite3.connect(path, isolation_level=None)) as writer:
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute(
                "INSERT INTO actor VALUES('live_writer','other','Live Writer','2000-01-01T00:00:00Z')"
            )
            shm = Path(str(path) + "-shm")
            before = shm.read_bytes()
            with self.assertRaisesRegex(LocalDeploymentRuntimeError, "未 fence writer"):
                self.seal("comments", attempt="attempt-unfenced")
            self.assertEqual(before, shm.read_bytes())

    def test_memory_backup_workspace_copy_canary_and_closed_commit(self) -> None:
        active_before = {
            database: (self.root / "state" / filename).read_bytes()
            for database, filename in (
                ("comments", "comments.sqlite3"),
                ("research_workspace", "research_workspace.sqlite3"),
            )
        }
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "attempt-copy",
                "nonce-b3",
            )
            for database in ("comments", "research_workspace"):
                result = self.runtime.create_isolated_copy(
                    workspace=workspace,
                    operation="activate_successor",
                    database_name=database,
                    state_identity_sha256=digest("state"),
                    compatibility_manifest=self.compatibility(database),
                )
                self.assertIsInstance(result, IsolatedCopyResult)
                self.assertIsInstance(result.source_seal, StateDatabaseSeal)
                self.assertIsInstance(result.copy_evidence, IsolatedSqliteCopyEvidence)
                copy_document = result.copy_evidence.as_dict()
                self.assertEqual(["main"], copy_document["destination_members"])
                self.assertNotIn("path", str(copy_document).casefold())
                committed = self.runtime.commit_evidence(
                    persistence=self.persistence,
                    lock=lock,
                    workspace=workspace,
                    evidence_id=f"{database}-copy",
                    evidence=result.copy_evidence,
                )
                self.assertEqual(result.copy_evidence.canonical_bytes(), committed.raw)

                canary = self.runtime.run_controller_canary(
                    workspace=workspace,
                    database_name=database,
                    copy_evidence=result.copy_evidence,
                )
                self.assertIsInstance(canary, DeploymentCanaryEvidence)
                canary_document = canary.as_dict()
                self.assertEqual(1, canary_document["challenge"]["applied_rowcount"])
                self.assertEqual(0, canary_document["challenge"]["stale_rowcount"])
                self.assertEqual(1, canary_document["challenge"]["readback_revision"])
                self.assertEqual(3, canary_document["business_probe"]["event_count"])
                self.assertEqual(3, canary_document["business_probe"]["receipt_count"])
                self.assertEqual(
                    "diagnostic_only_not_exact_release",
                    canary_document["qualification_scope"],
                )
                self.runtime.commit_evidence(
                    persistence=self.persistence,
                    lock=lock,
                    workspace=workspace,
                    evidence_id=f"{database}-canary",
                    evidence=canary,
                )
            workspace.close()

        for database, filename in (
            ("comments", "comments.sqlite3"),
            ("research_workspace", "research_workspace.sqlite3"),
        ):
            path = self.root / "state" / filename
            self.assertEqual(active_before[database], path.read_bytes())
            self.assertFalse(Path(str(path) + "-journal").exists())

    def test_missing_partial_sidecar_schema_and_migration_drift_fail_closed(self) -> None:
        comments = self.root / "state" / "comments.sqlite3"
        Path(str(comments) + "-wal").write_bytes(b"not-a-wal")
        with self.assertRaisesRegex(LocalDeploymentRuntimeError, "WAL/SHM"):
            self.seal("comments", attempt="attempt-partial")
        Path(str(comments) + "-wal").unlink()

        with closing(sqlite3.connect(comments)) as connection:
            connection.execute("DELETE FROM comment_target_schema")
            connection.commit()
        with self.assertRaisesRegex(LocalDeploymentRuntimeError, "marker"):
            self.seal("comments", attempt="attempt-marker")

        workspace = self.root / "state" / "research_workspace.sqlite3"
        with closing(sqlite3.connect(workspace)) as connection:
            connection.execute(
                "UPDATE schema_migration SET up_sha256=? WHERE version=2",
                (digest("drift"),),
            )
            connection.commit()
        with self.assertRaisesRegex(LocalDeploymentRuntimeError, "ledger"):
            self.seal("research_workspace", attempt="attempt-ledger")


if __name__ == "__main__":
    unittest.main()
