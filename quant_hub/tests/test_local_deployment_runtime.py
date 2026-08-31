from __future__ import annotations

from contextlib import closing, contextmanager
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
from quant_hub.ops.local_deployment_persistence import (
    DeploymentJournalError,
    DeploymentLockBusy,
)
from quant_hub.ops import local_release_identity as identity
from quant_hub.ops.local_deployment_runtime import (
    IsolatedCopyResult,
    LocalDeploymentRuntimeError,
    ProductionWindowsDeploymentRuntime,
    TestOnlyWindowsDeploymentRuntimeAdapter as RuntimeAdapter,
    _MutableSqliteIdentityGuardSet,
    _resolve_product_workspace_migration_root,
)
from quant_hub.ops.local_runtime_evidence import (
    DeploymentCanaryEvidence,
    IsolatedSqliteCopyEvidence,
    StateDatabaseSeal,
)
from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_up
from tests.test_local_deployment_persistence import history_to, journal, release


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

    def bootstrap_compatibility(
        self,
        database: str,
        *,
        candidate_manifest_sha256: str | None = None,
    ):
        version = 2 if database == "comments" else 3
        return self.runtime.compatibility_manifest(
            operation="bootstrap_first_pair",
            database_name=database,
            candidate_release_id="release-r0",
            candidate_release_manifest_sha256=(
                digest("r0")
                if candidate_manifest_sha256 is None
                else candidate_manifest_sha256
            ),
            candidate_read_versions=[version],
            candidate_write_versions=[version],
            prior_release_id=None,
            prior_release_manifest_sha256=None,
            prior_read_versions=None,
            prior_write_versions=None,
        )

    @contextmanager
    def locked_bootstrap_expand(
        self,
        *,
        attempt: str = "bootstrap-legacy-v2",
        nonce: str = "bootstrap-legacy-v2-nonce",
    ):
        candidate = release("release-r0", b"bootstrap-r0", "a")
        candidate_hash = identity.identity_sha256(candidate)
        first = journal(
            None,
            candidate,
            operation="bootstrap_first_pair",
            attempt=attempt,
            nonce=nonce,
        )
        with self.persistence.global_lock() as lock:
            for revision in history_to(first, "root_preflight_verified"):
                self.persistence.journals.append(revision, lock=lock)
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            try:
                authorization = (
                    self.persistence.lock_bootstrap_comment_schema_expand_authorization(
                        lock,
                        workspace,
                    )
                )
                yield (
                    authorization,
                    self.bootstrap_compatibility(
                        "comments",
                        candidate_manifest_sha256=candidate_hash,
                    ),
                    workspace,
                    str(first["state_plan"]["state_identity_sha256"]),
                )
            finally:
                workspace.close()

    @staticmethod
    def database_snapshot(path: Path) -> tuple[object, ...]:
        sidecars = tuple(
            (
                suffix,
                Path(str(path) + suffix).read_bytes()
                if Path(str(path) + suffix).is_file()
                else None,
            )
            for suffix in ("-wal", "-shm", "-journal")
        )
        with closing(sqlite3.connect(path)) as connection:
            schema = connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall()
            comments = connection.execute(
                "SELECT * FROM comment ORDER BY comment_id"
            ).fetchall()
        return path.read_bytes(), sidecars, schema, comments

    def downgrade_comments_to_exact_legacy_v2(self) -> Path:
        path = self.root / "state" / "comments.sqlite3"
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("DROP TABLE comment_target")
            connection.execute("DROP TABLE comment_target_schema")
            connection.execute(
                "INSERT INTO actor VALUES(?,?,?,?)",
                (
                    "legacy_actor",
                    "other",
                    "Legacy Actor",
                    "2000-01-01T00:00:00.000000Z",
                ),
            )
            connection.execute(
                """
                INSERT INTO comment(
                    comment_id,research_id,actor_id,body,created_at,updated_at,
                    revision,deleted_at
                ) VALUES(?,?,?,?,?,?,1,NULL)
                """,
                (
                    "legacy_comment",
                    "legacy_research",
                    "legacy_actor",
                    "legacy body",
                    "2000-01-01T00:00:00.000000Z",
                    "2000-01-01T00:00:00.000000Z",
                ),
            )
            connection.execute(
                "INSERT INTO comment_event VALUES(?,?, 'create',NULL,?,?,1,?)",
                (
                    "legacy_event",
                    "legacy_comment",
                    digest("legacy body"),
                    "legacy_actor",
                    "2000-01-01T00:00:00.000000Z",
                ),
            )
        return path

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

    def test_bootstrap_expands_exact_legacy_comments_then_seals_and_canaries(self) -> None:
        path = self.downgrade_comments_to_exact_legacy_v2()

        for operation in ("activate_successor", "rollback_to_prior"):
            with self.subTest(operation=operation), self.assertRaisesRegex(
                LocalDeploymentRuntimeError, "marker"
            ):
                self.runtime.seal_database(
                    attempt_id=f"ordinary-before-expand-{operation}",
                    nonce=f"ordinary-before-expand-{operation}-nonce",
                    operation=operation,
                    database_name="comments",
                    state_identity_sha256=digest("state"),
                    compatibility_manifest=self.compatibility(
                        "comments", operation=operation
                    ),
                )

        with self.locked_bootstrap_expand() as (
            authorization,
            compatibility,
            workspace,
            state_identity_sha256,
        ):
            expanded = self.runtime.expand_bootstrap_comment_schema(
                authorization=authorization,
                compatibility_manifest=compatibility,
            )
            self.assertEqual(
                1, expanded["backfilled_comment_targets"]
            )
            self.assertEqual(
                {
                    "logical_version": 2,
                    "comment_store_schema": [1, 2],
                    "comment_target_schema": [3],
                },
                expanded["logical_schema"],
            )
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(
                    [(3,)],
                    connection.execute(
                        "SELECT version FROM comment_target_schema ORDER BY version"
                    ).fetchall(),
                )
                self.assertEqual(
                    [("legacy_comment", "research", "legacy_research")],
                    connection.execute(
                        """
                        SELECT comment_id,target_kind,research_id
                        FROM comment_target ORDER BY comment_id
                        """
                    ).fetchall(),
                )

            replay = self.runtime.expand_bootstrap_comment_schema(
                authorization=authorization,
                compatibility_manifest=compatibility,
            )
            self.assertEqual(0, replay["backfilled_comment_targets"])

            seal = self.runtime.seal_database(
                attempt_id="bootstrap-legacy-v2",
                nonce="bootstrap-legacy-v2-nonce",
                operation="bootstrap_first_pair",
                database_name="comments",
                state_identity_sha256=state_identity_sha256,
                compatibility_manifest=compatibility,
            )
            self.assertEqual(
                state_identity_sha256,
                seal.as_dict()["state_identity_sha256"],
            )
            self.assertEqual(
                [3], seal.as_dict()["logical_schema"]["comment_target_schema"]
            )
            for operation in ("activate_successor", "rollback_to_prior"):
                ordinary = self.runtime.seal_database(
                    attempt_id=f"ordinary-after-expand-{operation}",
                    nonce=f"ordinary-after-expand-{operation}-nonce",
                    operation=operation,
                    database_name="comments",
                    state_identity_sha256=state_identity_sha256,
                    compatibility_manifest=self.compatibility(
                        "comments", operation=operation
                    ),
                )
                self.assertEqual(
                    [3],
                    ordinary.as_dict()["logical_schema"]["comment_target_schema"],
                )

            copied = self.runtime.create_isolated_copy(
                workspace=workspace,
                operation="bootstrap_first_pair",
                database_name="comments",
                state_identity_sha256=state_identity_sha256,
                compatibility_manifest=compatibility,
            )
            canary = self.runtime.run_controller_canary(
                workspace=workspace,
                database_name="comments",
                copy_evidence=copied.copy_evidence,
            )
            self.assertEqual(1, canary.as_dict()["challenge"]["applied_rowcount"])
            self.assertEqual(0, canary.as_dict()["challenge"]["stale_rowcount"])

    def test_bootstrap_comment_expand_failure_rolls_back_partial_schema_and_facts(self) -> None:
        path = self.downgrade_comments_to_exact_legacy_v2()
        with closing(sqlite3.connect(path)) as connection:
            before_schema = connection.execute(
                "SELECT type,name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall()
            before_facts = connection.execute(
                "SELECT * FROM comment ORDER BY comment_id"
            ).fetchall()
        before_identity = path.stat()

        def fail_after_partial_backfill(connection: sqlite3.Connection) -> int:
            connection.execute(
                """
                INSERT INTO comment_target(
                    comment_target_id,comment_id,target_kind,research_id,created_at
                ) VALUES('partial_target','legacy_comment','research',
                         'legacy_research','2000-01-01T00:00:00.000000Z')
                """
            )
            raise RuntimeError("injected backfill failure")

        with self.locked_bootstrap_expand(
            attempt="bootstrap-expand-failure",
            nonce="bootstrap-expand-failure-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            with patch(
                "quant_hub.collaboration.comment_store._backfill_legacy_comment_targets",
                side_effect=fail_after_partial_backfill,
            ), self.assertRaisesRegex(LocalDeploymentRuntimeError, "原子扩展失败"):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(
                    0,
                    connection.execute(
                        "SELECT count(*) FROM sqlite_master WHERE name LIKE 'comment_target%'"
                    ).fetchone()[0],
                )

            with patch(
                "quant_hub.ops.local_deployment_runtime._inspect_connection",
                side_effect=LocalDeploymentRuntimeError(
                    "injected verification failure"
                ),
            ), self.assertRaisesRegex(
                LocalDeploymentRuntimeError, "injected verification failure"
            ):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )

        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(
                before_schema,
                connection.execute(
                    "SELECT type,name,sql FROM sqlite_master ORDER BY type,name"
                ).fetchall(),
            )
            self.assertEqual(
                before_facts,
                connection.execute("SELECT * FROM comment ORDER BY comment_id").fetchall(),
            )
            self.assertEqual(
                0,
                connection.execute(
                    "SELECT count(*) FROM sqlite_master WHERE name LIKE 'comment_target%'"
                ).fetchone()[0],
            )
        after_identity = path.stat()
        self.assertEqual(
            (before_identity.st_dev, before_identity.st_ino),
            (after_identity.st_dev, after_identity.st_ino),
        )

    def test_bootstrap_comment_expand_rejects_direct_empty_and_no_journal_without_db_write(
        self,
    ) -> None:
        path = self.downgrade_comments_to_exact_legacy_v2()
        compatibility = self.bootstrap_compatibility("comments")
        before = self.database_snapshot(path)

        with self.assertRaisesRegex(
            LocalDeploymentRuntimeError,
            "exact locked authorization",
        ):
            self.runtime.expand_bootstrap_comment_schema(
                authorization=None,  # type: ignore[arg-type]
                compatibility_manifest=compatibility,
            )
        with self.assertRaisesRegex(
            LocalDeploymentRuntimeError,
            "exact locked authorization",
        ):
            self.runtime.expand_bootstrap_comment_schema(
                authorization=object(),  # type: ignore[arg-type]
                compatibility_manifest=compatibility,
            )
        with self.assertRaises(TypeError):
            self.runtime.expand_bootstrap_comment_schema(  # type: ignore[call-arg]
                attempt_id="caller-self-report",
                nonce="caller-self-report-nonce",
                operation="bootstrap_first_pair",
                database_name="comments",
                state_identity_sha256=digest("state"),
                compatibility_manifest=compatibility,
            )
        with self.persistence.global_lock() as lock:
            with self.assertRaisesRegex(
                DeploymentLockBusy,
                "exact lock/workspace",
            ):
                self.persistence.lock_bootstrap_comment_schema_expand_authorization(
                    lock,
                    object(),  # type: ignore[arg-type]
                )
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "missing-journal",
                "missing-journal-nonce",
            )
            try:
                with self.assertRaisesRegex(
                    DeploymentJournalError,
                    "journal 不存在",
                ):
                    self.persistence.lock_bootstrap_comment_schema_expand_authorization(
                        lock,
                        workspace,
                    )
            finally:
                workspace.close()

        self.assertEqual(before, self.database_snapshot(path))

    def test_bootstrap_comment_expand_rejects_released_locked_authorization_without_db_write(
        self,
    ) -> None:
        path = self.downgrade_comments_to_exact_legacy_v2()
        with self.locked_bootstrap_expand(
            attempt="released-authorization",
            nonce="released-authorization-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            pass
        before = self.database_snapshot(path)
        with self.assertRaisesRegex(
            LocalDeploymentRuntimeError,
            "authorization 已失效",
        ):
            self.runtime.expand_bootstrap_comment_schema(
                authorization=authorization,
                compatibility_manifest=compatibility,
            )
        self.assertEqual(before, self.database_snapshot(path))

    def test_bootstrap_comment_expand_rejects_expected_names_with_wrong_master_types(
        self,
    ) -> None:
        path = self.downgrade_comments_to_exact_legacy_v2()
        names = (
            "comment_target",
            "comment_target_comment_identity",
            "comment_target_document_idx",
            "comment_target_no_delete",
            "comment_target_no_update",
            "comment_target_origin_version_idx",
            "comment_target_schema",
        )
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            for name in names:
                connection.execute(f'CREATE TABLE "{name}"(value INTEGER)')
        before = self.database_snapshot(path)
        with self.locked_bootstrap_expand(
            attempt="wrong-master-types",
            nonce="wrong-master-types-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            with self.assertRaisesRegex(
                LocalDeploymentRuntimeError,
                "原子扩展失败",
            ):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )
        self.assertEqual(before, self.database_snapshot(path))

    def test_bootstrap_comment_expand_rejects_simplified_same_type_schema_shape(
        self,
    ) -> None:
        path = self.downgrade_comments_to_exact_legacy_v2()
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.executescript(
                """
                CREATE TABLE comment_target_schema(
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT
                );
                INSERT INTO comment_target_schema VALUES(3,'fake');
                CREATE TABLE comment_target(
                    comment_target_id TEXT PRIMARY KEY,
                    comment_id TEXT UNIQUE,
                    target_kind TEXT,
                    research_id TEXT,
                    document_id TEXT,
                    origin_document_version_id TEXT
                );
                CREATE INDEX comment_target_document_idx
                ON comment_target(research_id,document_id,target_kind,comment_id);
                CREATE INDEX comment_target_origin_version_idx
                ON comment_target(origin_document_version_id,comment_id);
                CREATE TRIGGER comment_target_comment_identity
                BEFORE INSERT ON comment_target BEGIN SELECT 1; END;
                CREATE TRIGGER comment_target_no_update
                BEFORE UPDATE ON comment_target BEGIN SELECT 1; END;
                CREATE TRIGGER comment_target_no_delete
                BEFORE DELETE ON comment_target BEGIN SELECT 1; END;
                """
            )
        before = self.database_snapshot(path)
        with self.locked_bootstrap_expand(
            attempt="simplified-target-schema",
            nonce="simplified-target-schema-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            with self.assertRaisesRegex(
                LocalDeploymentRuntimeError,
                "原子扩展失败",
            ):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )
        self.assertEqual(before, self.database_snapshot(path))

    def test_bootstrap_comment_expand_rejects_extra_trigger_on_target_without_db_write(
        self,
    ) -> None:
        path = self.root / "state" / "comments.sqlite3"
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.execute(
                """
                CREATE TRIGGER rogue_target_trigger
                AFTER INSERT ON comment_target BEGIN SELECT 1; END
                """
            )
        before = self.database_snapshot(path)
        with self.locked_bootstrap_expand(
            attempt="extra-target-trigger",
            nonce="extra-target-trigger-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            with self.assertRaisesRegex(
                LocalDeploymentRuntimeError,
                "原子扩展失败",
            ):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )
        self.assertEqual(before, self.database_snapshot(path))

    def test_bootstrap_comment_expand_rejects_extra_index_on_target_without_db_write(
        self,
    ) -> None:
        path = self.root / "state" / "comments.sqlite3"
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.execute(
                "CREATE INDEX rogue_target_index ON comment_target(research_id)"
            )
        before = self.database_snapshot(path)
        with self.locked_bootstrap_expand(
            attempt="extra-target-index",
            nonce="extra-target-index-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            with self.assertRaisesRegex(
                LocalDeploymentRuntimeError,
                "原子扩展失败",
            ):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )
        self.assertEqual(before, self.database_snapshot(path))

    def test_bootstrap_comment_expand_rejects_extra_prefixed_table_without_db_write(
        self,
    ) -> None:
        path = self.root / "state" / "comments.sqlite3"
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.execute(
                "CREATE TABLE comment_target_shadow(value TEXT) STRICT"
            )
        before = self.database_snapshot(path)
        with self.locked_bootstrap_expand(
            attempt="extra-target-table",
            nonce="extra-target-table-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            with self.assertRaisesRegex(
                LocalDeploymentRuntimeError,
                "原子扩展失败",
            ):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )
        self.assertEqual(before, self.database_snapshot(path))

    def test_bootstrap_comment_expand_rejects_case_variant_target_objects_without_db_write(
        self,
    ) -> None:
        path = self.root / "state" / "comments.sqlite3"
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.executescript(
                """
                CREATE TABLE COMMENT_TARGET_EVIL(value TEXT) STRICT;
                CREATE INDEX CASE_ROGUE_INDEX ON COMMENT_TARGET(research_id);
                CREATE TRIGGER CASE_ROGUE_TRIGGER
                AFTER INSERT ON COMMENT_TARGET BEGIN SELECT 1; END;
                """
            )
        before = self.database_snapshot(path)
        with self.locked_bootstrap_expand(
            attempt="case-variant-target-objects",
            nonce="case-variant-target-objects-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            with self.assertRaisesRegex(
                LocalDeploymentRuntimeError,
                "原子扩展失败",
            ):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )
        self.assertEqual(before, self.database_snapshot(path))

    @unittest.skipIf(os.name == "nt", "POSIX test-only identity guard")
    def test_posix_mutable_guard_rejects_replacement_fd_even_with_pinned_decoy(
        self,
    ) -> None:
        main = self.root / "state" / "comments.sqlite3"
        replacement = self.root / "tmp" / "decoy-replacement.sqlite3"
        initialize_comment_store(replacement)
        with _MutableSqliteIdentityGuardSet(
            [main], allow_posix_test_only=True
        ) as guard:
            guard.capture_connection_open_baseline()
            replacement_fd = os.open(replacement, os.O_RDONLY)
            decoy_fd = os.open(main, os.O_RDONLY)
            try:
                with self.assertRaisesRegex(
                    LocalDeploymentRuntimeError,
                    "未钉扎的 regular file identity",
                ):
                    guard._assert_posix_connection_main_identity(main)
            finally:
                os.close(decoy_fd)
                os.close(replacement_fd)

    def test_bootstrap_comment_expand_rejects_path_replacement_before_sqlite_open(
        self,
    ) -> None:
        path = self.downgrade_comments_to_exact_legacy_v2()
        replacement = self.root / "tmp" / "replacement-comments.sqlite3"
        displaced = self.root / "tmp" / "displaced-comments.sqlite3"
        initialize_comment_store(replacement)
        with closing(sqlite3.connect(replacement, isolation_level=None)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("DROP TABLE comment_target")
            connection.execute("DROP TABLE comment_target_schema")
        original_before = self.database_snapshot(path)
        replacement_before = self.database_snapshot(replacement)
        real_connect = sqlite3.connect
        replacement_attempted = False

        def replace_before_sqlite_open(*args: object, **kwargs: object):
            nonlocal replacement_attempted
            if not replacement_attempted:
                replacement_attempted = True
                os.replace(path, displaced)
                os.replace(replacement, path)
            return real_connect(*args, **kwargs)

        with self.locked_bootstrap_expand(
            attempt="replace-before-sqlite-open",
            nonce="replace-before-sqlite-open-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            with patch(
                "quant_hub.ops.local_deployment_runtime.sqlite3.connect",
                side_effect=replace_before_sqlite_open,
            ), self.assertRaises(LocalDeploymentRuntimeError):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )

        self.assertTrue(replacement_attempted)
        original_after_path = displaced if displaced.exists() else path
        replacement_after_path = path if displaced.exists() else replacement
        self.assertEqual(
            original_before,
            self.database_snapshot(original_after_path),
        )
        self.assertEqual(
            replacement_before,
            self.database_snapshot(replacement_after_path),
        )

    def test_bootstrap_comment_expand_rejects_path_aba_around_sqlite_open(
        self,
    ) -> None:
        path = self.downgrade_comments_to_exact_legacy_v2()
        replacement = self.root / "tmp" / "aba-replacement-comments.sqlite3"
        displaced_original = self.root / "tmp" / "aba-original-comments.sqlite3"
        displaced_replacement = (
            self.root / "tmp" / "aba-opened-replacement-comments.sqlite3"
        )
        initialize_comment_store(replacement)
        with closing(sqlite3.connect(replacement, isolation_level=None)) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("DROP TABLE comment_target")
            connection.execute("DROP TABLE comment_target_schema")
        original_before = self.database_snapshot(path)
        replacement_before = self.database_snapshot(replacement)
        real_connect = sqlite3.connect
        aba_attempted = False

        def aba_around_sqlite_open(*args: object, **kwargs: object):
            nonlocal aba_attempted
            if aba_attempted:
                return real_connect(*args, **kwargs)
            aba_attempted = True
            os.replace(path, displaced_original)
            os.replace(replacement, path)
            connection = real_connect(*args, **kwargs)
            os.replace(path, displaced_replacement)
            os.replace(displaced_original, path)
            return connection

        with self.locked_bootstrap_expand(
            attempt="aba-around-sqlite-open",
            nonce="aba-around-sqlite-open-nonce",
        ) as (authorization, compatibility, _workspace, _state_identity):
            with patch(
                "quant_hub.ops.local_deployment_runtime.sqlite3.connect",
                side_effect=aba_around_sqlite_open,
            ), self.assertRaises(LocalDeploymentRuntimeError):
                self.runtime.expand_bootstrap_comment_schema(
                    authorization=authorization,
                    compatibility_manifest=compatibility,
                )

        self.assertTrue(aba_attempted)
        original_after_path = path
        replacement_after_path = (
            displaced_replacement
            if displaced_replacement.exists()
            else replacement
        )
        self.assertEqual(
            original_before,
            self.database_snapshot(original_after_path),
        )
        self.assertEqual(
            replacement_before,
            self.database_snapshot(replacement_after_path),
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
