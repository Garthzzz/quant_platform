from __future__ import annotations

import copy
import hashlib
import inspect
import os
from pathlib import Path
import pickle
import sqlite3
import tempfile
import unittest
from unittest import mock

from quant_hub.collaboration.comment_store import initialize_comment_store
from quant_hub.config import Settings
from quant_hub.ops.local_exact_runtime_canary_evidence import (
    EXACT_RUNTIME_CANARY_RESULT,
    build_exact_runtime_canary_request,
)
from quant_hub.ops.local_exact_runtime_canary_runner import (
    ExactRuntimeCanaryRunner,
    ExactRuntimeCanaryRunnerError,
)
from quant_hub.ops import local_exact_runtime_canary_runner as runner_module
from quant_hub.ops import local_windows_writer_lease_holder as holder_module
from quant_hub.ops.local_release_identity import canonical_bytes
from quant_hub.ops.local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity
from quant_hub.ops.local_windows_writer_lease_holder import WindowsWriterLeaseBusy
from quant_hub.platform import db as platform_db
from quant_hub.research_workspace.service import ResearchWorkspace


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


@unittest.skipUnless(os.name == "nt", "真实 Win32 writer lease canary 只在 Windows 执行")
class ExactRuntimeCanaryRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(
            prefix="qrh-exact-canary-", dir=Path.cwd()
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve(strict=True)
        (self.root / "state").mkdir()
        (self.root / "tmp" / "service").mkdir(parents=True)
        self.identity = ExactRuntimeLeaseIdentity(
            attempt_id="exact-canary-attempt",
            nonce="exact-canary-deployment-nonce",
            operation="activation",
            role="candidate",
            start_nonce="exact-canary-start-nonce",
            state_identity_sha256="c" * 64,
            release_id="release-r1",
            manifest_sha256="d" * 64,
        )
        self.lease_adapter = (
            holder_module._TestOnlyWindowsWriterLeaseHolderAdapter.load()
        )
        self.runner = (
            runner_module._TestOnlyExactRuntimeCanaryRunnerAdapter.for_test_only()
        )
        self.base = (
            self.root
            / "tmp"
            / "deployment-attempts"
            / f"{self.identity.attempt_id}-{self.identity.nonce}"
            / "runtime-canary"
            / self.identity.role
        )
        self.state = self.base / "state"
        self.state.mkdir(parents=True)
        (self.base / "tmp").mkdir()
        self._prepare_databases()
        fixture_lease = self.lease_adapter.acquire(self.root, self.identity)
        try:
            initial_views = {
                filename: runner_module._capture_consistent_view(
                    fixture_lease, self.state / filename
                )
                for filename in ("comments.sqlite3", "research_workspace.sqlite3")
            }
            for filename in ("comments.sqlite3", "research_workspace.sqlite3"):
                runner_module._normalize_main_only(
                    fixture_lease, self.state / filename
                )
        finally:
            fixture_lease.close()
        self.request = self._write_request(initial_views)
        self.lease = self.lease_adapter.acquire(self.root, self.identity)
        self.addCleanup(self._close_lease)

    def _close_lease(self) -> None:
        if getattr(self.lease, "_state", None) == "live":
            self.lease.close()

    def _fixture_settings(self) -> Settings:
        project = self.root / "fixture-project"
        var = self.root / "fixture-var"
        migrations = Path(__file__).resolve().parents[1] / "migrations" / "platform"
        return Settings(
            project_root=project,
            archive_root=project / "reference" / "archive",
            var_root=var,
            database_path=var / "db" / "platform.sqlite3",
            object_root=var / "objects",
            migration_root=migrations,
        )

    def _prepare_databases(self) -> None:
        comments = self.state / "comments.sqlite3"
        initialize_comment_store(comments)

        settings = self._fixture_settings()
        settings.archive_root.mkdir(parents=True)
        document = (
            settings.research_workspace_root
            / "01_canary_project"
            / "01_canary_document.md"
        )
        document.parent.mkdir(parents=True)
        document.write_text("# Canary document\n\nfixture\n", encoding="utf-8")
        workspace = ResearchWorkspace(
            settings,
            database_path=self.state / "research_workspace.sqlite3",
        )
        workspace.sync()
        self.assertTrue(workspace.tree()["items"])

    def _write_request(self, initial_views: dict[str, dict[str, object]]):
        databases = []
        for index, (name, filename) in enumerate(
            (
                ("comments", "comments.sqlite3"),
                ("research_workspace", "research_workspace.sqlite3"),
            ),
            start=1,
        ):
            view = initial_views[filename]
            databases.append(
                {
                    "database_name": name,
                    "relative_path": (
                        f"tmp/deployment-attempts/{self.identity.attempt_id}-"
                        f"{self.identity.nonce}/"
                        f"runtime-canary/{self.identity.role}/state/{filename}"
                    ),
                    "source_seal_sha256": _hash(f"source-{index}"),
                    "isolated_copy_evidence_sha256": _hash(f"copy-{index}"),
                    "compatibility_evidence_sha256": _hash(f"compat-{index}"),
                    "initial_consistent_bytes": view["bytes"],
                    "initial_consistent_sha256": view["sha256"],
                }
            )
        document = build_exact_runtime_canary_request(
            {
                "schema_version": "qrh-exact-runtime-canary-request/v1",
                "scope": "exact_runtime_canary_request_only",
                "attempt_id": self.identity.attempt_id,
                "nonce": self.identity.nonce,
                "operation": self.identity.operation,
                "role": self.identity.role,
                "start_nonce": self.identity.start_nonce,
                "authorization_sha256": self.identity.authorization_sha256,
                "scm_identity_sha256": self.identity.scm_identity_sha256,
                "state_identity_sha256": self.identity.state_identity_sha256,
                "release": {
                    "release_id": self.identity.release_id,
                    "release_path": self.identity.release_path,
                    "manifest_sha256": self.identity.manifest_sha256,
                },
                "databases": databases,
            }
        )
        raw = canonical_bytes(document)
        (self.base / "request.json").write_bytes(raw)
        return document

    @staticmethod
    def _database_snapshot(path: Path, statements: tuple[str, ...]) -> tuple[object, ...]:
        connection = sqlite3.connect(path)
        try:
            return tuple(connection.execute(statement).fetchall() for statement in statements)
        finally:
            connection.close()

    def test_real_file_canary_runs_under_same_live_lease_and_replays_exact_result(self) -> None:
        challenge = "ab" * 24
        evidence = self.runner.run(self.lease, challenge)
        document = evidence.as_dict()
        self.assertEqual(EXACT_RUNTIME_CANARY_RESULT, document["result"])
        self.assertEqual(challenge, document["challenge_nonce"])
        self.assertEqual(
            self.lease.record_document["lease_record_sha256"],
            document["writer_lease_claim"]["lease_record_sha256"],
        )
        self.assertEqual(
            ["comments", "research_workspace"],
            [item["database_name"] for item in document["databases"]],
        )
        self.assertEqual(
            [["main"], ["main"]],
            [item["final_members"] for item in document["databases"]],
        )
        self.assertFalse(tuple(self.state.glob("*.sqlite3-*")))
        self.assertFalse(tuple((self.base / "tmp").iterdir()))
        self.assertTrue((self.base / "result.json").is_file())
        replay = self.runner.run(self.lease, challenge)
        self.assertEqual(evidence.canonical_bytes(), replay.canonical_bytes())
        with self.assertRaises(ExactRuntimeCanaryRunnerError):
            self.runner.run(self.lease, "cd" * 24)

    def test_sidecar_created_after_normalization_never_publishes_result(self) -> None:
        original = runner_module._normalize_main_only
        injected = False

        def normalize_then_inject(lease, path):
            nonlocal injected
            original(lease, path)
            if not injected:
                Path(str(path) + "-wal").write_bytes(
                    b"post-normalization-third-value"
                )
                injected = True

        with mock.patch.object(
            runner_module,
            "_normalize_main_only",
            side_effect=normalize_then_inject,
        ), self.assertRaisesRegex(
            ExactRuntimeCanaryRunnerError,
            "main-only",
        ):
            self.runner.run(self.lease, "cd" * 24)
        self.assertTrue(injected)
        self.assertFalse((self.base / "result.json").exists())

    def test_existing_result_post_read_sidecar_never_returns_replay(self) -> None:
        challenge = "ab" * 24
        self.runner.run(self.lease, challenge)
        original = runner_module._read_existing_result
        injected = False

        def read_then_inject(*args, **kwargs):
            nonlocal injected
            observed = original(*args, **kwargs)
            Path(str(self.state / "comments.sqlite3") + "-wal").write_bytes(
                b"existing-result-post-read-third-value"
            )
            injected = True
            return observed

        with mock.patch.object(
            runner_module,
            "_read_existing_result",
            side_effect=read_then_inject,
        ), self.assertRaisesRegex(
            ExactRuntimeCanaryRunnerError,
            "main-only",
        ):
            self.runner.run(self.lease, challenge)
        self.assertTrue(injected)

    def test_initial_consistent_mismatch_fails_before_any_canary_write(self) -> None:
        changed = copy.deepcopy(self.request)
        changed["databases"][0]["initial_consistent_sha256"] = _hash("wrong")
        for database in changed["databases"]:
            database.pop("request_database_sha256")
        changed.pop("database_order_sha256")
        changed.pop("request_sha256")
        changed = build_exact_runtime_canary_request(
            {
                key: value
                for key, value in changed.items()
                if key not in {"database_order_sha256", "request_sha256"}
            }
        )
        (self.base / "request.json").write_bytes(canonical_bytes(changed))
        with self.assertRaises(ExactRuntimeCanaryRunnerError):
            self.runner.run(self.lease, "ab" * 24)
        for path in self.state.glob("*.sqlite3"):
            connection = sqlite3.connect(path)
            try:
                count = connection.execute(
                    "SELECT count(*) FROM sqlite_master WHERE name='deployment_canary'"
                ).fetchone()[0]
            finally:
                connection.close()
            self.assertEqual(0, count)

    def test_record_drift_and_revoked_lease_fail_before_runner_authority(self) -> None:
        record_path = self.root / "state" / "writer_lease.json"
        original = record_path.read_bytes()
        record_path.write_bytes(original + b"\n")
        with self.assertRaises(ExactRuntimeCanaryRunnerError):
            self.runner.run(self.lease, "ab" * 24)
        record_path.write_bytes(original)
        self.lease.close()
        with self.assertRaises(ExactRuntimeCanaryRunnerError):
            self.runner.run(self.lease, "ab" * 24)

    def test_record_drift_after_first_challenge_insert_rolls_back_and_lock_stays_busy(self) -> None:
        record_path = self.root / "state" / "writer_lease.json"
        original_record = record_path.read_bytes()
        original_execute = runner_module._execute_write
        drifted = False

        def drift_after_insert(lease, connection, sql, parameters=()):
            nonlocal drifted
            cursor = original_execute(lease, connection, sql, parameters)
            if not drifted and sql.strip().startswith(
                "INSERT INTO deployment_canary(challenge_id,revision)"
            ):
                drifted = True
                record_path.write_bytes(original_record + b"\n")
            return cursor

        try:
            with mock.patch.object(
                runner_module, "_execute_write", side_effect=drift_after_insert
            ):
                with self.assertRaises(ExactRuntimeCanaryRunnerError):
                    self.runner.run(self.lease, "ab" * 24)
        finally:
            record_path.write_bytes(original_record)
        self.assertTrue(drifted)
        self.assertFalse((self.base / "result.json").exists())
        connection = sqlite3.connect(self.state / "comments.sqlite3")
        try:
            count = connection.execute(
                "SELECT count(*) FROM sqlite_master WHERE name='deployment_canary'"
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(0, count)
        with self.assertRaises(WindowsWriterLeaseBusy):
            self.lease_adapter.acquire(self.root, self.identity)

    def test_archive_application_write_drift_rolls_back_before_commit(self) -> None:
        database = self.state / "comments.sqlite3"
        statements = (
            "SELECT comment_id,revision,deleted_at FROM comment ORDER BY comment_id",
            "SELECT comment_event_id,revision FROM comment_event ORDER BY comment_event_id",
            "SELECT idempotency_key,outcome,http_status FROM command_receipt ORDER BY idempotency_key",
            "SELECT event_id,event_type FROM outbox_event ORDER BY event_id",
        )
        before = self._database_snapshot(database, statements)
        record_path = self.root / "state" / "writer_lease.json"
        original_record = record_path.read_bytes()
        connection_type = platform_db._ExactRuntimeWriterFencedConnection
        original_execute = connection_type.execute
        drifted = False

        def drift_after_comment_insert(connection, sql, parameters=()):
            nonlocal drifted
            cursor = original_execute(connection, sql, parameters)
            normalized = " ".join(sql.split()).casefold()
            if not drifted and "insert into comment(" in normalized:
                drifted = True
                record_path.write_bytes(original_record + b"\n")
            return cursor

        try:
            with mock.patch.object(
                connection_type, "execute", new=drift_after_comment_insert
            ):
                with self.assertRaises(ExactRuntimeCanaryRunnerError):
                    self.runner.run(self.lease, "ab" * 24)
        finally:
            record_path.write_bytes(original_record)
        self.assertTrue(drifted)
        self.assertEqual(before, self._database_snapshot(database, statements))
        self.assertFalse((self.base / "result.json").exists())
        with self.assertRaises(WindowsWriterLeaseBusy):
            self.lease_adapter.acquire(self.root, self.identity)

    def test_workspace_application_write_drift_rolls_back_before_commit(self) -> None:
        database = self.state / "research_workspace.sqlite3"
        statements = (
            "SELECT node_id,revision FROM research_workspace_node ORDER BY node_id",
            "SELECT comment_id,revision,deleted_at FROM research_workspace_comment ORDER BY comment_id",
            "SELECT comment_event_id,revision FROM research_workspace_comment_event ORDER BY comment_event_id",
            "SELECT event_id,event_kind FROM research_workspace_event ORDER BY event_id",
            "SELECT idempotency_key,outcome_json,http_status FROM research_workspace_command_receipt ORDER BY idempotency_key",
        )
        before = self._database_snapshot(database, statements)
        record_path = self.root / "state" / "writer_lease.json"
        original_record = record_path.read_bytes()
        connection_type = platform_db._ExactRuntimeWriterFencedConnection
        original_execute = connection_type.execute
        drifted = False

        def drift_after_workspace_comment_insert(connection, sql, parameters=()):
            nonlocal drifted
            cursor = original_execute(connection, sql, parameters)
            normalized = " ".join(sql.split()).casefold()
            if (
                not drifted
                and "insert into research_workspace_comment(" in normalized
            ):
                drifted = True
                record_path.write_bytes(original_record + b"\n")
            return cursor

        try:
            with mock.patch.object(
                connection_type,
                "execute",
                new=drift_after_workspace_comment_insert,
            ):
                with self.assertRaises(ExactRuntimeCanaryRunnerError):
                    self.runner.run(self.lease, "ab" * 24)
        finally:
            record_path.write_bytes(original_record)
        self.assertTrue(drifted)
        self.assertEqual(before, self._database_snapshot(database, statements))
        self.assertFalse((self.base / "result.json").exists())
        with self.assertRaises(WindowsWriterLeaseBusy):
            self.lease_adapter.acquire(self.root, self.identity)

    def test_result_publication_is_create_only_and_preserves_racing_third_value(self) -> None:
        original_publish = runner_module._write_through_replace
        foreign = b'{"foreign":true}'

        def race_publish(api, *, tmp_dir, final_path, raw, replace_existing=True):
            self.assertFalse(replace_existing)
            final_path.write_bytes(foreign)
            return original_publish(
                api,
                tmp_dir=tmp_dir,
                final_path=final_path,
                raw=raw,
                replace_existing=replace_existing,
            )

        with mock.patch.object(
            runner_module, "_write_through_replace", side_effect=race_publish
        ):
            with self.assertRaises(ExactRuntimeCanaryRunnerError):
                self.runner.run(self.lease, "ab" * 24)
        self.assertEqual(foreign, (self.base / "result.json").read_bytes())
        self.assertFalse(any((self.base / "tmp").glob("writer-lease-*.tmp")))

    def test_unknown_layout_member_and_boolean_challenge_fail_before_write(self) -> None:
        extra = self.state / "unexpected.sqlite3"
        extra.write_bytes(b"not a database")
        with self.assertRaises(ExactRuntimeCanaryRunnerError):
            self.runner.run(self.lease, "ab" * 24)
        extra.unlink()
        with self.assertRaises(ExactRuntimeCanaryRunnerError):
            self.runner.run(self.lease, True)  # type: ignore[arg-type]
        self.assertFalse((self.base / "result.json").exists())

    def test_product_surface_rejects_test_lease_and_injection(self) -> None:
        product = ExactRuntimeCanaryRunner.load_exact_d()
        self.assertEqual(
            ["self", "lease", "challenge_nonce"],
            list(inspect.signature(ExactRuntimeCanaryRunner.run).parameters),
        )
        self.assertEqual(
            [],
            list(inspect.signature(ExactRuntimeCanaryRunner.load_exact_d).parameters),
        )
        with self.assertRaises(TypeError):
            product.run(self.lease, "ab" * 24)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            pickle.dumps(product)
        self.assertNotIn(
            "_TestOnlyExactRuntimeCanaryRunnerAdapter", runner_module.__all__
        )
        self.assertEqual(
            {"ExactRuntimeCanaryRunner", "ExactRuntimeCanaryRunnerError"},
            set(runner_module.__all__),
        )
        with self.assertRaises(ExactRuntimeCanaryRunnerError):
            runner_module._assert_exact_release_application_loaded(self.root)


if __name__ == "__main__":
    unittest.main()
