from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
import unittest
from contextlib import closing
from unittest.mock import patch

from quant_hub.collaboration import checkpoint as checkpoint_module
from quant_hub.collaboration.checkpoint import (
    CHECKPOINT_MANIFEST_HASH_NAME,
    CHECKPOINT_MANIFEST_NAME,
    CheckpointConflictError,
    CheckpointError,
    create_sqlite_checkpoint,
    validate_checkpoint_manifest,
    verify_sqlite_checkpoint,
)
from quant_hub.ops.release_identity import (
    canonical_manifest_bytes,
    manifest_sha256,
)


class SQLiteCheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.comments = self.root / "live" / "comments.sqlite3"
        self.workspace = self.root / "live" / "research_workspace.sqlite3"
        self.comments.parent.mkdir(parents=True)
        with closing(sqlite3.connect(self.comments)) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript(
                """
                PRAGMA user_version=2;
                CREATE TABLE actor(actor_id TEXT PRIMARY KEY,display_name TEXT NOT NULL);
                CREATE TABLE comment(
                    comment_id TEXT PRIMARY KEY,
                    actor_id TEXT NOT NULL REFERENCES actor(actor_id),
                    body TEXT NOT NULL
                );
                INSERT INTO actor VALUES('act_1','研究员');
                INSERT INTO comment VALUES('com_1','act_1','已提交评论');
                """
            )
            connection.commit()
        with closing(sqlite3.connect(self.workspace)) as connection:
            connection.executescript(
                """
                PRAGMA user_version=7;
                CREATE TABLE observation(observation_id TEXT PRIMARY KEY,note TEXT NOT NULL);
                INSERT INTO observation VALUES('obs_1','已提交观察');
                """
            )
            connection.commit()
        self.checkpoint_root = self.root / "checkpoints"
        self.release_hash = "a" * 64
        self.captured_at = datetime(2026, 8, 21, 1, 2, 3, tzinfo=UTC)

    def _create(self, checkpoint_id: str = "checkpoint-20260821-0001"):
        return create_sqlite_checkpoint(
            sources={
                "comments": self.comments,
                "research_workspace": self.workspace,
            },
            checkpoint_root=self.checkpoint_root,
            checkpoint_id=checkpoint_id,
            state_authority_id="quant-platform-d-state",
            captured_under_release_id="release-v39-test",
            captured_under_manifest_sha256=self.release_hash,
            captured_at=self.captured_at,
            allow_test_root=True,
        )

    def test_online_backup_is_immutable_complete_and_restorable(self) -> None:
        # A WAL writer remains open with an uncommitted change.  Online backup
        # must remain usable and capture only committed source state.
        writer = sqlite3.connect(self.comments, timeout=5)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("BEGIN IMMEDIATE")
        writer.execute(
            "INSERT INTO comment VALUES('com_uncommitted','act_1','尚未提交')"
        )

        created = self._create()
        report = verify_sqlite_checkpoint(created.root)
        self.assertTrue(report.valid, report.errors)
        self.assertEqual(self.captured_at, report.captured_at)
        self.assertEqual(2, report.database_count)

        manifest_bytes = created.manifest_path.read_bytes()
        manifest = json.loads(manifest_bytes)
        validate_checkpoint_manifest(manifest)
        self.assertEqual(canonical_manifest_bytes(manifest), manifest_bytes)
        self.assertEqual(created.manifest_sha256, manifest_sha256(manifest))
        self.assertEqual(
            created.manifest_sha256,
            (created.root / CHECKPOINT_MANIFEST_HASH_NAME)
            .read_text(encoding="ascii")
            .strip(),
        )
        self.assertEqual(
            {
                "release_id": "release-v39-test",
                "manifest_sha256": self.release_hash,
            },
            manifest["captured_under_active_release"],
        )
        self.assertEqual(
            "sqlite_online_backup", manifest["state"]["backup_protocol"]["name"]
        )
        self.assertFalse(manifest["state"]["backup_protocol"]["wal_shm_copied"])
        records = {
            item["logical_name"]: item for item in manifest["state"]["databases"]
        }
        self.assertEqual(1, records["comments"]["logical_counts"]["comment"])
        self.assertEqual(2, records["comments"]["schema"]["user_version"])
        self.assertEqual(7, records["research_workspace"]["schema"]["user_version"])
        self.assertTrue(records["comments"]["restore_validation"]["schema_matches"])
        self.assertFalse(
            any(
                path.name.endswith(("-wal", "-shm"))
                for path in created.root.rglob("*")
            )
        )

        # The writer can still commit after capture; the checkpoint remains
        # an immutable earlier recovery point.
        writer.commit()
        self.assertEqual(1, records["comments"]["logical_counts"]["comment"])
        self.assertTrue(verify_sqlite_checkpoint(created.root).valid)

    def test_restore_proof_uses_explicit_scratch_root_when_supplied(self) -> None:
        scratch = self.root / "vm-approved-scratch"
        original = tempfile.TemporaryDirectory
        observed: list[Path | None] = []

        def tracked(*args, **kwargs):
            raw_dir = kwargs.get("dir")
            observed.append(Path(raw_dir) if raw_dir is not None else None)
            return original(*args, **kwargs)

        with patch(
            "quant_hub.collaboration.checkpoint.tempfile.TemporaryDirectory",
            side_effect=tracked,
        ):
            created = create_sqlite_checkpoint(
                sources={"comments": self.comments},
                checkpoint_root=self.checkpoint_root,
                checkpoint_id="checkpoint-explicit-scratch",
                state_authority_id="quant-platform-d-state",
                captured_under_release_id="release-v39-test",
                captured_under_manifest_sha256=self.release_hash,
                captured_at=self.captured_at,
                scratch_root=scratch,
                allow_test_root=True,
            )
        self.assertTrue(verify_sqlite_checkpoint(created.root).valid)
        # Creation proves the copied databases and then re-verifies the whole
        # immutable checkpoint; both restore probes must stay in D scratch.
        self.assertEqual([scratch.resolve(), scratch.resolve()], observed)
        self.assertEqual([], list(scratch.iterdir()))

    def test_production_api_rejects_arbitrary_versioned_backup_root(self) -> None:
        with self.assertRaisesRegex(CheckpointError, "live writer-handoff authorization"):
            create_sqlite_checkpoint(
                sources={"comments": self.comments},
                checkpoint_root=self.root / "backups" / "state-versions",
                checkpoint_id="version-1",
                state_authority_id="quant-platform-d-state",
                captured_under_release_id="release-v39-test",
                captured_under_manifest_sha256=self.release_hash,
                captured_at=self.captured_at,
            )

    def test_test_flag_cannot_checkpoint_production_d_or_aliases_before_io(self) -> None:
        roots = (
            Path(r"D:\quant\quant_platform\backups\state-versions"),
            Path(r"D:\quant\quant_platform\.\backups\state-versions"),
            Path(r"D:\quant\quant_platform\child\..\backups\state-versions"),
            Path(r"d:/QUANT/quant_PLATFORM/backups/state-versions"),
        )
        with patch.object(
            Path,
            "mkdir",
            side_effect=AssertionError("checkpoint mkdir must not run"),
        ), patch(
            "quant_hub.collaboration.checkpoint._online_backup",
            side_effect=AssertionError("SQLite backup must not run"),
        ):
            for checkpoint_root in roots:
                with self.subTest(root=str(checkpoint_root)), self.assertRaisesRegex(
                    CheckpointError, "cannot target production D root"
                ):
                    create_sqlite_checkpoint(
                        sources={
                            "comments": Path(
                                r"D:\quant\quant_platform\state\comments.sqlite3"
                            )
                        },
                        checkpoint_root=checkpoint_root,
                        checkpoint_id="forbidden-state-version",
                        state_authority_id="quant-platform-d-state",
                        captured_under_release_id="release-r1",
                        captured_under_manifest_sha256=self.release_hash,
                        captured_at=self.captured_at,
                        allow_test_root=True,
                    )

    def test_reusing_checkpoint_id_fails_without_changing_existing_bytes(self) -> None:
        created = self._create()
        before = {
            path.relative_to(created.root).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in created.root.rglob("*")
            if path.is_file()
        }
        with closing(sqlite3.connect(self.comments)) as connection:
            connection.execute(
                "INSERT INTO comment VALUES('com_2','act_1','后来写入')"
            )
            connection.commit()
        with self.assertRaises(CheckpointConflictError):
            self._create()
        after = {
            path.relative_to(created.root).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in created.root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_hash_or_restore_corruption_fails_closed(self) -> None:
        created = self._create()
        database_path = created.root / "state" / "comments.sqlite3"
        with database_path.open("ab") as stream:
            stream.write(b"corrupt-after-checkpoint")
        report = verify_sqlite_checkpoint(created.root)
        self.assertFalse(report.valid)
        self.assertEqual(("checkpoint_validation_failed",), report.errors)

    def _product_shaped_authority(
        self,
        root: Path,
        *,
        attempt_id: str,
        target_release: str = "release-r1",
        target_hash: str = "b" * 64,
    ):
        (root / "tmp").mkdir(exist_ok=True)
        (root / "state" / "locks").mkdir(parents=True, exist_ok=True)
        (root / "control").mkdir(exist_ok=True)
        for name, source in (
            ("comments.sqlite3", self.comments),
            ("research_workspace.sqlite3", self.workspace),
        ):
            shutil.copy2(source, root / "state" / name)
        legacy = root / "legacy-state"
        legacy.mkdir()
        shutil.copy2(self.comments, legacy / "comments.sqlite3")
        shutil.copy2(self.workspace, legacy / "research_workspace.sqlite3")
        nonce = "N" * 64
        lock = root / "state" / "locks" / "writer-handoff.lock"
        descriptor = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        stream = os.fdopen(descriptor, "w", encoding="ascii", newline="\n")
        stream.write(nonce + "\n")
        stream.flush()
        os.fsync(stream.fileno())
        journal = {
            "schema_version": "qrh-writer-handoff-pending/v4",
            "attempt_id": attempt_id,
            "nonce_sha256": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
            "inspection_sha256": "c" * 64,
            "success_receipt_id": f"writer-handoff-success-{attempt_id}",
            "release_id": target_release,
            "manifest_sha256": target_hash,
            "phase": "legacy_stopped",
            "commit_evidence": None,
            "authority": "coordination_only",
            "legacy_process": {
                "pid": 3901,
                "executable": r"C:\quant_platform\.venv\Scripts\python.exe",
                "argv": [
                    r"C:\quant_platform\.venv\Scripts\python.exe",
                    "-I",
                    r"C:\quant_platform\tools\viewer\server.py",
                ],
                "executable_sha256": "d" * 64,
                "server_sha256": "e" * 64,
            },
        }
        (root / "control" / "writer_handoff_pending.json").write_bytes(
            canonical_manifest_bytes(journal)
        )
        return stream, legacy

    def test_product_authorization_binds_r1_journal_but_captures_r0(self) -> None:
        root = (self.root / "product-root").resolve()
        root.mkdir()
        attempt = "handoff-product-auth-test"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch(
            "quant_hub.collaboration.checkpoint.tempfile.TemporaryDirectory",
            side_effect=AssertionError("production restore must remain in memory"),
        ):
            creations = []
            for kind in ("legacy-c-final", "d-prehandoff"):
                if kind == "d-prehandoff":
                    journal_path = root / "control" / "writer_handoff_pending.json"
                    journal = json.loads(journal_path.read_text(encoding="utf-8"))
                    journal["phase"] = "final_checkpoint_created"
                    journal["commit_evidence"] = {
                        "final_checkpoint_id": creations[0].checkpoint_id,
                        "final_checkpoint_manifest_sha256": (
                            creations[0].manifest_sha256
                        ),
                        "prehandoff_checkpoint_id": None,
                        "prehandoff_checkpoint_manifest_sha256": None,
                    }
                    journal_path.write_bytes(canonical_manifest_bytes(journal))
                authorization = checkpoint_module._issue_production_checkpoint_authorization(
                    vm_root=root,
                    attempt_id=attempt,
                    checkpoint_kind=kind,
                    captured_under_release_id="release-r0",
                    captured_under_manifest_sha256="a" * 64,
                    writer_target_release_id="release-r1",
                    writer_target_manifest_sha256="b" * 64,
                )
                creations.append(
                    checkpoint_module._create_production_sqlite_checkpoint(
                        authorization
                    )
                )
            for creation in creations:
                manifest = json.loads(creation.manifest_path.read_text(encoding="utf-8"))
                self.assertEqual(
                    {
                        "release_id": "release-r0",
                        "manifest_sha256": "a" * 64,
                    },
                    manifest["captured_under_active_release"],
                )
                self.assertTrue(
                    checkpoint_module._verify_production_sqlite_checkpoint(
                        creation.root, attempt_id=attempt
                    ).valid
                )
                pinned = checkpoint_module._read_production_sqlite_checkpoint_bytes(
                    creation.root,
                    attempt_id=attempt,
                    expected_manifest_sha256=creation.manifest_sha256,
                )
                self.assertEqual(
                    {"comments", "research_workspace"}, set(pinned)
                )
                for raw in pinned.values():
                    self.assertTrue(raw.startswith(b"SQLite format 3\x00"))

    def test_production_authority_rejects_fake_closed_and_wrong_target_before_mkdir(self) -> None:
        root = (self.root / "product-denial-root").resolve()
        root.mkdir()
        attempt = "handoff-product-denial-test"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        handoff_root = root / "tmp" / "writer-handoff"
        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ):
            with self.assertRaises(CheckpointError):
                checkpoint_module._issue_production_checkpoint_authorization(
                    vm_root=root,
                    attempt_id=attempt,
                    checkpoint_kind="legacy-c-final",
                    captured_under_release_id="release-r0",
                    captured_under_manifest_sha256="a" * 64,
                    writer_target_release_id="wrong-r1",
                    writer_target_manifest_sha256="d" * 64,
                )
            self.assertFalse(handoff_root.exists())
            fake = object.__new__(
                checkpoint_module._ProductionCheckpointAuthorization
            )
            with self.assertRaisesRegex(CheckpointError, "not live"):
                checkpoint_module._create_production_sqlite_checkpoint(fake)
            self.assertFalse(handoff_root.exists())
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            stream.close()
            (root / "state" / "locks" / "writer-handoff.lock").unlink()
            with self.assertRaisesRegex(CheckpointError, "lock"):
                checkpoint_module._create_production_sqlite_checkpoint(
                    authorization
                )
            self.assertFalse(handoff_root.exists())

    def test_production_checkpoint_mkdir_swap_is_rejected_with_zero_outside_files(self) -> None:
        root = (self.root / "product-mkdir-swap-root").resolve()
        root.mkdir()
        outside = (self.root / "mkdir-swap-outside").resolve()
        outside.mkdir()
        attempt = "handoff-product-mkdir-swap"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        original_mkdir = checkpoint_module._BoundDirectory.mkdir

        def swap_after_mkdir(bound, name, mode=0o700):
            original_mkdir(bound, name, mode)
            if name == "checkpoints":
                child = bound.path / name
                os.rmdir(child)
                os.symlink(outside, child, target_is_directory=True)

        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch.object(
            checkpoint_module._BoundDirectory,
            "mkdir",
            new=swap_after_mkdir,
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            with self.assertRaises(Exception):
                checkpoint_module._create_production_sqlite_checkpoint(
                    authorization
                )
        self.assertEqual([], list(outside.iterdir()))

    def test_production_checkpoint_has_no_path_backup_swap_window(self) -> None:
        root = (self.root / "product-backup-swap-root").resolve()
        root.mkdir()
        outside = (self.root / "backup-swap-outside").resolve()
        outside.mkdir()
        attempt = "handoff-product-backup-swap"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch(
            "quant_hub.collaboration.checkpoint._online_backup",
            side_effect=AssertionError("production path backup must not be callable"),
        ), patch(
            "quant_hub.collaboration.checkpoint.os.rename",
            side_effect=AssertionError("production publication must be handle-selected"),
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            creation = checkpoint_module._create_production_sqlite_checkpoint(
                authorization
            )
        self.assertTrue(creation.root.is_dir())
        self.assertEqual([], list(outside.iterdir()))

    def test_production_checkpoint_rename_failure_cleans_exact_partial(self) -> None:
        root = (self.root / "product-rename-failure-root").resolve()
        root.mkdir()
        attempt = "handoff-product-rename-failure"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        checkpoint_parent = (
            root / "tmp" / "writer-handoff" / attempt / "checkpoints"
        )
        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch.object(
            checkpoint_module._BoundDirectory,
            "replace_open_windows_handle",
            side_effect=OSError("injected checkpoint publication failure"),
        ), patch(
            "quant_hub.collaboration.checkpoint.shutil.rmtree",
            side_effect=AssertionError("production cleanup must not use rmtree"),
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            with self.assertRaisesRegex(
                OSError, "injected checkpoint publication failure"
            ):
                checkpoint_module._create_production_sqlite_checkpoint(
                    authorization
                )
        self.assertTrue(checkpoint_parent.is_dir())
        self.assertEqual([], list(checkpoint_parent.iterdir()))

    def test_production_checkpoint_post_rename_rebase_failure_cleans_destination(
        self,
    ) -> None:
        root = (self.root / "p-rb").resolve()
        root.mkdir()
        attempt = "rb-fail"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        checkpoint_parent = (
            root / "tmp" / "writer-handoff" / attempt / "checkpoints"
        )
        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch.object(
            checkpoint_module._BoundDirectory,
            "verify_windows_final_paths",
            side_effect=OSError("injected post-rename rebase failure"),
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            with self.assertRaisesRegex(
                OSError, "injected post-rename rebase failure"
            ):
                checkpoint_module._create_production_sqlite_checkpoint(
                    authorization
                )
        self.assertTrue(checkpoint_parent.is_dir())
        self.assertEqual([], list(checkpoint_parent.iterdir()))

    def test_post_rename_root_remains_exclusive_before_binding_transfer(
        self,
    ) -> None:
        root = (self.root / "p-root-window").resolve()
        root.mkdir()
        attempt = "root-window"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        original_record = checkpoint_module._BoundDirectory.record_ancestor_rename
        displaced: Path | None = None

        def attack_after_record(bound, *, old_ancestor, new_ancestor):
            nonlocal displaced
            original_record(
                bound,
                old_ancestor=old_ancestor,
                new_ancestor=new_ancestor,
            )
            displaced = new_ancestor.with_name(new_ancestor.name + ".displaced")
            with self.assertRaises(PermissionError):
                os.replace(new_ancestor, displaced)

        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch.object(
            checkpoint_module._BoundDirectory,
            "record_ancestor_rename",
            new=attack_after_record,
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            creation = checkpoint_module._create_production_sqlite_checkpoint(
                authorization
            )
        self.assertTrue(creation.root.is_dir())
        self.assertIsNotNone(displaced)
        self.assertFalse(displaced.exists())

    def test_member_swap_before_first_repin_cleans_original_and_replacement(
        self,
    ) -> None:
        root = (self.root / "p-member-window").resolve()
        root.mkdir()
        attempt = "member-window"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        checkpoint_parent = (
            root / "tmp" / "writer-handoff" / attempt / "checkpoints"
        )
        original_pin = checkpoint_module._pin_regular_file
        displaced: Path | None = None
        attacked = False

        def swap_before_pin(path, expected, *, delete_authority=False):
            nonlocal attacked, displaced
            if (
                delete_authority
                and not attacked
                and path.name == CHECKPOINT_MANIFEST_NAME
            ):
                attacked = True
                displaced = (
                    path.parent.parent / ".original-manifest-before-repin"
                )
                os.replace(path, displaced)
                path.write_bytes(b"replacement\n")
            return original_pin(
                path,
                expected,
                delete_authority=delete_authority,
            )

        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch.object(
            checkpoint_module,
            "_pin_regular_file",
            new=swap_before_pin,
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            with self.assertRaises(Exception):
                checkpoint_module._create_production_sqlite_checkpoint(
                    authorization
                )
        self.assertTrue(attacked)
        self.assertIsNotNone(displaced)
        self.assertFalse(displaced.exists())
        self.assertEqual([], list(checkpoint_parent.iterdir()))

    def test_production_checkpoint_invalid_formal_verification_cleans_destination(
        self,
    ) -> None:
        root = (self.root / "p-vf").resolve()
        root.mkdir()
        attempt = "verify-fail"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        checkpoint_parent = (
            root / "tmp" / "writer-handoff" / attempt / "checkpoints"
        )

        def invalid_verification(checkpoint_path, **_kwargs):
            return checkpoint_module.CheckpointVerification(
                checkpoint_id=checkpoint_path.name,
                root=checkpoint_path,
                valid=False,
                manifest_sha256=None,
                captured_at=None,
                database_count=0,
                errors=("injected_verification_failure",),
            )

        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch.object(
            checkpoint_module,
            "_verify_production_sqlite_checkpoint_under_guard",
            new=invalid_verification,
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            with self.assertRaisesRegex(
                CheckpointError, "failed post-publish verification"
            ):
                checkpoint_module._create_production_sqlite_checkpoint(
                    authorization
                )
        self.assertTrue(checkpoint_parent.is_dir())
        self.assertEqual([], list(checkpoint_parent.iterdir()))

    def test_formal_verification_cannot_move_published_root_before_cleanup(
        self,
    ) -> None:
        root = (self.root / "p-root-pin").resolve()
        root.mkdir()
        attempt = "root-pin"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        checkpoint_parent = (
            root / "tmp" / "writer-handoff" / attempt / "checkpoints"
        )
        displaced: Path | None = None

        def attack_then_reject(checkpoint_path, **_kwargs):
            nonlocal displaced
            displaced = checkpoint_path.with_name(checkpoint_path.name + ".displaced")
            with self.assertRaises(PermissionError):
                os.replace(checkpoint_path, displaced)
            return checkpoint_module.CheckpointVerification(
                checkpoint_id=checkpoint_path.name,
                root=checkpoint_path,
                valid=False,
                manifest_sha256=None,
                captured_at=None,
                database_count=0,
                errors=("injected_verification_failure",),
            )

        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch.object(
            checkpoint_module,
            "_verify_production_sqlite_checkpoint_under_guard",
            new=attack_then_reject,
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            with self.assertRaisesRegex(
                CheckpointError, "failed post-publish verification"
            ):
                checkpoint_module._create_production_sqlite_checkpoint(
                    authorization
                )
        self.assertIsNotNone(displaced)
        self.assertFalse(displaced.exists())
        self.assertEqual([], list(checkpoint_parent.iterdir()))

    def test_formal_verification_cannot_replace_manifest_before_cleanup(
        self,
    ) -> None:
        root = (self.root / "p-member-pin").resolve()
        root.mkdir()
        attempt = "member-pin"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        checkpoint_parent = (
            root / "tmp" / "writer-handoff" / attempt / "checkpoints"
        )
        displaced: Path | None = None

        def attack_then_reject(checkpoint_path, **_kwargs):
            nonlocal displaced
            manifest = checkpoint_path / CHECKPOINT_MANIFEST_NAME
            displaced = checkpoint_path / (CHECKPOINT_MANIFEST_NAME + ".displaced")
            with self.assertRaises(PermissionError):
                os.replace(manifest, displaced)
            self.assertTrue(manifest.is_file())
            return checkpoint_module.CheckpointVerification(
                checkpoint_id=checkpoint_path.name,
                root=checkpoint_path,
                valid=False,
                manifest_sha256=None,
                captured_at=None,
                database_count=0,
                errors=("injected_verification_failure",),
            )

        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch.object(
            checkpoint_module,
            "_verify_production_sqlite_checkpoint_under_guard",
            new=attack_then_reject,
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            with self.assertRaisesRegex(
                CheckpointError, "failed post-publish verification"
            ):
                checkpoint_module._create_production_sqlite_checkpoint(
                    authorization
                )
        self.assertIsNotNone(displaced)
        self.assertFalse(displaced.exists())
        self.assertEqual([], list(checkpoint_parent.iterdir()))

    def test_production_checkpoint_monitor_failure_cleans_moved_identity(self) -> None:
        root = (self.root / "product-monitor-failure-root").resolve()
        root.mkdir()
        attempt = "handoff-product-monitor-failure"
        stream, legacy = self._product_shaped_authority(root, attempt_id=attempt)
        self.addCleanup(stream.close)
        checkpoint_parent = (
            root / "tmp" / "writer-handoff" / attempt / "checkpoints"
        )
        original_enable = checkpoint_module._BoundDirectory.enable_self_rename

        def mutate_after_descendant_pins_close(bound) -> None:
            (bound.path / CHECKPOINT_MANIFEST_NAME).write_bytes(b"tampered\n")
            original_enable(bound)

        with patch.object(checkpoint_module, "PRODUCTION_VM_ROOT", root), patch.object(
            checkpoint_module, "_LEGACY_STATE_ROOT", legacy
        ), patch.object(
            checkpoint_module._BoundDirectory,
            "enable_self_rename",
            new=mutate_after_descendant_pins_close,
        ):
            authorization = checkpoint_module._issue_production_checkpoint_authorization(
                vm_root=root,
                attempt_id=attempt,
                checkpoint_kind="legacy-c-final",
                captured_under_release_id="release-r0",
                captured_under_manifest_sha256="a" * 64,
                writer_target_release_id="release-r1",
                writer_target_manifest_sha256="b" * 64,
            )
            with self.assertRaisesRegex(
                Exception, "post-publish verification|namespace changed"
            ):
                checkpoint_module._create_production_sqlite_checkpoint(
                    authorization
                )
        self.assertTrue(checkpoint_parent.is_dir())
        self.assertEqual([], list(checkpoint_parent.iterdir()))



if __name__ == "__main__":
    unittest.main()
