from __future__ import annotations

from contextlib import closing, redirect_stdout
import hashlib
from io import StringIO
import json
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from quant_hub.config import ConfigurationError
from quant_hub.knowledge.semantic import SemanticJobStore
from quant_hub.ops import semantic_authority
from quant_hub.ops.semantic_authority import (
    SemanticAuthorityError,
    promote_semantic_authority,
    resolve_semantic_authority,
    verify_semantic_authority,
)


def _hold_semantic_promotion_lock(state_root, ready_event) -> None:
    with semantic_authority._promotion_lock(Path(state_root)):
        ready_event.set()
        time.sleep(60)


def _compete_for_semantic_promotion_lock(
    state_root, start_event, release_event, result_queue
) -> None:
    start_event.wait(15)
    try:
        with semantic_authority._promotion_lock(Path(state_root)):
            result_queue.put(("claimed",))
            release_event.wait(15)
    except SemanticAuthorityError as error:
        result_queue.put(("rejected", str(error)))


def _promote_worker(project_root, state_root, source_path, start_event, result_queue) -> None:
    start_event.wait(15)
    try:
        receipt = promote_semantic_authority(
            project_root=Path(project_root),
            state_root=Path(state_root),
            source_path=Path(source_path),
            promoted_at="2026-08-21T12:00:00Z",
        )
        result_queue.put(("ok", receipt.promotion_id))
    except Exception as error:
        result_queue.put((type(error).__name__, str(error)))


class SemanticAuthorityPromotionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "git-project"
        self.state = self.root / "protected-state"
        self.project.mkdir()
        self.state.mkdir()
        self.source = self.project / ".campaign" / "semantic_jobs.sqlite3"
        self.source.parent.mkdir()
        self.store = SemanticJobStore(self.source)
        self.live = self.store.connect()
        self.live.execute("PRAGMA wal_autocheckpoint=0")
        self.source_body = "绝密研究正文：quote-should-not-enter-receipt"
        self.fake_key = "CREDENTIAL_SENTINEL_DO_NOT_EMIT_7e3b19"
        self._insert_job(
            "job-terminal",
            status="succeeded",
            payload=json.dumps(
                {
                    "document_id": "research-secret",
                    "quote": self.source_body,
                    "credential": self.fake_key,
                },
                ensure_ascii=False,
            ),
        )
        self.live.commit()

    def tearDown(self) -> None:
        self.live.close()
        self.temporary.cleanup()

    def test_promotion_lock_is_process_owned_and_recovers_after_kill(self) -> None:
        context = multiprocessing.get_context("spawn")
        ready = context.Event()
        process = context.Process(
            target=_hold_semantic_promotion_lock,
            args=(str(self.state), ready),
        )
        process.start()
        self.assertTrue(ready.wait(timeout=20))
        with self.assertRaisesRegex(
            SemanticAuthorityError,
            "another semantic authority promotion is active",
        ):
            with semantic_authority._promotion_lock(self.state):
                self.fail("a competing process acquired the promotion lock")

        process.terminate()
        process.join(timeout=20)
        self.assertFalse(process.is_alive())
        with semantic_authority._promotion_lock(self.state):
            pass
        lock_path = self.state / ".semantic_authority_promotion.lock"
        self.assertTrue(lock_path.is_file())
        self.assertEqual(
            semantic_authority._PROMOTION_LOCK_MARKER,
            lock_path.read_bytes(),
        )

    def test_promotion_lock_rejects_unknown_persistent_identity(self) -> None:
        lock_path = self.state / ".semantic_authority_promotion.lock"
        lock_path.write_bytes(b"legacy-or-tampered-lock\n")
        with self.assertRaisesRegex(
            SemanticAuthorityError,
            "promotion lock identity is invalid",
        ):
            with semantic_authority._promotion_lock(self.state):
                self.fail("a tampered persistent lock was accepted")

    def test_promotion_lock_initialization_is_atomic_across_eight_processes(self) -> None:
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        release = context.Event()
        results = context.Queue()
        processes = tuple(
            context.Process(
                target=_compete_for_semantic_promotion_lock,
                args=(str(self.state), start, release, results),
            )
            for _ in range(8)
        )
        for process in processes:
            process.start()
        start.set()
        observed = tuple(results.get(timeout=30) for _ in processes)
        release.set()
        for process in processes:
            process.join(timeout=30)
            if process.is_alive():
                process.terminate()
                process.join(timeout=10)
            self.assertEqual(0, process.exitcode)
        self.assertEqual(1, sum(row[0] == "claimed" for row in observed), observed)
        self.assertEqual(7, sum(row[0] == "rejected" for row in observed), observed)
        self.assertTrue(
            all(
                row[0] == "claimed"
                or "another semantic authority promotion is active" in row[1]
                for row in observed
            ),
            observed,
        )

    def test_first_promotion_receipt_root_is_initialized_under_process_lock(self) -> None:
        self.live.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.live.close()
        context = multiprocessing.get_context("spawn")
        start = context.Event()
        results = context.Queue()
        processes = tuple(
            context.Process(
                target=_promote_worker,
                args=(
                    str(self.project),
                    str(self.state),
                    str(self.source),
                    start,
                    results,
                ),
            )
            for _ in range(8)
        )
        for process in processes:
            process.start()
        start.set()
        observed = tuple(results.get(timeout=60) for _ in processes)
        for process in processes:
            process.join(timeout=60)
            if process.is_alive():
                process.terminate()
                process.join(timeout=10)
            self.assertEqual(0, process.exitcode)
        self.assertGreaterEqual(sum(row[0] == "ok" for row in observed), 1)
        self.assertTrue(
            all(
                row[0] == "ok"
                or (
                    row[0] == "SemanticAuthorityError"
                    and "another semantic authority promotion is active" in row[1]
                )
                for row in observed
            ),
            observed,
        )
        self.assertEqual(1, len({row[1] for row in observed if row[0] == "ok"}))
        receipts = tuple(
            (self.state / "semantic_promotion_receipts").glob("semprom_*.json")
        )
        self.assertEqual(1, len(receipts))

    def _insert_job(
        self,
        key: str,
        *,
        status: str,
        payload: str = "{}",
    ) -> None:
        self.live.execute(
            "INSERT INTO semantic_job VALUES(?,?,?,?,?,?,?,?)",
            (
                key,
                "doc-1",
                "docv-1",
                payload,
                status,
                None,
                "2026-08-21T00:00:00Z",
                "2026-08-21T00:00:00Z",
            ),
        )

    @staticmethod
    def _sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _promote(self, **overrides):
        arguments = {
            "project_root": self.project,
            "state_root": self.state,
            "source_path": self.source,
            "promoted_at": "2026-08-21T12:00:00Z",
        }
        arguments.update(overrides)
        return promote_semantic_authority(**arguments)

    def test_online_backup_captures_committed_wal_and_leaves_source_unchanged(self) -> None:
        wal = self.source.with_name(self.source.name + "-wal")
        self.assertTrue(wal.is_file())
        before = self._sha256(self.source)

        receipt = self._promote()

        self.assertEqual(before, self._sha256(self.source))
        target = self.state / "semantic_jobs.sqlite3"
        with closing(sqlite3.connect(target)) as connection:
            row = connection.execute(
                "SELECT status,payload_json FROM semantic_job WHERE job_key='job-terminal'"
            ).fetchone()
        self.assertEqual("succeeded", row[0])
        self.assertIn("research-secret", row[1])
        self.assertEqual(receipt.source["logical_sha256"], receipt.target["logical_sha256"])
        self.assertEqual(receipt.source["schema_sha256"], receipt.target["schema_sha256"])
        self.assertEqual(receipt.source["row_counts"], receipt.target["row_counts"])
        self.assertNotEqual(receipt.source["observed_main_file_sha256"], "0" * 64)
        self.assertEqual(receipt.target["file_sha256"], self._sha256(target))
        verified = verify_semantic_authority(
            project_root=self.project,
            state_root=self.state,
            promotion_id=receipt.promotion_id,
            source_path=self.source,
        )
        self.assertEqual(receipt, verified)
        self.assertEqual(
            receipt,
            resolve_semantic_authority(
                project_root=self.project,
                state_root=self.state,
            ),
        )
        output = StringIO()
        with redirect_stdout(output):
            code = semantic_authority.main(
                [
                    "--project-root", str(self.project),
                    "--state-root", str(self.state),
                    "resolve",
                ]
            )
        public = json.loads(output.getvalue())
        self.assertEqual(0, code)
        self.assertEqual(receipt.promotion_id, public["promotion_id"])
        self.assertNotIn(self.source_body, output.getvalue())
        self.assertNotIn(self.fake_key, output.getvalue())

    def test_source_wal_checkpoint_does_not_change_logical_authority(self) -> None:
        receipt = self._promote()
        observed_main = receipt.source["observed_main_file_sha256"]

        # A normal WAL checkpoint changes the main-file bytes without changing
        # any semantic row.  The archived source is therefore verified by its
        # deterministic logical identity, not this transient physical hash.
        self.live.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
        self.assertNotEqual(observed_main, self._sha256(self.source))
        verified = verify_semantic_authority(
            project_root=self.project,
            state_root=self.state,
            promotion_id=receipt.promotion_id,
            source_path=self.source,
        )
        self.assertEqual(receipt, verified)

    def test_same_logical_identity_is_idempotent(self) -> None:
        first = self._promote()
        receipt_path = (
            self.state
            / "semantic_promotion_receipts"
            / f"{first.promotion_id}.json"
        )
        before = receipt_path.read_bytes()

        second = self._promote(promoted_at="2099-01-01T00:00:00Z")

        self.assertEqual(first, second)
        self.assertEqual(before, receipt_path.read_bytes())
        self.assertEqual(1, len(list(receipt_path.parent.glob("*.json"))))

    def test_queued_and_running_jobs_are_rejected(self) -> None:
        for status in ("queued", "running"):
            with self.subTest(status=status):
                self.live.execute(
                    "UPDATE semantic_job SET status=? WHERE job_key='job-terminal'",
                    (status,),
                )
                self.live.commit()
                with self.assertRaisesRegex(SemanticAuthorityError, "queued/running"):
                    self._promote()
                self.assertFalse((self.state / "semantic_jobs.sqlite3").exists())
                self.live.execute(
                    "UPDATE semantic_job SET status='succeeded' WHERE job_key='job-terminal'"
                )
                self.live.commit()

    def test_existing_target_with_different_identity_fails_closed(self) -> None:
        self._promote()
        second = self.project / ".campaign-2" / "semantic_jobs.sqlite3"
        second.parent.mkdir()
        second_store = SemanticJobStore(second)
        with closing(second_store.connect()) as connection:
            connection.execute(
                "INSERT INTO semantic_job VALUES(?,?,?,?,?,?,?,?)",
                (
                    "different-job",
                    "doc-2",
                    "docv-2",
                    "{}",
                    "succeeded",
                    None,
                    "2026-08-21T00:00:00Z",
                    "2026-08-21T00:00:00Z",
                ),
            )
            connection.commit()
        with self.assertRaisesRegex(SemanticAuthorityError, "requires the exact current"):
            self._promote(source_path=second)

    def test_explicit_rotation_replaces_only_the_exact_current_promotion(self) -> None:
        first = self._promote()
        second = self.project / ".campaign-rotation" / "semantic_jobs.sqlite3"
        second.parent.mkdir()
        second_store = SemanticJobStore(second)
        with closing(second_store.connect()) as connection:
            connection.execute(
                "INSERT INTO semantic_job VALUES(?,?,?,?,?,?,?,?)",
                (
                    "rotated-job", "doc-2", "docv-2", "{}", "succeeded",
                    None, "2026-08-21T00:00:00Z", "2026-08-21T00:00:00Z",
                ),
            )
            connection.commit()
        rotated = self._promote(
            source_path=second,
            promoted_at="2026-08-21T13:00:00Z",
            expected_current_promotion_id=first.promotion_id,
        )
        self.assertNotEqual(first.promotion_id, rotated.promotion_id)
        self.assertEqual(
            rotated,
            resolve_semantic_authority(
                project_root=self.project,
                state_root=self.state,
            ),
        )
        self.assertTrue(
            (
                self.state
                / "semantic_promotion_receipts"
                / f"{first.promotion_id}.json"
            ).is_file()
        )
        with self.assertRaisesRegex(SemanticAuthorityError, "requested identity"):
            verify_semantic_authority(
                project_root=self.project,
                state_root=self.state,
                promotion_id=first.promotion_id,
            )

    def test_rotation_replay_closes_replace_before_receipt_crash(self) -> None:
        first = self._promote()
        second = self.project / ".campaign-crash" / "semantic_jobs.sqlite3"
        second.parent.mkdir()
        second_store = SemanticJobStore(second)
        with closing(second_store.connect()) as connection:
            connection.execute(
                "INSERT INTO semantic_job VALUES(?,?,?,?,?,?,?,?)",
                (
                    "post-crash-job", "doc-3", "docv-3", "{}", "succeeded",
                    None, "2026-08-21T00:00:00Z", "2026-08-21T00:00:00Z",
                ),
            )
            connection.commit()
        with patch.object(
            semantic_authority,
            "_write_receipt_immutable",
            side_effect=OSError("receipt-cut"),
        ):
            with self.assertRaises(OSError):
                self._promote(
                    source_path=second,
                    expected_current_promotion_id=first.promotion_id,
                )
        with self.assertRaises(SemanticAuthorityError):
            resolve_semantic_authority(
                project_root=self.project,
                state_root=self.state,
            )

        recovered = self._promote(
            source_path=second,
            expected_current_promotion_id=first.promotion_id,
        )
        self.assertEqual(
            recovered,
            resolve_semantic_authority(
                project_root=self.project,
                state_root=self.state,
            ),
        )

    def test_first_promotion_replays_replace_before_receipt_crash(self) -> None:
        with patch.object(
            semantic_authority,
            "_write_receipt_immutable",
            side_effect=OSError("first-receipt-cut"),
        ):
            with self.assertRaises(OSError):
                self._promote()
        self.assertTrue((self.state / "semantic_jobs.sqlite3").is_file())
        self.assertEqual(
            (),
            tuple((self.state / "semantic_promotion_receipts").glob("*.json")),
        )

        recovered = self._promote()

        self.assertEqual(
            recovered,
            resolve_semantic_authority(
                project_root=self.project,
                state_root=self.state,
            ),
        )

    def test_retry_cleans_only_canonical_promotion_partials(self) -> None:
        receipts = self.state / "semantic_promotion_receipts"
        receipts.mkdir()
        target_partial = self.state / (
            "semantic_jobs.sqlite3." + "a" * 32 + ".partial"
        )
        receipt_partial = receipts / (
            "semprom_" + "b" * 40 + ".json." + "c" * 32 + ".partial"
        )
        target_partial.write_bytes(b"discardable target partial")
        receipt_partial.write_bytes(b"discardable receipt partial")

        self._promote()

        self.assertFalse(target_partial.exists())
        self.assertFalse(receipt_partial.exists())

        unknown = receipts / "unexpected.partial"
        unknown.write_bytes(b"must not be guessed")
        with self.assertRaisesRegex(
            SemanticAuthorityError,
            "unknown semantic promotion partial",
        ):
            self._promote()
        self.assertTrue(unknown.is_file())

    def test_cross_table_generation_version_mismatch_is_rejected(self) -> None:
        self._insert_job("job-second", status="succeeded")
        generation_payload = {
            "generation_id": "generation-cross-version",
            "job_key": "job-terminal",
            "document_version_id": "docv-1",
            "status": "succeeded",
            "created_at": "2026-08-21T00:02:00Z",
        }
        candidate_payload = {
            "candidate_id": "candidate-cross-version",
            "generation_id": "generation-cross-version",
            "document_version_id": "docv-other",
            "fact_status": "model_candidate",
        }
        encode = lambda value: json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.live.execute(
            "INSERT INTO knowledge_generation VALUES(?,?,?,?,?,?)",
            (
                "generation-cross-version",
                "job-terminal",
                "docv-1",
                encode(generation_payload),
                "succeeded",
                "2026-08-21T00:02:00Z",
            ),
        )
        self.live.execute(
            "INSERT INTO knowledge_candidate VALUES(?,?,?,?,?,?)",
            (
                "candidate-cross-version",
                "generation-cross-version",
                "docv-other",
                encode(candidate_payload),
                "model_candidate",
                "2026-08-21T00:02:00Z",
            ),
        )
        self.live.commit()

        with self.assertRaisesRegex(
            SemanticAuthorityError,
            "candidate.*generation version",
        ):
            self._promote()
        self.assertFalse((self.state / "semantic_jobs.sqlite3").exists())

    def test_nonterminal_generation_and_nonformal_effective_state_are_rejected(self) -> None:
        encode = lambda value: json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        running_generation = {
            "generation_id": "generation-running",
            "job_key": "job-terminal",
            "document_version_id": "docv-1",
            "status": "running",
            "created_at": "2026-08-21T00:02:00Z",
        }
        self.live.execute(
            "INSERT INTO knowledge_generation VALUES(?,?,?,?,?,?)",
            (
                "generation-running",
                "job-terminal",
                "docv-1",
                encode(running_generation),
                "running",
                "2026-08-21T00:02:00Z",
            ),
        )
        self.live.commit()
        with self.assertRaisesRegex(
            SemanticAuthorityError, "generation.*unknown"
        ):
            self._promote()

        self.live.execute(
            "DELETE FROM knowledge_generation WHERE generation_id='generation-running'"
        )
        item_payload = {
            "knowledge_item_id": "formal-item-invalid-state",
            "document_version_id": "docv-1",
            "fact_status": "source_explicit",
        }
        self.live.execute(
            "INSERT INTO knowledge_item VALUES(?,?,?,?,?)",
            (
                "formal-item-invalid-state",
                "docv-1",
                encode(item_payload),
                "source_explicit",
                "2026-08-21T00:03:00Z",
            ),
        )
        self.live.execute(
            "INSERT INTO knowledge_item_state VALUES(?,?,?,?,?)",
            (
                "formal-item-invalid-state",
                "model_candidate",
                None,
                None,
                "2026-08-21T00:03:00Z",
            ),
        )
        self.live.commit()
        with self.assertRaisesRegex(
            SemanticAuthorityError, "item_state.*unknown"
        ):
            self._promote()

    def test_formal_item_missing_effective_state_is_rejected(self) -> None:
        payload = json.dumps(
            {
                "knowledge_item_id": "formal-item-missing-state",
                "document_version_id": "docv-1",
                "fact_status": "source_explicit",
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.live.execute(
            "INSERT INTO knowledge_item VALUES(?,?,?,?,?)",
            (
                "formal-item-missing-state",
                "docv-1",
                payload,
                "source_explicit",
                "2026-08-21T00:03:00Z",
            ),
        )
        self.live.commit()
        with self.assertRaisesRegex(
            SemanticAuthorityError, "missing its effective state"
        ):
            self._promote()
        self.assertFalse((self.state / "semantic_jobs.sqlite3").exists())

    def test_target_or_receipt_tamper_is_detected(self) -> None:
        receipt = self._promote()
        target = self.state / "semantic_jobs.sqlite3"
        with closing(sqlite3.connect(target)) as connection:
            connection.execute(
                "UPDATE semantic_job SET error_code='tampered' WHERE job_key='job-terminal'"
            )
            connection.commit()
        with self.assertRaisesRegex(SemanticAuthorityError, "does not.*receipt"):
            verify_semantic_authority(
                project_root=self.project,
                state_root=self.state,
                promotion_id=receipt.promotion_id,
            )

        # Restore by recreating the fixture in a new protected root, then prove
        # the content-addressed receipt detects metadata edits as well.
        second_state = self.root / "protected-state-2"
        second_state.mkdir()
        second = self._promote(state_root=second_state)
        receipt_path = (
            second_state
            / "semantic_promotion_receipts"
            / f"{second.promotion_id}.json"
        )
        value = json.loads(receipt_path.read_text(encoding="utf-8"))
        value["promoted_at"] = "2099-01-01T00:00:00Z"
        receipt_path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            SemanticAuthorityError, "identity|canonically encoded"
        ):
            verify_semantic_authority(
                project_root=self.project,
                state_root=second_state,
                promotion_id=second.promotion_id,
            )

    def test_project_internal_state_root_is_rejected(self) -> None:
        internal = self.project / "runtime-state"
        internal.mkdir()
        with self.assertRaisesRegex(SemanticAuthorityError, "outside"):
            self._promote(state_root=internal)
        self.assertFalse((internal / "semantic_jobs.sqlite3").exists())

    def test_non_regular_existing_target_is_rejected(self) -> None:
        (self.state / "semantic_jobs.sqlite3").mkdir()
        with self.assertRaisesRegex(SemanticAuthorityError, "regular"):
            self._promote()

    def test_reparse_target_is_rejected_before_partial_creation(self) -> None:
        target = self.state / "semantic_jobs.sqlite3"
        expected_parent = self.state.resolve(strict=True)
        original = semantic_authority.ensure_no_reparse_components

        def reject_target(path: Path) -> None:
            # GitHub's Windows runner may spell the temporary root through a
            # short-name/canonical alias after ``state_root.resolve()``.  Match
            # the actual semantic target by its already-existing canonical
            # parent instead of comparing that spelling to the fixture path.
            candidate = Path(path)
            if (
                candidate.name == semantic_authority.TARGET_FILE_NAME
                and candidate.parent.resolve(strict=True) == expected_parent
            ):
                raise ConfigurationError("simulated reparse target")
            original(candidate)

        with patch(
            "quant_hub.ops.semantic_authority.ensure_no_reparse_components",
            side_effect=reject_target,
        ):
            with self.assertRaisesRegex(SemanticAuthorityError, "unsafe"):
                self._promote()
        self.assertFalse(target.exists())
        self.assertFalse(any(self.state.glob("*.partial")))

    def test_failed_atomic_replace_leaves_no_target_or_partial(self) -> None:
        with patch(
            "quant_hub.ops.semantic_authority.os.replace",
            side_effect=OSError("simulated atomic replace failure"),
        ):
            with self.assertRaisesRegex(SemanticAuthorityError, "atomic"):
                self._promote()
        self.assertFalse((self.state / "semantic_jobs.sqlite3").exists())
        self.assertFalse(any(self.state.glob("semantic_jobs.sqlite3.*.partial")))

    def test_schema_and_foreign_key_corruption_are_rejected(self) -> None:
        invalid_schema = self.project / ".bad-schema" / "semantic_jobs.sqlite3"
        invalid_schema.parent.mkdir()
        bad_store = SemanticJobStore(invalid_schema)
        with closing(bad_store.connect()) as connection:
            connection.execute("DROP TABLE recompile_campaign")
            connection.commit()
        with self.assertRaisesRegex(SemanticAuthorityError, "table set"):
            self._promote(source_path=invalid_schema)

        invalid_fk = self.project / ".bad-fk" / "semantic_jobs.sqlite3"
        invalid_fk.parent.mkdir()
        fk_store = SemanticJobStore(invalid_fk)
        with closing(fk_store.connect()) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute(
                "INSERT INTO knowledge_generation VALUES(?,?,?,?,?,?)",
                (
                    "gen-orphan",
                    "missing-job",
                    "docv-1",
                    "{}",
                    "succeeded",
                    "2026-08-21T00:00:00Z",
                ),
            )
            connection.commit()
        with self.assertRaisesRegex(SemanticAuthorityError, "foreign_key_check"):
            self._promote(source_path=invalid_fk)

    def test_generation_and_fact_status_domains_are_closed(self) -> None:
        invalid_generation = self.project / ".bad-generation" / "semantic_jobs.sqlite3"
        invalid_generation.parent.mkdir()
        generation_store = SemanticJobStore(invalid_generation)
        with closing(generation_store.connect()) as connection:
            connection.execute(
                "INSERT INTO semantic_job VALUES(?,?,?,?,?,?,?,?)",
                (
                    "job-1",
                    "doc-1",
                    "docv-1",
                    "{}",
                    "succeeded",
                    None,
                    "2026-08-21T00:00:00Z",
                    "2026-08-21T00:00:00Z",
                ),
            )
            connection.execute(
                "INSERT INTO knowledge_generation VALUES(?,?,?,?,?,?)",
                (
                    "gen-1",
                    "job-1",
                    "docv-1",
                    "{}",
                    "silently_active",
                    "2026-08-21T00:00:00Z",
                ),
            )
            connection.commit()
        with self.assertRaisesRegex(SemanticAuthorityError, "generation.*unknown"):
            self._promote(source_path=invalid_generation)

        invalid_item = self.project / ".bad-item" / "semantic_jobs.sqlite3"
        invalid_item.parent.mkdir()
        item_store = SemanticJobStore(invalid_item)
        with closing(item_store.connect()) as connection:
            connection.execute(
                "INSERT INTO knowledge_item VALUES(?,?,?,?,?)",
                (
                    "item-1",
                    "docv-1",
                    "{}",
                    "model_candidate",
                    "2026-08-21T00:00:00Z",
                ),
            )
            connection.execute(
                "INSERT INTO knowledge_item_state VALUES(?,?,?,?,?)",
                (
                    "item-1",
                    "model_candidate",
                    None,
                    None,
                    "2026-08-21T00:00:00Z",
                ),
            )
            connection.commit()
        with self.assertRaisesRegex(SemanticAuthorityError, "non-formal"):
            self._promote(source_path=invalid_item)

    def test_receipt_contains_only_hashes_counts_roles_and_time(self) -> None:
        receipt = self._promote()
        path = (
            self.state
            / "semantic_promotion_receipts"
            / f"{receipt.promotion_id}.json"
        )
        raw = path.read_text(encoding="utf-8")
        self.assertNotIn(self.source_body, raw)
        self.assertNotIn(self.fake_key, raw)
        self.assertNotIn(str(self.source), raw)
        self.assertNotIn("payload_json", raw)
        self.assertNotIn("quote", raw.lower())
        self.assertEqual(
            "campaign_workspace_archived_read_only", receipt.source["path_role"]
        )
        self.assertEqual(
            "protected_state_active_authority", receipt.target["path_role"]
        )
        self.assertEqual(
            {"active": "target", "source": "archived_read_only"},
            receipt.authority,
        )


if __name__ == "__main__":
    unittest.main()
