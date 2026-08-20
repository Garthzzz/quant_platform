from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import threading
from typing import Callable, TypeVar

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import (
    ActorInput,
    ArchiveDocumentInput,
    ArchiveReleaseInput,
)
from quant_hub.archive.database import archive_connection
from quant_hub.collaboration.service import (
    ArchiveCollaboration,
    CommandOutcome,
    IdempotencyConflict,
)
from quant_hub.ids import stable_sha256
from quant_hub.platform.db import connect_database
from quant_hub.platform.releases import (
    ReleaseAuthority,
    ReleaseCandidateSpec,
)
from tests.helpers import SettingsTestCase


T = TypeVar("T")


def _run_concurrently(count: int, action: Callable[[int], T]) -> list[T]:
    """让全部 worker 在同一断点起跑，并把线程内异常带回测试线程。"""

    barrier = threading.Barrier(count)

    def invoke(index: int) -> T:
        barrier.wait(timeout=20)
        return action(index)

    with ThreadPoolExecutor(max_workers=count) as executor:
        futures = [executor.submit(invoke, index) for index in range(count)]
        return [future.result(timeout=60) for future in futures]


class BConcurrencyTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.source = b"# Concurrent archive\n\nimmutable body with $r_t$.\n"
        (self.archive / "concurrent.md").write_bytes(self.source)
        self.catalog = ArchiveCatalog(self.settings)
        self.catalog.initialize()
        self.actor = ActorInput(actor_kind="zhang_zhengze")

    def _draft(self) -> ArchiveReleaseInput:
        return ArchiveReleaseInput(
            research_slug="concurrent-archive",
            display_title="并发边界研究",
            release_key="v1",
            documents=(
                ArchiveDocumentInput(
                    document_slug="main",
                    document_role="primary",
                    source_path="concurrent.md",
                    **self.approved_source_fields("concurrent.md"),
                    navigation_role="primary",
                    sort_key=10,
                    mapping_authority_urn="qrh:review:b-concurrency-mapping",
                    mapping_note="B 门禁并发测试的显式 source→document 映射",
                ),
            ),
            activate=False,
        )

    def _certified_release(self) -> ArchiveReleaseInput:
        draft = self._draft()
        spec = self.catalog.prepare_release_candidate(draft)
        authority = ReleaseAuthority(self.settings)
        candidate = authority.register_candidate(spec)
        decision = authority.record_decision(
            candidate.candidate_id,
            deterministic_gate_hash=stable_sha256(
                "b-concurrency/archive-gate/v1", spec.artifact_manifest_hash
            ),
            review_set_hash=stable_sha256(
                "b-concurrency/archive-review/v1", spec.source_snapshot_hash
            ),
            reconciliation_hash=stable_sha256(
                "b-concurrency/archive-reconciliation/v1",
                spec.projection_revision,
            ),
            verdict="pass",
        )
        certificate = authority.issue_snapshot(
            decision.decision_id,
            requirements_manifest_hash=spec.requirements_manifest_hash,
            issuance_key=stable_sha256("b-concurrency/archive-issuance/v1"),
        )
        return draft.model_copy(
            update={
                "activate": True,
                "release_snapshot_urn": certificate.snapshot_urn,
                "activation_decision_hash": certificate.decision_hash,
            }
        )

    def _published_research_id(self) -> str:
        release = self.catalog.publish_release(self._certified_release())
        return release.research_id

    def test_release_authority_same_material_is_atomic_and_idempotent(self) -> None:
        spec = ReleaseCandidateSpec(
            domain="archive",
            subject_urn="qrh:archive-research:concurrent-authority",
            subject_version_urn=(
                "qrh:archive-release:concurrent-authority:sha256:" + "a" * 64
            ),
            artifact_manifest_hash="a" * 64,
            source_snapshot_hash="b" * 64,
            projection_revision="concurrency-projection-v1-" + "c" * 64,
            requirements_manifest_hash="d" * 64,
        )
        gate_hash = stable_sha256("b-concurrency/authority-gate/v1")
        review_hash = stable_sha256("b-concurrency/authority-review/v1")
        reconciliation_hash = stable_sha256(
            "b-concurrency/authority-reconciliation/v1"
        )
        issuance_key = stable_sha256("b-concurrency/authority-issuance/v1")

        def issue(_: int):
            authority = ReleaseAuthority(self.settings)
            candidate = authority.register_candidate(spec)
            decision = authority.record_decision(
                candidate.candidate_id,
                deterministic_gate_hash=gate_hash,
                review_set_hash=review_hash,
                reconciliation_hash=reconciliation_hash,
                verdict="pass",
            )
            certificate = authority.issue_snapshot(
                decision.decision_id,
                requirements_manifest_hash=spec.requirements_manifest_hash,
                issuance_key=issuance_key,
            )
            return candidate, decision, certificate

        results = _run_concurrently(4, issue)
        candidates = [item[0] for item in results]
        decisions = [item[1] for item in results]
        certificates = [item[2] for item in results]

        self.assertEqual(1, sum(item.created for item in candidates))
        self.assertEqual(1, sum(item.created for item in decisions))
        self.assertEqual(1, sum(item.created for item in certificates))
        self.assertEqual(1, len({item.candidate_id for item in candidates}))
        self.assertEqual(1, len({item.decision_id for item in decisions}))
        self.assertEqual(1, len({item.snapshot_id for item in certificates}))
        self.assertEqual(1, len({item.snapshot_urn for item in certificates}))

        connection = connect_database(self.settings.database_path)
        try:
            self.assertEqual(
                (1, 1, 1, 1),
                tuple(
                    int(connection.execute(query).fetchone()[0])
                    for query in (
                        "SELECT count(*) FROM release_candidate",
                        "SELECT count(*) FROM release_decision",
                        "SELECT count(*) FROM release_snapshot",
                        "SELECT count(*) FROM outbox_event "
                        "WHERE event_type='PlatformReleaseSnapshotIssued'",
                    )
                ),
            )
        finally:
            connection.close()

    def test_certified_archive_publish_and_activation_are_concurrently_idempotent(
        self,
    ) -> None:
        certified = self._certified_release()

        results = _run_concurrently(
            4,
            lambda _: ArchiveCatalog(self.settings).publish_release(certified),
        )

        self.assertEqual(1, sum(item.created for item in results))
        self.assertEqual(1, len({item.research_id for item in results}))
        self.assertEqual(1, len({item.research_release_id for item in results}))
        self.assertEqual(1, len({item.activation_id for item in results}))
        self.assertEqual({1}, {item.active_revision for item in results})

        with archive_connection(self.settings) as connection:
            self.assertEqual(
                (1, 1, 1, 1, 1, 1),
                tuple(
                    int(connection.execute(query).fetchone()[0])
                    for query in (
                        "SELECT count(*) FROM research",
                        "SELECT count(*) FROM research_release",
                        "SELECT count(*) FROM research_release_candidate_identity",
                        "SELECT count(*) FROM research_release_activation",
                        "SELECT count(*) FROM active_research_release",
                        "SELECT count(*) FROM research_release_authority_consumption",
                    )
                ),
            )
            self.assertEqual(
                1,
                connection.execute(
                    "SELECT count(*) FROM outbox_event "
                    "WHERE event_type='ArchiveResearchReleaseActivated'"
                ).fetchone()[0],
            )

    def test_comment_revision_competition_has_exactly_one_winner(self) -> None:
        research_id = self._published_research_id()
        collaboration = ArchiveCollaboration(self.settings)
        created = collaboration.create_comment(
            research_id,
            self.actor,
            "并发更新前的评论",
            idempotency_key="b-concurrency-comment-create-0001",
        )
        self.assertTrue(created.ok)
        comment_id = str(created.data["comment_id"])

        outcomes = _run_concurrently(
            2,
            lambda index: ArchiveCollaboration(self.settings).update_comment(
                comment_id,
                self.actor,
                f"并发候选正文 {index}",
                expected_revision=1,
                idempotency_key=f"b-concurrency-comment-update-{index:04d}",
            ),
        )

        winners = [item for item in outcomes if item.ok]
        rejected = [item for item in outcomes if not item.ok]
        self.assertEqual(1, len(winners))
        self.assertEqual(1, len(rejected))
        self.assertEqual(2, winners[0].data["revision"])
        self.assertEqual(409, rejected[0].status)
        self.assertEqual("revision_conflict", rejected[0].error_code)

        comments = collaboration.list_comments(research_id)
        self.assertEqual(1, len(comments))
        self.assertEqual(2, comments[0]["revision"])
        self.assertEqual(winners[0].data["content"], comments[0]["content"])
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                2,
                connection.execute(
                    "SELECT count(*) FROM comment_event WHERE comment_id=?",
                    (comment_id,),
                ).fetchone()[0],
            )
            self.assertEqual(
                3,
                connection.execute(
                    "SELECT count(*) FROM command_receipt "
                    "WHERE command_name LIKE 'comment.%'"
                ).fetchone()[0],
            )

    def test_same_comment_idempotency_key_creates_once_and_replays_once(self) -> None:
        research_id = self._published_research_id()
        key = "b-concurrency-comment-same-key-0001"

        outcomes = _run_concurrently(
            2,
            lambda _: ArchiveCollaboration(self.settings).create_comment(
                research_id,
                self.actor,
                "同 key、同 payload 的并发评论",
                idempotency_key=key,
            ),
        )

        self.assertTrue(all(item.ok for item in outcomes))
        self.assertEqual(1, sum(not item.replayed for item in outcomes))
        self.assertEqual(1, sum(item.replayed for item in outcomes))
        self.assertEqual(1, len({item.data["comment_id"] for item in outcomes}))
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                (1, 1, 1, 1),
                tuple(
                    int(connection.execute(query, (key,)).fetchone()[0])
                    if "?" in query
                    else int(connection.execute(query).fetchone()[0])
                    for query in (
                        "SELECT count(*) FROM command_receipt WHERE idempotency_key=?",
                        "SELECT count(*) FROM comment",
                        "SELECT count(*) FROM comment_event",
                        "SELECT count(*) FROM outbox_event "
                        "WHERE event_type='ArchiveCommentCreated'",
                    )
                ),
            )

    def test_same_comment_key_with_different_payload_fails_closed(self) -> None:
        research_id = self._published_research_id()
        key = "b-concurrency-comment-collision-0001"

        def create(index: int) -> tuple[str, CommandOutcome | IdempotencyConflict]:
            try:
                outcome = ArchiveCollaboration(self.settings).create_comment(
                    research_id,
                    self.actor,
                    f"竞争 payload {index}",
                    idempotency_key=key,
                )
            except IdempotencyConflict as error:
                return "conflict", error
            return "outcome", outcome

        results = _run_concurrently(2, create)

        self.assertEqual(1, sum(kind == "outcome" for kind, _ in results))
        self.assertEqual(1, sum(kind == "conflict" for kind, _ in results))
        outcome = next(value for kind, value in results if kind == "outcome")
        self.assertIsInstance(outcome, CommandOutcome)
        assert isinstance(outcome, CommandOutcome)
        self.assertTrue(outcome.ok)
        with archive_connection(self.settings) as connection:
            self.assertEqual(
                (1, 1, 1),
                (
                    connection.execute(
                        "SELECT count(*) FROM command_receipt WHERE idempotency_key=?",
                        (key,),
                    ).fetchone()[0],
                    connection.execute("SELECT count(*) FROM comment").fetchone()[0],
                    connection.execute("SELECT count(*) FROM comment_event").fetchone()[0],
                ),
            )


if __name__ == "__main__":
    import unittest

    unittest.main()
