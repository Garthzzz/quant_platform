from __future__ import annotations

from contextlib import closing
import copy
import json
from pathlib import Path
import sqlite3

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.contracts import (
    ActorInput,
    ArchiveDocumentInput,
    ArchiveReleaseInput,
    ManualTopicCreateInput,
    ManualTopicUpdateInput,
)
from quant_hub.collaboration.service import ArchiveCollaboration
from quant_hub.evidence.database import initialize_evidence_database
from quant_hub.ids import sha256_hex, stable_sha256
from quant_hub.paper_lab.database import initialize_paper_lab_database
from quant_hub.paper_lab.contracts import EDITABLE_PAPER_FIELDS as CONTRACT_EDITABLE_FIELDS
from quant_hub.paper_lab.service import EDITABLE_PAPER_FIELDS, PaperLabService
from quant_hub.platform.db import connect_database
from quant_hub.platform.reviews import (
    ReviewCertificateSpec,
    review_certificate_material_hash,
)
from quant_hub.reviewed_runtime import (
    _review_certificate_matches_candidate,
    _validate_archive_command_request,
    _validate_archive_closure,
    _validate_archive_receipt_actor,
    _validate_paper_lab_closure,
    _validate_rejected_archive_receipt,
    capture_runtime_state,
    validate_resume_state,
)
from quant_hub.runtime_seal import RuntimeSealError, canonical_json, payload_sha256
from tests.helpers import SettingsTestCase


class ReviewedRuntimeRecoveryTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        (self.project / "reference" / "proj2").mkdir(parents=True)
        (self.project / "quant_hub" / "paper_lab" / "papers").mkdir(parents=True)
        (self.project / "quant_hub" / "paper_lab" / "papers" / ".gitkeep").write_bytes(b"\n")
        ArchiveCatalog(self.settings).initialize()
        initialize_evidence_database(self.settings)
        initialize_paper_lab_database(self.settings)
        (self.var / "inbox").mkdir(parents=True, exist_ok=True)
        with closing(connect_database(self.settings.archive_database_path)) as connection:
            connection.execute(
                """
                INSERT INTO research(
                    research_id,canonical_slug,display_title,lifecycle_status,created_at
                ) VALUES('res_runtime','runtime','运行期测试','active','2026-01-01T00:00:00Z')
                """
            )
        self.code_root = self.var / "runtime_contract" / "code"
        self.migrations_root = self.var / "runtime_contract" / "migrations"
        self.launcher = self.code_root / "tools" / "run_local.py"
        self.launcher.parent.mkdir(parents=True)
        self.migrations_root.mkdir(parents=True)
        self.launcher.write_text("# frozen launcher fixture\n", encoding="utf-8")
        (self.code_root / "src.txt").write_text("frozen code\n", encoding="utf-8")
        (self.migrations_root / "contract.sql").write_text(
            "-- frozen migrations\n", encoding="utf-8"
        )

    def capture(self) -> dict[str, object]:
        return capture_runtime_state(
            project=self.project,
            delivery=self.var,
            code_root=self.code_root,
            migrations_root=self.migrations_root,
            launcher_path=self.launcher,
        )

    def validate(self, baseline: dict[str, object]) -> dict[str, object]:
        return validate_resume_state(
            receipt={"runtime_state_after_create_app": baseline},
            project=self.project,
            delivery=self.var,
            code_root=self.code_root,
            migrations_root=self.migrations_root,
            launcher_path=self.launcher,
        )

    @staticmethod
    def actor() -> ActorInput:
        return ActorInput(actor_kind="zhang_zhengze", display_name="张正泽")

    def publish_runtime_update_fixture(self):
        relative_path = "runtime-update.md"
        source = "# 运行期更新\n\n用于 reviewed runtime 闭包测试。\n".encode("utf-8")
        (self.archive / relative_path).write_bytes(source)
        release = ArchiveReleaseInput(
            research_slug="runtime-update",
            display_title="运行期更新",
            release_key="v1",
            documents=(
                ArchiveDocumentInput(
                    document_slug="main",
                    document_role="primary",
                    source_path=relative_path,
                    **self.approved_source_fields(relative_path),
                    navigation_role="primary",
                    sort_key=10,
                    mapping_authority_urn="qrh:review:runtime-update",
                    mapping_note="reviewed runtime update closure fixture",
                ),
            ),
            summary="运行期更新闭包测试。",
            summary_provenance_urn=(
                f"qrh:object:obj_sha256_{sha256_hex(source)}"
            ),
            activate=False,
        )
        return self.publish_with_test_certificate(
            ArchiveCatalog(self.settings),
            release,
            label="runtime-update-v1",
        )

    def test_archive_outbox_event_version_is_closed_over_command(self) -> None:
        baseline = self.capture()
        outcome = ArchiveCollaboration(self.settings).set_work_state(
            "res_runtime",
            "in_progress",
            None,
            self.actor(),
            idempotency_key="runtime-event-version",
        )
        self.assertTrue(outcome.ok)
        actual = self.capture()
        before = baseline["databases"]["archive.sqlite3"]["row_manifest"]
        forged = copy.deepcopy(
            actual["databases"]["archive.sqlite3"]["row_manifest"]
        )
        table = forged["outbox_event"]
        columns = table["columns"]
        event_type_index = columns.index("event_type")
        event_version_index = columns.index("event_version")
        row = next(
            item
            for item in table["rows"]
            if item["values"][event_type_index] == "ArchiveResearchWorkStateSet"
        )
        row["values"][event_version_index] = "2"
        row["row_sha256"] = payload_sha256(row["values"])
        table["manifest_sha256"] = payload_sha256(table["rows"])
        with self.assertRaisesRegex(RuntimeSealError, "event version"):
            _validate_archive_closure(
                before,
                forged,
                platform_actual=actual["databases"]["platform.sqlite3"]["row_manifest"],
            )

    def test_update_annotation_outbox_timestamp_is_bound_to_annotation_event(self) -> None:
        published = self.publish_runtime_update_fixture()
        collaboration = ArchiveCollaboration(self.settings)
        update_id = stable_sha256(
            published.research_id,
            published.document_manifest_hash,
            "published",
        )
        baseline = self.capture()
        outcome = collaboration.annotate_research_update(
            update_id,
            self.actor(),
            "运行期说明",
            expected_revision=0,
            idempotency_key="runtime-update-annotation-timestamp",
        )
        self.assertTrue(outcome.ok)
        actual = self.capture()
        before = baseline["databases"]["archive.sqlite3"]["row_manifest"]
        forged = copy.deepcopy(
            actual["databases"]["archive.sqlite3"]["row_manifest"]
        )
        table = forged["outbox_event"]
        columns = table["columns"]
        event_type_index = columns.index("event_type")
        created_at_index = columns.index("created_at")
        row = next(
            item
            for item in table["rows"]
            if item["values"][event_type_index] == "ArchiveResearchUpdateAnnotated"
        )
        row["values"][created_at_index] = "2099-01-01T00:00:00Z"
        row["row_sha256"] = payload_sha256(row["values"])
        table["manifest_sha256"] = payload_sha256(table["rows"])
        with self.assertRaisesRegex(RuntimeSealError, "timestamp differs"):
            _validate_archive_closure(
                before,
                forged,
                platform_actual=actual["databases"]["platform.sqlite3"]["row_manifest"],
            )

    def test_resume_rejects_a_self_consistent_but_corrupt_update_baseline(self) -> None:
        self.publish_runtime_update_fixture()
        collaboration = ArchiveCollaboration(self.settings)
        with closing(connect_database(self.settings.archive_database_path)) as connection:
            connection.execute("DROP TRIGGER research_update_no_update")
            connection.execute(
                "UPDATE research_update SET release_revision=99"
            )
        # Make the checkpoint and JSONL agree with the forged row.  The runtime
        # gate must still reject it by independently replaying the activation chain.
        collaboration.export_research_update_history()
        corrupt_baseline = self.capture()
        with self.assertRaisesRegex(
            RuntimeSealError,
            "first activation occurrence",
        ):
            self.validate(corrupt_baseline)

    def test_archive_requests_reuse_shared_contracts_and_canonical_notes(self) -> None:
        with self.assertRaisesRegex(RuntimeSealError, "actor"):
            _validate_archive_receipt_actor(
                command="topic.create",
                request={
                    "actor": {
                        "actor_kind": "zhang_zhengze",
                        "display_name": "伪造姓名",
                    }
                },
                receipt={"actor_id": "act_forged"},
                actors={
                    "act_forged": {
                        "actor_kind": "zhang_zhengze",
                        "display_name": "伪造姓名",
                    }
                },
            )
        with self.assertRaisesRegex(RuntimeSealError, "topic"):
            _validate_archive_command_request(
                "topic.create",
                {
                    "topic": {
                        "topic_key": "INVALID_TOPIC",
                        "title": "不可由 TopicInput 构造",
                        "manual_order": 1,
                    },
                    "actor": self.actor().model_dump(mode="json"),
                },
            )
        for command, request in (
            (
                "topic.set_state",
                {
                    "topic_id": "top_" + "a" * 32,
                    "state": "paused",
                    "note": "  非规范说明  ",
                    "actor": self.actor().model_dump(mode="json"),
                },
            ),
            (
                "research.set_work_state",
                {
                    "research_id": "res_runtime",
                    "state": "paused",
                    "note": "  非规范说明  ",
                    "actor": self.actor().model_dump(mode="json"),
                },
            ),
        ):
            with self.subTest(command=command), self.assertRaisesRegex(
                RuntimeSealError, "state"
            ):
                _validate_archive_command_request(command, request)

    @staticmethod
    def _review_material() -> tuple[dict[str, object], dict[str, object]]:
        identity = {
            "subject_urn": "qrh:research:test",
            "subject_version_urn": "qrh:research-release:test:v1",
            "artifact_manifest_hash": "1" * 64,
        }
        spec = ReviewCertificateSpec(
            gate_name="archive_research_completion",
            gate_version="1",
            subject_urn=str(identity["subject_urn"]),
            subject_version_urn=str(identity["subject_version_urn"]),
            artifact_manifest_hash=str(identity["artifact_manifest_hash"]),
            requirements_manifest_hash=stable_sha256(
                "archive-completion-review-requirements/v1",
                "active-release-bound",
                "frozen-review-artifact",
                "released-summary-required",
                "source-completion-evidence",
            ),
            review_artifact_hash="2" * 64,
            review_set_hash="3" * 64,
            reviewer_identity_hash="4" * 64,
        )
        issuance_key = "5" * 64
        issued_at = "2026-01-01T00:00:00Z"
        certificate_id = "rvc_test"
        certificate = {
            "certificate_id": certificate_id,
            "certificate_urn": f"qrh:review-certificate:{certificate_id}",
            "gate_name": spec.gate_name,
            "gate_version": spec.gate_version,
            "subject_urn": spec.subject_urn,
            "subject_version_urn": spec.subject_version_urn,
            "artifact_manifest_hash": spec.artifact_manifest_hash,
            "requirements_manifest_hash": spec.requirements_manifest_hash,
            "review_artifact_hash": spec.review_artifact_hash,
            "review_set_hash": spec.review_set_hash,
            "reviewer_identity_hash": spec.reviewer_identity_hash,
            "verdict": "pass",
            "issuance_key": issuance_key,
            "certificate_hash": review_certificate_material_hash(
                spec, issuance_key, issued_at
            ),
            "issued_at": issued_at,
        }
        return identity, certificate

    def test_review_certificate_hash_and_platform_material_are_bound(self) -> None:
        identity, certificate = self._review_material()
        urn = certificate["certificate_urn"]
        self.assertTrue(
            _review_certificate_matches_candidate(
                certificate, certificate_urn=urn, identity=identity
            )
        )
        forged = dict(certificate, certificate_hash="f" * 64)
        self.assertFalse(
            _review_certificate_matches_candidate(
                forged, certificate_urn=urn, identity=identity
            )
        )

    def test_review_rejections_replay_candidate_summary_and_certificate_evidence(self) -> None:
        identity, certificate = self._review_material()
        release_id = "rel_test"
        research_id = "res_runtime"
        request = {
            "research_id": research_id,
            "research_release_id": release_id,
            "reason": "审核式完成",
            "actor": None,
            "review_urn": certificate["certificate_urn"],
        }
        receipt = {
            "http_status": 409,
            "aggregate_urn": f"qrh:research:{research_id}",
            "created_at": "2026-01-02T00:00:00Z",
        }
        common = {
            "command": "research.complete",
            "request": request,
            "receipt": receipt,
            "topics": {},
            "researches": {research_id: {"research_id": research_id}},
            "active_releases": {
                research_id: {"research_release_id": release_id}
            },
            "decisions": {},
            "completion_consumptions": set(),
            "comments": {},
            "comment_events": [],
            "topic_mutations": [],
            "topic_states": [],
            "topic_links": [],
        }
        _validate_rejected_archive_receipt(
            **common,
            error={"code": "review_candidate_incomplete"},
            candidate_identities={},
            released_summary_ids=set(),
            review_certificates={},
        )
        _validate_rejected_archive_receipt(
            **common,
            error={"code": "review_certificate_invalid"},
            candidate_identities={(release_id, research_id): identity},
            released_summary_ids={release_id},
            review_certificates={},
        )
        with self.assertRaisesRegex(RuntimeSealError, "not reachable"):
            _validate_rejected_archive_receipt(
                **common,
                error={"code": "review_certificate_invalid"},
                candidate_identities={(release_id, research_id): identity},
                released_summary_ids={release_id},
                review_certificates={str(certificate["certificate_urn"]): certificate},
            )

    @staticmethod
    def rewrite_receipt_request(
        manifest: dict[str, object],
        command: str,
        mutate: object,
        *,
        aggregate_urn: str | None = None,
    ) -> None:
        table = manifest["command_receipt"]
        columns = table["columns"]
        command_index = columns.index("command_name")
        payload_index = columns.index("payload_hash")
        result_index = columns.index("result_json")
        result_hash_index = columns.index("result_hash")
        aggregate_index = columns.index("aggregate_urn")
        row = next(
            item
            for item in table["rows"]
            if item["values"][command_index] == command
        )
        result = json.loads(row["values"][result_index])
        mutate(result["request"])
        result_json = canonical_json(result)
        row["values"][payload_index] = stable_sha256(
            "archive-command/v1", command, canonical_json(result["request"])
        )
        row["values"][result_index] = result_json
        row["values"][result_hash_index] = stable_sha256(
            "archive-command-result/v1", result_json
        )
        if aggregate_urn is not None:
            row["values"][aggregate_index] = aggregate_urn
        row["row_sha256"] = payload_sha256(row["values"])
        table["manifest_sha256"] = payload_sha256(table["rows"])

    def test_legal_comment_manual_topic_and_blueprint_resume(self) -> None:
        baseline = self.capture()
        collaboration = ArchiveCollaboration(self.settings)
        comment = collaboration.create_comment(
            "res_runtime",
            self.actor(),
            "合法评论",
            idempotency_key="runtime-comment-001",
        )
        self.assertTrue(comment.ok)
        topic = collaboration.create_manual_topic(
            ManualTopicCreateInput(
                title="后续研究",
                state="planned",
                note="待排期",
                manual_order=1,
                parent_topic_id=None,
            ),
            self.actor(),
            idempotency_key="runtime-topic-001",
        )
        self.assertTrue(topic.ok)
        no_op = collaboration.update_manual_topic(
            str(topic.data["topic_id"]),
            ManualTopicUpdateInput(title="后续研究"),
            self.actor(),
            expected_revision=1,
            idempotency_key="runtime-topic-noop-001",
        )
        self.assertTrue(no_op.ok)
        blueprint = PaperLabService(self.settings).save_blueprint(
            "运行期蓝图",
            "验证恢复闭包",
            [],
            idempotency_key="runtime-blueprint-001",
        )
        self.assertEqual(1, blueprint["version"])
        self.validate(baseline)

    def test_baseline_business_row_change_is_rejected_with_unchanged_schema(self) -> None:
        baseline = self.capture()
        with closing(sqlite3.connect(self.settings.archive_database_path)) as connection:
            connection.execute(
                "UPDATE research SET display_title='未授权漂移' WHERE research_id='res_runtime'"
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "activation row changed"):
            self.validate(baseline)

    def test_managed_file_addition_is_rejected_but_safe_drop_pdf_is_untrusted(self) -> None:
        baseline = self.capture()
        drop = self.project / "quant_hub" / "paper_lab" / "papers"
        (drop / "new-paper.pdf").write_bytes(b"%PDF-1.4\ninput\n%%EOF")
        (drop / "ACQUISITION_MANIFEST.json").write_text(
            '{"schema_version":"qrh-paper-acquisition-manifest/v1"}\n',
            encoding="utf-8",
        )
        # 投递区只被安全枚举，不直接纳入 activation 五树或提供下载；
        # 获取清单同样只参与运行基线绑定，不会被当成论文或直接服务。
        self.validate(baseline)
        unsupported = drop / "notes.json"
        unsupported.write_text("{}\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeSealError, "unsupported file"):
            self.validate(baseline)
        unsupported.unlink()
        (self.var / "inbox" / "unreviewed.bin").write_bytes(b"unreviewed")
        with self.assertRaisesRegex(RuntimeSealError, "managed files inbox"):
            self.validate(baseline)

    def test_legacy_topic_and_research_dashboard_state_resume(self) -> None:
        collaboration = ArchiveCollaboration(self.settings)
        topic = collaboration.create_manual_topic(
            ManualTopicCreateInput(
                title="状态议题",
                state="planned",
                note=None,
                manual_order=2,
                parent_topic_id=None,
            ),
            self.actor(),
            idempotency_key="runtime-state-topic-base",
        )
        topic_id = str(topic.data["topic_id"])
        linked = collaboration.link_topic_research(
            topic_id,
            "res_runtime",
            self.actor(),
            link_kind="supporting",
            dashboard_primary=False,
            display_rank=0,
            provenance_urn="qrh:test:runtime-link",
            idempotency_key="runtime-state-link-base",
        )
        self.assertTrue(linked.ok)
        baseline = self.capture()
        topic_state = collaboration.set_topic_state(
            topic_id,
            "paused",
            "等待数据",
            self.actor(),
            idempotency_key="runtime-state-topic-001",
        )
        work_state = collaboration.set_work_state(
            "res_runtime",
            "in_progress",
            "分析中",
            self.actor(),
            idempotency_key="runtime-state-research-001",
        )
        self.assertTrue(topic_state.ok)
        self.assertTrue(work_state.ok)
        self.validate(baseline)

    def test_research_projection_drift_is_rejected_after_legal_event(self) -> None:
        baseline = self.capture()
        outcome = ArchiveCollaboration(self.settings).set_work_state(
            "res_runtime",
            "in_progress",
            None,
            self.actor(),
            idempotency_key="runtime-state-research-drift",
        )
        self.assertTrue(outcome.ok)
        with closing(sqlite3.connect(self.settings.archive_database_path)) as connection:
            connection.execute(
                """
                UPDATE research_status_projection SET work_status='paused'
                WHERE research_id='res_runtime'
                """
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "not deterministic"):
            self.validate(baseline)

    def test_blueprint_validation_drift_is_rejected_despite_valid_receipt(self) -> None:
        baseline = self.capture()
        result = PaperLabService(self.settings).save_blueprint(
            "闭包蓝图",
            "验证三方一致",
            [],
            idempotency_key="runtime-blueprint-drift",
        )
        with closing(sqlite3.connect(self.settings.paper_lab_database_path)) as connection:
            connection.execute(
                """
                UPDATE blueprint_version SET validation_report_json='{"valid":false}'
                WHERE blueprint_version_id=?
                """,
                (result["blueprint_version_id"],),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "validation report differs"):
            self.validate(baseline)

    def test_registered_drop_pdf_has_content_addressed_file_database_event_closure(self) -> None:
        baseline = self.capture()
        drop = self.project / "quant_hub" / "paper_lab" / "papers"
        (drop / "1_runtime.pdf").write_bytes(b"%PDF-1.4\nruntime\n%%EOF")
        service = PaperLabService(self.settings)
        candidate = service.scan().candidates[0]
        outcome = service.register_candidate(candidate.candidate_id)
        self.assertTrue(outcome.created)
        self.validate(baseline)

    def test_repeated_drop_registration_is_a_legal_idempotent_runtime_sequence(self) -> None:
        baseline = self.capture()
        drop = self.project / "quant_hub" / "paper_lab" / "papers"
        (drop / "2_repeated.pdf").write_bytes(b"%PDF-1.4\nrepeated\n%%EOF")
        service = PaperLabService(self.settings)
        candidate = service.scan().candidates[0]
        first = service.register_candidate(candidate.candidate_id)
        second = service.register_candidate(candidate.candidate_id)
        self.assertTrue(first.created)
        self.assertFalse(second.created)
        self.assertEqual(first.paper_version_id, second.paper_version_id)
        self.validate(baseline)

    def test_save_paper_field_create_and_update_have_exact_resume_closure(self) -> None:
        drop = self.project / "quant_hub" / "paper_lab" / "papers"
        (drop / "3_overlay.pdf").write_bytes(b"%PDF-1.4\noverlay\n%%EOF")
        service = PaperLabService(self.settings)
        candidate = service.scan().candidates[0]
        registered = service.register_candidate(candidate.candidate_id)
        latest_version_id = "labver_runtime_overlay_latest"
        with closing(sqlite3.connect(self.settings.paper_lab_database_path)) as connection:
            connection.execute(
                """
                INSERT INTO lab_paper_version(
                    paper_version_id,paper_id,content_sha256,bytes,media_type,
                    original_filename,source_location_urn,asset_relative_path,
                    discovery_status,created_at
                ) VALUES(?,?,?,1,'application/pdf','latest.pdf',
                    'qrh:test:latest-version','fixture/latest.pdf','registered',
                    '2090-01-01T00:00:00Z')
                """,
                (latest_version_id, registered.paper_id, "b" * 64),
            )
            connection.commit()
        baseline = self.capture()
        first = service.save_paper_field(
            registered.paper_id,
            "summary",
            "第一版",
            expected_version=0,
            actor_display_name="张正泽",
            reason="运行期测试",
            idempotency_key="runtime-overlay-001",
        )
        second = service.save_paper_field(
            registered.paper_id,
            "summary",
            "第二版",
            expected_version=1,
            actor_display_name="张正泽",
            reason="继续修订",
            idempotency_key="runtime-overlay-002",
        )
        self.assertEqual((1, 2), (first["version"], second["version"]))
        self.assertEqual(latest_version_id, first["paper_version_id"])
        self.validate(baseline)

    def test_projection_timestamp_drift_is_rejected(self) -> None:
        collaboration = ArchiveCollaboration(self.settings)
        topic = collaboration.create_manual_topic(
            ManualTopicCreateInput(
                title="时间戳议题",
                state="planned",
                note=None,
                manual_order=3,
                parent_topic_id=None,
            ),
            self.actor(),
            idempotency_key="runtime-timestamp-topic-base",
        )
        topic_id = str(topic.data["topic_id"])
        baseline = self.capture()
        collaboration.set_topic_state(
            topic_id,
            "paused",
            None,
            self.actor(),
            idempotency_key="runtime-timestamp-topic-change",
        )
        collaboration.set_work_state(
            "res_runtime",
            "in_progress",
            None,
            self.actor(),
            idempotency_key="runtime-timestamp-research-change",
        )
        with closing(sqlite3.connect(self.settings.archive_database_path)) as connection:
            connection.execute(
                "UPDATE topic_projection SET updated_at='2099-01-01T00:00:00Z' WHERE topic_id=?",
                (topic_id,),
            )
            connection.execute(
                "UPDATE research_status_projection SET updated_at='2099-01-01T00:00:00Z' WHERE research_id='res_runtime'"
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "timestamp|projection"):
            self.validate(baseline)

    def test_same_topic_research_link_can_be_upserted_twice(self) -> None:
        collaboration = ArchiveCollaboration(self.settings)
        topic = collaboration.create_manual_topic(
            ManualTopicCreateInput(
                title="重复关联议题",
                state="planned",
                note=None,
                manual_order=4,
                parent_topic_id=None,
            ),
            self.actor(),
            idempotency_key="runtime-relink-topic-base",
        )
        topic_id = str(topic.data["topic_id"])
        baseline = self.capture()
        first = collaboration.link_topic_research(
            topic_id,
            "res_runtime",
            self.actor(),
            link_kind="supporting",
            dashboard_primary=False,
            display_rank=3,
            provenance_urn="qrh:test:first-link",
            idempotency_key="runtime-relink-001",
        )
        second = collaboration.link_topic_research(
            topic_id,
            "res_runtime",
            self.actor(),
            link_kind="primary",
            dashboard_primary=False,
            display_rank=1,
            provenance_urn="qrh:test:second-link",
            idempotency_key="runtime-relink-002",
        )
        self.assertTrue(first.ok and second.ok)
        self.validate(baseline)

    def test_blueprint_constraints_drift_is_rejected(self) -> None:
        baseline = self.capture()
        result = PaperLabService(self.settings).save_blueprint(
            "确定性蓝图",
            "固定版本契约",
            [],
            idempotency_key="runtime-blueprint-contract",
        )
        with closing(sqlite3.connect(self.settings.paper_lab_database_path)) as connection:
            connection.execute(
                "UPDATE blueprint_version SET constraints_json='{\"forged\":true}' WHERE blueprint_version_id=?",
                (result["blueprint_version_id"],),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "version contract"):
            self.validate(baseline)

    def test_non_comment_receipt_payload_hash_tamper_is_rejected(self) -> None:
        baseline = self.capture()
        outcome = ArchiveCollaboration(self.settings).set_work_state(
            "res_runtime",
            "in_progress",
            None,
            self.actor(),
            idempotency_key="runtime-payload-hash-tamper",
        )
        self.assertTrue(outcome.ok)
        actual = self.capture()
        before = baseline["databases"]["archive.sqlite3"]["row_manifest"]
        after = copy.deepcopy(
            actual["databases"]["archive.sqlite3"]["row_manifest"]
        )
        table = after["command_receipt"]
        columns = table["columns"]
        command_index = columns.index("command_name")
        payload_index = columns.index("payload_hash")
        row = next(
            item
            for item in table["rows"]
            if item["values"][command_index] == "research.set_work_state"
        )
        row["values"][payload_index] = "f" * 64
        row["row_sha256"] = payload_sha256(row["values"])
        table["manifest_sha256"] = payload_sha256(table["rows"])
        with self.assertRaisesRegex(RuntimeSealError, "request/payload hash"):
            _validate_archive_closure(
                before,
                after,
                platform_actual=actual["databases"]["platform.sqlite3"]["row_manifest"],
            )

    def test_applied_non_comment_result_identity_must_match_canonical_request(self) -> None:
        baseline = self.capture()
        outcome = ArchiveCollaboration(self.settings).set_work_state(
            "res_runtime",
            "in_progress",
            None,
            self.actor(),
            idempotency_key="runtime-request-result-identity",
        )
        self.assertTrue(outcome.ok)
        actual = self.capture()
        before = baseline["databases"]["archive.sqlite3"]["row_manifest"]
        after = copy.deepcopy(actual["databases"]["archive.sqlite3"]["row_manifest"])
        table = after["command_receipt"]
        columns = table["columns"]
        command_index = columns.index("command_name")
        payload_index = columns.index("payload_hash")
        result_index = columns.index("result_json")
        result_hash_index = columns.index("result_hash")
        row = next(
            item
            for item in table["rows"]
            if item["values"][command_index] == "research.set_work_state"
        )
        result = json.loads(row["values"][result_index])
        result["request"]["research_id"] = "res_forged"
        result_json = canonical_json(result)
        row["values"][payload_index] = stable_sha256(
            "archive-command/v1",
            "research.set_work_state",
            canonical_json(result["request"]),
        )
        row["values"][result_index] = result_json
        row["values"][result_hash_index] = stable_sha256(
            "archive-command-result/v1", result_json
        )
        row["row_sha256"] = payload_sha256(row["values"])
        table["manifest_sha256"] = payload_sha256(table["rows"])
        with self.assertRaisesRegex(RuntimeSealError, "identity differs|aggregate differs"):
            _validate_archive_closure(
                before,
                after,
                platform_actual=actual["databases"]["platform.sqlite3"]["row_manifest"],
            )

    def test_rejected_topic_link_receipt_still_binds_actor_aggregate_and_entities(self) -> None:
        baseline = self.capture()
        outcome = ArchiveCollaboration(self.settings).link_topic_research(
            "top_missing_runtime",
            "res_runtime",
            self.actor(),
            link_kind="supporting",
            dashboard_primary=False,
            display_rank=1,
            provenance_urn="qrh:test:rejected-link",
            idempotency_key="runtime-rejected-link",
        )
        self.assertFalse(outcome.ok)
        actual = self.capture()
        before = baseline["databases"]["archive.sqlite3"]["row_manifest"]
        legitimate = actual["databases"]["archive.sqlite3"]["row_manifest"]
        platform = actual["databases"]["platform.sqlite3"]["row_manifest"]
        _validate_archive_closure(before, legitimate, platform_actual=platform)
        forged = copy.deepcopy(legitimate)
        table = forged["command_receipt"]
        columns = table["columns"]
        command_index = columns.index("command_name")
        actor_index = columns.index("actor_id")
        aggregate_index = columns.index("aggregate_urn")
        row = next(
            item
            for item in table["rows"]
            if item["values"][command_index] == "topic.link_research"
        )
        row["values"][actor_index] = None
        row["values"][aggregate_index] = "qrh:topic:forged"
        row["row_sha256"] = payload_sha256(row["values"])
        table["manifest_sha256"] = payload_sha256(table["rows"])
        with self.assertRaisesRegex(RuntimeSealError, "actor|aggregate"):
            _validate_archive_closure(before, forged, platform_actual=platform)

    def test_topic_update_expected_revision_binds_mutation_prior_revision(self) -> None:
        collaboration = ArchiveCollaboration(self.settings)
        created = collaboration.create_manual_topic(
            ManualTopicCreateInput(
                title="版本前置条件",
                state="planned",
                note=None,
                manual_order=5,
                parent_topic_id=None,
            ),
            self.actor(),
            idempotency_key="runtime-revision-topic-base",
        )
        topic_id = str(created.data["topic_id"])
        baseline = self.capture()
        changed = collaboration.update_manual_topic(
            topic_id,
            ManualTopicUpdateInput(title="版本前置条件已更新"),
            self.actor(),
            expected_revision=1,
            idempotency_key="runtime-revision-topic-change",
        )
        self.assertTrue(changed.ok)
        actual = self.capture()
        before = baseline["databases"]["archive.sqlite3"]["row_manifest"]
        forged = copy.deepcopy(actual["databases"]["archive.sqlite3"]["row_manifest"])
        self.rewrite_receipt_request(
            forged,
            "topic.update_manual",
            lambda request: request.__setitem__("expected_revision", 999),
        )
        with self.assertRaisesRegex(RuntimeSealError, "prior revision"):
            _validate_archive_closure(
                before,
                forged,
                platform_actual=actual["databases"]["platform.sqlite3"]["row_manifest"],
            )

    def test_rejected_comment_not_found_requires_missing_or_deleted_target(self) -> None:
        collaboration = ArchiveCollaboration(self.settings)
        active = collaboration.create_comment(
            "res_runtime",
            self.actor(),
            "仍然存在",
            idempotency_key="runtime-active-comment-base",
        )
        active_id = str(active.data["comment_id"])
        baseline = self.capture()
        rejected = collaboration.update_comment(
            "cmt_missing_runtime",
            self.actor(),
            "修改",
            expected_revision=1,
            idempotency_key="runtime-comment-not-found",
        )
        self.assertFalse(rejected.ok)
        actual = self.capture()
        before = baseline["databases"]["archive.sqlite3"]["row_manifest"]
        legitimate = actual["databases"]["archive.sqlite3"]["row_manifest"]
        platform = actual["databases"]["platform.sqlite3"]["row_manifest"]
        _validate_archive_closure(before, legitimate, platform_actual=platform)
        forged = copy.deepcopy(legitimate)
        self.rewrite_receipt_request(
            forged,
            "comment.update",
            lambda request: request.__setitem__("comment_id", active_id),
            aggregate_urn=f"qrh:comment:{active_id}",
        )
        with self.assertRaisesRegex(RuntimeSealError, "not reachable"):
            _validate_archive_closure(before, forged, platform_actual=platform)

    def test_rejected_invalid_comment_requires_an_actually_invalid_body(self) -> None:
        baseline = self.capture()
        rejected = ArchiveCollaboration(self.settings).create_comment(
            "res_runtime",
            self.actor(),
            "   ",
            idempotency_key="runtime-invalid-comment",
        )
        self.assertFalse(rejected.ok)
        actual = self.capture()
        before = baseline["databases"]["archive.sqlite3"]["row_manifest"]
        legitimate = actual["databases"]["archive.sqlite3"]["row_manifest"]
        platform = actual["databases"]["platform.sqlite3"]["row_manifest"]
        _validate_archive_closure(before, legitimate, platform_actual=platform)
        forged = copy.deepcopy(legitimate)
        self.rewrite_receipt_request(
            forged,
            "comment.create",
            lambda request: request.__setitem__("body", "合法评论"),
        )
        with self.assertRaisesRegex(RuntimeSealError, "not reachable"):
            _validate_archive_closure(before, forged, platform_actual=platform)

    def test_paper_field_resume_allowlist_matches_service_and_rejects_unknown_field(self) -> None:
        self.assertIs(EDITABLE_PAPER_FIELDS, CONTRACT_EDITABLE_FIELDS)
        drop = self.project / "quant_hub" / "paper_lab" / "papers"
        (drop / "4_overlay-policy.pdf").write_bytes(
            b"%PDF-1.4\noverlay-policy\n%%EOF"
        )
        service = PaperLabService(self.settings)
        registered = service.register_candidate(service.scan().candidates[0].candidate_id)
        baseline = self.capture()
        service.save_paper_field(
            registered.paper_id,
            "summary",
            "合法字段",
            expected_version=0,
            actor_display_name="张正泽",
            reason="策略闭包",
            idempotency_key="runtime-overlay-policy",
        )
        actual = self.capture()
        before = baseline["databases"]["paper_lab.sqlite3"]["row_manifest"]
        after = copy.deepcopy(
            actual["databases"]["paper_lab.sqlite3"]["row_manifest"]
        )
        table = after["paper_lab_event"]
        columns = table["columns"]
        type_index = columns.index("event_type")
        payload_index = columns.index("payload_json")
        event = next(
            item
            for item in table["rows"]
            if item["values"][type_index] == "paper_field_overlay_saved"
        )
        payload = json.loads(event["values"][payload_index])
        payload["request"]["field_name"] = "not_editable"
        event["values"][payload_index] = canonical_json(payload)
        event["row_sha256"] = payload_sha256(event["values"])
        table["manifest_sha256"] = payload_sha256(table["rows"])
        with self.assertRaisesRegex(RuntimeSealError, "canonical request"):
            _validate_paper_lab_closure(before, after, added_managed_files={})

    def test_orphan_content_addressed_paper_lab_asset_is_rejected(self) -> None:
        baseline = self.capture()
        digest = "a" * 64
        orphan = self.settings.paper_lab_asset_root / digest[:2] / f"{digest}.pdf"
        orphan.parent.mkdir(parents=True)
        orphan.write_bytes(b"%PDF-1.4\norphan\n%%EOF")
        with self.assertRaisesRegex(RuntimeSealError, "managed assets do not close"):
            self.validate(baseline)

    def test_orphan_topic_state_event_is_rejected(self) -> None:
        collaboration = ArchiveCollaboration(self.settings)
        topic = collaboration.create_manual_topic(
            ManualTopicCreateInput(
                title="基线议题",
                state="planned",
                note=None,
                manual_order=1,
                parent_topic_id=None,
            ),
            self.actor(),
            idempotency_key="runtime-topic-base",
        )
        topic_id = str(topic.data["topic_id"])
        baseline = self.capture()
        with closing(sqlite3.connect(self.settings.archive_database_path)) as connection:
            actor_id = connection.execute(
                "SELECT actor_id FROM actor WHERE actor_kind='zhang_zhengze'"
            ).fetchone()[0]
            connection.execute(
                """
                INSERT INTO topic_state_event(
                    topic_state_event_id,topic_id,state,note,actor_id,occurred_at,
                    supersedes_event_id
                ) VALUES('tevt_orphan',?,'paused','孤立',?,'2026-02-01T00:00:00Z',NULL)
                """,
                (topic_id, actor_id),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "no unique applied mutation"):
            self.validate(baseline)

    def test_topic_state_supersedes_gap_is_rejected(self) -> None:
        collaboration = ArchiveCollaboration(self.settings)
        created = collaboration.create_manual_topic(
            ManualTopicCreateInput(
                title="基线议题",
                state="planned",
                note="初始",
                manual_order=1,
                parent_topic_id=None,
            ),
            self.actor(),
            idempotency_key="runtime-topic-gap-base",
        )
        topic_id = str(created.data["topic_id"])
        baseline = self.capture()
        now = "2099-02-01T00:00:00Z"
        with closing(sqlite3.connect(self.settings.archive_database_path)) as connection:
            connection.row_factory = sqlite3.Row
            actor_id = connection.execute(
                "SELECT actor_id FROM actor WHERE actor_kind='zhang_zhengze'"
            ).fetchone()[0]
            current = connection.execute(
                "SELECT * FROM topic WHERE topic_id=?", (topic_id,)
            ).fetchone()
            latest_state = connection.execute(
                """
                SELECT * FROM topic_state_event WHERE topic_id=?
                ORDER BY occurred_at DESC,topic_state_event_id DESC LIMIT 1
                """,
                (topic_id,),
            ).fetchone()
            old_snapshot = {
                "title": current["title"],
                "parent_topic_id": current["parent_topic_id"],
                "manual_order": current["manual_order"],
                "manual_state": latest_state["state"],
                "state_note": latest_state["note"],
                "retired_at": current["retired_at"],
            }
            new_snapshot = {**old_snapshot, "manual_state": "paused", "state_note": "暂停"}
            state_event_id = "tevt_gap"
            connection.execute(
                """
                INSERT INTO topic_state_event(
                    topic_state_event_id,topic_id,state,note,actor_id,occurred_at,
                    supersedes_event_id
                ) VALUES(?,?,'paused','暂停',?,?,NULL)
                """,
                (state_event_id, topic_id, actor_id, now),
            )
            connection.execute(
                "UPDATE topic SET revision=2,updated_at=? WHERE topic_id=?", (now, topic_id)
            )
            connection.execute(
                """
                INSERT INTO topic_mutation_event(
                    topic_mutation_event_id,topic_id,event_kind,prior_revision,new_revision,
                    old_payload_json,new_payload_json,actor_id,occurred_at
                ) VALUES('tmut_gap',?,'update',1,2,?,?,?,?)
                """,
                (
                    topic_id,
                    canonical_json(old_snapshot),
                    canonical_json(new_snapshot),
                    actor_id,
                    now,
                ),
            )
            connection.execute(
                """
                UPDATE topic_projection SET effective_state='paused',source_kind='manual',
                    source_event_id=?,updated_at=? WHERE topic_id=?
                """,
                (state_event_id, now, topic_id),
            )
            data = {
                "topic_id": topic_id,
                "topic_key": current["topic_key"],
                "title": current["title"],
                "parent_topic_id": None,
                "manual_order": 1,
                "manual_state": "paused",
                "state_note": "暂停",
                "retired_at": None,
                "revision": 2,
            }
            request = {
                "topic_id": topic_id,
                "changes": {"state": "paused", "note": "暂停"},
                "actor": self.actor().model_dump(mode="json"),
                "expected_revision": 1,
            }
            result_json = canonical_json({"data": data, "request": request})
            connection.execute(
                """
                INSERT INTO command_receipt(
                    receipt_id,idempotency_key,command_name,payload_hash,aggregate_urn,
                    actor_id,outcome,result_json,result_hash,http_status,created_at
                ) VALUES('rcpt_gap','runtime-topic-gap','topic.update_manual',?,? ,?,
                    'applied',?,?,200,?)
                """,
                (
                    stable_sha256(
                        "archive-command/v1",
                        "topic.update_manual",
                        canonical_json(request),
                    ),
                    f"qrh:topic:{topic_id}",
                    actor_id,
                    result_json,
                    stable_sha256("archive-command-result/v1", result_json),
                    now,
                ),
            )
            payload_json = canonical_json(data)
            connection.execute(
                """
                INSERT INTO outbox_event(
                    event_id,event_type,event_version,aggregate_urn,payload_json,payload_hash,
                    created_at,published_at,publish_attempt_count
                ) VALUES('evt_gap','ArchiveManualTopicUpdated','1',?,?,?,?,NULL,0)
                """,
                (
                    f"qrh:topic:{topic_id}",
                    payload_json,
                    stable_sha256("archive-outbox/v1", payload_json),
                    now,
                ),
            )
            connection.commit()
        with self.assertRaisesRegex(RuntimeSealError, "field set is invalid"):
            self.validate(baseline)


if __name__ == "__main__":
    import unittest

    unittest.main()
