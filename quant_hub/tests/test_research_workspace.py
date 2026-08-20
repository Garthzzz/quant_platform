from __future__ import annotations

from quant_hub.app import create_app
from quant_hub.archive.contracts import ActorInput
from quant_hub.archive.database import initialize_archive_database
from quant_hub.research_workspace import ResearchWorkspace
from quant_hub.research_workspace.database import research_workspace_connection
from quant_hub.research_workspace.store import (
    backup_research_workspace_store,
    research_workspace_store_state,
)
from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_down, migrate_up
from tests.helpers import SettingsTestCase


class ResearchWorkspaceTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.workspace_root = self.project / "研究修订工作区"
        self.document = (
            self.workspace_root
            / "01_低信噪比训练体系"
            / "01_训练机制"
            / "01_优化器"
            / "01_学习率与批量规模.md"
        )
        self.document.parent.mkdir(parents=True)
        (self.workspace_root / "README.md").write_text(
            "# 研究工作台\n\n统一管理量化研究目录与研究状态。\n",
            encoding="utf-8",
        )
        (self.workspace_root / "01_低信噪比训练体系" / "README.md").write_text(
            (
                "# 低信噪比训练体系\n\n"
                "研究训练工厂的稳定性、效率与泛化边界。\n\n"
                "## 研究问题\n\n"
                "弱标签条件下，训练工厂如何保留有效信号？\n\n"
                "## 研究结构\n\n"
                "- **训练动态**：比较优化温度与稳定性。\n"
                "- **泛化边界**：验证样本外增量。\n"
            ),
            encoding="utf-8",
        )
        self.document.write_text(
            "# 学习率、批量规模与优化温度\n\n正文 v1。\n",
            encoding="utf-8",
        )
        initialize_archive_database(self.settings)
        self.workspace = ResearchWorkspace(self.settings)
        self.actor = ActorInput(actor_kind="zhang_zhengze")

    def _document_node(self) -> dict[str, object]:
        return next(
            item
            for item in self.workspace.tree()["items"]
            if item["node_kind"] == "document"
        )

    def test_workspace_database_migration_is_independent_and_reversible(self) -> None:
        path = self.var / "db" / "workspace-migration-test.sqlite3"
        connection = connect_database(path)
        self.addCleanup(connection.close)
        root = self.settings.research_workspace_migration_root
        self.assertEqual([1, 2, 3], migrate_up(connection, root))
        self.assertEqual([], migrate_up(connection, root))
        self.assertEqual(
            "ok", connection.execute("PRAGMA integrity_check").fetchone()[0]
        )
        self.assertEqual([], connection.execute("PRAGMA foreign_key_check").fetchall())
        self.assertEqual([3, 2, 1], migrate_down(connection, root, steps=3))

    def test_manual_project_creation_builds_source_directory_and_replays(self) -> None:
        self.workspace.sync()
        outcome = self.workspace.create_project(
            title="Q88｜跨市场稳健性研究",
            description="研究跨市场有效性与约束迁移。",
            research_question="同一信号如何跨市场保持稳定？",
            research_content="比较市场结构、成本边界与样本外退化。",
            lifecycle_status="in_progress",
            status_note="进入资料整理。",
            actor=self.actor,
            idempotency_key="workspace-project-create-0001",
        )
        self.assertTrue(outcome.ok)
        self.assertEqual(201, outcome.status)
        self.assertEqual("Q2｜跨市场稳健性研究", outcome.data["display_title"])
        self.assertEqual("in_progress", outcome.data["lifecycle_status"])
        created = self.workspace_root / "02_跨市场稳健性研究" / "README.md"
        self.assertTrue(created.is_file())
        self.assertIn(
            "## 研究问题\n\n同一信号如何跨市场保持稳定？",
            created.read_text(encoding="utf-8"),
        )

        replay = self.workspace.create_project(
            title="Q88｜跨市场稳健性研究",
            description="研究跨市场有效性与约束迁移。",
            research_question="同一信号如何跨市场保持稳定？",
            research_content="比较市场结构、成本边界与样本外退化。",
            lifecycle_status="in_progress",
            status_note="进入资料整理。",
            actor=self.actor,
            idempotency_key="workspace-project-create-0001",
        )
        self.assertTrue(replay.replayed)
        self.assertEqual(2, len(self.workspace.project_options()))
        detail = self.workspace.get_node(str(outcome.data["node_id"]))
        self.assertTrue(
            any(
                event["actor"]
                and event["actor"]["display_name"] == "张正泽"
                for event in detail["events"]
            )
        )

    def test_sync_is_hierarchical_incremental_and_move_aware(self) -> None:
        report = self.workspace.sync()
        self.assertEqual("completed", report["status"])
        self.assertEqual(5, report["created_count"])
        initial_tree = self.workspace.tree()
        self.assertEqual(initial_tree["total_count"], initial_tree["matched_count"])
        project = next(
            item for item in initial_tree["items"] if item["node_kind"] == "project"
        )
        self.assertEqual(
            "Q1｜低信噪比训练体系",
            project["display_title"],
        )
        self.assertEqual(
            "弱标签条件下，训练工厂如何保留有效信号？",
            project["research_question"],
        )
        self.assertIn("• 训练动态：比较优化温度与稳定性。", project["research_content"])
        self.assertEqual(1, initial_tree["stats"]["todo"])
        self.assertEqual(0, initial_tree["stats"]["in_progress"])
        original = self._document_node()
        original_id = str(original["node_id"])
        self.assertEqual("学习率、批量规模与优化温度", original["display_title"])
        self.assertEqual("todo", original["lifecycle_status"])

        repeat = self.workspace.sync()
        self.assertEqual(0, repeat["created_count"])
        self.assertEqual(0, repeat["updated_count"])

        self.document.write_text(
            "# 学习率、批量规模与优化温度\n\n正文 v2，增加稳定性分析。\n",
            encoding="utf-8",
        )
        changed = self.workspace.sync()
        self.assertGreaterEqual(changed["updated_count"], 1)
        self.assertEqual(original_id, self._document_node()["node_id"])

        moved = self.document.with_name("02_优化温度协同.md")
        self.document.replace(moved)
        self.document = moved
        move_report = self.workspace.sync()
        self.assertEqual(1, move_report["moved_count"])
        moved_node = self._document_node()
        self.assertEqual(original_id, moved_node["node_id"])
        self.assertTrue(str(moved_node["source_relative_path"]).endswith("02_优化温度协同.md"))

        self.document.unlink()
        missing = self.workspace.sync()
        self.assertEqual(1, missing["missing_count"])
        node = self.workspace.get_node(original_id)
        self.assertEqual("missing", node["source_state"])
        self.assertEqual("archived", node["lifecycle_status"])

        self.document.write_text(
            "# 学习率、批量规模与优化温度\n\n正文 v2，增加稳定性分析。\n",
            encoding="utf-8",
        )
        restored = self.workspace.sync()
        self.assertEqual(1, restored["restored_count"])
        self.assertEqual("present", self.workspace.get_node(original_id)["source_state"])

        with research_workspace_connection(self.settings) as connection:
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
            self.assertEqual([], connection.execute("PRAGMA foreign_key_check").fetchall())

    def test_status_metadata_filter_and_node_comments_are_reversible(self) -> None:
        self.workspace.sync()
        node = next(
            item
            for item in self.workspace.tree()["items"]
            if item["node_kind"] == "project"
        )
        node_id = str(node["node_id"])
        updated = self.workspace.update_node(
            node_id,
            {
                "title": "优化温度协同研究",
                "description": "比较学习率与批量规模的联合效应。",
                "research_question": "如何比较优化温度与泛化能力？",
                "research_content": "训练动态、稳定性与样本外增量验证。",
                "lifecycle_status": "review",
                "status_note": "等待交叉验证复核。",
            },
            self.actor,
            expected_revision=int(node["revision"]),
            idempotency_key="workspace-node-update-0001",
        )
        self.assertTrue(updated.ok)
        self.assertEqual("review", updated.data["lifecycle_status"])

        replay = self.workspace.update_node(
            node_id,
            {
                "title": "优化温度协同研究",
                "description": "比较学习率与批量规模的联合效应。",
                "research_question": "如何比较优化温度与泛化能力？",
                "research_content": "训练动态、稳定性与样本外增量验证。",
                "lifecycle_status": "review",
                "status_note": "等待交叉验证复核。",
            },
            self.actor,
            expected_revision=int(node["revision"]),
            idempotency_key="workspace-node-update-0001",
        )
        self.assertTrue(replay.replayed)

        filtered = self.workspace.tree(query="如何比较优化温度", status="review")
        self.assertEqual(1, filtered["matched_count"])
        self.assertGreater(len(filtered["items"]), 1)
        self.assertEqual("system", filtered["tree"][0]["node_kind"])
        projects = self.workspace.project_options()
        self.assertEqual(1, len(projects))
        project_filtered = self.workspace.tree(parent_node_id=projects[0]["node_id"])
        self.assertEqual(4, project_filtered["matched_count"])

        document = self._document_node()
        rejected = self.workspace.update_node(
            str(document["node_id"]),
            {"lifecycle_status": "completed"},
            self.actor,
            expected_revision=int(document["revision"]),
            idempotency_key="workspace-document-status-rejected-0001",
        )
        self.assertFalse(rejected.ok)
        self.assertEqual("project_fields_require_project_node", rejected.error_code)

        created = self.workspace.create_comment(
            node_id,
            self.actor,
            "请补充极端行情下的学习率敏感性。",
            idempotency_key="workspace-comment-create-0001",
        )
        self.assertTrue(created.ok)
        self.assertEqual(1, len(self.workspace.list_comments(node_id)))
        comment_id = str(created.data["comment_id"])
        changed = self.workspace.change_comment(
            comment_id,
            self.actor,
            body="请补充极端行情与成交约束下的学习率敏感性。",
            expected_revision=1,
            idempotency_key="workspace-comment-update-0001",
            delete=False,
        )
        self.assertTrue(changed.ok)
        deleted = self.workspace.change_comment(
            comment_id,
            self.actor,
            body=None,
            expected_revision=2,
            idempotency_key="workspace-comment-delete-0001",
            delete=True,
        )
        self.assertTrue(deleted.ok)
        self.assertEqual([], self.workspace.list_comments(node_id))

    def test_http_workspace_contract_preserves_url_filters_and_etags(self) -> None:
        self.workspace.sync()
        app = create_app(
            self.settings,
            {
                "TESTING": True,
                "SECRET_KEY": "research-workspace-test",
                "TRUSTED_ORIGINS": ("http://localhost",),
            },
        )
        client = app.test_client()
        tree = client.get(
            "/api/v1/research-tree",
            query_string={"q": "学习率", "node_kind": "document"},
        )
        self.assertEqual(200, tree.status_code)
        payload = tree.get_json()["data"]
        self.assertEqual(1, payload["matched_count"])
        node = next(item for item in payload["items"] if item["node_kind"] == "document")
        node_id = node["node_id"]
        project_node = next(
            item for item in payload["items"] if item["node_kind"] == "project"
        )
        project_node_id = project_node["node_id"]
        page = client.get("/", query_string={"q": "学习率", "node": node_id})
        html = page.get_data(as_text=True)
        self.assertEqual(200, page.status_code)
        self.assertIn('value="学习率"', html)
        self.assertIn('aria-current="page"', html)
        self.assertIn("学习率、批量规模与优化温度", html)
        self.assertIn("Q1｜低信噪比训练体系", html)
        self.assertIn("有价值但暂时搁置", html)
        self.assertNotIn("workspace-tree__kind", html)
        self.assertNotIn("节点类型", html)
        self.assertNotIn("新增研究专项", html)
        self.assertNotIn("data-research-project-create", html)
        self.assertIn("研究进度监视", html)
        self.assertIn("<legend>记录者</legend>", html)
        self.assertIn("<legend>编辑者</legend>", html)
        self.assertIn("<legend>评论者</legend>", html)
        self.assertNotIn("记录人", html)
        self.assertNotIn("执行人", html)

        session = client.get("/api/v1/session").get_json()["data"]
        headers = {
            "Origin": "http://localhost",
            "X-CSRF-Token": session["csrf_token"],
            "Idempotency-Key": "workspace-http-update-0001",
            "If-Match": f'"research-node:{node_id}:r{node["revision"]}"',
        }
        update = client.patch(
            f"/api/v1/research-nodes/{project_node_id}",
            json={
                "actor": {"actor_kind": "song_dingkun", "display_name": None},
                "lifecycle_status": "in_progress",
                "research_question": "如何稳定复现弱信号？",
                "status_note": "进入实现验证。",
            },
            headers={
                **headers,
                "If-Match": (
                    f'"research-node:{project_node_id}:r{project_node["revision"]}"'
                ),
            },
        )
        self.assertEqual(200, update.status_code)
        self.assertRegex(
            update.headers["ETag"], rf'^"research-node:{project_node_id}:r\d+"$'
        )

        stale = client.patch(
            f"/api/v1/research-nodes/{project_node_id}",
            json={
                "actor": {"actor_kind": "song_dingkun", "display_name": None},
                "lifecycle_status": "completed",
            },
            headers={
                **headers,
                "Idempotency-Key": "workspace-http-update-stale-0001",
                "If-Match": (
                    f'"research-node:{project_node_id}:r{project_node["revision"]}"'
                ),
            },
        )
        self.assertEqual(409, stale.status_code)

        create_payload = {
            "actor": {"actor_kind": "zhang_zhengze", "display_name": None},
            "title": "新的风险预算研究",
            "description": "研究预算约束与风险暴露。",
            "research_question": "预算约束怎样影响稳健配置？",
            "research_content": "比较约束强度、换手与样本外风险。",
            "lifecycle_status": "todo",
            "status_note": None,
        }
        create_headers = {
            "Origin": "http://localhost",
            "X-CSRF-Token": session["csrf_token"],
            "Idempotency-Key": "workspace-http-project-create-0001",
        }
        created = client.post(
            "/api/v1/research-projects",
            json=create_payload,
            headers=create_headers,
        )
        self.assertEqual(201, created.status_code)
        self.assertEqual("false", created.headers["Idempotency-Replayed"])
        created_data = created.get_json()["data"]
        self.assertEqual("Q2｜新的风险预算研究", created_data["display_title"])
        self.assertRegex(
            created.headers["ETag"],
            rf'^"research-node:{created_data["node_id"]}:r\d+"$',
        )
        replay = client.post(
            "/api/v1/research-projects",
            json=create_payload,
            headers=create_headers,
        )
        self.assertEqual(201, replay.status_code)
        self.assertEqual("true", replay.headers["Idempotency-Replayed"])

        css_response = client.get("/static/styles.css")
        self.addCleanup(css_response.close)
        css = css_response.get_data(as_text=True)
        self.assertIn("word-break: keep-all", css)
        self.assertIn("white-space: nowrap", css)

    def test_external_comment_store_survives_release_database_replacement(self) -> None:
        external = self.project / "persistent_data" / "research_workspace.sqlite3"
        service = ResearchWorkspace(
            self.settings,
            database_path=external,
        )
        service.sync()
        node_id = str(
            next(
                item for item in service.tree()["items"]
                if item["node_kind"] == "document"
            )["node_id"]
        )
        created = service.create_comment(
            node_id,
            self.actor,
            "这条评论必须独立于发布数据库长期保留。",
            idempotency_key="workspace-external-comment-0001",
        )
        self.assertTrue(created.ok)
        self.assertEqual(
            1,
            research_workspace_store_state(
                self.settings, database_path=external
            )["active_comments"],
        )

        replacement = self.var / "db" / "archive.replacement.sqlite3"
        self.settings.archive_database_path.replace(replacement)
        initialize_archive_database(self.settings)
        service_after_update = ResearchWorkspace(
            self.settings,
            database_path=external,
        )
        service_after_update.sync()
        restored_node_id = str(
            next(
                item
                for item in service_after_update.tree()["items"]
                if item["source_relative_path"]
                == self.document.relative_to(self.workspace_root).as_posix()
            )["node_id"]
        )
        # Stable node IDs are release-database local; an external comment remains
        # preserved even when the new release has not yet reconciled its subject ID.
        self.assertEqual(node_id, restored_node_id)
        self.assertEqual(1, len(service_after_update.list_comments(node_id)))
        backup = backup_research_workspace_store(
            self.settings,
            self.project / "persistent_data" / "backups",
            database_path=external,
        )
        self.assertIsNotNone(backup)
        self.assertTrue(backup.is_file())
