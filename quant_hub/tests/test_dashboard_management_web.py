from __future__ import annotations

from quant_hub.app import create_app
from tests.helpers import SettingsTestCase


class DashboardManagementWebTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.comment_database = self.project / "persistent" / "comments.sqlite3"
        self.app = create_app(
            self.settings,
            {
                "TESTING": True,
                "SECRET_KEY": "dashboard-management-web-test",
                "TRUSTED_ORIGINS": ("http://localhost",),
                "COMMENT_DATABASE_PATH": str(self.comment_database),
            },
        )
        self.client = self.app.test_client()
        session = self.client.get("/api/v1/session")
        self.assertEqual(200, session.status_code)
        self.csrf = session.get_json()["data"]["csrf_token"]

    def headers(self, key: str, *, etag: str | None = None) -> dict[str, str]:
        headers = {
            "Origin": "http://localhost",
            "X-CSRF-Token": self.csrf,
            "Idempotency-Key": key,
        }
        if etag is not None:
            headers["If-Match"] = etag
        return headers

    def assert_envelope(self, response, status: int, error: str | None = None):
        self.assertEqual(status, response.status_code, response.get_data(as_text=True))
        self.assertEqual("application/json", response.mimetype)
        payload = response.get_json()
        self.assertEqual("v1", payload["api_version"])
        self.assertIn("request_id", payload["meta"])
        if error is None:
            self.assertIn("data", payload)
            self.assertNotIn("error", payload)
        else:
            self.assertEqual(error, payload["error"]["code"])
            self.assertNotIn("data", payload)
        return payload

    def test_home_exposes_unified_workspace_lifecycle_and_accessible_controls(self) -> None:
        response = self.client.get("/")
        self.assertEqual(200, response.status_code)
        html = response.get_data(as_text=True)

        for heading in ("量化研究工作台", "最近研究更新", "研究目录"):
            self.assertEqual(1, html.count(f">{heading}<"), heading)
        for lifecycle in (
            "待开始",
            "进行中",
            "待复核",
            "已完成",
            "有价值但暂时搁置",
            "已取消",
        ):
            self.assertIn(lifecycle, html)
        self.assertIn('name="q"', html)
        self.assertIn('name="parent_node_id"', html)
        self.assertIn('name="status"', html)
        self.assertNotIn('name="node_kind"', html)
        self.assertIn("data-workspace-sync", html)
        self.assertIn('role="status" aria-live="polite"', html)
        self.assertIn("研究进度监视", html)
        self.assertIn("其他待完成研究", html)
        self.assertIn("值得推进但暂时搁置的研究", html)
        self.assertEqual(2, html.count("data-topic-create"))
        self.assertNotIn("data-research-project-create", html)
        self.assertIn("不会生成 Q 编号", html)

        with self.client.get("/static/app.js") as script_response:
            script = script_response.get_data(as_text=True)
        self.assertIn("/api/v1/research-tree/sync", script)
        self.assertIn("/api/v1/research-nodes/", script)
        self.assertIn("/api/v1/research-node-comments/", script)
        self.assertIn('headers["If-Match"] = etag', script)
        self.assertIn("globalThis.confirm", script)
        self.assertIn("research-tree-sync", script)

    def test_manual_topic_rest_lifecycle_is_audited_concurrent_and_idempotent(self) -> None:
        root_body = {
            "actor": {"actor_kind": "zhang_zhengze", "display_name": None},
            "title": "跨市场稳健性评估",
            "state": "planned",
            "note": "形成跨市场、跨时段与成本扰动下的稳健性证据。",
            "parent_topic_id": None,
        }
        root_headers = self.headers("dashboard-root-create-0001")
        created = self.client.post(
            "/api/v1/dashboard-topics", json=root_body, headers=root_headers
        )
        root_payload = self.assert_envelope(created, 201)["data"]
        root_id = root_payload["topic_id"]
        root_etag = created.headers["ETag"]
        self.assertRegex(root_etag, rf'^"topic:{root_id}:r1"$')
        self.assertEqual("false", created.headers["Idempotency-Replayed"])
        self.assertTrue(root_payload["is_manual"])
        self.assertEqual("张正泽", root_payload["created_by"]["display_name"])
        self.assertEqual("张正泽", root_payload["last_modified_by"]["display_name"])

        replay = self.client.post(
            "/api/v1/dashboard-topics", json=root_body, headers=root_headers
        )
        self.assert_envelope(replay, 201)
        self.assertEqual(root_id, replay.get_json()["data"]["topic_id"])
        self.assertEqual("true", replay.headers["Idempotency-Replayed"])

        collision_body = {**root_body, "title": "同键不同载荷"}
        collision = self.client.post(
            "/api/v1/dashboard-topics", json=collision_body, headers=root_headers
        )
        self.assert_envelope(collision, 409, "idempotency_conflict")

        child_body = {
            "actor": {"actor_kind": "other", "display_name": "研究协作者"},
            "title": "成本冲击情景",
            "state": "paused",
            "note": "等待交易成本数据补齐后恢复。",
            "parent_topic_id": None,
        }
        child_created = self.client.post(
            "/api/v1/dashboard-topics",
            json=child_body,
            headers=self.headers("dashboard-child-create-0001"),
        )
        child_payload = self.assert_envelope(child_created, 201)["data"]
        child_id = child_payload["topic_id"]
        child_etag = child_created.headers["ETag"]
        self.assertEqual(0, child_payload["depth"])
        self.assertIsNone(child_payload["parent_topic_id"])
        self.assertEqual("研究协作者", child_payload["created_by"]["display_name"])

        nested = self.client.post(
            "/api/v1/dashboard-topics",
            json={**child_body, "title": "错误的层级议题", "parent_topic_id": root_id},
            headers=self.headers("dashboard-nested-rejected-0001"),
        )
        self.assert_envelope(nested, 422, "invalid_topic_parent")

        listed = self.assert_envelope(self.client.get("/api/v1/dashboard-topics"), 200)
        listed_topics = listed["data"]["topics"]
        self.assertEqual(2, len(listed_topics))
        self.assertEqual({root_id, child_id}, {item["topic_id"] for item in listed_topics})
        for item in listed_topics:
            self.assertIn("revision", item)
            self.assertIn("etag", item)

        home = self.client.get("/").get_data(as_text=True)
        self.assertIn("量化研究工作台", home)
        self.assertIn("跨市场稳健性评估", home)
        self.assertIn("成本冲击情景", home)
        self.assertIn("data-topic-managed", home)
        self.assertNotIn("Q8｜跨市场稳健性评估", home)

        update_body = {
            "actor": {"actor_kind": "song_dingkun", "display_name": None},
            "title": "成本冲击与容量约束情景",
            "state": "planned",
            "note": "已补齐成本数据，转入待完成队列。",
            "parent_topic_id": None,
        }
        missing = self.client.patch(
            f"/api/v1/dashboard-topics/{child_id}",
            json=update_body,
            headers=self.headers("dashboard-child-missing-etag-0001"),
        )
        self.assert_envelope(missing, 428, "precondition_required")
        malformed = self.client.patch(
            f"/api/v1/dashboard-topics/{child_id}",
            json=update_body,
            headers=self.headers(
                "dashboard-child-bad-etag-0001", etag='W/"topic:bad:r1"'
            ),
        )
        self.assert_envelope(malformed, 400, "invalid_precondition")
        wrong_target = self.client.patch(
            f"/api/v1/dashboard-topics/{child_id}",
            json=update_body,
            headers=self.headers("dashboard-child-wrong-target-0001", etag=root_etag),
        )
        self.assert_envelope(wrong_target, 400, "precondition_target_mismatch")

        updated = self.client.patch(
            f"/api/v1/dashboard-topics/{child_id}",
            json=update_body,
            headers=self.headers("dashboard-child-update-0001", etag=child_etag),
        )
        updated_payload = self.assert_envelope(updated, 200)["data"]
        updated_etag = updated.headers["ETag"]
        self.assertRegex(updated_etag, rf'^"topic:{child_id}:r2"$')
        self.assertEqual(2, updated_payload["revision"])
        self.assertIsNone(updated_payload["parent_topic_id"])
        self.assertEqual("planned", updated_payload["manual_state"])
        self.assertEqual("宋定坤", updated_payload["last_modified_by"]["display_name"])

        stale = self.client.patch(
            f"/api/v1/dashboard-topics/{child_id}",
            json={**update_body, "title": "过期写入"},
            headers=self.headers("dashboard-child-stale-0001", etag=child_etag),
        )
        self.assert_envelope(stale, 409, "revision_conflict")

        detail = self.client.get(f"/api/v1/dashboard-topics/{child_id}")
        detail_payload = self.assert_envelope(detail, 200)["data"]["topic"]
        self.assertEqual("成本冲击与容量约束情景", detail_payload["title"])
        self.assertEqual(updated_etag, detail.headers["ETag"])

        delete_body = {
            "actor": {"actor_kind": "zhang_zhengze", "display_name": None}
        }
        delete_headers = self.headers("dashboard-root-delete-0001", etag=root_etag)
        deleted = self.client.delete(
            f"/api/v1/dashboard-topics/{root_id}",
            json=delete_body,
            headers=delete_headers,
        )
        deleted_payload = self.assert_envelope(deleted, 200)["data"]
        self.assertTrue(deleted_payload["retired"])
        self.assertRegex(deleted.headers["ETag"], rf'^"topic:{root_id}:r2"$')

        delete_replay = self.client.delete(
            f"/api/v1/dashboard-topics/{root_id}",
            json=delete_body,
            headers=delete_headers,
        )
        self.assert_envelope(delete_replay, 200)
        self.assertEqual("true", delete_replay.headers["Idempotency-Replayed"])

        visible = self.client.get("/api/v1/dashboard-topics").get_json()["data"]["topics"]
        self.assertEqual([child_id], [item["topic_id"] for item in visible])
        all_items = self.client.get(
            "/api/v1/dashboard-topics", query_string={"include_retired": "true"}
        ).get_json()["data"]["topics"]
        self.assertEqual(2, len(all_items))
        retired = next(item for item in all_items if item["topic_id"] == root_id)
        self.assertTrue(retired["retired"])
        self.assertIsNotNone(retired["retired_at"])
        self.assertEqual(
            404,
            self.client.get(f"/api/v1/dashboard-topics/{root_id}").status_code,
        )
        retired_detail = self.client.get(
            f"/api/v1/dashboard-topics/{root_id}",
            query_string={"include_retired": "true"},
        )
        self.assert_envelope(retired_detail, 200)

        bad_query = self.client.get(
            "/api/v1/dashboard-topics", query_string={"include_retired": "not-bool"}
        )
        self.assert_envelope(bad_query, 422, "validation_error")

    def test_management_writes_require_csrf_and_creation_rejects_if_match(self) -> None:
        body = {
            "actor": {"actor_kind": "zhang_zhengze", "display_name": None},
            "title": "安全边界测试",
            "state": "planned",
        }
        no_csrf = self.client.post(
            "/api/v1/dashboard-topics",
            json=body,
            headers={
                "Origin": "http://localhost",
                "Idempotency-Key": "dashboard-no-csrf-0001",
            },
        )
        self.assert_envelope(no_csrf, 403, "csrf_rejected")

        unexpected = self.client.post(
            "/api/v1/dashboard-topics",
            json=body,
            headers=self.headers(
                "dashboard-unexpected-etag-0001",
                etag='"topic:top_00000000000000000000000000000000:r1"',
            ),
        )
        self.assert_envelope(unexpected, 400, "unexpected_precondition")


if __name__ == "__main__":
    import unittest

    unittest.main()
