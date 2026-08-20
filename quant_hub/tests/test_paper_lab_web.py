from __future__ import annotations

import hashlib
import os
import sqlite3

from quant_hub.app import create_app
from quant_hub.paper_lab.database import paper_lab_connection
from quant_hub.paper_lab.presentation import build_paper_presentation_html
from quant_hub.paper_lab.service import PaperLabService
from quant_hub.paper_lab.web import register_paper_lab
from tests.helpers import SettingsTestCase


class PaperLabWebTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.app = create_app(self.settings, {"TESTING": True})
        register_paper_lab(self.app, self.settings)
        self.client = self.app.test_client()

    def _seed_component(self, *, component_id: str = "component-test-1") -> None:
        with paper_lab_connection(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO concept_component VALUES(
                    ?,'concept_block','legacy-test-1','model','测试组件',1,
                    '{"input_types":[],"output_types":["signal"],"one_liner":"可复原组件"}',
                    '{}',?,'validated','t'
                )
                """,
                (component_id, "a" * 64),
            )

    def _write_headers(self, key: str) -> dict[str, str]:
        token = "A" * 43
        with self.client.session_transaction() as session:
            session["csrf_token"] = token
        return {
            "Origin": "http://localhost",
            "X-CSRF-Token": token,
            "Idempotency-Key": key,
        }

    def _register_paper(self) -> str:
        self.settings.paper_lab_drop_root.mkdir(parents=True, exist_ok=True)
        (self.settings.paper_lab_drop_root / "1_editable.pdf").write_bytes(
            b"%PDF-1.4\neditable fixture\n%%EOF"
        )
        return PaperLabService(self.settings).register_all()[0].paper_id

    def test_index_components_and_empty_list_are_reachable(self) -> None:
        self.assertEqual(self.client.get("/paper-lab/").status_code, 200)
        response = self.client.get("/api/v1/paper-lab/papers")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"]["count"], 0)
        self.assertEqual(
            self.client.get("/api/v1/paper-lab/papers?view=summary").status_code,
            200,
        )
        invalid = self.client.get("/api/v1/paper-lab/papers?view=unknown")
        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(invalid.get_json()["error"]["code"], "invalid_query")
        designer = self.client.get("/paper-lab/designer")
        self.assertEqual(designer.status_code, 200)
        self.assertIn('id="designer-selected"', designer.get_data(as_text=True))
        for restored_designer_control in (
            'id="designer-tab-tags"', 'id="designer-tag-grid"',
            'id="designer-component-dialog"', 'id="designer-visualize"',
            'id="designer-download-svg"', 'id="designer-download-png"',
        ):
            self.assertIn(restored_designer_control, designer.get_data(as_text=True))
        javascript = self.client.get("/paper-lab/static/paper_lab.js")
        try:
            self.assertEqual(javascript.status_code, 200)
            script = javascript.get_data(as_text=True)
            for designer_contract in (
                "componentPayload", "kind=tag_component", "showComponentDetail",
                "architectureSvg", "image/svg+xml", "image/png",
            ):
                self.assertIn(designer_contract, script)
        finally:
            javascript.close()

    def test_index_restores_legacy_viewer_columns_and_interactions(self) -> None:
        response = self.client.get("/paper-lab/")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        legacy_columns = (
            "id", "title", "model_type", "asset_market", "rating", "source_type",
            "start_year", "research_topic", "status", "institution", "data_input",
            "data_preprocess", "method_model", "method_special", "loss_function",
            "training_config", "pipeline_output", "link", "authors", "venue",
            "end_year", "study_period", "sample_length", "prediction_target",
            "input_features", "feature_count", "oos_method", "metrics", "performance",
            "special_tech", "main_findings", "innovations_insights",
            "caveats_replication", "summary", "diagram", "phase", "updated_at",
        )
        for column in legacy_columns:
            self.assertIn(f'data-colkey="{column}"', html)
        for control in (
            'id="paper-lab-advanced"', 'id="paper-column-groups"',
            'id="paper-view-stats"', 'id="paper-view-compare"',
            'id="paper-detail-drawer"', 'id="paper-export-filtered"',
        ):
            self.assertIn(control, html)
        self.assertIn("paper_lab_index.js", html)

        javascript = self.client.get("/paper-lab/static/paper_lab_index.js")
        try:
            self.assertEqual(javascript.status_code, 200)
            script = javascript.get_data(as_text=True)
            for migrated_contract in (
                "COLUMN_GROUPS", "DEFAULT_RATINGS", "renderStats", "renderCompare",
                "openDrawer", "exportCsv", "expected_version", "Idempotency-Key",
            ):
                self.assertIn(migrated_contract, script)
        finally:
            javascript.close()

    def test_profile_styles_expand_drawer_without_flattening_small_labels(self) -> None:
        css = self.client.get("/paper-lab/static/paper_lab.css").get_data(as_text=True)
        script = self.client.get(
            "/paper-lab/static/paper_lab_index.js"
        ).get_data(as_text=True)

        self.assertIn("width:min(68rem,68vw)", css)
        self.assertIn(
            ".paper-library{width:calc(100% - 1.5rem);max-width:116rem;",
            css,
        )
        self.assertIn(".paper-drawer-content{", css)
        self.assertIn("font-size:1rem", css)
        self.assertIn(".paper-drawer-value{", css)
        self.assertIn("line-height:1.58", css)
        self.assertIn(
            ".paper-pipeline-note-text{min-width:0;font-size:.86rem;line-height:1.5}",
            css,
        )
        self.assertIn(".paper-drawer-field h3", css)
        self.assertIn("font-size:.78rem", css)
        self.assertIn(".paper-pipeline-tag", css)
        self.assertIn("font-size:.69rem", css)
        self.assertIn("paper-pipeline-arrow", script)
        self.assertIn('aria-hidden="true">→</span>', script)
        self.assertIn('data-math-rendered="mathml"]>.math-source--fallback', css)
        self.assertIn("overscroll-behavior-inline:contain", css)
        self.assertIn("white-space:pre-wrap", css)
        self.assertNotIn("transition:all", css.replace(" ", ""))

    def test_safe_presentation_projection_renders_math_and_keeps_html_inert(self) -> None:
        raw = (
            "损失-MSE | 均方误差 | "
            r"$L_{MSE} = \frac{1}{N}\sum_{i=1}^{N}(\hat{r}_{i,t+1} - r_{i,t+1})^2$"
            "\n→ 最小化预测误差 <img src=x onerror=alert(1)>"
        )

        projected = build_paper_presentation_html({"loss_function": raw})[
            "loss_function"
        ]

        self.assertIn('class="paper-pipeline-tag paper-pipeline-loss"', projected)
        self.assertIn('class="paper-pipeline-arrow"', projected)
        self.assertIn('data-math-rendered="mathml"', projected)
        self.assertIn("<math", projected)
        self.assertNotIn(r"$L_{MSE}", projected)
        self.assertNotIn("<img", projected)
        self.assertIn("&lt;img", projected)

    def test_pipeline_projection_repairs_bounded_legacy_latex_and_inline_arrow(self) -> None:
        raw = (
            "loss | " + r"$\beta_1$ coefficient" + " | "
            + "$L = \x0crac{1}{N}\\sum_i e_i^2$ → minimizes error"
        )

        projected = build_paper_presentation_html({"loss_function": raw})[
            "loss_function"
        ]

        self.assertEqual(2, projected.count('data-math-rendered="mathml"'))
        self.assertIn('class="paper-pipeline-arrow"', projected)
        self.assertIn("minimizes error", projected)
        self.assertNotIn("\x0c", projected)
        self.assertNotIn(r"$\beta_1$", projected)
        self.assertIn("\x0crac", raw)

    def test_detail_api_adds_parallel_presentation_without_mutating_raw_fields(self) -> None:
        paper_id = self._register_paper()
        raw = (
            "损失-MSE | 均方误差 | "
            r"$L_{MSE} = \frac{1}{N}\sum_{i=1}^{N}(\hat{r}_{i,t+1} - r_{i,t+1})^2$"
            "\n→ 作为统一回归目标"
        )
        updated = self.client.patch(
            f"/api/v1/paper-lab/papers/{paper_id}",
            json={
                "field": "loss_function",
                "value": raw,
                "expected_version": 0,
                "actor_display_name": "测试研究员",
                "reason": "公式展示回归",
            },
            headers=self._write_headers("paper-profile-math-1"),
        )
        self.assertEqual(200, updated.status_code)

        detail = self.client.get(f"/api/v1/paper-lab/papers/{paper_id}")
        self.assertEqual(200, detail.status_code)
        paper = detail.get_json()["data"]["paper"]
        self.assertEqual(raw, paper["loss_function"])
        self.assertEqual("paper-lab-research-text/v1", paper["presentation_version"])
        self.assertIn("<math", paper["presentation_html"]["loss_function"])
        self.assertNotIn(r"$L_{MSE}", paper["presentation_html"]["loss_function"])

        listing = self.client.get("/api/v1/paper-lab/papers?limit=10&view=full")
        listed = listing.get_json()["data"]["papers"][0]
        self.assertEqual(raw, listed["loss_function"])
        self.assertNotIn("presentation_html", listed)

    def test_full_detail_renders_math_but_editor_retains_raw_value(self) -> None:
        paper_id = self._register_paper()
        raw = r"样本外误差为 $L_{MSE}=\frac{1}{N}\sum_i e_i^2$。"
        updated = self.client.patch(
            f"/api/v1/paper-lab/papers/{paper_id}",
            json={
                "field": "main_findings",
                "value": raw,
                "expected_version": 0,
                "actor_display_name": "测试研究员",
                "reason": "完整详情公式展示回归",
            },
            headers=self._write_headers("paper-detail-math-1"),
        )
        self.assertEqual(200, updated.status_code)

        body = self.client.get(f"/paper-lab/papers/{paper_id}").get_data(
            as_text=True
        )
        self.assertIn('class="preserve-lines paper-research-text"', body)
        self.assertIn('data-math-rendered="mathml"', body)
        self.assertIn("<math", body)
        self.assertIn(raw, body)

    def test_blueprint_write_without_session_csrf_is_rejected_before_write(self) -> None:
        response = self.client.post(
            "/api/v1/paper-lab/blueprints",
            json={"name": "x", "objective": "x", "components": []},
            headers={
                "Origin": "http://localhost",
                "Idempotency-Key": "paper-lab-test-1",
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json()["error"]["code"], "csrf_rejected")
        with paper_lab_connection(self.settings) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM architecture_blueprint").fetchone()[0],
                0,
            )

    def test_blueprint_write_is_idempotent_and_key_reuse_conflicts(self) -> None:
        self._seed_component()
        headers = self._write_headers("paper-lab-blueprint-1")
        payload = {
            "name": "测试蓝图",
            "objective": "验证写入契约",
            "components": [{
                "component_id": "component-test-1",
                "layer": "model",
                "layer_order": 1,
                "ordinal": 0,
            }],
        }

        first = self.client.post(
            "/api/v1/paper-lab/blueprints", json=payload, headers=headers,
        )
        self.assertEqual(first.status_code, 201)
        first_envelope = first.get_json()
        self.assertEqual(
            set(first_envelope), {"api_version", "data", "meta"},
        )
        self.assertTrue(first_envelope["meta"]["request_id"])
        first_result = first_envelope["data"]["blueprint"]
        self.assertFalse(first_result["replayed"])

        replay = self.client.post(
            "/api/v1/paper-lab/blueprints", json=payload, headers=headers,
        )
        self.assertEqual(replay.status_code, 201)
        replay_result = replay.get_json()["data"]["blueprint"]
        self.assertTrue(replay_result["replayed"])
        self.assertEqual(
            replay_result["blueprint_version_id"], first_result["blueprint_version_id"],
        )

        conflict = self.client.post(
            "/api/v1/paper-lab/blueprints",
            json={**payload, "objective": "不同命令"},
            headers=headers,
        )
        self.assertEqual(conflict.status_code, 409)
        conflict_envelope = conflict.get_json()
        self.assertEqual(
            set(conflict_envelope), {"api_version", "error", "meta"},
        )
        self.assertTrue(conflict_envelope["meta"]["request_id"])
        self.assertEqual(conflict_envelope["error"]["code"], "idempotency_conflict")
        with paper_lab_connection(self.settings) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM blueprint_version").fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT count(*) FROM paper_lab_command_receipt"
                ).fetchone()[0],
                1,
            )

    def test_designer_can_validate_save_version_list_and_restore(self) -> None:
        self._seed_component()
        components = [{
            "component_id": "component-test-1",
            "layer": "model",
            "layer_order": 0,
            "ordinal": 0,
            "forced": False,
        }]
        validation = self.client.post(
            "/api/v1/paper-lab/blueprints/validate",
            json={"components": components},
            headers=self._write_headers("designer-validate-1"),
        )
        self.assertEqual(validation.status_code, 200)
        self.assertTrue(validation.get_json()["data"]["validation"]["valid"])

        first = self.client.post(
            "/api/v1/paper-lab/blueprints",
            json={"name": "可恢复蓝图", "objective": "浏览器设计器验收", "components": components},
            headers=self._write_headers("designer-save-1"),
        )
        self.assertEqual(first.status_code, 201)
        first_result = first.get_json()["data"]["blueprint"]
        blueprint_id = first_result["blueprint_id"]
        self.assertEqual(first_result["version"], 1)

        second = self.client.post(
            "/api/v1/paper-lab/blueprints",
            json={
                "blueprint_id": blueprint_id,
                "name": "可恢复蓝图",
                "objective": "第二个不可变版本",
                "components": [{**components[0], "forced": True}],
            },
            headers=self._write_headers("designer-save-2"),
        )
        self.assertEqual(second.status_code, 201)
        self.assertEqual(second.get_json()["data"]["blueprint"]["version"], 2)

        listing = self.client.get("/api/v1/paper-lab/blueprints")
        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.get_json()["data"]["count"], 1)
        self.assertEqual(listing.get_json()["data"]["blueprints"][0]["version"], 2)

        latest = self.client.get(f"/api/v1/paper-lab/blueprints/{blueprint_id}")
        self.assertEqual(latest.status_code, 200)
        restored = latest.get_json()["data"]["blueprint"]
        self.assertEqual(restored["objective"], "第二个不可变版本")
        self.assertEqual(restored["version"], 2)
        self.assertEqual(restored["components"][0]["component_id"], "component-test-1")
        self.assertEqual(restored["components"][0]["forced"], 1)

        old = self.client.get(
            f"/api/v1/paper-lab/blueprints/{blueprint_id}?version=1"
        )
        self.assertEqual(old.status_code, 200)
        self.assertEqual(old.get_json()["data"]["blueprint"]["version"], 1)

    def test_designer_rejects_unknown_component_without_persisting(self) -> None:
        response = self.client.post(
            "/api/v1/paper-lab/blueprints/validate",
            json={
                "components": [{
                    "component_id": "component-missing",
                    "layer": "model",
                    "ordinal": 0,
                    "layer_order": 0,
                }]
            },
            headers=self._write_headers("designer-validate-missing"),
        )
        self.assertEqual(response.status_code, 200)
        result = response.get_json()["data"]["validation"]
        self.assertFalse(result["valid"])
        self.assertEqual(result["errors"][0]["code"], "component_not_found")
        with paper_lab_connection(self.settings) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM architecture_blueprint").fetchone()[0],
                0,
            )

    def test_viewer_field_edit_is_versioned_idempotent_and_source_preserving(self) -> None:
        paper_id = self._register_paper()
        detail = self.client.get(f"/paper-lab/papers/{paper_id}")
        self.assertEqual(detail.status_code, 200)
        self.assertIn("版本化覆盖层", detail.get_data(as_text=True))
        self.assertIn("/paper-lab/static/paper_lab.js", detail.get_data(as_text=True))

        command = {
            "field": "main_findings",
            "value": "研究员复核后的结论",
            "expected_version": 0,
            "actor_display_name": "测试研究员",
            "reason": "兼容 Viewer 编辑但不改来源",
        }
        headers = self._write_headers("paper-field-edit-1")
        first = self.client.patch(
            f"/api/v1/paper-lab/papers/{paper_id}", json=command, headers=headers,
        )
        self.assertEqual(first.status_code, 200)
        result = first.get_json()["data"]["paper_field"]
        self.assertEqual(result["version"], 1)
        self.assertFalse(result["replayed"])

        replay = self.client.patch(
            f"/api/v1/paper-lab/papers/{paper_id}", json=command, headers=headers,
        )
        self.assertEqual(replay.status_code, 200)
        self.assertTrue(replay.get_json()["data"]["paper_field"]["replayed"])

        stale = self.client.patch(
            f"/api/v1/paper-lab/papers/{paper_id}",
            json={**command, "value": "过期覆盖"},
            headers=self._write_headers("paper-field-edit-stale"),
        )
        self.assertEqual(stale.status_code, 409)
        self.assertEqual(stale.get_json()["error"]["code"], "paper_field_version_conflict")

        second = self.client.patch(
            f"/api/v1/paper-lab/papers/{paper_id}",
            json={**command, "value": "第二版结论", "expected_version": 1},
            headers=self._write_headers("paper-field-edit-2"),
        )
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.get_json()["data"]["paper_field"]["version"], 2)

        projected = self.client.get(f"/api/v1/paper-lab/papers/{paper_id}")
        self.assertEqual(projected.status_code, 200)
        paper = projected.get_json()["data"]["paper"]
        self.assertEqual(paper["main_findings"], "第二版结论")
        self.assertEqual(paper["field_overlay_versions"]["main_findings"], 2)
        with paper_lab_connection(self.settings) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM paper_field_overlay").fetchone()[0],
                2,
            )
            source_title = connection.execute(
                "SELECT canonical_title FROM lab_paper WHERE paper_id=?", (paper_id,)
            ).fetchone()[0]
            self.assertEqual(source_title, "editable")
            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                connection.execute(
                    "UPDATE paper_field_overlay SET value_text='tampered' WHERE paper_id=?",
                    (paper_id,),
                )

    def test_viewer_field_edit_rejects_unknown_field_and_missing_version(self) -> None:
        paper_id = self._register_paper()
        missing_version = self.client.patch(
            f"/api/v1/paper-lab/papers/{paper_id}",
            json={"field": "summary", "value": "x", "actor_display_name": "测试"},
            headers=self._write_headers("paper-field-invalid-1"),
        )
        self.assertEqual(missing_version.status_code, 422)
        unknown = self.client.patch(
            f"/api/v1/paper-lab/papers/{paper_id}",
            json={
                "field": "content_sha256",
                "value": "x",
                "expected_version": 0,
                "actor_display_name": "测试",
            },
            headers=self._write_headers("paper-field-invalid-2"),
        )
        self.assertEqual(unknown.status_code, 422)
        with paper_lab_connection(self.settings) as connection:
            self.assertEqual(
                connection.execute("SELECT count(*) FROM paper_field_overlay").fetchone()[0],
                0,
            )

    def test_path_traversal_asset_is_not_routable(self) -> None:
        self.assertEqual(
            self.client.get("/api/v1/paper-lab/versions/not-a-version/content").status_code,
            404,
        )

    def test_pdf_and_note_routes_verify_frozen_bytes_and_single_link_on_every_read(self) -> None:
        pdf_bytes = b"%PDF-1.4\nfrozen-route\n%%EOF"
        drop = self.settings.paper_lab_drop_root
        drop.mkdir(parents=True, exist_ok=True)
        (drop / "1_frozen_route.pdf").write_bytes(pdf_bytes)
        service = self.app.extensions["paper_lab_service"]
        registration = service.register_all()[0]
        pdf_url = f"/api/v1/paper-lab/versions/{registration.paper_version_id}/content"
        healthy = self.client.get(pdf_url)
        self.assertEqual(healthy.status_code, 200)
        self.assertEqual(healthy.data, pdf_bytes)
        with paper_lab_connection(self.settings) as connection:
            version = connection.execute(
                "SELECT asset_relative_path FROM lab_paper_version WHERE paper_version_id=?",
                (registration.paper_version_id,),
            ).fetchone()
        asset = self.settings.paper_lab_asset_root / version["asset_relative_path"]

        asset.write_bytes(b"corrupted-pdf")
        corrupted = self.client.get(pdf_url)
        self.assertEqual(corrupted.status_code, 409)
        self.assertEqual(
            corrupted.get_json()["error"]["code"], "paper_asset_integrity_error"
        )
        self.assertNotIn(b"corrupted-pdf", corrupted.data)

        asset.write_bytes(pdf_bytes)
        hardlink_source = asset.with_name(asset.name + ".hardlink-source")
        asset.replace(hardlink_source)
        os.link(hardlink_source, asset)
        try:
            linked = self.client.get(pdf_url)
            self.assertEqual(linked.status_code, 409)
            self.assertEqual(linked.get_json()["error"]["details"]["reason"], "hard_linked")
        finally:
            asset.unlink()
            hardlink_source.replace(asset)

        note_bytes = b"# frozen note\n"
        note_relative = "research/notes/1_frozen.md"
        note_path = self.settings.paper_lab_asset_root.parent / "legacy_snapshot" / note_relative
        note_path.parent.mkdir(parents=True, exist_ok=True)
        note_path.write_bytes(note_bytes)
        note_id = "labnote_frozen_route_test"
        with paper_lab_connection(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO lab_note(
                    note_id,paper_id,content_sha256,bytes,source_location_urn,
                    snapshot_relative_path,note_kind,template_status,is_canonical,created_at
                ) VALUES(?,?,?,?,?,?,'legacy','legacy',1,'t')
                """,
                (
                    note_id,
                    registration.paper_id,
                    hashlib.sha256(note_bytes).hexdigest(),
                    len(note_bytes),
                    "qrh:test-note",
                    note_relative,
                ),
            )
        note_url = f"/api/v1/paper-lab/notes/{note_id}/content"
        note_healthy = self.client.get(note_url)
        self.assertEqual(note_healthy.status_code, 200)
        self.assertEqual(note_healthy.data, note_bytes)
        note_path.write_bytes(b"corrupted-note")
        note_corrupted = self.client.get(note_url)
        self.assertEqual(note_corrupted.status_code, 409)
        self.assertEqual(
            note_corrupted.get_json()["error"]["code"], "note_asset_integrity_error"
        )
        self.assertNotIn(b"corrupted-note", note_corrupted.data)

        note_path.write_bytes(note_bytes)
        outside_note_id = "labnote_outside_route_test"
        outside_bytes = b"outside path identity"
        with paper_lab_connection(self.settings) as connection:
            connection.execute(
                """
                INSERT INTO lab_note(
                    note_id,paper_id,content_sha256,bytes,source_location_urn,
                    snapshot_relative_path,note_kind,template_status,is_canonical,created_at
                ) VALUES(?,?,?,?,?,'C:/outside.md','legacy','legacy',0,'t')
                """,
                (
                    outside_note_id,
                    registration.paper_id,
                    hashlib.sha256(outside_bytes).hexdigest(),
                    len(outside_bytes),
                    "qrh:test-outside-note",
                ),
            )
        outside = self.client.get(
            f"/api/v1/paper-lab/notes/{outside_note_id}/content"
        )
        self.assertEqual(outside.status_code, 409)
        self.assertEqual(
            outside.get_json()["error"]["details"]["reason"], "unsafe_relative_path"
        )
