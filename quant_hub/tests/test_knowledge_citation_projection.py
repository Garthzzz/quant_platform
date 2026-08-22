from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from quant_hub.evidence.ids import citation_id_for_marker
from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge.contracts import canonical_json
from quant_hub.knowledge.citations import (
    CitationProjectionError,
    build_citation_projection,
)
from quant_hub.knowledge.retrieval import ArtifactKnowledgeIndex, KnowledgeIndex
from quant_hub.knowledge.semantic import (
    SemanticJobStore,
    build_enriched_snapshot,
    extract_source_explicit,
)
from quant_hub.knowledge_mcp.mirror import (
    FileAuthorityProbe,
    MirrorError,
    MirrorStore,
    build_search_artifact,
    validate_search_artifact,
)
from quant_hub.knowledge_mcp.service import KnowledgeMCPService
from quant_hub.ops.release_builder import ReleaseBuildError, prepare_knowledge_search
from quant_hub.ops.release_identity import manifest_sha256
from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_up


ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = ROOT / "migrations" / "research_papers"
NOW = "2026-08-22T00:00:00Z"


def _manifest(snapshot_id: str) -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": "citation-projection-fixture",
        "built_at": NOW,
        "application": {
            "source_kind": "git",
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": "b" * 64,
            "build_tool_version": "citation-projection-tests/v1",
        },
        "content": {
            "snapshot_id": snapshot_id,
            "source_inventory_sha256": None,
            "ir_sha256": None,
            "knowledge_sha256": None,
            "search_sha256": None,
            "knowledge_enrichment": {"status": "ready"},
        },
        "resources": {},
        "state": {"compatibility": {"comments": {"read": [2], "write": [2]}}},
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
    }


class KnowledgeCitationProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.source = (
            "# 投影测试\n\n"
            "方法：使用 Alpha 构造信号 [A]。\n\n"
            "限制：Beta 条件失效 [B]。\n"
        ).encode("utf-8")
        (self.sources / "research.md").write_bytes(self.source)
        report = ReferenceCompiler().compile(self.sources)
        assert report.candidate_snapshot is not None
        self.base = report.candidate_snapshot
        self.version_id = next(iter(self.base.active_membership.values()))
        self.source_sha256 = hashlib.sha256(self.source).hexdigest()
        self.source_objects = {self.source_sha256: self.source}
        self.database = self.root / "research_papers.sqlite3"
        connection = connect_database(self.database)
        migrate_up(connection, MIGRATIONS)
        connection.close()
        self.overlay = self.root / "citation_projection_overrides.json"
        self.overlay.write_text(
            json.dumps(
                {
                    "schema_version": "qrh-reviewed-citation-projection/v1",
                    "review_scope": "public-test-fixture",
                    "reviewed_at": NOW,
                    "documents": [],
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
            newline="",
        )

    def _projection(self, base=None, source_objects=None):
        return build_citation_projection(
            base or self.base,
            self.database,
            source_objects or self.source_objects,
            overlay_manifest_path=self.overlay,
            evidence_migration_root=MIGRATIONS,
        )

    def _valid_overlay_manifest(self) -> dict[str, object]:
        marker = "Alpha"
        line_number = self.source[: self.source.index(marker.encode("utf-8"))].count(
            b"\n"
        ) + 1
        return {
            "schema_version": "qrh-reviewed-citation-projection/v1",
            "review_scope": "public-test-fixture",
            "reviewed_at": NOW,
            "documents": [
                {
                    "source_path": "research.md",
                    "document_sha256": self.source_sha256,
                    "entries": [
                        {
                            "key": "paper-a",
                            "line_number": line_number,
                            "marker": marker,
                            "source_candidate_id": "candidate-a",
                            "relation_summary_zh": "公开测试关系。",
                            "paper": {
                                "paper_id": "paper_" + "1" * 32,
                                "title": "Paper A",
                                "external_links": [
                                    {
                                        "kind": "repository",
                                        "url": "https://example.invalid/paper-a",
                                    }
                                ],
                            },
                        }
                    ],
                }
            ],
        }

    def _write_overlay(self, name: str, manifest: dict[str, object]) -> Path:
        path = self.root / name
        path.write_text(
            json.dumps(
                manifest,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            encoding="utf-8",
            newline="",
        )
        return path

    def _insert_occurrence(
        self,
        marker: str,
        *,
        binding_status: str,
        document_sha256: str | None = None,
        payload: bytes | None = None,
        key: str,
    ) -> str:
        source = payload or self.source
        source_sha256 = document_sha256 or hashlib.sha256(source).hexdigest()
        marker_bytes = marker.encode("utf-8")
        start = source.index(marker_bytes)
        end = start + len(marker_bytes)
        citation_id = citation_id_for_marker(source_sha256, start, end, marker_bytes)
        line_number = source[:start].count(b"\n") + 1
        context = source.decode("utf-8").splitlines()[line_number - 1]
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            """
            INSERT INTO citation_occurrence(
                citation_id,document_sha256,locator_kind,locator_json,line_start,
                line_end,byte_start,byte_end,raw_marker_text,raw_marker_sha256,
                context_text,context_sha256,occurrence_kind,locator_status,
                status_reason,created_at
            ) VALUES(?,?,'utf8_bytes','{}',?,?,?,?,?,?,?,?,?,'valid','verified',?)
            """,
            (
                citation_id,
                source_sha256,
                line_number,
                line_number,
                start,
                end,
                marker,
                hashlib.sha256(marker_bytes).hexdigest(),
                context,
                hashlib.sha256(context.encode("utf-8")).hexdigest(),
                "formal_reference",
                NOW,
            ),
        )
        ledger_id = f"ledger-{key}"
        connection.execute(
            """
            INSERT INTO citation_ledger_entry(
                ledger_entry_id,citation_id,clue_id,research_urn,
                archive_release_urn,document_version_urn,source_object_urn,
                source_path,canonical_path,locator_claim,occurrence_type,
                candidate_link_method,evidence_strength,identifier_claim,
                entry_status,entry_reason,raw_payload_json,imported_at
            ) VALUES(?,?,NULL,'qrh:test:research','qrh:test:release',?,?,'research.md',
                     'research.md','exact','formal_reference','fixture','strong','',
                     ?,'fixture','{}',?)
            """,
            (
                ledger_id,
                citation_id,
                f"qrh:test:version:{source_sha256}",
                f"obj_sha256_{source_sha256}",
                binding_status,
                NOW,
            ),
        )
        if binding_status == "resolved":
            paper_id = f"paper-{key}"
            event_id = f"paper-event-{key}"
            connection.execute(
                """
                INSERT INTO paper_identity_event(
                    identity_event_id,event_kind,from_paper_id,to_paper_id,scheme,
                    normalized_value,provenance_urn,payload_json,occurred_at
                ) VALUES(?,'paper_created',NULL,?,NULL,NULL,'qrh:test','{}',?)
                """,
                (event_id, paper_id, NOW),
            )
            connection.execute(
                "INSERT INTO paper(paper_id,canonical_urn,creation_event_id,created_at) VALUES(?,?,?,?)",
                (paper_id, f"qrh:test:paper:{key}", event_id, NOW),
            )
        else:
            paper_id = None
        binding_id = f"binding-{key}"
        binding_event_id = f"binding-event-{key}"
        connection.execute(
            """
            INSERT INTO citation_binding(
                binding_id,ledger_entry_id,paper_id,binding_status,rationale,
                provenance_urn,created_at
            ) VALUES(?,?,?,?,?,'qrh:test',?)
            """,
            (binding_id, ledger_id, paper_id, binding_status, "fixture", NOW),
        )
        connection.execute(
            """
            INSERT INTO citation_binding_event(
                binding_event_id,ledger_entry_id,binding_id,event_kind,
                supersedes_event_id,provenance_urn,occurred_at
            ) VALUES(?,?,?,'binding_created',NULL,'qrh:test',?)
            """,
            (binding_event_id, ledger_id, binding_id, NOW),
        )
        connection.execute(
            """
            INSERT INTO citation_binding_projection(
                ledger_entry_id,binding_id,source_event_id,revision,updated_at
            ) VALUES(?,?,?,1,?)
            """,
            (ledger_id, binding_id, binding_event_id, NOW),
        )
        connection.commit()
        connection.close()
        return citation_id

    def test_resolved_active_projection_is_read_only_and_direct_artifact_equal(self) -> None:
        citation_a = self._insert_occurrence("[A]", binding_status="resolved", key="a")
        self._insert_occurrence("[B]", binding_status="unresolved", key="b")
        inactive = b"# old\n\nOld [C].\n"
        self._insert_occurrence(
            "[C]",
            binding_status="resolved",
            document_sha256=hashlib.sha256(inactive).hexdigest(),
            payload=inactive,
            key="c",
        )
        database_hash = hashlib.sha256(self.database.read_bytes()).hexdigest()
        source_hash = hashlib.sha256(self.source).hexdigest()
        projection = self._projection()
        self.assertEqual([citation_a], [row.citation_id for row in projection.occurrences])
        self.assertEqual("valid", projection.occurrences[0].resolution_state)
        self.assertEqual(
            "evidence_binding", projection.occurrences[0].authority_kind
        )
        self.assertEqual(database_hash, hashlib.sha256(self.database.read_bytes()).hexdigest())
        self.assertEqual(source_hash, hashlib.sha256(self.source).hexdigest())
        self.assertFalse(self.database.with_name(self.database.name + "-wal").exists())
        self.assertFalse(self.database.with_name(self.database.name + "-shm").exists())

        store = SemanticJobStore(self.root / "semantic.sqlite3")
        extract_source_explicit(self.base, store)
        enriched = build_enriched_snapshot(self.base, store)
        direct = KnowledgeIndex(
            self.base, enriched, citation_projection=projection
        )
        artifact_value = json.loads(
            build_search_artifact(
                self.base,
                enriched=enriched,
                citation_projection=projection,
            )
        )
        validate_search_artifact(
            artifact_value, expected_snapshot_id=enriched.snapshot_id
        )
        artifact = ArtifactKnowledgeIndex(artifact_value)
        try:
            direct_rows = {
                row.record_id: row.citation_ids for row in direct.records
            }
            artifact_rows = {
                row.record_id: row.citation_ids for row in artifact.records
            }
            self.assertEqual(direct_rows, artifact_rows)
            self.assertIn(citation_a, {value for row in direct_rows.values() for value in row})
        finally:
            direct.close()
            artifact.close()

    def test_multi_binding_keeps_citations_on_their_exact_locator(self) -> None:
        citation_a = self._insert_occurrence("[A]", binding_status="resolved", key="a")
        citation_b = self._insert_occurrence("[B]", binding_status="resolved", key="b")
        projection = self._projection()
        store = SemanticJobStore(self.root / "semantic.sqlite3")
        extract_source_explicit(self.base, store)
        enriched = build_enriched_snapshot(self.base, store)
        items = sorted(
            enriched.knowledge_items.values(),
            key=lambda item: item.evidence[0].byte_start,
        )
        self.assertGreaterEqual(len(items), 2)
        combined = replace(
            items[0],
            knowledge_item_id="knowledge-combined-citation-fixture",
            cluster_id="cluster-combined-citation-fixture",
            evidence=(items[0].evidence[0], items[-1].evidence[0]),
        )
        combined_enriched = replace(
            enriched,
            knowledge_items={combined.knowledge_item_id: combined},
            accepted_knowledge_hash="c" * 64,
            coverage_hash="d" * 64,
        )
        artifact = json.loads(
            build_search_artifact(
                self.base,
                enriched=combined_enriched,
                citation_projection=projection,
            )
        )
        validate_search_artifact(
            artifact, expected_snapshot_id=combined_enriched.snapshot_id
        )
        members = artifact["knowledge"][0]["source_citations"]
        self.assertEqual([[citation_a], [citation_b]], [row["citation_ids"] for row in members])

        forged_binding = replace(
            items[-1].evidence[0],
            byte_start=items[-1].evidence[0].byte_start + 1,
        )
        forged = replace(
            combined,
            evidence=(items[0].evidence[0], forged_binding),
        )
        forged_enriched = replace(
            combined_enriched,
            knowledge_items={forged.knowledge_item_id: forged},
        )
        with self.assertRaisesRegex(
            CitationProjectionError, "differs from active source bytes"
        ):
            KnowledgeIndex(
                self.base,
                forged_enriched,
                citation_projection=projection,
            )
        with self.assertRaisesRegex(MirrorError, "quote locator is invalid"):
            build_search_artifact(
                self.base,
                enriched=forged_enriched,
                citation_projection=projection,
            )

    def test_native_src_survives_when_sidecar_is_configured(self) -> None:
        native_id = citation_id_for_marker("1" * 64, 0, 1, b"x")
        sources = self.root / "native-sources"
        sources.mkdir()
        source = (
            f"# Native\n\n方法：使用 Gamma。 ^src:{{{native_id}}}\n"
        ).encode("utf-8")
        (sources / "native.md").write_bytes(source)
        report = ReferenceCompiler().compile(sources)
        assert report.candidate_snapshot is not None
        base = report.candidate_snapshot
        digest = hashlib.sha256(source).hexdigest()
        projection = self._projection(base, {digest: source})
        store = SemanticJobStore(self.root / "native-semantic.sqlite3")
        extract_source_explicit(base, store)
        enriched = build_enriched_snapshot(base, store)
        item = next(iter(enriched.knowledge_items.values()))
        binding = item.evidence[0]
        marker_start = source.index(f"^src:{{{native_id}}}".encode("utf-8"))
        binding_end = marker_start - 1
        adjacent_quote_bytes = source[binding.byte_start:binding_end]
        adjacent_binding = replace(
            binding,
            quote=adjacent_quote_bytes.decode("utf-8"),
            quote_sha256=hashlib.sha256(adjacent_quote_bytes).hexdigest(),
            byte_end=binding_end,
        )
        adjacent_item = replace(item, evidence=(adjacent_binding,))
        enriched = replace(
            enriched,
            knowledge_items={adjacent_item.knowledge_item_id: adjacent_item},
            accepted_knowledge_hash="e" * 64,
            coverage_hash="f" * 64,
        )
        artifact = json.loads(
            build_search_artifact(
                base,
                enriched=enriched,
                citation_projection=projection,
            )
        )
        validate_search_artifact(artifact, expected_snapshot_id=enriched.snapshot_id)
        self.assertEqual(
            [native_id],
            sorted(
                {
                    citation_id
                    for row in artifact["chunks"]
                    for citation_id in row["citation_ids"]
                }
            ),
        )
        self.assertEqual(1, len(artifact["native_citation_references"]))

        adjacent_proofs = [
            proof
            for row in artifact["knowledge"]
            for member in row["source_citations"]
            for proof in member["citation_attributions"]
            if proof["relation"] == "adjacent"
        ]
        self.assertTrue(adjacent_proofs)

        null_projection = json.loads(json.dumps(artifact))
        null_projection["citation_projection"] = None
        with self.assertRaisesRegex(MirrorError, "projection identity"):
            validate_search_artifact(
                null_projection, expected_snapshot_id=enriched.snapshot_id
            )

        forged_native = json.loads(json.dumps(artifact))
        raw_marker = forged_native["native_citation_references"][0]["raw_marker_text"]
        forged_marker = raw_marker[:-1] + "]"
        forged_native["native_citation_references"][0][
            "raw_marker_text"
        ] = forged_marker
        forged_native["native_citation_references"][0][
            "raw_marker_sha256"
        ] = hashlib.sha256(forged_marker.encode("utf-8")).hexdigest()
        with self.assertRaisesRegex(MirrorError, "native citation reference identity"):
            validate_search_artifact(
                forged_native, expected_snapshot_id=enriched.snapshot_id
            )

        forged_gap = json.loads(json.dumps(artifact))
        proof = next(
            proof
            for row in forged_gap["knowledge"]
            for member in row["source_citations"]
            for proof in member["citation_attributions"]
            if proof["relation"] == "adjacent"
        )
        gap_length = len(proof["gap_text"].encode("utf-8"))
        self.assertGreater(gap_length, 0)
        proof["gap_text"] = "x" * gap_length
        proof["gap_sha256"] = hashlib.sha256(
            proof["gap_text"].encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(MirrorError, "attribution gap is invalid"):
            validate_search_artifact(
                forged_gap, expected_snapshot_id=enriched.snapshot_id
            )

    def test_long_block_native_citation_belongs_only_to_covering_child(self) -> None:
        native_id = citation_id_for_marker("3" * 64, 0, 1, b"x")
        marker = f"^src:{{{native_id}}}"
        sources = self.root / "long-native-sources"
        sources.mkdir()
        source = (
            "# Long native\n\n"
            + "alpha " * 520
            + marker
            + " omega" * 520
            + "\n"
        ).encode("utf-8")
        (sources / "long-native.md").write_bytes(source)
        report = ReferenceCompiler().compile(sources)
        assert report.candidate_snapshot is not None
        base = report.candidate_snapshot
        digest = hashlib.sha256(source).hexdigest()
        projection = self._projection(base, {digest: source})
        marker_start = source.index(marker.encode("utf-8"))
        marker_end = marker_start + len(marker.encode("utf-8"))
        child_chunks = [
            chunk for chunk in base.chunks.values() if chunk.role == "child"
        ]
        self.assertGreater(len(child_chunks), 1)
        covering_children = [
            chunk
            for chunk in child_chunks
            if chunk.byte_start <= marker_start
            and marker_end <= chunk.byte_end
        ]
        self.assertEqual(1, len(covering_children))

        artifact = json.loads(
            build_search_artifact(base, citation_projection=projection)
        )
        validate_search_artifact(artifact, expected_snapshot_id=base.snapshot_id)
        artifact_children = [
            row for row in artifact["chunks"] if row["role"] == "child"
        ]
        self.assertEqual(
            [covering_children[0].chunk_id],
            [
                row["chunk_id"]
                for row in artifact_children
                if native_id in row["citation_ids"]
            ],
        )
        self.assertTrue(
            all(
                (native_id in row["citation_ids"])
                == (row["byte_start"] <= marker_start <= marker_end <= row["byte_end"])
                for row in artifact_children
            )
        )
        with KnowledgeIndex(base, citation_projection=projection) as direct_index:
            direct = {
                row.record_id: row.citation_ids
                for row in direct_index.records
                if row.source_kind == "chunk"
            }
        with ArtifactKnowledgeIndex(artifact) as artifact_index:
            rebuilt = {
                row.record_id: row.citation_ids
                for row in artifact_index.records
                if row.source_kind == "chunk"
            }
        self.assertEqual(direct, rebuilt)

    def test_projection_container_material_is_a_closed_structural_member(self) -> None:
        sources = self.root / "projection-container-sources"
        sources.mkdir()
        source = (
            "# Projection container\n\n"
            "- First reviewed Alpha occurrence.\n"
            "- Second list item keeps the container non-atomic.\n"
        ).encode("utf-8")
        (sources / "list.md").write_bytes(source)
        report = ReferenceCompiler().compile(sources)
        self.assertIsNotNone(report.candidate_snapshot)
        base = report.candidate_snapshot
        assert base is not None
        source_sha256 = hashlib.sha256(source).hexdigest()
        marker = "Alpha"
        marker_start = source.index(marker.encode("utf-8"))
        overlay = self._write_overlay(
            "projection-container-overrides.json",
            {
                "schema_version": "qrh-reviewed-citation-projection/v1",
                "review_scope": "projection-container-public-fixture",
                "reviewed_at": NOW,
                "documents": [
                    {
                        "source_path": "list.md",
                        "document_sha256": source_sha256,
                        "entries": [
                            {
                                "key": "projection-container-alpha",
                                "line_number": source[:marker_start].count(b"\n") + 1,
                                "marker": marker,
                                "source_candidate_id": "candidate-container-alpha",
                                "relation_summary_zh": "公开容器引用回归。",
                                "paper": {
                                    "paper_id": "paper_" + "7" * 32,
                                    "title": "Container Citation Fixture",
                                    "external_links": [
                                        {
                                            "kind": "repository",
                                            "url": "https://example.invalid/container",
                                        }
                                    ],
                                },
                            }
                        ],
                    }
                ],
            },
        )
        projection = build_citation_projection(
            base,
            self.database,
            {source_sha256: source},
            overlay_manifest_path=overlay,
            evidence_migration_root=MIGRATIONS,
        )
        artifact = json.loads(
            build_search_artifact(base, citation_projection=projection)
        )
        material_keys = {
            (row["document_version_id"], row["span_id"])
            for row in artifact["citation_source_material"]
        }
        chunk_keys = {
            (row["document_version_id"], span_id)
            for row in artifact["chunks"]
            for span_id in row["ordered_span_ids"]
        }
        occurrence_keys = {
            (version["version_id"], span_id)
            for row in artifact["citations"]
            for version in artifact["versions"]
            if version["is_current"] is True
            and version["source_sha256"] == row["source_sha256"]
            for span_id in row["containing_span_ids"]
        }
        self.assertEqual(material_keys, occurrence_keys)
        self.assertTrue(material_keys - chunk_keys)
        validate_search_artifact(artifact, expected_snapshot_id=base.snapshot_id)

    def test_mcp_search_get_returns_only_the_selected_locator_citation(self) -> None:
        citation_a = self._insert_occurrence("[A]", binding_status="resolved", key="a")
        citation_b = self._insert_occurrence("[B]", binding_status="resolved", key="b")
        projection = self._projection()
        store = SemanticJobStore(self.root / "mcp-semantic.sqlite3")
        extract_source_explicit(self.base, store)
        enriched = build_enriched_snapshot(self.base, store)
        artifact_bytes = build_search_artifact(
            self.base,
            enriched=enriched,
            citation_projection=projection,
        )
        artifact_value = json.loads(artifact_bytes)
        release = _manifest(enriched.snapshot_id)
        release["release_id"] = "citation-mcp-release"
        release["resources"] = {"inventory_sha256": "4" * 64}
        release["content"].update(
            {
                "source_inventory_sha256": "1" * 64,
                "ir_sha256": "2" * 64,
                "knowledge_sha256": "3" * 64,
                "search_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
            }
        )
        authority = self.root / "authority"
        releases = authority / "releases"
        control = authority / "control"
        release_root = releases / "citation-mcp-release"
        (release_root / "content").mkdir(parents=True)
        control.mkdir(parents=True)
        (release_root / "content" / "mcp_search.json").write_bytes(artifact_bytes)
        (release_root / "release_manifest.json").write_text(
            json.dumps(release, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
            newline="",
        )
        active = {
            "schema_version": "qrh-active-release/v1",
            "release_id": "citation-mcp-release",
            "release_path": r"D:\quant\quant_platform\releases\citation-mcp-release",
            "manifest_sha256": manifest_sha256(release),
        }
        (control / "active_release.json").write_text(
            json.dumps(active, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
            newline="",
        )
        service = KnowledgeMCPService(
            store=MirrorStore(self.root / "mirror"),
            authority=FileAuthorityProbe(control / "active_release.json", releases),
            artifact_release_root=releases,
        )
        self.addCleanup(service.close)
        search = service.search_quant_knowledge(
            query="Alpha", limit=20, budget_chars=50_000
        )
        self.assertEqual("ok", search.get("status"), search)
        candidates = [
            row
            for row in search["results"]
            if row.get("object_kind") != "evidence_chunk"
            and citation_a in row.get("citation_ids", [])
        ]
        self.assertTrue(candidates)
        search_member = next(
            member
            for member in candidates[0]["source_citations"]
            if citation_a in member["citation_ids"]
        )
        artifact_member = next(
            member
            for row in artifact_value["knowledge"]
            if row["knowledge_item_id"] == candidates[0]["object_id"]
            for member in row["source_citations"]
            if citation_a in member["citation_ids"]
        )
        self.assertEqual(
            artifact_member["citation_attributions"],
            search_member["citation_attributions"],
        )
        self.assertIsNotNone(search_member["source_material_identity"])
        self.assertNotIn("source_text", search_member["source_material_identity"])
        self.assertNotIn("attributes", search_member["source_material_identity"])
        self.assertRegex(
            search_member["source_material_identity"]["attributes_sha256"],
            r"^[0-9a-f]{64}$",
        )
        expanded = service.get_quant_knowledge(
            object_id=candidates[0]["object_id"]
        )
        self.assertEqual("ok", expanded["status"])
        per_locator = expanded["source_citations"]
        self.assertIn(citation_a, {value for row in per_locator for value in row["citation_ids"]})
        self.assertNotIn(citation_b, {value for row in per_locator for value in row["citation_ids"]})
        expanded_member = next(
            member for member in per_locator if citation_a in member["citation_ids"]
        )
        self.assertEqual(
            artifact_member["citation_attributions"],
            expanded_member["citation_attributions"],
        )
        self.assertEqual(
            search_member["source_material_identity"],
            expanded_member["source_material_identity"],
        )
        self.assertNotIn("source_text", expanded_member["source_material_identity"])
        self.assertNotIn("attributes", expanded_member["source_material_identity"])

    def test_forged_punctuation_proof_cannot_replace_real_author_gap(self) -> None:
        native_id = citation_id_for_marker("2" * 64, 0, 1, b"x")
        sources = self.root / "author-gap-sources"
        sources.mkdir()
        marker = f"^src:{{{native_id}}}"
        source = f"# Native\n\n方法：使用 Gamma author {marker}\n".encode("utf-8")
        (sources / "native.md").write_bytes(source)
        report = ReferenceCompiler().compile(sources)
        assert report.candidate_snapshot is not None
        base = report.candidate_snapshot
        source_sha256 = hashlib.sha256(source).hexdigest()
        projection = self._projection(base, {source_sha256: source})
        store = SemanticJobStore(self.root / "author-gap-semantic.sqlite3")
        extract_source_explicit(base, store)
        enriched = build_enriched_snapshot(base, store)
        item = next(iter(enriched.knowledge_items.values()))
        binding = item.evidence[0]
        binding_end = source.index(b"Gamma") + len(b"Gamma")
        quote_bytes = source[binding.byte_start:binding_end]
        exact_binding = replace(
            binding,
            quote=quote_bytes.decode("utf-8"),
            quote_sha256=hashlib.sha256(quote_bytes).hexdigest(),
            byte_end=binding_end,
        )
        item = replace(item, evidence=(exact_binding,))
        enriched = replace(
            enriched,
            knowledge_items={item.knowledge_item_id: item},
            accepted_knowledge_hash="7" * 64,
            coverage_hash="8" * 64,
        )
        artifact = json.loads(
            build_search_artifact(
                base,
                enriched=enriched,
                citation_projection=projection,
            )
        )
        validate_search_artifact(artifact, expected_snapshot_id=enriched.snapshot_id)
        knowledge = artifact["knowledge"][0]
        member = knowledge["source_citations"][0]
        self.assertEqual([], member["citation_ids"])
        self.assertEqual([], member["citation_attributions"])
        marker_start = source.index(marker.encode("utf-8"))
        real_gap = source[binding_end:marker_start]
        self.assertLessEqual(len(real_gap), 24)
        self.assertTrue(any(value in b"abcdefghijklmnopqrstuvwxyz" for value in real_gap))

        forged_gap = b"." * len(real_gap)
        material = next(
            row
            for row in artifact["citation_source_material"]
            if row["document_version_id"] == item.document_version_id
            and row["byte_start"] <= binding_end < marker_start <= row["byte_end"]
        )
        material_bytes = material["source_text"].encode("utf-8")
        relative_gap_start = binding_end - material["byte_start"]
        relative_gap_end = marker_start - material["byte_start"]
        forged_material_bytes = (
            material_bytes[:relative_gap_start]
            + forged_gap
            + material_bytes[relative_gap_end:]
        )
        material["source_text"] = forged_material_bytes.decode("utf-8")
        material["source_text_sha256"] = hashlib.sha256(
            forged_material_bytes
        ).hexdigest()
        member["citation_ids"] = [native_id]
        member["citation_attributions"] = [
            {
                "citation_id": native_id,
                "relation": "adjacent",
                "anchor_byte_end": binding_end,
                "gap_text": forged_gap.decode("ascii"),
                "gap_sha256": hashlib.sha256(forged_gap).hexdigest(),
            }
        ]
        knowledge["citation_ids"] = [native_id]
        retrieval_record = next(
            row
            for row in artifact["retrieval"]["records"]
            if row["record_id"] == knowledge["knowledge_item_id"]
        )
        retrieval_record["citation_ids"] = [native_id]
        membership_material = {
            key: artifact[key]
            for key in (
                "documents",
                "versions",
                "chunks",
                "knowledge",
                "citation_projection",
                "citations",
                "native_citation_references",
                "citation_source_material",
            )
        }
        artifact["retrieval"]["canonical_membership_sha256"] = hashlib.sha256(
            canonical_json(membership_material).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(
            MirrorError, "source material identity"
        ):
            validate_search_artifact(
                artifact, expected_snapshot_id=enriched.snapshot_id
            )

    def test_bad_marker_or_source_fails_closed(self) -> None:
        self._insert_occurrence("[A]", binding_status="resolved", key="a")
        tampered_sources = {self.source_sha256: self.source + b"tampered"}
        with self.assertRaisesRegex(CitationProjectionError, "active source identity"):
            build_citation_projection(
                self.base,
                self.database,
                tampered_sources,
                overlay_manifest_path=self.overlay,
                evidence_migration_root=MIGRATIONS,
            )
        connection = sqlite3.connect(self.database)
        try:
            trigger_sql = str(
                connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' "
                    "AND name='citation_no_update'"
                ).fetchone()[0]
            )
            connection.execute("DROP TRIGGER citation_no_update")
            connection.execute(
                "UPDATE citation_occurrence SET raw_marker_sha256=?",
                ("0" * 64,),
            )
            connection.execute(trigger_sql)
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(CitationProjectionError, "marker identity"):
            self._projection()

    def test_immutable_evidence_rejects_rollback_journal(self) -> None:
        database_hash = hashlib.sha256(self.database.read_bytes()).hexdigest()
        rollback_journal = self.database.with_name(self.database.name + "-journal")
        rollback_journal.write_bytes(b"public-hot-journal-fixture")
        with self.assertRaisesRegex(
            CitationProjectionError, "SQLite journal artifacts"
        ):
            self._projection()
        self.assertEqual(
            database_hash, hashlib.sha256(self.database.read_bytes()).hexdigest()
        )
        self.assertTrue(rollback_journal.exists())
        self.assertFalse(self.database.with_name(self.database.name + "-wal").exists())
        self.assertFalse(self.database.with_name(self.database.name + "-shm").exists())

    def test_join_authority_schema_types_and_foreign_keys_are_closed(self) -> None:
        mutations = {
            "declared-type": (
                "table",
                "citation_binding",
                "binding_status TEXT NOT NULL",
                "binding_status INTEGER NOT NULL",
                "schema is not closed",
            ),
            "foreign-key": (
                "table",
                "citation_binding",
                "REFERENCES citation_ledger_entry(ledger_entry_id) ON DELETE RESTRICT",
                "REFERENCES citation_occurrence(citation_id) ON DELETE RESTRICT",
                "foreign keys are not closed",
            ),
            "foreign-key-on-update": (
                "table",
                "citation_binding",
                "REFERENCES citation_ledger_entry(ledger_entry_id) ON DELETE RESTRICT",
                "REFERENCES citation_ledger_entry(ledger_entry_id) "
                "ON UPDATE CASCADE ON DELETE RESTRICT",
                "foreign keys are not closed",
            ),
            "check-constraint": (
                "table",
                "citation_binding",
                "'resolved','source_only','unresolved','conflicted','rejected_non_paper'",
                "'resolved','source_only','unresolved','conflicted','rejected_non_paper','forged'",
                "authority schema differs from sealed migrations",
            ),
            "trigger-body": (
                "trigger",
                "citation_binding_projection_validate_insert",
                "citation binding projection requires its creation event",
                "forged citation binding projection event",
                "authority schema differs from sealed migrations",
            ),
        }
        for name, (object_type, object_name, original, replacement, message) in mutations.items():
            with self.subTest(name=name):
                database = self.root / f"forged-{name}.sqlite3"
                connection = connect_database(database)
                migrate_up(connection, MIGRATIONS)
                connection.execute("PRAGMA writable_schema=ON")
                sql = str(
                    connection.execute(
                        "SELECT sql FROM sqlite_master WHERE type=? AND name=?",
                        (object_type, object_name),
                    ).fetchone()[0]
                )
                self.assertIn(original, sql)
                connection.execute(
                    "UPDATE sqlite_master SET sql=? WHERE type=? AND name=?",
                    (sql.replace(original, replacement, 1), object_type, object_name),
                )
                connection.execute("PRAGMA writable_schema=OFF")
                connection.commit()
                connection.close()
                with self.assertRaisesRegex(CitationProjectionError, message):
                    build_citation_projection(
                        self.base,
                        database,
                        self.source_objects,
                        overlay_manifest_path=self.overlay,
                        evidence_migration_root=MIGRATIONS,
                    )

    def test_reviewed_overlay_paths_types_and_document_identity_are_closed(self) -> None:
        cases: list[tuple[str, object]] = [
            ("backslash", ("source_path", r"folder\research.md")),
            ("drive", ("source_path", r"C:\research.md")),
            ("unc", ("source_path", r"\\server\share\research.md")),
            ("traversal", ("source_path", "../research.md")),
            ("posix-absolute", ("source_path", "/research.md")),
            ("line-string", ("line_number", "3")),
            ("candidate-number", ("source_candidate_id", 7)),
            ("relation-object", ("relation_summary_zh", {"text": "forged"})),
            ("title-number", ("title", 7)),
        ]
        for name, mutation in cases:
            with self.subTest(name=name):
                manifest = self._valid_overlay_manifest()
                document = manifest["documents"][0]
                field, value = mutation
                if field == "source_path":
                    document[field] = value
                elif field == "title":
                    document["entries"][0]["paper"][field] = value
                else:
                    document["entries"][0][field] = value
                path = self._write_overlay(f"invalid-{name}.json", manifest)
                with self.assertRaisesRegex(
                    CitationProjectionError, "reviewed citation overlay is invalid"
                ):
                    build_citation_projection(
                        self.base,
                        self.database,
                        self.source_objects,
                        overlay_manifest_path=path,
                        evidence_migration_root=MIGRATIONS,
                    )

        for name, identity_field in (
            ("duplicate-sha", "document_sha256"),
            ("duplicate-path", "source_path"),
            ("duplicate-path-case", "source_path_case"),
        ):
            with self.subTest(name=name):
                manifest = self._valid_overlay_manifest()
                duplicate = json.loads(json.dumps(manifest["documents"][0]))
                if identity_field == "document_sha256":
                    duplicate["source_path"] = "duplicate.md"
                elif identity_field == "source_path":
                    duplicate["document_sha256"] = "f" * 64
                else:
                    duplicate["document_sha256"] = "f" * 64
                    duplicate["source_path"] = "RESEARCH.md"
                manifest["documents"].append(duplicate)
                path = self._write_overlay(f"invalid-{name}.json", manifest)
                with self.assertRaisesRegex(
                    CitationProjectionError, "reviewed citation overlay is invalid"
                ):
                    build_citation_projection(
                        self.base,
                        self.database,
                        self.source_objects,
                        overlay_manifest_path=path,
                        evidence_migration_root=MIGRATIONS,
                    )

    def test_reviewed_overlay_external_link_keys_are_closed(self) -> None:
        marker = "Alpha"
        line_number = self.source[: self.source.index(marker.encode("utf-8"))].count(
            b"\n"
        ) + 1
        invalid_overlay = self.root / "invalid-link-overlay.json"
        invalid_overlay.write_text(
            json.dumps(
                {
                    "schema_version": "qrh-reviewed-citation-projection/v1",
                    "review_scope": "public-test-fixture",
                    "reviewed_at": NOW,
                    "documents": [
                        {
                            "source_path": "research.md",
                            "document_sha256": self.source_sha256,
                            "entries": [
                                {
                                    "key": "paper-a",
                                    "line_number": line_number,
                                    "marker": marker,
                                    "source_candidate_id": "candidate-a",
                                    "relation_summary_zh": "公开测试关系。",
                                    "paper": {
                                        "paper_id": "paper_" + "1" * 32,
                                        "title": "Paper A",
                                        "external_links": [
                                            {
                                                "kind": "repository",
                                                "url": "https://example.invalid/paper-a",
                                                "unexpected": True,
                                            }
                                        ],
                                    },
                                }
                            ],
                        }
                    ],
                },
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            CitationProjectionError, "reviewed citation overlay is invalid"
        ):
            build_citation_projection(
                self.base,
                self.database,
                self.source_objects,
                overlay_manifest_path=invalid_overlay,
                evidence_migration_root=MIGRATIONS,
            )
        invalid_scalars = self.root / "invalid-scalar-overlay.json"
        invalid_scalars.write_text(
            json.dumps(
                {
                    "schema_version": "qrh-reviewed-citation-projection/v1",
                    "review_scope": "",
                    "reviewed_at": 20260822,
                    "documents": [],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            CitationProjectionError, "reviewed citation overlay is invalid"
        ):
            build_citation_projection(
                self.base,
                self.database,
                self.source_objects,
                overlay_manifest_path=invalid_scalars,
                evidence_migration_root=MIGRATIONS,
            )

    def test_release_builder_consumes_configured_sidecar_and_binds_search_hash(self) -> None:
        citation_a = self._insert_occurrence("[A]", binding_status="resolved", key="a")
        store = SemanticJobStore(self.root / "semantic.sqlite3")
        extract_source_explicit(self.base, store)
        enriched = build_enriched_snapshot(self.base, store)
        candidate = self.root / "candidate"
        candidate.mkdir()
        (candidate / "app.py").write_text("print('ok')\n", encoding="utf-8")
        prepared = prepare_knowledge_search(
            candidate_root=candidate,
            manifest_without_inventory=_manifest(enriched.snapshot_id),
            snapshot=self.base,
            enriched=enriched,
            source_objects=self.source_objects,
            evidence_database_path=self.database,
            citation_overlay_manifest_path=self.overlay,
            evidence_migration_root=MIGRATIONS,
        )
        artifact = json.loads(prepared.artifact_path.read_bytes())
        self.assertEqual("qrh-mcp-search-artifact/v3", artifact["schema_version"])
        self.assertEqual(
            hashlib.sha256(self.database.read_bytes()).hexdigest(),
            artifact["citation_projection"]["evidence_database_sha256"],
        )
        self.assertIn(citation_a, {row["citation_id"] for row in artifact["citations"]})
        self.assertEqual(
            prepared.artifact_sha256,
            prepared.manifest_without_inventory["content"]["search_sha256"],
        )

    def test_release_builder_fails_closed_on_missing_or_tampered_overlay(self) -> None:
        store = SemanticJobStore(self.root / "semantic.sqlite3")
        extract_source_explicit(self.base, store)
        enriched = build_enriched_snapshot(self.base, store)
        invalid_overlay = self.root / "invalid-overlay.json"
        invalid_overlay.write_text("{}", encoding="utf-8")
        for name, overlay in (
            ("missing", self.root / "missing-overlay.json"),
            ("tampered", invalid_overlay),
        ):
            with self.subTest(name=name):
                candidate = self.root / f"candidate-{name}"
                candidate.mkdir()
                with self.assertRaisesRegex(
                    ReleaseBuildError, "knowledge release closure is invalid"
                ):
                    prepare_knowledge_search(
                        candidate_root=candidate,
                        manifest_without_inventory=_manifest(enriched.snapshot_id),
                        snapshot=self.base,
                        enriched=enriched,
                        source_objects=self.source_objects,
                        evidence_database_path=self.database,
                        citation_overlay_manifest_path=overlay,
                        evidence_migration_root=MIGRATIONS,
                    )
        tampered_migrations = self.root / "tampered-migrations"
        tampered_migrations.mkdir()
        for migration in MIGRATIONS.iterdir():
            payload = migration.read_bytes()
            if migration.name == "0001_evidence_core.up.sql":
                payload += b"\n-- tampered public fixture\n"
            (tampered_migrations / migration.name).write_bytes(payload)
        candidate = self.root / "candidate-tampered-migrations"
        candidate.mkdir()
        with self.assertRaisesRegex(
            ReleaseBuildError, "knowledge release closure is invalid"
        ):
            prepare_knowledge_search(
                candidate_root=candidate,
                manifest_without_inventory=_manifest(enriched.snapshot_id),
                snapshot=self.base,
                enriched=enriched,
                source_objects=self.source_objects,
                evidence_database_path=self.database,
                citation_overlay_manifest_path=self.overlay,
                evidence_migration_root=tampered_migrations,
            )


if __name__ == "__main__":
    unittest.main()
