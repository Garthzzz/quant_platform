from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from quant_hub.presentation.chapters import (
    ArchiveChapterManifestError,
    ArchiveChapterManifests,
)
from tools.build_archive_chapter_manifests import (
    _chapter_revision_id,
    build,
)


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
ARCHIVE_ROOT = WORKSPACE_ROOT / "reference" / "archive"
POLICY = FORMAL_ROOT / "fixtures" / "archive_chapters" / "chapter_policy.json"
EVIDENCE_SNAPSHOT = (
    FORMAL_ROOT / "fixtures" / "archive_chapters" / "evidence_absolute_spans.json"
)
MANIFEST_ROOT = (
    FORMAL_ROOT / "src" / "quant_hub" / "presentation" / "chapter_manifests"
)


class ArchiveChapterManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.pointer = json.loads(
            (MANIFEST_ROOT / "active.json").read_text(encoding="utf-8")
        )
        cls.generation_root = (
            MANIFEST_ROOT
            / "generations"
            / str(cls.pointer["generation_directory"])
        )
        cls.loader = ArchiveChapterManifests(MANIFEST_ROOT)

    def test_build_is_byte_deterministic_and_matches_active_generation(self) -> None:
        outputs = build(POLICY, ARCHIVE_ROOT)
        self.assertEqual(
            set(outputs),
            {
                "index.json",
                "q2-low-snr-neural-selection-factory.json",
                "q5-factor-history-sequence-compression.json",
            },
        )
        for name, payload in outputs.items():
            with self.subTest(name=name):
                self.assertEqual(payload, (self.generation_root / name).read_bytes())
                self.assertEqual(
                    hashlib.sha256(payload).hexdigest(),
                    self.pointer["files"][name],
                )

    def test_q2_q5_exact_coverage_identity_and_source_reconstruction(self) -> None:
        expectations = {
            "q2-low-snr-neural-selection-factory": (12, 32, 68_000),
            "q5-factor-history-sequence-compression": (1, 27, 21_102),
        }
        all_revisions: set[str] = set()
        for slug, (document_count, chapter_count, max_bytes) in expectations.items():
            manifest = self.loader.manifest(slug)
            self.assertIsNotNone(manifest)
            assert manifest is not None
            self.assertEqual(document_count, len(manifest["documents"]))
            self.assertEqual(
                chapter_count,
                sum(len(document["chapters"]) for document in manifest["documents"]),
            )
            release_key = manifest["archive_release_binding"]["archive_release_key"]
            for document in manifest["documents"]:
                source = (ARCHIVE_ROOT / document["source_path"]).read_bytes()
                self.assertEqual(document["source_bytes"], len(source))
                self.assertEqual(document["source_sha256"], hashlib.sha256(source).hexdigest())
                rebuilt = b""
                for chapter in document["chapters"]:
                    start = chapter["absolute_start"]
                    end = chapter["absolute_end"]
                    fragment = source[start:end]
                    rebuilt += fragment
                    self.assertLessEqual(len(fragment), max_bytes)
                    self.assertEqual(
                        chapter["source_slice_sha256"],
                        hashlib.sha256(fragment).hexdigest(),
                    )
                    self.assertNotRegex(chapter["chapter_key"], r"/section-[0-9]+$")
                    expected_revision = _chapter_revision_id(
                        release_key=release_key,
                        document_key=document["document_key"],
                        source_sha256=document["source_sha256"],
                        manifest_revision=manifest["manifest_revision"],
                        chapter_key=chapter["chapter_key"],
                        start=start,
                        end=end,
                    )
                    self.assertEqual(expected_revision, chapter["chapter_revision_id"])
                    self.assertNotIn(expected_revision, all_revisions)
                    all_revisions.add(expected_revision)
                self.assertEqual(source, rebuilt)
        self.assertEqual(59, len(all_revisions))

    def test_every_relationship_pipeline_node_and_anchor_has_exact_target(self) -> None:
        for slug in (
            "q2-low-snr-neural-selection-factory",
            "q5-factor-history-sequence-compression",
        ):
            manifest = self.loader.manifest(slug)
            assert manifest is not None
            documents = {
                document["document_key"]: document
                for document in manifest["documents"]
            }
            chapters = {
                chapter["chapter_revision_id"]: chapter
                for document in manifest["documents"]
                for chapter in document["chapters"]
            }
            for edge in manifest["relationship_edges"]:
                self.assertIn(edge["from_document_key"], documents)
                self.assertGreater(len(edge["targets"]), 0)
                for target in edge["targets"]:
                    self.assertIn(target["target_document_key"], documents)
                    chapter = chapters[target["target_chapter_revision_id"]]
                    self.assertEqual(target["target_chapter_key"], chapter["chapter_key"])
                    self.assertIn(
                        target["target_anchor_id"], chapter["heading_anchor_ids"]
                    )
            for edge in manifest["pipeline_node_edges"]:
                self.assertIn(edge["source_document_key"], documents)
                self.assertIn(edge["target_document_key"], documents)
                chapter = chapters[edge["target_chapter_revision_id"]]
                self.assertEqual(edge["target_chapter_key"], chapter["chapter_key"])
                self.assertIn(
                    edge["target_anchor_id"], chapter["heading_anchor_ids"]
                )
            legacy_identities: set[tuple[str, str]] = set()
            for alias in manifest["legacy_chapter_redirects"]:
                identity = (
                    alias["document_key"], alias["legacy_route_slug"]
                )
                self.assertNotIn(identity, legacy_identities)
                legacy_identities.add(identity)
                chapter = chapters[alias["target_chapter_revision_id"]]
                self.assertEqual(
                    alias["target_chapter_key"], chapter["chapter_key"]
                )
                self.assertIn(
                    alias["target_anchor_id"], chapter["heading_anchor_ids"]
                )
            for source_path, entry in manifest["path_anchor_index"].items():
                document = documents[entry["document_key"]]
                source = (ARCHIVE_ROOT / source_path).read_bytes()
                for anchor_id, anchor in entry["anchors"].items():
                    self.assertEqual(anchor_id, anchor["local_anchor"])
                    self.assertLess(anchor["absolute_byte_start"], anchor["absolute_byte_end"])
                    self.assertLessEqual(anchor["absolute_byte_end"], len(source))
                    chapter = chapters[anchor["chapter_revision_id"]]
                    self.assertEqual(anchor["chapter_key"], chapter["chapter_key"])
                    self.assertLessEqual(
                        chapter["absolute_start"], anchor["absolute_byte_start"]
                    )
                    self.assertLessEqual(
                        anchor["absolute_byte_end"], chapter["absolute_end"]
                    )

    def test_q2_uses_research_semantics_instead_of_heading_fragments(self) -> None:
        manifest = self.loader.manifest("q2-low-snr-neural-selection-factory")
        assert manifest is not None
        documents = {
            document["document_key"]: document
            for document in manifest["documents"]
        }
        expected_counts = {
            "research-backbone": 8,
            "research-overview": 1,
            "training-pipeline": 1,
            "d1-preprocessing-input-semantics": 5,
            "d2-factor-representation": 3,
            "d2-evidence-adjudication": 5,
            "d3-d6-effective-complexity": 4,
            "optimization-temperature": 1,
            "sensitivity-budget": 1,
            "tradeable-objective-alignment": 1,
            "glossary": 1,
            "historical-research-discipline": 1,
        }
        self.assertEqual(
            expected_counts,
            {key: len(item["chapters"]) for key, item in documents.items()},
        )
        overview = documents["research-overview"]["chapters"][0]
        self.assertEqual((0, 26352), (overview["absolute_start"], overview["absolute_end"]))
        cross_cutting = documents["research-backbone"]["chapters"][1]
        self.assertEqual("research-backbone/cross-cutting-principles", cross_cutting["chapter_key"])
        self.assertEqual(
            (27378, 95374),
            (cross_cutting["absolute_start"], cross_cutting["absolute_end"]),
        )
        self.assertGreaterEqual(len(cross_cutting["heading_anchor_ids"]), 8)
        self.assertEqual(24, len(manifest["pipeline_node_edges"]))
        pipeline = {
            edge["node_key"]: edge for edge in manifest["pipeline_node_edges"]
        }
        for node_key in ("step-2-d2", "step-2-d3", "step-2-d4", "step-2-d5"):
            self.assertEqual("research-backbone", pipeline[node_key]["target_document_key"])
            self.assertEqual("research-backbone/forward", pipeline[node_key]["target_chapter_key"])
        self.assertEqual(
            "D2：特征表征层设计、坍缩诊断与参数机制",
            documents["d2-factor-representation"]["display_title"],
        )
        self.assertEqual(216, len(manifest["legacy_chapter_redirects"]))

    def test_cross_boundary_evidence_span_fails_the_build(self) -> None:
        manifest = self.loader.manifest("q5-factor-history-sequence-compression")
        assert manifest is not None
        document = manifest["documents"][0]
        boundary = document["chapters"][0]["absolute_end"]
        spans = {
            document["source_sha256"]: [
                {
                    "absolute_start": boundary - 1,
                    "absolute_end": boundary + 1,
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "crosses a chapter boundary"):
            build(POLICY, ARCHIVE_ROOT, absolute_spans=spans)

    def test_same_count_different_evidence_spans_change_manifest_seals(self) -> None:
        manifest = self.loader.manifest("q5-factor-history-sequence-compression")
        assert manifest is not None
        source_sha256 = manifest["documents"][0]["source_sha256"]
        first = build(
            POLICY,
            ARCHIVE_ROOT,
            absolute_spans={
                source_sha256: [{"absolute_start": 1, "absolute_end": 2}]
            },
        )
        second = build(
            POLICY,
            ARCHIVE_ROOT,
            absolute_spans={
                source_sha256: [{"absolute_start": 2, "absolute_end": 3}]
            },
        )
        self.assertNotEqual(
            first["q5-factor-history-sequence-compression.json"],
            second["q5-factor-history-sequence-compression.json"],
        )
        self.assertNotEqual(first["index.json"], second["index.json"])

    def test_formal_evidence_snapshot_is_content_sealed_into_active_generation(self) -> None:
        snapshot = json.loads(EVIDENCE_SNAPSHOT.read_text(encoding="utf-8"))
        claimed = snapshot.pop("snapshot_content_sha256")
        canonical = (
            json.dumps(snapshot, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
        ).encode("utf-8")
        self.assertEqual(claimed, hashlib.sha256(canonical).hexdigest())
        q2 = self.loader.manifest("q2-low-snr-neural-selection-factory")
        assert q2 is not None
        self.assertEqual(
            271,
            sum(
                document["absolute_span_gate"]["external_absolute_spans"]
                for document in q2["documents"]
            ),
        )
        self.assertEqual(
            4,
            sum(
                document["absolute_span_gate"][
                    "external_non_positional_occurrences"
                ]
                for document in q2["documents"]
            ),
        )
        index = json.loads((self.generation_root / "index.json").read_bytes())
        self.assertEqual(
            claimed, index["evidence_absolute_span_snapshot_sha256"]
        )

    def test_pointer_tampering_is_rejected_before_serving(self) -> None:
        # The active loader has already verified all immutable files.  Its public
        # revision and index seal must be the exact pointer-bound values.
        self.assertEqual(self.pointer["index_sha256"], self.loader.index_sha256)
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
        self.assertEqual(policy["manifest_revision"], self.loader.manifest_revision)
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory) / "chapter_manifests"
            shutil.copytree(MANIFEST_ROOT, copied)
            q5 = (
                copied
                / "generations"
                / str(self.pointer["generation_directory"])
                / "q5-factor-history-sequence-compression.json"
            )
            q5.write_bytes(q5.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                ArchiveChapterManifestError, "does not match pointer"
            ):
                ArchiveChapterManifests(copied)


if __name__ == "__main__":
    unittest.main()
