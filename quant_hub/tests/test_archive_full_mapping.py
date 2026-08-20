from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from quant_hub.archive.contracts import ArchiveReleaseInput


FORMAL_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = FORMAL_ROOT.parent
FIXTURE_ROOT = FORMAL_ROOT / "fixtures" / "archive_full"
GENERATED_ROOT = FIXTURE_ROOT / "generated"
ARCHIVE_ROOT = WORKSPACE_ROOT / "reference" / "archive"


def tree_bytes(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class FullArchiveMappingTests(unittest.TestCase):
    def test_candidate_covers_every_markdown_exactly_once_or_with_reason(self) -> None:
        index = json.loads((GENERATED_ROOT / "index.json").read_text(encoding="utf-8"))
        self.assertEqual("READY_FOR_INDEPENDENT_MAPPING_REVIEW", index["status"])
        markdown = {
            path.relative_to(ARCHIVE_ROOT).as_posix()
            for path in ARCHIVE_ROOT.rglob("*")
            if path.is_file() and path.suffix.lower() in {".md", ".markdown"}
        }
        self.assertEqual(len(markdown), index["source"]["markdown_count"])
        self.assertEqual(
            index["source"]["markdown_count"],
            index["coverage"]["assigned_count"]
            + index["coverage"]["excluded_count"]
            + index["coverage"]["unassigned_count"],
        )
        self.assertEqual(0, index["coverage"]["unassigned_count"])
        self.assertEqual(0, index["coverage"]["multiply_assigned_count"])

        bootstrap = index["bootstrap_releases"]
        self.assertEqual(1, len(bootstrap))
        bootstrap_path = WORKSPACE_ROOT / bootstrap[0]["path"]
        bootstrap_payload = bootstrap_path.read_bytes()
        self.assertEqual(
            bootstrap[0]["sha256"],
            hashlib.sha256(bootstrap_payload).hexdigest(),
        )
        bootstrap_release = ArchiveReleaseInput.model_validate_json(bootstrap_payload)
        self.assertEqual(bootstrap[0]["release_key"], bootstrap_release.release_key)
        self.assertEqual(bootstrap[0]["research_slug"], bootstrap_release.research_slug)
        self.assertFalse(bootstrap_release.activate)

        assigned: set[str] = set()
        document_count = 0
        for group in index["groups"]:
            release_path = GENERATED_ROOT / group["release_file"]
            payload = release_path.read_bytes()
            self.assertEqual(group["release_sha256"], hashlib.sha256(payload).hexdigest())
            release = ArchiveReleaseInput.model_validate_json(payload)
            self.assertFalse(release.activate)
            self.assertEqual(group["document_count"], len(release.documents))
            document_count += len(release.documents)
            for document in release.documents:
                self.assertNotIn(document.source_path, assigned)
                assigned.add(document.source_path)
                source = (ARCHIVE_ROOT / Path(document.source_path)).read_bytes()
                self.assertEqual(document.approved_bytes, len(source))
                self.assertEqual(document.approved_content_sha256, hashlib.sha256(source).hexdigest())
        self.assertEqual(index["coverage"]["assigned_count"], document_count)

        excluded = {row["path"] for row in index["excluded"]}
        self.assertEqual(index["coverage"]["excluded_count"], len(excluded))
        self.assertTrue(all(row["reason"].strip() for row in index["excluded"]))
        self.assertFalse(assigned & excluded)
        self.assertEqual(markdown, assigned | excluded)

    def test_generated_mapping_is_byte_deterministic_and_uses_utf8_lf(self) -> None:
        expected = tree_bytes(GENERATED_ROOT)
        with tempfile.TemporaryDirectory(prefix="qrh-full-mapping-") as raw:
            output = Path(raw) / "generated"
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(FORMAL_ROOT / "src")
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    str(FORMAL_ROOT / "tools" / "build_full_archive_manifests.py"),
                    "--archive-root",
                    str(ARCHIVE_ROOT),
                    "--output",
                    str(output),
                ],
                cwd=WORKSPACE_ROOT,
                env=environment,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                0,
                result.returncode,
                result.stderr.decode("utf-8", errors="replace"),
            )
            self.assertEqual(expected, tree_bytes(output))
        for relative_path, payload in expected.items():
            if relative_path.endswith((".json", ".tsv")):
                payload.decode("utf-8")
                self.assertNotIn(b"\r\n", payload)
                self.assertTrue(payload.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
