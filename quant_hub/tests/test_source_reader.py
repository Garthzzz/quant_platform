from __future__ import annotations

from pathlib import Path
import os
import subprocess
from unittest.mock import patch

from quant_hub.archive.catalog import ArchiveCatalog
from quant_hub.archive.source_reader import (
    ReadOnlyArchiveAssetSource,
    ReadOnlyArchiveSource,
    SourceBoundaryError,
    UnstableSourceError,
)
from quant_hub.ids import sha256_hex
from tests.helpers import SettingsTestCase


class MutatingReader(ReadOnlyArchiveSource):
    def _after_read(self, path: Path) -> None:
        path.write_bytes(path.read_bytes() + b"changed")


class SourceReaderTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.path = self.archive / "研究" / "示例.md"
        self.path.parent.mkdir()
        self.payload = "# 标题\n\n$\\alpha + \\beta$\n".encode("utf-8")
        self.path.write_bytes(self.payload)

    def test_exact_read_only_snapshot(self) -> None:
        before = self.path.read_bytes()
        snapshot = ReadOnlyArchiveSource(self.archive).snapshot("研究/示例.md")
        self.assertEqual(before, snapshot.content)
        self.assertEqual(sha256_hex(before), snapshot.sha256)
        self.assertEqual(len(before), snapshot.bytes)
        self.assertEqual("研究/示例.md", snapshot.relative_path)
        self.assertEqual("archive:///%E7%A0%94%E7%A9%B6/%E7%A4%BA%E4%BE%8B.md", snapshot.origin_uri)
        self.assertEqual(before, self.path.read_bytes())

    def test_windows_case_alias_uses_filesystem_canonical_origin(self) -> None:
        reader = ReadOnlyArchiveSource(self.archive)
        canonical = reader.snapshot("研究/示例.md")
        alias = reader.snapshot("研究/示例.MD")
        self.assertEqual(canonical.relative_path, alias.relative_path)
        self.assertEqual(canonical.origin_uri, alias.origin_uri)
        self.assertEqual(canonical.sha256, alias.sha256)

    def test_escape_absolute_missing_and_directory_are_rejected(self) -> None:
        reader = ReadOnlyArchiveSource(self.archive)
        non_markdown = self.archive / "研究" / "raw.txt"
        non_markdown.write_text("not markdown", encoding="utf-8")
        for candidate in (
            "../escape.md",
            str(self.path.resolve()),
            "C:relative.md",
            "研究/示例.md:stream.md",
            "研究/trailing .md",
            "研究/control\n.md",
            "missing.md",
            "研究",
            "研究/raw.txt",
        ):
            with self.subTest(candidate=candidate):
                with self.assertRaises((SourceBoundaryError, OSError)):
                    reader.snapshot(candidate)

    def test_reparse_component_is_fail_closed(self) -> None:
        reader = ReadOnlyArchiveSource(self.archive)
        with (
            patch("quant_hub.archive.source_reader.is_reparse_point", side_effect=lambda path: Path(path).name == "研究"),
            self.assertRaisesRegex(SourceBoundaryError, "reparse"),
        ):
            reader.snapshot("研究/示例.md")

    def test_change_during_read_is_rejected(self) -> None:
        with self.assertRaisesRegex(UnstableSourceError, "changed"):
            MutatingReader(self.archive).snapshot("研究/示例.md")

    def test_non_utf8_markdown_is_rejected_without_rewriting_bytes(self) -> None:
        invalid = self.archive / "研究" / "invalid.md"
        payload = b"# invalid\n\xff\xfe"
        invalid.write_bytes(payload)
        with self.assertRaisesRegex(SourceBoundaryError, "UTF-8"):
            ReadOnlyArchiveSource(self.archive).snapshot("研究/invalid.md")
        self.assertEqual(payload, invalid.read_bytes())

    def test_manifest_frozen_non_markdown_asset_is_exact_and_fail_closed(self) -> None:
        asset = self.archive / "研究" / "appendix.pdf"
        payload = b"%PDF-1.7\ncontrolled fixture\n%%EOF\n"
        asset.write_bytes(payload)
        before = asset.read_bytes()
        reader = ReadOnlyArchiveAssetSource(self.archive)
        snapshot = reader.read_verified(
            "研究/appendix.pdf",
            expected_sha256=sha256_hex(payload),
            expected_bytes=len(payload),
        )
        self.assertEqual(payload, snapshot.content)
        self.assertEqual("研究/appendix.pdf", snapshot.relative_path)
        self.assertEqual(before, asset.read_bytes())
        with self.assertRaisesRegex(SourceBoundaryError, "frozen manifest"):
            reader.read_verified(
                "研究/appendix.pdf",
                expected_sha256="0" * 64,
                expected_bytes=len(payload),
            )
        for candidate in ("../appendix.pdf", "研究/示例.md", "研究/missing.pdf"):
            with self.subTest(candidate=candidate):
                with self.assertRaises(SourceBoundaryError):
                    reader.read_verified(
                        candidate,
                        expected_sha256=sha256_hex(payload),
                        expected_bytes=len(payload),
                    )

    def test_hash_bound_raster_figure_is_allowed_but_active_svg_is_rejected(self) -> None:
        payload = b"\x89PNG\r\n\x1a\ncontrolled-raster-fixture"
        figure = self.archive / "研究" / "figure.png"
        figure.write_bytes(payload)
        reader = ReadOnlyArchiveAssetSource(self.archive)
        snapshot = reader.read_verified(
            "研究/figure.png",
            expected_sha256=sha256_hex(payload),
            expected_bytes=len(payload),
        )
        self.assertEqual(payload, snapshot.content)

        svg = self.archive / "研究" / "active.svg"
        svg_payload = b"<svg><script>alert(1)</script></svg>"
        svg.write_bytes(svg_payload)
        with self.assertRaisesRegex(SourceBoundaryError, "canonical or allowed"):
            reader.read_verified(
                "研究/active.svg",
                expected_sha256=sha256_hex(svg_payload),
                expected_bytes=len(svg_payload),
            )

    def test_catalog_can_use_an_explicit_verified_presentation_asset_root(self) -> None:
        payload = b"\x89PNG\r\n\x1a\nexternal-presentation-fixture"
        asset_root = self.root / "presentation-assets"
        asset = asset_root / "研究" / "figure.png"
        asset.parent.mkdir(parents=True)
        asset.write_bytes(payload)
        catalog = ArchiveCatalog(
            self.settings,
            presentation_asset_root=asset_root,
        )
        frozen = {
            "asset_id": "fixture-figure",
            "source_path": "研究/figure.png",
            "sha256": sha256_hex(payload),
            "bytes": len(payload),
            "media_type": "image/png",
            "filename": "figure.png",
        }
        with patch.object(catalog.presentation, "internal_asset", return_value=frozen):
            content, identity = catalog.presentation_asset("fixture-figure")
        self.assertEqual(payload, content)
        self.assertEqual(frozen, identity)

    def test_real_windows_junction_component_is_rejected(self) -> None:
        if os.name != "nt":
            self.skipTest("Windows runtime contract")
        external = self.root / "external"
        external.mkdir()
        (external / "outside.md").write_text("# outside\n", encoding="utf-8")
        junction = self.archive / "junction"
        completed = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(external)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
        try:
            with self.assertRaisesRegex(SourceBoundaryError, "reparse"):
                ReadOnlyArchiveSource(self.archive).snapshot("junction/outside.md")
            self.assertEqual("# outside\n", (external / "outside.md").read_text(encoding="utf-8"))
        finally:
            if os.path.lexists(junction):
                os.rmdir(junction)
