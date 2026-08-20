from __future__ import annotations

import hashlib

from quant_hub.paper_lab.scanner import PaperDropScanner
from quant_hub.paper_lab.service import PaperLabService
from tests.helpers import SettingsTestCase


class PaperLabScannerTests(SettingsTestCase):
    def _write(self, name: str, payload: bytes) -> None:
        root = self.settings.paper_lab_drop_root
        root.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(payload)

    def test_scan_is_pure_read_and_dated_file_is_not_renamed(self) -> None:
        self._write("7_standard.pdf", b"%PDF-1.4\n%%EOF")
        self._write("20260715-华泰证券-新论文.pdf", b"%PDF-1.4\nsecond\n%%EOF")
        self._write("bad.pdf", b"not a PDF")
        before = {
            path.name: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in self.settings.paper_lab_drop_root.iterdir()
        }
        first = PaperDropScanner(self.settings).scan()
        second = PaperDropScanner(self.settings).scan()
        after = {
            path.name: (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in self.settings.paper_lab_drop_root.iterdir()
        }
        self.assertEqual(before, after)
        self.assertEqual(first.source_manifest_sha256, second.source_manifest_sha256)
        self.assertEqual(first.source_file_count, 3)
        dated = next(item for item in first.candidates if item.naming_kind == "dated")
        self.assertEqual(dated.institution_hint, "华泰证券")
        self.assertTrue((self.settings.paper_lab_drop_root / dated.original_filename).exists())
        self.assertEqual(first.status, "PARTIAL")

    def test_registration_copies_asset_without_changing_drop(self) -> None:
        payload = b"%PDF-1.7\ncontent\n%%EOF"
        self._write("1_paper.pdf", payload)
        original = self.settings.paper_lab_drop_root / "1_paper.pdf"
        service = PaperLabService(self.settings)
        candidate = service.scan().candidates[0]
        result = service.register_candidate(candidate.candidate_id)
        self.assertEqual(result.status, "discovered")
        self.assertEqual(original.read_bytes(), payload)
        digest = hashlib.sha256(payload).hexdigest()
        self.assertEqual(
            (self.settings.paper_lab_asset_root / digest[:2] / f"{digest}.pdf").read_bytes(),
            payload,
        )
