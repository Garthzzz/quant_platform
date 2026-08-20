from __future__ import annotations

import hashlib
import os

from quant_hub.evidence.contracts import FetchAttemptInput
from quant_hub.evidence.repository import EvidenceRepository
from quant_hub.evidence.resources import (
    EvidenceResourceCorruption,
    EvidenceResourceNotFound,
    EvidenceResourceStore,
)
from tests.helpers import SettingsTestCase


class EvidenceResourceTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.repository = EvidenceRepository(self.settings)
        self.repository.initialize()
        self.store = EvidenceResourceStore(self.settings)
        self.payload = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF\n"
        self.paper = self.repository.create_paper(
            "report:test-resource", provenance_urn="qrh:test:resource"
        )
        digest = hashlib.sha256(self.payload).hexdigest()
        self.attempt = self.repository.record_fetch_attempt(
            FetchAttemptInput(
                requested_url="https://example.test/paper.pdf",
                redirect_chain=(),
                final_url="https://example.test/paper.pdf",
                http_status=200,
                response_mime="application/pdf",
                response_bytes=len(self.payload),
                response_sha256=digest,
                request_identity_hash="a" * 64,
                rights_status="public_access_unknown_reuse",
                legal_basis="test fixture",
                result_status="succeeded",
            ),
            paper_id=self.paper.paper_id,
            candidate_id=None,
            attempt_key="resource-success",
        )
        self.staged = self.store.put_pdf(self.payload)
        self.resource_id, _ = self.repository.register_resource(
            paper_id=self.paper.paper_id,
            fetch_attempt_id=self.attempt.fetch_attempt_id,
            content_sha256=self.staged.content_sha256,
            size=self.staged.bytes,
            relative_path=self.staged.relative_path,
            rights_status="public_access_unknown_reuse",
        )

    def test_route_contract_resolves_only_resource_id_and_rechecks_bytes(self) -> None:
        response = self.store.resource_response(self.resource_id)
        self.assertEqual(self.payload, response.payload)
        self.assertEqual("application/pdf", response.media_type)
        self.assertEqual(f"{self.resource_id}.pdf", response.download_name)
        for attack in ("../paper.pdf", "/absolute.pdf", "a\\..\\paper.pdf"):
            with self.subTest(attack=attack), self.assertRaises(EvidenceResourceNotFound):
                self.store.resource_response(attack)

    def test_hard_link_and_content_tampering_fail_closed(self) -> None:
        target = self.settings.research_papers_root.joinpath(
            *self.staged.relative_path.split("/")
        )
        hard_link = target.with_suffix(".hardlink.pdf")
        os.link(target, hard_link)
        try:
            with self.assertRaisesRegex(EvidenceResourceCorruption, "single-link"):
                self.store.resource_response(self.resource_id)
        finally:
            hard_link.unlink()
        target.write_bytes(b"%PDF-1.4\ntampered\n%%EOF\n")
        with self.assertRaisesRegex(EvidenceResourceCorruption, "database identity"):
            self.store.resource_response(self.resource_id)

    def test_non_pdf_payload_is_rejected_before_registration(self) -> None:
        with self.assertRaisesRegex(EvidenceResourceCorruption, "PDF magic"):
            self.store.put_pdf(b"not a PDF")


if __name__ == "__main__":
    import unittest

    unittest.main()
