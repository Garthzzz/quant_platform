from __future__ import annotations

import unittest

from pydantic import ValidationError

from quant_hub.archive.contracts import (
    ActorInput,
    ArchiveDocumentInput,
    ArchiveReleaseInput,
)


class ArchiveContractTests(unittest.TestCase):
    def _document(self, **changes: object) -> ArchiveDocumentInput:
        payload: dict[str, object] = {
            "document_slug": "main",
            "document_role": "primary",
            "source_path": "研究/正文.md",
            "approved_origin_uri": "archive:///%E7%A0%94%E7%A9%B6/%E6%AD%A3%E6%96%87.md",
            "approved_object_urn": "qrh:object:obj_sha256_" + "a" * 64,
            "approved_content_sha256": "a" * 64,
            "approved_bytes": 123,
            "navigation_role": "primary",
            "sort_key": 10,
            "mapping_authority_urn": "qrh:review:fixture",
            "mapping_note": "测试中的显式映射决定",
        }
        payload.update(changes)
        return ArchiveDocumentInput.model_validate(payload)

    def test_release_requires_one_primary_and_explicit_activation(self) -> None:
        release = ArchiveReleaseInput(
            research_slug="research-a",
            display_title="研究 A",
            release_key="release-v1",
            documents=(self._document(),),
            activate=True,
            release_snapshot_urn="qrh:release_snapshot:fixture",
            activation_decision_hash="a" * 64,
        )
        self.assertEqual("研究/正文.md", release.documents[0].source_path)

        with self.assertRaises(ValidationError):
            ArchiveReleaseInput(
                research_slug="research-a",
                display_title="研究 A",
                release_key="release-v1",
                documents=(self._document(navigation_role="supporting"),),
                activate=True,
                release_snapshot_urn="qrh:release_snapshot:fixture",
                activation_decision_hash="a" * 64,
            )
        with self.assertRaises(ValidationError):
            ArchiveReleaseInput(
                research_slug="research-a",
                display_title="研究 A",
                release_key="release-v1",
                documents=(self._document(),),
                activate=True,
            )

    def test_source_path_and_document_identity_are_canonical(self) -> None:
        for invalid in ("../逃逸.md", "研究\\正文.md", "/绝对.md", "研究/正文.txt"):
            with self.subTest(invalid=invalid), self.assertRaises(Exception):
                self._document(source_path=invalid)
        with self.assertRaises(ValidationError):
            ArchiveReleaseInput(
                research_slug="research-a",
                display_title="研究 A",
                release_key="release-v1",
                documents=(self._document(), self._document()),
                activate=False,
            )

    def test_actor_presets_and_other_cannot_be_confused(self) -> None:
        self.assertEqual("zhang_zhengze", ActorInput(actor_kind="zhang_zhengze").actor_kind)
        self.assertEqual(
            "研究员甲",
            ActorInput(actor_kind="other", display_name="研究员甲").display_name,
        )
        with self.assertRaises(ValidationError):
            ActorInput(actor_kind="other")
        with self.assertRaises(ValidationError):
            ActorInput(actor_kind="other", display_name="张正泽")
        with self.assertRaises(ValidationError):
            ActorInput(actor_kind="song_dingkun", display_name="伪造姓名")


if __name__ == "__main__":
    unittest.main()
