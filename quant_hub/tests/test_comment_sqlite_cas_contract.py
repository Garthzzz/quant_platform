from __future__ import annotations

import inspect
import unittest

from quant_hub.collaboration.service import ArchiveCollaboration
from quant_hub.research_workspace import ResearchWorkspace


def _normalized_source(value: object) -> str:
    return " ".join(inspect.getsource(value).split())


class CommentSqliteCasContractTest(unittest.TestCase):
    def test_archive_edit_and_delete_use_revision_predicate_and_rowcount(self) -> None:
        source = _normalized_source(ArchiveCollaboration._change_comment)
        predicate = (
            "WHERE comment_id=? AND revision=? AND deleted_at IS NULL"
        )
        self.assertEqual(2, source.count(predicate))
        self.assertIn("type(updated.rowcount) is not int", source)
        self.assertIn("updated.rowcount != 1", source)

    def test_workspace_comment_and_node_updates_use_sql_cas(self) -> None:
        create_source = _normalized_source(ResearchWorkspace.create_comment)
        change_source = _normalized_source(ResearchWorkspace.change_comment)
        comment_predicate = (
            "WHERE comment_id=? AND revision=? AND deleted_at IS NULL"
        )
        node_predicate = "WHERE node_id=? AND revision=?"
        self.assertEqual(1, create_source.count(node_predicate))
        self.assertEqual(2, change_source.count(comment_predicate))
        self.assertEqual(1, change_source.count(node_predicate))
        self.assertIn("node_updated.rowcount != 1", create_source)
        self.assertIn("comment_updated.rowcount != 1", change_source)
        self.assertIn("node_updated.rowcount != 1", change_source)


if __name__ == "__main__":
    unittest.main()
