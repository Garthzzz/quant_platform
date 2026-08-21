from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "release" / "git_guard.py"
SPEC = importlib.util.spec_from_file_location("qrh_git_guard", MODULE_PATH)
assert SPEC and SPEC.loader
git_guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(git_guard)


class GitGuardTests(unittest.TestCase):
    def test_policy_excludes_runtime_research_and_content_assets(self) -> None:
        policy = git_guard.load_policy(ROOT / "config" / "git_tracked_policy.json")
        for path in (
            "reference/archive/research.md",
            "deploy/company_broadcast.zip",
            "quant_hub/data/comments.sqlite3",
            "quant_hub/paper_lab/papers/paper.pdf",
            "quant_hub/src/quant_hub/presentation/archive_presentation.json",
        ):
            self.assertFalse(git_guard.allowed(path, policy), path)
        self.assertTrue(git_guard.allowed("quant_hub/src/quant_hub/app.py", policy))
        self.assertTrue(git_guard.allowed("openspec/changes/design-vm-knowledge-mcp/design.md", policy))
        self.assertTrue(
            git_guard.allowed(
                "docs/verification/STAGE4_PUBLIC_RAG_REPAIR_20260822.md", policy
            )
        )
        self.assertFalse(git_guard.allowed("docs/verification/private-result.md", policy))

    def test_gate_reports_secret_by_fingerprint_without_value(self) -> None:
        policy = git_guard.load_policy(ROOT / "config" / "git_tracked_policy.json")
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            path = Path(temporary) / "probe.py"
            secret = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz" + "012345"
            path.write_text(f"token = '{secret}'\n", encoding="utf-8")
            rel = path.relative_to(ROOT).as_posix()
            policy["tracked_exact"].append(rel)
            result = git_guard.gate([rel], policy)
            self.assertEqual(result["status"], "blocked")
            payload = json.dumps(result)
            self.assertNotIn(secret, payload)
            self.assertIn("github_token", payload)

    def test_manifest_design_is_explicitly_allowed_but_other_state_is_not(self) -> None:
        policy = git_guard.load_policy(ROOT / "config" / "git_tracked_policy.json")
        design = "project_state/architecture/quant_platform_VM知识MCP总体设计_20260820.md"
        self.assertTrue(git_guard.allowed(design, policy))
        self.assertFalse(git_guard.allowed("project_state/CURRENT.md", policy))


if __name__ == "__main__":
    unittest.main()
