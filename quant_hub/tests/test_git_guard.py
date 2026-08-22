from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import tomllib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "release" / "git_guard.py"
SPEC = importlib.util.spec_from_file_location("qrh_git_guard", MODULE_PATH)
assert SPEC and SPEC.loader
git_guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(git_guard)

SETUP_MODULE_PATH = ROOT / "quant_hub" / "setup.py"
SETUP_SPEC = importlib.util.spec_from_file_location(
    "qrh_public_wheel_setup", SETUP_MODULE_PATH
)
assert SETUP_SPEC and SETUP_SPEC.loader
public_wheel_setup = importlib.util.module_from_spec(SETUP_SPEC)
SETUP_SPEC.loader.exec_module(public_wheel_setup)


class GitGuardTests(unittest.TestCase):
    def test_public_wheel_excludes_all_ignored_presentation_json(self) -> None:
        policy = git_guard.load_policy(ROOT / "config" / "git_tracked_policy.json")
        package_config = tomllib.loads(
            (ROOT / "quant_hub" / "pyproject.toml").read_text(encoding="utf-8")
        )
        excluded = set(
            package_config["tool"]["setuptools"]["exclude-package-data"][
                "quant_hub.presentation"
            ]
        )
        self.assertNotIn(
            "quant_hub.presentation",
            package_config["tool"]["setuptools"]["package-data"],
        )
        expected = {
            Path(path).name
            for path in policy["excluded_exact"]
            if path.startswith("quant_hub/src/quant_hub/presentation/")
            and path.endswith(".json")
        }
        self.assertEqual(expected, excluded)

        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            build_lib = Path(temporary) / "build-lib"
            presentation = build_lib / "quant_hub" / "presentation"
            supplements = presentation / "supplements" / "private"
            supplements.mkdir(parents=True)
            public_module = presentation / "archive.py"
            public_module.write_text("PUBLIC = True\n", encoding="utf-8")
            for name in expected:
                (presentation / name).write_text("private\n", encoding="utf-8")
            (supplements / "private.md").write_text("private\n", encoding="utf-8")

            public_wheel_setup.prune_private_presentation_data(build_lib)

            self.assertTrue(public_module.is_file())
            self.assertEqual(
                [],
                [
                    path
                    for path in (presentation / "supplements").rglob("*")
                    if path.is_file()
                ],
            )
            for name in expected:
                self.assertFalse((presentation / name).exists())

    def test_public_wheel_pruner_rejects_links_without_touching_external_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            temporary_root = Path(temporary)
            build_lib = temporary_root / "build-lib"
            presentation = build_lib / "quant_hub" / "presentation"
            presentation.mkdir(parents=True)
            external = temporary_root / "external.json"
            external.write_bytes(b"external-authority")
            linked = presentation / "archive_presentation.json"
            os.link(external, linked)

            public_wheel_setup.prune_private_presentation_data(build_lib)

            self.assertFalse(linked.exists())
            self.assertEqual(b"external-authority", external.read_bytes())

        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            temporary_root = Path(temporary)
            build_lib = temporary_root / "build-lib"
            package_root = build_lib / "quant_hub"
            package_root.mkdir(parents=True)
            presentation = package_root / "presentation"
            try:
                presentation.symlink_to(
                    temporary_root / "missing-external", target_is_directory=True
                )
            except OSError as exc:
                self.skipTest(f"directory symlink unavailable: {type(exc).__name__}")

            with self.assertRaisesRegex(
                public_wheel_setup.SetupError, "reparse point"
            ):
                public_wheel_setup.prune_private_presentation_data(build_lib)

        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            temporary_root = Path(temporary)
            external_build = temporary_root / "external-build"
            victim = (
                external_build
                / "quant_hub"
                / "presentation"
                / "archive_presentation.json"
            )
            victim.parent.mkdir(parents=True)
            victim.write_bytes(b"external-authority")
            linked_build = temporary_root / "linked-build"
            try:
                linked_build.symlink_to(external_build, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlink unavailable: {type(exc).__name__}")

            with self.assertRaisesRegex(
                public_wheel_setup.SetupError, "root contains a reparse point"
            ):
                public_wheel_setup.prune_private_presentation_data(linked_build)
            self.assertEqual(b"external-authority", victim.read_bytes())

        with tempfile.TemporaryDirectory(dir=ROOT) as temporary:
            temporary_root = Path(temporary)
            external_parent = temporary_root / "external-parent"
            victim = (
                external_parent
                / "build-lib"
                / "quant_hub"
                / "presentation"
                / "archive_presentation.json"
            )
            victim.parent.mkdir(parents=True)
            victim.write_bytes(b"external-authority")
            linked_parent = temporary_root / "linked-parent"
            try:
                linked_parent.symlink_to(external_parent, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"directory symlink unavailable: {type(exc).__name__}")

            with self.assertRaisesRegex(
                public_wheel_setup.SetupError, "root contains a reparse point"
            ):
                public_wheel_setup.prune_private_presentation_data(
                    linked_parent / "build-lib"
                )
            self.assertEqual(b"external-authority", victim.read_bytes())

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
        self.assertTrue(
            git_guard.allowed(
                "docs/verification/STAGE4_CITATION_PROJECTION_20260822.md", policy
            )
        )
        citation_record = git_guard.gate(
            ["docs/verification/STAGE4_CITATION_PROJECTION_20260822.md"], policy
        )
        self.assertEqual("pass", citation_record["status"], citation_record)
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
