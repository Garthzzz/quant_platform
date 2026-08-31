from __future__ import annotations

from contextlib import closing
import hashlib
import json
from pathlib import Path, PureWindowsPath
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from quant_hub.knowledge.contracts import canonical_json
from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge.semantic import (
    SemanticJobStore,
    deprecate_item,
    extract_source_explicit,
)
from quant_hub.ops.publish_adapters import (
    HTTPResponse,
    ReleaseFile,
    sealed_candidate_tooling_update_script,
    verified_d_tooling_python_script,
)
from quant_hub.ops.publish_runtime import (
    EnvironmentSecretProvider,
    GitSnapshot,
    ProcessResult,
    ProductionSourceFreezer,
    ProductionPublishRuntime,
    PublishRuntimeError,
    RUNTIME_CONFIG_SCHEMA,
    RuntimeDependencies,
    RuntimePublishConfig,
)
from quant_hub.ops.vm_boundary import validate_production_vm_write_path
from quant_hub.ops.release_builder import seal_release
from quant_hub.ops.semantic_authority import promote_semantic_authority
from quant_hub.ops.windows_service import quant_hub_package_inventory_sha256
from quant_hub.platform.db import connect_database
from quant_hub.platform.migrations import migrate_up
from quant_hub.generic_research.release import deserialize_snapshot


RESEARCH_PAPERS_MIGRATIONS = (
    Path(__file__).resolve().parents[1] / "migrations" / "research_papers"
)


class MemoryBackend:
    def __init__(self) -> None:
        self.files: dict[str, ReleaseFile] = {}
        self.partial: PureWindowsPath | None = None
        self.paths: list[PureWindowsPath] = []

    def ensure_directory(self, path):
        approved = validate_production_vm_write_path(path, allow_root=False)
        self.paths.append(approved)
        if approved.name.endswith(".partial"):
            self.partial = approved

    def inventory(self, path):
        self.paths.append(validate_production_vm_write_path(path, allow_root=False))
        return dict(self.files)

    def upload(self, local_path, remote_path):
        approved = validate_production_vm_write_path(remote_path, allow_root=False)
        self.paths.append(approved)
        assert self.partial is not None
        relative = approved.relative_to(self.partial).as_posix()
        value = Path(local_path).read_bytes()
        self.files[relative] = ReleaseFile(
            relative, len(value), hashlib.sha256(value).hexdigest()
        )


class FakeInvoker:
    def __init__(self) -> None:
        self.calls = []

    def invoke(self, **arguments):
        self.calls.append(arguments)
        mode = arguments["deployment_mode"]
        return {
            "schema_version": "qrh-vm-deploy-result/v1",
            "release_id": arguments["release_id"],
            "release_manifest_sha256": arguments["release_manifest_sha256"],
            "publish_candidate_sha256": arguments["publish_candidate_sha256"],
            "status": "activated" if mode == "activate" else "candidate_validated",
            "evidence_id": "activation-fixture" if mode == "activate" else "candidate-fixture",
            "evidence_type": "activation_receipt" if mode == "activate" else "candidate_validation_event",
        }


class PublishRuntimeTests(unittest.TestCase):
    def test_v1_remote_tooling_is_limited_to_candidate_and_update_boundaries(self) -> None:
        candidate_only = verified_d_tooling_python_script(
            "deployment_cli_module", allow_legacy=True
        )
        activate = verified_d_tooling_python_script("deployment_cli_module")
        updater = sealed_candidate_tooling_update_script(
            release_id="release-r1",
            release_manifest_sha256="a" * 64,
            attempt_id="tooling-r1",
        )
        self.assertIn("$allowLegacy=$true", candidate_only)
        self.assertIn("$allowLegacy=$true", updater)
        self.assertIn("$allowLegacy=$false", activate)
        self.assertIn("legacy_operational_binding_forbidden", activate)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.project = self.root / "project"
        self.project.mkdir()
        subprocess.run(["git", "init", "-b", "main"], cwd=self.project, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=self.project, check=True)
        subprocess.run(["git", "config", "user.name", "test"], cwd=self.project, check=True)
        (self.project / "app.py").write_text("print('legacy unchanged')\n", encoding="utf-8")
        (self.project / "quant_hub").mkdir()
        (self.project / "quant_hub" / "service.py").write_text(
            "print('Git code overlay')\n", encoding="utf-8"
        )
        subprocess.run(["git", "add", "app.py", "quant_hub/service.py"], cwd=self.project, check=True)
        subprocess.run(["git", "commit", "-m", "fixture"], cwd=self.project, check=True, capture_output=True)
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.project, check=True,
            capture_output=True, text=True, encoding="utf-8",
        ).stdout.strip()
        self.reference = self.root / "read-only-reference"
        self.reference.mkdir()
        (self.reference / "research.md").write_text(
            "# Factor\n\n方法：Use point-in-time evidence.\n", encoding="utf-8"
        )
        self.protected = self.root / "protected"
        self.protected.mkdir()
        self._seed_semantic_state(self.protected / "publish-state")
        self.runtime_base = self.root / "immutable-runtime-base"
        base_files = {
            "runtime_contract/start.py": b"print('v39-launcher-ok')\n",
            "runtime_contract/code/old.py": b"print('old')\n",
            "runtime_contract/code/src/quant_hub/presentation/archive_presentation.json": b'{"schema_version":"private-archive-fixture/v1"}\n',
            "runtime_contract/code/src/quant_hub/presentation/citation_projection_overrides.json": canonical_json(
                {
                    "schema_version": "qrh-reviewed-citation-projection/v1",
                    "review_scope": "public-test-fixture",
                    "reviewed_at": "2026-08-22T00:00:00Z",
                    "documents": [],
                }
            ).encode("utf-8"),
            "runtime_contract/code/src/quant_hub/presentation/evidence_zh_overlays.json": b'{"schema_version":"private-evidence-fixture/v1"}\n',
            "runtime_contract/code/src/quant_hub/presentation/research_supplements.json": b'{"schema_version":"private-supplement-fixture/v1"}\n',
            "runtime_contract/code/src/quant_hub/presentation/chapter_manifests/active.json": b'{"generation_id":"private-generation"}\n',
            "runtime_contract/code/src/quant_hub/presentation/supplements/private.md": b"private supplement\n",
            "runtime/templates/index.html": b"<main>V39 legacy</main>\n",
            "runtime/static/app.css": b"body{color:#111}\n",
            "runtime/db/archive.sqlite3": b"archive-db",
            "runtime/db/platform.sqlite3": b"platform-db",
            "runtime/db/paper_lab.sqlite3": b"paper-lab-db",
            "runtime/research_papers/paper.pdf": b"%PDF-fixture",
            "runtime/objects/legacy-object.bin": b"legacy-object",
            "runtime/paper_lab/catalog.json": b"{}",
            "persistent_seed/research_workspace.sqlite3": b"seed",
        }
        for relative, payload in base_files.items():
            path = self.runtime_base / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        research_papers_database = (
            self.runtime_base / "runtime" / "db" / "research_papers.sqlite3"
        )
        research_papers_connection = connect_database(research_papers_database)
        migrate_up(research_papers_connection, RESEARCH_PAPERS_MIGRATIONS)
        research_papers_connection.close()
        staged_migrations = (
            self.runtime_base / "runtime_contract" / "migrations"
            / "research_papers"
        )
        staged_migrations.mkdir(parents=True)
        for migration in RESEARCH_PAPERS_MIGRATIONS.iterdir():
            (staged_migrations / migration.name).write_bytes(migration.read_bytes())
        base_manifest = {
            "schema_version": "qrh-release-manifest/v1",
            "release_id": "v39-like-base",
            "built_at": "2026-08-21T00:00:00Z",
            "application": {
                "source_kind": "legacy_broadcast",
                "commit_sha": "0" * 40,
                "tracked_tree_sha256": "1" * 64,
                "build_tool_version": "v39-like-fixture/v1",
                "source_archive_sha256": "2" * 64,
                "legacy_deployment_id": "v39-like-fixture",
            },
            "content": {
                "snapshot_id": "v39-like-snapshot",
                "source_inventory_sha256": "3" * 64,
                "ir_sha256": "4" * 64,
                "knowledge_sha256": "5" * 64,
                "search_sha256": "6" * 64,
                "knowledge_enrichment": {"status": "not_applicable"},
            },
            "resources": {},
            "state": {"compatibility": {"comments": {"read": [1], "write": [1]}}},
        }
        sealed_base = seal_release(
            candidate_root=self.runtime_base,
            manifest_without_inventory=base_manifest,
        )
        overlay = self.root / "resource-overlay"
        overlay.mkdir()
        (overlay / "new-object.bin").write_bytes(b"new-object")
        self.operational = self.root / "operational-bootstrap-source"
        operational_files = {
            "tooling/python/Lib/site-packages/win32/pythonservice.exe": b"python-service",
            "tooling/python/python.exe": b"python-runtime",
            "tooling/python/Lib/site-packages/quant_hub/ops/windows_service.py": b"service-host",
            "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py": b"service-entry",
            "tooling/python/Lib/site-packages/quant_hub/ops/vm_deploy_cli.py": b"deploy-cli",
            "tooling/python/Lib/site-packages/quant_hub/web/access_gate.py": b"access-gate",
            "control/deployment_runtime.json": canonical_json(
                {"schema_version": "qrh-vm-deploy-runtime/v1", "fixture": True}
            ).encode("utf-8"),
        }
        for relative, payload in operational_files.items():
            path = self.operational.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        bindings = {
            "service_executable": "tooling/python/Lib/site-packages/win32/pythonservice.exe",
            "service_python": "tooling/python/python.exe",
            "service_host_module": "tooling/python/Lib/site-packages/quant_hub/ops/windows_service.py",
            "service_entry_module": "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            "deployment_cli_module": "tooling/python/Lib/site-packages/quant_hub/ops/vm_deploy_cli.py",
            "access_gate_module": "tooling/python/Lib/site-packages/quant_hub/web/access_gate.py",
            "deployment_runtime": "control/deployment_runtime.json",
        }
        service_candidate = {
            "schema_version": "qrh-windows-service-install-candidate/v1",
            "service_name": "QuantResearchHub",
            "python_class": "quant_hub.ops.windows_service.QuantResearchHubWindowsService",
            "start_type": "automatic",
        }
        for field, relative in bindings.items():
            source = self.operational.joinpath(*relative.split("/"))
            service_candidate[field] = str(
                PureWindowsPath(r"D:\quant\quant_platform").joinpath(
                    *relative.split("/")
                )
            )
            service_candidate[f"{field}_sha256"] = hashlib.sha256(
                source.read_bytes()
            ).hexdigest()
        package = self.operational / "tooling/python/Lib/site-packages/quant_hub"
        service_candidate["quant_hub_package_root"] = str(
            PureWindowsPath(r"D:\quant\quant_platform")
            / "tooling/python/Lib/site-packages/quant_hub"
        )
        service_candidate["quant_hub_package_inventory_sha256"] = (
            quant_hub_package_inventory_sha256(package)
        )
        (self.operational / "control" / "service_install_candidate.json").write_text(
            canonical_json(service_candidate), encoding="utf-8"
        )
        self.config_value = {
            "schema_version": RUNTIME_CONFIG_SCHEMA,
            "project_root": str(self.project),
            "state_root": str(self.protected / "publish-state"),
            "candidate_root": str(self.protected / "candidates"),
            "git_remote": "origin",
            "runtime_base": str(self.runtime_base),
            "runtime_base_manifest_sha256": sealed_base.manifest_sha256,
            "reference_archive_root": str(self.reference),
            "code_source_relative_path": "quant_hub",
            "code_overlay_relative_path": "runtime_contract/code",
            "launcher_relative_path": "runtime_contract/start.py",
            "required_runtime_paths": {
                "launcher": "runtime_contract/start.py",
                "templates": "runtime/templates",
                "static": "runtime/static",
                "archive_database": "runtime/db/archive.sqlite3",
                "platform_database": "runtime/db/platform.sqlite3",
                "research_papers_database": "runtime/db/research_papers.sqlite3",
                "paper_lab_database": "runtime/db/paper_lab.sqlite3",
                "presentation_manifest": "runtime_contract/code/src/quant_hub/presentation/archive_presentation.json",
                "papers": "runtime/research_papers",
                "objects": "runtime/objects",
                "paper_lab": "runtime/paper_lab",
                "state_seed": "persistent_seed",
            },
            "resource_overlays": [
                {
                    "logical_name": "new_objects",
                    "source_path": str(overlay),
                    "target_relative_path": "runtime/objects",
                }
            ],
            "github": {
                "owner": "Garthzzz", "repository": "quant_platform",
                "workflow_id": 123, "credential_target": "github-actions-read",
                "poll_interval_seconds": 1, "timeout_seconds": 10,
            },
            "vm": {
                "ssh_alias": "honghu-vm",
                "target_address": "10.5.1.240",
                "root": r"D:\quant\quant_platform",
            },
        }

    def _seed_semantic_state(self, state_root: Path, mutator=None) -> None:
        state_root.mkdir(parents=True, exist_ok=False)
        source = state_root.parent / (state_root.name + "-semantic-campaign.sqlite3")
        semantic_store = SemanticJobStore(source)
        semantic_report = ReferenceCompiler().compile(self.reference)
        assert semantic_report.candidate_snapshot is not None
        extract_source_explicit(semantic_report.candidate_snapshot, semantic_store)
        if mutator is not None:
            mutator(semantic_store, semantic_report.candidate_snapshot)
        with closing(semantic_store.connect()) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        promote_semantic_authority(
            project_root=self.project,
            state_root=state_root,
            source_path=source,
            promoted_at="2026-08-21T00:00:00Z",
        )

    def config(self):
        return RuntimePublishConfig.parse(self.config_value)

    def dependencies(self):
        backend = MemoryBackend()
        invoker = FakeInvoker()
        process_calls = []

        def process(arguments, cwd):
            call = tuple(arguments)
            process_calls.append(call)
            if call[:2] in {
                ("git", "ls-tree"),
                ("git", "rev-parse"),
                ("git", "hash-object"),
            }:
                completed = subprocess.run(
                    list(call), cwd=cwd, check=False, capture_output=True,
                    text=True, encoding="utf-8",
                )
                return ProcessResult(completed.returncode, completed.stdout)
            if call[:2] == ("git", "ls-remote"):
                return ProcessResult(0, f"{self.commit}\trefs/heads/main\n")
            return ProcessResult(0, "")

        def http_get(*_):
            return HTTPResponse(
                200,
                json.dumps(
                    {
                        "workflow_runs": [
                            {
                                "id": 99, "workflow_id": 123,
                                "head_sha": self.commit, "head_branch": "main",
                                "event": "push", "status": "completed",
                                "conclusion": "success",
                                "repository": {"full_name": "Garthzzz/quant_platform"},
                            }
                        ]
                    }
                ).encode(),
            )

        deps = RuntimeDependencies(
            process_runner=process,
            secret_provider=EnvironmentSecretProvider(
                {"QRH_SECRET_GITHUB_ACTIONS_READ": "memory-secret"}
            ),
            http_get=http_get,
            vm_backend=backend,
            deployment_invoker=invoker,
        )
        return deps, backend, invoker, process_calls

    def test_candidate_only_assembles_full_fixed_pipeline(self) -> None:
        local_ignored_overlay = (
            self.project / "quant_hub" / "src" / "quant_hub" / "presentation"
            / "citation_projection_overrides.json"
        )
        local_ignored_overlay.parent.mkdir(parents=True)
        local_ignored_overlay.write_text("development-machine-only", encoding="utf-8")
        local_private_assets = {
            "archive_presentation.json": b"local-unsealed-archive",
            "evidence_zh_overlays.json": b"local-unsealed-evidence",
            "research_supplements.json": b"local-unsealed-supplements",
        }
        for name, payload in local_private_assets.items():
            (local_ignored_overlay.parent / name).write_bytes(payload)
        local_private_chapter = local_ignored_overlay.parent / "chapter_manifests" / "active.json"
        local_private_chapter.parent.mkdir()
        local_private_chapter.write_bytes(b"local-unsealed-chapter")
        local_private_supplement = local_ignored_overlay.parent / "supplements" / "private.md"
        local_private_supplement.parent.mkdir()
        local_private_supplement.write_bytes(b"local-unsealed-supplement")
        deps, backend, invoker, process_calls = self.dependencies()
        semantic_path = self.protected / "publish-state" / "semantic_jobs.sqlite3"
        semantic_hash_before = hashlib.sha256(semantic_path.read_bytes()).hexdigest()
        result = ProductionPublishRuntime(self.config(), dependencies=deps).publish(
            commit_sha=self.commit, candidate_only=True
        )
        self.assertEqual("succeeded", result["status"])
        self.assertEqual("candidate_only", result["result"]["deployment_mode"])
        self.assertEqual("candidate_only", invoker.calls[0]["deployment_mode"])
        self.assertTrue(any(call[:2] == ("git", "push") for call in process_calls))
        self.assertIn(
            (
                sys.executable,
                "-B",
                "-m",
                "unittest",
                "discover",
                "-s",
                "quant_hub/tests",
                "-t",
                "quant_hub",
                "-p",
                "test_*.py",
                "-q",
            ),
            process_calls,
        )
        self.assertIn(
            (
                sys.executable,
                "-B",
                "tools/release/git_guard.py",
                "gate",
                "--scope",
                "all",
            ),
            process_calls,
        )
        self.assertEqual(
            semantic_hash_before,
            hashlib.sha256(semantic_path.read_bytes()).hexdigest(),
        )
        self.assertFalse(semantic_path.with_name(semantic_path.name + "-wal").exists())
        self.assertFalse(semantic_path.with_name(semantic_path.name + "-shm").exists())
        self.assertTrue(
            all(str(path).casefold().startswith(r"d:\quant\quant_platform") for path in backend.paths)
        )
        releases = list((self.protected / "candidates").glob("release-*"))
        self.assertEqual(1, len(releases))
        self.assertTrue((releases[0] / "runtime" / "templates" / "index.html").is_file())
        self.assertTrue((releases[0] / "runtime" / "static" / "app.css").is_file())
        self.assertTrue((releases[0] / "runtime" / "db" / "archive.sqlite3").is_file())
        self.assertTrue((releases[0] / "runtime" / "objects" / "legacy-object.bin").is_file())
        self.assertTrue((releases[0] / "runtime" / "objects" / "new-object.bin").is_file())
        launcher = releases[0] / "runtime_contract" / "start.py"
        self.assertTrue(launcher.is_file())
        self.assertTrue((releases[0] / "runtime_contract" / "code" / "service.py").is_file())
        self.assertEqual(
            "print('Git code overlay')\n",
            (releases[0] / "runtime_contract" / "code" / "service.py").read_text(encoding="utf-8"),
        )
        self.assertFalse((releases[0] / "runtime_contract" / "code" / "app.py").exists())
        self.assertEqual(
            "<main>V39 legacy</main>\n",
            (releases[0] / "runtime" / "templates" / "index.html").read_text(encoding="utf-8"),
        )
        self.assertFalse((releases[0] / "runtime_contract" / "code" / "old.py").exists())
        staged_overlay = (
            releases[0] / "runtime_contract" / "code" / "src" / "quant_hub"
            / "presentation" / "citation_projection_overrides.json"
        )
        base_overlay = (
            self.runtime_base / "runtime_contract" / "code" / "src" / "quant_hub"
            / "presentation" / "citation_projection_overrides.json"
        )
        self.assertEqual(base_overlay.read_bytes(), staged_overlay.read_bytes())
        self.assertNotEqual(local_ignored_overlay.read_bytes(), staged_overlay.read_bytes())
        for relative in (
            "archive_presentation.json",
            "evidence_zh_overlays.json",
            "research_supplements.json",
            "chapter_manifests/active.json",
            "supplements/private.md",
        ):
            base_private = base_overlay.parent.joinpath(*relative.split("/"))
            staged_private = staged_overlay.parent.joinpath(*relative.split("/"))
            self.assertEqual(base_private.read_bytes(), staged_private.read_bytes())
        self.assertFalse((releases[0] / "external" / "reference").exists())
        launched = subprocess.run(
            [sys.executable, str(launcher)], capture_output=True, text=True,
            encoding="utf-8", check=False,
        )
        self.assertEqual(0, launched.returncode)
        self.assertEqual("v39-launcher-ok", launched.stdout.strip())
        manifest = json.loads((releases[0] / "release_manifest.json").read_text(encoding="utf-8"))
        serialized_manifest = canonical_json(manifest)
        self.assertTrue(manifest["content"]["snapshot_id"].startswith("ksnap_"))
        self.assertEqual("qrh-release-manifest/v2", manifest["schema_version"])
        self.assertEqual(
            "ready_set",
            manifest["content"]["knowledge_enrichment"]["status"],
        )
        self.assertTrue((self.protected / "publish-state" / "semantic_jobs.sqlite3").is_file())
        self.assertFalse((releases[0] / "semantic_jobs.sqlite3").exists())
        self.assertNotIn("checkpoint_id", serialized_manifest)
        self.assertNotIn("checkpoint_manifest_sha256", serialized_manifest)

    def test_missing_inherited_private_presentation_manifest_fails_before_publish(self) -> None:
        presentation_manifest = (
            self.runtime_base
            / "runtime_contract"
            / "code"
            / "src"
            / "quant_hub"
            / "presentation"
            / "archive_presentation.json"
        )
        presentation_manifest.unlink()
        seal_path = self.runtime_base / "release_manifest.json"
        seal_path.unlink()
        base_manifest = {
            "schema_version": "qrh-release-manifest/v1",
            "release_id": "v39-like-base-without-presentation",
            "built_at": "2026-08-21T00:00:00Z",
            "application": {
                "source_kind": "legacy_broadcast",
                "commit_sha": "0" * 40,
                "tracked_tree_sha256": "1" * 64,
                "build_tool_version": "v39-like-fixture/v1",
                "source_archive_sha256": "2" * 64,
                "legacy_deployment_id": "v39-like-fixture",
            },
            "content": {
                "snapshot_id": "v39-like-snapshot",
                "source_inventory_sha256": "3" * 64,
                "ir_sha256": "4" * 64,
                "knowledge_sha256": "5" * 64,
                "search_sha256": "6" * 64,
                "knowledge_enrichment": {"status": "not_applicable"},
            },
            "resources": {},
            "state": {"compatibility": {"comments": {"read": [1], "write": [1]}}},
        }
        resealed = seal_release(
            candidate_root=self.runtime_base,
            manifest_without_inventory=base_manifest,
        )
        self.config_value["runtime_base_manifest_sha256"] = resealed.manifest_sha256
        deps, *_ = self.dependencies()
        freezer = ProductionSourceFreezer(
            self.config(), process_runner=deps.process_runner
        )
        with self.assertRaisesRegex(PublishRuntimeError, "presentation_manifest"):
            freezer(
                GitSnapshot(
                    commit_sha=self.commit,
                    branch="main",
                    tracked_tree_sha256="7" * 64,
                    tracked_clean=True,
                )
            )

    def test_semantic_only_change_creates_a_new_release_identity(self) -> None:
        first_deps, *_ = self.dependencies()
        first = ProductionPublishRuntime(self.config(), dependencies=first_deps).publish(
            commit_sha=self.commit, candidate_only=True
        )
        self.assertEqual("succeeded", first["status"])
        candidates = self.protected / "candidates"
        first_release = next(candidates.glob("release-*"))
        first_manifest = json.loads(
            (first_release / "release_manifest.json").read_text(encoding="utf-8")
        )
        def deprecate_promoted_input(store, snapshot):
            items = store.items_for_versions(tuple(snapshot.active_membership.values()))
            self.assertEqual(1, len(items))
            deprecate_item(
                store,
                items[0],
                actor="release-identity-fixture",
                reason="prove semantic-only release identity change",
            )

        second_state = self.protected / "publish-state-semantic-2"
        second_candidates = self.protected / "candidates-semantic-2"
        self._seed_semantic_state(second_state, mutator=deprecate_promoted_input)
        self.config_value["state_root"] = str(second_state)
        self.config_value["candidate_root"] = str(second_candidates)

        second_deps, *_ = self.dependencies()
        second = ProductionPublishRuntime(self.config(), dependencies=second_deps).publish(
            commit_sha=self.commit, candidate_only=True
        )
        self.assertEqual("succeeded", second["status"])
        second_release = next(second_candidates.glob("release-*"))
        manifests = [
            first_manifest,
            json.loads((second_release / "release_manifest.json").read_text(encoding="utf-8")),
        ]
        self.assertEqual(
            {self.commit},
            {manifest["application"]["commit_sha"] for manifest in manifests},
        )
        self.assertEqual(2, len({manifest["release_id"] for manifest in manifests}))
        self.assertEqual(2, len({manifest["content"]["snapshot_id"] for manifest in manifests}))
        self.assertNotEqual(
            first_manifest["content"]["knowledge_sha256"],
            next(
                manifest["content"]["knowledge_sha256"]
                for manifest in manifests
                if manifest["release_id"] != first_manifest["release_id"]
            ),
        )

    def test_cross_process_retry_reuses_exact_immutable_candidate(self) -> None:
        first_deps, *_ = self.dependencies()
        first_runtime = ProductionPublishRuntime(self.config(), dependencies=first_deps)
        first = first_runtime.publish(commit_sha=self.commit, candidate_only=True)
        first_material = next(iter(first_runtime.freezer.materials.values()))
        first_manifest_bytes = (
            first_material.source_root / "release_manifest.json"
        ).read_bytes()

        # A fresh runtime/freezer models retry after a downstream CI or
        # transport failure. It must reuse R rather than reseal or overwrite it.
        second_deps, *_ = self.dependencies()
        second_runtime = ProductionPublishRuntime(self.config(), dependencies=second_deps)
        second = second_runtime.publish(commit_sha=self.commit, candidate_only=True)
        second_material = next(iter(second_runtime.freezer.materials.values()))
        self.assertEqual("succeeded", first["status"])
        self.assertEqual("succeeded", second["status"])
        self.assertEqual(first_material.release_id, second_material.release_id)
        self.assertEqual(
            first_material.release_manifest_sha256,
            second_material.release_manifest_sha256,
        )
        self.assertEqual(first_material.source_root, second_material.source_root)
        self.assertEqual(
            first_manifest_bytes,
            (second_material.source_root / "release_manifest.json").read_bytes(),
        )
        self.assertEqual(1, len(list((self.protected / "candidates").glob("release-*"))))

    def test_cross_process_retry_rejects_same_identity_candidate_tamper(self) -> None:
        first_deps, *_ = self.dependencies()
        first_runtime = ProductionPublishRuntime(self.config(), dependencies=first_deps)
        first_runtime.publish(commit_sha=self.commit, candidate_only=True)
        first_material = next(iter(first_runtime.freezer.materials.values()))
        (first_material.source_root / "runtime" / "static" / "app.css").write_bytes(
            b"tampered-after-seal"
        )

        second_deps, *_ = self.dependencies()
        second_runtime = ProductionPublishRuntime(self.config(), dependencies=second_deps)
        with self.assertRaises(Exception):
            second_runtime.publish(commit_sha=self.commit, candidate_only=True)
        self.assertEqual({}, second_runtime.freezer.materials)

    def test_default_activate_passes_local_deployment_attempt(self) -> None:
        deps, _backend, invoker, _calls = self.dependencies()
        result = ProductionPublishRuntime(self.config(), dependencies=deps).publish(
            commit_sha=self.commit
        )
        self.assertEqual("activated", result["result"]["status"])
        attempt = invoker.calls[0]["deployment_attempt_id"]
        self.assertRegex(attempt, r"^deploy-[0-9a-f]{64}$")

    def test_fresh_activate_retry_reuses_vm_deployment_attempt(self) -> None:
        first_deps, *_first = self.dependencies()
        first_runtime = ProductionPublishRuntime(
            self.config(), dependencies=first_deps
        )
        first_runtime.publish(commit_sha=self.commit)
        first_invoker = first_deps.deployment_invoker

        second_deps, *_second = self.dependencies()
        second_runtime = ProductionPublishRuntime(
            self.config(), dependencies=second_deps
        )
        second_runtime.publish(commit_sha=self.commit)
        second_invoker = second_deps.deployment_invoker

        self.assertEqual(
            first_invoker.calls[0]["deployment_attempt_id"],
            second_invoker.calls[0]["deployment_attempt_id"],
        )

    def test_missing_protected_github_secret_fails_before_push(self) -> None:
        deps, _backend, _invoker, calls = self.dependencies()
        deps = RuntimeDependencies(
            process_runner=deps.process_runner,
            secret_provider=EnvironmentSecretProvider({}),
            http_get=deps.http_get,
            vm_backend=deps.vm_backend,
            deployment_invoker=deps.deployment_invoker,
        )
        runtime = ProductionPublishRuntime(self.config(), dependencies=deps)
        with self.assertRaisesRegex(PublishRuntimeError, "credential"):
            runtime.publish(commit_sha=self.commit, candidate_only=True)
        self.assertFalse(any(call[:2] == ("git", "push") for call in calls))

    def test_protected_config_must_be_outside_project_and_contains_no_secret(self) -> None:
        external = self.protected / "publish.json"
        external.write_text(canonical_json(self.config_value), encoding="utf-8")
        loaded = RuntimePublishConfig.load(external, expected_project_root=self.project)
        self.assertEqual(self.project, loaded.project_root)
        self.assertNotIn("token", canonical_json(self.config_value).casefold())
        inside = self.project / "publish.json"
        inside.write_text(canonical_json(self.config_value), encoding="utf-8")
        with self.assertRaisesRegex(PublishRuntimeError, "outside"):
            RuntimePublishConfig.load(inside, expected_project_root=self.project)

    def test_presentation_manifest_authority_is_bound_to_loader_path(self) -> None:
        self.config_value["required_runtime_paths"]["presentation_manifest"] = (
            "runtime_contract/code/src/quant_hub/presentation/"
            "citation_projection_overrides.json"
        )
        with self.assertRaisesRegex(
            PublishRuntimeError, "presentation manifest authority"
        ):
            self.config()

    def test_tracked_code_cannot_override_inherited_private_authority(self) -> None:
        tracked_private = (
            self.project
            / "quant_hub"
            / "src"
            / "quant_hub"
            / "presentation"
            / "archive_presentation.json"
        )
        tracked_private.parent.mkdir(parents=True)
        tracked_private.write_bytes(b"tracked-private-conflict")
        subprocess.run(
            ["git", "add", tracked_private.relative_to(self.project).as_posix()],
            cwd=self.project,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "tracked private conflict"],
            cwd=self.project,
            check=True,
            capture_output=True,
        )
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.project,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stdout.strip()
        deps, *_ = self.dependencies()
        freezer = ProductionSourceFreezer(
            self.config(), process_runner=deps.process_runner
        )
        with self.assertRaisesRegex(PublishRuntimeError, "tracked code conflicts"):
            freezer(
                GitSnapshot(
                    commit_sha=self.commit,
                    branch="main",
                    tracked_tree_sha256="8" * 64,
                    tracked_clean=True,
                )
            )

    def test_prior_release_reuses_historical_source_objects_after_revision(self) -> None:
        first_deps, *_ = self.dependencies()
        first_runtime = ProductionPublishRuntime(self.config(), dependencies=first_deps)
        first_runtime.publish(commit_sha=self.commit, candidate_only=True)
        first_release = next(iter(first_runtime.freezer.materials.values()))
        old_source_hash = hashlib.sha256(
            (self.reference / "research.md").read_bytes()
        ).hexdigest()

        (self.reference / "research.md").write_text(
            "# Factor\n\nEvidence revised with limitation.\n", encoding="utf-8"
        )
        (self.project / "quant_hub" / "service.py").write_text(
            "print('updated code')\n", encoding="utf-8"
        )
        subprocess.run(["git", "add", "quant_hub/service.py"], cwd=self.project, check=True)
        subprocess.run(["git", "commit", "-m", "revision"], cwd=self.project, check=True, capture_output=True)
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=self.project, check=True,
            capture_output=True, text=True, encoding="utf-8",
        ).stdout.strip()
        self.config_value["runtime_base"] = str(first_release.source_root)
        self.config_value["runtime_base_manifest_sha256"] = first_release.release_manifest_sha256
        self.config_value["state_root"] = str(self.protected / "publish-state-revision")
        self.config_value["candidate_root"] = str(self.protected / "candidates-revision")
        self._seed_semantic_state(self.protected / "publish-state-revision")
        second_deps, *_ = self.dependencies()
        second_runtime = ProductionPublishRuntime(self.config(), dependencies=second_deps)
        second_runtime.publish(commit_sha=self.commit, candidate_only=True)
        second_release = next(iter(second_runtime.freezer.materials.values()))
        objects = second_release.source_root / "content" / "source_objects" / "sha256"
        self.assertTrue((objects / old_source_hash).is_file())
        new_source_hash = hashlib.sha256(
            (self.reference / "research.md").read_bytes()
        ).hexdigest()
        self.assertTrue((objects / new_source_hash).is_file())
        snapshot = deserialize_snapshot(
            (second_release.source_root / "content" / "deterministic_snapshot.json").read_bytes()
        )
        document = next(iter(snapshot.documents.values()))
        self.assertEqual(2, len(document.version_ids))



if __name__ == "__main__":
    unittest.main()
