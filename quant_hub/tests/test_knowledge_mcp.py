from __future__ import annotations

from contextlib import redirect_stdout
import base64
import copy
import hashlib
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge.contracts import canonical_json
from quant_hub.knowledge.semantic import (
    EnrichedSnapshot,
    EvidenceBinding,
    KnowledgeGeneration,
    KnowledgeItem,
)
from quant_hub.knowledge.retrieval import ArtifactKnowledgeIndex, TaskContext
from quant_hub.knowledge_mcp.cli import main as mcp_cli
from quant_hub.knowledge_mcp.evaluation import (
    ToolChoiceCase,
    ToolTraceEvent,
    evaluate_tool_choice,
)
from quant_hub.knowledge_mcp.install import (
    AGENT_ROUTING_RULES,
    ClientConfig,
    install_profile,
    uninstall_profile,
)
from quant_hub.knowledge_mcp.mirror import (
    AuthorityUnavailable,
    AuthorityIdentity,
    FileAuthorityProbe,
    MirrorError,
    MirrorStore,
    OpenSSHAuthoritySource,
    SubprocessCommandRunner,
    build_search_artifact,
    validate_search_artifact,
)
from quant_hub.knowledge_mcp.server import (
    SERVER_INSTRUCTIONS,
    TOOLS,
    StdioMCPServer,
)
from quant_hub.knowledge_mcp.service import KnowledgeMCPService
from quant_hub.ops.release_identity import manifest_sha256


H = {name: str(index) * 64 for index, name in enumerate(("tree", "source", "ir", "knowledge", "resources"), 1)}


def _release(release_id: str, snapshot_id: str, artifact: bytes) -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": release_id,
        "built_at": "2026-08-21T08:00:00+08:00",
        "application": {
            "commit_sha": "a" * 40,
            "tracked_tree_sha256": H["tree"],
            "build_tool_version": "mcp-tests/v1",
        },
        "content": {
            "snapshot_id": snapshot_id,
            "source_inventory_sha256": H["source"],
            "ir_sha256": H["ir"],
            "knowledge_sha256": H["knowledge"],
            "search_sha256": hashlib.sha256(artifact).hexdigest(),
            "knowledge_enrichment": {"status": "pending"},
        },
        "resources": {"inventory_sha256": H["resources"]},
        "state": {
            "compatibility": {
                "comments": {"read": [1], "write": [1]},
                "workspace": {"read": [1], "write": [1]},
            }
        },
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
    }


class MCPFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.reference = root / "intake"
        self.reference.mkdir()
        self.source = self.reference / "factor.md"
        self.source.write_text(
            "# Leakage Controls\n\n"
            + "\n\n".join(
                f"## Check {index}\n\nUse leakage embargo and temporal split number {index}."
                for index in range(8)
            )
            + "\n",
            encoding="utf-8",
        )
        first = ReferenceCompiler(max_chunk_bytes=150).compile(self.reference)
        assert first.candidate_snapshot is not None
        self.snapshot1 = first.candidate_snapshot
        self.artifact1 = build_search_artifact(self.snapshot1)
        self.release1 = _release("release-r1", self.snapshot1.snapshot_id, self.artifact1)

        self.source.write_text(
            self.source.read_text(encoding="utf-8")
            + "\n## Revision\n\nUse purged folds and record the embargo horizon.\n",
            encoding="utf-8",
        )
        second = ReferenceCompiler(max_chunk_bytes=150).compile(
            self.reference, previous=self.snapshot1
        )
        assert second.candidate_snapshot is not None
        self.snapshot2 = second.candidate_snapshot
        self.artifact2 = build_search_artifact(self.snapshot2)
        self.release2 = _release("release-r2", self.snapshot2.snapshot_id, self.artifact2)

        self.authority = root / "authority"
        self.releases = self.authority / "releases"
        self.control = self.authority / "control"
        self.releases.mkdir(parents=True)
        self.control.mkdir()
        self._write_release(self.release1, self.artifact1)
        self._write_release(self.release2, self.artifact2)
        self.activate(self.release1)
        self.mirror = root / "user-data" / "mirror"

    def _write_release(self, release: dict[str, object], artifact: bytes) -> None:
        target = self.releases / str(release["release_id"])
        (target / "content").mkdir(parents=True)
        (target / "release_manifest.json").write_text(
            canonical_json(release), encoding="utf-8", newline=""
        )
        (target / "content" / "mcp_search.json").write_bytes(artifact)

    def activate(self, release: dict[str, object]) -> None:
        active = {
            "schema_version": "qrh-active-release/v1",
            "release_id": release["release_id"],
            "release_path": f"D:\\quant\\quant_platform\\releases\\{release['release_id']}",
            "manifest_sha256": manifest_sha256(release),
        }
        (self.control / "active_release.json").write_text(
            canonical_json(active), encoding="utf-8", newline=""
        )

    def service(self) -> KnowledgeMCPService:
        return KnowledgeMCPService(
            store=MirrorStore(self.mirror),
            authority=FileAuthorityProbe(
                self.control / "active_release.json", self.releases
            ),
            artifact_release_root=self.releases,
        )


class KnowledgeMCPServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = MCPFixture(Path(temporary.name))

    def test_fresh_search_get_and_fail_closed_stale_mode(self) -> None:
        service = self.fixture.service()
        result = service.search_quant_knowledge(query="leakage embargo", limit=2)
        expected = AuthorityIdentity(
            "release-r1",
            manifest_sha256(self.fixture.release1),
            self.fixture.snapshot1.snapshot_id,
        )
        self.assertEqual("fresh", result["availability"])
        self.assertEqual(expected.to_dict(), result["identity"])
        self.assertEqual(expected.to_dict(), result["observed_identity"])
        self.assertIsNotNone(result["authority_verified_at"])
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["results"])
        self.assertTrue(result["continuation"])
        object_id = result["results"][0]["object_id"]

        expanded = service.get_quant_knowledge(object_id=object_id)
        self.assertEqual(expected.to_dict(), expanded["identity"])
        self.assertEqual("source_explicit", result["results"][0]["fact_status"])
        self.assertEqual(
            self.fixture.snapshot1.snapshot_id,
            expanded["identity"]["snapshot_id"],
        )

        (self.fixture.control / "active_release.json").rename(
            self.fixture.control / "active_release.offline"
        )
        unavailable = service.search_quant_knowledge(query="leakage")
        self.assertEqual("unavailable", unavailable["availability"])
        self.assertEqual([], unavailable["results"])
        self.assertIsNone(unavailable["identity"])
        self.assertIsNotNone(unavailable["last_authority_verified_at"])
        stale = service.search_quant_knowledge(query="leakage", allow_stale=True)
        self.assertEqual("stale", stale["availability"])
        self.assertEqual(expected.to_dict(), stale["identity"])
        self.assertIsNone(stale["observed_identity"])

    def test_mcp_product_search_is_the_shared_artifact_ranking_contract(self) -> None:
        artifact = json.loads(self.fixture.artifact1)
        with ArtifactKnowledgeIndex(artifact) as index:
            expected = index.search(
                "leakage embargo",
                context=TaskContext.create(objective="leakage control"),
                limit=len(index.records),
            )
        actual = self.fixture.service().search_quant_knowledge(
            query="leakage embargo",
            task_context={"objective": "leakage control"},
            limit=20,
            budget_chars=50_000,
        )
        self.assertEqual("ok", actual["status"])
        self.assertEqual(expected.index_version, actual["index_version"])
        self.assertEqual(expected.total_candidates, actual["total_candidates"])
        self.assertEqual(
            [card.evidence_id for card in expected.cards],
            [row["object_id"] for row in actual["results"]],
        )
        self.assertEqual(
            [card.score for card in expected.cards],
            [row["score"] for row in actual["results"]],
        )
        self.assertEqual(
            [list(card.hit_reasons) for card in expected.cards],
            [row["match_reasons"] for row in actual["results"]],
        )

    def test_activation_and_rollback_invalidate_then_require_updates_search_get(self) -> None:
        service = self.fixture.service()
        # Use two independent anchors so the pagination fixture exercises more
        # than one grounded result under the production no-answer threshold.
        first = service.search_quant_knowledge(query="leakage embargo", limit=1)
        continuation = first["continuation"]
        self.assertTrue(continuation)

        self.fixture.activate(self.fixture.release2)
        changed = service.search_quant_knowledge(query="leakage")
        self.assertEqual("snapshot_refresh_required", changed["status"])
        self.assertEqual("release-r2", changed["changed_to"]["release_id"])

        updates = service.list_knowledge_updates(
            from_snapshot_id=self.fixture.snapshot1.snapshot_id
        )
        self.assertEqual("ok", updates["status"])
        self.assertEqual(self.fixture.snapshot2.snapshot_id, updates["to_snapshot_id"])
        self.assertTrue(updates["updates"])
        invalid = service.search_quant_knowledge(
            query="leakage embargo", limit=1, cursor=continuation
        )
        self.assertEqual("continuation_invalid", invalid["status"])
        second = service.search_quant_knowledge(query="purged folds")
        self.assertEqual("release-r2", second["identity"]["release_id"])
        expanded = service.get_quant_knowledge(
            object_id=second["results"][0]["object_id"]
        )
        self.assertEqual(self.fixture.snapshot2.snapshot_id, expanded["identity"]["snapshot_id"])

        self.fixture.activate(self.fixture.release1)
        rollback = service.search_quant_knowledge(query="leakage")
        self.assertEqual("snapshot_refresh_required", rollback["status"])
        update_back = service.list_knowledge_updates(
            from_snapshot_id=self.fixture.snapshot2.snapshot_id
        )
        self.assertEqual(self.fixture.snapshot1.snapshot_id, update_back["to_snapshot_id"])
        after = service.search_quant_knowledge(query="leakage")
        self.assertEqual("release-r1", after["identity"]["release_id"])

    def test_forged_authority_and_corrupt_mirror_never_return_fresh(self) -> None:
        service = self.fixture.service()
        fresh = service.search_quant_knowledge(query="leakage")
        self.assertEqual("fresh", fresh["availability"])
        active_path = self.fixture.control / "active_release.json"
        active = json.loads(active_path.read_text(encoding="utf-8"))
        active["manifest_sha256"] = "f" * 64
        active_path.write_text(canonical_json(active), encoding="utf-8", newline="")
        forged = service.search_quant_knowledge(query="leakage")
        self.assertEqual("unavailable", forged["availability"])

        self.fixture.activate(self.fixture.release1)
        mirrored = self.fixture.mirror / "releases" / manifest_sha256(self.fixture.release1)
        (mirrored / "content" / "mcp_search.json").write_text("{}", encoding="utf-8")
        corrupted = service.search_quant_knowledge(query="leakage")
        self.assertEqual("unavailable", corrupted["availability"])
        with self.assertRaises(MirrorError):
            MirrorStore(self.fixture.mirror).current()

    def test_missing_old_mirror_does_not_deadlock_required_update_handshake(self) -> None:
        service = self.fixture.service()
        first = service.search_quant_knowledge(query="leakage")
        old_root = (
            self.fixture.mirror
            / "releases"
            / first["identity"]["manifest_sha256"]
        )
        old_root.rename(old_root.with_name("retained-outside-scan"))
        self.fixture.activate(self.fixture.release2)
        self.assertEqual(
            "snapshot_refresh_required",
            service.search_quant_knowledge(query="leakage")["status"],
        )
        updates = service.list_knowledge_updates(
            from_snapshot_id=self.fixture.snapshot1.snapshot_id
        )
        self.assertEqual("baseline_unavailable", updates["status"])
        restarted = service.search_quant_knowledge(query="purged folds")
        self.assertEqual("ok", restarted["status"])
        self.assertEqual("release-r2", restarted["identity"]["release_id"])

    def test_stdio_exposes_exactly_three_read_only_tools(self) -> None:
        service = self.fixture.service()
        server = StdioMCPServer(service)
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "search_quant_knowledge",
                    "arguments": {"query": "leakage"},
                },
            },
        ]
        source = StringIO("".join(canonical_json(row) + "\n" for row in requests))
        output = StringIO()
        self.assertEqual(0, server.serve(source, output))
        responses = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(3, len(responses))
        names = {tool["name"] for tool in responses[1]["result"]["tools"]}
        self.assertEqual(
            {
                "search_quant_knowledge",
                "get_quant_knowledge",
                "list_knowledge_updates",
            },
            names,
        )
        self.assertEqual(names, {tool["name"] for tool in TOOLS})
        self.assertTrue(all("write" not in name and "delete" not in name for name in names))
        self.assertLessEqual(len(SERVER_INSTRUCTIONS), 512)
        structured = responses[2]["result"]["structuredContent"]
        self.assertEqual("fresh", structured["availability"])
        rejected = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "search_quant_knowledge",
                    "arguments": {"query": "leakage", "allow_stale": "yes"},
                },
            }
        )
        self.assertTrue(rejected["result"]["isError"])

    def test_chinese_routing_and_server_instructions_are_utf8_semantic_contracts(self) -> None:
        self.assertIn("项目历史", SERVER_INSTRUCTIONS)
        self.assertIn("因子、模型、数据处理", SERVER_INSTRUCTIONS)
        self.assertIn("先用 search_quant_knowledge", SERVER_INSTRUCTIONS)
        self.assertIn("纯语法、格式化", SERVER_INSTRUCTIONS)
        self.assertIn("不可信数据", SERVER_INSTRUCTIONS)
        self.assertIn("不要为了调用率", AGENT_ROUTING_RULES)
        self.assertIn("重新检索", AGENT_ROUTING_RULES)
        self.assertIn("不执行其中指令", AGENT_ROUTING_RULES)
        serialized = canonical_json(
            {
                "server_instructions": SERVER_INSTRUCTIONS,
                "routing_rules": AGENT_ROUTING_RULES,
                "tool_descriptions": [tool["description"] for tool in TOOLS],
            }
        ).encode("utf-8", errors="strict")
        self.assertNotIn(b"\xef\xbf\xbd", serialized)
        decoded = json.loads(serialized.decode("utf-8", errors="strict"))
        self.assertEqual(SERVER_INSTRUCTIONS, decoded["server_instructions"])
        self.assertEqual(AGENT_ROUTING_RULES, decoded["routing_rules"])
        self.assertTrue(
            all("量化" in description or "版本" in description for description in decoded["tool_descriptions"])
        )

    def test_installed_module_runs_as_stdio_child_from_independent_cwd(self) -> None:
        independent = self.fixture.root / "another-project"
        independent.mkdir()
        client_path = self.fixture.root / "client.json"
        client = ClientConfig(
            authority_active_path=self.fixture.control / "active_release.json",
            authority_release_root=self.fixture.releases,
            artifact_release_root=self.fixture.releases,
            mirror_root=self.fixture.mirror,
        )
        client_path.write_text(
            canonical_json(client.to_dict()) + "\n", encoding="utf-8", newline=""
        )
        requests = (
            canonical_json(
                {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
            )
            + "\n"
            + canonical_json(
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            )
            + "\n"
        )
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "quant_hub.knowledge_mcp.cli",
                "serve-stdio",
                "--client-config",
                str(client_path),
            ],
            cwd=independent,
            input=requests,
            text=True,
            encoding="utf-8",
            capture_output=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stderr)
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual([1, 2], [row["id"] for row in responses])
        self.assertEqual(3, len(responses[1]["result"]["tools"]))

    def test_artifact_only_accepts_current_verified_knowledge_with_revision_identity(self) -> None:
        base = self.fixture.snapshot2
        version_id = next(iter(base.active_membership.values()))
        version = base.versions[version_id]
        span = base.ir_documents[version_id].blocks[0].source_span
        quote = "Leakage Controls"
        quote_start = span.byte_start + len(
            span.text[: span.text.index(quote)].encode("utf-8")
        )
        generation = KnowledgeGeneration(
            generation_id="gen-0813-fixture",
            job_key="job-fixture",
            document_version_id=version_id,
            requested_model_alias="deepseek-v4-pro",
            provider_revision="DeepSeek-V4-Pro-0813",
            model_identity_contract_hash="c" * 64,
            model_identity_evidence_url="https://example.test/model-evidence",
            model_identity_evidence_hash="d" * 64,
            model_identity_evidence_observed_at="2026-08-21T00:00:00Z",
            returned_model="deepseek-v4-pro",
            system_fingerprint="fp-0813",
            response_id="response-fixture",
            response_created_at="2026-08-21T00:01:00Z",
            response_hash="e" * 64,
            prompt_version="qrh-prompt/v1",
            output_schema_version="qrh-output/v1",
            source_sha256=version.source_sha256,
            ir_hash="f" * 64,
            status="succeeded",
            created_at="2026-08-21T00:01:00Z",
        )
        item = KnowledgeItem(
            knowledge_item_id="knowledge-method-fixture",
            cluster_id="cluster-fixture",
            document_id=version.document_id,
            document_version_id=version_id,
            kind="method",
            text="Use purged folds with an explicit embargo horizon.",
            evidence=(
                EvidenceBinding(
                    span_id=span.span_id,
                    quote=quote,
                    quote_sha256=hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                    byte_start=quote_start,
                    byte_end=quote_start + len(quote.encode("utf-8")),
                ),
            ),
            applicability={"market": ("A股",), "frequency": ("日频",)},
            relation=None,
            fact_status="machine_verified",
            extractor="deepseek-v4-pro",
            extractor_version="qrh-semantic/v1",
            generation_id=generation.generation_id,
            accepted_at="2026-08-21T00:02:00Z",
            accepted_by=None,
        )
        enriched = EnrichedSnapshot(
            schema_version="qrh-enriched-knowledge-snapshot/v1",
            base_snapshot_id=base.snapshot_id,
            snapshot_id="ksnap-fixture",
            knowledge_status_membership={version_id: "ready"},
            generation_membership={version_id: generation.generation_id},
            knowledge_items={item.knowledge_item_id: item},
            coverage_reports={},
            accepted_knowledge_hash="1" * 64,
            coverage_hash="2" * 64,
        )
        artifact = json.loads(
            build_search_artifact(
                base, enriched=enriched, generations=(generation,)
            )
        )
        self.assertEqual("ksnap-fixture", artifact["snapshot_id"])
        self.assertEqual(
            {
                "base_snapshot_id": base.snapshot_id,
                "snapshot_id": "ksnap-fixture",
                "knowledge_status_membership": {version_id: "ready"},
                "generation_membership": {version_id: generation.generation_id},
                "accepted_knowledge_hash": "1" * 64,
                "coverage_hash": "2" * 64,
            },
            artifact["knowledge_identity"],
        )
        exported = artifact["knowledge"][0]
        self.assertEqual("DeepSeek-V4-Pro-0813", exported["generation"]["provider_revision"])
        self.assertEqual("fp-0813", exported["generation"]["system_fingerprint"])
        self.assertEqual(span.span_id, exported["source_locator"]["span_id"])
        validate_search_artifact(artifact, expected_snapshot_id="ksnap-fixture")

        def reject_tamper(mutator) -> None:
            tampered = copy.deepcopy(artifact)
            mutator(tampered)
            with self.assertRaises(MirrorError):
                validate_search_artifact(
                    tampered, expected_snapshot_id="ksnap-fixture"
                )

        chunk_record = next(
            row for row in artifact["retrieval"]["records"] if row["source_kind"] == "chunk"
        )
        chunk_record_id = chunk_record["record_id"]
        knowledge_record_id = item.knowledge_item_id

        def retrieval_record(value, record_id):
            return next(
                row
                for row in value["retrieval"]["records"]
                if row["record_id"] == record_id
            )

        reject_tamper(
            lambda value: retrieval_record(value, chunk_record_id).__setitem__(
                "text", "drifted chunk text"
            )
        )
        reject_tamper(
            lambda value: retrieval_record(value, chunk_record_id)["locator"].__setitem__(
                "byte_end",
                retrieval_record(value, chunk_record_id)["locator"]["byte_end"] - 1,
            )
        )
        reject_tamper(
            lambda value: retrieval_record(value, chunk_record_id).__setitem__(
                "document_version_id", "ver_drifted"
            )
        )
        reject_tamper(
            lambda value: retrieval_record(value, chunk_record_id).__setitem__(
                "active_status", "superseded"
            )
        )
        reject_tamper(
            lambda value: retrieval_record(value, knowledge_record_id).__setitem__(
                "fact_status", "human_reviewed"
            )
        )
        reject_tamper(
            lambda value: value["knowledge"][0]["generation"].__setitem__(
                "returned_model", "drifted-provider-alias"
            )
        )
        reject_tamper(
            lambda value: retrieval_record(value, knowledge_record_id)[
                "applicability"
            ].__setitem__("market", ["drifted-market"])
        )
        with self.assertRaisesRegex(MirrorError, "successful generation"):
            build_search_artifact(base, enriched=enriched)

    def test_pending_source_explicit_artifact_is_closed_and_searchable(self) -> None:
        base = self.fixture.snapshot2
        version_id = next(iter(base.active_membership.values()))
        version = base.versions[version_id]
        span = base.ir_documents[version_id].blocks[0].source_span
        quote = span.text.splitlines()[0]
        byte_start = span.byte_start
        item = KnowledgeItem(
            knowledge_item_id="knowledge-source-explicit-pending",
            cluster_id="cluster-source-explicit-pending",
            document_id=version.document_id,
            document_version_id=version_id,
            kind="method",
            text=quote,
            evidence=(
                EvidenceBinding(
                    span_id=span.span_id,
                    quote=quote,
                    quote_sha256=hashlib.sha256(quote.encode("utf-8")).hexdigest(),
                    byte_start=byte_start,
                    byte_end=byte_start + len(quote.encode("utf-8")),
                ),
            ),
            applicability={},
            relation=None,
            fact_status="source_explicit",
            extractor="deterministic-ir",
            extractor_version="qrh-ir/v1",
            generation_id=None,
            accepted_at="2026-08-21T00:02:00Z",
            accepted_by=None,
        )
        enriched = EnrichedSnapshot(
            schema_version="qrh-enriched-knowledge-snapshot/v1",
            base_snapshot_id=base.snapshot_id,
            snapshot_id="ksnap-source-explicit-pending",
            knowledge_status_membership={version_id: "pending"},
            generation_membership={},
            knowledge_items={item.knowledge_item_id: item},
            coverage_reports={},
            accepted_knowledge_hash="3" * 64,
            coverage_hash="4" * 64,
        )
        artifact = json.loads(build_search_artifact(base, enriched=enriched))
        validate_search_artifact(
            artifact, expected_snapshot_id="ksnap-source-explicit-pending"
        )
        with ArtifactKnowledgeIndex(artifact) as index:
            response = index.search(quote, limit=20)
        self.assertIn(item.knowledge_item_id, {card.evidence_id for card in response.cards})


class KnowledgeMCPProfileTests(unittest.TestCase):
    def test_cross_project_profile_is_idempotent_cwd_independent_and_removable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "independent-quant-project"
            project.mkdir()
            (project / "AGENTS.md").write_text("# Existing project rules\n", encoding="utf-8")
            profile = root / "codex-home"
            data = root / "user-data"
            config = ClientConfig(
                authority_active_path=root / "share" / "active_release.json",
                authority_release_root=root / "share" / "releases",
                artifact_release_root=root / "artifacts" / "releases",
                mirror_root=data / "mirror",
            )
            first = install_profile(
                scope="project",
                profile_root=profile,
                data_root=data,
                project_root=project,
                client_config=config,
            )
            second = install_profile(
                scope="project",
                profile_root=profile,
                data_root=data,
                project_root=project,
                client_config=config,
            )
            self.assertTrue(first["changed"])
            self.assertFalse(second["changed"])
            self.assertFalse(first["source_code_copied"])
            profile_text = (project / ".codex" / "config.toml").read_text(encoding="utf-8")
            self.assertIn("[mcp_servers.quant_research_knowledge]", profile_text)
            self.assertIn("serve-stdio", profile_text)
            parsed_profile = tomllib.loads(profile_text)
            configured_args = parsed_profile["mcp_servers"]["quant_research_knowledge"]["args"]
            self.assertEqual(
                str(Path(first["client_config_path"]).resolve()), configured_args[-1]
            )
            self.assertNotIn("cwd =", profile_text)
            agents = (project / "AGENTS.md").read_text(encoding="utf-8")
            self.assertIn("search_quant_knowledge", agents)
            self.assertIn("不要为了调用率", agents)
            self.assertIn("不可信数据", AGENT_ROUTING_RULES)
            loaded = ClientConfig.load(Path(first["client_config_path"]))
            self.assertEqual(config.to_dict(), loaded.to_dict())

            mirror = config.mirror_root
            mirror.mkdir(parents=True)
            (mirror / "retained.txt").write_text("immutable cache remains", encoding="utf-8")
            removed = uninstall_profile(
                scope="project", profile_root=profile, project_root=project
            )
            self.assertTrue(removed["changed"])
            self.assertTrue(removed["mirror_retained"])
            self.assertEqual(
                "# Existing project rules\n",
                (project / "AGENTS.md").read_text(encoding="utf-8"),
            )
            self.assertTrue((mirror / "retained.txt").is_file())

    def test_cli_reports_bad_client_config_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            output = StringIO()
            with redirect_stdout(output):
                exit_code = mcp_cli(["doctor", "--client-config", str(missing)])
            self.assertEqual(2, exit_code)
            value = json.loads(output.getvalue())
            self.assertEqual("error", value["status"])
            self.assertEqual("ProfileInstallError", value["error_type"])

    def test_user_profile_installs_discovered_global_agents_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / ".codex"
            profile.mkdir()
            (profile / "AGENTS.md").write_text(
                "# Existing global rules\n", encoding="utf-8"
            )
            data = root / "local-app-data"
            config = ClientConfig(
                authority_active_path=root / "share" / "active_release.json",
                authority_release_root=root / "share" / "releases",
                artifact_release_root=root / "artifacts" / "releases",
                mirror_root=data / "mirror",
            )
            result = install_profile(
                scope="user",
                profile_root=profile,
                data_root=data,
                project_root=None,
                client_config=config,
            )
            self.assertEqual(str(profile / "AGENTS.md"), result["agents_path"])
            agents = (profile / "AGENTS.md").read_text(encoding="utf-8")
            self.assertIn("# Existing global rules", agents)
            self.assertIn("search_quant_knowledge", agents)
            uninstall_profile(
                scope="user", profile_root=profile, project_root=None
            )
            self.assertEqual(
                "# Existing global rules\n",
                (profile / "AGENTS.md").read_text(encoding="utf-8"),
            )

    def test_doctor_synchronizes_and_verifies_exact_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = MCPFixture(Path(directory))
            client = ClientConfig(
                authority_active_path=fixture.control / "active_release.json",
                authority_release_root=fixture.releases,
                artifact_release_root=fixture.releases,
                mirror_root=fixture.mirror,
            )
            client_path = fixture.root / "client.json"
            client_path.write_text(
                canonical_json(client.to_dict()) + "\n", encoding="utf-8", newline=""
            )
            output = StringIO()
            with redirect_stdout(output):
                exit_code = mcp_cli(
                    ["doctor", "--client-config", str(client_path)]
                )
            self.assertEqual(0, exit_code)
            value = json.loads(output.getvalue())
            self.assertEqual("fresh", value["status"])
            self.assertEqual(value["authority_identity"], value["local_identity"])
            self.assertEqual("release-r1", value["local_identity"]["release_id"])


class FakeOpenSSHRunner:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files
        self.calls: list[tuple[str, ...]] = []
        self.fail = False

    def run(self, argv, *, timeout_seconds: float) -> bytes:
        call = tuple(argv)
        self.calls.append(call)
        if self.fail:
            raise AuthorityUnavailable("simulated network failure")
        if call[:6] != ("ssh", "-T", "-o", "BatchMode=yes", "--", "honghu-vm"):
            raise AssertionError(f"unexpected OpenSSH boundary: {call[:6]!r}")
        if call[6:11] != (
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
        ):
            raise AssertionError("remote command contract changed")
        script = base64.b64decode(call[11]).decode("utf-16-le")
        self._assert_read_only(script)
        marker = "[IO.File]::ReadAllBytes('"
        start = script.index(marker) + len(marker)
        path = script[start : script.index("')", start)]
        if path not in self.files:
            raise AuthorityUnavailable("simulated missing remote file")
        return base64.b64encode(self.files[path])

    @staticmethod
    def _assert_read_only(script: str) -> None:
        lowered = script.casefold()
        assert "readallbytes" in lowered
        for forbidden in (
            "writeallbytes",
            "set-content",
            "new-item",
            "remove-item",
            "move-item",
        ):
            assert forbidden not in lowered


class OpenSSHAuthorityTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.fixture = MCPFixture(Path(temporary.name))
        self.files: dict[str, bytes] = {}
        self._publish_remote(self.fixture.release1, self.fixture.artifact1)
        self.runner = FakeOpenSSHRunner(self.files)
        self.source = OpenSSHAuthoritySource("honghu-vm", runner=self.runner)

    def _publish_remote(self, release: dict[str, object], artifact: bytes) -> None:
        release_id = str(release["release_id"])
        release_root = rf"D:\quant\quant_platform\releases\{release_id}"
        active = {
            "schema_version": "qrh-active-release/v1",
            "release_id": release_id,
            "release_path": release_root,
            "manifest_sha256": manifest_sha256(release),
        }
        self.files[r"D:\quant\quant_platform\control\active_release.json"] = (
            canonical_json(active).encode("utf-8")
        )
        self.files[release_root + r"\release_manifest.json"] = canonical_json(
            release
        ).encode("utf-8")
        self.files[release_root + r"\content\mcp_search.json"] = artifact

    def test_exact_remote_identity_download_and_atomic_mirror_adoption(self) -> None:
        service = KnowledgeMCPService(
            store=MirrorStore(self.fixture.mirror),
            authority=self.source,
            artifact_release_root=self.source,
        )
        result = service.search_quant_knowledge(query="leakage", limit=1)
        self.assertEqual("fresh", result["availability"])
        expected = AuthorityIdentity(
            "release-r1",
            manifest_sha256(self.fixture.release1),
            self.fixture.snapshot1.snapshot_id,
        )
        self.assertEqual(expected.to_dict(), result["identity"])
        self.assertEqual(expected, MirrorStore(self.fixture.mirror).current().identity)
        self.assertTrue(self.runner.calls)
        self.assertTrue(
            all(call[5] == "honghu-vm" and len(call) == 12 for call in self.runner.calls)
        )

        self._publish_remote(self.fixture.release2, self.fixture.artifact2)
        changed = service.search_quant_knowledge(query="leakage")
        self.assertEqual("snapshot_refresh_required", changed["status"])
        self.assertEqual(
            self.fixture.snapshot2.snapshot_id,
            MirrorStore(self.fixture.mirror).current().identity.snapshot_id,
        )

    def test_network_and_identity_failures_are_explicit_and_never_silent(self) -> None:
        service = KnowledgeMCPService(
            store=MirrorStore(self.fixture.mirror),
            authority=self.source,
            artifact_release_root=self.source,
        )
        self.assertEqual(
            "fresh", service.search_quant_knowledge(query="embargo")["availability"]
        )
        self.runner.fail = True
        unavailable = service.search_quant_knowledge(query="embargo")
        self.assertEqual("unavailable", unavailable["availability"])
        self.assertIsNone(unavailable["identity"])
        stale = service.search_quant_knowledge(query="embargo", allow_stale=True)
        self.assertEqual("stale", stale["availability"])
        self.assertEqual("release-r1", stale["identity"]["release_id"])

        self.runner.fail = False
        active_path = r"D:\quant\quant_platform\control\active_release.json"
        active = json.loads(self.files[active_path])
        active["manifest_sha256"] = "f" * 64
        self.files[active_path] = canonical_json(active).encode("utf-8")
        with self.assertRaises(AuthorityUnavailable):
            self.source.probe()

    def test_client_config_has_no_key_material_and_supports_legacy_file_mode(self) -> None:
        config = ClientConfig(
            mirror_root=self.fixture.mirror,
            authority_mode="openssh",
            ssh_alias="honghu-vm",
        )
        serialized = config.to_dict()
        self.assertEqual(
            {"schema_version", "authority_mode", "ssh_alias", "mirror_root"},
            set(serialized),
        )
        self.assertFalse(any("key" in name.casefold() for name in serialized))
        path = self.fixture.root / "openssh-client.json"
        path.write_text(canonical_json(serialized), encoding="utf-8")
        self.assertEqual(serialized, ClientConfig.load(path).to_dict())
        with self.assertRaises(ValueError):
            OpenSSHAuthoritySource("honghu-vm; whoami", runner=self.runner)

    def test_real_shell_free_subprocess_boundary(self) -> None:
        runner = SubprocessCommandRunner(max_stdout_bytes=16)
        output = runner.run(
            (
                sys.executable,
                "-c",
                "import sys;sys.stdout.buffer.write(b'boundary-ok')",
            ),
            timeout_seconds=5,
        )
        self.assertEqual(b"boundary-ok", output)


class ToolChoiceEvaluationTests(unittest.TestCase):
    def test_positive_negative_gain_identity_and_update_sequence_gate(self) -> None:
        identity = AuthorityIdentity("release-r2", "a" * 64, "snapshot-r2")
        fresh = {"availability": "fresh", "identity": identity.to_dict()}
        quality = {
            "grounded_decision": 0.9,
            "condition_limitation_recognition": 0.85,
            "citation_correctness": 1.0,
        }
        baseline = {
            "grounded_decision": 0.5,
            "condition_limitation_recognition": 0.4,
            "citation_correctness": 0.6,
        }
        report = evaluate_tool_choice(
            (
                ToolChoiceCase(
                    case_id="implicit-backtest-leakage",
                    should_call=True,
                    required_sequence=(
                        "list_knowledge_updates",
                        "search_quant_knowledge",
                        "get_quant_knowledge",
                    ),
                    events=tuple(
                        ToolTraceEvent(name, fresh)
                        for name in (
                            "list_knowledge_updates",
                            "search_quant_knowledge",
                            "get_quant_knowledge",
                        )
                    ),
                    expected_identity=identity,
                    decision_claims_current=True,
                    assisted_quality=quality,
                    no_mcp_quality=baseline,
                ),
                ToolChoiceCase(
                    case_id="format-python-file",
                    should_call=False,
                    events=(),
                ),
            )
        )
        self.assertEqual("PASS", report.status)
        self.assertEqual(1.0, report.should_call_accuracy)
        self.assertEqual(1.0, report.should_not_call_accuracy)
        self.assertEqual(1, report.grounded_gain_cases)

        rejected = evaluate_tool_choice(
            (
                ToolChoiceCase(
                    case_id="bad-current-claim",
                    should_call=True,
                    events=(
                        ToolTraceEvent(
                            "search_quant_knowledge",
                            {"availability": "stale", "identity": identity.to_dict()},
                        ),
                    ),
                    expected_identity=identity,
                    decision_claims_current=True,
                    assisted_quality=baseline,
                    no_mcp_quality=baseline,
                ),
                ToolChoiceCase(
                    case_id="unnecessary-search",
                    should_call=False,
                    events=(ToolTraceEvent("search_quant_knowledge", fresh),),
                ),
            )
        )
        self.assertEqual("FAIL", rejected.status)
        self.assertIn(
            "bad-current-claim:stale_or_unavailable_supported_current",
            rejected.findings,
        )
        self.assertIn("unnecessary-search:meaningless_tool_call", rejected.findings)


if __name__ == "__main__":
    unittest.main()
