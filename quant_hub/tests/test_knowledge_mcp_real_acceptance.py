from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.knowledge.contracts import canonical_json
from quant_hub.knowledge_mcp.acceptance_cli import (
    _run,
    main,
    validate_real_acceptance_evidence_root,
)
from quant_hub.knowledge_mcp.acceptance_contracts import (
    REAL_CODEX_EVIDENCE_REPLAY_AUTHORITY,
    REAL_ACCEPTANCE_PROMPTS_SCHEMA,
    REAL_CODEX_LAUNCH_SCHEMA,
    REAL_CODEX_RUNNER,
    _summarize_codex_non_user_layers,
    build_real_codex_command,
    collect_openai_authenticode,
    validate_arm_command_difference,
    validate_real_codex_launch_config_bytes,
)
from quant_hub.knowledge_mcp.acceptance_runner import (
    acceptance_evidence_inventory,
    load_real_acceptance_inputs,
    record_real_acceptance_inputs,
)
from quant_hub.knowledge_mcp.evaluation import (
    AcceptanceCaseDefinition,
    _replay_authority_for_runners,
    build_acceptance_preregistration,
)
from quant_hub.knowledge_mcp.mirror import AuthorityIdentity


SERVER = "quant_research_knowledge"
MODEL = "acceptance-test-model"
RUN_ID = "real-codex-run-20260831"
MANIFEST_SHA = "a" * 64


class _Pins:
    def close(self) -> None:
        return None


class _FailingClosePins:
    def close(self) -> None:
        raise RuntimeError("runtime pin close failed")


class _SyntheticProcess:
    """Deliberately lacks a live Windows PID and can never qualify as real."""

    returncode = 0

    def kill(self) -> None:
        self.returncode = -9

    def wait(self, timeout: int | None = None) -> int:
        return self.returncode


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RealAcceptanceRunnerTests(unittest.TestCase):
    def test_real_runner_label_can_never_mint_authoritative_gate(self) -> None:
        authority = _replay_authority_for_runners({REAL_CODEX_RUNNER})
        self.assertEqual(REAL_CODEX_EVIDENCE_REPLAY_AUTHORITY, authority)
        self.assertNotEqual("AUTHORITATIVE_REAL_CODEX_INTEGRATED_GATE", authority)

    def _fixture(self, root: Path):
        client_config = root / "client.json"
        client_config.write_bytes(b'{"schema_version":"test-client/v1"}')
        launcher = root / "qrh-knowledge-mcp.exe"
        launcher.write_bytes(Path(sys.executable).read_bytes())
        package_root = root / "quant_hub"
        package_root.mkdir()
        (package_root / "__init__.py").write_bytes(b"# frozen package\n")
        distribution_root = root / "quant_hub-0.dist-info"
        distribution_root.mkdir()
        (distribution_root / "METADATA").write_bytes(b"Name: quant-hub\nVersion: 0\n")
        config_value = {
            "schema_version": REAL_CODEX_LAUNCH_SCHEMA,
            "execution_scope": "local",
            "evidence_parent": str(root.resolve()),
            "codex_executable": str(Path(sys.executable).resolve()),
            "codex_executable_sha256": _sha(Path(sys.executable)),
            "codex_authenticode": {
                "status": "Valid",
                "signer_subject": "CN=OpenAI, O=OpenAI",
                "signer_thumbprint": "A" * 40,
            },
            "working_directory": str(root.resolve()),
            "sandbox": "read-only",
            "timeout_seconds": 30,
            "skip_git_repo_check": True,
            "mcp_server": {
                "command": str(launcher.resolve()),
                "command_sha256": _sha(launcher),
                "args": [
                    "serve-stdio",
                    "--client-config",
                    str(client_config.resolve()),
                ],
                "cwd": str(root.resolve()),
                "env": {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONPATH": str(package_root.resolve().parent),
                    "PYTHONSAFEPATH": "1",
                    "PYTHONUTF8": "1",
                },
                "env_vars": [],
                "enabled": True,
                "required": True,
                "enabled_tools": [
                    "search_quant_knowledge",
                    "get_quant_knowledge",
                    "list_knowledge_updates",
                ],
                "default_tools_approval_mode": "writes",
                "startup_timeout_sec": 20,
                "tool_timeout_sec": 60,
                "client_config_path": str(client_config.resolve()),
                "client_config_sha256": _sha(client_config),
                "python_executable": str(Path(sys.executable).resolve()),
                "python_executable_sha256": _sha(Path(sys.executable)),
                "runtime_closures": [
                    {
                        "name": "quant_hub_package",
                        "root": str(package_root.resolve()),
                        "files": [
                            {"relative_path": "__init__.py", "sha256": _sha(package_root / "__init__.py")}
                        ],
                    },
                    {
                        "name": "quant_hub_distribution",
                        "root": str(distribution_root.resolve()),
                        "files": [
                            {"relative_path": "METADATA", "sha256": _sha(distribution_root / "METADATA")}
                        ],
                    },
                ],
            },
        }
        config = canonical_json(config_value).encode("utf-8")
        prompts = {
            "implicit-leakage": b"choose a leakage-safe backtest split",
            "format-only": b"format this local file",
        }
        preregistration = build_acceptance_preregistration(
            suite_id="real-codex-acceptance-v2",
            authority_identity=AuthorityIdentity(
                "release-r1", MANIFEST_SHA, "snapshot-r1"
            ),
            server_name=SERVER,
            model=MODEL,
            config_bytes=config,
            run_id=RUN_ID,
            preregistered_at="2026-08-30T00:00:00+00:00",
            cases=(
                AcceptanceCaseDefinition(
                    case_id="implicit-leakage",
                    prompt_bytes=prompts["implicit-leakage"],
                    should_call=True,
                    required_sequence=(
                        "search_quant_knowledge",
                        "get_quant_knowledge",
                    ),
                    maximum_target_calls=2,
                ),
                AcceptanceCaseDefinition(
                    case_id="format-only",
                    prompt_bytes=prompts["format-only"],
                    should_call=False,
                    maximum_target_calls=0,
                ),
            ),
            marker_definitions={
                "grounded_decision": ["purged split"],
                "condition_limitation_recognition": ["embargo", "locator"],
                "citation_correctness": ["citation"],
            },
        )
        provenance = {
            "fixture": "structural-only",
            "codex_executable": {"path": config_value["codex_executable"]},
            "mcp_command": {"path": config_value["mcp_server"]["command"]},
        }
        return preregistration, config, prompts, provenance

    def _record(self, root: Path):
        preregistration, config, prompts, provenance = self._fixture(root)
        evidence_root = root / "evidence"
        with (
            patch(
                "quant_hub.knowledge_mcp.acceptance_runner.observe_static_provenance",
                return_value=provenance,
            ),
            patch(
                "quant_hub.knowledge_mcp.acceptance_runner.pin_runtime_closure",
                return_value=_Pins(),
            ),
        ):
            record_real_acceptance_inputs(
                preregistration=preregistration,
                config_bytes=config,
                prompts=prompts,
                evidence_root=evidence_root,
            )
        return evidence_root, preregistration, config, prompts, provenance

    def test_v2_config_freezes_full_target_and_arm_only_changes_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _preregistration, config_bytes, _prompts, _provenance = self._fixture(root)
            config = validate_real_codex_launch_config_bytes(
                config_bytes, server_name=SERVER
            )
            validate_arm_command_difference(config, server_name=SERVER, model=MODEL)
            assisted = build_real_codex_command(
                config, server_name=SERVER, model=MODEL, arm="assisted"
            )
            control = build_real_codex_command(
                config, server_name=SERVER, model=MODEL, arm="no_mcp"
            )
            self.assertIn("--ignore-user-config", assisted)
            self.assertIn("--ignore-rules", assisted)
            self.assertIn("--strict-config", assisted)
            for isolation_override in (
                "features.apps=false",
                "features.enable_mcp_apps=false",
                "features.plugins=false",
                "features.tool_search=false",
            ):
                self.assertIn(isolation_override, assisted)
            self.assertEqual(len(assisted), len(control))
            differences = [(left, right) for left, right in zip(assisted, control) if left != right]
            self.assertEqual(1, len(differences))
            self.assertIn("mcp_servers={quant_research_knowledge={", differences[0][0])
            self.assertIn("enabled=true", differences[0][0])
            self.assertIn("enabled=false", differences[0][1])
            self.assertIn("required=true", differences[0][0])
            self.assertTrue(differences[0][0].endswith("}}"))
            self.assertFalse(differences[0][0].endswith("}}}"))

    def test_effective_non_user_layer_cannot_contribute_another_mcp(self) -> None:
        user = {
            "name": {"type": "user"},
            "version": "user-v1",
            "config": {"mcp_servers": {"ignored_user_server": {}}},
        }
        system = {
            "name": {"type": "system"},
            "version": "system-v1",
            "config": {},
        }
        summaries = _summarize_codex_non_user_layers([user, system])
        self.assertEqual(["system"], [row["type"] for row in summaries])
        enterprise = {
            "name": {"type": "enterpriseManaged"},
            "version": "enterprise-v1",
            "config": {"mcp_servers": {"ambient_enterprise_server": {}}},
        }
        with self.assertRaisesRegex(ValueError, "ambient MCP"):
            _summarize_codex_non_user_layers([user, enterprise, system])

    def test_patched_popen_and_sys_executable_cannot_sign_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            evidence_root, _prereg, _config, _prompts, provenance = self._record(root)
            with (
                patch(
                    "quant_hub.knowledge_mcp.acceptance_runner.observe_static_provenance",
                    return_value=provenance,
                ),
                patch(
                    "quant_hub.knowledge_mcp.acceptance_runner.pin_runtime_closure",
                    return_value=_Pins(),
                ),
                patch(
                    "quant_hub.knowledge_mcp.acceptance_cli.pin_runtime_closure",
                    return_value=_Pins(),
                ),
                patch(
                    "quant_hub.knowledge_mcp.acceptance_runner.subprocess.Popen",
                    return_value=_SyntheticProcess(),
                ),
            ):
                result = _run(evidence_root)
            self.assertEqual("FAIL", result["status"])
            self.assertEqual(
                "PUBLIC_SYNTHETIC_NON_QUALIFYING_GATE", result["authority"]
            )
            self.assertTrue((evidence_root / "campaign-failure.json").is_file())
            self.assertFalse((evidence_root / "campaign-receipt.json").exists())
            receipt = json.loads((evidence_root / "campaign-failure.json").read_bytes())
            self.assertEqual("provenance_failed", receipt["failed_status"])
            with self.assertRaises(ValueError):
                validate_real_acceptance_evidence_root(evidence_root)

    def test_preregister_cli_stages_closed_inputs_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            preregistration, config, prompts, provenance = self._fixture(root)
            preregistration_path = root / "preregistration-source.json"
            config_path = root / "launch-source.json"
            preregistration_path.write_bytes(preregistration)
            config_path.write_bytes(config)
            cases = []
            for case_id, prompt in prompts.items():
                path = root / f"{case_id}.txt"
                path.write_bytes(prompt)
                cases.append({"case_id": case_id, "prompt_path": path.name})
            prompt_manifest_path = root / "prompts.json"
            prompt_manifest_path.write_bytes(
                canonical_json(
                    {"schema_version": REAL_ACCEPTANCE_PROMPTS_SCHEMA, "cases": cases}
                ).encode("utf-8")
            )
            evidence_root = root / "cli-evidence"
            output = StringIO()
            with (
                patch(
                    "quant_hub.knowledge_mcp.acceptance_runner.observe_static_provenance",
                    return_value=provenance,
                ),
                patch(
                    "quant_hub.knowledge_mcp.acceptance_runner.pin_runtime_closure",
                    return_value=_Pins(),
                ),
                redirect_stdout(output),
            ):
                code = main(
                    [
                        "preregister", "--preregistration", str(preregistration_path),
                        "--launch-config", str(config_path), "--prompts-manifest",
                        str(prompt_manifest_path), "--evidence-root", str(evidence_root),
                    ]
                )
            self.assertEqual(0, code)
            self.assertEqual("preregistered", json.loads(output.getvalue())["status"])
            with patch(
                "quant_hub.knowledge_mcp.acceptance_runner.observe_static_provenance",
                return_value=provenance,
            ):
                loaded = load_real_acceptance_inputs(evidence_root)
            self.assertEqual(preregistration, loaded[0])
            self.assertEqual(config, loaded[2])
            self.assertEqual(prompts, loaded[3])
            self.assertFalse((evidence_root / "dispatch").exists())
            self.assertFalse(any(root.glob(".cli-evidence.staging-*")))

    def test_campaign_pin_failure_writes_nonqualifying_top_level_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            evidence_root, _prereg, _config, _prompts, provenance = self._record(root)
            with (
                patch(
                    "quant_hub.knowledge_mcp.acceptance_runner.observe_static_provenance",
                    return_value=provenance,
                ),
                patch(
                    "quant_hub.knowledge_mcp.acceptance_cli.pin_runtime_closure",
                    side_effect=ValueError("cannot pin runtime"),
                ),
            ):
                result = _run(evidence_root)
            self.assertEqual("FAIL", result["status"])
            receipt = json.loads((evidence_root / "campaign-failure.json").read_bytes())
            self.assertEqual("__campaign__", receipt["failed_case_id"])
            self.assertEqual("provenance_error", receipt["failed_status"])
            self.assertEqual(
                "PUBLIC_SYNTHETIC_NON_QUALIFYING_GATE", receipt["authority"]
            )

    def test_unexpected_runtime_error_after_dispatch_writes_failure_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            evidence_root, _prereg, _config, _prompts, provenance = self._record(root)
            with (
                patch(
                    "quant_hub.knowledge_mcp.acceptance_runner.observe_static_provenance",
                    return_value=provenance,
                ),
                patch(
                    "quant_hub.knowledge_mcp.acceptance_cli.pin_runtime_closure",
                    return_value=_Pins(),
                ),
                patch(
                    "quant_hub.knowledge_mcp.acceptance_cli.run_real_acceptance_arm",
                    side_effect=RuntimeError("unexpected runner failure"),
                ),
            ):
                result = _run(evidence_root)
            self.assertEqual("FAIL", result["status"])
            self.assertTrue((evidence_root / "campaign-failure.json").is_file())
            self.assertFalse((evidence_root / "campaign-receipt.json").exists())
            receipt = json.loads((evidence_root / "campaign-failure.json").read_bytes())
            self.assertEqual("provenance_error", receipt["failed_status"])
            self.assertEqual("implicit-leakage", receipt["failed_case_id"])
            self.assertEqual("assisted", receipt["failed_arm"])

    def test_campaign_pin_close_error_has_one_failure_terminal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            evidence_root, _prereg, _config, _prompts, provenance = self._record(root)
            with (
                patch(
                    "quant_hub.knowledge_mcp.acceptance_runner.observe_static_provenance",
                    return_value=provenance,
                ),
                patch(
                    "quant_hub.knowledge_mcp.acceptance_cli.pin_runtime_closure",
                    return_value=_FailingClosePins(),
                ),
                patch(
                    "quant_hub.knowledge_mcp.acceptance_cli.run_real_acceptance_arm",
                    side_effect=RuntimeError("unexpected runner failure"),
                ),
            ):
                result = _run(evidence_root)
            self.assertEqual("FAIL", result["status"])
            self.assertTrue((evidence_root / "campaign-failure.json").is_file())
            self.assertFalse((evidence_root / "campaign-receipt.json").exists())
            receipt = json.loads((evidence_root / "campaign-failure.json").read_bytes())
            self.assertEqual("__campaign__", receipt["failed_case_id"])
            self.assertIn("closure close failed", receipt["reason"])

    def test_extra_file_and_existing_root_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            evidence_root, preregistration, config, prompts, provenance = self._record(root)
            (evidence_root / "opaque-pass.json").write_bytes(b"{}")
            with (
                patch(
                    "quant_hub.knowledge_mcp.acceptance_runner.observe_static_provenance",
                    return_value=provenance,
                ),
                self.assertRaisesRegex(ValueError, "inventory"),
            ):
                load_real_acceptance_inputs(evidence_root)
            second = root / "already-exists"
            second.mkdir()
            with self.assertRaises(FileExistsError):
                record_real_acceptance_inputs(
                    preregistration=preregistration,
                    config_bytes=config,
                    prompts=prompts,
                    evidence_root=second,
                )

    def test_config_rejects_script_open_control_and_unbound_client(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            _preregistration, config_bytes, _prompts, _provenance = self._fixture(root)
            base = json.loads(config_bytes)
            for mutate in (
                lambda value: value["mcp_server"].__setitem__("enabled", False),
                lambda value: value["mcp_server"].__setitem__("required", False),
                lambda value: value["mcp_server"].__setitem__("env_vars", ["HOME"]),
                lambda value: value["mcp_server"].__setitem__(
                    "env", {"PYTHONPATH": "unbound"}
                ),
                lambda value: value["mcp_server"]["args"].append("--unexpected"),
                lambda value: value["mcp_server"]["enabled_tools"].reverse(),
                lambda value: value["mcp_server"].__setitem__("client_config_path", str(root / "other.json")),
                lambda value: value.__setitem__("codex_executable", str(root / "codex.cmd")),
            ):
                changed = json.loads(canonical_json(base))
                mutate(changed)
                with self.assertRaises(ValueError):
                    validate_real_codex_launch_config_bytes(
                        canonical_json(changed).encode("utf-8"), server_name=SERVER
                    )

    @unittest.skipUnless(os.name == "nt", "Authenticode gate is Windows-only")
    def test_python_executable_is_not_accepted_as_openai_codex(self) -> None:
        with self.assertRaisesRegex(ValueError, "Authenticode"):
            collect_openai_authenticode(Path(sys.executable))


if __name__ == "__main__":
    unittest.main()
