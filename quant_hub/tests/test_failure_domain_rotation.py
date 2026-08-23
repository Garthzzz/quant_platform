from __future__ import annotations

import ast
from contextlib import ExitStack, redirect_stdout
import hashlib
import importlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from quant_hub.ops.failure_domain import (
    FACTS_SCHEMA,
    PROBE_SCHEMA,
    attest_failure_domain,
    canonical_bytes,
)
from quant_hub.ops.failure_domain_rotation import (
    CAPTURE_SCHEMA,
    CHALLENGE_SCHEMA,
    DIAGNOSTIC_READINESS,
    OBSERVATION_SCHEMA,
    ROTATION_READINESS,
    FailureDomainRotationError,
    _canonical_object,
    _verify_attestation,
    apply_rotation,
    diagnose_legacy_current_attestation,
    diagnostic_source_manifest,
    main,
    prepare_rotation,
    verify_current_attestation,
)
from quant_hub.ops.failure_domain_authority import (
    AUTHORITY_ERROR_CODE,
    FailureDomainAuthorityNotReady,
    failure_domain_authority_status,
    require_failure_domain_authority,
)


CHALLENGE_TIME = "2026-08-23T08:00:00Z"
CAPTURE_TIME = "2026-08-23T08:00:10Z"
OBSERVATION_TIME = "2026-08-23T08:00:15Z"
INSPECT_TIME = "2026-08-23T08:00:20Z"
CHANGED_FILE_MANIFEST = (
    ".github/workflows/ci.yml",
    "docs/runbooks/COLD_RECOVERY.md",
    "openspec/changes/design-vm-knowledge-mcp/specs/vm-atomic-deployment/spec.md",
    "openspec/changes/design-vm-knowledge-mcp/tasks.md",
    "quant_hub/pyproject.toml",
    "quant_hub/src/quant_hub/ops/cold_bundle_cli.py",
    "quant_hub/src/quant_hub/ops/cold_restore_cli.py",
    "quant_hub/src/quant_hub/ops/failure_domain.py",
    "quant_hub/src/quant_hub/ops/failure_domain_authority.py",
    "quant_hub/src/quant_hub/ops/failure_domain_rotation.py",
    "quant_hub/src/quant_hub/ops/operational_source_cli.py",
    "quant_hub/src/quant_hub/ops/production_host_facts_cli.py",
    "quant_hub/src/quant_hub/ops/publish.py",
    "quant_hub/src/quant_hub/ops/publish_adapters.py",
    "quant_hub/src/quant_hub/ops/publish_recovery_cli.py",
    "quant_hub/src/quant_hub/ops/publish_runtime.py",
    "quant_hub/src/quant_hub/ops/stage_closure.py",
    "quant_hub/src/quant_hub/ops/state_only_backup.py",
    "quant_hub/src/quant_hub/ops/writer_handoff.py",
    "quant_hub/src/quant_hub/ops/writer_handoff_client.py",
    "quant_hub/tests/test_cold_bundle_cli.py",
    "quant_hub/tests/test_cold_restore_cli.py",
    "quant_hub/tests/test_failure_domain_rotation.py",
    "quant_hub/tests/test_publish_adapters.py",
    "quant_hub/tests/test_publish_cli.py",
    "quant_hub/tests/test_publish_runtime.py",
    "quant_hub/tests/test_stage_closure.py",
    "quant_hub/tests/test_state_only_backup.py",
    "quant_hub/tests/test_writer_handoff.py",
    "quant_hub/tests/test_writer_handoff_client.py",
    "tools/release/failure_domain_cli.py",
)

# Closed inventory for the formal publish/recovery/handoff product surface.
# New exported classes, public methods, factories or helpers must be placed in
# exactly one category before the wheel can pass this test.
FAILURE_DOMAIN_GATED_SURFACES = frozenset(
    """
publish:PublishPipeline.execute
publish:PublishQueue.submit
publish:PublishQueue.finish
publish:PublishQueue.request
publish:PublishQueue.running_request
publish:PublishCoordinator.submit_and_drain
publish_adapters:IncrementalVMTransport.__call__
publish_adapters:OpenSSHVMBackend.ensure_directory
publish_adapters:OpenSSHVMBackend.upload
publish_adapters:VMDeploymentAdapter.__call__
publish_adapters:OpenSSHDeploymentInvoker.invoke
publish_recovery_cli:capture
publish_recovery_cli:identify_active
publish_recovery_cli:cleanup_capture
publish_recovery_cli:capture_legacy
publish_recovery_cli:register
publish_runtime:OpenSSHRecoveryActions.capture_checkpoint
publish_runtime:OpenSSHRecoveryActions.read_active_identity
publish_runtime:OpenSSHRecoveryActions.capture_state_only_checkpoint
publish_runtime:OpenSSHRecoveryActions.cleanup_state_only_capture
publish_runtime:OpenSSHRecoveryActions.register_protection
publish_runtime:RecoveryProtectionCoordinator.preflight_materials
publish_runtime:RecoveryProtectionCoordinator.preflight
publish_runtime:RecoveryProtectionCoordinator.protect
publish_runtime:ProductionSourceFreezer.__call__
publish_runtime:ExactGitPush.__call__
publish_runtime:ProductionPublishRuntime
publish_runtime:ProductionPublishRuntime.publish
writer_handoff:WindowsHandoffRuntime
writer_handoff:WindowsHandoffRuntime.observe
writer_handoff:WindowsHandoffRuntime.stop_legacy
writer_handoff:WindowsHandoffRuntime.wait_port_free
writer_handoff:WindowsHandoffRuntime.start_d_service
writer_handoff:WindowsHandoffRuntime.stop_d_service
writer_handoff:WindowsHandoffRuntime.d_external_open
writer_handoff:WindowsHandoffRuntime.probe_d
writer_handoff:WindowsHandoffRuntime.start_legacy
writer_handoff:WindowsHandoffRuntime.verify_legacy_restored
writer_handoff:inspect_d_closure
writer_handoff:seed_v39_access_identity
writer_handoff:inspect_writer_handoff
writer_handoff:apply_writer_handoff
writer_handoff:finalize_writer_handoff
writer_handoff:inspect_writer_handoff_status
writer_handoff_client:WriterHandoffClient
writer_handoff_client:WriterHandoffClient.inspect
writer_handoff_client:WriterHandoffClient.status
writer_handoff_client:WriterHandoffClient.finalize
writer_handoff_client:WriterHandoffClient.run
writer_handoff_client:_client_from_runtime_config
""".split()
)

DIAGNOSTIC_ONLY_SURFACES = frozenset(
    """
publish:inspect_local_git
publish:dry_run_plan
publish_adapters:OpenSSHVMBackend.inventory
writer_handoff:validate_inspection_receipt
""".split()
)

QUALIFICATION_INPUT_SURFACES = frozenset(
    """
publish_adapters:GitHubExactSHACI.__call__
publish_runtime:FixedLocalGates.tests
publish_runtime:FixedLocalGates.public
publish_runtime:ProductionSourceFreezer.material
""".split()
)

SUPPORT_CONFIG_SURFACES = frozenset(
    """
publish_adapters:GitHubCIConfig
publish_adapters:VMConfig
""".split()
)

SUPPORT_PROTOCOL_SURFACES = frozenset(
    """
publish:InspectGit
publish:RunGate
publish:FreezeSources
publish:PushOnce
publish:WaitExactCI
publish:TransportCandidate
publish:DeployCandidate
publish_adapters:SecretProvider
publish_adapters:HTTPGet
publish_adapters:MaterialResolver
publish_adapters:VMTransportBackend
publish_adapters:VMTransportBackend.ensure_directory
publish_adapters:VMTransportBackend.inventory
publish_adapters:VMTransportBackend.upload
publish_adapters:CommandRunner
publish_adapters:DeploymentInvoker
publish_adapters:DeploymentInvoker.invoke
publish_adapters:ActivationAuthorizationResolver
publish_runtime:ProcessRunner
publish_runtime:RecoveryProtector
publish_runtime:RecoveryProtector.preflight
publish_runtime:RecoveryProtector.protect
publish_runtime:RecoveryProtectionActions
publish_runtime:RecoveryProtectionActions.capture_checkpoint
publish_runtime:RecoveryProtectionActions.register_protection
writer_handoff:HandoffRuntime
writer_handoff:HandoffRuntime.observe
writer_handoff:HandoffRuntime.stop_legacy
writer_handoff:HandoffRuntime.wait_port_free
writer_handoff:HandoffRuntime.start_d_service
writer_handoff:HandoffRuntime.stop_d_service
writer_handoff:HandoffRuntime.d_external_open
writer_handoff:HandoffRuntime.probe_d
writer_handoff:HandoffRuntime.start_legacy
writer_handoff:HandoffRuntime.verify_legacy_restored
writer_handoff:DClosureVerifier
writer_handoff:CheckpointBuilder
""".split()
)

FAIL_CLOSED_SUPPORT_SURFACES = frozenset(
    """
publish_runtime:UnavailableRecoveryProtector
publish_runtime:UnavailableRecoveryProtector.preflight
publish_runtime:UnavailableRecoveryProtector.protect
publish_runtime:UnavailableRecoveryActions
publish_runtime:UnavailableRecoveryActions.capture_checkpoint
publish_runtime:UnavailableRecoveryActions.register_protection
""".split()
)

CLI_DISPATCH_SURFACES = frozenset(
    """
publish:main
publish_recovery_cli:main
writer_handoff:main
writer_handoff_client:main
""".split()
)

NON_AUTHORITY_SUPPORT_SURFACES = frozenset(
    """
publish:PublishError
publish:PublishLocked
publish:PublishFailed
publish:PublishStepError
publish:PublishRequest
publish:PublishRequest.create
publish:GitSnapshot
publish:GateResult
publish:FrozenSources
publish:PushResult
publish:CIResult
publish:TransferResult
publish:VMDeployResult
publish:PublishResult
publish:PublishActions
publish:PublishPipeline
publish:PublishQueue
publish:PublishCoordinator
publish_adapters:PublishAdapterError
publish_adapters:SecretValue
publish_adapters:SecretValue.reveal
publish_adapters:ProductionPublishConfig
publish_adapters:ProductionPublishConfig.parse
publish_adapters:ProductionPublishConfig.load
publish_adapters:HTTPResponse
publish_adapters:GitHubExactSHACI
publish_adapters:ReleaseFile
publish_adapters:ReleaseMaterial
publish_adapters:IncrementalVMTransport
publish_adapters:CommandResult
publish_adapters:ssh_target_guard_script
publish_adapters:exact_production_root_parent_guard_script
publish_adapters:verified_d_tooling_python_script
publish_adapters:bootstrap_verified_d_tooling_python_script
publish_adapters:OpenSSHVMBackend
publish_adapters:ActivationAuthorization
publish_adapters:VMDeploymentAdapter
publish_adapters:OpenSSHDeploymentInvoker
publish_recovery_cli:PublishRecoveryCLIError
publish_runtime:PublishRuntimeError
publish_runtime:ResourceOverlayConfig
publish_runtime:RecoveryRuntimeConfig
publish_runtime:RuntimePublishConfig
publish_runtime:RuntimePublishConfig.parse
publish_runtime:RuntimePublishConfig.load
publish_runtime:ProcessResult
publish_runtime:EnvironmentSecretProvider
publish_runtime:EnvironmentSecretProvider.__call__
publish_runtime:OpenSSHRecoveryActions
publish_runtime:RecoveryProtectionCoordinator
publish_runtime:ProductionSourceFreezer
publish_runtime:FixedLocalGates
publish_runtime:ExactGitPush
publish_runtime:RuntimeDependencies
writer_handoff:WriterHandoffError
writer_handoff:V39Baseline
writer_handoff:LegacyProcess
writer_handoff:LegacyProcess.document
writer_handoff:RuntimeObservation
writer_handoff:HandoffApplyResult
writer_handoff:LegacyProcess
writer_handoff_client:WriterHandoffClientError
writer_handoff_client:WriterHandoffRunError
writer_handoff_client:WriterHandoffClientConfig
writer_handoff_client:WriterHandoffClientResult
writer_handoff_client:WriterHandoffClientResult.public_document
""".split()
)

PUBLIC_SURFACE_CLASSIFICATION = {
    "FAILURE_DOMAIN_GATED": FAILURE_DOMAIN_GATED_SURFACES,
    "DIAGNOSTIC_ONLY": DIAGNOSTIC_ONLY_SURFACES,
    "QUALIFICATION_INPUT": QUALIFICATION_INPUT_SURFACES,
    "SUPPORT_CONFIG": SUPPORT_CONFIG_SURFACES,
    "SUPPORT_PROTOCOL": SUPPORT_PROTOCOL_SURFACES,
    "FAIL_CLOSED_SUPPORT": FAIL_CLOSED_SUPPORT_SURFACES,
    "CLI_DISPATCH": CLI_DISPATCH_SURFACES,
    "NON_AUTHORITY_SUPPORT": NON_AUTHORITY_SUPPORT_SURFACES,
}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def host_facts(role: str, root: str) -> dict[str, object]:
    machine = "production-vm-240" if role == "production" else "recovery-host"
    volume = "volume-d" if role == "production" else "volume-r"
    value: dict[str, object] = {
        "schema_version": FACTS_SCHEMA,
        "role": role,
        "host_name": machine,
        "machine_identity": machine,
        "canonical_path": root,
        "path_kind": "local",
        "reparse_or_symlink": False,
        "volume_identity": volume,
        "storage_backend": "local-ntfs:" + volume,
        "storage_authority": machine + "|" + volume,
        "tool_version": "tests/v1",
    }
    value["facts_sha256"] = sha(canonical_bytes(value))
    return value


def independence_probe() -> dict[str, object]:
    return {
        "schema_version": PROBE_SCHEMA,
        "production_root_available": False,
        "recovery_bundle_readable": True,
        "closure_verified": True,
        "empty_root_precondition": True,
        "bundle_id": "bundle-v39",
        "release_id": "release-v39",
        "release_manifest_sha256": "c" * 64,
        "bundle_inventory_sha256": "a" * 64,
        "materialization_event_id": "cold-materialization-bundle-v39",
        "materialization_event_sha256": "d" * 64,
        "probe_tool_sha256": "b" * 64,
    }


def tree_identity(root: Path) -> tuple[tuple[str, int, str], ...]:
    return tuple(
        (path.relative_to(root).as_posix(), path.stat().st_size, sha(path.read_bytes()))
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


SURFACE_MODULES = (
    "publish",
    "publish_adapters",
    "publish_recovery_cli",
    "publish_runtime",
    "writer_handoff",
    "writer_handoff_client",
)

FORMAL_INTERNAL_FACTORIES = {
    "writer_handoff_client": ("_client_from_runtime_config",),
}


def _assigned_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Assign):
        return tuple(
            target.id for target in node.targets if isinstance(target, ast.Name)
        )
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return (node.target.id,)
    return ()


def _public_surface_inventory() -> tuple[set[str], dict[str, ast.AST]]:
    """Enumerate definitions without treating ``__all__`` as an access filter.

    A class key represents its callable constructor.  Public methods (including
    class/static/property descriptors), ``__call__`` and module-local callable
    aliases are separate surfaces.  Imported helpers are dependencies rather
    than definitions of this six-module formal surface.
    """

    inventory: set[str] = set()
    nodes: dict[str, ast.AST] = {}
    for short_name in SURFACE_MODULES:
        module = importlib.import_module(f"quant_hub.ops.{short_name}")
        parsed = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
        for node in parsed.body:
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                if node.name.startswith("_"):
                    continue
                key = f"{short_name}:{node.name}"
                inventory.add(key)
                nodes[key] = node
                if isinstance(node, ast.ClassDef):
                    for method in node.body:
                        if not isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            continue
                        if method.name == "__call__" or not method.name.startswith("_"):
                            method_key = f"{key}.{method.name}"
                            inventory.add(method_key)
                            nodes[method_key] = method
                continue
            for name in _assigned_names(node):
                if name.startswith("_") or not callable(getattr(module, name, None)):
                    continue
                key = f"{short_name}:{name}"
                inventory.add(key)
                nodes[key] = node
        for factory_name in FORMAL_INTERNAL_FACTORIES.get(short_name, ()):
            factory = next(
                node
                for node in parsed.body
                if isinstance(node, ast.FunctionDef)
                and node.name == factory_name
            )
            key = f"{short_name}:{factory_name}"
            inventory.add(key)
            nodes[key] = factory
    return inventory, nodes


def _documented_exports_are_consistent(inventory: set[str]) -> None:
    for short_name in SURFACE_MODULES:
        module = importlib.import_module(f"quant_hub.ops.{short_name}")
        declared = getattr(module, "__all__", None)
        if declared is None:
            continue
        assert isinstance(declared, list), short_name
        assert len(declared) == len(set(declared)), short_name
        for name in declared:
            assert isinstance(name, str) and name and not name.startswith("_"), (
                short_name,
                name,
            )
            assert hasattr(module, name), (short_name, name)
            if callable(getattr(module, name)):
                assert f"{short_name}:{name}" in inventory, (short_name, name)


def _first_effective_statement(node: ast.AST) -> ast.stmt:
    if isinstance(node, ast.ClassDef):
        node = next(
            child
            for child in node.body
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            and child.name == "__init__"
        )
    assert isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    body = list(node.body)
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    if not body:
        raise AssertionError("public callable has no effective statement")
    return body[0]


def _is_authority_gate(statement: ast.stmt) -> bool:
    return (
        isinstance(statement, ast.Expr)
        and isinstance(statement.value, ast.Call)
        and isinstance(statement.value.func, ast.Name)
        and statement.value.func.id == "require_failure_domain_authority"
        and not statement.value.args
        and not statement.value.keywords
    )


def _authority_gate_count(node: ast.AST) -> int:
    return sum(
        1
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id == "require_failure_domain_authority"
        and not call.args
        and not call.keywords
    )


class FailureDomainRotationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        for relative in (
            "failure-domain/challenges",
            "failure-domain/captures/manual-challenge",
            "failure-domain/observations",
        ):
            (self.root / relative).mkdir(parents=True)
        self.production = host_facts("production", r"D:\quant\quant_platform")
        self.recovery = host_facts("recovery", str(self.root))
        self.probe = independence_probe()
        current = attest_failure_domain(
            production_facts=self.production,
            recovery_facts=self.recovery,
            independence_probe=self.probe,
            observed_at=OBSERVATION_TIME,
        )
        self.current = self._write(
            "failure-domain/current.json",
            {**current.payload, "attestation_sha256": current.sha256},
        )
        self.challenge, self.challenge_path = self._manual_challenge()
        captures: dict[str, tuple[dict[str, object], Path]] = {}
        for kind, source in (
            ("production_facts", self.production),
            ("recovery_facts", self.recovery),
            ("independence_probe", self.probe),
        ):
            captures[kind] = self._manual_capture(kind, source)
        self.captures = captures
        self.observation, self.observation_path = self._manual_observation()

    def test_formal_public_surface_inventory_is_closed_and_gates_are_first(self) -> None:
        inventory, nodes = _public_surface_inventory()
        _documented_exports_are_consistent(inventory)
        categories = tuple(PUBLIC_SURFACE_CLASSIFICATION.values())
        for index, left in enumerate(categories):
            for right in categories[index + 1 :]:
                self.assertFalse(left & right, left & right)
        classified = set().union(*categories)
        report = {
            "inventory_total": len(inventory),
            "category_counts": {
                name: len(surfaces)
                for name, surfaces in PUBLIC_SURFACE_CLASSIFICATION.items()
            },
            "unclassified": sorted(inventory - classified),
            "unknown_classification": sorted(classified - inventory),
        }
        self.assertEqual(classified, inventory, json.dumps(report, sort_keys=True))
        self.assertEqual(
            len(inventory),
            sum(report["category_counts"].values()),
            json.dumps(report, sort_keys=True),
        )
        for surface in FAILURE_DOMAIN_GATED_SURFACES:
            with self.subTest(surface=surface):
                self.assertTrue(
                    _is_authority_gate(_first_effective_statement(nodes[surface])),
                    surface,
                )
        exact_git_push = nodes["publish_runtime:ExactGitPush.__call__"]
        self.assertEqual(1, _authority_gate_count(exact_git_push))
        adapters = importlib.import_module("quant_hub.ops.publish_adapters")
        runtime = importlib.import_module("quant_hub.ops.publish_runtime")
        self.assertNotIn("subprocess_runner", vars(adapters))
        self.assertNotIn("urllib_http_get", vars(adapters))
        self.assertNotIn("production_process_runner", vars(runtime))
        process_runner = Mock(side_effect=AssertionError("process boundary reached"))
        with self.assertRaisesRegex(
            FailureDomainAuthorityNotReady, AUTHORITY_ERROR_CODE
        ):
            runtime.ExactGitPush(None, process_runner)("a" * 40)
        process_runner.assert_not_called()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write(self, relative: str, value: object) -> Path:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(canonical_bytes(value))
        return target

    @staticmethod
    def _rotation_module_hash() -> str:
        module = importlib.import_module("quant_hub.ops.failure_domain_rotation")
        return sha(Path(module.__file__).read_bytes())

    @staticmethod
    def _production_module_hash() -> str:
        module = importlib.import_module("quant_hub.ops.production_host_facts_cli")
        return sha(Path(module.__file__).read_bytes())

    def _manual_challenge(self) -> tuple[dict[str, object], Path]:
        payload: dict[str, object] = {
            "schema_version": CHALLENGE_SCHEMA,
            "challenge_id": "manual-challenge",
            "issued_at": CHALLENGE_TIME,
            "issuer": {
                "producer_id": "qrh-failure-domain-challenge-issuer",
                "producer_tool_sha256": self._rotation_module_hash(),
            },
        }
        payload["challenge_sha256"] = sha(canonical_bytes(payload))
        return payload, self._write("failure-domain/challenges/manual-challenge.json", payload)

    def _manual_capture(
        self, kind: str, source: dict[str, object]
    ) -> tuple[dict[str, object], Path]:
        producer_ids = {
            "production_facts": "qrh-production-host-facts",
            "recovery_facts": "qrh-failure-domain-recovery-facts",
            "independence_probe": "qrh-failure-domain-independence-probe",
        }
        tool_hash = (
            self._production_module_hash()
            if kind == "production_facts"
            else self._rotation_module_hash()
        )
        payload: dict[str, object] = {
            "schema_version": CAPTURE_SCHEMA,
            "source_kind": kind,
            "challenge_id": self.challenge["challenge_id"],
            "challenge_sha256": sha(self.challenge_path.read_bytes()),
            "captured_at": CAPTURE_TIME,
            "producer": {
                "producer_id": producer_ids[kind],
                "producer_tool_sha256": tool_hash,
            },
            "source_sha256": sha(canonical_bytes(source)),
            "source": source,
        }
        payload["capture_sha256"] = sha(canonical_bytes(payload))
        path = self._write(
            f"failure-domain/captures/manual-challenge/{kind}.json", payload
        )
        return payload, path

    def _manual_observation(self) -> tuple[dict[str, object], Path]:
        built = attest_failure_domain(
            production_facts=self.production,
            recovery_facts=self.recovery,
            independence_probe=self.probe,
            observed_at=OBSERVATION_TIME,
        )
        sources = {
            "production_facts": self.production,
            "recovery_facts": self.recovery,
            "independence_probe": self.probe,
        }
        payload: dict[str, object] = {
            "schema_version": OBSERVATION_SCHEMA,
            "observation_id": "failure-domain-observation-manual-challenge",
            "observed_at": OBSERVATION_TIME,
            "producer": {
                "producer_id": "qrh-failure-domain-observer",
                "producer_tool_sha256": self._rotation_module_hash(),
            },
            "challenge_id": self.challenge["challenge_id"],
            "challenge_path": "failure-domain/challenges/manual-challenge.json",
            "challenge_file_sha256": sha(self.challenge_path.read_bytes()),
            "challenge_sha256": self.challenge["challenge_sha256"],
            "source_capture_path": {
                kind: path.relative_to(self.root).as_posix()
                for kind, (_, path) in self.captures.items()
            },
            "source_capture_file_sha256": {
                kind: sha(path.read_bytes())
                for kind, (_, path) in self.captures.items()
            },
            "source_file_sha256": {
                kind: sha(canonical_bytes(source)) for kind, source in sources.items()
            },
            "source_captured_at": {kind: CAPTURE_TIME for kind in sources},
            "production": self.production,
            "recovery": self.recovery,
            "independence_probe": self.probe,
            "next_attestation_sha256": built.sha256,
        }
        payload["observation_sha256"] = sha(canonical_bytes(payload))
        return payload, self._write(
            "failure-domain/observations/manual-challenge.json", payload
        )

    def _prepare_args(self, mode: str) -> dict[str, object]:
        return {
            "mode": mode,
            "recovery_root": self.root,
            "current_path": self.current,
            "observation_path": self.observation_path,
            "expected_current_file_sha256": sha(self.current.read_bytes()),
            "expected_observation_file_sha256": sha(self.observation_path.read_bytes()),
            "max_age_seconds": 300,
            "rotation_id": "rotation-r4",
            "intent_path": self.root / "failure-domain/intents/rotation-r4.json",
        }

    def test_prepare_rejects_before_any_file_access_or_mutation(self) -> None:
        isolated = self.root / "untouched"
        before = tree_identity(self.root)
        with self.assertRaisesRegex(FailureDomainRotationError, "FAKE_ONLY/NOT_READY"):
            prepare_rotation(
                mode="prepare",
                recovery_root=isolated,
                current_path=isolated / "missing-current.json",
                observation_path=isolated / "missing-observation.json",
                expected_current_file_sha256="0" * 64,
                expected_observation_file_sha256="0" * 64,
                max_age_seconds=300,
                rotation_id="never-written",
                intent_path=isolated / "missing-intent.json",
            )
        self.assertEqual(before, tree_identity(self.root))
        self.assertFalse(isolated.exists())

    def test_manual_current_hash_lineage_is_diagnostic_only_and_read_only(self) -> None:
        before = tree_identity(self.root)
        with patch(
            "quant_hub.ops.failure_domain_rotation._now_utc",
            return_value=INSPECT_TIME,
        ):
            result = prepare_rotation(**self._prepare_args("inspect"))
        self.assertEqual("DIAGNOSTIC_ONLY", result["status"])
        self.assertFalse(result["authority"])
        self.assertEqual(ROTATION_READINESS, result["rotation_readiness"])
        self.assertEqual(DIAGNOSTIC_READINESS, result["diagnostic_readiness"])
        self.assertEqual(before, tree_identity(self.root))
        self.assertFalse((self.root / "failure-domain/intents").exists())

    def test_formal_apply_and_verify_are_not_importable_mutating_cores(self) -> None:
        module = importlib.import_module("quant_hub.ops.failure_domain_rotation")
        forbidden = {
            "_apply_rotation_core",
            "_atomic_replace_current",
            "_write_new_bytes",
            "_write_new_document",
            "_rotation_lock",
            "issue_challenge",
            "capture_recovery_facts",
            "capture_independence_probe",
            "create_observation",
        }
        self.assertTrue(forbidden.isdisjoint(vars(module)))
        for callable_value in (apply_rotation, verify_current_attestation):
            with self.assertRaisesRegex(
                FailureDomainRotationError, "FAKE_ONLY/NOT_READY"
            ):
                callable_value(
                    recovery_root=self.root,
                    current_path=self.current,
                    completion_path=self.root / "missing.json",
                )

    def test_product_rotation_ast_has_no_filesystem_mutator(self) -> None:
        module = importlib.import_module("quant_hub.ops.failure_domain_rotation")
        source = Path(module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden_attributes = {
            "write_bytes",
            "write_text",
            "mkdir",
            "unlink",
            "rename",
            "link",
            "symlink_to",
            "fsync",
        }
        observed = {
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertTrue(forbidden_attributes.isdisjoint(observed), observed)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                self.assertNotEqual("open", node.func.id)
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "os"
            ):
                self.assertNotIn(node.func.attr, {"replace", "link", "open"})

    def test_cli_statuses_close_without_tree_mutation(self) -> None:
        disabled = (
            ["issue-challenge", "--recovery-root", str(self.root / "missing")],
            [
                "capture-recovery-facts", "--recovery-root",
                str(self.root / "missing"), "--challenge",
                str(self.root / "missing-challenge"),
            ],
            [
                "capture-independence-probe", "--recovery-root",
                str(self.root / "missing"), "--challenge",
                str(self.root / "missing-challenge"), "--bundle-root",
                str(self.root / "missing-bundle"), "--materialization-event",
                str(self.root / "missing-event"), "--probe-tool",
                str(self.root / "missing-tool"),
            ],
            [
                "observe", "--recovery-root", str(self.root / "missing"),
                "--challenge", str(self.root / "missing-challenge"),
                "--production-capture", str(self.root / "missing-production"),
                "--recovery-capture", str(self.root / "missing-recovery"),
                "--independence-capture", str(self.root / "missing-probe"),
                "--output", str(self.root / "missing-output"),
            ],
            [
                "rotate-prepare", "--mode", "prepare",
                "--recovery-root", str(self.root / "missing"),
                "--current", str(self.root / "missing-current"),
                "--observation", str(self.root / "missing-observation"),
                "--expected-current-file-sha256", "0" * 64,
                "--expected-observation-file-sha256", "0" * 64,
                "--max-age-seconds", "300", "--rotation-id", "r4",
                "--intent-output", str(self.root / "missing-intent"),
            ],
            [
                "rotate-apply", "--recovery-root", str(self.root / "missing"),
                "--current", str(self.root / "missing-current"),
                "--observation", str(self.root / "missing-observation"),
                "--intent", str(self.root / "missing-intent"),
                "--expected-current-file-sha256", "0" * 64,
                "--expected-observation-file-sha256", "0" * 64,
                "--expected-intent-file-sha256", "0" * 64,
                "--max-age-seconds", "300",
            ],
            [
                "verify-current", "--recovery-root", str(self.root / "missing"),
                "--current", str(self.root / "missing-current"),
                "--expected-current-file-sha256", "0" * 64,
                "--completion", str(self.root / "missing-completion"),
                "--expected-completion-file-sha256", "0" * 64,
                "--max-age-seconds", "300",
            ],
        )
        for argv in disabled:
            before = tree_identity(self.root)
            output = io.StringIO()
            with self.subTest(command=argv[0]), redirect_stdout(output):
                self.assertEqual(2, main(argv))
            result = json.loads(output.getvalue())
            self.assertEqual("NOT_READY", result["status"])
            self.assertFalse(result["authority"])
            self.assertNotEqual("PASS", result["status"])
            self.assertEqual(before, tree_identity(self.root))

    def test_inspect_cli_is_diagnostic_only_and_does_not_write_intent(self) -> None:
        values = self._prepare_args("inspect")
        argv = [
            "rotate-prepare", "--mode", "inspect",
            "--recovery-root", str(values["recovery_root"]),
            "--current", str(values["current_path"]),
            "--observation", str(values["observation_path"]),
            "--expected-current-file-sha256",
            str(values["expected_current_file_sha256"]),
            "--expected-observation-file-sha256",
            str(values["expected_observation_file_sha256"]),
            "--max-age-seconds", str(values["max_age_seconds"]),
            "--rotation-id", str(values["rotation_id"]),
            "--intent-output", str(values["intent_path"]),
        ]
        before = tree_identity(self.root)
        output = io.StringIO()
        with patch(
            "quant_hub.ops.failure_domain_rotation._now_utc",
            return_value=INSPECT_TIME,
        ), redirect_stdout(output):
            self.assertEqual(0, main(argv))
        result = json.loads(output.getvalue())
        self.assertEqual("DIAGNOSTIC_ONLY", result["status"])
        self.assertFalse(result["authority"])
        self.assertEqual(before, tree_identity(self.root))
        self.assertFalse(Path(values["intent_path"]).exists())

    def test_legacy_current_remains_diagnostic_only(self) -> None:
        before = tree_identity(self.root)
        with patch(
            "quant_hub.ops.failure_domain_rotation._now_utc",
            return_value=INSPECT_TIME,
        ):
            result = diagnose_legacy_current_attestation(
                recovery_root=self.root,
                current_path=self.current,
                expected_current_file_sha256=sha(self.current.read_bytes()),
                max_age_seconds=300,
            )
        self.assertEqual("DIAGNOSTIC_ONLY", result["status"])
        self.assertTrue(result["legacy_diagnostic_only"])
        self.assertFalse(result["authority"])
        self.assertEqual(before, tree_identity(self.root))

    def test_attestation_payload_drift_and_json_adversaries_fail_closed(self) -> None:
        current = json.loads(self.current.read_bytes())
        current["verdict"] = "third-party-pass"
        with self.assertRaisesRegex(FailureDomainRotationError, "identity differs"):
            _verify_attestation(canonical_bytes(current))
        invalid = (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            (b'{"a":' * 1500) + b"0" + (b"}" * 1500),
            b'{"a":"' + (b"x" * (2 * 1024 * 1024)) + b'"}',
        )
        for raw in invalid:
            with self.subTest(size=len(raw)), self.assertRaises(
                FailureDomainRotationError
            ):
                _canonical_object(raw, label="adversarial")

    def test_changed_file_source_manifest_matches_independent_recalculation(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        result = diagnostic_source_manifest(
            repo_root=repo_root,
            repo_relative_paths=tuple(reversed(CHANGED_FILE_MANIFEST)),
        )
        payload = bytearray()
        for relative in sorted(
            CHANGED_FILE_MANIFEST, key=lambda item: item.encode("utf-8")
        ):
            digest = sha((repo_root / relative).read_bytes())
            payload.extend(relative.encode("utf-8"))
            payload.extend(b"\0")
            payload.extend(digest.encode("ascii"))
            payload.extend(b"\0")
        self.assertEqual(len(CHANGED_FILE_MANIFEST), len(result["entries"]))
        self.assertEqual(sha(bytes(payload)), result["manifest_sha256"])
        self.assertEqual("DIAGNOSTIC_ONLY", result["status"])
        self.assertFalse(result["authority"])

    def test_unique_authority_gate_is_closed_and_has_no_path_input(self) -> None:
        status = failure_domain_authority_status()
        self.assertEqual("NOT_READY", status["status"])
        self.assertFalse(status["authority"])
        self.assertEqual(AUTHORITY_ERROR_CODE, status["error_code"])
        with self.assertRaises(FailureDomainAuthorityNotReady) as caught:
            require_failure_domain_authority()
        self.assertEqual(AUTHORITY_ERROR_CODE, caught.exception.code)
        self.assertFalse(caught.exception.authority)

    def test_formal_entry_matrix_rejects_before_config_path_git_or_remote(self) -> None:
        from quant_hub.ops import publish as publish_module
        from quant_hub.ops import publish_recovery_cli as recovery_module
        from quant_hub.ops import publish_runtime as runtime_module
        from quant_hub.ops import writer_handoff_client as client_module

        missing = self.root / "formal-entry-must-not-be-read"
        expected = failure_domain_authority_status()
        before = tree_identity(self.root)
        spies = {
            "open": Mock(side_effect=AssertionError("open reached")),
            "path_open": Mock(side_effect=AssertionError("Path.open reached")),
            "read_bytes": Mock(side_effect=AssertionError("read_bytes reached")),
            "read_text": Mock(side_effect=AssertionError("read_text reached")),
            "config": Mock(side_effect=AssertionError("config load reached")),
            "git": Mock(side_effect=AssertionError("Git subprocess reached")),
            "remote": Mock(side_effect=AssertionError("remote client reached")),
            "root": Mock(side_effect=AssertionError("VM root reached")),
            "snapshot": Mock(side_effect=AssertionError("write snapshot reached")),
            "json_read": Mock(side_effect=AssertionError("evidence read reached")),
        }
        public_calls = (
            lambda: recovery_module.capture(
                vm_root=missing,
                checkpoint_id="checkpoint-never",
                state_authority_id="authority-never",
            ),
            lambda: recovery_module.capture_legacy(
                vm_root=missing,
                checkpoint_id="checkpoint-never",
                state_authority_id="authority-never",
                release_id="release-never",
                release_manifest_sha256="a" * 64,
            ),
            lambda: recovery_module.identify_active(vm_root=missing),
            lambda: recovery_module.cleanup_capture(
                vm_root=missing, checkpoint_id="checkpoint-never"
            ),
            lambda: recovery_module.register(
                vm_root=missing,
                release_id="release-never",
                release_manifest_sha256="a" * 64,
                publish_candidate_sha256="b" * 64,
                deployment_attempt_id="attempt-never",
                checkpoint_manifest_path=missing / "checkpoint.json",
                recovery_manifest_path=missing / "recovery.json",
                protection_evidence_path=missing / "evidence.json",
            ),
        )
        cli_calls = (
            (
                publish_module.main,
                ["--project-root", str(missing), "--dry-run"],
            ),
            (
                publish_module.main,
                [
                    "--project-root", str(missing), "--config",
                    str(missing / "runtime.json"),
                ],
            ),
            (
                client_module.main,
                [
                    "--config", str(missing / "runtime.json"),
                    "--project-root", str(missing),
                    "--release-manifest-sha256", "a" * 64,
                    "run",
                ],
            ),
            (
                client_module.main,
                [
                    "--config", str(missing / "runtime.json"),
                    "--project-root", str(missing),
                    "--release-manifest-sha256", "a" * 64,
                    "status", "--inspection-sha256", "b" * 64,
                ],
            ),
            (
                client_module.main,
                [
                    "--config", str(missing / "runtime.json"),
                    "--project-root", str(missing),
                    "--release-manifest-sha256", "a" * 64,
                    "finalize", "--inspection-sha256", "b" * 64,
                ],
            ),
            (
                recovery_module.main,
                [
                    "capture", "--vm-root", str(missing),
                    "--checkpoint-id", "checkpoint-never",
                    "--state-authority-id", "authority-never",
                ],
            ),
            (
                recovery_module.main,
                [
                    "capture-legacy", "--vm-root", str(missing),
                    "--checkpoint-id", "checkpoint-never",
                    "--state-authority-id", "authority-never",
                    "--release-id", "release-never",
                    "--release-manifest-sha256", "a" * 64,
                ],
            ),
            (
                recovery_module.main,
                ["identify-active", "--vm-root", str(missing)],
            ),
            (
                recovery_module.main,
                [
                    "cleanup-capture", "--vm-root", str(missing),
                    "--checkpoint-id", "checkpoint-never",
                ],
            ),
            (
                recovery_module.main,
                [
                    "register", "--vm-root", str(missing),
                    "--release-id", "release-never",
                    "--release-manifest-sha256", "a" * 64,
                    "--publish-candidate-sha256", "b" * 64,
                    "--deployment-attempt-id", "attempt-never",
                    "--checkpoint-manifest", str(missing / "checkpoint.json"),
                    "--recovery-manifest", str(missing / "recovery.json"),
                    "--protection-evidence", str(missing / "evidence.json"),
                ],
            ),
        )
        with ExitStack() as stack:
            stack.enter_context(patch("builtins.open", spies["open"]))
            stack.enter_context(patch.object(Path, "open", spies["path_open"]))
            stack.enter_context(patch.object(Path, "read_bytes", spies["read_bytes"]))
            stack.enter_context(patch.object(Path, "read_text", spies["read_text"]))
            stack.enter_context(
                patch.object(
                    runtime_module.RuntimePublishConfig, "load", spies["config"]
                )
            )
            stack.enter_context(patch.object(publish_module.subprocess, "run", spies["git"]))
            stack.enter_context(
                patch.object(client_module, "_client_from_runtime_config", spies["remote"])
            )
            stack.enter_context(patch.object(recovery_module, "_root", spies["root"]))
            stack.enter_context(
                patch.object(
                    recovery_module, "capture_vm_write_snapshot", spies["snapshot"]
                )
            )
            stack.enter_context(patch.object(recovery_module, "read_json", spies["json_read"]))
            for call in public_calls:
                with self.subTest(public=call), self.assertRaises(
                    FailureDomainAuthorityNotReady
                ) as caught:
                    call()
                self.assertEqual(AUTHORITY_ERROR_CODE, caught.exception.code)
            for entry, argv in cli_calls:
                output = io.StringIO()
                with self.subTest(entry=entry.__module__, command=argv[0]), redirect_stdout(
                    output
                ):
                    self.assertEqual(2, entry(argv))
                rendered = output.getvalue()
                self.assertEqual(expected, json.loads(rendered))
                self.assertNotIn(str(missing), rendered)
        for label, spy in spies.items():
            with self.subTest(spy=label):
                spy.assert_not_called()
        self.assertEqual(before, tree_identity(self.root))
        self.assertFalse(missing.exists())

    def test_real_product_consumers_reject_v1_before_evidence_access(self) -> None:
        from quant_hub.ops.cold_bundle_cli import ColdBundleBuilder, main as cold_bundle_main
        from quant_hub.ops.cold_restore_cli import OpenSSHColdRestore
        from quant_hub.ops.publish_recovery_cli import main as recovery_main, register
        from quant_hub.ops.publish_runtime import (
            ProductionPublishRuntime,
            RecoveryProtectionCoordinator,
            UnavailableRecoveryActions,
        )
        from quant_hub.ops.stage_closure import (
            DirectoryEvidenceResolver,
            build_stage5_release_certificate,
            verify_failure_domain_attestation,
        )
        from quant_hub.ops.state_only_backup import (
            apply_task_candidate,
            build_task_candidate,
            run_state_only_backup,
            validate_task_candidate,
        )
        from quant_hub.ops.writer_handoff import (
            V39Baseline,
            apply_writer_handoff,
            finalize_writer_handoff,
            inspect_writer_handoff,
            inspect_writer_handoff_status,
        )

        attestation = json.loads(self.current.read_bytes())
        missing = self.root / "must-not-be-read"
        recovery = SimpleNamespace(
            recovery_root=missing,
            attestation_path=missing / "legacy-v1.json",
        )
        config = SimpleNamespace(
            vm=SimpleNamespace(target_address="10.5.1.240"),
            recovery=recovery,
            project_root=missing,
        )
        coordinator = RecoveryProtectionCoordinator(
            recovery, actions=UnavailableRecoveryActions()
        )
        cold_bundle = ColdBundleBuilder(config)
        cold_restore = OpenSSHColdRestore(config)
        baseline = V39Baseline("a" * 64)
        nonce = "a" * 48
        calls = (
            coordinator._attestation,
            coordinator.preflight,
            lambda: ProductionPublishRuntime.publish(
                object.__new__(ProductionPublishRuntime),
                commit_sha="a" * 40,
                candidate_only=True,
            ),
            lambda: cold_bundle.build(
                release_root=missing, bundle_id="never", state_source="d_active"
            ),
            lambda: cold_bundle_main(
                [
                    "--config", str(missing / "config.json"),
                    "--project-root", str(missing),
                    "--release-root", str(missing),
                    "--bundle-id", "never",
                    "--state-source", "d_active",
                ]
            ),
            lambda: register(
                vm_root=missing,
                release_id="never",
                release_manifest_sha256="a" * 64,
                publish_candidate_sha256="b" * 64,
                deployment_attempt_id="never",
                checkpoint_manifest_path=missing / "checkpoint.json",
                recovery_manifest_path=missing / "recovery.json",
                protection_evidence_path=missing / "v1.json",
            ),
            lambda: cold_restore.inspect_prepare_empty(
                missing,
                intent_nonce="never-inspect-authority",
                expected_legacy_deployment_id="never",
                qualification_reset_materialized=True,
            ),
            lambda: cold_restore.apply_prepare_empty(
                missing,
                intent_nonce="never-apply-authority",
                expected_pre_delete_inventory_sha256="c" * 64,
                expected_legacy_deployment_id="never",
                qualification_reset_materialized=True,
            ),
            lambda: cold_restore.restore(
                missing, evidence_output=missing / "restore.json"
            ),
            lambda: verify_failure_domain_attestation(attestation),
            lambda: build_stage5_release_certificate(
                issued_at=INSPECT_TIME,
                artifact_refs={},
                gate_evidence=(),
                runbook_evidence=(),
                resolver=DirectoryEvidenceResolver(missing),
            ),
            lambda: run_state_only_backup(config=config, vm=object()),
            lambda: build_task_candidate(
                config_path=missing / "config.json",
                project_root=missing,
                operational_root=missing,
                operational_python=missing / "python.exe",
                recovery_root=missing,
                failure_domain_attestation_path=missing / "v1.json",
            ),
            lambda: validate_task_candidate(attestation),
            lambda: apply_task_candidate(
                attestation, adapter=object(), allow_os_registration=True
            ),
            lambda: inspect_writer_handoff(
                vm_root=missing,
                baseline=baseline,
                runtime=object(),
                nonce=nonce,
                allow_test_root=True,
            ),
            lambda: apply_writer_handoff(
                vm_root=missing,
                baseline=baseline,
                runtime=object(),
                inspection_receipt=attestation,
                expected_inspection_sha256="d" * 64,
                nonce=nonce,
                allow_test_root=True,
            ),
            lambda: finalize_writer_handoff(
                vm_root=missing,
                baseline=baseline,
                runtime=object(),
                attempt_id="never",
                nonce=nonce,
                allow_test_root=True,
            ),
            lambda: inspect_writer_handoff_status(
                vm_root=missing,
                baseline=baseline,
                inspection_sha256="e" * 64,
                nonce=nonce,
                allow_test_root=True,
            ),
        )
        before = tree_identity(self.root)
        for call in calls:
            with self.subTest(call=call), self.assertRaisesRegex(
                FailureDomainAuthorityNotReady, AUTHORITY_ERROR_CODE
            ):
                call()
            self.assertEqual(before, tree_identity(self.root))
            self.assertFalse(missing.exists())

    def test_legacy_source_cli_is_zero_mutation_not_ready(self) -> None:
        from tools.release import failure_domain_cli as legacy_cli

        self.assertNotIn("_write_new", vars(legacy_cli))
        missing = self.root / "legacy-cli-must-not-write"
        commands = (
            [
                "facts", "--root", str(missing), "--role", "recovery",
                "--output", str(missing / "current.json"),
            ],
            [
                "attest", "--production-facts", str(missing / "p.json"),
                "--recovery-facts", str(missing / "r.json"),
                "--independence-probe", str(missing / "i.json"),
                "--observed-at", INSPECT_TIME,
                "--output", str(missing / "current.json"),
            ],
            [
                "independence-probe", "--recovery-root", str(missing),
                "--bundle-root", str(missing / "bundle"),
                "--materialization-event", str(missing / "event.json"),
                "--probe-tool", str(missing / "tool.py"),
                "--output", str(missing / "current.json"),
            ],
        )
        before = tree_identity(self.root)
        for argv in commands:
            output = io.StringIO()
            with self.subTest(command=argv[0]), redirect_stdout(output):
                self.assertEqual(2, legacy_cli.main(argv))
            result = json.loads(output.getvalue())
            self.assertEqual("NOT_READY", result["status"])
            self.assertFalse(result["authority"])
            self.assertFalse(result["output_created"])
            self.assertNotEqual("PASS", result["status"])
            self.assertEqual(before, tree_identity(self.root))
            self.assertFalse(missing.exists())

    def test_installed_package_public_surface_and_ast_are_read_only(self) -> None:
        """Build/install the wheel and repeat the public/AST assertions there."""

        repo_root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "site"
            wheelhouse = Path(temporary) / "wheelhouse"
            subprocess.run(
                [
                    sys.executable, "-m", "pip", "wheel", "--no-deps",
                    "--no-build-isolation", "--wheel-dir", str(wheelhouse),
                    str(repo_root / "quant_hub"),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            wheel = next(wheelhouse.glob("*.whl"))
            subprocess.run(
                [
                    sys.executable, "-m", "pip", "install", "--no-deps",
                    "--target", str(target), str(wheel),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            script = """
import sys
sys.path.insert(0, __TARGET__)
import ast
import subprocess
from pathlib import Path, PureWindowsPath
import quant_hub.ops.failure_domain_rotation as module
installed_module = Path(module.__file__).resolve()
assert installed_module.is_relative_to(Path(__TARGET__).resolve()), installed_module
assert not installed_module.is_relative_to(Path(__REPO__).resolve()), installed_module
forbidden = {'_apply_rotation_core', '_atomic_replace_current', '_write_new_bytes',
             '_write_new_document', '_rotation_lock', 'issue_challenge',
             'capture_recovery_facts', 'capture_independence_probe',
             'create_observation'}
assert forbidden.isdisjoint(vars(module)), forbidden & set(vars(module))
tree = ast.parse(Path(module.__file__).read_text(encoding='utf-8'))
mutators = {'write_bytes', 'write_text', 'mkdir', 'unlink', 'rename',
            'link', 'symlink_to', 'fsync'}
calls = {n.func.attr for n in ast.walk(tree)
         if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
assert mutators.isdisjoint(calls), mutators & calls
for node in ast.walk(tree):
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name) and node.func.value.id == 'os'):
        assert node.func.attr not in {'replace', 'link', 'open'}

# Exercise the actual installed product call graph with a fresh, self-consistent
# legacy v1 document. Every formal path must stop at the one v2 authority gate
# before consulting the deliberately absent evidence tree.
import hashlib
import importlib.metadata
import json
import os
import tempfile
import builtins
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace as NS
from quant_hub.ops.failure_domain import FACTS_SCHEMA, PROBE_SCHEMA, attest_failure_domain, canonical_bytes
from quant_hub.ops.failure_domain_authority import FailureDomainAuthorityNotReady, failure_domain_authority_status
import quant_hub.ops.publish as publish_module
import quant_hub.ops.publish_adapters as adapters_module
import quant_hub.ops.publish_recovery_cli as recovery_module
import quant_hub.ops.publish_runtime as runtime_module
import quant_hub.ops.writer_handoff as handoff_module
import quant_hub.ops.writer_handoff_client as client_module
from quant_hub.ops.publish import PublishCoordinator, PublishPipeline, PublishQueue
from quant_hub.ops.publish_adapters import CommandResult, GitHubExactSHACI, HTTPResponse, IncrementalVMTransport, OpenSSHDeploymentInvoker, OpenSSHVMBackend, ProductionPublishConfig, VMDeploymentAdapter
from quant_hub.ops.publish_runtime import ExactGitPush, FixedLocalGates, OpenSSHRecoveryActions, ProcessResult, ProductionPublishRuntime, ProductionSourceFreezer, PublishRuntimeError, RecoveryProtectionCoordinator, UnavailableRecoveryActions, UnavailableRecoveryProtector
from quant_hub.ops.cold_bundle_cli import ColdBundleBuilder, main as cold_bundle_main
from quant_hub.ops.cold_restore_cli import OpenSSHColdRestore
from quant_hub.ops.publish_recovery_cli import capture, capture_legacy, cleanup_capture, identify_active, main as recovery_main, register
from quant_hub.ops.stage_closure import DirectoryEvidenceResolver, build_stage5_release_certificate, verify_failure_domain_attestation
from quant_hub.ops.state_only_backup import apply_task_candidate, build_task_candidate, run_state_only_backup, validate_task_candidate
from quant_hub.ops.writer_handoff import V39Baseline, WindowsHandoffRuntime, apply_writer_handoff, finalize_writer_handoff, inspect_writer_handoff, inspect_writer_handoff_status, seed_v39_access_identity
from quant_hub.ops.writer_handoff_client import WriterHandoffClient

# Rebuild the closed API inventory from this freshly installed wheel.  This is
# intentionally independent of the source checkout and fails if a new exported
# callable has not been classified.
classification = __CLASSIFICATION__
source_inventory = set(__SOURCE_INVENTORY__)
surface_modules = ('publish', 'publish_adapters', 'publish_recovery_cli',
                   'publish_runtime', 'writer_handoff', 'writer_handoff_client')
internal_factories = {'writer_handoff_client': ('_client_from_runtime_config',)}
inventory = set(); surface_nodes = {}
for short_name in surface_modules:
    product = __import__('quant_hub.ops.' + short_name, fromlist=['*'])
    parsed = ast.parse(Path(product.__file__).read_text(encoding='utf-8'))
    for node in parsed.body:
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name.startswith('_'):
                continue
            key = short_name + ':' + node.name; inventory.add(key); surface_nodes[key] = node
            if isinstance(node, ast.ClassDef):
                for method in node.body:
                    if (isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and (method.name == '__call__' or not method.name.startswith('_'))):
                        method_key = key + '.' + method.name
                        inventory.add(method_key); surface_nodes[method_key] = method
            continue
        assigned = []
        if isinstance(node, ast.Assign):
            assigned = [target.id for target in node.targets if isinstance(target, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            assigned = [node.target.id]
        for name in assigned:
            if name.startswith('_') or not callable(getattr(product, name, None)):
                continue
            key = short_name + ':' + name
            inventory.add(key); surface_nodes[key] = node
    for factory_name in internal_factories.get(short_name, ()):
        factory = next(node for node in parsed.body if isinstance(node, ast.FunctionDef)
                       and node.name == factory_name)
        inventory.add(short_name + ':' + factory_name)
        surface_nodes[short_name + ':' + factory_name] = factory
    declared = getattr(product, '__all__', None)
    if declared is not None:
        assert isinstance(declared, list) and len(declared) == len(set(declared)), short_name
        for name in declared:
            assert isinstance(name, str) and name and not name.startswith('_'), (short_name, name)
            assert hasattr(product, name), (short_name, name)
            if callable(getattr(product, name)):
                assert short_name + ':' + name in inventory, (short_name, name)
category_sets = [set(rows) for rows in classification.values()]
for index, left in enumerate(category_sets):
    for right in category_sets[index + 1:]: assert not left & right, left & right
assert inventory == source_inventory, (inventory ^ source_inventory)
assert set().union(*category_sets) == inventory, (set().union(*category_sets) ^ inventory)
inventory_report = {'inventory_total': len(inventory),
                    'category_counts': {name: len(rows) for name, rows in classification.items()}}
assert len(inventory) == sum(inventory_report['category_counts'].values()), inventory_report
def first_effective(node):
    if isinstance(node, ast.ClassDef):
        node = next(child for child in node.body if isinstance(child, ast.FunctionDef)
                    and child.name == '__init__')
    body = list(node.body)
    if (body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)): body = body[1:]
    return body[0]
for surface in classification['FAILURE_DOMAIN_GATED']:
    first = first_effective(surface_nodes[surface])
    assert (isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
            and isinstance(first.value.func, ast.Name)
            and first.value.func.id == 'require_failure_domain_authority'
            and not first.value.args and not first.value.keywords), surface
exact_push_node = surface_nodes['publish_runtime:ExactGitPush.__call__']
exact_push_gates = [call for call in ast.walk(exact_push_node)
                    if isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id == 'require_failure_domain_authority'
                    and not call.args and not call.keywords]
assert len(exact_push_gates) == 1
assert 'subprocess_runner' not in vars(adapters_module)
assert 'urllib_http_get' not in vars(adapters_module)
assert 'production_process_runner' not in vars(runtime_module)

# Exercise the explicitly allowed diagnostics with injected boundaries. Git
# inspection must leave even temporary repository metadata byte-identical;
# remote inventory may execute one read-only injected SSH boundary, but its
# generated script must contain no creation, move or deletion command.
def file_tree(directory):
    return tuple((str(item.relative_to(directory)), item.stat().st_size,
                  hashlib.sha256(item.read_bytes()).hexdigest())
                 for item in sorted(directory.rglob('*')) if item.is_file())
with tempfile.TemporaryDirectory() as diagnostic_temp:
    diagnostic_repo = Path(diagnostic_temp) / 'repo'; diagnostic_repo.mkdir()
    subprocess.run(['git', 'init', '-b', 'main'], cwd=diagnostic_repo, check=True,
                   capture_output=True)
    subprocess.run(['git', 'config', 'user.email', 'wheel@example.invalid'],
                   cwd=diagnostic_repo, check=True)
    subprocess.run(['git', 'config', 'user.name', 'wheel'], cwd=diagnostic_repo, check=True)
    (diagnostic_repo / 'tracked.txt').write_bytes(b'exact\\n')
    subprocess.run(['git', 'add', 'tracked.txt'], cwd=diagnostic_repo, check=True)
    subprocess.run(['git', 'commit', '-m', 'fixture'], cwd=diagnostic_repo,
                   check=True, capture_output=True)
    head = subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=diagnostic_repo,
                          check=True, capture_output=True, text=True).stdout.strip()
    before_diagnostic = file_tree(diagnostic_repo)
    git_result = publish_module.inspect_local_git(diagnostic_repo, head)
    plan = publish_module.dry_run_plan(diagnostic_repo, head)
    assert file_tree(diagnostic_repo) == before_diagnostic
    assert git_result.tracked_clean is True and plan['external_actions_executed'] is False
    assert not ({'authority', 'failure_domain_attestation', 'receipt'} & set(plan))

    qualification_calls = []
    def qualification_runner(arguments, cwd):
        qualification_calls.append((tuple(arguments), cwd))
        return ProcessResult(0, '')
    local_gates = FixedLocalGates(NS(project_root=diagnostic_repo), qualification_runner)
    local_results = (local_gates.tests(git_result), local_gates.public(git_result))
    assert all(result.status == 'pass' for result in local_results)
    assert all(call[1] == diagnostic_repo for call in qualification_calls)
    assert all('-B' in call[0] for call in qualification_calls)

    publish_config = ProductionPublishConfig.parse({
        'schema_version': 'qrh-production-publish-config/v1',
        'github': {'owner': 'owner', 'repository': 'repository', 'workflow_id': 1,
                   'credential_target': None, 'poll_interval_seconds': 1,
                   'timeout_seconds': 10},
        'vm': {'ssh_alias': 'honghu-vm', 'target_address': '10.5.1.240',
               'root': r'D:\\quant\\quant_platform'},
    })
    ci_body = json.dumps({'workflow_runs': [{
        'id': 1, 'workflow_id': 1, 'head_sha': head, 'head_branch': 'main',
        'event': 'push', 'status': 'completed', 'conclusion': 'success',
        'repository': {'full_name': 'owner/repository'},
    }]}).encode('utf-8')
    ci_result = GitHubExactSHACI(
        publish_config.github,
        secret_provider=lambda _: None,
        http_get=lambda *_: HTTPResponse(200, ci_body),
    )(head)
    assert ci_result.status == 'success' and not hasattr(ci_result, 'authority')
    assert file_tree(diagnostic_repo) == before_diagnostic

    remote_scripts = []
    def readonly_runner(arguments):
        remote_scripts.append(adapters_module.base64.b64decode(arguments[-1]).decode('utf-16-le'))
        return CommandResult(0, '[]')
    inventory_result = OpenSSHVMBackend(
        publish_config.vm, command_runner=readonly_runner
    ).inventory(
        PureWindowsPath(r'D:\\quant\\quant_platform\\incoming\\existing.partial')
    )
    assert inventory_result == {} and len(remote_scripts) == 1
    assert all(token not in remote_scripts[0] for token in ('New-Item', 'Move-Item', 'Remove-Item'))

def digest(raw): return hashlib.sha256(raw).hexdigest()
def facts(role, root):
    machine = 'vm-240' if role == 'production' else 'recovery-host'
    volume = 'volume-d' if role == 'production' else 'volume-r'
    value = {'schema_version': FACTS_SCHEMA, 'role': role, 'host_name': machine,
             'machine_identity': machine, 'canonical_path': root,
             'path_kind': 'local', 'reparse_or_symlink': False,
             'volume_identity': volume, 'storage_backend': 'local-ntfs:' + volume,
             'storage_authority': machine + '|' + volume, 'tool_version': 'wheel-test/v1'}
    value['facts_sha256'] = digest(canonical_bytes(value)); return value

with tempfile.TemporaryDirectory() as td:
    root = Path(td).resolve(); missing = root / 'must-not-be-read'
    production = facts('production', r'D:\\quant\\quant_platform')
    recovery_facts = facts('recovery', str(root))
    probe = {'schema_version': PROBE_SCHEMA, 'production_root_available': False,
             'recovery_bundle_readable': True, 'closure_verified': True,
             'empty_root_precondition': True, 'bundle_id': 'bundle-v39',
             'release_id': 'release-v39', 'release_manifest_sha256': 'c' * 64,
             'bundle_inventory_sha256': 'a' * 64,
             'materialization_event_id': 'cold-materialization-bundle-v39',
             'materialization_event_sha256': 'd' * 64, 'probe_tool_sha256': 'b' * 64}
    diagnostic = attest_failure_domain(production_facts=production,
        recovery_facts=recovery_facts, independence_probe=probe,
        observed_at='2026-08-23T08:00:15Z')
    assert diagnostic.status == 'DIAGNOSTIC_ONLY' and diagnostic.authority is False
    v1 = {**diagnostic.payload, 'attestation_sha256': diagnostic.sha256}
    recovery = NS(recovery_root=missing, attestation_path=missing / 'v1.json')
    config = NS(vm=NS(target_address='10.5.1.240'), recovery=recovery, project_root=missing)
    coordinator = RecoveryProtectionCoordinator(recovery, actions=UnavailableRecoveryActions())
    cold_bundle = ColdBundleBuilder(config); cold_restore = OpenSSHColdRestore(config)
    baseline = V39Baseline('a' * 64); nonce = 'a' * 48
    calls = [
        coordinator._attestation, coordinator.preflight,
        lambda: ProductionPublishRuntime.publish(object.__new__(ProductionPublishRuntime),
            commit_sha='a' * 40, candidate_only=True),
        lambda: cold_bundle.build(release_root=missing, bundle_id='never', state_source='d_active'),
        lambda: cold_bundle_main(['--config', str(missing/'config.json'), '--project-root', str(missing),
            '--release-root', str(missing), '--bundle-id', 'never', '--state-source', 'd_active']),
        lambda: register(vm_root=missing, release_id='never', release_manifest_sha256='a' * 64,
            publish_candidate_sha256='b' * 64, deployment_attempt_id='never',
            checkpoint_manifest_path=missing/'c.json', recovery_manifest_path=missing/'r.json',
            protection_evidence_path=missing/'v1.json'),
        lambda: capture(vm_root=missing, checkpoint_id='checkpoint-never',
            state_authority_id='authority-never'),
        lambda: capture_legacy(vm_root=missing, checkpoint_id='checkpoint-never',
            state_authority_id='authority-never', release_id='release-never',
            release_manifest_sha256='a' * 64),
        lambda: identify_active(vm_root=missing),
        lambda: cleanup_capture(vm_root=missing, checkpoint_id='checkpoint-never'),
        lambda: cold_restore.inspect_prepare_empty(missing, intent_nonce='never-inspect-authority',
            expected_legacy_deployment_id='never', qualification_reset_materialized=True),
        lambda: cold_restore.apply_prepare_empty(missing, intent_nonce='never-apply-authority',
            expected_pre_delete_inventory_sha256='c' * 64,
            expected_legacy_deployment_id='never', qualification_reset_materialized=True),
        lambda: cold_restore.restore(missing, evidence_output=missing/'restore.json'),
        lambda: verify_failure_domain_attestation(v1),
        lambda: build_stage5_release_certificate(issued_at='2026-08-23T08:00:20Z',
            artifact_refs={}, gate_evidence=(), runbook_evidence=(),
            resolver=DirectoryEvidenceResolver(missing)),
        lambda: run_state_only_backup(config=config, vm=object()),
        lambda: build_task_candidate(config_path=missing/'config.json', project_root=missing,
            operational_root=missing, operational_python=missing/'python.exe',
            recovery_root=missing, failure_domain_attestation_path=missing/'v1.json'),
        lambda: validate_task_candidate(v1),
        lambda: apply_task_candidate(v1, adapter=object(), allow_os_registration=True),
        lambda: seed_v39_access_identity(vm_root=missing, baseline=baseline, allow_test_root=True),
        lambda: inspect_writer_handoff(vm_root=missing, baseline=baseline, runtime=object(),
            nonce=nonce, allow_test_root=True),
        lambda: apply_writer_handoff(vm_root=missing, baseline=baseline, runtime=object(),
            inspection_receipt=v1, expected_inspection_sha256='d' * 64,
            nonce=nonce, allow_test_root=True),
        lambda: finalize_writer_handoff(vm_root=missing, baseline=baseline, runtime=object(),
            attempt_id='never', nonce=nonce, allow_test_root=True),
        lambda: inspect_writer_handoff_status(vm_root=missing, baseline=baseline,
            inspection_sha256='e' * 64, nonce=nonce, allow_test_root=True),
    ]
    for call in calls:
        try: call()
        except FailureDomainAuthorityNotReady as error:
            assert error.code == 'FAILURE_DOMAIN_AUTHORITY_NOT_READY' and error.authority is False
        else: raise AssertionError('installed formal consumer accepted legacy v1')
        assert not missing.exists()

    # Load the real console-entry metadata from this freshly installed wheel,
    # then prove both console entry points and every recovery CLI branch stop
    # before config/path/Git/evidence/remote boundaries.  The authority gate is
    # intentionally not patched in this formal matrix.
    distribution = next(
        item for item in importlib.metadata.distributions(path=[__TARGET__])
        if item.metadata['Name'] == 'quant-research-hub'
    )
    entries = {item.name: item for item in distribution.entry_points}
    assert entries['qrh-publish'].value == 'quant_hub.ops.publish:main'
    assert entries['qrh-writer-handoff-client'].value == 'quant_hub.ops.writer_handoff_client:main'
    publish_entry = entries['qrh-publish'].load()
    client_entry = entries['qrh-writer-handoff-client'].load()
    assert Path(sys.modules[publish_entry.__module__].__file__).resolve().is_relative_to(Path(__TARGET__).resolve())
    assert Path(sys.modules[client_entry.__module__].__file__).resolve().is_relative_to(Path(__TARGET__).resolve())
    expected = failure_domain_authority_status()
    cli_calls = [
        (publish_entry, ['--project-root', str(missing), '--dry-run']),
        (publish_entry, ['--project-root', str(missing), '--config', str(missing/'runtime.json')]),
        (client_entry, ['--config', str(missing/'runtime.json'), '--project-root', str(missing),
            '--release-manifest-sha256', 'a' * 64, 'run']),
        (client_entry, ['--config', str(missing/'runtime.json'), '--project-root', str(missing),
            '--release-manifest-sha256', 'a' * 64, 'status', '--inspection-sha256', 'b' * 64]),
        (client_entry, ['--config', str(missing/'runtime.json'), '--project-root', str(missing),
            '--release-manifest-sha256', 'a' * 64, 'finalize', '--inspection-sha256', 'b' * 64]),
        (recovery_main, ['capture', '--vm-root', str(missing), '--checkpoint-id',
            'checkpoint-never', '--state-authority-id', 'authority-never']),
        (recovery_main, ['capture-legacy', '--vm-root', str(missing), '--checkpoint-id',
            'checkpoint-never', '--state-authority-id', 'authority-never', '--release-id',
            'release-never', '--release-manifest-sha256', 'a' * 64]),
        (recovery_main, ['identify-active', '--vm-root', str(missing)]),
        (recovery_main, ['cleanup-capture', '--vm-root', str(missing), '--checkpoint-id',
            'checkpoint-never']),
        (recovery_main, ['register', '--vm-root', str(missing), '--release-id', 'release-never',
            '--release-manifest-sha256', 'a' * 64, '--publish-candidate-sha256', 'b' * 64,
            '--deployment-attempt-id', 'attempt-never', '--checkpoint-manifest',
            str(missing/'c.json'), '--recovery-manifest', str(missing/'r.json'),
            '--protection-evidence', str(missing/'v1.json')]),
    ]
    class Spy:
        def __init__(self, label): self.label = label; self.call_count = 0
        def __call__(self, *args, **kwargs):
            self.call_count += 1
            raise AssertionError(self.label + ' reached')
    spies = {name: Spy(name) for name in (
        'open', 'path_open', 'read_bytes', 'read_text', 'config', 'git',
        'popen', 'path_resolve', 'path_exists', 'path_mkdir', 'path_stat',
        'path_unlink', 'os_open', 'os_replace', 'os_link', 'os_unlink',
        'remote', 'root', 'snapshot', 'json_read', 'http'
    )}
    before_tree = tuple(sorted(str(item.relative_to(root)) for item in root.rglob('*')))
    originals = {
        'open': builtins.open,
        'path_open': Path.open,
        'read_bytes': Path.read_bytes,
        'read_text': Path.read_text,
        'path_resolve': Path.resolve,
        'path_exists': Path.exists,
        'path_mkdir': Path.mkdir,
        'path_stat': Path.stat,
        'path_unlink': Path.unlink,
        'config': runtime_module.RuntimePublishConfig.__dict__['load'],
        'git': publish_module.subprocess.run,
        'popen': handoff_module.subprocess.Popen,
        'os_open': publish_module.os.open,
        'os_replace': publish_module.os.replace,
        'os_link': client_module.os.link,
        'os_unlink': client_module.os.unlink,
        'remote': client_module._client_from_runtime_config,
        'root': recovery_module._root,
        'snapshot': recovery_module.capture_vm_write_snapshot,
        'json_read': recovery_module.read_json,
        'http': adapters_module.build_opener,
    }
    try:
        builtins.open = spies['open']
        Path.open = spies['path_open']
        Path.read_bytes = spies['read_bytes']
        Path.read_text = spies['read_text']
        Path.resolve = spies['path_resolve']
        Path.exists = spies['path_exists']
        Path.mkdir = spies['path_mkdir']
        Path.stat = spies['path_stat']
        Path.unlink = spies['path_unlink']
        runtime_module.RuntimePublishConfig.load = classmethod(spies['config'])
        publish_module.subprocess.run = spies['git']
        handoff_module.subprocess.Popen = spies['popen']
        publish_module.os.open = spies['os_open']
        publish_module.os.replace = spies['os_replace']
        client_module.os.link = spies['os_link']
        client_module.os.unlink = spies['os_unlink']
        client_module._client_from_runtime_config = spies['remote']
        recovery_module._root = spies['root']
        recovery_module.capture_vm_write_snapshot = spies['snapshot']
        recovery_module.read_json = spies['json_read']
        adapters_module.build_opener = spies['http']
        queue = PublishQueue(missing)
        exact_git_process = Spy('exact_git_process')
        gated_api_calls = [
            lambda: PublishPipeline.execute(object.__new__(PublishPipeline), None),
            lambda: queue.submit(None),
            lambda: queue.finish('never', RuntimeError()),
            lambda: queue.request('never'),
            lambda: queue.running_request(),
            lambda: PublishCoordinator.submit_and_drain(object.__new__(PublishCoordinator), None),
            lambda: ProductionPublishRuntime(None),
            lambda: ProductionSourceFreezer.__call__(object.__new__(ProductionSourceFreezer), None),
            lambda: RecoveryProtectionCoordinator.preflight_materials(object.__new__(RecoveryProtectionCoordinator)),
            lambda: RecoveryProtectionCoordinator.preflight(object.__new__(RecoveryProtectionCoordinator)),
            lambda: RecoveryProtectionCoordinator.protect(object.__new__(RecoveryProtectionCoordinator), material=None, publish_candidate_sha256='a'*64),
            lambda: ExactGitPush(None, exact_git_process)('a'*40),
            lambda: OpenSSHRecoveryActions.capture_checkpoint(object.__new__(OpenSSHRecoveryActions), material=None),
            lambda: OpenSSHRecoveryActions.read_active_identity(object.__new__(OpenSSHRecoveryActions)),
            lambda: OpenSSHRecoveryActions.capture_state_only_checkpoint(object.__new__(OpenSSHRecoveryActions), release_id='never', release_manifest_sha256='a'*64, checkpoint_id='never'),
            lambda: OpenSSHRecoveryActions.cleanup_state_only_capture(object.__new__(OpenSSHRecoveryActions), checkpoint_id='never'),
            lambda: OpenSSHRecoveryActions.register_protection(object.__new__(OpenSSHRecoveryActions), material=None, publish_candidate_sha256='a'*64, bundle_root=missing, recovery_manifest_sha256='b'*64, checkpoint_root=missing),
            lambda: IncrementalVMTransport.__call__(object.__new__(IncrementalVMTransport), {}),
            lambda: OpenSSHVMBackend.ensure_directory(object.__new__(OpenSSHVMBackend), PureWindowsPath(r'D:\\quant\\quant_platform\\incoming\\never')),
            lambda: OpenSSHVMBackend.upload(object.__new__(OpenSSHVMBackend), missing, PureWindowsPath(r'D:\\quant\\quant_platform\\incoming\\never')),
            lambda: VMDeploymentAdapter.__call__(object.__new__(VMDeploymentAdapter), {}),
            lambda: OpenSSHDeploymentInvoker.invoke(object.__new__(OpenSSHDeploymentInvoker), vm_root=PureWindowsPath(r'D:\\quant\\quant_platform'), release_id='never', release_manifest_sha256='a'*64, publish_candidate_sha256='b'*64, deployment_mode='candidate_only', deployment_attempt_id=None, recovery_protection_receipt_id=None),
            lambda: WindowsHandoffRuntime(missing),
            lambda: WindowsHandoffRuntime.observe(object.__new__(WindowsHandoffRuntime), 8765),
            lambda: WindowsHandoffRuntime.stop_legacy(object.__new__(WindowsHandoffRuntime), None),
            lambda: WindowsHandoffRuntime.wait_port_free(object.__new__(WindowsHandoffRuntime), 8765),
            lambda: WindowsHandoffRuntime.start_d_service(object.__new__(WindowsHandoffRuntime), 'never'),
            lambda: WindowsHandoffRuntime.stop_d_service(object.__new__(WindowsHandoffRuntime), 'never'),
            lambda: WindowsHandoffRuntime.d_external_open(object.__new__(WindowsHandoffRuntime), 8765),
            lambda: WindowsHandoffRuntime.probe_d(object.__new__(WindowsHandoffRuntime), baseline),
            lambda: WindowsHandoffRuntime.start_legacy(object.__new__(WindowsHandoffRuntime), None),
            lambda: WindowsHandoffRuntime.verify_legacy_restored(object.__new__(WindowsHandoffRuntime), None, 'never', 8765),
            lambda: WriterHandoffClient(None),
            lambda: WriterHandoffClient.inspect(object.__new__(WriterHandoffClient), baseline),
            lambda: WriterHandoffClient.status(object.__new__(WriterHandoffClient), 'a'*64, baseline),
            lambda: WriterHandoffClient.finalize(object.__new__(WriterHandoffClient), 'a'*64, baseline),
            lambda: WriterHandoffClient.run(object.__new__(WriterHandoffClient), baseline),
            lambda: originals['remote'](missing/'config.json', missing),
            *calls,
        ]
        for call in gated_api_calls:
            try: call()
            except FailureDomainAuthorityNotReady: pass
            else: raise AssertionError('gated installed-wheel API reached a boundary')
        assert exact_git_process.call_count == 0
        unavailable = (
            (UnavailableRecoveryProtector().preflight, (), 'activation recovery protector is unavailable'),
            (UnavailableRecoveryProtector().protect, (), 'activation recovery protector is unavailable'),
            (UnavailableRecoveryActions().capture_checkpoint, (), 'production checkpoint capture adapter is unavailable'),
            (UnavailableRecoveryActions().register_protection, (), 'production recovery receipt registrar is unavailable'),
        )
        for fail_closed, arguments, expected_message in unavailable:
            try: fail_closed(*arguments)
            except PublishRuntimeError as error: assert expected_message in str(error)
            else: raise AssertionError('fail-closed support adapter did not reject')
        for entry, argv in cli_calls:
            output = StringIO()
            with redirect_stdout(output):
                assert entry(argv) == 2
            rendered = output.getvalue()
            assert json.loads(rendered) == expected
            assert str(missing) not in rendered
    finally:
        builtins.open = originals['open']
        Path.open = originals['path_open']
        Path.read_bytes = originals['read_bytes']
        Path.read_text = originals['read_text']
        Path.resolve = originals['path_resolve']
        Path.exists = originals['path_exists']
        Path.mkdir = originals['path_mkdir']
        Path.stat = originals['path_stat']
        Path.unlink = originals['path_unlink']
        runtime_module.RuntimePublishConfig.load = originals['config']
        publish_module.subprocess.run = originals['git']
        handoff_module.subprocess.Popen = originals['popen']
        publish_module.os.open = originals['os_open']
        publish_module.os.replace = originals['os_replace']
        client_module.os.link = originals['os_link']
        client_module.os.unlink = originals['os_unlink']
        client_module._client_from_runtime_config = originals['remote']
        recovery_module._root = originals['root']
        recovery_module.capture_vm_write_snapshot = originals['snapshot']
        recovery_module.read_json = originals['json_read']
        adapters_module.build_opener = originals['http']
    assert all(item.call_count == 0 for item in spies.values()), {
        name: item.call_count for name, item in spies.items()
    }
    assert tuple(sorted(str(item.relative_to(root)) for item in root.rglob('*'))) == before_tree
    assert not missing.exists()

consumer_names = ('publish', 'publish_runtime', 'cold_bundle_cli', 'publish_recovery_cli',
                  'cold_restore_cli', 'stage_closure', 'state_only_backup', 'writer_handoff',
                  'writer_handoff_client')
for name in consumer_names:
    consumer = __import__('quant_hub.ops.' + name, fromlist=['*'])
    source = Path(consumer.__file__).read_text(encoding='utf-8')
    parsed = ast.parse(source)
    assert not any(isinstance(n, ast.Name) and n.id == 'attest_failure_domain'
                   for n in ast.walk(parsed)), name
""".replace("__TARGET__", repr(str(target))).replace(
                "__REPO__", repr(str(repo_root))
            ).replace(
                "__CLASSIFICATION__",
                repr({
                    category: sorted(surfaces)
                    for category, surfaces in PUBLIC_SURFACE_CLASSIFICATION.items()
                }),
            ).replace(
                "__SOURCE_INVENTORY__",
                repr(sorted(_public_surface_inventory()[0])),
            )
            installed_check = Path(temporary) / "installed_wheel_surface_check.py"
            installed_check.write_text(script, encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-I", str(installed_check)],
                cwd=temporary,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                0,
                completed.returncode,
                f"installed-wheel stdout:\n{completed.stdout}\n"
                f"installed-wheel stderr:\n{completed.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
