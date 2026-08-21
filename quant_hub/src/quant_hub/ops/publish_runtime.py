"""Production assembly for the cwd-independent ``qrh-publish`` command.

Construction is side-effect free.  Tests inject every external boundary; the
default assembly uses fixed Git, GitHub and OpenSSH adapters and only performs
work when :meth:`ProductionPublishRuntime.publish` is called.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import subprocess
from typing import Callable, Mapping, Protocol, Sequence
from uuid import uuid4

from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point
from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge.contracts import canonical_json
from quant_hub.knowledge.semantic import (
    SemanticJobStore,
    build_enriched_snapshot,
)
from quant_hub.runtime_seal import safe_tree_file_state
from quant_hub.collaboration.checkpoint import verify_sqlite_checkpoint
from quant_hub.generic_research.release import (
    KNOWLEDGE_ARTIFACT_PATH,
    SNAPSHOT_ARTIFACT_PATH,
    SOURCE_MANIFEST_PATH,
    SOURCE_OBJECT_PREFIX,
    deserialize_snapshot,
)
from quant_hub.knowledge_mcp.mirror import SEARCH_ARTIFACT_RELATIVE_PATH

from .publish import (
    FrozenSources,
    GateResult,
    GitSnapshot,
    PublishActions,
    PublishCoordinator,
    PublishError,
    PublishPipeline,
    PublishQueue,
    PublishRequest,
    PushResult,
    inspect_local_git,
)
from .semantic_authority import resolve_semantic_authority
from .publish_adapters import (
    ActivationAuthorization,
    CommandResult,
    GitHubCIConfig,
    GitHubExactSHACI,
    IncrementalVMTransport,
    OpenSSHDeploymentInvoker,
    OpenSSHVMBackend,
    ProductionPublishConfig,
    ReleaseFile,
    ReleaseMaterial,
    SecretProvider,
    SecretValue,
    VMConfig,
    VMDeploymentAdapter,
    ssh_target_guard_script,
    verified_d_tooling_python_script,
    subprocess_runner as remote_subprocess_runner,
)
from .failure_domain import attest_failure_domain
from .recovery_bundle import build_recovery_bundle, verify_recovery_bundle
from .release_builder import seal_knowledge_release
from .release_identity import manifest_sha256, validate_release_manifest


RUNTIME_CONFIG_SCHEMA = "qrh-production-publish-runtime/v1"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")


class PublishRuntimeError(PublishError):
    pass


@dataclass(frozen=True)
class ResourceOverlayConfig:
    logical_name: str
    source_path: Path
    target_relative_path: str


@dataclass(frozen=True)
class RecoveryRuntimeConfig:
    recovery_root: Path
    attestation_path: Path
    attestation_max_age_seconds: int
    state_authority_id: str
    restore_tool: Path
    runbook: Path
    operational_root: Path


@dataclass(frozen=True)
class RuntimePublishConfig:
    project_root: Path
    state_root: Path
    candidate_root: Path
    git_remote: str
    runtime_base: Path
    runtime_base_manifest_sha256: str
    reference_archive_root: Path
    code_source_relative_path: str
    code_overlay_relative_path: str
    launcher_relative_path: str
    required_runtime_paths: Mapping[str, str]
    resource_overlays: tuple[ResourceOverlayConfig, ...]
    github: GitHubCIConfig
    vm: VMConfig
    recovery: RecoveryRuntimeConfig

    @classmethod
    def parse(cls, value: object) -> "RuntimePublishConfig":
        fields = {
            "schema_version", "project_root", "state_root", "candidate_root",
            "git_remote", "runtime_base", "runtime_base_manifest_sha256",
            "reference_archive_root", "code_source_relative_path",
            "code_overlay_relative_path",
            "launcher_relative_path", "required_runtime_paths", "resource_overlays",
            "github", "vm", "recovery",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise PublishRuntimeError("publish runtime config schema is not closed")
        if value["schema_version"] != RUNTIME_CONFIG_SCHEMA:
            raise PublishRuntimeError("unsupported publish runtime config schema")
        paths = {
            name: Path(str(value[name]))
            for name in ("project_root", "state_root", "candidate_root")
        }
        if any(not path.is_absolute() for path in paths.values()):
            raise PublishRuntimeError("runtime paths must be absolute")
        remote = value["git_remote"]
        if not isinstance(remote, str) or _NAME.fullmatch(remote) is None:
            raise PublishRuntimeError("git_remote is invalid")
        runtime_base = Path(str(value["runtime_base"]))
        archive_root = Path(str(value["reference_archive_root"]))
        if not runtime_base.is_absolute() or not archive_root.is_absolute():
            raise PublishRuntimeError("runtime base and reference archive paths must be absolute")
        base_hash = value["runtime_base_manifest_sha256"]
        if not isinstance(base_hash, str) or re.fullmatch(r"[0-9a-f]{64}", base_hash) is None:
            raise PublishRuntimeError("runtime base manifest hash is invalid")

        def relative_path(raw: object, label: str) -> str:
            if not isinstance(raw, str):
                raise PublishRuntimeError(f"{label} is invalid")
            pure = PurePosixPath(raw)
            if pure.is_absolute() or not pure.parts or ".." in pure.parts or "\\" in raw:
                raise PublishRuntimeError(f"{label} is invalid")
            return pure.as_posix()

        raw_code_source = value["code_source_relative_path"]
        if raw_code_source == ".":
            code_source = "."
        else:
            code_source = relative_path(raw_code_source, "code source path")
        code_overlay = relative_path(value["code_overlay_relative_path"], "code overlay path")
        launcher = relative_path(value["launcher_relative_path"], "launcher path")
        required_names = {
            "launcher", "templates", "static", "archive_database",
            "platform_database", "research_papers_database", "paper_lab_database",
            "papers", "objects", "paper_lab", "state_seed",
        }
        raw_required = value["required_runtime_paths"]
        if not isinstance(raw_required, dict) or set(raw_required) != required_names:
            raise PublishRuntimeError("required runtime path authorities are not closed")
        required = {
            name: relative_path(raw_required[name], f"required runtime path {name}")
            for name in sorted(required_names)
        }
        if required["launcher"] != launcher:
            raise PublishRuntimeError("launcher authority and required path differ")
        raw_sources = value["resource_overlays"]
        if not isinstance(raw_sources, list):
            raise PublishRuntimeError("resource_overlays must be a list")
        sources: list[ResourceOverlayConfig] = []
        seen: set[str] = set()
        for raw in raw_sources:
            if not isinstance(raw, dict) or set(raw) != {
                "logical_name", "source_path", "target_relative_path"
            }:
                raise PublishRuntimeError("resource overlay config is not closed")
            name = raw["logical_name"]
            path = Path(str(raw["source_path"]))
            if (
                not isinstance(name, str)
                or _NAME.fullmatch(name) is None
                or name in seen
                or not path.is_absolute()
            ):
                raise PublishRuntimeError("resource overlay identity/path is invalid")
            seen.add(name)
            sources.append(
                ResourceOverlayConfig(
                    name,
                    path,
                    relative_path(raw["target_relative_path"], "resource overlay target"),
                )
            )
        code_pure = PurePosixPath(code_overlay)
        if any(
            (target := PurePosixPath(item.target_relative_path)) == code_pure
            or target in code_pure.parents
            or code_pure in target.parents
            for item in sources
        ):
            raise PublishRuntimeError("resource overlay must not overlap the exact Git code overlay")
        transport = ProductionPublishConfig.parse(
            {
                "schema_version": "qrh-production-publish-config/v1",
                "github": value["github"],
                "vm": value["vm"],
            }
        )
        raw_recovery = value["recovery"]
        recovery_fields = {
            "root", "failure_domain_attestation", "attestation_max_age_seconds",
            "state_authority_id", "restore_tool", "runbook", "operational_root",
        }
        if not isinstance(raw_recovery, dict) or set(raw_recovery) != recovery_fields:
            raise PublishRuntimeError("recovery runtime config is not closed")
        recovery_paths = {
            key: Path(str(raw_recovery[key]))
            for key in (
                "root", "failure_domain_attestation", "restore_tool", "runbook",
                "operational_root",
            )
        }
        if any(not path.is_absolute() for path in recovery_paths.values()):
            raise PublishRuntimeError("recovery paths must be absolute")
        project_resolved = paths["project_root"].resolve()
        mutable_roots = (
            paths["state_root"].resolve(),
            paths["candidate_root"].resolve(),
            recovery_paths["root"].resolve(),
        )
        source_roots = (
            runtime_base.resolve(),
            archive_root.resolve(),
            *(source.source_path.resolve() for source in sources),
            recovery_paths["operational_root"].resolve(),
        )
        if any(root == project_resolved or root.is_relative_to(project_resolved) for root in mutable_roots):
            raise PublishRuntimeError("mutable publish/recovery roots must stay outside Git")
        if any(
            mutable == source
            or mutable.is_relative_to(source)
            or source.is_relative_to(mutable)
            for mutable in mutable_roots
            for source in source_roots
        ):
            raise PublishRuntimeError("mutable publish/recovery root overlaps a read-only source")
        max_age = raw_recovery["attestation_max_age_seconds"]
        authority = raw_recovery["state_authority_id"]
        if (
            not isinstance(max_age, int)
            or isinstance(max_age, bool)
            or not 60 <= max_age <= 31 * 86400
            or not isinstance(authority, str)
            or _NAME.fullmatch(authority) is None
        ):
            raise PublishRuntimeError("recovery policy is invalid")
        return cls(
            project_root=paths["project_root"],
            state_root=paths["state_root"],
            candidate_root=paths["candidate_root"],
            git_remote=remote,
            runtime_base=runtime_base,
            runtime_base_manifest_sha256=base_hash,
            reference_archive_root=archive_root,
            code_source_relative_path=code_source,
            code_overlay_relative_path=code_overlay,
            launcher_relative_path=launcher,
            required_runtime_paths=required,
            resource_overlays=tuple(sources),
            github=transport.github,
            vm=transport.vm,
            recovery=RecoveryRuntimeConfig(
                recovery_root=recovery_paths["root"],
                attestation_path=recovery_paths["failure_domain_attestation"],
                attestation_max_age_seconds=max_age,
                state_authority_id=authority,
                restore_tool=recovery_paths["restore_tool"],
                runbook=recovery_paths["runbook"],
                operational_root=recovery_paths["operational_root"],
            ),
        )

    @classmethod
    def load(cls, path: Path, *, expected_project_root: Path) -> "RuntimePublishConfig":
        config_path = Path(path).resolve(strict=True)
        project = Path(expected_project_root).resolve(strict=True)
        if config_path.is_relative_to(project):
            raise PublishRuntimeError("production config must stay outside the Git project")
        ensure_no_reparse_components(config_path)
        try:
            value = json.loads(config_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PublishRuntimeError("production config is unreadable") from error
        config = cls.parse(value)
        if config.project_root.resolve(strict=True) != project:
            raise PublishRuntimeError("production config belongs to another project root")
        return config


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: str = ""


ProcessRunner = Callable[[Sequence[str], Path], ProcessResult]


def production_process_runner(arguments: Sequence[str], cwd: Path) -> ProcessResult:
    completed = subprocess.run(
        list(arguments), cwd=cwd, shell=False, check=False, capture_output=True,
        text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"},
    )
    # stderr is deliberately not returned: Git remotes and providers can emit
    # credential-bearing diagnostics.
    return ProcessResult(completed.returncode, completed.stdout)


class EnvironmentSecretProvider:
    """Process-local protected credential provider; values are never persisted."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self.environment = os.environ if environment is None else environment

    def __call__(self, target: str) -> SecretValue | None:
        if _NAME.fullmatch(target) is None:
            raise PublishRuntimeError("secret target is invalid")
        key = "QRH_SECRET_" + re.sub(r"[^A-Za-z0-9]", "_", target).upper()
        value = self.environment.get(key)
        return SecretValue(value) if value else None


class RecoveryProtector(Protocol):
    def preflight(self) -> None: ...

    def protect(
        self,
        *,
        material: ReleaseMaterial,
        publish_candidate_sha256: str,
    ) -> ActivationAuthorization: ...


class UnavailableRecoveryProtector:
    """Fail closed when production recovery assembly was not supplied."""

    def preflight(self) -> None:
        raise PublishRuntimeError(
            "activation recovery protector is unavailable; candidate_only remains permitted"
        )

    def protect(self, **_: object) -> ActivationAuthorization:
        raise PublishRuntimeError(
            "activation recovery protector is unavailable; candidate_only remains permitted"
        )


class RecoveryProtectionActions(Protocol):
    def capture_checkpoint(self, *, material: ReleaseMaterial) -> Path: ...

    def register_protection(
        self,
        *,
        material: ReleaseMaterial,
        publish_candidate_sha256: str,
        bundle_root: Path,
        recovery_manifest_sha256: str,
        checkpoint_root: Path,
    ) -> ActivationAuthorization: ...


class UnavailableRecoveryActions:
    def capture_checkpoint(self, **_: object) -> Path:
        raise PublishRuntimeError("production checkpoint capture adapter is unavailable")

    def register_protection(self, **_: object) -> ActivationAuthorization:
        raise PublishRuntimeError("production recovery receipt registrar is unavailable")


class OpenSSHRecoveryActions:
    """Fixed OpenSSH/SCP C capture and protection-receipt registration."""

    def __init__(
        self,
        runtime: RuntimePublishConfig,
        *,
        command_runner: Callable[[Sequence[str]], CommandResult] = remote_subprocess_runner,
        vm_backend: OpenSSHVMBackend | None = None,
        deployment_invoker: OpenSSHDeploymentInvoker | None = None,
    ) -> None:
        self.runtime = runtime
        self.command_runner = command_runner
        self.vm_backend = vm_backend or OpenSSHVMBackend(
            runtime.vm, command_runner=command_runner
        )
        self.deployment_invoker = deployment_invoker or OpenSSHDeploymentInvoker(
            runtime.vm, command_runner=command_runner
        )

    def _remote(self, arguments: Sequence[str]) -> Mapping[str, object]:
        temporary_path = self.runtime.vm.root / "tmp" / "publish-recovery"
        temporary = str(temporary_path)
        ps_literal = lambda value: "'" + str(value).replace("'", "''") + "'"
        rendered = ",".join(ps_literal(value) for value in arguments)
        # Arguments are identity/path validated by callers and JSON quoted into
        # a fixed EncodedCommand, never interpreted as source instructions.
        script = (
            ssh_target_guard_script(self.runtime.vm.target_address)
            + OpenSSHVMBackend._ensure_directory_script(temporary_path)
            + verified_d_tooling_python_script("publish_recovery_cli_module")
            +
            f"$tmp={ps_literal(temporary)};"
            "$env:PYTHONDONTWRITEBYTECODE='1';$env:TEMP=$tmp;$env:TMP=$tmp;"
            f"$a=@({rendered});$o=& $python @a;"
            "if($LASTEXITCODE-ne 0){throw 'publish_recovery_cli_failed'};"
            "$o|Write-Output"
        )
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        result = self.command_runner(
            (
                "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "--", self.runtime.vm.ssh_alias, "powershell.exe", "-NoProfile",
                "-NonInteractive", "-EncodedCommand", encoded,
            )
        )
        if result.returncode != 0:
            raise PublishRuntimeError("fixed VM recovery command failed")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise PublishRuntimeError("fixed VM recovery result is invalid") from error
        if not isinstance(value, dict):
            raise PublishRuntimeError("fixed VM recovery result must be an object")
        return value

    def capture_checkpoint(self, *, material: ReleaseMaterial) -> Path:
        checkpoint_id = f"checkpoint-{material.release_manifest_sha256[:20]}-{uuid4().hex[:12]}"
        return self.capture_state_only_checkpoint(
            release_id=material.release_id,
            release_manifest_sha256=material.release_manifest_sha256,
            checkpoint_id=checkpoint_id,
        )

    def read_active_identity(self) -> Mapping[str, str]:
        value = self._remote(
            (
                "-B", "-m", "quant_hub.ops.publish_recovery_cli",
                "identify-active", "--vm-root", str(self.runtime.vm.root),
            )
        )
        release_id = value.get("release_id")
        release_hash = value.get("release_manifest_sha256")
        if (
            value.get("schema_version") != "qrh-state-only-active-identity/v1"
            or not isinstance(release_id, str)
            or _NAME.fullmatch(release_id) is None
            or not isinstance(release_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", release_hash) is None
        ):
            raise PublishRuntimeError("VM active recovery identity is invalid")
        return {
            "release_id": release_id,
            "release_manifest_sha256": release_hash,
        }

    def capture_state_only_checkpoint(
        self,
        *,
        release_id: str,
        release_manifest_sha256: str,
        checkpoint_id: str,
    ) -> Path:
        if (
            _NAME.fullmatch(release_id) is None
            or _NAME.fullmatch(checkpoint_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", release_manifest_sha256) is None
        ):
            raise PublishRuntimeError("state-only capture identity is invalid")
        value = self._remote(
            (
                "-B", "-m", "quant_hub.ops.publish_recovery_cli", "capture",
                "--vm-root", str(self.runtime.vm.root),
                "--checkpoint-id", checkpoint_id,
                "--state-authority-id", self.runtime.recovery.state_authority_id,
            )
        )
        expected_root = PureWindowsPath(self.runtime.vm.root) / "tmp" / "publish-recovery" / "checkpoints" / checkpoint_id
        if (
            value.get("schema_version") != "qrh-publish-checkpoint-result/v1"
            or value.get("checkpoint_id") != checkpoint_id
            or PureWindowsPath(str(value.get("checkpoint_root"))) != expected_root
        ):
            raise PublishRuntimeError("VM checkpoint result identity/path differs")
        intake = self.runtime.recovery.recovery_root / "checkpoint-intake"
        intake.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(intake)
        destination = intake / checkpoint_id
        if destination.exists():
            raise PublishRuntimeError("local checkpoint intake identity already exists")
        remote_source = (
            f"{self.runtime.vm.ssh_alias}:"
            + str(expected_root).replace("\\", "/")
        )
        copied = self.command_runner(
            (
                "scp", "-q", "-r", "-o", "BatchMode=yes", "-o",
                "ConnectTimeout=20", "--", remote_source, str(intake),
            )
        )
        if copied.returncode != 0 or not destination.is_dir():
            raise PublishRuntimeError("VM checkpoint download failed")
        report = verify_sqlite_checkpoint(destination)
        if (
            not report.valid
            or report.checkpoint_id != checkpoint_id
            or report.manifest_sha256 != value.get("checkpoint_manifest_sha256")
        ):
            raise PublishRuntimeError("downloaded checkpoint identity differs")
        return destination

    def cleanup_state_only_capture(self, *, checkpoint_id: str) -> None:
        if _NAME.fullmatch(checkpoint_id) is None:
            raise PublishRuntimeError("state-only cleanup checkpoint identity is invalid")
        value = self._remote(
            (
                "-B", "-m", "quant_hub.ops.publish_recovery_cli",
                "cleanup-capture", "--vm-root", str(self.runtime.vm.root),
                "--checkpoint-id", checkpoint_id,
            )
        )
        if (
            value.get("schema_version") != "qrh-publish-checkpoint-cleanup/v1"
            or value.get("checkpoint_id") != checkpoint_id
        ):
            raise PublishRuntimeError("VM checkpoint cleanup identity differs")

    def register_protection(
        self,
        *,
        material: ReleaseMaterial,
        publish_candidate_sha256: str,
        bundle_root: Path,
        recovery_manifest_sha256: str,
        checkpoint_root: Path,
    ) -> ActivationAuthorization:
        attempt_id = f"deploy-{publish_candidate_sha256[:24]}"
        finalized = self.deployment_invoker.invoke(
            vm_root=self.runtime.vm.root,
            release_id=material.release_id,
            release_manifest_sha256=material.release_manifest_sha256,
            publish_candidate_sha256=publish_candidate_sha256,
            deployment_mode="candidate_only",
            deployment_attempt_id=None,
            recovery_protection_receipt_id=None,
        )
        if finalized.get("status") != "candidate_validated":
            raise PublishRuntimeError("candidate could not be finalized before protection")
        checkpoint_manifest = checkpoint_root / "checkpoint_manifest.json"
        recovery_manifest = bundle_root / "recovery_manifest.json"
        attestation = self._verified_attestation()
        evidence = {
            "schema_version": "qrh-publish-recovery-protection-evidence/v1",
            "release_id": material.release_id,
            "release_manifest_sha256": material.release_manifest_sha256,
            "publish_candidate_sha256": publish_candidate_sha256,
            "checkpoint_manifest_sha256": hashlib.sha256(
                checkpoint_manifest.read_bytes()
            ).hexdigest(),
            "recovery_manifest_sha256": recovery_manifest_sha256,
            "failure_domain_attestation": attestation,
            "bundle_verification": {
                "closure": True,
                "compatibility": True,
                "no_secret": True,
                "failure_domain": True,
            },
        }
        staging = self.runtime.recovery.recovery_root / f".registration-{uuid4().hex}"
        staging.mkdir()
        try:
            files = {
                "checkpoint_manifest.json": checkpoint_manifest,
                "recovery_manifest.json": recovery_manifest,
            }
            evidence_path = staging / "protection_evidence.json"
            evidence_path.write_text(canonical_json(evidence), encoding="utf-8")
            files["protection_evidence.json"] = evidence_path
            remote_root = self.runtime.vm.root / "tmp" / "publish-recovery" / "registration" / attempt_id
            self.vm_backend.ensure_directory(remote_root)
            for name, source in files.items():
                self.vm_backend.upload(source, remote_root / name)
            value = self._remote(
                (
                    "-B", "-m", "quant_hub.ops.publish_recovery_cli", "register",
                    "--vm-root", str(self.runtime.vm.root),
                    "--release-id", material.release_id,
                    "--release-manifest-sha256", material.release_manifest_sha256,
                    "--publish-candidate-sha256", publish_candidate_sha256,
                    "--deployment-attempt-id", attempt_id,
                    "--checkpoint-manifest", str(remote_root / "checkpoint_manifest.json"),
                    "--recovery-manifest", str(remote_root / "recovery_manifest.json"),
                    "--protection-evidence", str(remote_root / "protection_evidence.json"),
                )
            )
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        if (
            value.get("schema_version") != "qrh-publish-protection-result/v1"
            or value.get("deployment_attempt_id") != attempt_id
            or value.get("release_manifest_sha256") != material.release_manifest_sha256
            or value.get("recovery_manifest_sha256") != recovery_manifest_sha256
        ):
            raise PublishRuntimeError("VM recovery protection registration differs")
        receipt_id = value.get("recovery_protection_receipt_id")
        if not isinstance(receipt_id, str) or _NAME.fullmatch(receipt_id) is None:
            raise PublishRuntimeError("VM recovery protection receipt ID is invalid")
        return ActivationAuthorization(attempt_id, receipt_id)

    def _verified_attestation(self) -> Mapping[str, object]:
        # Reuse the exact preflight implementation, including freshness and
        # recovery-root binding, immediately before receipt registration.
        return RecoveryProtectionCoordinator(
            self.runtime.recovery, actions=self
        )._attestation()


class RecoveryProtectionCoordinator:
    """Build C/RM closure and return only a registered protection authorization."""

    def __init__(
        self,
        config: RecoveryRuntimeConfig,
        *,
        actions: RecoveryProtectionActions,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.config = config
        self.actions = actions
        self.now = now

    def _attestation(self) -> Mapping[str, object]:
        try:
            value = json.loads(self.config.attestation_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PublishRuntimeError("failure-domain attestation is unavailable") from error
        if not isinstance(value, dict):
            raise PublishRuntimeError("failure-domain attestation is invalid")
        expected_attestation_fields = {
            "schema_version", "observed_at", "production_host_facts_sha256",
            "recovery_host_facts_sha256", "production", "recovery",
            "independence_probe", "verdict", "attestation_sha256",
        }
        if set(value) != expected_attestation_fields:
            raise PublishRuntimeError("failure-domain attestation schema is not closed")
        claimed = value.get("attestation_sha256")
        try:
            rebuilt = attest_failure_domain(
                production_facts=value["production"],
                recovery_facts=value["recovery"],
                independence_probe=value["independence_probe"],
                observed_at=str(value["observed_at"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise PublishRuntimeError("failure-domain attestation cannot be verified") from error
        if claimed != rebuilt.sha256 or any(
            value.get(key) != rebuilt.payload.get(key) for key in rebuilt.payload
        ):
            raise PublishRuntimeError("failure-domain attestation identity differs")
        recovery = rebuilt.payload["recovery"]
        assert isinstance(recovery, Mapping)
        if Path(str(recovery["canonical_path"])).resolve(strict=True) != self.config.recovery_root.resolve(strict=True):
            raise PublishRuntimeError("attestation belongs to another recovery root")
        try:
            observed = datetime.fromisoformat(str(value["observed_at"]).replace("Z", "+00:00"))
        except ValueError as error:
            raise PublishRuntimeError("attestation timestamp is invalid") from error
        if observed.tzinfo is None or observed.utcoffset() is None:
            raise PublishRuntimeError("attestation timestamp must be timezone-aware")
        age = (self.now().astimezone(UTC) - observed.astimezone(UTC)).total_seconds()
        if age < 0 or age > self.config.attestation_max_age_seconds:
            raise PublishRuntimeError("failure-domain attestation is stale")
        return value

    def preflight_materials(self) -> None:
        """Verify the off-host recovery material roots without claiming protection.

        This is intentionally weaker than :meth:`preflight`: it exists only so
        the initial legacy-C qualification bundle can be assembled before the
        first real empty-D materialisation event exists.  It must never be used
        to register a recovery-protection receipt.
        """
        root = self.config.recovery_root.resolve(strict=True)
        ensure_no_reparse_components(root)
        if not root.is_dir():
            raise PublishRuntimeError("recovery root is unavailable")
        for path in (self.config.restore_tool, self.config.runbook):
            ensure_no_reparse_components(path)
            if not path.resolve(strict=True).is_file():
                raise PublishRuntimeError("recovery tool/runbook is unavailable")
        operational = self.config.operational_root.resolve(strict=True)
        ensure_no_reparse_components(operational)
        if not operational.is_dir():
            raise PublishRuntimeError("operational bootstrap root is unavailable")

    def preflight(self) -> None:
        self.preflight_materials()
        self._attestation()

    def protect(
        self,
        *,
        material: ReleaseMaterial,
        publish_candidate_sha256: str,
    ) -> ActivationAuthorization:
        self.preflight()
        checkpoint_root = self.actions.capture_checkpoint(material=material).resolve(strict=True)
        checkpoint = verify_sqlite_checkpoint(checkpoint_root)
        if not checkpoint.valid or not checkpoint.manifest_sha256:
            raise PublishRuntimeError("captured SQLite checkpoint is not restorable")
        attempt_id = f"deploy-{publish_candidate_sha256[:24]}"
        bundle = build_recovery_bundle(
            release_root=material.source_root,
            checkpoint_root=checkpoint_root,
            recovery_root=self.config.recovery_root,
            bundle_id=attempt_id,
            created_at=self.now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
            restore_tool=self.config.restore_tool,
            runbook=self.config.runbook,
            operational_root=self.config.operational_root,
            compatibility={"verdict": "compatible", "policy": "expand_only_no_down_migration"},
        )
        verification = verify_recovery_bundle(bundle.root)
        if (
            not verification.valid
            or verification.release_id != material.release_id
            or verification.release_manifest_sha256 != material.release_manifest_sha256
            or verification.checkpoint_manifest_sha256 != checkpoint.manifest_sha256
            or verification.recovery_manifest_sha256 != bundle.recovery_manifest_sha256
        ):
            raise PublishRuntimeError("cold recovery bundle identity/closure verification failed")
        authorization = self.actions.register_protection(
            material=material,
            publish_candidate_sha256=publish_candidate_sha256,
            bundle_root=bundle.root,
            recovery_manifest_sha256=bundle.recovery_manifest_sha256,
            checkpoint_root=checkpoint_root,
        )
        if not isinstance(authorization, ActivationAuthorization):
            raise PublishRuntimeError("recovery registrar returned invalid authorization")
        return authorization


class ProductionSourceFreezer:
    """Freeze tracked code plus read-only external sources, then seal with R."""

    def __init__(self, config: RuntimePublishConfig, *, process_runner: ProcessRunner):
        self.config = config
        self.process_runner = process_runner
        self.materials: dict[str, ReleaseMaterial] = {}

    @staticmethod
    def _copy_file(source: Path, target: Path) -> None:
        info = source.lstat()
        if stat_is_reparse_point(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PublishRuntimeError("source freeze encountered an unsafe file")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    def _git_files(self, commit_sha: str) -> tuple[str, ...]:
        result = self.process_runner(
            ("git", "ls-tree", "-r", "--name-only", "-z", commit_sha),
            self.config.project_root,
        )
        if result.returncode != 0:
            raise PublishRuntimeError("cannot enumerate exact tracked tree")
        paths = tuple(item for item in result.stdout.split("\0") if item)
        if not paths:
            raise PublishRuntimeError("tracked tree is empty")
        return paths

    def _copy_runtime_base(self, staging: Path) -> Mapping[str, object] | None:
        base = self.config.runtime_base.resolve(strict=True)
        ensure_no_reparse_components(base)
        manifest_path = base / "release_manifest.json"
        try:
            manifest = validate_release_manifest(
                json.loads(manifest_path.read_text(encoding="utf-8"))
            )
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise PublishRuntimeError("runtime base release manifest is invalid") from error
        if manifest_sha256(manifest) != self.config.runtime_base_manifest_sha256:
            raise PublishRuntimeError("runtime base manifest identity differs")
        actual = safe_tree_file_state(base)
        actual.pop("release_manifest.json", None)
        expected = {
            str(item["path"]): {
                "bytes": int(item["bytes"]), "sha256": str(item["sha256"])
            }
            for item in manifest["inventory"]["files"]
        }
        if actual != expected:
            raise PublishRuntimeError("runtime base closure differs from its immutable R")
        overlay = PurePosixPath(self.config.code_overlay_relative_path)
        for relative_text in sorted(actual):
            relative = PurePosixPath(relative_text)
            if relative == overlay or overlay in relative.parents:
                continue
            self._copy_file(base.joinpath(*relative.parts), staging.joinpath(*relative.parts))
        prior_path = base / SNAPSHOT_ARTIFACT_PATH
        if prior_path.is_file():
            try:
                return deserialize_snapshot(prior_path.read_bytes())
            except (OSError, TypeError, ValueError) as error:
                raise PublishRuntimeError("runtime base deterministic snapshot is invalid") from error
        return None

    def _overlay_resource(
        self, configured: ResourceOverlayConfig, staging: Path
    ) -> list[dict[str, object]]:
        source = configured.source_path.resolve(strict=True)
        ensure_no_reparse_components(source)
        target_root = staging.joinpath(
            *PurePosixPath(configured.target_relative_path).parts
        )
        records: list[dict[str, object]] = []
        if source.is_file():
            self._copy_file(source, target_root)
            value = target_root.read_bytes()
            records.append(
                {
                    "logical_name": configured.logical_name,
                    "source_path": source.name,
                    "target_path": configured.target_relative_path,
                    "bytes": len(value),
                    "sha256": hashlib.sha256(value).hexdigest(),
                }
            )
            return records
        if not source.is_dir():
            raise PublishRuntimeError("resource overlay source is unavailable")
        state = safe_tree_file_state(source)
        for relative_text, facts in sorted(state.items()):
            relative = PurePosixPath(relative_text)
            target = target_root.joinpath(*relative.parts)
            self._copy_file(source.joinpath(*relative.parts), target)
            copied = target.read_bytes()
            if len(copied) != facts["bytes"] or hashlib.sha256(copied).hexdigest() != facts["sha256"]:
                raise PublishRuntimeError("resource overlay changed during freeze")
            records.append(
                {
                    "logical_name": configured.logical_name,
                    "source_path": relative.as_posix(),
                    "target_path": (
                        PurePosixPath(configured.target_relative_path) / relative
                    ).as_posix(),
                    "bytes": facts["bytes"],
                    "sha256": facts["sha256"],
                }
            )
        return records

    @staticmethod
    def _validated_candidate(
        root: Path, *, expected_release_id: str
    ) -> tuple[Mapping[str, object], dict[str, dict[str, object]]]:
        """Return a fully checked immutable candidate and its non-manifest tree.

        A retry may encounter a candidate sealed by an earlier process whose
        downstream CI/transport failed.  The release manifest timestamp makes
        the manifest bytes intentionally different, so reuse is permitted only
        after independently proving the existing manifest and every byte it
        inventories.  The existing manifest remains the identity authority.
        """

        physical = root.resolve(strict=True)
        ensure_no_reparse_components(physical)
        manifest_path = physical / "release_manifest.json"
        try:
            manifest_bytes = manifest_path.read_bytes()
            manifest = validate_release_manifest(
                json.loads(manifest_bytes.decode("utf-8"))
            )
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise PublishRuntimeError("existing immutable candidate manifest is invalid") from error
        if manifest["release_id"] != expected_release_id:
            raise PublishRuntimeError("existing immutable candidate release identity differs")
        actual = safe_tree_file_state(physical)
        manifest_facts = actual.pop("release_manifest.json", None)
        if manifest_path.read_bytes() != manifest_bytes:
            raise PublishRuntimeError("existing immutable candidate manifest changed during validation")
        if manifest_facts is None or manifest_facts != {
            "bytes": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        }:
            raise PublishRuntimeError("existing immutable candidate manifest changed during validation")
        inventory = manifest.get("inventory")
        if not isinstance(inventory, Mapping) or not isinstance(inventory.get("files"), list):
            raise PublishRuntimeError("existing immutable candidate inventory is invalid")
        expected = {
            str(item["path"]): {
                "bytes": int(item["bytes"]), "sha256": str(item["sha256"])
            }
            for item in inventory["files"]
        }
        if actual != expected:
            raise PublishRuntimeError("existing immutable candidate tree differs from inventory")
        if manifest["resources"].get("inventory_sha256") != manifest_sha256(inventory):
            raise PublishRuntimeError("existing immutable candidate inventory binding differs")
        return manifest, actual

    @classmethod
    def _reuse_exact_candidate(
        cls, *, existing: Path, staged: Path, expected_release_id: str
    ) -> tuple[Mapping[str, object], dict[str, dict[str, object]]]:
        existing_manifest, existing_tree = cls._validated_candidate(
            existing, expected_release_id=expected_release_id
        )
        staged_manifest, staged_tree = cls._validated_candidate(
            staged, expected_release_id=expected_release_id
        )
        # built_at is evidence of the process that performed each seal, not an
        # input to the release_id.  No other manifest field may drift.
        comparable_existing = dict(existing_manifest)
        comparable_staged = dict(staged_manifest)
        comparable_existing.pop("built_at", None)
        comparable_staged.pop("built_at", None)
        if comparable_existing != comparable_staged or existing_tree != staged_tree:
            raise PublishRuntimeError(
                "same release identity resolves to different immutable candidate bytes"
            )
        return existing_manifest, existing_tree

    def __call__(self, snapshot: GitSnapshot) -> FrozenSources:
        candidate_parent = self.config.candidate_root.resolve()
        candidate_parent.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(candidate_parent)
        staging = candidate_parent / f".freeze-{uuid4().hex}"
        staging.mkdir()
        try:
            previous_snapshot = self._copy_runtime_base(staging)
            code_root = staging.joinpath(
                *PurePosixPath(self.config.code_overlay_relative_path).parts
            )
            code_source = PurePosixPath(self.config.code_source_relative_path)
            copied_code_files = 0
            for relative_text in self._git_files(snapshot.commit_sha):
                relative = PurePosixPath(relative_text)
                if relative.is_absolute() or ".." in relative.parts:
                    raise PublishRuntimeError("tracked path escapes project root")
                if self.config.code_source_relative_path == ".":
                    overlay_relative = relative
                elif code_source in relative.parents:
                    overlay_relative = relative.relative_to(code_source)
                else:
                    continue
                source = self.config.project_root.joinpath(*relative.parts).resolve(strict=True)
                if not source.is_relative_to(self.config.project_root.resolve(strict=True)):
                    raise PublishRuntimeError("tracked path escapes project root")
                target = code_root.joinpath(*overlay_relative.parts)
                self._copy_file(source, target)
                copied_code_files += 1
                expected_blob = self.process_runner(
                    ("git", "rev-parse", f"{snapshot.commit_sha}:{relative.as_posix()}"),
                    self.config.project_root,
                )
                copied_blob = self.process_runner(
                    ("git", "hash-object", str(target)), self.config.project_root
                )
                if (
                    expected_blob.returncode != 0
                    or copied_blob.returncode != 0
                    or expected_blob.stdout.strip() != copied_blob.stdout.strip()
                ):
                    raise PublishRuntimeError("tracked source differs from exact Git object")
            if copied_code_files == 0:
                raise PublishRuntimeError("configured exact Git code source is empty")
            external_inventory: list[dict[str, object]] = []
            for configured in self.config.resource_overlays:
                external_inventory.extend(self._overlay_resource(configured, staging))
            required_files = {
                "launcher", "archive_database", "platform_database",
                "research_papers_database", "paper_lab_database",
            }
            missing = []
            for name, relative in self.config.required_runtime_paths.items():
                path = staging.joinpath(*PurePosixPath(relative).parts)
                if (name in required_files and not path.is_file()) or (
                    name not in required_files and not path.is_dir()
                ):
                    missing.append(name)
            launcher = staging.joinpath(
                *PurePosixPath(self.config.launcher_relative_path).parts
            )
            if missing or not launcher.is_file():
                raise PublishRuntimeError(
                    "runnable runtime base/overlay is incomplete: " + ",".join(missing)
                )
            state_root = self.config.state_root.resolve(strict=True)
            ensure_no_reparse_components(state_root)
            semantic_receipt = resolve_semantic_authority(
                project_root=self.config.project_root,
                state_root=state_root,
            )
            inventory_payload = {
                "schema_version": "qrh-publish-source-authority-inventory/v1",
                "runtime_base_manifest_sha256": self.config.runtime_base_manifest_sha256,
                "reference_archive": {
                    "path_role": "read_only_archive",
                    "tree": safe_tree_file_state(
                        self.config.reference_archive_root.resolve(strict=True)
                    ),
                },
                "resource_overlays": external_inventory,
                "code_source_relative_path": self.config.code_source_relative_path,
                "code_overlay_relative_path": self.config.code_overlay_relative_path,
                "launcher_relative_path": self.config.launcher_relative_path,
                "semantic_authority": {
                    "promotion_id": semantic_receipt.promotion_id,
                    "file_sha256": semantic_receipt.target["file_sha256"],
                    "logical_sha256": semantic_receipt.target["logical_sha256"],
                    "schema_sha256": semantic_receipt.target["schema_sha256"],
                    "row_counts": semantic_receipt.target["row_counts"],
                },
            }
            inventory_bytes = canonical_json(inventory_payload).encode("utf-8")
            inventory_hash = hashlib.sha256(inventory_bytes).hexdigest()
            inventory_path = staging / "content" / "publish_source_authorities.json"
            inventory_path.parent.mkdir(parents=True, exist_ok=True)
            inventory_path.write_bytes(inventory_bytes)
            reference_root = self.config.reference_archive_root.resolve(strict=True)
            compiled = ReferenceCompiler().compile(
                reference_root, previous=previous_snapshot
            )
            if compiled.candidate_snapshot is None:
                raise PublishRuntimeError("frozen reference did not produce a valid snapshot")
            knowledge_snapshot = compiled.candidate_snapshot
            # A publish is a pure consumer of the promoted semantic authority.
            # It must never switch journal mode, run schema initialisation, or
            # backfill rows: any knowledge change is compiled in a separate
            # workspace and receives a new immutable promotion identity first.
            semantic_store = SemanticJobStore(
                state_root / "semantic_jobs.sqlite3", read_only=True
            )
            enriched = build_enriched_snapshot(knowledge_snapshot, semantic_store)
            selected_generation_ids = set(enriched.generation_membership.values())
            selected_generations = tuple(
                generation
                for version_id in sorted(knowledge_snapshot.active_membership.values())
                for generation in semantic_store.generations_for_version(version_id)
                if generation.generation_id in selected_generation_ids
            )
            if {
                generation.generation_id for generation in selected_generations
            } != selected_generation_ids:
                raise PublishRuntimeError("selected semantic generation closure is incomplete")
            status_counts: dict[str, int] = {}
            for status in enriched.knowledge_status_membership.values():
                status_counts[status] = status_counts.get(status, 0) + 1
            enrichment_status = (
                "ready"
                if set(status_counts).issubset({"ready", "blocked_policy"})
                else "partial"
            )
            semantic_identity = hashlib.sha256(
                (
                    snapshot.tracked_tree_sha256
                    + inventory_hash
                    + enriched.snapshot_id
                ).encode("ascii")
            ).hexdigest()
            release_id = (
                f"release-{snapshot.commit_sha[:12]}-{semantic_identity[:12]}"
            )
            manifest = {
                "schema_version": "qrh-release-manifest/v1",
                "release_id": release_id,
                "built_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "application": {
                    "source_kind": "git",
                    "commit_sha": snapshot.commit_sha,
                    "tracked_tree_sha256": snapshot.tracked_tree_sha256,
                    "build_tool_version": "qrh-production-publish-runtime/v1",
                },
                "content": {
                    "snapshot_id": enriched.snapshot_id,
                    "knowledge_enrichment": {
                        "status": enrichment_status,
                        "base_snapshot_id": knowledge_snapshot.snapshot_id,
                        "status_counts": dict(sorted(status_counts.items())),
                    },
                },
                "resources": {},
                "state": {
                    "compatibility": {
                        "comments": {"read": [1, 2], "write": [1, 2]},
                        "research_workspace": {
                            "read": [1, 2, 3], "write": [1, 2, 3]
                        },
                        "rollback_policy": "expand_only_no_down_migration",
                    }
                },
                "recovery": {
                    "compatibility": {
                        "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                        "restore_protocol_versions": ["qrh-restore/v1"],
                    }
                },
            }
            source_objects: dict[str, bytes] = {}
            prior_objects = staging / SOURCE_OBJECT_PREFIX
            if prior_objects.is_dir():
                for path in prior_objects.iterdir():
                    if path.is_file() and re.fullmatch(r"[0-9a-f]{64}", path.name):
                        value = path.read_bytes()
                        if hashlib.sha256(value).hexdigest() != path.name:
                            raise PublishRuntimeError("historical source object identity differs")
                        source_objects[path.name] = value
            for version_id in knowledge_snapshot.active_membership.values():
                version = knowledge_snapshot.versions[version_id]
                path = reference_root.joinpath(*PurePosixPath(version.logical_path).parts)
                value = path.read_bytes()
                if hashlib.sha256(value).hexdigest() != version.source_sha256:
                    raise PublishRuntimeError("active reference source changed after compile")
                source_objects[version.source_sha256] = value
            for relative in (
                SNAPSHOT_ARTIFACT_PATH,
                SOURCE_MANIFEST_PATH,
                KNOWLEDGE_ARTIFACT_PATH,
                SEARCH_ARTIFACT_RELATIVE_PATH,
            ):
                generated = staging / relative
                if generated.is_file():
                    generated.unlink()
            sealed = seal_knowledge_release(
                candidate_root=staging,
                manifest_without_inventory=manifest,
                snapshot=knowledge_snapshot,
                enriched=enriched,
                generations=selected_generations,
                source_objects=source_objects,
            )
            final = candidate_parent / sealed.release_id
            if final.exists():
                release, _ = self._reuse_exact_candidate(
                    existing=final,
                    staged=staging,
                    expected_release_id=sealed.release_id,
                )
                shutil.rmtree(staging)
            else:
                os.replace(staging, final)
                release, _ = self._validated_candidate(
                    final, expected_release_id=sealed.release_id
                )
            effective_manifest_sha256 = manifest_sha256(release)
            files = tuple(
                ReleaseFile(str(item["path"]), int(item["bytes"]), str(item["sha256"]))
                for item in release["inventory"]["files"]
            ) + (
                ReleaseFile(
                    "release_manifest.json",
                    (final / "release_manifest.json").stat().st_size,
                    hashlib.sha256((final / "release_manifest.json").read_bytes()).hexdigest(),
                ),
            )
            material = ReleaseMaterial(
                sealed.release_id, effective_manifest_sha256, final, files
            )
            self.materials[sealed.release_id] = material
            return FrozenSources(
                freeze_id=f"freeze-{semantic_identity[:24]}",
                commit_sha=snapshot.commit_sha,
                inventory_sha256=inventory_hash,
                release_id=sealed.release_id,
                release_manifest_sha256=effective_manifest_sha256,
            )
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            raise

    def material(self, release_id: str, release_hash: str) -> ReleaseMaterial:
        material = self.materials.get(release_id)
        if material is None or material.release_manifest_sha256 != release_hash:
            raise PublishRuntimeError("frozen release material is unavailable")
        return material


class FixedLocalGates:
    def __init__(self, config: RuntimePublishConfig, runner: ProcessRunner):
        self.config = config
        self.runner = runner

    def _run(self, gate_id: str, snapshot: GitSnapshot, arguments: Sequence[str]) -> GateResult:
        result = self.runner(arguments, self.config.project_root)
        return GateResult(
            gate_id=gate_id,
            commit_sha=snapshot.commit_sha,
            status="pass" if result.returncode == 0 else "blocked",
        )

    def tests(self, snapshot: GitSnapshot) -> GateResult:
        return self._run(
            "local-tests-v1",
            snapshot,
            (
                "python", "-B", "-m", "unittest", "discover", "-s",
                "quant_hub/tests", "-p", "test_*.py", "-q",
            ),
        )

    def public(self, snapshot: GitSnapshot) -> GateResult:
        return self._run(
            "public-git-guard-v1",
            snapshot,
            ("python", "-B", "tools/release/git_guard.py", "gate", "--scope", "all"),
        )


class ExactGitPush:
    def __init__(self, config: RuntimePublishConfig, runner: ProcessRunner):
        self.config = config
        self.runner = runner

    def __call__(self, commit_sha: str) -> PushResult:
        push = self.runner(
            (
                "git", "push", "--porcelain", self.config.git_remote,
                f"{commit_sha}:refs/heads/main",
            ),
            self.config.project_root,
        )
        if push.returncode != 0:
            raise PublishRuntimeError("exact-SHA Git push failed")
        observed = self.runner(
            ("git", "ls-remote", "--heads", self.config.git_remote, "refs/heads/main"),
            self.config.project_root,
        )
        rows = observed.stdout.split()
        if observed.returncode != 0 or not rows or rows[0] != commit_sha:
            raise PublishRuntimeError("remote main does not resolve to pushed exact SHA")
        return PushResult(commit_sha, "pushed")


@dataclass(frozen=True)
class RuntimeDependencies:
    process_runner: ProcessRunner = production_process_runner
    secret_provider: SecretProvider | None = None
    http_get: Callable | None = None
    vm_backend: object | None = None
    deployment_invoker: object | None = None
    recovery_protector: RecoveryProtector | None = None
    recovery_actions: RecoveryProtectionActions | None = None
    remote_command_runner: Callable[[Sequence[str]], CommandResult] | None = None


class ProductionPublishRuntime:
    def __init__(
        self,
        config: RuntimePublishConfig,
        *,
        dependencies: RuntimeDependencies | None = None,
    ) -> None:
        deps = dependencies or RuntimeDependencies()
        secret_provider = deps.secret_provider or EnvironmentSecretProvider()
        freezer = ProductionSourceFreezer(config, process_runner=deps.process_runner)
        gates = FixedLocalGates(config, deps.process_runner)
        github_arguments = {
            "secret_provider": secret_provider,
        }
        if deps.http_get is not None:
            github_arguments["http_get"] = deps.http_get
        ci = GitHubExactSHACI(config.github, **github_arguments)
        remote_runner = deps.remote_command_runner or remote_subprocess_runner
        vm_backend = deps.vm_backend or OpenSSHVMBackend(
            config.vm, command_runner=remote_runner
        )
        invoker = deps.deployment_invoker or OpenSSHDeploymentInvoker(
            config.vm, command_runner=remote_runner
        )
        transport = IncrementalVMTransport(
            config.vm, material_resolver=freezer.material, backend=vm_backend
        )
        protector = deps.recovery_protector or RecoveryProtectionCoordinator(
            config.recovery,
            actions=deps.recovery_actions
            or OpenSSHRecoveryActions(
                config,
                command_runner=remote_runner,
                vm_backend=vm_backend,
                deployment_invoker=invoker,
            ),
        )

        def deploy(candidate: Mapping[str, object]):
            mode = candidate.get("deployment_mode")

            def authorize(release_id: str, candidate_hash: str) -> ActivationAuthorization:
                release = candidate.get("release")
                assert isinstance(release, Mapping)
                material = freezer.material(release_id, str(release["manifest_sha256"]))
                return protector.protect(
                    material=material,
                    publish_candidate_sha256=candidate_hash,
                )

            return VMDeploymentAdapter(
                config.vm,
                invoker=invoker,
                activation_authorization_resolver=(authorize if mode == "activate" else None),
            )(candidate)

        self.config = config
        self.freezer = freezer
        self.protector = protector
        self.secret_provider = secret_provider
        self.pipeline = PublishPipeline(
            PublishActions(
                inspect_git=lambda sha: inspect_local_git(config.project_root, sha),
                local_test_gate=gates.tests,
                public_guard=gates.public,
                freeze_sources=freezer,
                push_once=ExactGitPush(config, deps.process_runner),
                wait_exact_ci=ci,
                transport_candidate=transport,
                deploy_candidate=deploy,
            )
        )
        self.coordinator = PublishCoordinator(PublishQueue(config.state_root), self.pipeline)

    def publish(self, *, commit_sha: str, candidate_only: bool = False) -> Mapping[str, object]:
        target = self.config.github.credential_target
        if target is not None and not isinstance(self.secret_provider(target), SecretValue):
            raise PublishRuntimeError("protected GitHub credential is unavailable")
        if not candidate_only:
            self.protector.preflight()
        request = PublishRequest.create(
            commit_sha,
            deployment_mode="candidate_only" if candidate_only else "activate",
        )
        return self.coordinator.submit_and_drain(request)


__all__ = [
    "EnvironmentSecretProvider",
    "ResourceOverlayConfig",
    "FixedLocalGates",
    "ProcessResult",
    "OpenSSHRecoveryActions",
    "ProductionPublishRuntime",
    "ProductionSourceFreezer",
    "PublishRuntimeError",
    "RecoveryProtector",
    "RecoveryProtectionActions",
    "RecoveryProtectionCoordinator",
    "RecoveryRuntimeConfig",
    "RUNTIME_CONFIG_SCHEMA",
    "RuntimeDependencies",
    "RuntimePublishConfig",
]
