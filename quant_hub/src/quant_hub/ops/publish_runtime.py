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
import sys
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
    _subprocess_runner as _remote_subprocess_runner,
)
from .release_builder import seal_knowledge_release
from .release_identity import manifest_sha256, validate_release_manifest
from . import local_release_identity as local_identity


RUNTIME_CONFIG_SCHEMA = "qrh-production-publish-runtime/v1"
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")

# These business-data assets are deliberately excluded from Public Git, but
# they are part of the sealed production runtime. A code overlay must inherit
# their exact bytes from the validated immutable runtime base instead of
# silently dropping them or reading an unsealed developer working copy.
_INHERITED_PRIVATE_CODE_EXACT = frozenset(
    {
        PurePosixPath("src/quant_hub/presentation/archive_presentation.json"),
        PurePosixPath(
            "src/quant_hub/presentation/citation_projection_overrides.json"
        ),
        PurePosixPath("src/quant_hub/presentation/evidence_zh_overlays.json"),
        PurePosixPath("src/quant_hub/presentation/research_supplements.json"),
    }
)
_INHERITED_PRIVATE_CODE_PREFIXES = (
    PurePosixPath("src/quant_hub/presentation/chapter_manifests"),
    PurePosixPath("src/quant_hub/presentation/supplements"),
)


def _is_inherited_private_code_path(relative: PurePosixPath) -> bool:
    return relative in _INHERITED_PRIVATE_CODE_EXACT or any(
        prefix in relative.parents for prefix in _INHERITED_PRIVATE_CODE_PREFIXES
    )


class PublishRuntimeError(PublishError):
    pass


def _validate_candidate_release(value: object) -> Mapping[str, object]:
    if isinstance(value, dict) and value.get("schema_version") == (
        local_identity.RELEASE_MANIFEST_SCHEMA
    ):
        return local_identity.validate_release_manifest(value)
    return validate_release_manifest(value)


def _candidate_manifest_sha256(value: Mapping[str, object]) -> str:
    if value.get("schema_version") == local_identity.RELEASE_MANIFEST_SCHEMA:
        return local_identity.identity_sha256(value)
    return manifest_sha256(value)


def _candidate_inventory_sha256(value: Mapping[str, object]) -> str:
    if value.get("schema_version") == "qrh-release-file-inventory/v2":
        return local_identity.identity_sha256(value)
    return manifest_sha256(value)


@dataclass(frozen=True)
class ResourceOverlayConfig:
    logical_name: str
    source_path: Path
    target_relative_path: str


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

    @classmethod
    def parse(cls, value: object) -> "RuntimePublishConfig":
        fields = {
            "schema_version", "project_root", "state_root", "candidate_root",
            "git_remote", "runtime_base", "runtime_base_manifest_sha256",
            "reference_archive_root", "code_source_relative_path",
            "code_overlay_relative_path",
            "launcher_relative_path", "required_runtime_paths", "resource_overlays",
            "github", "vm",
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
            "presentation_manifest", "papers", "objects", "paper_lab", "state_seed",
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
        presentation_manifest = (
            PurePosixPath(code_overlay)
            / "src"
            / "quant_hub"
            / "presentation"
            / "archive_presentation.json"
        ).as_posix()
        if required["presentation_manifest"] != presentation_manifest:
            raise PublishRuntimeError(
                "presentation manifest authority and code overlay differ"
            )
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
        project_resolved = paths["project_root"].resolve()
        mutable_roots = (
            paths["state_root"].resolve(),
            paths["candidate_root"].resolve(),
        )
        source_roots = (
            runtime_base.resolve(),
            archive_root.resolve(),
            *(source.source_path.resolve() for source in sources),
        )
        if any(root == project_resolved or root.is_relative_to(project_resolved) for root in mutable_roots):
            raise PublishRuntimeError("mutable publish roots must stay outside Git")
        if any(
            mutable == source
            or mutable.is_relative_to(source)
            or source.is_relative_to(mutable)
            for mutable in mutable_roots
            for source in source_roots
        ):
            raise PublishRuntimeError("mutable publish root overlaps a read-only source")
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


def _production_process_runner(arguments: Sequence[str], cwd: Path) -> ProcessResult:
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
            manifest = _validate_candidate_release(
                json.loads(manifest_path.read_text(encoding="utf-8"))
            )
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise PublishRuntimeError("runtime base release manifest is invalid") from error
        if (
            _candidate_manifest_sha256(manifest)
            != self.config.runtime_base_manifest_sha256
        ):
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
                overlay_relative = relative.relative_to(overlay)
                if not _is_inherited_private_code_path(overlay_relative):
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
            manifest = _validate_candidate_release(
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
        if manifest["resources"].get(
            "inventory_sha256"
        ) != _candidate_inventory_sha256(inventory):
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
                if _is_inherited_private_code_path(overlay_relative):
                    raise PublishRuntimeError(
                        "tracked code conflicts with inherited private runtime authority"
                    )
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
                "presentation_manifest",
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
                "schema_version": local_identity.RELEASE_MANIFEST_SCHEMA,
                "release_id": release_id,
                "built_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "application": {
                    "source_kind": "git",
                    "commit_sha": snapshot.commit_sha,
                    "tracked_tree_sha256": snapshot.tracked_tree_sha256,
                    "build_tool_version": "qrh-production-publish-runtime/v2",
                    "provenance": {
                        "builder": "qrh-production-source-freezer",
                        "labels": ["exact-local-active-prior", "public-source"],
                    },
                },
                "content": {
                    "snapshot_id": enriched.snapshot_id,
                    "source_inventory_sha256": None,
                    "ir_sha256": None,
                    "knowledge_sha256": None,
                    "search_sha256": None,
                    "page_projection_sha256": None,
                    "mcp_sha256": None,
                    "active_membership_sha256": local_identity.identity_sha256(
                        dict(sorted(knowledge_snapshot.active_membership.items()))
                    ),
                    "knowledge_enrichment": {
                        "status": "ready_set",
                        "generation_membership_sha256": (
                            local_identity.identity_sha256(
                                dict(sorted(enriched.generation_membership.items()))
                            )
                        ),
                        "status_membership_sha256": (
                            local_identity.identity_sha256(
                                dict(
                                    sorted(
                                        enriched.knowledge_status_membership.items()
                                    )
                                )
                            )
                        ),
                        "semantic_authority_sha256": (
                            local_identity.identity_sha256(
                                semantic_receipt.to_dict()
                            )
                        ),
                    },
                    "presentation": {"language": "zh-CN"},
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
                evidence_database_path=staging.joinpath(
                    *PurePosixPath(
                        self.config.required_runtime_paths[
                            "research_papers_database"
                        ]
                    ).parts
                ),
                citation_overlay_manifest_path=staging.joinpath(
                    *PurePosixPath(self.config.code_overlay_relative_path).parts,
                    "src",
                    "quant_hub",
                    "presentation",
                    "citation_projection_overrides.json",
                ),
                evidence_migration_root=staging.joinpath(
                    "runtime_contract",
                    "migrations",
                    "research_papers",
                ),
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
            effective_manifest_sha256 = _candidate_manifest_sha256(release)
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
                sys.executable, "-B", "-m", "unittest", "discover", "-s",
                "quant_hub/tests", "-t", "quant_hub", "-p", "test_*.py", "-q",
            ),
        )

    def public(self, snapshot: GitSnapshot) -> GateResult:
        return self._run(
            "public-git-guard-v1",
            snapshot,
            (
                sys.executable,
                "-B",
                "tools/release/git_guard.py",
                "gate",
                "--scope",
                "all",
            ),
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
    process_runner: ProcessRunner = _production_process_runner
    secret_provider: SecretProvider | None = None
    http_get: Callable | None = None
    vm_backend: object | None = None
    deployment_invoker: object | None = None
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
        remote_runner = deps.remote_command_runner or _remote_subprocess_runner
        vm_backend = deps.vm_backend or OpenSSHVMBackend(
            config.vm, command_runner=remote_runner
        )
        invoker = deps.deployment_invoker or OpenSSHDeploymentInvoker(
            config.vm, command_runner=remote_runner
        )
        transport = IncrementalVMTransport(
            config.vm, material_resolver=freezer.material, backend=vm_backend
        )
        def deploy(candidate: Mapping[str, object]):
            mode = candidate.get("deployment_mode")

            def authorize(release_id: str, candidate_hash: str) -> ActivationAuthorization:
                release = candidate.get("release")
                assert isinstance(release, Mapping)
                manifest_sha256 = str(release["manifest_sha256"])
                freezer.material(release_id, manifest_sha256)
                return ActivationAuthorization(
                    # The VM journal is the crash-replay authority.  A fresh
                    # publisher process must address the same journal for the
                    # same immutable publish candidate instead of minting a
                    # second attempt after an unknown remote outcome.
                    deployment_attempt_id=f"deploy-{manifest_sha256}"
                )

            return VMDeploymentAdapter(
                config.vm,
                invoker=invoker,
                activation_authorization_resolver=(authorize if mode == "activate" else None),
            )(candidate)

        self.config = config
        self.freezer = freezer
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
    "ProductionPublishRuntime",
    "ProductionSourceFreezer",
    "PublishRuntimeError",
    "RUNTIME_CONFIG_SCHEMA",
    "RuntimeDependencies",
    "RuntimePublishConfig",
]
