"""``qrh-publish`` 的生产边界 adapters 与配置合同。

本模块实现真实协议，但导入/构造不会产生网络或 VM 写入。GitHub HTTP、SSH/SCP
以及 credential provider 都可注入，因此测试永远只使用内存响应和临时目录。
任何 VM 路径在交给 runner 前都必须经过 :mod:`quant_hub.ops.vm_boundary`。
"""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import subprocess
import time
from typing import Callable, Mapping, Protocol, Sequence
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

from quant_hub.config import ensure_no_reparse_components

from .publish import (
    CIResult,
    PublishError,
    TransferResult,
    VMDeployResult,
)
from .release_identity import (
    IdentityContractError,
    manifest_sha256,
    validate_release_manifest,
)
from .vm_boundary import (
    PRODUCTION_VM_ROOT,
    VMBoundaryError,
    validate_production_vm_write_path,
)


CONFIG_SCHEMA = "qrh-production-publish-config/v1"
REMOTE_INVENTORY_SCHEMA = "qrh-remote-file-inventory/v1"
ADAPTER_REPORT_SCHEMA = "qrh-incremental-transport-report/v1"
FULL_SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}")


class PublishAdapterError(PublishError):
    pass


class SecretValue:
    """只允许 provider/HTTP boundary 显式 reveal；repr/str 永不泄露值。"""

    __slots__ = ("__value",)

    def __init__(self, value: str):
        if not isinstance(value, str) or not value:
            raise PublishAdapterError("credential provider returned an empty secret")
        self.__value = value

    def reveal(self) -> str:
        return self.__value

    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    __str__ = __repr__


SecretProvider = Callable[[str], SecretValue | None]


def _closed(value: object, fields: set[str], label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise PublishAdapterError(f"{label} schema is not closed")
    return value


def _full_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or FULL_SHA.fullmatch(value) is None:
        raise PublishAdapterError(f"{label} is not a full lowercase commit SHA")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise PublishAdapterError(f"{label} is not a lowercase SHA-256")
    return value


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or NAME.fullmatch(value) is None or ".." in value:
        raise PublishAdapterError(f"{label} is invalid")
    return value


@dataclass(frozen=True)
class GitHubCIConfig:
    owner: str
    repository: str
    workflow_id: int
    credential_target: str | None
    poll_interval_seconds: float
    timeout_seconds: float


@dataclass(frozen=True)
class VMConfig:
    ssh_alias: str
    root: PureWindowsPath


@dataclass(frozen=True)
class ProductionPublishConfig:
    github: GitHubCIConfig
    vm: VMConfig

    @classmethod
    def parse(cls, value: object) -> "ProductionPublishConfig":
        root = _closed(value, {"schema_version", "github", "vm"}, "publish config")
        if root["schema_version"] != CONFIG_SCHEMA:
            raise PublishAdapterError("unsupported publish config schema")
        github = _closed(
            root["github"],
            {
                "owner", "repository", "workflow_id", "credential_target",
                "poll_interval_seconds", "timeout_seconds",
            },
            "github config",
        )
        vm = _closed(root["vm"], {"ssh_alias", "root"}, "vm config")
        workflow_id = github["workflow_id"]
        poll = github["poll_interval_seconds"]
        timeout = github["timeout_seconds"]
        if not isinstance(workflow_id, int) or isinstance(workflow_id, bool) or workflow_id <= 0:
            raise PublishAdapterError("workflow_id must be a positive integer")
        if (
            isinstance(poll, bool)
            or not isinstance(poll, (int, float))
            or not 1 <= float(poll) <= 60
        ):
            raise PublishAdapterError("poll interval must be between 1 and 60 seconds")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 10 <= float(timeout) <= 3600
        ):
            raise PublishAdapterError("CI timeout must be between 10 and 3600 seconds")
        credential_target = github["credential_target"]
        if credential_target is not None:
            credential_target = _name(credential_target, "credential_target")
        try:
            approved_root = validate_production_vm_write_path(
                str(vm["root"]), allow_root=True
            )
        except VMBoundaryError as error:
            raise PublishAdapterError("VM root is outside the approved boundary") from error
        if approved_root != PRODUCTION_VM_ROOT:
            raise PublishAdapterError(r"VM root must be exactly D:\quant\quant_platform")
        return cls(
            github=GitHubCIConfig(
                owner=_name(github["owner"], "github owner"),
                repository=_name(github["repository"], "github repository"),
                workflow_id=workflow_id,
                credential_target=credential_target,
                poll_interval_seconds=float(poll),
                timeout_seconds=float(timeout),
            ),
            vm=VMConfig(
                ssh_alias=_name(vm["ssh_alias"], "ssh_alias"),
                root=approved_root,
            ),
        )

    @classmethod
    def load(cls, path: Path) -> "ProductionPublishConfig":
        try:
            return cls.parse(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PublishAdapterError("publish config is unreadable") from error


@dataclass(frozen=True)
class HTTPResponse:
    status: int
    body: bytes


HTTPGet = Callable[[str, Mapping[str, str], float], HTTPResponse]


def urllib_http_get(url: str, headers: Mapping[str, str], timeout: float) -> HTTPResponse:
    """最小 GitHub GET adapter；异常不回显 URL/header/body。"""

    class NoRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, response_headers, newurl):
            return None

    try:
        opener = build_opener(NoRedirect)
        with opener.open(
            Request(url, headers=dict(headers), method="GET"), timeout=timeout
        ) as response:
            body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise PublishAdapterError("GitHub API response exceeds the safe limit")
            return HTTPResponse(status=int(response.status), body=body)
    except PublishAdapterError:
        raise
    except Exception as error:
        raise PublishAdapterError(f"GitHub API request failed ({type(error).__name__})") from None


class GitHubExactSHACI:
    """只接受指定 repository/workflow/main/push/full SHA 的最新 workflow run。"""

    def __init__(
        self,
        config: GitHubCIConfig,
        *,
        secret_provider: SecretProvider,
        http_get: HTTPGet = urllib_http_get,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.config = config
        self.secret_provider = secret_provider
        self.http_get = http_get
        self.monotonic = monotonic
        self.sleep = sleep

    def _headers(self) -> Mapping[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "quant-research-hub-publish",
        }
        if self.config.credential_target is not None:
            secret = self.secret_provider(self.config.credential_target)
            if not isinstance(secret, SecretValue):
                raise PublishAdapterError("protected GitHub credential is unavailable")
            headers["Authorization"] = f"Bearer {secret.reveal()}"
        return headers

    def __call__(self, commit_sha: str) -> CIResult:
        sha = _full_sha(commit_sha, "CI commit_sha")
        query = urlencode(
            {"branch": "main", "event": "push", "head_sha": sha, "per_page": "100"}
        )
        url = (
            f"https://api.github.com/repos/{self.config.owner}/"
            f"{self.config.repository}/actions/runs?{query}"
        )
        deadline = self.monotonic() + self.config.timeout_seconds
        headers = self._headers()
        while True:
            response = self.http_get(url, headers, min(30.0, self.config.timeout_seconds))
            if response.status != 200:
                raise PublishAdapterError(f"GitHub API returned HTTP {response.status}")
            try:
                payload = json.loads(response.body.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError):
                raise PublishAdapterError("GitHub API returned invalid JSON") from None
            runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
            if not isinstance(runs, list):
                raise PublishAdapterError("GitHub workflow response schema is invalid")
            matches: list[Mapping[str, object]] = []
            for run in runs:
                if not isinstance(run, dict):
                    continue
                if (
                    run.get("head_sha") == sha
                    and run.get("head_branch") == "main"
                    and run.get("event") == "push"
                    and run.get("workflow_id") == self.config.workflow_id
                ):
                    repository = run.get("repository")
                    if isinstance(repository, dict) and repository.get("full_name") not in {
                        None, f"{self.config.owner}/{self.config.repository}",
                    }:
                        continue
                    matches.append(run)
            if matches:
                if any(not isinstance(run.get("id"), int) for run in matches):
                    raise PublishAdapterError("GitHub workflow run identity is invalid")
                latest = max(matches, key=lambda run: int(run["id"]))
                status = latest.get("status")
                if status == "completed":
                    if latest.get("conclusion") != "success":
                        raise PublishAdapterError("exact-SHA GitHub CI completed without success")
                    return CIResult(commit_sha=sha, status="success", run_id=str(latest["id"]))
                if status not in {"queued", "in_progress", "pending", "waiting", "requested"}:
                    raise PublishAdapterError("exact-SHA GitHub CI has an unknown status")
            now = self.monotonic()
            if now >= deadline:
                raise PublishAdapterError("exact-SHA GitHub CI timed out")
            self.sleep(min(self.config.poll_interval_seconds, max(0.0, deadline - now)))


@dataclass(frozen=True)
class ReleaseFile:
    path: str
    bytes: int
    sha256: str


@dataclass(frozen=True)
class ReleaseMaterial:
    release_id: str
    release_manifest_sha256: str
    source_root: Path
    files: tuple[ReleaseFile, ...]


MaterialResolver = Callable[[str, str], ReleaseMaterial]


class VMTransportBackend(Protocol):
    def ensure_directory(self, path: PureWindowsPath) -> None: ...

    def inventory(self, path: PureWindowsPath) -> Mapping[str, ReleaseFile]: ...

    def upload(self, local_path: Path, remote_path: PureWindowsPath) -> None: ...


def _relative(value: str) -> str:
    if not isinstance(value, str) or "\\" in value:
        raise PublishAdapterError("release file path must be normalized POSIX relative")
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise PublishAdapterError("release file path escapes its source root")
    for part in pure.parts:
        if part.endswith((".", " ")) or any(character in '<>:"|?*' for character in part):
            raise PublishAdapterError("release file path is Windows-unsafe")
    return pure.as_posix()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class IncrementalVMTransport:
    """只写 approved ``incoming/<release>.partial``，不删除、不触碰 active/C/reference。"""

    def __init__(
        self,
        config: VMConfig,
        *,
        material_resolver: MaterialResolver,
        backend: VMTransportBackend,
    ):
        self.config = config
        self.material_resolver = material_resolver
        self.backend = backend

    @staticmethod
    def _candidate(candidate: Mapping[str, object]) -> tuple[str, str, str]:
        release = candidate.get("release")
        if not isinstance(release, dict) or set(release) != {"release_id", "manifest_sha256"}:
            raise PublishAdapterError("publish candidate release binding is invalid")
        candidate_hash = _digest(
            candidate.get("candidate_manifest_sha256"), "publish candidate hash"
        )
        return (
            _name(release["release_id"], "release_id"),
            _digest(release["manifest_sha256"], "release manifest hash"),
            candidate_hash,
        )

    def __call__(self, candidate: Mapping[str, object]) -> TransferResult:
        release_id, release_hash, candidate_hash = self._candidate(candidate)
        material = self.material_resolver(release_id, release_hash)
        if material.release_id != release_id or material.release_manifest_sha256 != release_hash:
            raise PublishAdapterError("release material resolver returned another identity")
        source_root = material.source_root.resolve(strict=True)
        ensure_no_reparse_components(source_root)
        if not source_root.is_dir():
            raise PublishAdapterError("release material source root is not a directory")
        partial = validate_production_vm_write_path(
            self.config.root / "incoming" / f"{release_id}.partial", allow_root=False
        )
        self.backend.ensure_directory(partial)
        remote = self.backend.inventory(partial)
        expected: dict[str, ReleaseFile] = {}
        casefolded: set[str] = set()
        for item in material.files:
            relative = _relative(item.path)
            if relative.casefold() in casefolded:
                raise PublishAdapterError("release material contains case-colliding paths")
            casefolded.add(relative.casefold())
            if not isinstance(item.bytes, int) or item.bytes < 0:
                raise PublishAdapterError("release file byte count is invalid")
            digest = _digest(item.sha256, "release file hash")
            local = (source_root / PurePosixPath(relative)).resolve(strict=True)
            if not local.is_relative_to(source_root) or not local.is_file():
                raise PublishAdapterError("release file escapes its source root")
            ensure_no_reparse_components(local)
            if local.stat().st_size != item.bytes or _file_sha256(local) != digest:
                raise PublishAdapterError("local release material changed after freeze")
            expected[relative] = ReleaseFile(relative, item.bytes, digest)
        manifest_file = expected.get("release_manifest.json")
        if manifest_file is None:
            raise PublishAdapterError("release material does not contain the bound manifest")
        try:
            manifest_value = json.loads(
                (source_root / "release_manifest.json").read_text(encoding="utf-8")
            )
            semantic_manifest = validate_release_manifest(manifest_value)
        except (OSError, UnicodeError, json.JSONDecodeError, IdentityContractError) as error:
            raise PublishAdapterError("release manifest material is invalid") from error
        if (
            semantic_manifest["release_id"] != release_id
            or manifest_sha256(semantic_manifest) != release_hash
        ):
            raise PublishAdapterError("release material does not contain the bound manifest")

        for relative, item in expected.items():
            existing = remote.get(relative)
            pure_relative = PurePosixPath(relative)
            upload_temporary = pure_relative.with_name(
                f".{pure_relative.name}.upload.partial"
            ).as_posix()
            if existing is not None and (
                existing.bytes == item.bytes and existing.sha256 == item.sha256
            ) and upload_temporary not in remote:
                continue
            remote_target = validate_production_vm_write_path(
                partial / PureWindowsPath(relative), allow_root=False
            )
            self.backend.upload(source_root / PurePosixPath(relative), remote_target)

        observed = dict(self.backend.inventory(partial))
        if set(observed) != set(expected):
            raise PublishAdapterError("remote candidate inventory has missing or extra files")
        if any(
            observed[path].bytes != expected[path].bytes
            or observed[path].sha256 != expected[path].sha256
            for path in expected
        ):
            raise PublishAdapterError("remote candidate inventory hash verification failed")
        return TransferResult(candidate_manifest_sha256=candidate_hash, status="verified")


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str


CommandRunner = Callable[[Sequence[str]], CommandResult]


def subprocess_runner(arguments: Sequence[str]) -> CommandResult:
    """不使用 shell；失败不回显可能含敏感信息的 stdout/stderr。"""

    completed = subprocess.run(
        list(arguments), shell=False, check=False, capture_output=True,
        text=True, encoding="utf-8", errors="replace",
    )
    return CommandResult(returncode=completed.returncode, stdout=completed.stdout)


def _powershell_encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


class OpenSSHVMBackend:
    """使用 Windows OpenSSH/PowerShell 的实际 backend；命令均为 argv，不经 shell。"""

    def __init__(self, config: VMConfig, *, command_runner: CommandRunner = subprocess_runner):
        self.config = config
        self.command_runner = command_runner

    def _ssh(self, script: str) -> str:
        result = self.command_runner(
            [
                "ssh", self.config.ssh_alias, "powershell.exe", "-NoProfile",
                "-NonInteractive", "-EncodedCommand", _powershell_encoded(script),
            ]
        )
        if result.returncode != 0:
            raise PublishAdapterError("VM SSH command failed")
        return result.stdout

    @staticmethod
    def _ensure_directory_script(path: PureWindowsPath) -> str:
        approved = validate_production_vm_write_path(path, allow_root=False)
        production_root = str(PRODUCTION_VM_ROOT)
        return (
            "$ErrorActionPreference='Stop';"
            f"$approvedRoot={_ps_literal(production_root)};"
            f"$target={_ps_literal(str(approved))};"
            "if(-not(Test-Path -LiteralPath $approvedRoot -PathType Container)){throw 'root_missing'};"
            "$rootItem=Get-Item -LiteralPath $approvedRoot -Force;"
            "if(($rootItem.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'root_reparse'};"
            "$root=$rootItem.FullName.TrimEnd('\\');$current=$root;"
            "$relative=$target.Substring($approvedRoot.Length).TrimStart('\\');"
            "foreach($part in $relative.Split('\\',[StringSplitOptions]::RemoveEmptyEntries)){"
            "$current=Join-Path $current $part;"
            "if(Test-Path -LiteralPath $current){$item=Get-Item -LiteralPath $current -Force;"
            "if(-not $item.PSIsContainer){throw 'non_directory'};"
            "if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'reparse'}}"
            "else{$item=New-Item -ItemType Directory -Path $current;"
            "if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'reparse'}}};"
            "$resolved=(Resolve-Path -LiteralPath $target).Path;"
            "if(-not($resolved.StartsWith($root+'\\',[StringComparison]::OrdinalIgnoreCase))){throw 'escape'};"
        )

    def ensure_directory(self, path: PureWindowsPath) -> None:
        approved = validate_production_vm_write_path(path, allow_root=False)
        self._ssh(self._ensure_directory_script(approved))

    def inventory(self, path: PureWindowsPath) -> Mapping[str, ReleaseFile]:
        approved = validate_production_vm_write_path(path, allow_root=False)
        script = (
            self._ensure_directory_script(approved)
            +
            f"$r={_ps_literal(str(approved))};"
            "$root=(Resolve-Path -LiteralPath $r).Path;"
            "$bad=@(Get-ChildItem -LiteralPath $root -Directory -Recurse -Force|Where-Object{"
            "($_.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0});"
            "if($bad.Count-ne 0){throw 'reparse'};"
            "$rows=@(Get-ChildItem -LiteralPath $root -File -Recurse -Force|ForEach-Object{"
            "if(($_.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'reparse'};"
            "[ordered]@{path=$_.FullName.Substring($root.Length).TrimStart('\\').Replace('\\','/');"
            "bytes=$_.Length;sha256=(Get-FileHash -Algorithm SHA256 -LiteralPath $_.FullName).Hash.ToLowerInvariant()}});"
            "$rows|ConvertTo-Json -Compress"
        )
        output = self._ssh(script).strip()
        try:
            rows = json.loads(output or "[]")
        except json.JSONDecodeError:
            raise PublishAdapterError("VM inventory returned invalid JSON") from None
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list):
            raise PublishAdapterError("VM inventory schema is invalid")
        inventory: dict[str, ReleaseFile] = {}
        for raw in rows:
            row = _closed(raw, {"path", "bytes", "sha256"}, "VM inventory row")
            relative = _relative(str(row["path"]))
            if relative in inventory:
                raise PublishAdapterError("VM inventory contains duplicate paths")
            if not isinstance(row["bytes"], int) or row["bytes"] < 0:
                raise PublishAdapterError("VM inventory byte count is invalid")
            inventory[relative] = ReleaseFile(
                relative, int(row["bytes"]), _digest(row["sha256"], "VM file hash")
            )
        return inventory

    def upload(self, local_path: Path, remote_path: PureWindowsPath) -> None:
        approved = validate_production_vm_write_path(remote_path, allow_root=False)
        self.ensure_directory(approved.parent)
        expected_bytes = local_path.stat().st_size
        expected_hash = _file_sha256(local_path)
        temporary = validate_production_vm_write_path(
            approved.with_name(f".{approved.name}.upload.partial"),
            allow_root=False,
        )
        destination = (
            f"{self.config.ssh_alias}:"
            f"{str(temporary).replace(os.sep, '/').replace(chr(92), '/')}"
        )
        result = self.command_runner(["scp", "-q", str(local_path), destination])
        if result.returncode != 0:
            raise PublishAdapterError("VM SCP upload failed")
        # 只有远端临时文件的 hash/size/reparse 全部通过后才替换 partial 内目标。
        script = (
            "$ErrorActionPreference='Stop';"
            f"$tmp={_ps_literal(str(temporary))};$dst={_ps_literal(str(approved))};"
            "$item=Get-Item -LiteralPath $tmp -Force;"
            "if($item.PSIsContainer-or(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'upload_type'};"
            f"if($item.Length-ne {expected_bytes}){{throw 'upload_size'}};"
            f"if((Get-FileHash -Algorithm SHA256 -LiteralPath $tmp).Hash.ToLowerInvariant()-ne '{expected_hash}')"
            "{throw 'upload_hash'};"
            "if(Test-Path -LiteralPath $dst){$old=Get-Item -LiteralPath $dst -Force;"
            "if($old.PSIsContainer-or(($old.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'target_type'};"
            "Remove-Item -LiteralPath $dst -Force};"
            "Move-Item -LiteralPath $tmp -Destination $dst;"
            "$final=Get-Item -LiteralPath $dst -Force;"
            f"if($final.Length-ne {expected_bytes}){{throw 'final_size'}};"
            f"if((Get-FileHash -Algorithm SHA256 -LiteralPath $dst).Hash.ToLowerInvariant()-ne '{expected_hash}')"
            "{throw 'final_hash'};"
        )
        self._ssh(script)


class DeploymentInvoker(Protocol):
    def invoke(
        self,
        *,
        vm_root: PureWindowsPath,
        release_id: str,
        release_manifest_sha256: str,
        publish_candidate_sha256: str,
        deployment_mode: str,
    ) -> Mapping[str, object]: ...


class VMDeploymentAdapter:
    """调用固定 VM deployment-controller CLI，并复核返回身份。"""

    def __init__(self, config: VMConfig, *, invoker: DeploymentInvoker):
        self.config = config
        self.invoker = invoker

    def __call__(self, candidate: Mapping[str, object]) -> VMDeployResult:
        release_id, release_hash, candidate_hash = IncrementalVMTransport._candidate(candidate)
        deployment_mode = candidate.get("deployment_mode")
        if deployment_mode not in {"activate", "candidate_only"}:
            raise PublishAdapterError("publish candidate deployment_mode is invalid")
        root = validate_production_vm_write_path(self.config.root, allow_root=True)
        result = self.invoker.invoke(
            vm_root=root,
            release_id=release_id,
            release_manifest_sha256=release_hash,
            publish_candidate_sha256=candidate_hash,
            deployment_mode=str(deployment_mode),
        )
        value = _closed(
            result,
            {
                "schema_version", "release_id", "release_manifest_sha256",
                "publish_candidate_sha256", "status", "receipt_id", "receipt_type",
            },
            "VM deploy result",
        )
        if value["schema_version"] != "qrh-vm-deploy-result/v1":
            raise PublishAdapterError("unsupported VM deploy result schema")
        if (
            value["release_id"] != release_id
            or value["release_manifest_sha256"] != release_hash
            or value["publish_candidate_sha256"] != candidate_hash
        ):
            raise PublishAdapterError("VM deployment controller returned another identity")
        expected = (
            ("activated", "activation")
            if deployment_mode == "activate"
            else ("candidate_validated", "candidate_validation")
        )
        if (value["status"], value["receipt_type"]) != expected:
            raise PublishAdapterError("VM deployment controller did not satisfy requested mode")
        return VMDeployResult(
            candidate_manifest_sha256=candidate_hash,
            status=str(value["status"]),
            receipt_id=_name(value["receipt_id"], "VM deploy receipt_id"),
            receipt_type=str(value["receipt_type"]),
        )


class OpenSSHDeploymentInvoker:
    """实际远端调用固定 ``quant_hub.ops.vm_deploy_cli``；不接受任意命令。"""

    def __init__(self, config: VMConfig, *, command_runner: CommandRunner = subprocess_runner):
        self.config = config
        self.command_runner = command_runner

    def invoke(
        self,
        *,
        vm_root: PureWindowsPath,
        release_id: str,
        release_manifest_sha256: str,
        publish_candidate_sha256: str,
        deployment_mode: str,
    ) -> Mapping[str, object]:
        root = validate_production_vm_write_path(vm_root, allow_root=True)
        if deployment_mode not in {"activate", "candidate_only"}:
            raise PublishAdapterError("deployment_mode is invalid")
        temporary = validate_production_vm_write_path(
            root / "tmp" / "deployment-cli", allow_root=False
        )
        cli_arguments = [
            "-B", "-m", "quant_hub.ops.vm_deploy_cli", "apply-publish",
            "--vm-root", str(root), "--release-id", _name(release_id, "release_id"),
            "--release-manifest-sha256", _digest(release_manifest_sha256, "release hash"),
            "--publish-candidate-sha256", _digest(publish_candidate_sha256, "candidate hash"),
            "--deployment-mode", deployment_mode,
            "--json",
        ]
        rendered_arguments = ",".join(_ps_literal(item) for item in cli_arguments)
        script = (
            OpenSSHVMBackend._ensure_directory_script(temporary)
            + f"$tmp={_ps_literal(str(temporary))};"
            "$env:PYTHONDONTWRITEBYTECODE='1';$env:TEMP=$tmp;$env:TMP=$tmp;"
            f"$cli=@({rendered_arguments});$output=& python @cli;"
            "if($LASTEXITCODE-ne 0){throw 'deploy_cli_failed'};"
            "$output|Write-Output"
        )
        arguments = [
            "ssh", self.config.ssh_alias, "powershell.exe", "-NoProfile",
            "-NonInteractive", "-EncodedCommand", _powershell_encoded(script),
        ]
        result = self.command_runner(arguments)
        if result.returncode != 0:
            raise PublishAdapterError("remote deployment-controller CLI failed")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise PublishAdapterError("remote deployment-controller result is invalid JSON") from None
        if not isinstance(value, dict):
            raise PublishAdapterError("remote deployment-controller result must be an object")
        return value


__all__ = [
    "CONFIG_SCHEMA",
    "CommandResult",
    "GitHubExactSHACI",
    "HTTPResponse",
    "IncrementalVMTransport",
    "OpenSSHDeploymentInvoker",
    "OpenSSHVMBackend",
    "ProductionPublishConfig",
    "PublishAdapterError",
    "ReleaseFile",
    "ReleaseMaterial",
    "SecretValue",
    "VMDeploymentAdapter",
    "subprocess_runner",
]
