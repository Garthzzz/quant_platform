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
    target_address: str
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
        vm = _closed(root["vm"], {"ssh_alias", "target_address", "root"}, "vm config")
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
        if vm["target_address"] != "10.5.1.240":
            raise PublishAdapterError("production/recovery target must be 10.5.1.240")
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
                target_address="10.5.1.240",
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


def ssh_target_guard_script(target_address: str) -> str:
    """Bind every remote action to the configured server-side SSH address."""

    if target_address != "10.5.1.240":
        raise PublishAdapterError("production SSH target must be 10.5.1.240")
    return (
        "$ssh=($env:SSH_CONNECTION -split ' ');"
        f"if($ssh.Count-lt 3-or $ssh[2]-ne{_ps_literal(target_address)})"
        "{throw 'ssh_target_address_differs'};"
    )


def exact_production_root_parent_guard_script() -> str:
    """Return a write-free guard for exact D root and every existing parent."""

    production_root = str(PRODUCTION_VM_ROOT)
    return (
        f"$approvedRoot={_ps_literal(production_root)};"
        "$rootFull=[IO.Path]::GetFullPath($approvedRoot).TrimEnd('\\');"
        "$expectedFull=$approvedRoot.TrimEnd('\\');"
        "if(-not $rootFull.Equals($expectedFull,[StringComparison]::OrdinalIgnoreCase))"
        "{throw 'root_full_path_differs'};"
        "$rootCursor=$rootFull;"
        "while($true){$rootComponent=Get-Item -LiteralPath $rootCursor -Force -ErrorAction Stop;"
        "if(($rootComponent.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
        "{throw 'root_parent_reparse'};"
        "if(-not $rootComponent.PSIsContainer){throw 'root_chain_not_directory'};"
        "$rootParent=Split-Path -Parent $rootCursor;"
        "if(-not $rootParent-or $rootParent-eq $rootCursor){break};"
        "$rootCursor=$rootParent};"
    )


_OPERATIONAL_MODULE_BINDINGS = {
    "deployment_cli_module": (
        r"D:\quant\quant_platform\tooling\python\Lib\site-packages"
        r"\quant_hub\ops\vm_deploy_cli.py"
    ),
    "publish_recovery_cli_module": (
        r"D:\quant\quant_platform\tooling\python\Lib\site-packages"
        r"\quant_hub\ops\publish_recovery_cli.py"
    ),
}


def _powershell_package_inventory_verification_script() -> str:
    """Rebuild Python's canonical package inventory using PowerShell bytes."""

    return (
        "$packageDirs=@(Get-ChildItem -LiteralPath $packageFull -Directory -Recurse -Force);"
        "if(@($packageDirs|Where-Object{($_.Attributes-band"
        "[IO.FileAttributes]::ReparsePoint)-ne 0}).Count-ne 0){throw 'package_reparse'};"
        "$records=New-Object 'System.Collections.Generic.List[string]';"
        "$packageFiles=@(Get-ChildItem -LiteralPath $packageFull -File -Recurse -Force);"
        "foreach($file in $packageFiles){$relative=$file.FullName.Substring($packageFull.Length)."
        "TrimStart('\\').Replace('\\','/');if((@($relative -split '/') -contains '__pycache__')"
        "-or $relative.EndsWith('.pyc',[StringComparison]::OrdinalIgnoreCase)"
        "-or $relative.EndsWith('.pyo',[StringComparison]::OrdinalIgnoreCase)){continue};"
        "if(($file.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
        "{throw 'package_file_reparse'};$hash=(Get-FileHash -Algorithm SHA256 "
        "-LiteralPath $file.FullName).Hash.ToLowerInvariant();"
        # PowerShell single-quoted strings do not interpret backticks.  Use
        # explicit characters so these bytes equal Python's tab/newline form.
        "$records.Add($relative+[char]9+$file.Length+[char]9+$hash+[char]10)};"
        "$records.Sort([StringComparer]::Ordinal);$inventoryText=[string]::Concat($records);"
        "$inventoryBytes=(New-Object Text.UTF8Encoding($false)).GetBytes($inventoryText);"
        "$inventoryHasher=[Security.Cryptography.SHA256]::Create();try{"
        "$packageHash=([BitConverter]::ToString($inventoryHasher.ComputeHash($inventoryBytes)))."
        "Replace('-','').ToLowerInvariant()}finally{$inventoryHasher.Dispose()};"
        "if($packageHash-ne $candidate.quant_hub_package_inventory_sha256)"
        "{throw 'package_inventory_hash_mismatch'};"
    )


def verified_d_tooling_python_script(module_binding: str) -> str:
    """PowerShell prelude binding exact D Python and one fixed CLI module.

    This prelude uses only Windows/PowerShell primitives.  It verifies the
    closed install-candidate document and the complete non-reparse parent chain
    before executing any project Python code.
    """

    try:
        module_path = _OPERATIONAL_MODULE_BINDINGS[module_binding]
    except KeyError as error:
        raise PublishAdapterError("unreviewed operational module binding") from error
    python_path = r"D:\quant\quant_platform\tooling\python\python.exe"
    candidate_path = r"D:\quant\quant_platform\control\service_install_candidate.json"
    expected_fields = (
        "schema_version", "service_name", "python_class", "start_type",
        "service_executable", "service_executable_sha256", "service_python",
        "service_python_sha256", "service_host_module",
        "service_host_module_sha256", "service_entry_module",
        "service_entry_module_sha256", "deployment_cli_module",
        "deployment_cli_module_sha256", "publish_recovery_cli_module",
        "publish_recovery_cli_module_sha256", "access_gate_module",
        "access_gate_module_sha256", "deployment_runtime",
        "deployment_runtime_sha256", "quant_hub_package_root",
        "quant_hub_package_inventory_sha256",
    )
    rendered_fields = ",".join(_ps_literal(field) for field in expected_fields)
    module_hash_field = f"{module_binding}_sha256"
    package_verification = _powershell_package_inventory_verification_script()
    return (
        exact_production_root_parent_guard_script()
        + "function Assert-OperationalFile{param([string]$Path,[string]$Sha256);"
        "$full=[IO.Path]::GetFullPath($Path);"
        "if(-not $full.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
        "{throw 'operational_path_escaped_exact_root'};"
        "$cursor=$full;$first=$true;$file=$null;while($true){"
        "$item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop;"
        "if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
        "{throw 'operational_reparse_chain'};"
        "if($first){if($item.PSIsContainer){throw 'operational_not_regular_file'};"
        "$file=$item;$first=$false}elseif(-not $item.PSIsContainer)"
        "{throw 'operational_parent_not_directory'};"
        "$parent=Split-Path -Parent $cursor;if(-not $parent-or $parent-eq $cursor){break};"
        "$cursor=$parent};"
        "if($Sha256-and((Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash."
        "ToLowerInvariant()-ne $Sha256)){throw 'operational_hash_mismatch'};return $full};"
        f"$candidatePath={_ps_literal(candidate_path)};"
        "$candidateFull=Assert-OperationalFile $candidatePath '';"
        "$candidate=Get-Content -LiteralPath $candidateFull -Raw -Encoding UTF8|ConvertFrom-Json;"
        f"$expectedFields=@({rendered_fields})|Sort-Object;"
        "$actualFields=@($candidate.PSObject.Properties.Name)|Sort-Object;"
        "if(($expectedFields-join '|')-ne($actualFields-join '|'))"
        "{throw 'operational_binding_schema_differs'};"
        "if($candidate.schema_version-ne'qrh-windows-service-install-candidate/v1'"
        "-or $candidate.service_name-ne'QuantResearchHub'"
        "-or $candidate.python_class-ne"
        "'quant_hub.ops.windows_service.QuantResearchHubWindowsService'"
        "-or $candidate.start_type-ne'automatic'){throw 'operational_binding_identity_differs'};"
        "$packageExpected=Join-Path $rootFull 'tooling\\python\\Lib\\site-packages\\quant_hub';"
        "$packageFull=[IO.Path]::GetFullPath($packageExpected);"
        "if(-not $packageFull.Equals($candidate.quant_hub_package_root,"
        "[StringComparison]::OrdinalIgnoreCase)){throw 'package_binding_path_differs'};"
        "$packageCursor=$packageFull;while($true){$packageItem=Get-Item -LiteralPath "
        "$packageCursor -Force -ErrorAction Stop;if(-not $packageItem.PSIsContainer)"
        "{throw 'package_parent_not_directory'};if(($packageItem.Attributes-band"
        "[IO.FileAttributes]::ReparsePoint)-ne 0){throw 'package_reparse_chain'};"
        "$packageParent=Split-Path -Parent $packageCursor;if(-not $packageParent-or"
        "$packageParent-eq $packageCursor){break};$packageCursor=$packageParent};"
        + package_verification
        +
        f"$pythonExpected={_ps_literal(python_path)};"
        f"$moduleExpected={_ps_literal(module_path)};"
        "$pythonFull=Assert-OperationalFile $pythonExpected $candidate.service_python_sha256;"
        f"$moduleFull=Assert-OperationalFile $moduleExpected $candidate.{module_hash_field};"
        "if(-not $pythonFull.Equals($candidate.service_python,[StringComparison]::OrdinalIgnoreCase)"
        f"-or-not $moduleFull.Equals($candidate.{module_binding},[StringComparison]::OrdinalIgnoreCase))"
        "{throw 'operational_binding_path_differs'};"
        "$python=$pythonFull;"
        "$env:PYTHONPATH=Join-Path $rootFull 'tooling\\python\\Lib\\site-packages';"
    )


def bootstrap_verified_d_tooling_python_script(
    *, service_python_sha256: str, quant_hub_package_inventory_sha256: str
) -> str:
    """First-generation trust prelude before a service candidate exists."""

    python_hash = _digest(service_python_sha256, "bootstrap service Python hash")
    package_hash = _digest(
        quant_hub_package_inventory_sha256, "bootstrap quant_hub inventory hash"
    )
    return (
        exact_production_root_parent_guard_script()
        + "$packageFull=Join-Path $rootFull 'tooling\\python\\Lib\\site-packages\\quant_hub';"
        "$candidate=[pscustomobject]@{quant_hub_package_inventory_sha256="
        + _ps_literal(package_hash)
        + "};"
        + _powershell_package_inventory_verification_script()
        + "$pythonExpected=Join-Path $rootFull 'tooling\\python\\python.exe';"
        "$pythonItem=Get-Item -LiteralPath $pythonExpected -Force -ErrorAction Stop;"
        "if($pythonItem.PSIsContainer-or(($pythonItem.Attributes-band"
        "[IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'bootstrap_python_not_regular'};"
        "if((Get-FileHash -Algorithm SHA256 -LiteralPath $pythonExpected).Hash."
        "ToLowerInvariant()-ne"
        + _ps_literal(python_hash)
        + "){throw 'bootstrap_python_hash_mismatch'};$python=$pythonExpected;"
    )


class OpenSSHVMBackend:
    """使用 Windows OpenSSH/PowerShell 的实际 backend；命令均为 argv，不经 shell。"""

    def __init__(self, config: VMConfig, *, command_runner: CommandRunner = subprocess_runner):
        self.config = config
        self.command_runner = command_runner

    def _ssh(self, script: str) -> str:
        script = ssh_target_guard_script(self.config.target_address) + script
        result = self.command_runner(
            [
                "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "--", self.config.ssh_alias, "powershell.exe", "-NoProfile",
                "-NonInteractive", "-EncodedCommand", _powershell_encoded(script),
            ]
        )
        if result.returncode != 0:
            raise PublishAdapterError("VM SSH command failed")
        return result.stdout

    @staticmethod
    def _ensure_directory_script(path: PureWindowsPath) -> str:
        approved = validate_production_vm_write_path(path, allow_root=False)
        return (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + f"$target={_ps_literal(str(approved))};"
            "$targetFull=[IO.Path]::GetFullPath($target);"
            "if(-not $targetFull.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'target_escaped_exact_root'};"
            "$root=$rootFull;$current=$root;"
            "$relative=$targetFull.Substring($rootFull.Length).TrimStart('\\');"
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
        result = self.command_runner(
            [
                "scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "-o", f"HostName={self.config.target_address}",
                "--", str(local_path), destination,
            ]
        )
        if result.returncode != 0:
            raise PublishAdapterError("VM SCP upload failed")
        # 只有远端临时文件的 hash/size/reparse 全部通过后才替换 partial 内目标。
        script = (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + f"$tmp={_ps_literal(str(temporary))};$dst={_ps_literal(str(approved))};"
            "$tmpFull=[IO.Path]::GetFullPath($tmp);$dstFull=[IO.Path]::GetFullPath($dst);"
            "if(-not $tmpFull.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase)"
            "-or-not $dstFull.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'upload_path_escaped_exact_root'};"
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
        deployment_attempt_id: str | None,
        recovery_protection_receipt_id: str | None,
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class ActivationAuthorization:
    deployment_attempt_id: str
    recovery_protection_receipt_id: str


ActivationAuthorizationResolver = Callable[
    [str, str], ActivationAuthorization
]


class VMDeploymentAdapter:
    """调用固定 VM deployment-controller CLI，并复核返回身份。"""

    def __init__(
        self,
        config: VMConfig,
        *,
        invoker: DeploymentInvoker,
        activation_authorization_resolver: ActivationAuthorizationResolver | None = None,
    ):
        self.config = config
        self.invoker = invoker
        self.activation_authorization_resolver = activation_authorization_resolver

    def __call__(self, candidate: Mapping[str, object]) -> VMDeployResult:
        release_id, release_hash, candidate_hash = IncrementalVMTransport._candidate(candidate)
        deployment_mode = candidate.get("deployment_mode")
        if deployment_mode not in {"activate", "candidate_only"}:
            raise PublishAdapterError("publish candidate deployment_mode is invalid")
        authorization: ActivationAuthorization | None = None
        if deployment_mode == "activate":
            if self.activation_authorization_resolver is None:
                raise PublishAdapterError("activation recovery protection is unavailable")
            authorization = self.activation_authorization_resolver(
                release_id, candidate_hash
            )
            if not isinstance(authorization, ActivationAuthorization):
                raise PublishAdapterError("activation authorization schema is invalid")
            _name(authorization.deployment_attempt_id, "deployment_attempt_id")
            _name(
                authorization.recovery_protection_receipt_id,
                "recovery_protection_receipt_id",
            )
        root = validate_production_vm_write_path(self.config.root, allow_root=True)
        result = self.invoker.invoke(
            vm_root=root,
            release_id=release_id,
            release_manifest_sha256=release_hash,
            publish_candidate_sha256=candidate_hash,
            deployment_mode=str(deployment_mode),
            deployment_attempt_id=(
                authorization.deployment_attempt_id if authorization else None
            ),
            recovery_protection_receipt_id=(
                authorization.recovery_protection_receipt_id if authorization else None
            ),
        )
        value = _closed(
            result,
            {
                "schema_version", "release_id", "release_manifest_sha256",
                "publish_candidate_sha256", "status", "evidence_id", "evidence_type",
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
            ("activated", "activation_receipt")
            if deployment_mode == "activate"
            else ("candidate_validated", "candidate_validation_event")
        )
        if (value["status"], value["evidence_type"]) != expected:
            raise PublishAdapterError("VM deployment controller did not satisfy requested mode")
        return VMDeployResult(
            candidate_manifest_sha256=candidate_hash,
            status=str(value["status"]),
            evidence_id=_name(value["evidence_id"], "VM deploy evidence_id"),
            evidence_type=str(value["evidence_type"]),
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
        deployment_attempt_id: str | None,
        recovery_protection_receipt_id: str | None,
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
        ]
        if deployment_mode == "activate":
            cli_arguments.extend(
                [
                    "--deployment-attempt-id",
                    _name(deployment_attempt_id, "deployment_attempt_id"),
                    "--recovery-protection-receipt-id",
                    _name(
                        recovery_protection_receipt_id,
                        "recovery_protection_receipt_id",
                    ),
                ]
            )
        elif deployment_attempt_id is not None or recovery_protection_receipt_id is not None:
            raise PublishAdapterError("candidate_only cannot carry activation authorization")
        cli_arguments.append("--json")
        rendered_arguments = ",".join(_ps_literal(item) for item in cli_arguments)
        script = (
            ssh_target_guard_script(self.config.target_address)
            + OpenSSHVMBackend._ensure_directory_script(temporary)
            + verified_d_tooling_python_script("deployment_cli_module")
            + f"$tmp={_ps_literal(str(temporary))};"
            "$env:PYTHONDONTWRITEBYTECODE='1';$env:TEMP=$tmp;$env:TMP=$tmp;"
            f"$cli=@({rendered_arguments});$output=& $python @cli;"
            "if($LASTEXITCODE-ne 0){throw 'deploy_cli_failed'};"
            "$output|Write-Output"
        )
        arguments = [
            "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
            "--", self.config.ssh_alias, "powershell.exe", "-NoProfile",
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
    "ActivationAuthorization",
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
    "bootstrap_verified_d_tooling_python_script",
    "exact_production_root_parent_guard_script",
    "ssh_target_guard_script",
    "verified_d_tooling_python_script",
    "subprocess_runner",
]
