"""Build and seal the first D-root operational source without touching SCM."""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Callable, Mapping, Sequence
from uuid import uuid4

from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point
from quant_hub.runtime_seal import read_json, write_atomic_new_json

from .publish_adapters import (
    CommandResult,
    OpenSSHVMBackend,
    bootstrap_verified_d_tooling_python_script,
    exact_production_root_parent_guard_script,
    ssh_target_guard_script,
    subprocess_runner,
)
from .publish_runtime import RuntimePublishConfig
from .recovery_bundle import (
    RecoveryBundleError,
    _files as recovery_files,
    _operational_bootstrap,
    _scan_no_secret,
)
from .vm_boundary import (
    PRODUCTION_VM_ROOT,
    capture_vm_write_snapshot,
    finalize_vm_write_audit,
    validate_production_vm_write_path,
)
from .vm_deploy_cli import verify_production_root, verify_runtime_environment
from .vm_service_cli import production_runtime_document
from .windows_service import build_install_candidate, quant_hub_package_inventory_sha256


GENERATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
REMOTE_PREPARE_SCHEMA = "qrh-operational-prepare/v1"
SOURCE_RECEIPT_SCHEMA = "qrh-operational-source-receipt/v1"


class OperationalSourceError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical(value: object) -> bytes:
    return (
        json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _manifest_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_canonical_new(path: Path, value: object) -> None:
    payload = _manifest_bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    ensure_no_reparse_components(path.parent)
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.partial")
    reserved = False
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        reserved = True
        os.close(descriptor)
        os.replace(temporary, path)
        reserved = False
    finally:
        temporary.unlink(missing_ok=True)
        if reserved and path.exists() and path.stat().st_size == 0:
            path.unlink()


def _reject_cache_artifacts(root: Path) -> None:
    for path in root.rglob("*"):
        if path.name.casefold() == "__pycache__" or path.suffix.casefold() in {
            ".pyc", ".pyo",
        }:
            raise OperationalSourceError("operational source contains bytecode/cache")


def _tree_records(root: Path) -> list[dict[str, object]]:
    root = root.resolve(strict=True)
    ensure_no_reparse_components(root)
    records: list[dict[str, object]] = []
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in directories:
            path = current_path / name
            info = path.lstat()
            if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
                raise OperationalSourceError("operational source directory is unsafe")
        for name in files:
            path = current_path / name
            info = path.lstat()
            if (
                stat_is_reparse_point(info)
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
            ):
                raise OperationalSourceError("operational source file is unsafe")
            records.append(
                {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": info.st_size,
                    "sha256": _sha256(path),
                }
            )
    return records


def _inventory_document(root: Path, generation: str) -> dict[str, object]:
    records = _tree_records(root)
    return {
        "schema_version": "qrh-portable-runtime-inventory/v1",
        "generation": generation,
        "files": records,
    }


def _logical_d_candidate(root: Path) -> dict[str, object]:
    candidate = dict(build_install_candidate(root, "QuantResearchHub").document())
    path_fields = tuple(
        name
        for name in candidate
        if name not in {"quant_hub_package_root"}
        and not name.endswith("_sha256")
        and name
        not in {"schema_version", "service_name", "python_class", "start_type"}
    )
    physical = root.resolve(strict=True)
    for field in path_fields:
        relative = Path(str(candidate[field])).resolve(strict=True).relative_to(physical)
        candidate[field] = str(PRODUCTION_VM_ROOT.joinpath(*relative.parts))
    package = Path(str(candidate["quant_hub_package_root"])).resolve(strict=True)
    relative_package = package.relative_to(physical)
    candidate["quant_hub_package_root"] = str(
        PRODUCTION_VM_ROOT.joinpath(*relative_package.parts)
    )
    return candidate


CompatibilityRunner = Callable[
    [Sequence[str], Mapping[str, str], Path], subprocess.CompletedProcess[bytes]
]


def _compatibility_runner(
    arguments: Sequence[str], environment: Mapping[str, str], cwd: Path
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        list(arguments), cwd=cwd, env=dict(environment), shell=False, check=False,
        capture_output=True,
    )


def prepare_operational_control(
    *,
    root: Path,
    environment: Mapping[str, str],
    compatibility_runner: CompatibilityRunner = _compatibility_runner,
    allow_test_root: bool = False,
) -> Mapping[str, object]:
    """Validate an already transferred runtime and seal two control documents."""

    physical = root.resolve(strict=True)
    if allow_test_root:
        ensure_no_reparse_components(physical)
    else:
        physical = verify_production_root(physical)
        verify_runtime_environment(physical, environment)
        ssh = str(environment.get("SSH_CONNECTION", "")).split()
        if len(ssh) < 3 or ssh[2] != "10.5.1.240":
            raise OperationalSourceError("operational prepare target is not .240")
    python = physical / "tooling" / "python" / "python.exe"
    package = physical / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub"
    service_executable = (
        physical / "tooling" / "python" / "Lib" / "site-packages" / "win32"
        / "pythonservice.exe"
    )
    for path in (python, package, service_executable):
        ensure_no_reparse_components(path.resolve(strict=True))
    if not python.is_file() or not package.is_dir() or not service_executable.is_file():
        raise OperationalSourceError("portable Python/pywin32 runtime is incomplete")
    _reject_cache_artifacts(package)
    temporary = physical / "tmp" / "operational-prepare"
    temporary.mkdir(parents=True, exist_ok=True)
    process_environment = {
        **environment,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPYCACHEPREFIX": str(temporary / "pycache"),
        "TEMP": str(temporary),
        "TMP": str(temporary),
    }
    gates = (
        (str(python), "-I", "-B", "-m", "pip", "check"),
        (
            str(python), "-I", "-B", "-c",
            "import flask,sqlite3,win32service,win32serviceutil;"
            "import quant_hub.ops.vm_deploy_cli,quant_hub.ops.publish_recovery_cli,"
            "quant_hub.ops.service_entry",
        ),
    )
    for arguments in gates:
        result = compatibility_runner(arguments, process_environment, temporary)
        if result.returncode != 0:
            raise OperationalSourceError("portable Python compatibility gate failed")

    control = physical / "control"
    control.mkdir(parents=True, exist_ok=True)
    runtime_path = control / "deployment_runtime.json"
    runtime_document = production_runtime_document()
    if runtime_path.exists() and (
        read_json(runtime_path) != runtime_document
        or runtime_path.read_bytes() != _manifest_bytes(runtime_document)
    ):
        raise OperationalSourceError("deployment runtime identity already differs")
    if not runtime_path.exists():
        _write_canonical_new(runtime_path, runtime_document)
    candidate_document = _logical_d_candidate(physical)
    candidate_path = control / "service_install_candidate.json"
    if candidate_path.exists() and (
        read_json(candidate_path) != candidate_document
        or candidate_path.read_bytes() != _manifest_bytes(candidate_document)
    ):
        raise OperationalSourceError("service install candidate already differs")
    if not candidate_path.exists():
        _write_canonical_new(candidate_path, candidate_document)
    result = {
        "schema_version": REMOTE_PREPARE_SCHEMA,
        "status": "prepared_no_scm",
        "service_python_sha256": _sha256(python),
        "quant_hub_package_inventory_sha256": quant_hub_package_inventory_sha256(
            package
        ),
        "deployment_runtime_sha256": _sha256(runtime_path),
        "service_install_candidate_sha256": _sha256(candidate_path),
        "scm_changed": False,
        "active_changed": False,
        "secret_required": False,
    }
    return result


@dataclass(frozen=True)
class PortableRuntime:
    root: Path
    generation: str
    inventory: Mapping[str, object]
    python_sha256: str
    package_inventory_sha256: str


def inspect_portable_runtime(root: Path, generation: str) -> PortableRuntime:
    if GENERATION.fullmatch(generation) is None:
        raise OperationalSourceError("operational generation is invalid")
    physical = root.resolve(strict=True)
    _reject_cache_artifacts(physical)
    inventory = _inventory_document(physical, generation)
    files = recovery_files(physical)
    try:
        _scan_no_secret(physical, files)
    except RecoveryBundleError as error:
        raise OperationalSourceError("portable runtime no-secret gate failed") from error
    python = physical / "python.exe"
    package = physical / "Lib" / "site-packages" / "quant_hub"
    service = physical / "Lib" / "site-packages" / "win32" / "pythonservice.exe"
    if not python.is_file() or not package.is_dir() or not service.is_file():
        raise OperationalSourceError("portable runtime required files are missing")
    return PortableRuntime(
        physical, generation, inventory, _sha256(python),
        quant_hub_package_inventory_sha256(package),
    )


class OperationalSourceOrchestrator:
    def __init__(
        self,
        config: RuntimePublishConfig,
        *,
        command_runner: Callable[[Sequence[str]], CommandResult] = subprocess_runner,
        backend: OpenSSHVMBackend | None = None,
    ) -> None:
        self.config = config
        self.command_runner = command_runner
        self.backend = backend or OpenSSHVMBackend(
            config.vm, command_runner=command_runner
        )

    @staticmethod
    def _ps(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _adopt_script(
        self, portable: PortableRuntime, *, replace_existing_empty_d: bool
    ) -> str:
        root = self.config.vm.root
        partial = root / "tmp" / "operational-import" / f"{portable.generation}.partial"
        manifest = partial / "runtime_inventory.json"
        source = partial / "python"
        target = root / "tooling" / "python"
        replace = "$true" if replace_existing_empty_d else "$false"
        return (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + f"$manifest={self._ps(str(manifest))};$source={self._ps(str(source))};"
            f"$target={self._ps(str(target))};$replace={replace};"
            "$i=Get-Content -LiteralPath $manifest -Raw -Encoding UTF8|ConvertFrom-Json;"
            "if($i.schema_version-ne'qrh-portable-runtime-inventory/v1')"
            "{throw 'runtime_inventory_schema'};$expected=@{};foreach($r in $i.files){"
            "$expected[$r.path]=@($r.bytes,$r.sha256)};"
            "function Get-VerifiedTree($base){$actual=@{};"
            "Get-ChildItem -LiteralPath $base -File -Recurse -Force|%{"
            "if(($_.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
            "{throw 'runtime_file_reparse'};$rel=$_.FullName.Substring($base.Length)."
            "TrimStart('\\').Replace('\\','/');$actual[$rel]=@($_.Length,(Get-FileHash "
            "-LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())};"
            "if(@(Get-ChildItem -LiteralPath $base -Directory -Recurse -Force|?{"
            "($_.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0}).Count-ne 0)"
            "{throw 'runtime_directory_reparse'};return $actual};"
            "$actual=Get-VerifiedTree $source;"
            "if($actual.Count-ne $expected.Count){throw 'runtime_inventory_count'};"
            "foreach($k in $expected.Keys){if(-not $actual.ContainsKey($k)-or"
            "$actual[$k][0]-ne$expected[$k][0]-or$actual[$k][1]-ne$expected[$k][1])"
            "{throw 'runtime_inventory_hash'}};"
            "if(Test-Path -LiteralPath $target){"
            "$current=Get-VerifiedTree $target;$same=$current.Count-eq$expected.Count;"
            "if($same){foreach($k in $expected.Keys){if(-not$current.ContainsKey($k)-or"
            "$current[$k][0]-ne$expected[$k][0]-or$current[$k][1]-ne$expected[$k][1])"
            "{$same=$false;break}}};if($same){Remove-Item -LiteralPath "
            "(Split-Path -Parent $source) -Recurse -Force;"
            "@{status='tooling_reused';generation=$i.generation}|ConvertTo-Json -Compress;exit};"
            "if(-not $replace){throw 'existing_tooling_requires_explicit_replace'};"
            f"if(Test-Path -LiteralPath {self._ps(str(root / 'control' / 'active_release.json'))})"
            "{throw 'active_exists'};"
            f"if((Test-Path -LiteralPath {self._ps(str(root / 'releases'))})-and"
            f"@(Get-ChildItem -LiteralPath {self._ps(str(root / 'releases'))} -Force).Count-ne 0)"
            "{throw 'release_exists'};"
            f"if((Test-Path -LiteralPath {self._ps(str(root / 'state'))})-and"
            f"@(Get-ChildItem -LiteralPath {self._ps(str(root / 'state'))} -Force).Count-ne 0)"
            "{throw 'state_exists'};"
            "$old=$target+'.replaced';if(Test-Path -LiteralPath $old){throw 'old_exists'};"
            "Move-Item -LiteralPath $target -Destination $old;try{Move-Item -LiteralPath "
            "$source -Destination $target}catch{Move-Item -LiteralPath $old -Destination "
            "$target;throw};Remove-Item -LiteralPath $old -Recurse -Force}"
            "else{New-Item -ItemType Directory -Force -LiteralPath (Split-Path -Parent "
            "$target)|Out-Null;Move-Item -LiteralPath $source -Destination $target};"
            "@{status='tooling_adopted';generation=$i.generation}|ConvertTo-Json -Compress"
        )

    def prepare_remote(
        self,
        portable_runtime_root: Path,
        *,
        generation: str,
        replace_existing_empty_d: bool = False,
    ) -> Mapping[str, object]:
        portable = inspect_portable_runtime(portable_runtime_root, generation)
        if portable.root.is_relative_to(self.config.project_root.resolve(strict=True)):
            raise OperationalSourceError("portable runtime source must remain outside public Git")
        root = self.config.vm.root
        partial = root / "tmp" / "operational-import" / f"{generation}.partial"
        probe = (
            f"if(Test-Path -LiteralPath {self._ps(str(partial))})"
            "{throw 'operational_generation_staging_exists'};"
            "@{status='absent'}|ConvertTo-Json -Compress"
        )
        self.backend._ssh(probe)
        python_root = partial / "python"
        self.backend.ensure_directory(python_root)
        for record in portable.inventory["files"]:
            relative = PurePosixPath(str(record["path"]))
            self.backend.upload(
                portable.root.joinpath(*relative.parts),
                python_root.joinpath(*relative.parts),
            )
        self.config.state_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self.config.state_root) as temporary:
            manifest = Path(temporary) / "runtime_inventory.json"
            manifest.write_bytes(_canonical(portable.inventory))
            self.backend.upload(manifest, partial / "runtime_inventory.json")
        adopted = json.loads(
            self.backend._ssh(
                self._adopt_script(
                    portable, replace_existing_empty_d=replace_existing_empty_d
                )
            )
        )
        if adopted not in (
            {"status": "tooling_adopted", "generation": generation},
            {"status": "tooling_reused", "generation": generation},
        ):
            raise OperationalSourceError("remote tooling adoption evidence differs")
        temporary = root / "tmp" / "operational-prepare"
        arguments = (
            "-I", "-B", "-m", "quant_hub.ops.operational_source_cli",
            "prepare-control", "--vm-root", str(root), "--json",
        )
        rendered = ",".join(self._ps(item) for item in arguments)
        script = (
            ssh_target_guard_script(self.config.vm.target_address)
            + OpenSSHVMBackend._ensure_directory_script(temporary)
            + bootstrap_verified_d_tooling_python_script(
                service_python_sha256=portable.python_sha256,
                quant_hub_package_inventory_sha256=portable.package_inventory_sha256,
            )
            + f"$tmp={self._ps(str(temporary))};$env:PYTHONDONTWRITEBYTECODE='1';"
            "$env:PYTHONPYCACHEPREFIX=Join-Path $tmp 'pycache';$env:TEMP=$tmp;$env:TMP=$tmp;"
            f"$a=@({rendered});$o=& $python @a;if($LASTEXITCODE-ne 0)"
            "{throw 'operational_prepare_failed'};$o|Write-Output"
        )
        result = self.command_runner(
            (
                "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "--", self.config.vm.ssh_alias, "powershell.exe", "-NoProfile",
                "-NonInteractive", "-EncodedCommand",
                base64.b64encode(script.encode("utf-16-le")).decode("ascii"),
            )
        )
        if result.returncode != 0:
            raise OperationalSourceError("fixed remote operational prepare failed")
        value = json.loads(result.stdout)
        expected_result = {
            "schema_version": REMOTE_PREPARE_SCHEMA,
            "status": "prepared_no_scm",
            "service_python_sha256": portable.python_sha256,
            "quant_hub_package_inventory_sha256": portable.package_inventory_sha256,
            "scm_changed": False,
            "active_changed": False,
            "secret_required": False,
        }
        if any(value.get(key) != expected for key, expected in expected_result.items()):
            raise OperationalSourceError("remote operational prepare result differs")
        cleanup = (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + f"$p={self._ps(str(partial))};if(Test-Path -LiteralPath $p){{"
            "Remove-Item -LiteralPath $p -Recurse -Force};"
            "@{status='operational_staging_removed'}|ConvertTo-Json -Compress"
        )
        cleanup_result = json.loads(self.backend._ssh(cleanup))
        if cleanup_result != {"status": "operational_staging_removed"}:
            raise OperationalSourceError("remote operational staging cleanup differs")
        return value

    def _remote_inventory(self) -> Mapping[str, object]:
        root = self.config.vm.root
        # Only the self-contained runtime is part of disaster-recovery
        # bootstrap.  Existing diagnostic/source material under ``tooling`` is
        # deliberately excluded so it cannot silently enlarge the authority.
        tooling = root / "tooling" / "python"
        controls = tuple(
            root / "control" / name
            for name in ("deployment_runtime.json", "service_install_candidate.json")
        )
        script = (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + f"$root={self._ps(str(root))};$tooling={self._ps(str(tooling))};"
            "if(@(Get-ChildItem -LiteralPath $tooling -Directory -Recurse -Force|?{"
            "($_.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0}).Count-ne 0)"
            "{throw 'operational_directory_reparse'};"
            "$rows=@();Get-ChildItem -LiteralPath $tooling -File -Recurse -Force|%{"
            "if(($_.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
            "{throw 'operational_reparse'};$rows+=@{path='tooling/python/'+$_.FullName."
            "Substring($tooling.Length).TrimStart('\\').Replace('\\','/');bytes=$_.Length;"
            "sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash."
            "ToLowerInvariant()}};"
            + "".join(
                f"$f=Get-Item -LiteralPath {self._ps(str(path))} -Force;"
                "if($f.PSIsContainer-or(($f.Attributes-band[IO.FileAttributes]::ReparsePoint)"
                "-ne 0)){throw 'operational_control_type'};$rows+=@{path='control/"
                + path.name
                + "';bytes=$f.Length;sha256=(Get-FileHash -LiteralPath $f.FullName "
                "-Algorithm SHA256).Hash.ToLowerInvariant()};"
                for path in controls
            )
            + "$rows=@($rows|Sort-Object path);@{schema_version='qrh-remote-operational-tree/v1';"
            "files=$rows}|ConvertTo-Json -Compress -Depth 4"
        )
        value = json.loads(self.backend._ssh(script))
        if value.get("schema_version") != "qrh-remote-operational-tree/v1":
            raise OperationalSourceError("remote operational inventory differs")
        return value

    def download_and_seal(self, *, generation: str) -> Mapping[str, object]:
        if GENERATION.fullmatch(generation) is None:
            raise OperationalSourceError("operational generation is invalid")
        destination = self.config.recovery.operational_root.resolve()
        recovery = self.config.recovery.recovery_root.resolve(strict=True)
        if (
            destination.name != generation
            or destination.parent.name != "operational-sources"
            or destination.parent.parent != recovery.parent
            or destination.is_relative_to(self.config.project_root.resolve(strict=True))
        ):
            raise OperationalSourceError("off-host operational source authority is invalid")
        if destination.exists():
            raise OperationalSourceError("operational generation is immutable")
        ensure_no_reparse_components(recovery.parent)
        destination.parent.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(destination.parent.resolve(strict=True))
        before = self._remote_inventory()
        staging = destination.parent / f".{generation}.{uuid4().hex}.partial"
        staging.mkdir(parents=True)
        ensure_no_reparse_components(staging.resolve(strict=True))
        try:
            (staging / "control").mkdir()
            sources = (
                (self.config.vm.root / "tooling" / "python", staging / "tooling"),
                (
                    self.config.vm.root / "control" / "deployment_runtime.json",
                    staging / "control",
                ),
                (
                    self.config.vm.root / "control" / "service_install_candidate.json",
                    staging / "control",
                ),
            )
            for remote, local in sources:
                result = self.command_runner(
                    (
                        "scp", "-q", "-r", "-o", "BatchMode=yes", "-o",
                        "ConnectTimeout=20", "-o",
                        f"HostName={self.config.vm.target_address}", "--",
                        f"{self.config.vm.ssh_alias}:" + str(remote).replace("\\", "/"),
                        str(local),
                    )
                )
                if result.returncode != 0:
                    raise OperationalSourceError("operational source download failed")
            after = self._remote_inventory()
            if before != after:
                raise OperationalSourceError("remote operational source changed during download")
            local_records = _tree_records(staging)
            local_identity = {
                str(item["path"]): (int(item["bytes"]), str(item["sha256"]))
                for item in local_records
            }
            remote_files = before.get("files")
            remote_identity = {
                str(item["path"]): (int(item["bytes"]), str(item["sha256"]))
                for item in remote_files
            } if isinstance(remote_files, list) else {}
            if local_identity != remote_identity:
                raise OperationalSourceError("downloaded operational tree identity differs")
            _reject_cache_artifacts(staging)
            _operational_bootstrap(staging)
            try:
                no_secret = _scan_no_secret(staging, recovery_files(staging))
            except RecoveryBundleError as error:
                raise OperationalSourceError("operational source no-secret gate failed") from error
            os.replace(staging, destination)
            inventory_bytes = _canonical(before)
            receipt = {
                "schema_version": SOURCE_RECEIPT_SCHEMA,
                "generation": generation,
                "source_host_role": "production-vm-.240",
                "tree_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
                "file_count": len(local_records),
                "total_bytes": sum(int(item["bytes"]) for item in local_records),
                "no_secret_report_sha256": no_secret["report_sha256"],
                "contains_secret": False,
                "remote_stable_during_download": True,
            }
            receipts = destination.parent / "receipts"
            receipts.mkdir(exist_ok=True)
            write_atomic_new_json(receipts / f"{generation}.json", receipt)
            return receipt
        except BaseException:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)
            raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    remote = subparsers.add_parser("prepare-control")
    remote.add_argument("--vm-root", type=Path, required=True)
    remote.add_argument("--json", action="store_true")
    prepare = subparsers.add_parser("prepare-remote")
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--project-root", type=Path, required=True)
    prepare.add_argument("--portable-runtime-root", type=Path, required=True)
    prepare.add_argument("--generation", required=True)
    prepare.add_argument("--replace-existing-empty-d", action="store_true")
    download = subparsers.add_parser("download-seal")
    download.add_argument("--config", type=Path, required=True)
    download.add_argument("--project-root", type=Path, required=True)
    download.add_argument("--generation", required=True)
    args = parser.parse_args(argv)
    if args.command == "prepare-control":
        root = verify_production_root(args.vm_root)
        before = capture_vm_write_snapshot(root)
        try:
            value = prepare_operational_control(root=root, environment=os.environ)
        except BaseException:
            finalize_vm_write_audit(
                root, before, operation="operational-prepare", outcome="failed"
            )
            raise
        finalize_vm_write_audit(
            root, before, operation="operational-prepare", outcome="succeeded"
        )
    else:
        config = RuntimePublishConfig.load(
            args.config, expected_project_root=args.project_root
        )
        orchestrator = OperationalSourceOrchestrator(config)
        if args.command == "prepare-remote":
            value = orchestrator.prepare_remote(
                args.portable_runtime_root,
                generation=args.generation,
                replace_existing_empty_d=args.replace_existing_empty_d,
            )
        else:
            value = orchestrator.download_and_seal(generation=args.generation)
    print(json.dumps(value, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
