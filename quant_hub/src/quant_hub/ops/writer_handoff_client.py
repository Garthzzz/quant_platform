"""Off-host, fixed-target orchestration for the one-time V39 writer handoff.

The client never reads or writes legacy C state itself.  It preserves the
nonce-bound read-only inspection in the configured off-host recovery evidence
root, transfers those exact canonical bytes to the fixed D control intake, and
then invokes only the sealed ``quant_hub.ops.writer_handoff`` module.  Remote
stderr, nonce values, and receipt bodies are never printed by this module.
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import stat
from typing import Callable, Mapping, Sequence
from uuid import uuid4

from quant_hub.config import ensure_no_reparse_components

from .failure_domain_authority import (
    FailureDomainAuthorityNotReady,
    require_failure_domain_authority,
)
from .publish_adapters import (
    CommandResult,
    CommandRunner,
    OpenSSHVMBackend,
    VMConfig,
    exact_production_root_parent_guard_script,
    ssh_target_guard_script,
    _subprocess_runner,
    verified_d_tooling_python_script,
)
from .release_identity import canonical_manifest_bytes, manifest_sha256
from .vm_boundary import PRODUCTION_VM_ROOT, validate_production_vm_write_path
from .writer_handoff import (
    ACCESS_IDENTITY_CONTRACT,
    ACCESS_IDENTITY_SCHEMA,
    FAILURE_SCHEMA,
    INSPECT_SCHEMA,
    STATUS_SCHEMA,
    SUCCESS_SCHEMA,
    TARGET_ADDRESS,
    V39Baseline,
    validate_inspection_receipt,
)


CLIENT_RESULT_SCHEMA = "qrh-writer-handoff-client-result/v1"
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{48}$")


class WriterHandoffClientError(RuntimeError):
    """The handoff could not be orchestrated without weakening a boundary."""


class WriterHandoffRunError(WriterHandoffClientError):
    """A run failed after its immutable inspection was safely preserved.

    The inspection hash is intentionally the only recovery detail exposed to
    the console boundary.  It is non-secret and lets the operator resume with
    ``status``/``finalize`` without generating a second nonce or guessing an
    attempt from timestamps.
    """

    def __init__(self, inspection_sha256: str):
        super().__init__("writer handoff run requires exact inspection recovery")
        self.inspection_sha256 = _sha(inspection_sha256, "inspection hash")


@dataclass(frozen=True)
class WriterHandoffClientConfig:
    project_root: Path
    recovery_root: Path
    vm: VMConfig


@dataclass(frozen=True)
class WriterHandoffClientResult:
    status: str
    inspection_sha256: str
    attempt_id: str | None
    evidence_id: str | None
    evidence_sha256: str | None
    writer_authority_committed: bool

    def public_document(self) -> Mapping[str, object]:
        """Return only non-sensitive identities suitable for CLI stdout."""

        return {
            "schema_version": CLIENT_RESULT_SCHEMA,
            "status": self.status,
            "inspection_sha256": self.inspection_sha256,
            "attempt_id": self.attempt_id,
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
            "writer_authority_committed": self.writer_authority_committed,
        }


def _ps_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _encoded(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA_RE.fullmatch(value) is None:
        raise WriterHandoffClientError(f"{label} is invalid")
    return value


def _identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID_RE.fullmatch(value) is None or ".." in value:
        raise WriterHandoffClientError(f"{label} is invalid")
    return value


def _closed_json(output: str, fields: set[str], label: str) -> Mapping[str, object]:
    try:
        value = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise WriterHandoffClientError(f"{label} returned invalid JSON") from error
    if not isinstance(value, dict) or set(value) != fields:
        raise WriterHandoffClientError(f"{label} schema is not closed")
    return value


class WriterHandoffClient:
    """One fixed-alias/.240 handoff client with injectable process boundaries."""

    def __init__(
        self,
        config: WriterHandoffClientConfig,
        *,
        command_runner: CommandRunner = _subprocess_runner,
        nonce_factory: Callable[[int], bytes] = secrets.token_bytes,
    ):
        require_failure_domain_authority()
        self.config = config
        self.command_runner = command_runner
        self.nonce_factory = nonce_factory
        try:
            approved = validate_production_vm_write_path(config.vm.root, allow_root=True)
        except Exception as error:
            raise WriterHandoffClientError("VM root is outside the fixed boundary") from error
        if approved != PRODUCTION_VM_ROOT:
            raise WriterHandoffClientError("VM root must be the exact production D root")
        if config.vm.target_address != TARGET_ADDRESS:
            raise WriterHandoffClientError("writer handoff target must be 10.5.1.240")
        if not isinstance(config.vm.ssh_alias, str) or _ID_RE.fullmatch(config.vm.ssh_alias) is None:
            raise WriterHandoffClientError("SSH alias is invalid")
        self._recovery_root()

    def _recovery_root(self) -> Path:
        root = self.config.recovery_root.resolve(strict=True)
        project = self.config.project_root.resolve(strict=True)
        ensure_no_reparse_components(root)
        if not root.is_dir() or root == project or root.is_relative_to(project):
            raise WriterHandoffClientError("handoff evidence root must be off-host/Git-external")
        return root

    def _evidence_directory(self, category: str) -> Path:
        if category not in {"inspections", "terminal", "events"}:
            raise WriterHandoffClientError("handoff evidence category is invalid")
        current = self._recovery_root()
        for part in ("evidence", "writer-handoff", category):
            current = current / part
            if current.exists():
                ensure_no_reparse_components(current)
                if not current.is_dir():
                    raise WriterHandoffClientError("handoff evidence path is not a directory")
            else:
                current.mkdir()
                ensure_no_reparse_components(current)
        return current.resolve(strict=True)

    @staticmethod
    def _write_immutable(path: Path, payload: bytes) -> str:
        ensure_no_reparse_components(path.parent)
        digest = hashlib.sha256(payload).hexdigest()
        if os.path.lexists(path):
            info = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or path.read_bytes() != payload
            ):
                raise WriterHandoffClientError("immutable handoff evidence differs")
            return digest
        temporary = path.with_name(f".{path.name}.{uuid4().hex}.partial")
        try:
            with temporary.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, path)
            except FileExistsError:
                if not path.is_file() or path.is_symlink() or path.read_bytes() != payload:
                    raise WriterHandoffClientError("immutable handoff evidence race differs")
            if path.read_bytes() != payload:
                raise WriterHandoffClientError("immutable handoff evidence publication differs")
            return digest
        finally:
            temporary.unlink(missing_ok=True)

    def _ssh(self, script: str) -> CommandResult:
        guarded = ssh_target_guard_script(self.config.vm.target_address) + script
        return self.command_runner(
            (
                "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "--", self.config.vm.ssh_alias, "powershell.exe", "-NoProfile",
                "-NonInteractive", "-EncodedCommand", _encoded(guarded),
            )
        )

    def _module(self, arguments: Sequence[str]) -> CommandResult:
        root = str(PRODUCTION_VM_ROOT)
        runtime_tmp = str(PRODUCTION_VM_ROOT / "tmp")
        rendered = ",".join(_ps_literal(item) for item in arguments)
        # The deployment CLI individual binding is used as the immutable
        # bootstrap anchor; the same prelude then reconstructs and verifies the
        # whole quant_hub package inventory, which includes writer_handoff.py.
        script = (
            "$ErrorActionPreference='Stop';"
            + verified_d_tooling_python_script("deployment_cli_module")
            + f"$runtimeTmp={_ps_literal(runtime_tmp)};"
            "$tmpItem=Get-Item -LiteralPath $runtimeTmp -Force -ErrorAction Stop;"
            "if(-not $tmpItem.PSIsContainer-or(($tmpItem.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'runtime_tmp_invalid'};"
            "$env:PYTHONDONTWRITEBYTECODE='1';$env:PYTHONPYCACHEPREFIX=Join-Path "
            "$runtimeTmp 'pycache';$env:TEMP=$runtimeTmp;$env:TMP=$runtimeTmp;"
            f"$a=@({rendered});$o=& $python @a;$code=$LASTEXITCODE;"
            "if($null-ne $o){$o|Write-Output};exit $code"
        )
        if str(arguments[arguments.index("--vm-root") + 1]) != root:
            raise WriterHandoffClientError("writer handoff command root differs")
        return self._ssh(script)

    @staticmethod
    def _base_arguments(command: str, baseline: V39Baseline) -> list[str]:
        if command not in {
            "inspect", "apply", "status", "finalize", "seed-access-identity"
        }:
            raise WriterHandoffClientError("writer handoff command is not fixed")
        return [
            "-I", "-B", "-m", "quant_hub.ops.writer_handoff", command,
            "--vm-root", str(PRODUCTION_VM_ROOT),
            "--release-manifest-sha256", baseline.manifest_sha256,
        ]

    @staticmethod
    def _inspection_identity(
        receipt: Mapping[str, object], baseline: V39Baseline, nonce: str
    ) -> None:
        validate_inspection_receipt(receipt)
        if receipt.get("schema_version") != INSPECT_SCHEMA or receipt.get("nonce") != nonce:
            raise WriterHandoffClientError("inspection receipt nonce/schema differs")
        observation = receipt.get("observation")
        expected_v39 = {
            "release_id": baseline.release_id,
            "manifest_sha256": baseline.manifest_sha256,
            "snapshot_id": baseline.snapshot_id,
            "legacy_deployment_id": baseline.legacy_deployment_id,
        }
        if not isinstance(observation, Mapping) or observation.get("v39") != expected_v39:
            raise WriterHandoffClientError("inspection receipt is not the exact V39 identity")

    def _inspection_path(self, inspection_hash: str) -> Path:
        return self._evidence_directory("inspections") / f"{_sha(inspection_hash, 'inspection hash')}.json"

    def _load_inspection(
        self, inspection_hash: str, baseline: V39Baseline
    ) -> tuple[Mapping[str, object], str]:
        path = self._inspection_path(inspection_hash)
        ensure_no_reparse_components(path)
        if not path.is_file() or path.is_symlink():
            raise WriterHandoffClientError("off-host inspection evidence is unavailable")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != inspection_hash:
            raise WriterHandoffClientError("off-host inspection evidence hash differs")
        try:
            receipt = json.loads(raw)
        except json.JSONDecodeError as error:
            raise WriterHandoffClientError("off-host inspection evidence is invalid") from error
        if raw != canonical_manifest_bytes(receipt):
            raise WriterHandoffClientError("off-host inspection evidence is not canonical")
        if not isinstance(receipt, dict):
            raise WriterHandoffClientError("off-host inspection evidence is invalid")
        nonce = str(receipt.get("nonce", ""))
        if _NONCE_RE.fullmatch(nonce) is None:
            raise WriterHandoffClientError("off-host inspection nonce is invalid")
        self._inspection_identity(receipt, baseline, nonce)
        return receipt, nonce

    def _intent_paths(self, inspection_hash: str) -> tuple[PureWindowsPath, PureWindowsPath]:
        name = f"{_sha(inspection_hash, 'inspection hash')}.json"
        final = validate_production_vm_write_path(
            PRODUCTION_VM_ROOT / "control" / "writer-handoff-intents" / name,
            allow_root=False,
        )
        partial = validate_production_vm_write_path(
            final.with_name(f"{name}.partial"), allow_root=False
        )
        return final, partial

    def _upload_intent(self, local_path: Path, inspection_hash: str) -> PureWindowsPath:
        final, partial = self._intent_paths(inspection_hash)
        size = local_path.stat().st_size
        expected_hash = hashlib.sha256(local_path.read_bytes()).hexdigest()
        if expected_hash != inspection_hash:
            raise WriterHandoffClientError("local intent hash differs before transfer")
        directory_script = OpenSSHVMBackend._ensure_directory_script(final.parent)
        preflight = (
            directory_script
            + f"$final={_ps_literal(str(final))};$partial={_ps_literal(str(partial))};"
            "function Assert-IntentFile{param([string]$Path);$full=[IO.Path]::GetFullPath($Path);"
            "if(-not $full.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'intent_escaped_exact_root'};$item=Get-Item -LiteralPath $full -Force;"
            "if($item.PSIsContainer-or(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)"
            "-ne 0)){throw 'intent_not_regular'};return $item};"
            "if(Test-Path -LiteralPath $final){$item=Assert-IntentFile $final;"
            f"if($item.Length-ne {size}-or(Get-FileHash -Algorithm SHA256 -LiteralPath $final)."
            f"Hash.ToLowerInvariant()-ne{_ps_literal(expected_hash)}){{throw 'intent_final_differs'}};"
            "@{status='intent_adopted'}|ConvertTo-Json -Compress}"
            "elseif(Test-Path -LiteralPath $partial){$item=Assert-IntentFile $partial;"
            f"if($item.Length-ne {size}-or(Get-FileHash -Algorithm SHA256 -LiteralPath $partial)."
            f"Hash.ToLowerInvariant()-ne{_ps_literal(expected_hash)}){{throw 'intent_partial_differs'}};"
            "Move-Item -LiteralPath $partial -Destination $final;"
            "@{status='intent_adopted'}|ConvertTo-Json -Compress}"
            "else{@{status='intent_ready'}|ConvertTo-Json -Compress}"
        )
        prepared = self._ssh(preflight)
        if prepared.returncode != 0:
            raise WriterHandoffClientError("remote intent preflight failed")
        value = _closed_json(prepared.stdout, {"status"}, "intent preflight")
        if value["status"] == "intent_adopted":
            return final
        if value["status"] != "intent_ready":
            raise WriterHandoffClientError("remote intent preflight status differs")
        remote = f"{self.config.vm.ssh_alias}:{str(partial).replace(chr(92), '/')}"
        copied = self.command_runner(
            (
                "scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "-o", f"HostName={TARGET_ADDRESS}", "--", str(local_path), remote,
            )
        )
        if copied.returncode != 0:
            raise WriterHandoffClientError("writer handoff intent transfer failed")
        adopt = (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + f"$final={_ps_literal(str(final))};$partial={_ps_literal(str(partial))};"
            "$full=[IO.Path]::GetFullPath($partial);"
            "if(-not $full.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'intent_escaped_exact_root'};$cursor=Split-Path -Parent $full;"
            "while(-not $cursor.Equals($rootFull,[StringComparison]::OrdinalIgnoreCase)){"
            "$parent=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop;"
            "if(-not $parent.PSIsContainer-or(($parent.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'intent_parent_reparse'};"
            "$next=Split-Path -Parent $cursor;if(-not $next-or $next-eq $cursor)"
            "{throw 'intent_parent_escaped'};$cursor=$next};"
            "$item=Get-Item -LiteralPath $full -Force;"
            "if($item.PSIsContainer-or(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)"
            "-ne 0)){throw 'intent_not_regular'};"
            f"if($item.Length-ne {size}-or(Get-FileHash -Algorithm SHA256 -LiteralPath $full)."
            f"Hash.ToLowerInvariant()-ne{_ps_literal(expected_hash)}){{throw 'intent_hash_differs'}};"
            "if(Test-Path -LiteralPath $final){throw 'intent_final_race'};"
            "Move-Item -LiteralPath $partial -Destination $final;"
            "$adopted=Get-Item -LiteralPath $final -Force;"
            f"if($adopted.Length-ne {size}-or(Get-FileHash -Algorithm SHA256 -LiteralPath $final)."
            f"Hash.ToLowerInvariant()-ne{_ps_literal(expected_hash)}){{throw 'intent_adopt_differs'}};"
            "@{status='intent_adopted'}|ConvertTo-Json -Compress"
        )
        adopted = self._ssh(adopt)
        if adopted.returncode != 0:
            raise WriterHandoffClientError("remote intent adoption failed")
        if _closed_json(adopted.stdout, {"status"}, "intent adoption") != {"status": "intent_adopted"}:
            raise WriterHandoffClientError("remote intent adoption status differs")
        return final

    def _remote_status(
        self, inspection_hash: str, nonce: str, baseline: V39Baseline
    ) -> Mapping[str, object]:
        arguments = self._base_arguments("status", baseline) + [
            "--inspection-sha256", inspection_hash, "--nonce", nonce,
        ]
        result = self._module(arguments)
        if result.returncode != 0:
            raise WriterHandoffClientError("fixed remote handoff status failed")
        value = _closed_json(
            result.stdout,
            {
                "schema_version", "status", "attempt_id", "phase",
                "evidence_type", "evidence_id", "writer_authority_committed",
            },
            "handoff status",
        )
        if value.get("schema_version") != STATUS_SCHEMA:
            raise WriterHandoffClientError("handoff status schema differs")
        status = value.get("status")
        if status not in {
            "not_found", "in_progress_or_fenced", "finalize_required",
            "succeeded", "failed",
        } or not isinstance(value.get("writer_authority_committed"), bool):
            raise WriterHandoffClientError("handoff status value differs")
        if status == "not_found":
            if any(value.get(key) is not None for key in ("attempt_id", "phase", "evidence_type", "evidence_id")):
                raise WriterHandoffClientError("empty handoff status contains an identity")
        else:
            _identifier(value.get("attempt_id"), "attempt ID")
            _identifier(value.get("phase"), "handoff phase")
            _identifier(value.get("evidence_type"), "evidence type")
            _identifier(value.get("evidence_id"), "evidence ID")
        return value

    def _terminal_relative_path(self, status: Mapping[str, object]) -> PureWindowsPath:
        evidence_id = _identifier(status.get("evidence_id"), "terminal evidence ID")
        if status.get("status") == "succeeded" and status.get("evidence_type") == "writer_handoff_receipt":
            directory = "success"
        elif status.get("status") == "failed" and status.get("evidence_type") == "writer_handoff_failure":
            directory = "failure"
        else:
            raise WriterHandoffClientError("handoff status is not terminal evidence")
        expected_prefix = f"writer-handoff-{directory}-"
        if not evidence_id.startswith(expected_prefix):
            raise WriterHandoffClientError("terminal evidence ID differs")
        return validate_production_vm_write_path(
            PRODUCTION_VM_ROOT / "audit" / "writer-handoff" / directory / f"{evidence_id}.json",
            allow_root=False,
        )

    def _validate_terminal(
        self,
        value: object,
        *,
        status: Mapping[str, object],
        inspection_hash: str,
        nonce: str,
        baseline: V39Baseline,
    ) -> Mapping[str, object]:
        if not isinstance(value, dict):
            raise WriterHandoffClientError("terminal handoff evidence is invalid")
        succeeded = status["status"] == "succeeded"
        success_fields = {
            "schema_version", "receipt_type", "receipt_id", "attempt_id", "recorded_at",
            "authority", "inspection_sha256", "inspection_nonce_sha256", "release_id",
            "release_manifest_sha256", "snapshot_id", "final_checkpoint_id",
            "final_checkpoint_manifest_sha256", "prehandoff_checkpoint_id",
            "prehandoff_checkpoint_manifest_sha256", "writer_transition", "verification",
            "active_authority_changed",
        }
        failure_fields = {
            "schema_version", "receipt_type", "receipt_id", "attempt_id", "recorded_at",
            "authority", "inspection_sha256", "inspection_nonce_sha256", "release_id",
            "release_manifest_sha256", "failed_phase", "error_code", "final_checkpoint_id",
            "prehandoff_checkpoint_id", "d_external_open", "legacy_rollback",
            "success_activation_recorded",
        }
        if set(value) != (success_fields if succeeded else failure_fields):
            raise WriterHandoffClientError("terminal handoff evidence schema is not closed")
        expected_schema = SUCCESS_SCHEMA if succeeded else FAILURE_SCHEMA
        expected_type = "writer_handoff" if succeeded else "writer_handoff_failure"
        if (
            value.get("schema_version") != expected_schema
            or value.get("receipt_type") != expected_type
            or value.get("receipt_id") != status.get("evidence_id")
            or value.get("attempt_id") != status.get("attempt_id")
            or value.get("authority") != "evidence_only"
            or value.get("inspection_sha256") != inspection_hash
            or value.get("inspection_nonce_sha256")
            != hashlib.sha256(nonce.encode("ascii")).hexdigest()
            or value.get("release_id") != baseline.release_id
            or value.get("release_manifest_sha256") != baseline.manifest_sha256
        ):
            raise WriterHandoffClientError("terminal handoff evidence identity differs")
        _identifier(value.get("attempt_id"), "terminal attempt ID")
        if succeeded:
            if (
                value.get("snapshot_id") != baseline.snapshot_id
                or value.get("active_authority_changed") is not False
                or value.get("writer_transition")
                != {
                    "from": "C-legacy", "to": "D-active", "c_pid_stopped": True,
                    "d_unique_listener": True, "c_permanently_fenced": True,
                }
            ):
                raise WriterHandoffClientError("success handoff evidence semantics differ")
            verification = value.get("verification")
            if not isinstance(verification, dict) or any(
                verification.get(key) is not True
                for key in (
                    "unique_d_listener", "legacy_pid_stopped", "browser", "api",
                    "resource", "legacy_restart_fenced", "session_key_ready",
                )
            ) or verification.get("release_id") != baseline.release_id or verification.get(
                "manifest_sha256"
            ) != baseline.manifest_sha256 or verification.get("snapshot_id") != baseline.snapshot_id or verification.get(
                "writer_authority"
            ) != "D-active":
                raise WriterHandoffClientError("success handoff verification differs")
            for field in (
                "final_checkpoint_manifest_sha256",
                "prehandoff_checkpoint_manifest_sha256",
            ):
                _sha(value.get(field), field)
        else:
            rollback = value.get("legacy_rollback")
            if (
                value.get("success_activation_recorded") is not False
                or not isinstance(value.get("d_external_open"), bool)
                or not isinstance(rollback, dict)
                or set(rollback) != {"attempted", "succeeded", "d_state_restored", "blocked"}
                or any(not isinstance(item, bool) for item in rollback.values())
            ):
                raise WriterHandoffClientError("failure handoff evidence semantics differ")
            _identifier(value.get("failed_phase"), "failed phase")
            _identifier(value.get("error_code"), "handoff error code")
        return value

    def _download_terminal(
        self,
        status: Mapping[str, object],
        inspection_hash: str,
        nonce: str,
        baseline: V39Baseline,
    ) -> tuple[str, str]:
        remote_path = self._terminal_relative_path(status)
        probe_script = (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + f"$path={_ps_literal(str(remote_path))};$full=[IO.Path]::GetFullPath($path);"
            "if(-not $full.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'evidence_escaped_exact_root'};$cursor=Split-Path -Parent $full;"
            "while(-not $cursor.Equals($rootFull,[StringComparison]::OrdinalIgnoreCase)){"
            "$parent=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop;"
            "if(-not $parent.PSIsContainer-or(($parent.Attributes-band"
            "[IO.FileAttributes]::ReparsePoint)-ne 0)){throw 'evidence_parent_reparse'};"
            "$next=Split-Path -Parent $cursor;if(-not $next-or $next-eq $cursor)"
            "{throw 'evidence_parent_escaped'};$cursor=$next};"
            "$item=Get-Item -LiteralPath $full -Force;"
            "if($item.PSIsContainer-or(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)"
            "-ne 0)){throw 'evidence_not_regular'};[ordered]@{schema_version="
            "'qrh-writer-handoff-download-probe/v1';bytes=$item.Length;sha256="
            "(Get-FileHash -Algorithm SHA256 -LiteralPath $full).Hash.ToLowerInvariant()}|"
            "ConvertTo-Json -Compress"
        )
        probed = self._ssh(probe_script)
        if probed.returncode != 0:
            raise WriterHandoffClientError("remote terminal evidence probe failed")
        probe = _closed_json(probed.stdout, {"schema_version", "bytes", "sha256"}, "terminal probe")
        if (
            probe.get("schema_version") != "qrh-writer-handoff-download-probe/v1"
            or not isinstance(probe.get("bytes"), int)
            or isinstance(probe.get("bytes"), bool)
            or int(probe["bytes"]) <= 0
        ):
            raise WriterHandoffClientError("terminal evidence probe differs")
        remote_hash = _sha(probe.get("sha256"), "terminal evidence hash")
        evidence_id = _identifier(status.get("evidence_id"), "terminal evidence ID")
        directory = self._evidence_directory("terminal")
        staging = directory / f".{evidence_id}.{uuid4().hex}.download"
        remote = f"{self.config.vm.ssh_alias}:{str(remote_path).replace(chr(92), '/')}"
        try:
            copied = self.command_runner(
                (
                    "scp", "-q", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                    "-o", f"HostName={TARGET_ADDRESS}", "--", remote, str(staging),
                )
            )
            if copied.returncode != 0:
                raise WriterHandoffClientError("terminal evidence download failed")
            ensure_no_reparse_components(staging)
            if not staging.is_file() or staging.is_symlink():
                raise WriterHandoffClientError("downloaded terminal evidence is not regular")
            raw = staging.read_bytes()
            if len(raw) != probe["bytes"] or hashlib.sha256(raw).hexdigest() != remote_hash:
                raise WriterHandoffClientError("downloaded terminal evidence identity differs")
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as error:
                raise WriterHandoffClientError("downloaded terminal evidence is invalid") from error
            if raw != canonical_manifest_bytes(value):
                raise WriterHandoffClientError("downloaded terminal evidence is not canonical")
            self._validate_terminal(
                value,
                status=status,
                inspection_hash=inspection_hash,
                nonce=nonce,
                baseline=baseline,
            )
            final = directory / f"{evidence_id}.json"
            local_hash = self._write_immutable(final, raw)
            if local_hash != remote_hash:
                raise WriterHandoffClientError("published terminal evidence hash differs")
            return evidence_id, local_hash
        finally:
            staging.unlink(missing_ok=True)

    def inspect(self, baseline: V39Baseline) -> str:
        require_failure_domain_authority()
        seeded = self._module(self._base_arguments("seed-access-identity", baseline))
        if seeded.returncode != 0:
            raise WriterHandoffClientError("fixed V39 access identity seed failed")
        seed_result = _closed_json(
            seeded.stdout,
            {
                "schema_version", "status", "contract_version",
                "source_server_sha256", "protected_access_identity_present",
                "override_evidence_absent",
            },
            "V39 access identity seed",
        )
        if (
            seed_result.get("schema_version") != ACCESS_IDENTITY_SCHEMA
            or seed_result.get("status") not in {"seeded", "reused"}
            or seed_result.get("contract_version") != ACCESS_IDENTITY_CONTRACT
            or _SHA_RE.fullmatch(str(seed_result.get("source_server_sha256", ""))) is None
            or seed_result.get("protected_access_identity_present") is not True
            or seed_result.get("override_evidence_absent") is not True
        ):
            raise WriterHandoffClientError("V39 access identity seed result differs")
        nonce_bytes = self.nonce_factory(24)
        if not isinstance(nonce_bytes, bytes) or len(nonce_bytes) != 24:
            raise WriterHandoffClientError("nonce source did not return 24 random bytes")
        nonce = nonce_bytes.hex()
        arguments = self._base_arguments("inspect", baseline) + ["--nonce", nonce]
        result = self._module(arguments)
        if result.returncode != 0:
            raise WriterHandoffClientError("fixed remote handoff inspection failed")
        value = _closed_json(
            result.stdout,
            {"schema_version", "status", "inspection_sha256", "receipt"},
            "handoff inspection",
        )
        receipt = value.get("receipt")
        if (
            value.get("schema_version") != "qrh-writer-handoff-inspection-result/v1"
            or value.get("status") != "inspected_read_only"
            or not isinstance(receipt, dict)
        ):
            raise WriterHandoffClientError("handoff inspection result differs")
        self._inspection_identity(receipt, baseline, nonce)
        actual_hash = manifest_sha256(receipt)
        if value.get("inspection_sha256") != actual_hash:
            raise WriterHandoffClientError("handoff inspection hash differs")
        path = self._inspection_path(actual_hash)
        self._write_immutable(path, canonical_manifest_bytes(receipt))
        return actual_hash

    def status(self, inspection_hash: str, baseline: V39Baseline) -> WriterHandoffClientResult:
        require_failure_domain_authority()
        _, nonce = self._load_inspection(inspection_hash, baseline)
        status = self._remote_status(inspection_hash, nonce, baseline)
        evidence_id: str | None = None
        evidence_hash: str | None = None
        if status["status"] in {"succeeded", "failed"}:
            evidence_id, evidence_hash = self._download_terminal(
                status, inspection_hash, nonce, baseline
            )
        return WriterHandoffClientResult(
            status=str(status["status"]),
            inspection_sha256=inspection_hash,
            attempt_id=(str(status["attempt_id"]) if status["attempt_id"] is not None else None),
            evidence_id=evidence_id or (
                str(status["evidence_id"]) if status["evidence_id"] is not None else None
            ),
            evidence_sha256=evidence_hash,
            writer_authority_committed=bool(status["writer_authority_committed"]),
        )

    def finalize(self, inspection_hash: str, baseline: V39Baseline) -> WriterHandoffClientResult:
        require_failure_domain_authority()
        _, nonce = self._load_inspection(inspection_hash, baseline)
        status = self._remote_status(inspection_hash, nonce, baseline)
        if status["status"] == "finalize_required":
            attempt_id = _identifier(status.get("attempt_id"), "attempt ID")
            arguments = self._base_arguments("finalize", baseline) + [
                "--attempt-id", attempt_id, "--nonce", nonce,
            ]
            finalized = self._module(arguments)
            if finalized.returncode != 0:
                raise WriterHandoffClientError("fixed remote handoff finalize failed")
            value = _closed_json(
                finalized.stdout,
                {
                    "schema_version", "status", "evidence_type", "evidence_id",
                    "writer_authority_committed",
                },
                "handoff finalize",
            )
            if value != {
                "schema_version": "qrh-writer-handoff-finalize-result/v1",
                "status": "succeeded",
                "evidence_type": "writer_handoff_receipt",
                "evidence_id": f"writer-handoff-success-{attempt_id}",
                "writer_authority_committed": True,
            }:
                raise WriterHandoffClientError("handoff finalize result differs")
            status = self._remote_status(inspection_hash, nonce, baseline)
        if status["status"] not in {"succeeded", "failed"}:
            raise WriterHandoffClientError("handoff is not safely finalizable")
        evidence_id, evidence_hash = self._download_terminal(
            status, inspection_hash, nonce, baseline
        )
        return WriterHandoffClientResult(
            status=str(status["status"]),
            inspection_sha256=inspection_hash,
            attempt_id=str(status["attempt_id"]),
            evidence_id=evidence_id,
            evidence_sha256=evidence_hash,
            writer_authority_committed=bool(status["writer_authority_committed"]),
        )

    def run(self, baseline: V39Baseline) -> WriterHandoffClientResult:
        require_failure_domain_authority()
        inspection_hash = self.inspect(baseline)
        try:
            _, nonce = self._load_inspection(inspection_hash, baseline)
            local_path = self._inspection_path(inspection_hash)
            remote_intent = self._upload_intent(local_path, inspection_hash)
            arguments = self._base_arguments("apply", baseline) + [
                "--inspection-receipt", str(remote_intent),
                "--inspection-sha256", inspection_hash,
                "--nonce", nonce,
            ]
            applied = self._module(arguments)
            if applied.stdout:
                # Parse the complete closed result even for the expected rc=2
                # failure outcome.  It is advisory until status corroborates the
                # exact durable journal/terminal evidence below.
                try:
                    raw_value = json.loads(applied.stdout)
                except json.JSONDecodeError as error:
                    raise WriterHandoffClientError(
                        "handoff apply returned invalid JSON"
                    ) from error
                # An exact generic error is expected on an idempotent replay after
                # the inspection was already consumed.  It grants no authority;
                # the durable status query below must still resolve the preserved
                # inspection to its exact terminal attempt.
                if isinstance(raw_value, dict) and set(raw_value) == {
                    "schema_version", "status", "error_type"
                } and raw_value.get("schema_version") == "qrh-writer-handoff-cli-error/v1" and raw_value.get(
                    "status"
                ) == "error" and _ID_RE.fullmatch(str(raw_value.get("error_type", ""))):
                    pass
                else:
                    value = _closed_json(
                        applied.stdout,
                        {
                            "schema_version", "status", "evidence_type", "evidence_id",
                            "legacy_rollback_attempted", "legacy_rollback_succeeded",
                            "rollback_blocked", "error_code",
                        },
                        "handoff apply",
                    )
                    if (
                        value.get("schema_version") != "qrh-writer-handoff-apply-result/v1"
                        or value.get("status") not in {
                            "succeeded", "failed", "committed_evidence_pending"
                        }
                        or any(
                            not isinstance(value.get(field), bool)
                            for field in (
                                "legacy_rollback_attempted", "legacy_rollback_succeeded",
                                "rollback_blocked",
                            )
                        )
                    ):
                        raise WriterHandoffClientError("handoff apply result differs")
            # A transport disconnect is deliberately handled identically to a
            # committed-evidence-pending response: rediscover only the server-side
            # attempt bound to the preserved inspection and finalize that identity.
            return self.finalize(inspection_hash, baseline)
        except WriterHandoffRunError:
            raise
        except Exception as error:
            raise WriterHandoffRunError(inspection_hash) from error


def _client_from_runtime_config(path: Path, project_root: Path) -> WriterHandoffClient:
    require_failure_domain_authority()
    from .publish_runtime import RuntimePublishConfig

    runtime = RuntimePublishConfig.load(path, expected_project_root=project_root)
    return WriterHandoffClient(
        WriterHandoffClientConfig(
            project_root=runtime.project_root,
            recovery_root=runtime.recovery.recovery_root,
            vm=runtime.vm,
        )
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--release-manifest-sha256", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("run")
    for command in ("status", "finalize"):
        sub = commands.add_parser(command)
        sub.add_argument("--inspection-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        require_failure_domain_authority()
    except FailureDomainAuthorityNotReady as error:
        print(json.dumps(error.document(), ensure_ascii=False, sort_keys=True))
        return 2
    try:
        client = _client_from_runtime_config(args.config, args.project_root)
        baseline = V39Baseline(args.release_manifest_sha256)
        if args.command == "run":
            result = client.run(baseline)
        elif args.command == "status":
            result = client.status(args.inspection_sha256, baseline)
        else:
            result = client.finalize(args.inspection_sha256, baseline)
        document: Mapping[str, object] = result.public_document()
        code = 0 if result.status == "succeeded" else 2
    except Exception as error:
        if isinstance(error, WriterHandoffRunError):
            document = {
                "schema_version": "qrh-writer-handoff-client-error/v2",
                "status": "error",
                "error_type": type(error).__name__,
                "inspection_sha256": error.inspection_sha256,
            }
        else:
            document = {
                "schema_version": "qrh-writer-handoff-client-error/v1",
                "status": "error",
                "error_type": type(error).__name__,
            }
        code = 2
    print(json.dumps(document, ensure_ascii=False, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CLIENT_RESULT_SCHEMA",
    "WriterHandoffClient",
    "WriterHandoffClientConfig",
    "WriterHandoffClientError",
    "WriterHandoffClientResult",
    "WriterHandoffRunError",
    "main",
]
