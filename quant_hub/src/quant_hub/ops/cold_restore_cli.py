"""Transfer and materialize a verified off-host bundle on the sole `.240` VM.

No SMB/UNC path is assumed.  OpenSSH performs an empty-root preflight, SCP
places one immutable bundle under the exact D-root recovery import directory,
and the bundled Python/tool restore it in place.  No command targets C, a D
parent, or a sibling project path.
"""

from __future__ import annotations

import argparse
import base64
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Mapping, Sequence
from uuid import uuid4

from quant_hub.config import ensure_no_reparse_components

from .publish_adapters import (
    CommandResult,
    exact_production_root_parent_guard_script,
    subprocess_runner,
)
from .publish_runtime import RuntimePublishConfig
from .recovery_bundle import RecoveryVerification, verify_recovery_bundle
from .vm_boundary import PRODUCTION_WRITE_AREAS


class ColdRestoreCLIError(RuntimeError):
    pass


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_PREPARE_INSPECTION_SCHEMA = "qrh-prepare-empty-inspection/v1"
_PREPARE_APPLY_SCHEMA = "qrh-prepare-empty-application/v1"


class OpenSSHColdRestore:
    def __init__(
        self,
        config: RuntimePublishConfig,
        *,
        command_runner: Callable[[Sequence[str]], CommandResult] = subprocess_runner,
        bundle_verifier: Callable[[Path], RecoveryVerification] = verify_recovery_bundle,
    ) -> None:
        if config.vm.target_address != "10.5.1.240":
            raise ColdRestoreCLIError("cold restore target must be 10.5.1.240")
        self.config = config
        self.command_runner = command_runner
        self.bundle_verifier = bundle_verifier

    @staticmethod
    def _literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _ssh(self, script: str) -> Mapping[str, object]:
        target_guard = (
            "$ssh=($env:SSH_CONNECTION -split ' ');"
            f"if($ssh.Count-lt 3-or $ssh[2]-ne{self._literal(self.config.vm.target_address)})"
            "{throw 'ssh_target_address_differs'};"
        )
        encoded = base64.b64encode(
            (target_guard + script).encode("utf-16-le")
        ).decode("ascii")
        result = self.command_runner(
            (
                "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "--", self.config.vm.ssh_alias, "powershell.exe", "-NoProfile",
                "-NonInteractive", "-EncodedCommand", encoded,
            )
        )
        if result.returncode != 0:
            raise ColdRestoreCLIError("fixed .240 cold restore command failed")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ColdRestoreCLIError("fixed .240 cold restore response is invalid") from error
        if not isinstance(value, dict):
            raise ColdRestoreCLIError("fixed .240 cold restore response must be an object")
        return value

    @staticmethod
    def _bootstrap_identity(bundle: Path, relative: str) -> tuple[int, str]:
        """Bind a bootstrap executable to the already verified local closure."""

        try:
            inventory = json.loads(
                (bundle / "closure_inventory.json").read_text(encoding="utf-8")
            )
            records = inventory["files"]
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise ColdRestoreCLIError("verified bundle closure inventory is unreadable") from error
        matching = [
            item
            for item in records
            if isinstance(item, dict) and item.get("path") == relative
        ] if isinstance(records, list) else []
        if len(matching) != 1:
            raise ColdRestoreCLIError("bootstrap file is absent from verified closure")
        record = matching[0]
        expected_size = record.get("bytes")
        expected_hash = record.get("sha256")
        sums: dict[str, str] = {}
        try:
            for line in (bundle / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
                digest, name = line.split("  ", 1)
                if name in sums:
                    raise ValueError("duplicate sum")
                sums[name] = digest
        except (OSError, UnicodeError, ValueError) as error:
            raise ColdRestoreCLIError("verified bundle SHA256SUMS is unreadable") from error
        path = bundle.joinpath(*relative.split("/"))
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
            or not isinstance(expected_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None
            or sums.get(relative) != expected_hash
            or not path.is_file()
            or path.is_symlink()
        ):
            raise ColdRestoreCLIError("bootstrap identity is not a regular verified file")
        observed_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if path.stat().st_size != expected_size or observed_hash != expected_hash:
            raise ColdRestoreCLIError("bootstrap bytes changed after bundle verification")
        return expected_size, expected_hash

    @staticmethod
    def _canonical_bytes(value: object) -> bytes:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")

    @classmethod
    def _write_immutable_evidence(
        cls, path: Path, value: Mapping[str, object]
    ) -> str:
        """Atomically publish canonical evidence, allowing exact-byte retry only."""

        payload = cls._canonical_bytes(value)
        path.parent.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(path.parent)
        ensure_no_reparse_components(path)
        if os.path.lexists(path):
            info = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or path.read_bytes() != payload
            ):
                raise ColdRestoreCLIError("immutable off-host evidence already differs")
            return hashlib.sha256(payload).hexdigest()
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
                    raise ColdRestoreCLIError("immutable off-host evidence race differs")
            if path.read_bytes() != payload:
                raise ColdRestoreCLIError("immutable off-host evidence publication differs")
            return hashlib.sha256(payload).hexdigest()
        finally:
            temporary.unlink(missing_ok=True)

    @classmethod
    def _preflight_immutable_evidence(
        cls, path: Path, value: Mapping[str, object]
    ) -> None:
        if not os.path.lexists(path):
            return
        ensure_no_reparse_components(path)
        info = path.lstat()
        expected = cls._canonical_bytes(value)
        if (
            path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or path.read_bytes() != expected
        ):
            raise ColdRestoreCLIError("immutable off-host evidence already differs")

    def _recovery_root(self) -> Path:
        recovery = self.config.recovery.recovery_root.resolve(strict=True)
        ensure_no_reparse_components(recovery)
        project = self.config.project_root.resolve()
        if recovery == project or recovery.is_relative_to(project):
            raise ColdRestoreCLIError("recovery evidence authority must remain outside Git")
        return recovery

    def _controlled_evidence_path(self, path: Path, *, category: str) -> Path:
        recovery = self._recovery_root()
        controlled = recovery / "evidence" / category
        controlled.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(controlled)
        target = Path(path).resolve()
        if (
            target.suffix.casefold() != ".json"
            or not target.is_relative_to(controlled.resolve(strict=True))
        ):
            raise ColdRestoreCLIError(
                "evidence output must be a JSON file in the controlled recovery evidence directory"
            )
        ensure_no_reparse_components(target)
        return target

    def _verified_bundle(
        self, bundle_root: Path
    ) -> tuple[Path, RecoveryVerification, str, tuple[int, str], tuple[int, str]]:
        bundle = Path(bundle_root).resolve(strict=True)
        recovery = self._recovery_root()
        ensure_no_reparse_components(bundle)
        if bundle.parent != recovery:
            raise ColdRestoreCLIError("qualification bundle is outside RECOVERY_ROOT")
        report = self.bundle_verifier(bundle)
        if (
            not report.valid
            or not report.bundle_id
            or not report.release_id
            or not report.release_manifest_sha256
            or _SAFE_ID.fullmatch(report.bundle_id) is None
        ):
            raise ColdRestoreCLIError("off-host recovery bundle is not verified")
        expected_name = f"cold-recovery-{report.bundle_id}"
        if bundle.name != expected_name:
            raise ColdRestoreCLIError("off-host bundle directory and ID differ")
        restore_name = self.config.recovery.restore_tool.name
        if not restore_name or _SAFE_ID.fullmatch(restore_name) is None:
            raise ColdRestoreCLIError("restore tool filename is unsafe")
        python_identity = self._bootstrap_identity(
            bundle, "operational/tooling/python/python.exe"
        )
        tool_identity = self._bootstrap_identity(
            bundle, f"tools/restore/{restore_name}"
        )
        resealed = self.bundle_verifier(bundle)
        if resealed != report:
            raise ColdRestoreCLIError("off-host bundle identity changed during bootstrap seal")
        if self._bootstrap_identity(
            bundle, "operational/tooling/python/python.exe"
        ) != python_identity or self._bootstrap_identity(
            bundle, f"tools/restore/{restore_name}"
        ) != tool_identity:
            raise ColdRestoreCLIError("bootstrap identity changed during local seal")
        return bundle, report, restore_name, python_identity, tool_identity

    def _prepare_empty_script(
        self,
        *,
        expected_legacy_deployment_id: str,
        intent_nonce_sha256: str,
        apply: bool,
        expected_inventory_sha256: str | None,
    ) -> str:
        if _SAFE_ID.fullmatch(expected_legacy_deployment_id) is None:
            raise ColdRestoreCLIError("expected legacy deployment ID is invalid")
        if _SHA256.fullmatch(intent_nonce_sha256) is None:
            raise ColdRestoreCLIError("prepare-empty intent nonce hash is invalid")
        if apply:
            if (
                not isinstance(expected_inventory_sha256, str)
                or _SHA256.fullmatch(expected_inventory_sha256) is None
            ):
                raise ColdRestoreCLIError("expected pre-delete inventory hash is invalid")
        elif expected_inventory_sha256 is not None:
            raise ColdRestoreCLIError("inspection cannot claim a pre-delete inventory hash")
        allowed = ",".join(
            self._literal(name) for name in sorted(PRODUCTION_WRITE_AREAS)
        )
        expected_hash = self._literal(expected_inventory_sha256 or "")
        expected_deployment = self._literal(expected_legacy_deployment_id)
        intent_hash = self._literal(intent_nonce_sha256)
        schema = _PREPARE_APPLY_SCHEMA if apply else _PREPARE_INSPECTION_SCHEMA
        common = (
            "$ErrorActionPreference='Stop';"
            + exact_production_root_parent_guard_script()
            + "$root=$rootFull;"
            f"$allowed=@({allowed});"
            f"$expectedHash={expected_hash};$expectedDeployment={expected_deployment};"
            f"$intentHash={intent_hash};"
            "function Get-CanonicalRootInventory{"
            "$rootItem=Get-Item -LiteralPath $root -Force -ErrorAction Stop;"
            "if(-not $rootItem.PSIsContainer -or (($rootItem.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'exact_root_type'};"
            "$top=@(Get-ChildItem -LiteralPath $root -Force);"
            "foreach($item in $top){if($allowed -notcontains $item.Name)"
            "{throw 'unknown_top_level'};if(($item.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0){throw 'top_level_reparse'}};"
            "$records=New-Object 'System.Collections.Generic.List[string]';"
            "$files=0;$directories=0;$bytes=[long]0;"
            "$all=@(Get-ChildItem -LiteralPath $root -Force -Recurse);"
            "foreach($item in $all){if(($item.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0){throw 'inventory_reparse'};"
            "$relative=$item.FullName.Substring($root.Length).TrimStart('\\').Replace('\\','/');"
            "if(-not $relative -or $relative.Contains('../') -or $relative.Contains(':'))"
            "{throw 'inventory_relative_path'};"
            "if($item.PSIsContainer){$directories++;[void]$records.Add('D'+[char]9+"
            "$relative+[char]10)}else{$files++;$bytes+=$item.Length;"
            "$hash=(Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash."
            "ToLowerInvariant();[void]$records.Add('F'+[char]9+$relative+[char]9+"
            "$item.Length+[char]9+$hash+[char]10)}};"
            "$records.Sort([StringComparer]::Ordinal);$text=[string]::Concat($records);"
            "$payload=(New-Object Text.UTF8Encoding($false)).GetBytes($text);"
            "$hasher=[Security.Cryptography.SHA256]::Create();try{"
            "$hash=([BitConverter]::ToString($hasher.ComputeHash($payload))).Replace('-','')."
            "ToLowerInvariant()}finally{$hasher.Dispose()};"
            "return [pscustomobject]@{inventory_sha256=$hash;file_count=$files;"
            "directory_count=$directories;total_bytes=$bytes;top_level_count=$top.Count}};"
            "function Assert-NoDWriter{"
            "$active=Join-Path $root 'control\\active_release.json';"
            "if(Test-Path -LiteralPath $active){throw 'd_active_authority_exists'};"
            "$pending=Join-Path $root 'control\\pending_activation.json';"
            "if(Test-Path -LiteralPath $pending){throw 'd_pending_activation_exists'};"
            "$state=Join-Path $root 'state';if(Test-Path -LiteralPath $state){"
            "$stateItem=Get-Item -LiteralPath $state -Force;"
            "if(-not $stateItem.PSIsContainer -or (($stateItem.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0)){throw 'd_state_type'};"
            "if(@(Get-ChildItem -LiteralPath $state -Force).Count -ne 0)"
            "{throw 'd_state_writer_authority_exists'}}};"
            "function Assert-LegacyV39{"
            "$listeners=@(Get-NetTCPConnection -LocalPort 8765 -State Listen "
            "-ErrorAction Stop);$pids=@($listeners|Select-Object -ExpandProperty OwningProcess -Unique);"
            "if($pids.Count -ne 1){throw 'legacy_listener_identity'};"
            "$process=@(Get-CimInstance Win32_Process -Filter ('ProcessId='+$pids[0]) "
            "-ErrorAction Stop);if($process.Count -ne 1){throw 'legacy_process_identity'};"
            "$command=[string]$process[0].CommandLine;$normalized=$command.Replace('/','\\');"
            "if($normalized.IndexOf('C:\\quant_platform\\',"
            "[StringComparison]::OrdinalIgnoreCase) -lt 0 -or "
            "$normalized.IndexOf($root,[StringComparison]::OrdinalIgnoreCase) -ge 0)"
            "{throw 'listener_not_legacy_c'};"
            "$response=Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 "
            "-Uri 'http://127.0.0.1:8765/deploymentz';"
            "if($response.StatusCode -ne 200){throw 'legacy_deploymentz_status'};"
            "$deployment=$response.Content|ConvertFrom-Json;"
            "if($deployment.deployment_id -ne $expectedDeployment)"
            "{throw 'legacy_deployment_id_differs'}};"
            "Assert-NoDWriter;Assert-LegacyV39;$inventory=Get-CanonicalRootInventory;"
        )
        if not apply:
            return common + (
                "[ordered]@{"
                f"schema_version={self._literal(schema)};status='inspected_not_deleted';"
                "intent_nonce_sha256=$intentHash;"
                "inventory_sha256=$inventory.inventory_sha256;file_count=$inventory.file_count;"
                "directory_count=$inventory.directory_count;total_bytes=$inventory.total_bytes;"
                "top_level_count=$inventory.top_level_count;legacy_deployment_id=$expectedDeployment;"
                "active_absent=$true;writer_authority_absent=$true;old_c_v39_healthy=$true;"
                "deleted=$false}|ConvertTo-Json -Compress"
            )
        return common + (
            "if($inventory.inventory_sha256 -ne $expectedHash){throw 'pre_delete_inventory_differs'};"
            "Assert-NoDWriter;Assert-LegacyV39;$second=Get-CanonicalRootInventory;"
            "if($second.inventory_sha256 -ne $expectedHash){throw 'pre_delete_inventory_changed'};"
            "$children=@(Get-ChildItem -LiteralPath $root -Force|Sort-Object FullName);"
            "foreach($child in $children){$full=[IO.Path]::GetFullPath($child.FullName);"
            "$parent=[IO.Path]::GetFullPath((Split-Path -Parent $full)).TrimEnd('\\');"
            "if(-not $parent.Equals($root,[StringComparison]::OrdinalIgnoreCase) -or "
            "$full.Equals($root,[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'delete_target_not_exact_child'};"
            "$current=Get-Item -LiteralPath $full -Force -ErrorAction Stop;"
            "if(($current.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)"
            "{throw 'delete_target_reparse'};if($allowed -notcontains $current.Name)"
            "{throw 'delete_target_unknown'}};"
            "$third=Get-CanonicalRootInventory;if($third.inventory_sha256 -ne $expectedHash)"
            "{throw 'pre_delete_inventory_changed_after_child_preflight'};"
            "$confirmed=@(Get-ChildItem -LiteralPath $root -Force|Sort-Object FullName);"
            "if(($children.FullName -join [char]10) -ne ($confirmed.FullName -join [char]10))"
            "{throw 'pre_delete_child_set_changed'};"
            "foreach($child in $children){$current=Get-Item -LiteralPath $child.FullName "
            "-Force -ErrorAction Stop;if(($current.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0){throw 'delete_target_reparse'};"
            "Remove-Item -LiteralPath $child.FullName -Recurse -Force};"
            + exact_production_root_parent_guard_script()
            + "$root=$rootFull;$postRoot=Get-Item -LiteralPath $root -Force -ErrorAction Stop;"
            "if(-not $postRoot.PSIsContainer -or (($postRoot.Attributes -band "
            "[IO.FileAttributes]::ReparsePoint) -ne 0) -or "
            "@(Get-ChildItem -LiteralPath $root -Force).Count -ne 0)"
            "{throw 'exact_root_not_empty_after_prepare'};"
            "Assert-LegacyV39;[ordered]@{"
            f"schema_version={self._literal(schema)};status='prepared_empty_root';"
            "intent_nonce_sha256=$intentHash;"
            "pre_delete_inventory_sha256=$expectedHash;deleted_child_count=$children.Count;"
            "legacy_deployment_id=$expectedDeployment;root_exists=$true;root_empty=$true;"
            "old_c_v39_healthy=$true;active_absent=$true;writer_authority_absent=$true}"
            "|ConvertTo-Json -Compress"
        )

    @staticmethod
    def _prepare_identity(value: Mapping[str, object], *, apply: bool) -> None:
        schema = _PREPARE_APPLY_SCHEMA if apply else _PREPARE_INSPECTION_SCHEMA
        status = "prepared_empty_root" if apply else "inspected_not_deleted"
        if value.get("schema_version") != schema or value.get("status") != status:
            raise ColdRestoreCLIError("prepare-empty remote evidence schema differs")
        if value.get("legacy_deployment_id") is None:
            raise ColdRestoreCLIError("prepare-empty legacy identity is absent")
        if (
            not isinstance(value.get("intent_nonce_sha256"), str)
            or _SHA256.fullmatch(str(value["intent_nonce_sha256"])) is None
        ):
            raise ColdRestoreCLIError("prepare-empty nonce binding is absent")
        if apply:
            count = value.get("deleted_child_count")
            if (
                not isinstance(value.get("pre_delete_inventory_sha256"), str)
                or _SHA256.fullmatch(str(value["pre_delete_inventory_sha256"])) is None
                or not isinstance(count, int)
                or isinstance(count, bool)
                or count < 0
                or any(
                    value.get(field) is not True
                    for field in (
                        "root_exists", "root_empty", "old_c_v39_healthy",
                        "active_absent", "writer_authority_absent",
                    )
                )
            ):
                raise ColdRestoreCLIError("prepare-empty post-delete gates differ")
        else:
            counts = tuple(
                value.get(field)
                for field in (
                    "file_count", "directory_count", "total_bytes", "top_level_count"
                )
            )
            if (
                not isinstance(value.get("inventory_sha256"), str)
                or _SHA256.fullmatch(str(value["inventory_sha256"])) is None
                or value.get("deleted") is not False
                or any(
                    not isinstance(count, int)
                    or isinstance(count, bool)
                    or count < 0
                    for count in counts
                )
                or any(
                    value.get(field) is not True
                    for field in (
                        "old_c_v39_healthy", "active_absent",
                        "writer_authority_absent",
                    )
                )
            ):
                raise ColdRestoreCLIError("prepare-empty inspection gates differ")

    def inspect_prepare_empty(
        self,
        bundle_root: Path,
        *,
        intent_nonce: str,
        expected_legacy_deployment_id: str,
    ) -> Mapping[str, object]:
        _bundle, report, _restore, _python, _tool = self._verified_bundle(bundle_root)
        if len(intent_nonce) < 16 or _SAFE_ID.fullmatch(intent_nonce) is None:
            raise ColdRestoreCLIError("prepare-empty intent nonce is invalid")
        nonce_hash = hashlib.sha256(intent_nonce.encode("utf-8")).hexdigest()
        evidence = self._recovery_root() / "evidence" / "prepare-empty" / (
            f"{nonce_hash}.inspection.json"
        )
        if os.path.lexists(evidence):
            raise ColdRestoreCLIError("prepare-empty intent nonce was already inspected")
        result = self._ssh(
            self._prepare_empty_script(
                expected_legacy_deployment_id=expected_legacy_deployment_id,
                intent_nonce_sha256=nonce_hash,
                apply=False,
                expected_inventory_sha256=None,
            )
        )
        self._prepare_identity(result, apply=False)
        if (
            result.get("legacy_deployment_id") != expected_legacy_deployment_id
            or result.get("intent_nonce_sha256") != nonce_hash
        ):
            raise ColdRestoreCLIError("prepare-empty legacy deployment binding differs")
        recorded = {
            "schema_version": "qrh-prepare-empty-offhost-inspection/v1",
            "authority": "evidence_only",
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "intent_nonce_sha256": nonce_hash,
            "bundle_id": report.bundle_id,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "legacy_deployment_id": expected_legacy_deployment_id,
            "pre_delete_inventory_sha256": result["inventory_sha256"],
            "remote_gates": {
                "active_absent": True,
                "writer_authority_absent": True,
                "old_c_v39_healthy": True,
                "deleted": False,
            },
        }
        evidence_hash = self._write_immutable_evidence(evidence, recorded)
        return {
            "status": "inspected_not_deleted",
            "intent_nonce_sha256": nonce_hash,
            "pre_delete_inventory_sha256": result["inventory_sha256"],
            "legacy_deployment_id": expected_legacy_deployment_id,
            "bundle_id": report.bundle_id,
            "evidence_sha256": evidence_hash,
        }

    def apply_prepare_empty(
        self,
        bundle_root: Path,
        *,
        intent_nonce: str,
        expected_pre_delete_inventory_sha256: str,
        expected_legacy_deployment_id: str,
    ) -> Mapping[str, object]:
        _bundle, report, _restore, _python, _tool = self._verified_bundle(bundle_root)
        if len(intent_nonce) < 16 or _SAFE_ID.fullmatch(intent_nonce) is None:
            raise ColdRestoreCLIError("prepare-empty intent nonce is invalid")
        if _SHA256.fullmatch(expected_pre_delete_inventory_sha256) is None:
            raise ColdRestoreCLIError("expected pre-delete inventory hash is invalid")
        if _SAFE_ID.fullmatch(expected_legacy_deployment_id) is None:
            raise ColdRestoreCLIError("expected legacy deployment ID is invalid")
        nonce_hash = hashlib.sha256(intent_nonce.encode("utf-8")).hexdigest()
        evidence_root = self._recovery_root() / "evidence" / "prepare-empty"
        inspection_path = evidence_root / f"{nonce_hash}.inspection.json"
        try:
            ensure_no_reparse_components(inspection_path)
            inspection_info = inspection_path.lstat()
            inspection_bytes = inspection_path.read_bytes()
            inspection = json.loads(inspection_bytes.decode("utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise ColdRestoreCLIError("matching append-only inspection evidence is absent") from error
        if (
            inspection_path.is_symlink()
            or not stat.S_ISREG(inspection_info.st_mode)
            or inspection_info.st_nlink != 1
            or not isinstance(inspection, dict)
            or inspection_bytes != self._canonical_bytes(inspection)
            or set(inspection) != {
                "schema_version", "authority", "recorded_at",
                "intent_nonce_sha256", "bundle_id", "release_id",
                "release_manifest_sha256", "legacy_deployment_id",
                "pre_delete_inventory_sha256", "remote_gates",
            }
            or inspection.get("schema_version")
            != "qrh-prepare-empty-offhost-inspection/v1"
            or inspection.get("authority") != "evidence_only"
            or inspection.get("remote_gates")
            != {
                "active_absent": True,
                "writer_authority_absent": True,
                "old_c_v39_healthy": True,
                "deleted": False,
            }
        ):
            raise ColdRestoreCLIError("matching append-only inspection evidence is invalid")
        expected_inspection = {
            "intent_nonce_sha256": nonce_hash,
            "bundle_id": report.bundle_id,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "legacy_deployment_id": expected_legacy_deployment_id,
            "pre_delete_inventory_sha256": expected_pre_delete_inventory_sha256,
        }
        if any(inspection.get(key) != value for key, value in expected_inspection.items()):
            raise ColdRestoreCLIError("inspection evidence does not authorize this deletion")
        intent_path = evidence_root / f"{nonce_hash}.apply-intent.json"
        applied_path = evidence_root / f"{nonce_hash}.applied.json"
        if os.path.lexists(applied_path):
            raise ColdRestoreCLIError("prepare-empty intent nonce was already applied")
        intent = {
            "schema_version": "qrh-prepare-empty-offhost-apply-intent/v1",
            "authority": "coordination_only",
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            **expected_inspection,
            "inspection_evidence_sha256": hashlib.sha256(
                inspection_path.read_bytes()
            ).hexdigest(),
        }
        intent_hash = self._write_immutable_evidence(intent_path, intent)
        result = self._ssh(
            self._prepare_empty_script(
                expected_legacy_deployment_id=expected_legacy_deployment_id,
                intent_nonce_sha256=nonce_hash,
                apply=True,
                expected_inventory_sha256=expected_pre_delete_inventory_sha256,
            )
        )
        self._prepare_identity(result, apply=True)
        if (
            result.get("legacy_deployment_id") != expected_legacy_deployment_id
            or result.get("intent_nonce_sha256") != nonce_hash
            or result.get("pre_delete_inventory_sha256")
            != expected_pre_delete_inventory_sha256
        ):
            raise ColdRestoreCLIError("prepare-empty apply binding differs")
        applied = {
            "schema_version": "qrh-prepare-empty-offhost-applied/v1",
            "authority": "evidence_only",
            "recorded_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            **expected_inspection,
            "apply_intent_sha256": intent_hash,
            "root_exists": True,
            "root_empty": True,
            "old_c_v39_healthy": True,
        }
        applied_hash = self._write_immutable_evidence(applied_path, applied)
        return {
            "status": "prepared_empty_root",
            "intent_nonce_sha256": nonce_hash,
            "pre_delete_inventory_sha256": expected_pre_delete_inventory_sha256,
            "legacy_deployment_id": expected_legacy_deployment_id,
            "bundle_id": report.bundle_id,
            "evidence_sha256": applied_hash,
        }

    def restore(
        self, bundle_root: Path, *, evidence_output: Path
    ) -> Mapping[str, object]:
        bundle, report, restore_name, python_identity, tool_identity = (
            self._verified_bundle(bundle_root)
        )
        python_size, python_hash = python_identity
        tool_size, tool_hash = tool_identity
        evidence_path = self._controlled_evidence_path(
            evidence_output, category="cold-materialization"
        )
        audit_id = f"cold-materialization-{report.bundle_id}"
        expected_event = {
            "schema_version": "qrh-recovery-materialization-event/v1",
            "event_id": audit_id,
            "kind": "cold_recovery_materialized",
            "authority": "evidence_only",
            "fields": {
                "bundle_id": report.bundle_id,
                "release_id": report.release_id,
                "manifest_sha256": report.release_manifest_sha256,
                "empty_root_precondition": True,
                "import_cleaned": True,
                "runtime_tmp_cleaned": True,
            },
        }
        # A conflicting local authority must block before the first remote
        # write. Exact existing bytes are the sole idempotent case.
        self._preflight_immutable_evidence(evidence_path, expected_event)
        root = str(self.config.vm.root)
        import_parent = self.config.vm.root / "tmp" / "recovery-import"
        runtime_tmp = self.config.vm.root / "tmp" / "recovery-runtime"
        expected_name = bundle.name
        remote_bundle = import_parent / expected_name
        prepare = (
            exact_production_root_parent_guard_script()
            + "$root=$approvedRoot;"
            "if(@(Get-ChildItem -LiteralPath $root -Force).Count-ne 0){throw 'exact_d_root_not_empty'};"
            f"New-Item -ItemType Directory -Force -LiteralPath {self._literal(str(import_parent))}|Out-Null;"
            "@{status='prepared_empty_root';empty_root_precondition=$true}|ConvertTo-Json -Compress"
        )
        prepared = self._ssh(prepare)
        if prepared != {"status": "prepared_empty_root", "empty_root_precondition": True}:
            raise ColdRestoreCLIError("exact .240 D root empty precondition did not pass")
        copied = self.command_runner(
            (
                "scp", "-q", "-r", "-o", "BatchMode=yes", "-o",
                "ConnectTimeout=20", "-o",
                f"HostName={self.config.vm.target_address}", "--", str(bundle),
                f"{self.config.vm.ssh_alias}:" + str(import_parent).replace("\\", "/"),
            )
        )
        if copied.returncode != 0:
            raise ColdRestoreCLIError("verified bundle transfer to exact D staging failed")
        python = remote_bundle / "operational" / "tooling" / "python" / "python.exe"
        tool = remote_bundle / "tools" / "restore" / restore_name
        audit_path = self.config.vm.root / "audit" / "events" / f"{audit_id}.json"
        materialize = (
            f"$root={self._literal(root)};$bundle={self._literal(str(remote_bundle))};"
            "function Assert-BootstrapFile{param([string]$Path,[long]$Size,[string]$Sha256);"
            "$full=[IO.Path]::GetFullPath($Path);$rootFull=[IO.Path]::GetFullPath($root).TrimEnd('\\');"
            "if(-not $full.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'bootstrap_path_escaped_exact_d'};"
            "$cursor=$full;$first=$true;$file=$null;"
            "while($true){$item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop;"
            "if(($item.Attributes-band[IO.FileAttributes]::ReparsePoint)-ne 0)"
            "{throw 'bootstrap_reparse_chain'};"
            "if($first){if($item.PSIsContainer){throw 'bootstrap_not_regular_file'};$file=$item;$first=$false}"
            "elseif(-not $item.PSIsContainer){throw 'bootstrap_parent_not_directory'};"
            "$parent=Split-Path -Parent $cursor;if(-not $parent-or $parent-eq $cursor){break};"
            "$cursor=$parent};"
            "if($file.Length-ne $Size){throw 'bootstrap_size_mismatch'};"
            "$actual=(Get-FileHash -LiteralPath $full -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant();"
            "if($actual-ne $Sha256){throw 'bootstrap_hash_mismatch'}};"
            f"Assert-BootstrapFile {self._literal(str(python))} {python_size} {self._literal(python_hash)};"
            f"Assert-BootstrapFile {self._literal(str(tool))} {tool_size} {self._literal(tool_hash)};"
            f"$tmp={self._literal(str(runtime_tmp))};"
            "New-Item -ItemType Directory -Force -LiteralPath $tmp|Out-Null;"
            "$env:PYTHONDONTWRITEBYTECODE='1';$env:TEMP=$tmp;$env:TMP=$tmp;"
            f"$lines=& {self._literal(str(python))} -I -B {self._literal(str(tool))} "
            f"--bundle-root $bundle --empty-target-root $root --staged-under-target;"
            "if($LASTEXITCODE-ne 0){throw 'bundle_materialization_failed'};"
            "$result=($lines|Select-Object -Last 1|ConvertFrom-Json);"
            "if($result.status-ne'materialized_pending_post_restore_verification'"
            "-or $result.empty_root_precondition-ne $true){throw 'materialization_identity_failed'};"
            f"Remove-Item -LiteralPath {self._literal(str(import_parent))} -Recurse -Force;"
            "Remove-Item -LiteralPath $tmp -Recurse -Force;"
            f"$audit={self._literal(str(audit_path))};"
            "$auditParent=Split-Path -Parent $audit;"
            "New-Item -ItemType Directory -Force -LiteralPath $auditParent|Out-Null;"
            f"$event=@{{schema_version='qrh-recovery-materialization-event/v1';event_id={self._literal(audit_id)};"
            "kind='cold_recovery_materialized';authority='evidence_only';fields=@{"
            f"bundle_id={self._literal(report.bundle_id)};release_id={self._literal(report.release_id)};"
            f"manifest_sha256={self._literal(report.release_manifest_sha256)};"
            "empty_root_precondition=$true;import_cleaned=$true;runtime_tmp_cleaned=$true}};"
            "$json=$event|ConvertTo-Json -Compress -Depth 4;"
            "[IO.File]::WriteAllText($audit,$json,(New-Object Text.UTF8Encoding($false)));"
            "$event|ConvertTo-Json -Compress -Depth 4"
        )
        result = self._ssh(materialize)
        fields = result.get("fields") if isinstance(result, dict) else None
        if (
            result != expected_event
            or
            result.get("schema_version") != "qrh-recovery-materialization-event/v1"
            or result.get("event_id") != audit_id
            or not isinstance(fields, dict)
            or fields.get("bundle_id") != report.bundle_id
            or fields.get("release_id") != report.release_id
            or fields.get("manifest_sha256") != report.release_manifest_sha256
            or any(
                fields.get(key) is not True
                for key in (
                    "empty_root_precondition", "import_cleaned", "runtime_tmp_cleaned"
                )
            )
        ):
            raise ColdRestoreCLIError(".240 recovery materialization evidence differs")
        evidence_hash = self._write_immutable_evidence(evidence_path, result)
        return {
            "status": "cold_recovery_materialized",
            "event_id": audit_id,
            "bundle_id": report.bundle_id,
            "release_id": report.release_id,
            "release_manifest_sha256": report.release_manifest_sha256,
            "evidence_sha256": evidence_hash,
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--config", type=Path, required=True)
        target.add_argument("--project-root", type=Path, required=True)
        target.add_argument("--bundle-root", type=Path, required=True)

    restore = subparsers.add_parser("restore")
    common(restore)
    restore.add_argument("--evidence-output", type=Path, required=True)
    prepare = subparsers.add_parser("prepare-empty")
    common(prepare)
    prepare.add_argument("--mode", choices=("inspect", "apply"), required=True)
    prepare.add_argument("--intent-nonce", required=True)
    prepare.add_argument("--expected-legacy-deployment-id", required=True)
    prepare.add_argument("--expected-pre-delete-inventory-sha256")
    args = parser.parse_args(argv)
    config = RuntimePublishConfig.load(args.config, expected_project_root=args.project_root)
    operator = OpenSSHColdRestore(config)
    if args.command == "restore":
        result = operator.restore(
            args.bundle_root, evidence_output=args.evidence_output
        )
    elif args.mode == "inspect":
        if args.expected_pre_delete_inventory_sha256 is not None:
            parser.error("prepare-empty inspect does not accept an expected inventory hash")
        result = operator.inspect_prepare_empty(
            args.bundle_root,
            intent_nonce=args.intent_nonce,
            expected_legacy_deployment_id=args.expected_legacy_deployment_id,
        )
    else:
        if args.expected_pre_delete_inventory_sha256 is None:
            parser.error("prepare-empty apply requires the inspected inventory hash")
        result = operator.apply_prepare_empty(
            args.bundle_root,
            intent_nonce=args.intent_nonce,
            expected_pre_delete_inventory_sha256=(
                args.expected_pre_delete_inventory_sha256
            ),
            expected_legacy_deployment_id=args.expected_legacy_deployment_id,
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
