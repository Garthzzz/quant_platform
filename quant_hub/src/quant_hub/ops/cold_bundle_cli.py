"""Build one verified cold bundle on the developer off-host recovery root.

The command has one fixed production source/target topology: it asks the
``honghu-vm`` OpenSSH endpoint for a read-only SQLite online backup, downloads
that immutable checkpoint, and builds the bundle locally.  It never restores,
switches, installs a service, or writes outside the VM's exact D project root.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path, PureWindowsPath
from typing import Callable, Mapping, Sequence

from quant_hub.collaboration.checkpoint import verify_sqlite_checkpoint
from quant_hub.config import ensure_no_reparse_components

from .publish_adapters import (
    CommandResult,
    exact_production_root_parent_guard_script,
    verified_d_tooling_python_script,
    subprocess_runner,
)
from .publish_runtime import (
    PublishRuntimeError,
    RecoveryProtectionCoordinator,
    RuntimePublishConfig,
    UnavailableRecoveryActions,
)
from .recovery_bundle import RecoveryBundle, build_recovery_bundle, verify_recovery_bundle
from .release_identity import (
    canonical_manifest_bytes,
    manifest_sha256,
    validate_release_manifest,
)


class ColdBundleCLIError(PublishRuntimeError):
    pass


@dataclass(frozen=True)
class ColdBundleBuildResult:
    bundle: RecoveryBundle
    checkpoint_id: str
    checkpoint_manifest_sha256: str
    release_id: str
    release_manifest_sha256: str
    protection_status: str


class ColdBundleBuilder:
    """Fixed `.240` checkpoint download and off-host bundle assembly."""

    def __init__(
        self,
        config: RuntimePublishConfig,
        *,
        command_runner: Callable[[Sequence[str]], CommandResult] = subprocess_runner,
        preflight: Callable[[], None] | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if config.vm.target_address != "10.5.1.240":
            raise ColdBundleCLIError("cold recovery target must be 10.5.1.240")
        self.config = config
        self.command_runner = command_runner
        self.preflight = preflight or (
            lambda: RecoveryProtectionCoordinator(
                config.recovery, actions=UnavailableRecoveryActions()
            ).preflight()
        )
        self.now = now

    @staticmethod
    def _ps_literal(value: str) -> str:
        return "'" + value.replace("'", "''") + "'"

    def _remote(self, arguments: Sequence[str]) -> Mapping[str, object]:
        temporary_path = self.config.vm.root / "tmp" / "publish-recovery"
        temporary = str(temporary_path)
        rendered = ",".join(self._ps_literal(value) for value in arguments)
        script = (
            "$ssh=($env:SSH_CONNECTION -split ' ');"
            f"if($ssh.Count-lt 3-or $ssh[2]-ne{self._ps_literal(self.config.vm.target_address)})"
            "{throw 'ssh_target_address_differs'};"
            + exact_production_root_parent_guard_script()
            + verified_d_tooling_python_script("publish_recovery_cli_module")
            + f"$root=$approvedRoot;$tmp={self._ps_literal(temporary)};"
            "$tmpFull=[IO.Path]::GetFullPath($tmp);"
            "if(-not $tmpFull.StartsWith($rootFull+'\\',[StringComparison]::OrdinalIgnoreCase))"
            "{throw 'recovery_tmp_escaped_exact_root'};"
            "New-Item -ItemType Directory -Force -LiteralPath $tmp|Out-Null;"
            "$env:PYTHONDONTWRITEBYTECODE='1';$env:TEMP=$tmp;$env:TMP=$tmp;"
            f"$a=@({rendered});$o=& $python @a;"
            "if($LASTEXITCODE-ne 0){throw 'cold_bundle_capture_failed'};"
            "$o|Write-Output"
        )
        encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        result = self.command_runner(
            (
                "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=20",
                "--", self.config.vm.ssh_alias, "powershell.exe", "-NoProfile",
                "-NonInteractive", "-EncodedCommand", encoded,
            )
        )
        if result.returncode != 0:
            raise ColdBundleCLIError("fixed .240 checkpoint command failed")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ColdBundleCLIError("fixed .240 checkpoint response is invalid") from error
        if not isinstance(value, dict):
            raise ColdBundleCLIError("fixed .240 checkpoint response must be an object")
        return value

    def _capture_checkpoint(
        self,
        *,
        source: str,
        checkpoint_id: str,
        release_id: str,
        release_manifest_sha256: str,
    ) -> Path:
        arguments = [
            "-B", "-m", "quant_hub.ops.publish_recovery_cli",
            "capture-legacy" if source == "legacy_c" else "capture",
            "--vm-root", str(self.config.vm.root),
            "--checkpoint-id", checkpoint_id,
            "--state-authority-id", self.config.recovery.state_authority_id,
        ]
        if source == "legacy_c":
            arguments.extend(
                (
                    "--release-id", release_id,
                    "--release-manifest-sha256", release_manifest_sha256,
                )
            )
        value = self._remote(arguments)
        expected_root = (
            PureWindowsPath(self.config.vm.root)
            / "tmp" / "publish-recovery" / "checkpoints" / checkpoint_id
        )
        if (
            value.get("schema_version") != "qrh-publish-checkpoint-result/v1"
            or value.get("checkpoint_id") != checkpoint_id
            or PureWindowsPath(str(value.get("checkpoint_root"))) != expected_root
            or (source == "legacy_c" and value.get("source_authority") != "legacy_c_read_only")
        ):
            raise ColdBundleCLIError("checkpoint response identity/path differs")

        intake = self.config.recovery.recovery_root / "checkpoint-intake"
        intake.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(intake)
        destination = intake / checkpoint_id
        if destination.exists():
            raise ColdBundleCLIError("checkpoint intake identity already exists")
        remote_source = f"{self.config.vm.ssh_alias}:" + str(expected_root).replace("\\", "/")
        copied = self.command_runner(
            (
                "scp", "-q", "-r", "-o", "BatchMode=yes", "-o",
                "ConnectTimeout=20", "-o",
                f"HostName={self.config.vm.target_address}", "--",
                remote_source, str(intake),
            )
        )
        if copied.returncode != 0 or not destination.is_dir():
            raise ColdBundleCLIError("checkpoint download failed")
        scratch = self.config.recovery.recovery_root / "checkpoint-verify-scratch"
        scratch.mkdir(exist_ok=True)
        ensure_no_reparse_components(scratch)
        report = verify_sqlite_checkpoint(destination, scratch_root=scratch)
        if (
            not report.valid
            or report.checkpoint_id != checkpoint_id
            or report.manifest_sha256 != value.get("checkpoint_manifest_sha256")
        ):
            raise ColdBundleCLIError("downloaded checkpoint identity differs")
        return destination

    def build(self, *, release_root: Path, bundle_id: str, state_source: str) -> ColdBundleBuildResult:
        if state_source not in {"legacy_c", "d_active"}:
            raise ColdBundleCLIError("state source must be legacy_c or d_active")
        if state_source == "legacy_c":
            # The first V39 bundle is the input to the real empty-D recovery
            # exercise, whose materialisation event is in turn required by the
            # final failure-domain attestation.  Verify all off-host materials
            # here, but do not pretend an attestation or protection receipt
            # already exists.  Any D-active/state-only bundle still requires
            # the full fresh attestation below.
            RecoveryProtectionCoordinator(
                self.config.recovery, actions=UnavailableRecoveryActions()
            ).preflight_materials()
        else:
            self.preflight()
        release_root = Path(release_root).resolve(strict=True)
        manifest_path = release_root / "release_manifest.json"
        try:
            release_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            validate_release_manifest(release_manifest)
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise ColdBundleCLIError("release manifest is unavailable or invalid") from error
        if manifest_path.read_bytes() != canonical_manifest_bytes(release_manifest):
            raise ColdBundleCLIError("release manifest is not canonical")
        release_id = str(release_manifest["release_id"])
        release_hash = manifest_sha256(release_manifest)
        checkpoint_id = f"checkpoint-{bundle_id}"
        checkpoint_root = self._capture_checkpoint(
            source=state_source,
            checkpoint_id=checkpoint_id,
            release_id=release_id,
            release_manifest_sha256=release_hash,
        )
        checkpoint = verify_sqlite_checkpoint(
            checkpoint_root,
            scratch_root=self.config.recovery.recovery_root / "checkpoint-verify-scratch",
        )
        assert checkpoint.manifest_sha256 is not None
        bundle = build_recovery_bundle(
            release_root=release_root,
            checkpoint_root=checkpoint_root,
            recovery_root=self.config.recovery.recovery_root,
            bundle_id=bundle_id,
            created_at=self.now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
            restore_tool=self.config.recovery.restore_tool,
            runbook=self.config.recovery.runbook,
            operational_root=self.config.recovery.operational_root,
            compatibility={
                "verdict": "compatible",
                "policy": "expand_only_no_down_migration",
            },
            checkpoint_scratch_root=self.config.recovery.recovery_root
            / "checkpoint-verify-scratch",
        )
        verification = verify_recovery_bundle(
            bundle.root,
            checkpoint_scratch_root=self.config.recovery.recovery_root
            / "checkpoint-verify-scratch",
        )
        if (
            not verification.valid
            or verification.release_id != release_id
            or verification.release_manifest_sha256 != release_hash
            or verification.checkpoint_manifest_sha256 != checkpoint.manifest_sha256
        ):
            raise ColdBundleCLIError("built cold bundle identity/closure differs")
        return ColdBundleBuildResult(
            bundle=bundle,
            checkpoint_id=checkpoint_id,
            checkpoint_manifest_sha256=checkpoint.manifest_sha256,
            release_id=release_id,
            release_manifest_sha256=release_hash,
            protection_status=(
                "qualification_only_requires_empty_d_attestation"
                if state_source == "legacy_c"
                else "attestation_verified_bundle"
            ),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--release-root", type=Path, required=True)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--state-source", choices=("legacy_c", "d_active"), required=True)
    args = parser.parse_args(argv)
    config = RuntimePublishConfig.load(
        args.config, expected_project_root=args.project_root
    )
    result = ColdBundleBuilder(config).build(
        release_root=args.release_root,
        bundle_id=args.bundle_id,
        state_source=args.state_source,
    )
    print(
        json.dumps(
            {
                "status": "PASS",
                "bundle_id": result.bundle.bundle_id,
                "recovery_manifest_sha256": result.bundle.recovery_manifest_sha256,
                "checkpoint_id": result.checkpoint_id,
                "checkpoint_manifest_sha256": result.checkpoint_manifest_sha256,
                "release_id": result.release_id,
                "release_manifest_sha256": result.release_manifest_sha256,
                "protection_status": result.protection_status,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
