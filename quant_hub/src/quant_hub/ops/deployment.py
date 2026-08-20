"""VM D-root deployment controller 的本地、可测试核心。

本模块不实现 SSH/SMB transport、production writer handoff 或 publish orchestration。
调用者只能把完整 candidate 写入 ``incoming/<release>.partial``；controller 在全局
串行锁内验证逐文件 inventory、immutable release manifest 与 state compatibility，
然后才同卷原子 finalize。激活使用唯一 ``active_release.json``，服务启动和探针
全部由 callback 注入。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
from typing import Callable, Iterator, Mapping, Sequence
import uuid

from quant_hub.config import ensure_no_reparse_components
from quant_hub.runtime_seal import (
    RuntimeSealError,
    read_json,
    safe_tree_file_state,
    write_atomic_new_json,
)

from .release_identity import (
    IdentityContractError,
    authorize_receipt_append,
    canonical_manifest_bytes,
    lint_identity_graph,
    manifest_sha256,
    validate_active_release,
    validate_checkpoint_manifest,
    validate_receipt,
    validate_recovery_manifest,
    validate_release_manifest,
)


StateCompatibilityProbe = Callable[[Mapping[str, object]], bool]
StartRelease = Callable[[Path, Mapping[str, object]], bool]
StopRelease = Callable[[Path], None]
PostActivationProbe = Callable[[Path, Mapping[str, object]], Mapping[str, bool]]
RecoveryProtectionProbe = Callable[
    [Mapping[str, object], Mapping[str, object], Mapping[str, object]], bool
]


class DeploymentError(RuntimeError):
    pass


class CandidateValidationError(DeploymentError):
    pass


class ActiveAuthorityCorrupt(DeploymentError):
    pass


class DeploymentLocked(DeploymentError):
    pass


@dataclass(frozen=True)
class DeploymentResult:
    status: str
    candidate_release_id: str
    candidate_manifest_sha256: str
    prior_release_id: str
    prior_manifest_sha256: str
    receipt_id: str
    rollback_attempted: bool
    rollback_succeeded: bool


class DeploymentFailed(DeploymentError):
    def __init__(self, result: DeploymentResult):
        super().__init__(
            f"deployment failed for {result.candidate_release_id}; "
            f"rollback_succeeded={result.rollback_succeeded}"
        )
        self.result = result


@dataclass(frozen=True)
class DeploymentLayout:
    root: Path

    @classmethod
    def controlled(cls, root: Path) -> "DeploymentLayout":
        if not root.is_absolute():
            raise DeploymentError("deployment root must be absolute")
        ensure_no_reparse_components(root)
        root.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(root)
        resolved = root.resolve(strict=True)
        layout = cls(root=resolved)
        for directory in (
            layout.incoming,
            layout.releases,
            layout.control,
            layout.state,
            layout.backups,
            layout.audit_receipts,
            layout.audit_events,
            layout.locks,
        ):
            directory.mkdir(parents=True, exist_ok=True)
            ensure_no_reparse_components(directory)
        return layout

    @property
    def incoming(self) -> Path:
        return self.root / "incoming"

    @property
    def releases(self) -> Path:
        return self.root / "releases"

    @property
    def control(self) -> Path:
        return self.root / "control"

    @property
    def active(self) -> Path:
        return self.control / "active_release.json"

    @property
    def state(self) -> Path:
        """Release 外唯一可变状态根；controller 本身不写业务数据库。"""

        return self.root / "state"

    @property
    def backups(self) -> Path:
        return self.root / "backups"

    @property
    def audit_receipts(self) -> Path:
        return self.root / "audit" / "receipts"

    @property
    def audit_events(self) -> Path:
        return self.root / "audit" / "events"

    @property
    def locks(self) -> Path:
        return self.state / "locks"

    @property
    def deployment_lock(self) -> Path:
        return self.locks / "deployment.lock"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _stable_id(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}", value) is None
        or ".." in value
    ):
        raise DeploymentError(f"{label} is not a stable path-safe ID")
    return value


def _json_clone(value: object) -> Mapping[str, object]:
    return json.loads(canonical_manifest_bytes(value).decode("utf-8"))


class DeploymentController:
    def __init__(self, root: Path):
        self.layout = DeploymentLayout.controlled(root)

    @contextmanager
    def locked(self) -> Iterator[None]:
        """全局 fail-closed 串行锁；遗留锁必须由显式运维恢复处理。"""

        token = secrets.token_hex(16)
        try:
            descriptor = os.open(
                self.layout.deployment_lock,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError as error:
            raise DeploymentLocked("another deployment owns the global lock") from error
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(token.encode("ascii"))
                handle.flush()
                os.fsync(handle.fileno())
            yield
        finally:
            try:
                if self.layout.deployment_lock.read_text(encoding="ascii") == token:
                    self.layout.deployment_lock.unlink()
            except OSError:
                # 锁身份不明时保持 fail closed，不能删除另一个 owner 的锁。
                pass

    def partial_path(self, candidate_id: str) -> Path:
        candidate_id = _stable_id(candidate_id, label="candidate_id")
        return self.layout.incoming / f"{candidate_id}.partial"

    def release_path(self, release_id: str) -> Path:
        release_id = _stable_id(release_id, label="release_id")
        return self.layout.releases / release_id

    def _load_release(self, release_id: str) -> tuple[Mapping[str, object], str, Path]:
        release_path = self.release_path(release_id)
        if not release_path.is_dir():
            raise CandidateValidationError(f"finalized release is missing: {release_id}")
        ensure_no_reparse_components(release_path)
        try:
            release = validate_release_manifest(
                read_json(release_path / "release_manifest.json")
            )
        except (RuntimeSealError, IdentityContractError, OSError) as error:
            raise CandidateValidationError(
                f"finalized release manifest is invalid: {release_id}"
            ) from error
        if release["release_id"] != release_id:
            raise CandidateValidationError("release directory and release_id disagree")
        self._inventory_contract(release, release_path)
        return release, manifest_sha256(release), release_path

    @staticmethod
    def _inventory_contract(
        release: Mapping[str, object], candidate_root: Path
    ) -> Mapping[str, Mapping[str, object]]:
        inventory = release.get("inventory")
        if not isinstance(inventory, dict):
            raise CandidateValidationError("release manifest lacks file inventory")
        if set(inventory) != {"schema_version", "files"}:
            raise CandidateValidationError("release file inventory schema is not closed")
        if inventory["schema_version"] != "qrh-release-file-inventory/v1":
            raise CandidateValidationError("unsupported release file inventory schema")
        files = inventory["files"]
        if not isinstance(files, list):
            raise CandidateValidationError("release inventory files must be a list")
        expected: dict[str, Mapping[str, object]] = {}
        casefolded: dict[str, str] = {}
        for index, raw in enumerate(files):
            if not isinstance(raw, dict) or set(raw) != {"path", "bytes", "sha256"}:
                raise CandidateValidationError(f"invalid inventory record at index {index}")
            relative = raw["path"]
            if (
                not isinstance(relative, str)
                or not relative
                or relative == "release_manifest.json"
                or "\\" in relative
            ):
                raise CandidateValidationError("inventory path must be normalized POSIX relative")
            path = PurePosixPath(relative)
            forbidden_windows = set('<>:"|?*')
            device_names = {
                "con",
                "prn",
                "aux",
                "nul",
                *(f"com{index}" for index in range(1, 10)),
                *(f"lpt{index}" for index in range(1, 10)),
            }
            if (
                path.is_absolute()
                or ".." in path.parts
                or path.as_posix() != relative
                or any(
                    not part
                    or part.endswith((".", " "))
                    or any(character in forbidden_windows for character in part)
                    or any(ord(character) < 32 for character in part)
                    or part.split(".", 1)[0].casefold() in device_names
                    for part in path.parts
                )
            ):
                raise CandidateValidationError("inventory path escapes candidate root")
            folded = relative.casefold()
            if folded in casefolded:
                raise CandidateValidationError(
                    f"case-fold inventory collision: {casefolded[folded]!r}, {relative!r}"
                )
            casefolded[folded] = relative
            if isinstance(raw["bytes"], bool) or not isinstance(raw["bytes"], int) or raw["bytes"] < 0:
                raise CandidateValidationError("inventory bytes must be non-negative integer")
            if (
                not isinstance(raw["sha256"], str)
                or len(raw["sha256"]) != 64
                or any(character not in "0123456789abcdef" for character in raw["sha256"])
            ):
                raise CandidateValidationError("inventory sha256 is invalid")
            expected[relative] = {"bytes": raw["bytes"], "sha256": raw["sha256"]}

        bound_hash = manifest_sha256(inventory)
        resources = release.get("resources")
        if not isinstance(resources, dict) or resources.get("inventory_sha256") != bound_hash:
            raise CandidateValidationError(
                "release resources.inventory_sha256 does not bind file inventory"
            )
        try:
            actual = safe_tree_file_state(candidate_root)
        except (RuntimeSealError, OSError) as error:
            raise CandidateValidationError("candidate tree is not safely enumerable") from error
        if "release_manifest.json" not in actual:
            raise CandidateValidationError("candidate release_manifest.json is missing")
        del actual["release_manifest.json"]
        if actual != expected:
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            changed = sorted(
                path
                for path in set(actual) & set(expected)
                if actual[path] != expected[path]
            )
            raise CandidateValidationError(
                f"candidate inventory mismatch missing={missing} extra={extra} changed={changed}"
            )
        return expected

    def finalize_candidate(
        self,
        candidate_id: str,
        *,
        state_compatibility_probe: StateCompatibilityProbe,
    ) -> tuple[Path, str]:
        """验证并原子重命名 ``incoming/<id>.partial``；失败保留 partial。"""

        with self.locked():
            partial = self.partial_path(candidate_id)
            if not partial.is_dir():
                raise CandidateValidationError("candidate partial directory is missing")
            ensure_no_reparse_components(partial)
            final = self.release_path(candidate_id)
            if os.path.lexists(final):
                raise CandidateValidationError("immutable release path already exists")
            try:
                release = validate_release_manifest(
                    read_json(partial / "release_manifest.json")
                )
            except (RuntimeSealError, IdentityContractError, OSError) as error:
                raise CandidateValidationError("candidate release manifest is invalid") from error
            if release["release_id"] != candidate_id:
                raise CandidateValidationError("candidate_id and release_id disagree")
            manifest_before = canonical_manifest_bytes(release)
            self._inventory_contract(release, partial)
            try:
                compatible = state_compatibility_probe(release)
            except Exception as error:
                raise CandidateValidationError("state compatibility probe failed") from error
            if compatible is not True:
                raise CandidateValidationError("candidate is not compatible with current state")

            # Callback 后重读所有密封材料，阻止验证期间的 TOCTOU 漂移。
            try:
                release_after = validate_release_manifest(
                    read_json(partial / "release_manifest.json")
                )
            except (RuntimeSealError, IdentityContractError, OSError) as error:
                raise CandidateValidationError("candidate changed after state probe") from error
            if canonical_manifest_bytes(release_after) != manifest_before:
                raise CandidateValidationError("candidate manifest changed during validation")
            self._inventory_contract(release_after, partial)
            if partial.stat().st_dev != self.layout.releases.stat().st_dev:
                raise CandidateValidationError("candidate and releases are not on the same volume")
            self._append_event(
                "candidate_finalize_authorized",
                {
                    "release_id": candidate_id,
                    "manifest_sha256": manifest_sha256(release_after),
                },
            )
            try:
                os.rename(partial, final)
            except OSError as error:
                raise CandidateValidationError("atomic candidate finalize failed") from error
            ensure_no_reparse_components(final)
            _, digest, _ = self._load_release(candidate_id)
            return final, digest

    def _active_value(
        self, release_id: str, release_path: Path, manifest_digest: str
    ) -> Mapping[str, object]:
        return validate_active_release(
            {
                "schema_version": "qrh-active-release/v1",
                "release_id": release_id,
                "release_path": str(release_path),
                "manifest_sha256": manifest_digest,
            }
        )

    def _write_active(self, active: Mapping[str, object]) -> None:
        value = validate_active_release(active)
        payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True).encode(
            "utf-8"
        ) + b"\n"
        temporary = self.layout.control / f".active.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.layout.active)
        finally:
            if temporary.exists():
                temporary.unlink()

    def read_active(self) -> tuple[Mapping[str, object], Mapping[str, object]]:
        """只解析唯一 pointer；损坏时不从 receipt 猜 current。"""

        try:
            active = validate_active_release(read_json(self.layout.active))
            release, digest, release_path = self._load_release(str(active["release_id"]))
        except (RuntimeSealError, IdentityContractError, CandidateValidationError, OSError) as error:
            raise ActiveAuthorityCorrupt("active_release.json is missing or invalid") from error
        if active["manifest_sha256"] != digest:
            raise ActiveAuthorityCorrupt("active manifest hash does not resolve")
        if Path(str(active["release_path"])).resolve(strict=False) != release_path.resolve(
            strict=True
        ):
            raise ActiveAuthorityCorrupt("active release path escapes controlled releases")
        return active, release

    def replay_prior(
        self,
        *,
        prior_release_id: str,
        expected_manifest_sha256: str,
        start_release: StartRelease,
        probe_release: Callable[[Path, Mapping[str, object]], bool],
    ) -> Mapping[str, object]:
        """唯一允许在 active 损坏时使用的显式、精确 prior 恢复入口。"""

        with self.locked():
            release, digest, path = self._load_release(prior_release_id)
            if digest != expected_manifest_sha256:
                raise ActiveAuthorityCorrupt("explicit prior manifest hash is not exact")
            active = self._active_value(prior_release_id, path, digest)
            self._append_event(
                "prior_replay_authorized",
                {"release_id": prior_release_id, "manifest_sha256": digest},
            )
            self._write_active(active)
            if start_release(path, active) is not True or probe_release(path, active) is not True:
                raise ActiveAuthorityCorrupt("explicit prior failed to start or verify")
            observed, _ = self.read_active()
            if observed != active:
                raise ActiveAuthorityCorrupt("explicit prior pointer verification failed")
            return active

    def _receipt_path(self, receipt_id: str) -> Path:
        return self.layout.audit_receipts / f"{_stable_id(receipt_id, label='receipt_id')}.json"

    def _append_receipt(self, receipt: Mapping[str, object]) -> None:
        validated = validate_receipt(receipt)
        try:
            write_atomic_new_json(
                self._receipt_path(str(validated["receipt_id"])), validated
            )
        except FileExistsError as error:
            raise DeploymentError("append-only receipt_id already exists") from error

    def _load_receipt(self, receipt_id: str) -> Mapping[str, object]:
        try:
            receipt = validate_receipt(read_json(self._receipt_path(receipt_id)))
        except (RuntimeSealError, IdentityContractError, OSError) as error:
            raise DeploymentError("required immutable receipt is missing or invalid") from error
        if receipt["receipt_id"] != receipt_id:
            raise DeploymentError("receipt filename and identity disagree")
        return receipt

    def _append_event(self, kind: str, fields: Mapping[str, object]) -> None:
        event_id = f"{kind}-{uuid.uuid4().hex}"
        payload = {
            "schema_version": "qrh-deployment-audit-event/v1",
            "event_id": event_id,
            "kind": kind,
            "recorded_at": _now(),
            "fields": dict(fields),
            "authority": "evidence_only",
        }
        write_atomic_new_json(self.layout.audit_events / f"{event_id}.json", payload)

    def record_recovery_protection(
        self,
        *,
        receipt: object,
        recovery_manifest: object,
        checkpoint_manifest: object,
        external_protection_probe: RecoveryProtectionProbe,
    ) -> Mapping[str, object]:
        """在激活前记录已完成 R/RM/C 与外部恢复保护验证的 evidence。"""

        with self.locked():
            active, active_release = self.read_active()
            protection = _json_clone(validate_receipt(receipt))
            if protection["receipt_type"] != "recovery_protection":
                raise DeploymentError("pre-activation evidence must be recovery protection")
            checkpoint = _json_clone(validate_checkpoint_manifest(checkpoint_manifest))
            recovery = _json_clone(validate_recovery_manifest(recovery_manifest))
            candidate_hash = str(protection["release_manifest_sha256"])
            release_ref = recovery["release"]
            if not isinstance(release_ref, dict):
                raise DeploymentError("recovery release reference is invalid")
            candidate_id = str(release_ref["release_id"])
            candidate_release, loaded_candidate_hash, _ = self._load_release(
                candidate_id
            )
            if loaded_candidate_hash != candidate_hash:
                raise DeploymentError("protected candidate release hash is unavailable")
            if candidate_hash == active["manifest_sha256"]:
                raise DeploymentError("recovery protection cannot claim an already active release")

            captured = checkpoint["captured_under_active_release"]
            if not isinstance(captured, dict):
                raise DeploymentError("checkpoint captured release is invalid")
            captured_release, captured_hash, _ = self._load_release(
                str(captured["release_id"])
            )
            if captured_hash != captured["manifest_sha256"]:
                raise DeploymentError("checkpoint captured release hash is unavailable")
            releases: list[Mapping[str, object]] = [active_release, candidate_release]
            if all(
                manifest_sha256(existing) != captured_hash for existing in releases
            ):
                releases.append(captured_release)
            lint_identity_graph(
                active_release=active,
                release_manifests=releases,
                checkpoint_manifests=[checkpoint],
                recovery_manifests=[recovery],
                receipts=[protection],
            )
            frozen = (
                canonical_manifest_bytes(protection),
                canonical_manifest_bytes(recovery),
                canonical_manifest_bytes(checkpoint),
            )
            if external_protection_probe(protection, recovery, checkpoint) is not True:
                raise DeploymentError("external recovery protection probe did not pass")
            if frozen != (
                canonical_manifest_bytes(protection),
                canonical_manifest_bytes(recovery),
                canonical_manifest_bytes(checkpoint),
            ):
                raise DeploymentError("recovery protection evidence changed during probe")
            current_candidate, current_hash, _ = self._load_release(candidate_id)
            if current_hash != candidate_hash or current_candidate != candidate_release:
                raise DeploymentError("candidate changed during recovery protection probe")
            observed_active, _ = self.read_active()
            if observed_active != active:
                self._write_active(active)
                restored_active, _ = self.read_active()
                if restored_active != active:
                    raise ActiveAuthorityCorrupt(
                        "could not restore active after pre-activation identity drift"
                    )
                raise DeploymentError(
                    "active authority changed during pre-activation recovery verification"
                )
            self._append_receipt(protection)
            return protection

    @staticmethod
    def _post_gates(value: object) -> Mapping[str, bool]:
        if not isinstance(value, dict) or set(value) != {
            "health",
            "critical_functions",
            "writer_fence",
        }:
            raise DeploymentError("post-activation probe returned an invalid gate set")
        if any(value[field] is not True for field in value):
            raise DeploymentError("post-activation gates did not all pass")
        return value

    def activate(
        self,
        *,
        candidate_release_id: str,
        deployment_attempt_id: str,
        recovery_protection_receipt_id: str,
        start_release: StartRelease,
        stop_release: StopRelease,
        post_activation_probe: PostActivationProbe,
    ) -> DeploymentResult:
        """切换 candidate；成功后才写 activation，失败只写 failure 并回 prior。"""

        with self.locked():
            prior_active, prior_release = self.read_active()
            prior_id = str(prior_active["release_id"])
            prior_hash = str(prior_active["manifest_sha256"])
            candidate, candidate_hash, candidate_path = self._load_release(
                candidate_release_id
            )
            if candidate_hash == prior_hash:
                raise DeploymentError("candidate is already active; use explicit replay semantics")
            phase = "recovery_protection"
            switch_attempted = False
            protection: Mapping[str, object] | None = None
            try:
                protection = self._load_receipt(recovery_protection_receipt_id)
                if (
                    protection["receipt_type"] != "recovery_protection"
                    or protection["deployment_attempt_id"] != deployment_attempt_id
                    or protection["release_manifest_sha256"] != candidate_hash
                ):
                    raise DeploymentError(
                        "recovery protection receipt does not bind this candidate attempt"
                    )
                candidate_active = self._active_value(
                    candidate_release_id, candidate_path, candidate_hash
                )
                phase = "pointer_switch"
                switch_attempted = True
                self._write_active(candidate_active)
                observed, _ = self.read_active()
                if observed != candidate_active:
                    raise DeploymentError("candidate active pointer verification failed")

                phase = "candidate_start"
                if start_release(candidate_path, candidate_active) is not True:
                    raise DeploymentError("candidate start callback failed")
                phase = "post_activation"
                gates = self._post_gates(
                    post_activation_probe(candidate_path, candidate_active)
                )
                phase = "activation_receipt"
                activation = {
                    "schema_version": "qrh-activation-receipt/v1",
                    "receipt_type": "activation",
                    "receipt_id": f"activation-{uuid.uuid4().hex}",
                    "deployment_attempt_id": deployment_attempt_id,
                    "recorded_at": _now(),
                    "authority": "evidence_only",
                    "release_manifest_sha256": candidate_hash,
                    "recovery_manifest_sha256": protection[
                        "recovery_manifest_sha256"
                    ],
                    "checkpoint_manifest_sha256": protection[
                        "checkpoint_manifest_sha256"
                    ],
                    "verdict": "activated",
                    "switch": {
                        "active_pointer_switched": True,
                        "candidate_started": True,
                    },
                    "post_activation_verification": dict(gates),
                }
                observed, _ = self.read_active()
                authorize_receipt_append(
                    activation,
                    observed_active_release=observed,
                    existing_receipts=[protection],
                )
                self._append_event(
                    "activation_receipt_authorized",
                    {
                        "deployment_attempt_id": deployment_attempt_id,
                        "candidate_release_id": candidate_release_id,
                        "candidate_manifest_sha256": candidate_hash,
                        "prior_release_id": prior_id,
                        "prior_manifest_sha256": prior_hash,
                        "receipt_id": activation["receipt_id"],
                    },
                )
                # 成功 activation receipt 是最后一个可能失败的持久化动作；一旦
                # append 成功，后续不得再进入 rollback/failure 路径。
                self._append_receipt(activation)
                return DeploymentResult(
                    status="activated",
                    candidate_release_id=candidate_release_id,
                    candidate_manifest_sha256=candidate_hash,
                    prior_release_id=prior_id,
                    prior_manifest_sha256=prior_hash,
                    receipt_id=str(activation["receipt_id"]),
                    rollback_attempted=False,
                    rollback_succeeded=False,
                )
            except Exception:
                return self._activation_failed(
                    candidate_release_id=candidate_release_id,
                    candidate_hash=candidate_hash,
                    candidate_path=candidate_path,
                    deployment_attempt_id=deployment_attempt_id,
                    prior_active=prior_active,
                    prior_release=prior_release,
                    phase=phase,
                    switch_attempted=switch_attempted,
                    start_release=start_release,
                    stop_release=stop_release,
                )

    def _activation_failed(
        self,
        *,
        candidate_release_id: str,
        candidate_hash: str,
        candidate_path: Path,
        deployment_attempt_id: str,
        prior_active: Mapping[str, object],
        prior_release: Mapping[str, object],
        phase: str,
        switch_attempted: bool,
        start_release: StartRelease,
        stop_release: StopRelease,
    ) -> DeploymentResult:
        rollback_attempted = switch_attempted
        rollback_succeeded = False
        if switch_attempted:
            stopped = True
            try:
                stop_release(candidate_path)
            except Exception:
                stopped = False
            try:
                self._write_active(prior_active)
                prior_path = self.release_path(str(prior_active["release_id"]))
                restarted = start_release(prior_path, prior_active) is True
                observed, observed_release = self.read_active()
                rollback_succeeded = (
                    stopped
                    and restarted
                    and observed == prior_active
                    and observed_release == prior_release
                )
            except Exception:
                rollback_succeeded = False

        failure = {
            "schema_version": "qrh-failure-receipt/v1",
            "receipt_type": "failure",
            "receipt_id": f"failure-{uuid.uuid4().hex}",
            "deployment_attempt_id": deployment_attempt_id,
            "recorded_at": _now(),
            "authority": "evidence_only",
            "candidate_manifest_sha256": candidate_hash,
            "prior_manifest_sha256": prior_active["manifest_sha256"],
            "verdict": "failed",
            "failed_phase": phase,
            "error_code": f"{phase}_failed",
            "rollback": {
                "attempted": rollback_attempted,
                "succeeded": rollback_succeeded,
            },
        }
        authorize_receipt_append(failure)
        self._append_receipt(failure)
        result = DeploymentResult(
            status="failed",
            candidate_release_id=candidate_release_id,
            candidate_manifest_sha256=candidate_hash,
            prior_release_id=str(prior_active["release_id"]),
            prior_manifest_sha256=str(prior_active["manifest_sha256"]),
            receipt_id=str(failure["receipt_id"]),
            rollback_attempted=rollback_attempted,
            rollback_succeeded=rollback_succeeded,
        )
        raise DeploymentFailed(result)
