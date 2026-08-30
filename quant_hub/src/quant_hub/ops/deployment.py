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
import shutil
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
    manifest_sha256,
    validate_active_release,
    validate_receipt,
    validate_release_manifest,
)


StateCompatibilityProbe = Callable[[Mapping[str, object]], bool]
StartRelease = Callable[[Path, Mapping[str, object]], bool]
StopRelease = Callable[[Path], None]
PostActivationProbe = Callable[[Path, Mapping[str, object]], Mapping[str, bool]]
class DeploymentError(RuntimeError):
    pass


class CandidateValidationError(DeploymentError):
    pass


class ActiveAuthorityCorrupt(DeploymentError):
    pass


class DeploymentLocked(DeploymentError):
    pass


class PendingActivationResolutionRequired(DeploymentError):
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

    @property
    def pending_activation(self) -> Path:
        return self.control / "pending_activation.json"


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


_LEGACY_TEST_CONTROLLER_TOKEN = object()


class DeploymentController:
    """Historical v1 controller retained only for isolated regression tests."""

    def __init__(self, root: Path, *, _test_token: object | None = None):
        # Reject before DeploymentLayout can create, enumerate, or read paths.
        if _test_token is not _LEGACY_TEST_CONTROLLER_TOKEN:
            raise DeploymentError(
                "legacy DeploymentController is test-only; production requires v4 exact controller"
            )
        candidate = Path(root).resolve(strict=False)
        production = Path(r"D:\quant\quant_platform").resolve(strict=False)
        same_production = (
            os.path.normcase(os.path.normpath(str(candidate)))
            == os.path.normcase(os.path.normpath(str(production)))
        )
        if not same_production and candidate.exists() and production.exists():
            try:
                same_production = os.path.samefile(candidate, production)
            except OSError:
                # Fall through to the canonical comparison; uncertainty never
                # grants access to a path that already normalized to D root.
                pass
        if same_production:
            raise DeploymentError(
                "legacy DeploymentController cannot target the production D root"
            )
        self.layout = DeploymentLayout.controlled(root)

    @classmethod
    def for_test_only(cls, root: Path) -> "DeploymentController":
        return cls(root, _test_token=_LEGACY_TEST_CONTROLLER_TOKEN)

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

    def read_active(
        self, *, allow_pending_activation: bool = False
    ) -> tuple[Mapping[str, object], Mapping[str, object]]:
        """只解析唯一 pointer；损坏时不从 receipt 猜 current。"""

        if self.layout.pending_activation.exists() and not allow_pending_activation:
            raise PendingActivationResolutionRequired(
                "pending activation requires explicit controller resolution"
            )
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

    @staticmethod
    def _validate_pending_activation(value: object) -> Mapping[str, object]:
        fields = {
            "schema_version", "authority", "deployment_attempt_id",
            "candidate_active", "prior_active",
            "activation_receipt_id", "failure_receipt_id", "created_at",
            "service_start_nonce", "phase",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise PendingActivationResolutionRequired("pending activation schema differs")
        if (
            value.get("schema_version") != "qrh-pending-activation/v1"
            or value.get("authority") != "local_prior_coordination_only"
        ):
            raise PendingActivationResolutionRequired("pending activation identity differs")
        _stable_id(value.get("deployment_attempt_id"), label="deployment_attempt_id")
        _stable_id(value.get("activation_receipt_id"), label="activation_receipt_id")
        _stable_id(value.get("failure_receipt_id"), label="failure_receipt_id")
        _stable_id(value.get("service_start_nonce"), label="service_start_nonce")
        validate_active_release(value.get("candidate_active"))
        validate_active_release(value.get("prior_active"))
        if not isinstance(value.get("created_at"), str):
            raise PendingActivationResolutionRequired("pending activation time is invalid")
        if value.get("phase") not in {
            "prepared_before_pointer", "candidate_start_authorized",
            "prior_start_authorized",
        }:
            raise PendingActivationResolutionRequired("pending activation phase is invalid")
        return _json_clone(value)

    def _load_pending_activation(self) -> Mapping[str, object] | None:
        if not self.layout.pending_activation.exists():
            return None
        try:
            return self._validate_pending_activation(
                read_json(self.layout.pending_activation)
            )
        except (RuntimeSealError, IdentityContractError, OSError) as error:
            raise PendingActivationResolutionRequired(
                "pending activation journal is unreadable"
            ) from error

    def _write_pending_activation(self, value: Mapping[str, object]) -> None:
        journal = self._validate_pending_activation(value)
        try:
            write_atomic_new_json(self.layout.pending_activation, journal)
        except FileExistsError as error:
            raise PendingActivationResolutionRequired(
                "another pending activation already exists"
            ) from error

    def _remove_pending_activation(self, expected: Mapping[str, object]) -> None:
        observed = self._load_pending_activation()
        if observed != expected:
            raise PendingActivationResolutionRequired(
                "pending activation changed before terminal cleanup"
            )
        self.layout.pending_activation.unlink()

    def _replace_pending_activation(
        self, expected: Mapping[str, object], *, phase: str
    ) -> Mapping[str, object]:
        observed = self._load_pending_activation()
        if observed != expected:
            raise PendingActivationResolutionRequired(
                "pending activation changed before phase transition"
            )
        updated = self._validate_pending_activation({**expected, "phase": phase})
        temporary = self.layout.control / f".pending.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(canonical_manifest_bytes(updated))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.layout.pending_activation)
        finally:
            temporary.unlink(missing_ok=True)
        return updated

    def assert_no_pending_activation(self) -> None:
        if self._load_pending_activation() is not None:
            raise PendingActivationResolutionRequired(
                "service/controller cannot consume uncommitted active pointer"
            )

    def pending_service_start_authorization(
        self, active: Mapping[str, object]
    ) -> tuple[str, str, str] | None:
        """Return explicit SCM start args for an exact in-flight identity."""

        journal = self._load_pending_activation()
        if journal is None:
            return None
        observed = validate_active_release(active)
        if observed == journal["candidate_active"]:
            role = "candidate"
            required_phase = "candidate_start_authorized"
        elif observed == journal["prior_active"]:
            role = "prior"
            required_phase = "prior_start_authorized"
        else:
            raise PendingActivationResolutionRequired(
                "pending service start identity is neither candidate nor prior"
            )
        if journal["phase"] != required_phase:
            raise PendingActivationResolutionRequired(
                "pending service start role is not authorized in this phase"
            )
        return (
            role,
            str(journal["deployment_attempt_id"]),
            str(journal["service_start_nonce"]),
        )

    def authorize_service_start(
        self,
        *,
        active: Mapping[str, object],
        authorization: tuple[str, str, str] | None,
    ) -> None:
        journal = self._load_pending_activation()
        if journal is None:
            if authorization is not None:
                raise PendingActivationResolutionRequired(
                    "service start authorization has no pending activation"
                )
            return
        if authorization is None:
            raise PendingActivationResolutionRequired(
                "ordinary service start cannot consume pending activation"
            )
        expected = self.pending_service_start_authorization(active)
        if authorization != expected:
            raise PendingActivationResolutionRequired(
                "service start authorization does not bind pending attempt"
            )

    def resolve_pending_activation(
        self,
        *,
        start_release: StartRelease,
        stop_release: StopRelease,
    ) -> DeploymentResult | None:
        """Replay one durable journal without treating it as active authority."""

        with self.locked():
            journal = self._load_pending_activation()
            if journal is None:
                return None
            attempt_id = str(journal["deployment_attempt_id"])
            candidate_active = validate_active_release(journal["candidate_active"])
            prior_active = validate_active_release(journal["prior_active"])
            activation_id = str(journal["activation_receipt_id"])
            failure_id = str(journal["failure_receipt_id"])
            activation_path = self._receipt_path(activation_id)
            failure_path = self._receipt_path(failure_id)
            if activation_path.exists() and failure_path.exists():
                raise PendingActivationResolutionRequired(
                    "activation and failure receipts are mutually exclusive"
                )
            if activation_path.exists():
                activation = self._load_receipt(activation_id)
                if (
                    activation.get("receipt_type") != "activation"
                    or activation.get("deployment_attempt_id") != attempt_id
                    or activation.get("release_manifest_sha256")
                    != candidate_active["manifest_sha256"]
                ):
                    raise PendingActivationResolutionRequired(
                        "activation receipt does not close pending journal"
                    )
                observed, _ = self.read_active(allow_pending_activation=True)
                if observed != candidate_active:
                    raise PendingActivationResolutionRequired(
                        "committed activation receipt and active authority differ"
                    )
                self._enforce_terminal_release_pair(
                    active_manifest_sha256=str(candidate_active["manifest_sha256"]),
                    prior_manifest_sha256=str(prior_active["manifest_sha256"]),
                )
                self._remove_pending_activation(journal)
                return DeploymentResult(
                    "activated", str(candidate_active["release_id"]),
                    str(candidate_active["manifest_sha256"]),
                    str(prior_active["release_id"]),
                    str(prior_active["manifest_sha256"]), activation_id,
                    False, False,
                )

            candidate_path = self.release_path(str(candidate_active["release_id"]))
            try:
                stop_release(candidate_path)
            except Exception:
                pass
            self._write_active(prior_active)
            prior_path = self.release_path(str(prior_active["release_id"]))
            _prior_release, prior_hash, _ = self._load_release(
                str(prior_active["release_id"])
            )
            journal = self._replace_pending_activation(
                journal, phase="prior_start_authorized"
            )
            rollback_succeeded = (
                prior_hash == prior_active["manifest_sha256"]
                and start_release(prior_path, prior_active) is True
                and self.read_active(allow_pending_activation=True)[0] == prior_active
            )
            if not rollback_succeeded:
                raise PendingActivationResolutionRequired(
                    "pending activation could not restore explicit prior"
                )
            if failure_path.exists():
                failure = self._load_receipt(failure_id)
                if (
                    failure.get("receipt_type") != "failure"
                    or failure.get("deployment_attempt_id") != attempt_id
                    or failure.get("candidate_manifest_sha256")
                    != candidate_active["manifest_sha256"]
                    or failure.get("prior_manifest_sha256")
                    != prior_active["manifest_sha256"]
                ):
                    raise PendingActivationResolutionRequired(
                        "failure receipt does not close pending journal"
                    )
            else:
                failure = {
                    "schema_version": "qrh-failure-receipt/v1",
                    "receipt_type": "failure", "receipt_id": failure_id,
                    "deployment_attempt_id": attempt_id, "recorded_at": _now(),
                    "authority": "evidence_only",
                    "candidate_manifest_sha256": candidate_active["manifest_sha256"],
                    "prior_manifest_sha256": prior_active["manifest_sha256"],
                    "verdict": "failed", "failed_phase": "activation_interrupted",
                    "error_code": "activation_interrupted_resolved",
                    "rollback": {"attempted": True, "succeeded": True},
                }
                authorize_receipt_append(failure)
                self._append_receipt(failure)
            self._retire_exact_release(
                str(candidate_active["release_id"]),
                str(candidate_active["manifest_sha256"]),
            )
            self._remove_pending_activation(journal)
            return DeploymentResult(
                "failed", str(candidate_active["release_id"]),
                str(candidate_active["manifest_sha256"]),
                str(prior_active["release_id"]), str(prior_active["manifest_sha256"]),
                failure_id, True, True,
            )

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

    def _append_event(self, kind: str, fields: Mapping[str, object]) -> str:
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
        return event_id

    def _retire_exact_release(self, release_id: str, manifest_digest: str) -> None:
        """Remove one fully verified obsolete closure inside ``releases`` only."""

        candidate = self.release_path(release_id)
        if not os.path.lexists(candidate):
            return
        _release, observed_digest, path = self._load_release(release_id)
        if observed_digest != manifest_digest:
            raise PendingActivationResolutionRequired(
                "obsolete release identity changed before retention cleanup"
            )
        expected = self.layout.releases / _stable_id(release_id, label="release_id")
        if path.resolve(strict=True) != expected.resolve(strict=True):
            raise PendingActivationResolutionRequired(
                "obsolete release path escapes controlled releases"
            )
        ensure_no_reparse_components(path)
        shutil.rmtree(path)
        if os.path.lexists(path):
            raise PendingActivationResolutionRequired(
                "obsolete release retention cleanup did not complete"
            )

    def _enforce_terminal_release_pair(
        self, *, active_manifest_sha256: str, prior_manifest_sha256: str
    ) -> None:
        """Retain exactly the committed active and its explicit local prior."""

        retained = {active_manifest_sha256, prior_manifest_sha256}
        inventory: list[tuple[str, str]] = []
        for path in sorted(self.layout.releases.iterdir(), key=lambda item: item.name):
            if not path.is_dir():
                raise PendingActivationResolutionRequired(
                    "release root contains a non-directory entry"
                )
            _release, digest, _ = self._load_release(path.name)
            inventory.append((path.name, digest))
        extras = [
            (release_id, digest)
            for release_id, digest in inventory
            if digest not in retained
        ]
        self._append_event(
            "terminal_release_retention_authorized",
            {
                "active_manifest_sha256": active_manifest_sha256,
                "prior_manifest_sha256": prior_manifest_sha256,
                "obsolete_releases": [
                    {"release_id": release_id, "manifest_sha256": digest}
                    for release_id, digest in extras
                ],
            },
        )
        for release_id, digest in extras:
            self._retire_exact_release(release_id, digest)
        remaining = {
            self._load_release(path.name)[1]
            for path in self.layout.releases.iterdir()
            if path.is_dir()
        }
        if remaining != retained:
            raise PendingActivationResolutionRequired(
                "terminal release retention is not exact active plus one prior"
            )

    def record_candidate_validation(
        self,
        *,
        release_id: str,
        expected_manifest_sha256: str,
        publish_candidate_sha256: str,
        probe_evidence: Mapping[str, object],
    ) -> str:
        """验证 finalized candidate 并追加 evidence-only event；绝不生成 receipt。"""

        with self.locked():
            _release, digest, _path = self._load_release(release_id)
            if digest != expected_manifest_sha256:
                raise CandidateValidationError("finalized candidate manifest hash differs")
            if re.fullmatch(r"[0-9a-f]{64}", publish_candidate_sha256) is None:
                raise CandidateValidationError("publish candidate hash is invalid")
            return self._append_event(
                "candidate_validation_completed",
                {
                    "release_id": release_id,
                    "release_manifest_sha256": digest,
                    "publish_candidate_sha256": publish_candidate_sha256,
                    "status": "candidate_validated_not_active",
                    "receipt_created": False,
                    "probe_evidence": dict(probe_evidence),
                },
            )

    def verify_finalized_release(
        self, *, release_id: str, expected_manifest_sha256: str
    ) -> tuple[Path, str]:
        """只读复核 finalized release；不生成 event/receipt，不改变 active。"""

        with self.locked():
            _release, digest, path = self._load_release(release_id)
            if digest != expected_manifest_sha256:
                raise CandidateValidationError("finalized candidate manifest hash differs")
            return path, digest

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
            phase = "local_prior_preflight"
            switch_attempted = False
            journal: Mapping[str, object] | None = None
            activation_committed = False
            try:
                candidate_active = self._active_value(
                    candidate_release_id, candidate_path, candidate_hash
                )
                pending = self._validate_pending_activation(
                    {
                        "schema_version": "qrh-pending-activation/v1",
                        "authority": "local_prior_coordination_only",
                        "deployment_attempt_id": deployment_attempt_id,
                        "candidate_active": candidate_active,
                        "prior_active": prior_active,
                        "activation_receipt_id": f"activation-{uuid.uuid4().hex}",
                        "failure_receipt_id": f"failure-{uuid.uuid4().hex}",
                        "service_start_nonce": secrets.token_hex(24),
                        "phase": "prepared_before_pointer",
                        "created_at": _now(),
                    }
                )
                phase = "activation_journal"
                self._write_pending_activation(pending)
                journal = pending
                phase = "pointer_switch"
                switch_attempted = True
                self._write_active(candidate_active)
                observed, _ = self.read_active(allow_pending_activation=True)
                if observed != candidate_active:
                    raise DeploymentError("candidate active pointer verification failed")

                phase = "candidate_start"
                journal = self._replace_pending_activation(
                    journal, phase="candidate_start_authorized"
                )
                if start_release(candidate_path, candidate_active) is not True:
                    raise DeploymentError("candidate start callback failed")
                phase = "post_activation"
                gates = self._post_gates(
                    post_activation_probe(candidate_path, candidate_active)
                )
                phase = "activation_receipt"
                activation = {
                    "schema_version": "qrh-local-activation-receipt/v1",
                    "receipt_type": "activation",
                    "receipt_id": journal["activation_receipt_id"],
                    "deployment_attempt_id": deployment_attempt_id,
                    "recorded_at": _now(),
                    "authority": "evidence_only",
                    "release_manifest_sha256": candidate_hash,
                    "prior_manifest_sha256": prior_hash,
                    "verdict": "activated",
                    "switch": {
                        "active_pointer_switched": True,
                        "candidate_started": True,
                    },
                    "post_activation_verification": dict(gates),
                }
                observed, _ = self.read_active(allow_pending_activation=True)
                authorize_receipt_append(
                    activation,
                    observed_active_release=observed,
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
                activation_committed = True
                self._enforce_terminal_release_pair(
                    active_manifest_sha256=candidate_hash,
                    prior_manifest_sha256=prior_hash,
                )
                self._remove_pending_activation(journal)
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
                if activation_committed:
                    raise PendingActivationResolutionRequired(
                        "activation committed; pending journal cleanup must replay"
                    )
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
                    journal=journal,
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
        journal: Mapping[str, object] | None,
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
                if journal is not None:
                    journal = self._replace_pending_activation(
                        journal, phase="prior_start_authorized"
                    )
                restarted = start_release(prior_path, prior_active) is True
                observed, observed_release = self.read_active(
                    allow_pending_activation=journal is not None
                )
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
            "receipt_id": (
                journal["failure_receipt_id"]
                if journal is not None
                else f"failure-{uuid.uuid4().hex}"
            ),
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
        # A failure receipt is evidence, not authority.  If explicit prior
        # restart did not complete, keep the coordination journal so a later
        # controller can replay the same prior and reuse this one receipt.
        if journal is not None and rollback_succeeded:
            self._retire_exact_release(candidate_release_id, candidate_hash)
            self._remove_pending_activation(journal)
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
