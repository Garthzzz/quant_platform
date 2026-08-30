"""受控单命令 publish 的可测试编排核心。

本模块刻意不内置 GitHub、SSH/SMB 或 VM 凭据与连接逻辑。所有会改变外部状态的
动作均由调用方注入；核心只负责顺序、精确身份校验、一次 push 约束，以及
``running 不取消、pending 只保留最新`` 的并发语义。安装后的 ``qrh-publish``
可从任意 cwd 运行；``--dry-run`` 只执行本地只读 Git 检查并输出计划。
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Callable, Mapping
import uuid

from quant_hub.config import ensure_no_reparse_components

PUBLISH_STATE_SCHEMA = "qrh-publish-state/v1"
PUBLISH_EVENT_SCHEMA = "qrh-publish-audit-event/v1"
PUBLISH_CANDIDATE_SCHEMA = "qrh-publish-candidate/v1"
FULL_SHA = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
TERMINAL = {"succeeded", "failed", "superseded"}


class PublishError(RuntimeError):
    """受控发布 fail-closed。"""


class PublishLocked(PublishError):
    """本地编排状态正在被另一个进程更新。"""


class PublishFailed(PublishError):
    def __init__(self, request_id: str, message: str):
        super().__init__(f"publish {request_id} failed: {message}")
        self.request_id = request_id


class PublishStepError(PublishError):
    """不携带 callback 消息的安全失败摘要。"""

    def __init__(self, step: str, cause_type: str):
        super().__init__(f"{step} failed ({cause_type})")
        self.step = step
        self.cause_type = cause_type


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _full_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or FULL_SHA.fullmatch(value) is None:
        raise PublishError(f"{label} must be a lowercase full 40-character commit SHA")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise PublishError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _stable_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}", value) is None
        or ".." in value
    ):
        raise PublishError(f"{label} is not a stable path-safe identifier")
    return value


@dataclass(frozen=True)
class PublishRequest:
    request_id: str
    commit_sha: str
    submitted_at: str
    deployment_mode: str = "activate"

    @classmethod
    def create(
        cls, commit_sha: str, *, deployment_mode: str = "activate"
    ) -> "PublishRequest":
        return cls(
            request_id=f"publish-{uuid.uuid4().hex}",
            commit_sha=_full_sha(commit_sha, "commit_sha"),
            submitted_at=_now(),
            deployment_mode=_deployment_mode(deployment_mode),
        )


@dataclass(frozen=True)
class GitSnapshot:
    commit_sha: str
    branch: str
    tracked_tree_sha256: str
    tracked_clean: bool


@dataclass(frozen=True)
class GateResult:
    gate_id: str
    commit_sha: str
    status: str


@dataclass(frozen=True)
class FrozenSources:
    freeze_id: str
    commit_sha: str
    inventory_sha256: str
    release_id: str
    release_manifest_sha256: str


@dataclass(frozen=True)
class PushResult:
    commit_sha: str
    status: str


@dataclass(frozen=True)
class CIResult:
    commit_sha: str
    status: str
    run_id: str


@dataclass(frozen=True)
class TransferResult:
    candidate_manifest_sha256: str
    status: str


@dataclass(frozen=True)
class VMDeployResult:
    candidate_manifest_sha256: str
    status: str
    evidence_id: str
    evidence_type: str


@dataclass(frozen=True)
class PublishResult:
    request_id: str
    commit_sha: str
    candidate_manifest_sha256: str
    ci_run_id: str
    deploy_evidence_id: str
    deployment_mode: str
    status: str


def _deployment_mode(value: object) -> str:
    if value not in {"activate", "candidate_only"}:
        raise PublishError("deployment_mode must be activate or candidate_only")
    return str(value)


InspectGit = Callable[[str], GitSnapshot]
RunGate = Callable[[GitSnapshot], GateResult]
FreezeSources = Callable[[GitSnapshot], FrozenSources]
PushOnce = Callable[[str], PushResult]
WaitExactCI = Callable[[str], CIResult]
TransportCandidate = Callable[[Mapping[str, object]], TransferResult]
DeployCandidate = Callable[[Mapping[str, object]], VMDeployResult]


@dataclass(frozen=True)
class PublishActions:
    inspect_git: InspectGit
    public_guard: RunGate
    local_test_gate: RunGate
    freeze_sources: FreezeSources
    push_once: PushOnce
    wait_exact_ci: WaitExactCI
    transport_candidate: TransportCandidate
    deploy_candidate: DeployCandidate


class PublishPipeline:
    """对一个 request 执行唯一固定顺序，并逐步复核 exact identity。"""

    def __init__(self, actions: PublishActions):
        self.actions = actions

    @staticmethod
    def _call(step: str, action, *arguments):
        try:
            return action(*arguments)
        except PublishError:
            raise
        except Exception as error:
            # provider 异常消息可能含 URL/header/凭据，不带入编排状态或审计。
            raise PublishStepError(step, type(error).__name__) from None

    @staticmethod
    def _candidate(value: object) -> Mapping[str, object]:
        if not isinstance(value, dict) or set(value) != {
            "schema_version", "request_id", "commit_sha", "tracked_tree_sha256",
            "source_freeze", "release", "local_gates", "deployment_mode",
            "candidate_manifest_sha256",
        }:
            raise PublishError("publish candidate schema is not closed")
        if value["schema_version"] != PUBLISH_CANDIDATE_SCHEMA:
            raise PublishError("unsupported publish candidate schema")
        claimed = _digest(value["candidate_manifest_sha256"], "candidate_manifest_sha256")
        material = dict(value)
        del material["candidate_manifest_sha256"]
        if _sha256(material) != claimed:
            raise PublishError("publish candidate identity changed after freeze")
        return value

    @staticmethod
    def _gate(result: GateResult, *, expected_sha: str, label: str) -> GateResult:
        _stable_id(result.gate_id, f"{label}.gate_id")
        if _full_sha(result.commit_sha, f"{label}.commit_sha") != expected_sha:
            raise PublishError(f"{label} result belongs to another commit")
        if result.status != "pass":
            raise PublishError(f"{label} did not pass")
        return result

    def execute(self, request: PublishRequest) -> PublishResult:
        expected_sha = _full_sha(request.commit_sha, "request.commit_sha")
        deployment_mode = _deployment_mode(request.deployment_mode)
        snapshot = self._call("inspect_git", self.actions.inspect_git, expected_sha)
        if _full_sha(snapshot.commit_sha, "git.commit_sha") != expected_sha:
            raise PublishError("tracked tree HEAD changed before publish")
        if snapshot.branch != "main":
            raise PublishError("publish is allowed only from main")
        _digest(snapshot.tracked_tree_sha256, "git.tracked_tree_sha256")
        if snapshot.tracked_clean is not True:
            raise PublishError("tracked tree is dirty")

        local_gate = self._gate(
            self._call("local_test_gate", self.actions.local_test_gate, snapshot),
            expected_sha=expected_sha,
            label="local_test_gate",
        )
        public_gate = self._gate(
            self._call("public_guard", self.actions.public_guard, snapshot),
            expected_sha=expected_sha,
            label="public_guard",
        )
        frozen = self._call("freeze_sources", self.actions.freeze_sources, snapshot)
        _stable_id(frozen.freeze_id, "freeze_id")
        if _full_sha(frozen.commit_sha, "freeze.commit_sha") != expected_sha:
            raise PublishError("frozen non-Git sources belong to another commit")
        _digest(frozen.inventory_sha256, "freeze.inventory_sha256")
        _stable_id(frozen.release_id, "freeze.release_id")
        _digest(frozen.release_manifest_sha256, "freeze.release_manifest_sha256")

        candidate: dict[str, object] = {
            "schema_version": PUBLISH_CANDIDATE_SCHEMA,
            "request_id": _stable_id(request.request_id, "request_id"),
            "commit_sha": expected_sha,
            "tracked_tree_sha256": snapshot.tracked_tree_sha256,
            "source_freeze": {
                "freeze_id": frozen.freeze_id,
                "inventory_sha256": frozen.inventory_sha256,
            },
            "release": {
                "release_id": frozen.release_id,
                "manifest_sha256": frozen.release_manifest_sha256,
            },
            "local_gates": {
                "public_guard": public_gate.gate_id,
                "tests": local_gate.gate_id,
            },
            "deployment_mode": deployment_mode,
        }
        candidate["candidate_manifest_sha256"] = _sha256(candidate)
        candidate_hash = str(candidate["candidate_manifest_sha256"])

        # gate/freeze 可能耗时；push 前再次证明 tracked tree 仍是同一 clean 快照。
        observed = self._call("inspect_git_recheck", self.actions.inspect_git, expected_sha)
        if observed != snapshot:
            raise PublishError("tracked tree changed after local gates or source freeze")

        # 核心只存在这一处 push 调用；失败不会在内部隐式重试第二次 push。
        pushed = self._call("push_once", self.actions.push_once, expected_sha)
        if pushed.status != "pushed" or pushed.commit_sha != expected_sha:
            raise PublishError("push did not confirm the exact commit")
        ci = self._call("wait_exact_ci", self.actions.wait_exact_ci, expected_sha)
        if ci.status != "success" or ci.commit_sha != expected_sha:
            raise PublishError("GitHub CI did not pass for the exact commit")
        _stable_id(ci.run_id, "ci.run_id")

        self._candidate(candidate)
        transferred = self._call(
            "transport_candidate", self.actions.transport_candidate, candidate
        )
        self._candidate(candidate)
        if (
            transferred.status != "verified"
            or transferred.candidate_manifest_sha256 != candidate_hash
        ):
            raise PublishError("candidate transport did not verify the exact manifest")
        deployed = self._call("deploy_candidate", self.actions.deploy_candidate, candidate)
        self._candidate(candidate)
        expected_deploy = (
            ("activated", "activation_receipt")
            if deployment_mode == "activate"
            else ("candidate_validated", "candidate_validation_event")
        )
        if deployed.candidate_manifest_sha256 != candidate_hash or (
            deployed.status,
            deployed.evidence_type,
        ) != expected_deploy:
            raise PublishError("VM deploy did not return the exact candidate identity")
        _stable_id(deployed.evidence_id, "deploy.evidence_id")
        return PublishResult(
            request_id=request.request_id,
            commit_sha=expected_sha,
            candidate_manifest_sha256=candidate_hash,
            ci_run_id=ci.run_id,
            deploy_evidence_id=deployed.evidence_id,
            deployment_mode=deployment_mode,
            status=deployed.status,
        )


class PublishQueue:
    """跨进程 latest-only 队列；state 仅是编排状态，不是 release authority。"""

    def __init__(self, state_root: Path):
        if not state_root.is_absolute():
            raise PublishError("publish state root must be absolute")
        # Construction is deliberately lexical and zero-mutation. Queue
        # materialisation belongs to the gated orchestration methods below.
        self.root = state_root
        self.events = self.root / "audit"
        self.state_path = self.root / "publish_state.json"
        self.lock_path = self.root / "publish_state.lock"

    def _materialize(self) -> None:
        ensure_no_reparse_components(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        ensure_no_reparse_components(self.root)
        self.root = self.root.resolve(strict=True)
        self.events = self.root / "audit"
        self.events.mkdir(exist_ok=True)
        self.state_path = self.root / "publish_state.json"
        self.lock_path = self.root / "publish_state.lock"

    def _initial(self) -> dict[str, object]:
        return {
            "schema_version": PUBLISH_STATE_SCHEMA,
            "authority": "orchestration_only",
            "running_request_id": None,
            "pending_request_id": None,
            "requests": {},
        }

    def _load(self) -> dict[str, object]:
        if not self.state_path.exists():
            return self._initial()
        try:
            value = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PublishError("publish orchestration state is unreadable") from error
        if (
            not isinstance(value, dict)
            or set(value) != {
                "schema_version", "authority", "running_request_id",
                "pending_request_id", "requests",
            }
            or value["schema_version"] != PUBLISH_STATE_SCHEMA
            or value["authority"] != "orchestration_only"
            or not isinstance(value["requests"], dict)
        ):
            raise PublishError("publish orchestration state schema is invalid")
        running = value["running_request_id"]
        pending = value["pending_request_id"]
        requests = value["requests"]
        assert isinstance(requests, dict)
        if running is not None and running not in requests:
            raise PublishError("running request does not resolve")
        if pending is not None and pending not in requests:
            raise PublishError("pending request does not resolve")
        if running is not None and requests[running].get("status") != "running":
            raise PublishError("running request status is inconsistent")
        if pending is not None and requests[pending].get("status") != "pending":
            raise PublishError("pending request status is inconsistent")
        for request_id, record in requests.items():
            if not isinstance(record, dict) or record.get("request_id") != request_id:
                raise PublishError("publish request record is invalid")
            _stable_id(request_id, "stored request_id")
            _full_sha(record.get("commit_sha"), "stored commit_sha")
            _deployment_mode(record.get("deployment_mode"))
            if record.get("status") not in TERMINAL | {"running", "pending"}:
                raise PublishError("publish request status is invalid")
        return value

    def _write(self, value: Mapping[str, object]) -> None:
        temporary = self.root / f".publish-state-{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as handle:
                handle.write(_canonical(value))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _event(self, kind: str, fields: Mapping[str, object]) -> None:
        event_id = f"{kind}-{uuid.uuid4().hex}"
        value = {
            "schema_version": PUBLISH_EVENT_SCHEMA,
            "event_id": event_id,
            "kind": kind,
            "recorded_at": _now(),
            "authority": "evidence_only",
            "fields": dict(fields),
        }
        with (self.events / f"{event_id}.json").open("xb") as handle:
            handle.write(_canonical(value))

    def _locked(self):
        queue = self

        class Lock:
            def __enter__(self):
                try:
                    descriptor = os.open(
                        queue.lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                    )
                except FileExistsError as error:
                    raise PublishLocked("publish state lock already exists") from error
                self.token = uuid.uuid4().hex
                with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                    handle.write(self.token)
                    handle.flush()
                    os.fsync(handle.fileno())
                return self

            def __exit__(self, *_):
                try:
                    if queue.lock_path.read_text(encoding="ascii") == self.token:
                        queue.lock_path.unlink()
                except OSError:
                    pass

        return Lock()

    @staticmethod
    def _record(request: PublishRequest, status: str) -> dict[str, object]:
        return {
            "request_id": _stable_id(request.request_id, "request_id"),
            "commit_sha": _full_sha(request.commit_sha, "commit_sha"),
            "submitted_at": request.submitted_at,
            "deployment_mode": _deployment_mode(request.deployment_mode),
            "status": status,
            "superseded_by": None,
            "error": None,
            "result": None,
        }

    def submit(self, request: PublishRequest) -> str:
        """提交 request；返回 ``running`` 或 ``pending``，绝不取消 running。"""

        self._materialize()
        with self._locked():
            state = self._load()
            requests = state["requests"]
            assert isinstance(requests, dict)
            if request.request_id in requests:
                raise PublishError("request_id already exists")
            running = state["running_request_id"]
            if running is None:
                status = "running"
                state["running_request_id"] = request.request_id
            else:
                status = "pending"
                previous = state["pending_request_id"]
                if previous is not None:
                    old = requests[str(previous)]
                    old["status"] = "superseded"
                    old["superseded_by"] = request.request_id
                    self._event(
                        "pending_superseded",
                        {
                            "request_id": previous,
                            "commit_sha": old["commit_sha"],
                            "superseded_by": request.request_id,
                            "superseding_commit_sha": request.commit_sha,
                        },
                    )
                state["pending_request_id"] = request.request_id
            requests[request.request_id] = self._record(request, status)
            self._write(state)
            self._event(
                "request_submitted",
                {"request_id": request.request_id, "commit_sha": request.commit_sha, "status": status},
            )
            return status

    def finish(self, request_id: str, result: PublishResult | Exception) -> str | None:
        """结束 running 并提升最新 pending；失败也不会丢弃新的 pending。"""

        self._materialize()
        with self._locked():
            state = self._load()
            if state["running_request_id"] != request_id:
                raise PublishError("only the running request may finish")
            requests = state["requests"]
            assert isinstance(requests, dict)
            record = requests[request_id]
            if isinstance(result, PublishResult):
                record["status"] = "succeeded"
                record["result"] = asdict(result)
                kind = "request_succeeded"
                event_fields = {
                    "request_id": request_id,
                    "candidate_manifest_sha256": result.candidate_manifest_sha256,
                }
            else:
                record["status"] = "failed"
                # 不写 traceback、凭据、header 或 callback repr，只保存错误类型。
                if isinstance(result, PublishStepError):
                    safe_error = f"{result.step}:{result.cause_type}"
                else:
                    safe_error = type(result).__name__
                record["error"] = safe_error
                kind = "request_failed"
                event_fields = {"request_id": request_id, "error_code": safe_error}
            pending = state["pending_request_id"]
            state["pending_request_id"] = None
            state["running_request_id"] = pending
            if pending is not None:
                requests[str(pending)]["status"] = "running"
            self._write(state)
            self._event(kind, event_fields)
            if pending is not None:
                self._event("pending_promoted", {"request_id": pending})
            return str(pending) if pending is not None else None

    def request(self, request_id: str) -> Mapping[str, object]:
        self._materialize()
        with self._locked():
            state = self._load()
            requests = state["requests"]
            assert isinstance(requests, dict)
            if request_id not in requests:
                raise PublishError("unknown request_id")
            return json.loads(json.dumps(requests[request_id]))

    def running_request(self) -> PublishRequest | None:
        self._materialize()
        with self._locked():
            state = self._load()
            request_id = state["running_request_id"]
            if request_id is None:
                return None
            record = state["requests"][request_id]
            return PublishRequest(
                request_id=str(record["request_id"]),
                commit_sha=str(record["commit_sha"]),
                submitted_at=str(record["submitted_at"]),
                deployment_mode=str(record["deployment_mode"]),
            )


class PublishCoordinator:
    def __init__(self, queue: PublishQueue, pipeline: PublishPipeline):
        self.queue = queue
        self.pipeline = pipeline

    def submit_and_drain(self, request: PublishRequest) -> Mapping[str, object]:
        disposition = self.queue.submit(request)
        if disposition == "pending":
            return self.queue.request(request.request_id)

        current: PublishRequest | None = request
        while current is not None:
            try:
                outcome: PublishResult | Exception = self.pipeline.execute(current)
            except Exception as error:  # 每个 terminal 都进入可审计状态，再继续 latest pending。
                outcome = error
            next_id = self.queue.finish(current.request_id, outcome)
            current = self.queue.running_request() if next_id is not None else None
        submitted = self.queue.request(request.request_id)
        if submitted["status"] == "failed":
            raise PublishFailed(request.request_id, str(submitted["error"]))
        return submitted


def inspect_local_git(project_root: Path, expected_sha: str) -> GitSnapshot:
    """cwd 无关的只读 Git 检查；不 fetch、不 pull、不修改 index。"""

    root = project_root.resolve(strict=True)

    def git(*args: str) -> str:
        completed = subprocess.run(
            ["git", "--no-optional-locks", *args], cwd=root, check=False, capture_output=True,
            text=True, encoding="utf-8", errors="replace",
        )
        if completed.returncode:
            raise PublishError(completed.stderr.strip() or "local Git inspection failed")
        return completed.stdout.strip()

    commit = _full_sha(git("rev-parse", "HEAD"), "git HEAD")
    if commit != _full_sha(expected_sha, "expected_sha"):
        raise PublishError("expected SHA is not local HEAD")
    branch = git("branch", "--show-current")
    dirty = git("status", "--porcelain=v1", "--untracked-files=no")
    tree = git("ls-tree", "-r", "--full-tree", commit)
    return GitSnapshot(
        commit_sha=commit,
        branch=branch,
        tracked_tree_sha256=hashlib.sha256(tree.encode("utf-8")).hexdigest(),
        tracked_clean=not bool(dirty),
    )


def dry_run_plan(
    project_root: Path,
    expected_sha: str | None = None,
    *,
    deployment_mode: str = "activate",
) -> Mapping[str, object]:
    """只读验证 CLI 拓扑；绝不调用 push、CI、transport 或 deploy。"""

    root = project_root.resolve(strict=True)
    if expected_sha is None:
        completed = subprocess.run(
            ["git", "--no-optional-locks", "rev-parse", "HEAD"], cwd=root, check=False,
            capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if completed.returncode:
            raise PublishError("project root is not a readable Git worktree")
        expected_sha = completed.stdout.strip()
    snapshot = inspect_local_git(root, expected_sha)
    if snapshot.tracked_clean is not True:
        raise PublishError("dry-run blocked: tracked tree is dirty")
    return {
        "schema_version": "qrh-publish-dry-run/v1",
        "status": "validated",
        "project_root": str(root),
        "commit_sha": snapshot.commit_sha,
        "tracked_clean": snapshot.tracked_clean,
        "deployment_mode": _deployment_mode(deployment_mode),
        "steps": [
            "local_test_gate", "public_guard", "freeze_non_git_sources",
            "push_once", "wait_exact_sha_ci", "incremental_candidate_transport",
            "vm_deploy_cli",
        ],
        "external_actions_executed": False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--commit-sha")
    parser.add_argument(
        "--config",
        type=Path,
        help="Git 外受保护 production runtime config；非 dry-run 必填",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--candidate-only",
        action="store_true",
        help="显式无生产切换候选演练；默认 publish 必须完成 activation",
    )
    args = parser.parse_args(argv)
    if args.dry_run:
        result = dry_run_plan(
            args.project_root,
            args.commit_sha,
            deployment_mode="candidate_only" if args.candidate_only else "activate",
        )
    else:
        if args.config is None:
            parser.error("non-dry-run publish requires --config outside the Git project")
        from .publish_runtime import ProductionPublishRuntime, RuntimePublishConfig

        config = RuntimePublishConfig.load(
            args.config, expected_project_root=args.project_root
        )
        commit_sha = args.commit_sha
        if commit_sha is None:
            completed = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=args.project_root.resolve(strict=True),
                shell=False,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if completed.returncode:
                raise PublishError("cannot resolve local exact commit")
            commit_sha = completed.stdout.strip()
        result = ProductionPublishRuntime(config).publish(
            commit_sha=commit_sha,
            candidate_only=args.candidate_only,
        )
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
