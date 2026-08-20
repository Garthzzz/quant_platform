"""启动本地 Quant Research Hub Web；正式模式只运行已独立审核的密封候选。"""

from __future__ import annotations

import sys

# 正式入口必须在解释器处理 PYTHONPATH/user-site 之前建立隔离边界。此检查
# 只依赖 builtin sys，严格早于 argparse/pathlib 乃至任何 quant_hub import。
if (
    __name__ == "__main__"
    and "--allow-development-runtime" not in sys.argv[1:]
    and not sys.flags.isolated
):
    raise RuntimeError("sealed runtime requires isolated Python (-I)")

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
from typing import Any


def _bootstrap_is_reparse(info: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & flag
    )


def _bootstrap_no_reparse(path: Path) -> None:
    current = path.absolute()
    chain: list[Path] = []
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if os.path.lexists(candidate) and _bootstrap_is_reparse(candidate.lstat()):
            raise RuntimeError(f"bootstrap path contains a reparse component: {candidate}")


def _bootstrap_file(path: Path) -> tuple[bytes, os.stat_result]:
    _bootstrap_no_reparse(path)
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or _bootstrap_is_reparse(before)
        or before.st_nlink != 1
    ):
        raise RuntimeError(f"unsafe bootstrap file: {path}")
    payload = path.read_bytes()
    after = path.lstat()
    identity = lambda value: (
        value.st_size,
        value.st_mtime_ns,
        value.st_dev,
        value.st_ino,
        value.st_nlink,
    )
    if identity(before) != identity(after) or len(payload) != after.st_size:
        raise RuntimeError(f"bootstrap file changed while being read: {path}")
    return payload, after


def _bootstrap_tree(root: Path) -> dict[str, object]:
    _bootstrap_no_reparse(root)
    root = root.resolve(strict=True)
    root_info = root.lstat()
    if not stat.S_ISDIR(root_info.st_mode) or _bootstrap_is_reparse(root_info):
        raise RuntimeError("bootstrap code root is not a real directory")
    records: list[tuple[str, int, str]] = []
    folded: dict[str, str] = {}

    def register_path(relative: Path) -> None:
        name = relative.as_posix()
        case_key = name.casefold()
        if case_key in folded and folded[case_key] != name:
            raise RuntimeError("bootstrap code contains a case-fold collision")
        folded[case_key] = name

    def visit(directory: Path) -> None:
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root)
            info = entry.stat(follow_symlinks=False)
            if entry.is_symlink() or _bootstrap_is_reparse(info):
                raise RuntimeError(f"bootstrap code contains a link: {path}")
            excluded = any(part == "__pycache__" for part in relative.parts) or (
                relative.suffix in {".pyc", ".pyo"}
            )
            if stat.S_ISDIR(info.st_mode):
                if not excluded:
                    register_path(relative)
                    visit(path)
                continue
            if excluded:
                continue
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError(f"bootstrap code contains an unsafe file: {path}")
            payload, stable = _bootstrap_file(path)
            name = relative.as_posix()
            register_path(relative)
            records.append((name, stable.st_size, hashlib.sha256(payload).hexdigest()))

    visit(root)
    digest = hashlib.sha256()
    total = 0
    for relative, size, file_hash in sorted(records):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\n")
        total += size
    return {"files": len(records), "bytes": total, "tree_sha256": digest.hexdigest()}


def _bootstrap_production_import() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--var-root", type=Path)
    parser.add_argument("--activation-seal", type=Path)
    parser.add_argument("--startup-gate", type=Path)
    parser.add_argument("--project-root", type=Path)
    parser.add_argument("--allow-development-runtime", action="store_true")
    early, _unknown = parser.parse_known_args()
    if early.allow_development_runtime:
        return
    if (
        early.var_root is None
        or early.activation_seal is None
        or early.startup_gate is None
    ):
        raise RuntimeError(
            "sealed runtime preflight requires var-root, activation-seal and startup-gate"
        )
    raw_script = Path(__file__).absolute()
    _bootstrap_no_reparse(raw_script)
    script = raw_script.resolve(strict=True)
    delivery = early.var_root.resolve(strict=True)
    expected_script = (
        delivery / "runtime_contract" / "code" / "tools" / "run_local.py"
    )
    _bootstrap_no_reparse(expected_script)
    if script != expected_script.resolve(strict=True):
        raise RuntimeError("sealed bootstrap launcher path is not exact")
    quant_hub_roots = [
        parent
        for parent in delivery.parents
        if parent.name.casefold() == "quant_hub"
        and delivery.is_relative_to(parent / "var")
    ]
    if len(quant_hub_roots) != 1:
        raise RuntimeError("cannot derive one project for sealed bootstrap")
    derived_project = quant_hub_roots[0].parent.resolve(strict=True)
    project = (
        early.project_root.resolve(strict=True)
        if early.project_root is not None
        else derived_project
    )
    if project != derived_project:
        raise RuntimeError("sealed bootstrap project-root is not canonical")
    gate_path = early.startup_gate.resolve(strict=True)
    _bootstrap_no_reparse(gate_path)
    if not gate_path.is_relative_to((project / "project_state").resolve(strict=True)):
        raise RuntimeError("sealed bootstrap startup gate escaped project_state")
    gate_payload, _gate_info = _bootstrap_file(gate_path)
    try:
        gate = json.loads(gate_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid startup gate JSON during bootstrap") from error
    if (
        not isinstance(gate, dict)
        or gate.get("schema_version") != "qrh-reviewed-startup-gate/v1"
        or gate.get("status") != "PASS"
        or gate.get("initial_launch_mode") != "strict"
        or Path(str(gate.get("delivery_var", ""))).resolve(strict=True) != delivery
    ):
        raise RuntimeError("startup gate is not an exact PASS binding")
    artifacts = gate.get("review_artifacts")
    if not isinstance(artifacts, list) or not any(
        isinstance(item, dict) and item.get("kind") == "activation_report"
        for item in artifacts
    ):
        raise RuntimeError("startup gate omits activation review evidence")
    audit_root = (project / "project_state").resolve(strict=True)
    for item in artifacts:
        if not isinstance(item, dict):
            raise RuntimeError("startup gate review artifact is invalid")
        artifact_path = Path(str(item.get("path", ""))).resolve(strict=True)
        _bootstrap_no_reparse(artifact_path)
        if not artifact_path.is_relative_to(audit_root):
            raise RuntimeError("startup review artifact escaped project_state")
        artifact_payload, _artifact_info = _bootstrap_file(artifact_path)
        if hashlib.sha256(artifact_payload).hexdigest() != item.get("sha256"):
            raise RuntimeError("startup review artifact hash changed")
    expected_activation = delivery / "ACTIVATED_DELIVERY_SEAL.json"
    _bootstrap_no_reparse(expected_activation)
    activation_path = early.activation_seal.resolve(strict=True)
    if activation_path != expected_activation.resolve(strict=True):
        raise RuntimeError("sealed bootstrap activation path is not exact")
    payload, _info = _bootstrap_file(activation_path)
    if hashlib.sha256(payload).hexdigest() != gate.get("activation_seal_sha256"):
        raise RuntimeError("activation bytes differ from startup gate")
    try:
        activation = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("invalid activation JSON during bootstrap") from error
    if (
        not isinstance(activation, dict)
        or activation.get("schema_version") != "qrh-activated-delivery-seal/v1"
        or activation.get("status") != "PASS"
        or Path(str(activation.get("delivery_var", ""))).resolve(strict=True)
        != delivery
    ):
        raise RuntimeError("activation is not an exact PASS delivery binding")
    runtime = activation.get("runtime_contract")
    if not isinstance(runtime, dict):
        raise RuntimeError("activation omits bootstrap runtime contract")
    code_root = delivery / "runtime_contract" / "code"
    if _bootstrap_tree(code_root) != runtime.get("code"):
        raise RuntimeError("bootstrap runtime code tree differs from activation")
    if any(name == "quant_hub" or name.startswith("quant_hub.") for name in sys.modules):
        raise RuntimeError("quant_hub was preloaded before sealed bootstrap validation")


if __name__ == "__main__":
    _bootstrap_production_import()


SCRIPT_PATH = Path(__file__).resolve()
CODE_ROOT = SCRIPT_PATH.parents[1]
BUNDLED_SOURCE_ROOT = CODE_ROOT / "src"
if BUNDLED_SOURCE_ROOT.is_dir():
    # 正式启动脚本位于 <delivery>/runtime_contract/code/tools；这一插入保证
    # import 的是候选内源码，而不是调用者的 PYTHONPATH 或可变工作树。
    bundled = BUNDLED_SOURCE_ROOT.resolve(strict=True)
    sys.path[:] = [
        item
        for item in sys.path
        if not item or Path(item).resolve(strict=False) != bundled
    ]
    sys.path.insert(0, str(bundled))
    specification = importlib.util.find_spec("quant_hub")
    expected_package = (bundled / "quant_hub").resolve(strict=True)
    locations = [] if specification is None else specification.submodule_search_locations
    if not locations or {
        Path(item).resolve(strict=True) for item in locations
    } != {expected_package}:
        raise RuntimeError("quant_hub import does not resolve to bundled runtime source")

from quant_hub.app import create_app
from quant_hub.config import Settings
from quant_hub.runtime_seal import (
    RuntimeSealError,
    assert_material,
    database_state,
    file_identity,
    read_json,
    require_no_sqlite_sidecars,
    runtime_toolchain,
    safe_tree,
)
from quant_hub.reviewed_runtime import (
    capture_runtime_state,
    load_bootstrap_receipt,
    publish_or_validate_strict_receipt,
    validate_resume_state,
    validate_startup_bootstrap_contract,
)


def _discover_project_root(script_path: Path) -> Path:
    """从工作树或冻结候选布局发现 workspace，不依赖易碎 parents 索引。"""

    script = script_path.resolve(strict=True)
    candidates: list[Path] = []
    for quant_hub_root in script.parents:
        if quant_hub_root.name.casefold() != "quant_hub":
            continue
        workspace = quant_hub_root.parent
        reference = workspace / "reference"
        is_worktree_tool = script.parent == quant_hub_root / "tools"
        is_frozen_tool = script.is_relative_to(quant_hub_root / "var")
        if (
            (is_worktree_tool or is_frozen_tool)
            and (reference / "archive").is_dir()
            and (reference / "proj2").is_dir()
        ):
            candidates.append(workspace.resolve(strict=True))
    unique = {str(path): path for path in candidates}
    if len(unique) != 1:
        raise RuntimeSealError(
            "cannot derive one workspace from the run_local script and reference roots"
        )
    return next(iter(unique.values()))


WORKTREE_ROOT = _discover_project_root(SCRIPT_PATH)
ACTIVATION_SCHEMA = "qrh-activated-delivery-seal/v1"
STARTUP_GATE_SCHEMA = "qrh-reviewed-startup-gate/v1"
DATABASE_NAMES = (
    "platform.sqlite3",
    "archive.sqlite3",
    "research_papers.sqlite3",
    "paper_lab.sqlite3",
)
MANAGED_TREE_NAMES = (
    "inbox", "objects", "paper_lab", "replay", "research_papers", "exports"
)
REQUIRED_STARTUP_REVIEW_KINDS = {
    "activation_report",
    "browser_acceptance",
    "full_regression",
    "deployment_verdict",
}


def _sha256(path: Path) -> str:
    return str(file_identity(path)["sha256"])


def _require_exact_path(actual: Path, expected: Path, *, label: str) -> Path:
    resolved = actual.resolve(strict=True)
    target = expected.resolve(strict=True)
    if resolved != target:
        raise RuntimeSealError(f"{label} must be exactly {target}")
    return resolved


def _review_artifacts(gate: dict[str, object], project: Path) -> None:
    artifacts = gate.get("review_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise RuntimeSealError("startup gate has no independent review artifacts")
    audit_root = (project / "project_state").resolve(strict=True)
    observed_kinds: set[str] = set()
    for item in artifacts:
        if not isinstance(item, dict):
            raise RuntimeSealError("startup review artifact entry is invalid")
        path = Path(str(item.get("path", ""))).resolve(strict=True)
        if not path.is_file() or not path.is_relative_to(audit_root):
            raise RuntimeSealError("startup review artifact is outside project_state")
        if _sha256(path) != item.get("sha256"):
            raise RuntimeSealError(f"startup review artifact changed: {path}")
        observed_kinds.add(str(item.get("kind", "")))
    missing = REQUIRED_STARTUP_REVIEW_KINDS - observed_kinds
    if missing:
        raise RuntimeSealError(
            "startup gate is missing review kinds: " + ", ".join(sorted(missing))
        )


def _validate_sealed_runtime(
    *,
    project: Path,
    delivery: Path,
    migration_root: Path,
    activation_path: Path,
    startup_gate_path: Path,
    resume: bool,
) -> tuple[dict[str, object], dict[str, object]]:
    expected_code_root = delivery / "runtime_contract" / "code"
    expected_script = expected_code_root / "tools" / "run_local.py"
    _require_exact_path(SCRIPT_PATH, expected_script, label="sealed run_local")
    expected_migrations = delivery / "runtime_contract" / "migrations" / "platform"
    _require_exact_path(migration_root, expected_migrations, label="migration-root")
    _require_exact_path(
        activation_path,
        delivery / "ACTIVATED_DELIVERY_SEAL.json",
        label="activation-seal",
    )

    audit_root = (project / "project_state").resolve(strict=True)
    startup_gate = startup_gate_path.resolve(strict=True)
    if not startup_gate.is_file() or not startup_gate.is_relative_to(audit_root):
        raise RuntimeSealError("startup-gate must be a file under project_state")
    gate = read_json(startup_gate, schema_version=STARTUP_GATE_SCHEMA)
    if gate.get("status") != "PASS":
        raise RuntimeSealError("startup gate is not PASS")
    if Path(str(gate.get("delivery_var", ""))).resolve(strict=True) != delivery:
        raise RuntimeSealError("startup gate is bound to a different delivery")
    receipt_path = validate_startup_bootstrap_contract(
        gate,
        project=project,
        delivery=delivery,
    )

    activation = read_json(activation_path, schema_version=ACTIVATION_SCHEMA)
    if activation.get("status") != "PASS":
        raise RuntimeSealError("activation seal is not PASS")
    if Path(str(activation.get("delivery_var", ""))).resolve(strict=True) != delivery:
        raise RuntimeSealError("activation seal is bound to a different delivery")
    if _sha256(activation_path) != gate.get("activation_seal_sha256"):
        raise RuntimeSealError("activation seal hash differs from startup gate")
    _review_artifacts(gate, project)

    runtime_contract = activation.get("runtime_contract")
    if not isinstance(runtime_contract, dict):
        raise RuntimeSealError("activation seal has no runtime contract")
    actual_code = safe_tree(expected_code_root, exclude_runtime_caches=True)
    actual_migrations = safe_tree(expected_migrations.parent)
    assert_material(actual_code, runtime_contract.get("code"), label="runtime code")
    assert_material(
        actual_migrations,
        runtime_contract.get("migrations"),
        label="runtime migrations",
    )
    assert_material(
        runtime_toolchain(),
        runtime_contract.get("toolchain"),
        label="runtime toolchain",
    )

    expected_databases = activation.get("databases")
    if not isinstance(expected_databases, dict):
        raise RuntimeSealError("activation seal has no database contract")
    database_paths = [delivery / "db" / name for name in DATABASE_NAMES]
    require_no_sqlite_sidecars(database_paths)
    for name in DATABASE_NAMES:
        actual = database_state(delivery / "db" / name)
        expected = expected_databases.get(name)
        if not isinstance(expected, dict):
            raise RuntimeSealError(f"activation seal omits database: {name}")
        if resume:
            immutable_fields = (
                "integrity",
                "foreign_key_violations",
                "migration_versions",
                "schema_sha256",
            )
            assert_material(
                {field: actual.get(field) for field in immutable_fields},
                {field: expected.get(field) for field in immutable_fields},
                label=f"database schema {name}",
            )
        else:
            assert_material(actual, expected, label=f"database bytes {name}")

    expected_trees = activation.get("managed_trees")
    if not isinstance(expected_trees, dict):
        raise RuntimeSealError("activation seal has no managed-tree contract")
    if not resume:
        for name in MANAGED_TREE_NAMES:
            assert_material(
                safe_tree(delivery / name),
                expected_trees.get(name),
                label=f"managed tree {name}",
            )

    source_integrity = activation.get("source_integrity")
    if not isinstance(source_integrity, dict):
        raise RuntimeSealError("activation seal has no source-integrity contract")
    assert_material(
        safe_tree(project / "reference" / "archive"),
        source_integrity.get("archive"),
        label="reference/archive",
    )
    assert_material(
        safe_tree(project / "reference" / "proj2"),
        source_integrity.get("proj2"),
        label="reference/proj2",
    )
    if resume:
        receipt = load_bootstrap_receipt(
            receipt_path=receipt_path,
            project=project,
            delivery=delivery,
            activation_path=activation_path.resolve(strict=True),
            startup_gate_path=startup_gate,
        )
        validate_resume_state(
            receipt=receipt,
            project=project,
            delivery=delivery,
            code_root=expected_code_root,
            migrations_root=expected_migrations.parent,
            launcher_path=SCRIPT_PATH,
        )
    elif receipt_path.exists():
        # 重复 strict 只接受由同一 gate/activation 产生、且仍与 exact
        # activation state 一致的历史 receipt；永不静默重写。
        receipt = load_bootstrap_receipt(
            receipt_path=receipt_path,
            project=project,
            delivery=delivery,
            activation_path=activation_path.resolve(strict=True),
            startup_gate_path=startup_gate,
        )
        current = capture_runtime_state(
            project=project,
            delivery=delivery,
            code_root=expected_code_root,
            migrations_root=expected_migrations.parent,
            launcher_path=SCRIPT_PATH,
        )
        assert_material(
            current,
            receipt.get("runtime_state_after_create_app"),
            label="repeated strict bootstrap baseline",
        )
    return activation, gate


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=WORKTREE_ROOT)
    parser.add_argument("--archive-root", type=Path)
    parser.add_argument("--var-root", type=Path)
    parser.add_argument("--migration-root", type=Path)
    parser.add_argument("--activation-seal", type=Path)
    parser.add_argument("--startup-gate", type=Path)
    parser.add_argument(
        "--resume-reviewed-runtime",
        action="store_true",
        help="仅在首启后恢复同一审核运行根；仍严格校验代码、migration、schema 与来源。",
    )
    parser.add_argument(
        "--allow-development-runtime",
        action="store_true",
        help="显式开发模式；允许工作树代码/migration，禁止用于正式交付。",
    )
    parser.add_argument("--host", default="localhost", choices=("127.0.0.1", "localhost"))
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not 1 <= args.port <= 65_535:
        parser.error("port must be between 1 and 65535")

    project = args.project_root.resolve(strict=True)
    archive = (args.archive_root or project / "reference" / "archive").resolve(
        strict=True
    )
    if args.var_root is None:
        parser.error("--var-root is required")
    delivery = args.var_root.resolve(strict=True)

    if not args.allow_development_runtime:
        expected_archive = (project / "reference" / "archive").resolve(strict=True)
        if archive != expected_archive:
            parser.error("sealed runtime requires canonical reference/archive")

    if args.allow_development_runtime:
        if args.activation_seal or args.startup_gate or args.resume_reviewed_runtime:
            parser.error("development runtime cannot consume production seal options")
        settings = Settings.default(
            project_root=project,
            archive_root=archive,
            var_root=delivery,
            migration_root=args.migration_root,
        )
    else:
        if args.migration_root is None:
            parser.error("sealed runtime requires --migration-root")
        if args.activation_seal is None or args.startup_gate is None:
            parser.error("sealed runtime requires --activation-seal and --startup-gate")
        _validate_sealed_runtime(
            project=project,
            delivery=delivery,
            migration_root=args.migration_root,
            activation_path=args.activation_seal,
            startup_gate_path=args.startup_gate,
            resume=args.resume_reviewed_runtime,
        )
        settings = Settings.default(
            project_root=project,
            archive_root=archive,
            var_root=delivery,
            migration_root=args.migration_root,
        )
        settings.validate_reviewed_runtime()

    strict_before: dict[str, object] | None = None
    receipt_path: Path | None = None
    receipt_existed = False
    if not args.allow_development_runtime:
        gate = read_json(
            args.startup_gate.resolve(strict=True),
            schema_version=STARTUP_GATE_SCHEMA,
        )
        receipt_path = validate_startup_bootstrap_contract(
            gate,
            project=project,
            delivery=delivery,
        )
        receipt_existed = receipt_path.exists()
        if not args.resume_reviewed_runtime:
            strict_before = capture_runtime_state(
                project=project,
                delivery=delivery,
                code_root=CODE_ROOT,
                migrations_root=args.migration_root.resolve(strict=True).parent,
                launcher_path=SCRIPT_PATH,
            )

    if not args.allow_development_runtime:
        # All four sealed delivery databases are immutable publication inputs.
        # Mutable comments and research-workspace state live outside this root.
        os.environ["QUANT_HUB_READ_ONLY_DATABASE_ROOT"] = str(
            (delivery / "db").resolve(strict=True)
        )
    origin = f"http://{args.host}:{args.port}"
    app = create_app(
        settings,
        {
            "TRUSTED_ORIGINS": (origin,),
            "SESSION_COOKIE_SECURE": False,
            # The delivery databases are already migrated and hash-sealed.
            # Re-running Archive migrations would create WAL/SHM sidecars and
            # violate the strict immutable-runtime contract.
            "INITIALIZE_ARCHIVE_CATALOG": False,
            "COMMENT_DATABASE_PATH": str(
                project / "quant_hub" / "data" / "comments.sqlite3"
            ),
            "RESEARCH_WORKSPACE_DATABASE_PATH": str(
                project / "quant_hub" / "data" / "research_workspace.sqlite3"
            ),
        },
    )
    if not args.allow_development_runtime:
        assert receipt_path is not None
        if args.resume_reviewed_runtime:
            receipt = load_bootstrap_receipt(
                receipt_path=receipt_path,
                project=project,
                delivery=delivery,
                activation_path=args.activation_seal.resolve(strict=True),
                startup_gate_path=args.startup_gate.resolve(strict=True),
            )
            # create_app 后重跑与启动前完全相同的行级、逐文件及 ingress 闭包。
            validate_resume_state(
                receipt=receipt,
                project=project,
                delivery=delivery,
                code_root=CODE_ROOT,
                migrations_root=args.migration_root.resolve(strict=True).parent,
                launcher_path=SCRIPT_PATH,
            )
        else:
            assert strict_before is not None
            strict_after = capture_runtime_state(
                project=project,
                delivery=delivery,
                code_root=CODE_ROOT,
                migrations_root=args.migration_root.resolve(strict=True).parent,
                launcher_path=SCRIPT_PATH,
            )
            # receipt 只会在 create_app 后 exact 复核成功时独占发布。
            publish_or_validate_strict_receipt(
                receipt_path=receipt_path,
                project=project,
                delivery=delivery,
                activation_path=args.activation_seal.resolve(strict=True),
                startup_gate_path=args.startup_gate.resolve(strict=True),
                before=strict_before,
                after=strict_after,
                existed_before_launch=receipt_existed,
            )
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
