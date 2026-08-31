"""Exact-D Stage 5 revocation-surface producer.

This module inventories the fixed local product surfaces itself.  The report is
functional closure evidence for the local deployment; it is deliberately not
an independent or external MCP trust root.
"""

from __future__ import annotations

import argparse
import ast
import base64
import configparser
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import ntpath
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
import stat
import subprocess
import sys
import tomllib
from typing import Mapping, Sequence
import unicodedata

from .local_product_surface import (
    CANCELLED_MODULE_SURFACES,
    LocalProductSurfaceReport,
    scan_local_product_surface,
)
from .local_release_identity import canonical_bytes


REPORT_SCHEMA = "qrh-stage5-revocation-machine-audit-receipt/v1"
GATE_ROLE = "revocation_surface"
AUTHORITY_SCOPE = "LOCAL_FUNCTIONAL_CLOSURE_NOT_EXTERNAL_TRUST_ROOT"
PRODUCER_NAME = "qrh-stage5-revocation-surface-producer"
PRODUCER_VERSION = "1"
_TEST_REPORT_SCHEMA = "qrh-stage5-revocation-test-fixture/v1"
_TEST_AUTHORITY_SCOPE = "NON_QUALIFYING_TEST_FIXTURE"
_TEST_PRODUCER_NAME = "qrh-stage5-revocation-test-fixture-producer"
EXACT_PROJECT_ROOT = r"D:\quant\quant_platform"
DEFAULT_OUTPUT_RELATIVE_PATH = (
    "audit/release-closure/results/stage5/revocation-surface.json"
)

SURFACE_IDS = (
    "source",
    "fresh-wheel",
    "cli",
    "config",
    "schema",
    "windows-tasks",
    "runbook",
    "vm-write-set",
)
FINDING_CATEGORIES = (
    "periodic_state_copy_task",
    "outside_d_project_storage",
    "legacy_protection_export",
)

_REPORT_FIELDS = {
    "schema_version",
    "report_id",
    "gate_role",
    "authority_scope",
    "producer",
    "produced_at",
    "exact_project_root",
    "scans",
    "result",
    "report_sha256",
}
_SCAN_FIELDS = {"id", "outcome", "findings"}
_FINDING_FIELDS = {"category", "location"}
_RESULT_FIELDS = {
    "surface_checks_total",
    "surface_checks_passed",
    "periodic_state_copy_tasks",
    "outside_d_project_storage",
    "legacy_protection_exports",
}
_TASK_FIELDS = {"name", "actions", "triggers"}
_ACTION_FIELDS = {
    "kind",
    "execute",
    "arguments",
    "working_directory",
    "class_id",
    "data",
}
_TRIGGER_FIELDS = {"kind", "repetition_interval", "repetition_duration"}
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_WINDOWS_PATH_RE = re.compile(r"(?i)[a-z]:\\[^\s\"'<>|]+")
_QUOTED_WINDOWS_PATH_RE = re.compile(r"(?i)[\"']([a-z]:\\[^\"'<>|]+)[\"']")
_UNC_PATH_RE = re.compile(r"\\\\[^\\\s\"'<>|]+\\[^\s\"'<>|]+")
_SLASH_DRIVE_PATH_RE = re.compile(
    r"(?i)(?<![A-Za-z0-9])(?:file:///)?[a-z]:/[^\s\"'<>|]+"
)
_SLASH_UNC_PATH_RE = re.compile(
    r"(?<![:/A-Za-z0-9])//[^/\s\"'<>|]+/[^\s\"'<>|]+"
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ACRONYM_BOUNDARY_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_REPARSE_ATTRIBUTE = 0x400
_WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}
_EXPECTED_WRITE_AREAS = (
    "audit",
    "checkout",
    "control",
    "incoming",
    "locks",
    "logs",
    "releases",
    "state",
    "tmp",
    "tooling",
)
_LEGACY_READ_ONLY_SOURCES = (
    r"C:\quant_platform_data\comments.sqlite3",
    r"C:\quant_platform_data\research_workspace.sqlite3",
)
_EXPECTED_WRITE_CONTRACT = {
    "root_must_preexist": True,
    "reparse_points_forbidden": True,
    "python_bytecode_disabled": True,
    "temp_and_tmp_inside_root": True,
    "writes_outside_areas_forbidden": True,
    "os_managed_non_file_state": {
        "type": "windows_scm_service_registration",
        "service_name": "QuantResearchHub",
        "image_path": "exact_hash_verified_D_root_candidate_only",
        "python_class": (
            "quant_hub.ops.windows_service.QuantResearchHubWindowsService"
        ),
        "project_content_secret_temp_log_cache_on_C_forbidden": True,
    },
}


class RevocationSurfaceError(RuntimeError):
    """The live fixed surface or the canonical report failed closed."""


@dataclass(frozen=True, slots=True)
class _AuditInputs:
    root: Path
    source_root: Path
    wheel_root: Path
    wheel_runtime_findings: tuple[Mapping[str, str], ...]
    console_entrypoints: tuple[Mapping[str, str], ...]
    config_paths: tuple[Path, ...]
    schema_paths: tuple[Path, ...]
    runbook_paths: tuple[Path, ...]
    windows_tasks: tuple[Mapping[str, object], ...]
    write_set_path: Path


def _is_reparse(info: os.stat_result) -> bool:
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE)


def _ordinary_path(path: Path, *, kind: str) -> None:
    try:
        info = os.lstat(path)
    except OSError as error:
        raise RevocationSurfaceError(f"required {kind} is unavailable: {path}") from error
    if _is_reparse(info) or path.is_symlink():
        raise RevocationSurfaceError(f"{kind} contains a reparse path: {path}")
    if kind == "directory" and not stat.S_ISDIR(info.st_mode):
        raise RevocationSurfaceError(f"required directory is not ordinary: {path}")
    if kind == "file" and (
        not stat.S_ISREG(info.st_mode) or getattr(info, "st_nlink", 1) != 1
    ):
        raise RevocationSurfaceError(f"required file is not ordinary single-link: {path}")


def _ordinary_os_executable(path: Path) -> None:
    """Guard a fixed Windows-serviced executable without rejecting WinSxS hardlinks."""

    try:
        info = os.lstat(path)
    except OSError as error:
        raise RevocationSurfaceError(
            f"required operating-system executable is unavailable: {path}"
        ) from error
    if _is_reparse(info) or path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise RevocationSurfaceError(
            f"operating-system executable is not a regular non-reparse file: {path}"
        )


def _ordinary_chain(root: Path, path: Path, *, kind: str) -> None:
    _ordinary_path(root, kind="directory")
    try:
        relative = path.relative_to(root)
    except ValueError as error:
        raise RevocationSurfaceError("fixed scan path escaped the project root") from error
    current = root
    for index, part in enumerate(relative.parts):
        current = current / part
        _ordinary_path(current, kind=kind if index == len(relative.parts) - 1 else "directory")


def _regular_files(root: Path, *, suffixes: tuple[str, ...] | None = None) -> tuple[Path, ...]:
    _ordinary_path(root, kind="directory")
    result: list[Path] = []
    for current_text, directories, filenames in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_text)
        _ordinary_path(current, kind="directory")
        directories[:] = sorted(directories)
        for name in directories:
            _ordinary_path(current / name, kind="directory")
        for name in sorted(filenames):
            path = current / name
            _ordinary_path(path, kind="file")
            if suffixes is None or path.name.casefold().endswith(suffixes):
                result.append(path)
    return tuple(sorted(result, key=lambda value: value.relative_to(root).as_posix()))


def _source_records(root: Path) -> list[Mapping[str, str]]:
    records: list[Mapping[str, str]] = []
    for path in _regular_files(root, suffixes=(".py",)):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise RevocationSurfaceError(f"Python source is not strict UTF-8: {path}") from error
        records.append({"path": path.relative_to(root).as_posix(), "source": source})
    if not records:
        raise RevocationSurfaceError(f"controlled Python surface is empty: {root}")
    return records


def _assigned_names(target: ast.expr) -> tuple[str, ...]:
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, (ast.Tuple, ast.List)):
        return tuple(
            name for item in target.elts for name in _assigned_names(item)
        )
    return ()


def _dynamic_module_export_names(
    node: ast.AST, bindings: Mapping[str, set[str]]
) -> set[str]:
    if isinstance(node, ast.Subscript):
        owner = node.value
        if (
            isinstance(owner, ast.Call)
            and isinstance(owner.func, ast.Name)
            and owner.func.id in {"globals", "locals", "vars"}
            and not owner.args
            and not owner.keywords
        ):
            return _literal_string_values(node.slice, bindings)
    if isinstance(node, ast.Call):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "setattr"
            and len(node.args) >= 2
        ):
            return _literal_string_values(node.args[1], bindings)
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "update"
            and isinstance(node.func.value, ast.Call)
            and isinstance(node.func.value.func, ast.Name)
            and node.func.value.func.id in {"globals", "locals", "vars"}
        ):
            values = (
                _literal_string_values(node.args[0], bindings)
                if node.args
                else set()
            )
            values.update(
                keyword.arg
                for keyword in node.keywords
                if keyword.arg is not None
            )
            return values
    return set()


def _module_scope_store_names(
    tree: ast.Module, bindings: Mapping[str, set[str]]
) -> set[str]:
    names: set[str] = set()

    class Visitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            names.add(node.name)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            names.add(node.name)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            names.add(node.name)

        def visit_Lambda(self, node: ast.Lambda) -> None:
            del node

        def visit_Import(self, node: ast.Import) -> None:
            names.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            names.update(alias.asname or alias.name for alias in node.names)

        def visit_Name(self, node: ast.Name) -> None:
            if isinstance(node.ctx, ast.Store):
                names.add(node.id)

        def visit_Subscript(self, node: ast.Subscript) -> None:
            names.update(_dynamic_module_export_names(node, bindings))
            self.generic_visit(node)

        def visit_Call(self, node: ast.Call) -> None:
            names.update(_dynamic_module_export_names(node, bindings))
            self.generic_visit(node)

        def _visit_comprehension(
            self,
            element: ast.expr,
            generators: Sequence[ast.comprehension],
        ) -> None:
            # Python 3 comprehension targets have their own scope.  Their
            # iterable, conditions and result expressions still execute in the
            # surrounding module and therefore remain observable here.
            for generator in generators:
                self.visit(generator.iter)
                for condition in generator.ifs:
                    self.visit(condition)
            self.visit(element)

        def visit_ListComp(self, node: ast.ListComp) -> None:
            self._visit_comprehension(node.elt, node.generators)

        def visit_SetComp(self, node: ast.SetComp) -> None:
            self._visit_comprehension(node.elt, node.generators)

        def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
            self._visit_comprehension(node.elt, node.generators)

        def visit_DictComp(self, node: ast.DictComp) -> None:
            self._visit_comprehension(node.key, node.generators)
            self.visit(node.value)

    visitor = Visitor()
    for statement in tree.body:
        visitor.visit(statement)
    return names


def _expression_external_paths(
    value: ast.expr, bindings: Mapping[str, set[str]]
) -> set[str]:
    paths: set[str] = set()
    for text in _literal_string_values(value, bindings):
        paths.update(_outside_project_paths(text))
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in {"Path", "PureWindowsPath"}
        and value.args
    ):
        paths.update(_expression_external_paths(value.args[0], bindings))
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
        paths.update(_expression_external_paths(value.left, bindings))
        paths.update(_expression_external_paths(value.right, bindings))
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
        if value.func.attr in {"joinpath", "with_name", "with_suffix"}:
            paths.update(_expression_external_paths(value.func.value, bindings))
    return paths


def _static_file_mode(
    node: ast.Call,
    *,
    positional_index: int,
    default: str = "r",
) -> str | None:
    mode_node: ast.expr | None = None
    if len(node.args) > positional_index:
        mode_node = node.args[positional_index]
    for keyword in node.keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        return default
    if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
        return mode_node.value
    return None


def _call_identity(function: ast.expr) -> str:
    parts: list[str] = []
    cursor = function
    while isinstance(cursor, ast.Attribute):
        parts.append(cursor.attr)
        cursor = cursor.value
    if isinstance(cursor, ast.Name):
        parts.append(cursor.id)
    return ".".join(reversed(parts))


def _known_write_targets(node: ast.Call) -> tuple[list[ast.expr], str]:
    targets: list[ast.expr] = []
    identity = _call_identity(node.func)
    if isinstance(node.func, ast.Name) and node.func.id == "open" and node.args:
        mode = _static_file_mode(node, positional_index=1)
        if mode is None or any(flag in mode for flag in "wax+"):
            return [node.args[0]], "open-write"
        return [], ""
    if not isinstance(node.func, ast.Attribute):
        return [], ""
    attribute = node.func.attr
    owner = node.func.value
    if identity in {"os.replace", "os.rename"}:
        if len(node.args) >= 2:
            return [node.args[1]], identity.replace(".", "-")
        return [], ""
    if identity in {
        "os.mkdir",
        "os.makedirs",
        "os.remove",
        "os.removedirs",
        "os.rmdir",
        "os.unlink",
    }:
        if node.args:
            return [node.args[0]], identity.replace(".", "-")
        return [], ""
    if attribute == "open":
        mode = _static_file_mode(node, positional_index=0)
        if mode is None or any(flag in mode for flag in "wax+"):
            return [owner], "path-open-write"
        return [], ""
    if attribute in {"write_bytes", "write_text", "touch", "mkdir", "unlink", "rmdir"}:
        return [owner], f"path-{attribute}"
    if attribute in {"copy", "copy2", "copyfile", "copytree", "move"}:
        if len(node.args) >= 2:
            return [node.args[1]], f"copy-{attribute}"
        return [], ""
    if attribute == "connect" and node.args:
        return [node.args[0]], "database-connect"
    if attribute in {"replace", "rename"} and node.args:
        return [node.args[0]], f"path-{attribute}"
    return targets, ""


def _function_parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    return tuple(
        argument.arg
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
    )


def _call_argument_for_parameter(
    node: ast.Call,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    parameter: str,
) -> ast.expr | None:
    positional = (*function.args.posonlyargs, *function.args.args)
    for index, argument in enumerate(positional):
        if argument.arg == parameter and len(node.args) > index:
            return node.args[index]
    for keyword in node.keywords:
        if keyword.arg == parameter:
            return keyword.value
    return None


def _source_write_sink_findings(
    surface: str,
    path: str,
    tree: ast.Module,
    bindings: Mapping[str, set[str]],
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    writer_parameters: dict[str, set[str]] = {name: set() for name in functions}
    changed = True
    while changed:
        changed = False
        for name, function in functions.items():
            parameters = set(_function_parameters(function))
            discovered = set(writer_parameters[name])
            for call in (item for item in ast.walk(function) if isinstance(item, ast.Call)):
                targets, _ = _known_write_targets(call)
                callee = functions.get(_call_identity(call.func))
                if callee is not None:
                    for parameter in writer_parameters[callee.name]:
                        argument = _call_argument_for_parameter(call, callee, parameter)
                        if argument is not None:
                            targets.append(argument)
                for target in targets:
                    discovered.update(
                        item.id
                        for item in ast.walk(target)
                        if isinstance(item, ast.Name) and item.id in parameters
                    )
            if discovered != writer_parameters[name]:
                writer_parameters[name] = discovered
                changed = True
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        identity = _call_identity(node.func)
        targets, label = _known_write_targets(node)
        local_writer = functions.get(identity)
        if local_writer is not None:
            for parameter in writer_parameters[local_writer.name]:
                argument = _call_argument_for_parameter(node, local_writer, parameter)
                if argument is not None:
                    targets.append(argument)
            if writer_parameters[local_writer.name]:
                label = f"local-writer-{identity}"
        for target in targets:
            for external in _expression_external_paths(target, bindings):
                findings.append(
                    {
                        "category": "outside_d_project_storage",
                        "location": (
                            f"{surface}:{path}:write-sink:{label}:{external}"
                        )[:1024],
                    }
                )
    return findings


def _literal_string_values(
    value: ast.expr, bindings: Mapping[str, set[str]]
) -> set[str]:
    if isinstance(value, ast.Constant) and isinstance(value.value, str):
        return {value.value}
    if isinstance(value, ast.Name):
        return set(bindings.get(value.id, set()))
    if isinstance(value, ast.Starred):
        return _literal_string_values(value.value, bindings)
    if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
        return {
            name
            for item in value.elts
            for name in _literal_string_values(item, bindings)
        }
    if isinstance(value, ast.Dict):
        return {
            name
            for item in (*value.keys, *value.values)
            if item is not None
            for name in _literal_string_values(item, bindings)
        }
    if isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
        left = _literal_string_values(value.left, bindings)
        right = _literal_string_values(value.right, bindings)
        return {left_value + right_value for left_value in left for right_value in right}
    if isinstance(value, ast.JoinedStr):
        rendered = {""}
        for item in value.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                values = {item.value}
            elif isinstance(item, ast.FormattedValue) and item.conversion in {-1, 115}:
                values = _literal_string_values(item.value, bindings)
            else:
                return set()
            rendered = {prefix + suffix for prefix in rendered for suffix in values}
        return rendered
    if (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Attribute)
        and value.func.attr == "join"
        and isinstance(value.func.value, ast.Constant)
        and isinstance(value.func.value.value, str)
        and len(value.args) == 1
        and isinstance(value.args[0], (ast.Tuple, ast.List))
    ):
        parts: list[str] = []
        for item in value.args[0].elts:
            values = _literal_string_values(item, bindings)
            if len(values) != 1:
                return set()
            parts.append(next(iter(values)))
        return {value.func.value.value.join(parts)}
    return set()


def _source_symbol_findings(
    surface: str, records: Sequence[Mapping[str, str]]
) -> list[dict[str, str]]:
    """Find cancelled module-level exports, including aliases and ``__all__``."""

    findings: list[dict[str, str]] = []
    for record in records:
        path = str(record["path"])
        try:
            tree = ast.parse(str(record["source"]), filename=path)
        except SyntaxError as error:
            raise RevocationSurfaceError(
                f"Python source cannot be parsed for public-symbol closure: {path}"
            ) from error
        names: set[str] = set()
        bindings: dict[str, set[str]] = {}
        special_export_functions: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in {
                    "__getattr__",
                    "__dir__",
                }:
                    special_export_functions.append(node)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                for alias in node.names:
                    names.add(alias.asname or alias.name.rsplit(".", 1)[-1])
            elif isinstance(node, ast.Assign):
                assigned = {
                    name for target in node.targets for name in _assigned_names(target)
                }
                names.update(assigned)
                for target in node.targets:
                    names.update(_dynamic_module_export_names(target, bindings))
                values = _literal_string_values(node.value, bindings)
                for assigned_name in assigned:
                    bindings[assigned_name] = set(values)
                if "__all__" in assigned:
                    names.update(values)
            elif isinstance(node, ast.AnnAssign):
                assigned = set(_assigned_names(node.target))
                names.update(assigned)
                if node.value is not None:
                    values = _literal_string_values(node.value, bindings)
                    for assigned_name in assigned:
                        bindings[assigned_name] = set(values)
                    if "__all__" in assigned:
                        names.update(values)
            elif isinstance(node, ast.Expr):
                names.update(_dynamic_module_export_names(node.value, bindings))
        for function in special_export_functions:
            for node in ast.walk(function):
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    names.add(node.value)
                elif isinstance(node, ast.Name):
                    names.update(bindings.get(node.id, set()))
                elif isinstance(node, (ast.BinOp, ast.Call)):
                    names.update(_literal_string_values(node, bindings))
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                values = _literal_string_values(node.value, bindings)
                for target in node.targets:
                    for assigned_name in _assigned_names(target):
                        bindings.setdefault(assigned_name, set()).update(values)
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                values = _literal_string_values(node.value, bindings)
                for assigned_name in _assigned_names(node.target):
                    bindings.setdefault(assigned_name, set()).update(values)
        names.update(_module_scope_store_names(tree, bindings))
        findings.extend(_source_write_sink_findings(surface, path, tree, bindings))
        for binding_name, values in bindings.items():
            if not _protection_authority_reference(binding_name):
                continue
            for value in values:
                for external in _outside_project_paths(value):
                    findings.append(
                        {
                            "category": "outside_d_project_storage",
                            "location": (
                                f"{surface}:{path}:binding:{binding_name}:{external}"
                            )[:1024],
                        }
                    )
        for name in sorted(names, key=str.casefold):
            if not name.startswith("_") and _contains_legacy_identity(name):
                findings.append(
                    {
                        "category": "legacy_protection_export",
                        "location": f"{surface}:{path}:public-symbol:{name}"[:1024],
                    }
                )
    return findings


def _bytecode_legacy_findings(surface: str, root: Path) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in _regular_files(root, suffixes=(".pyc", ".pyo")):
        relative = path.relative_to(root).as_posix()
        if _contains_legacy_identity(relative):
            findings.append(
                {
                    "category": "legacy_protection_export",
                    "location": f"{surface}:{relative}:bytecode-module"[:1024],
                }
            )
    return findings


def _file_inventory_legacy_findings(
    surface: str, root: Path, files: Sequence[Path]
) -> list[dict[str, str]]:
    return [
        {
            "category": "legacy_protection_export",
            "location": (
                f"{surface}:{path.relative_to(root).as_posix()}:file-inventory"
            )[:1024],
        }
        for path in files
        if _contains_legacy_identity(path.relative_to(root).as_posix())
    ]


def _empty_inventory() -> dict[str, object]:
    return {
        "source_tree": [],
        "installed_wheel_entry_names": [],
        "console_entrypoints": [],
        "config_schema_filenames": [],
        "runbook_filenames": [],
        "scheduled_task_names": [],
    }


def _surface_report(root: Path, **field: object) -> LocalProductSurfaceReport:
    inventory = _empty_inventory()
    inventory.update(field)
    # local_product_surface consumes one canonical logical POSIX identity; the
    # physical root was already guarded separately above.
    return scan_local_product_surface(
        root=PureWindowsPath(EXACT_PROJECT_ROOT).as_posix(), inventory=inventory
    )


def _legacy_findings(surface: str, report: LocalProductSurfaceReport) -> list[dict[str, str]]:
    return [
        {
            "category": "legacy_protection_export",
            "location": (
                f"{surface}:{item.identity} [{item.category}.{item.code}]"
            )[:1024],
        }
        for item in report.violations
    ]


def _normalized_tokens(value: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", value)
    normalized = _ACRONYM_BOUNDARY_RE.sub(" ", normalized)
    normalized = _CAMEL_BOUNDARY_RE.sub(" ", normalized)
    return tuple(token.casefold() for token in re.findall(r"[A-Za-z0-9]+", normalized))


def _contains_legacy_identity(value: str) -> bool:
    tokens = _normalized_tokens(value)
    for surface in CANCELLED_MODULE_SURFACES:
        signature = "".join(surface.split("_"))
        width_limit = len(surface.split("_"))
        for start in range(len(tokens)):
            for width in range(1, min(width_limit, len(tokens) - start) + 1):
                if "".join(tokens[start : start + width]) == signature:
                    return True
    return False


def _contains_state_copy_identity(value: str) -> bool:
    tokens = set(_normalized_tokens(value))
    if _contains_legacy_identity(value):
        return True
    copy_word = bool(
        tokens
        & {
            "backup",
            "copy",
            "mirror",
            "replica",
            "robocopy",
            "snapshot",
            "sync",
            "xcopy",
        }
    )
    state_word = bool(tokens & {"state", "comments", "workspace", "sqlite", "database"})
    return copy_word and state_word


def _canonical_task_rows(value: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(value, list):
        raise RevocationSurfaceError("Windows task capture must be a list")
    rows: list[Mapping[str, object]] = []
    identities: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != _TASK_FIELDS:
            raise RevocationSurfaceError("Windows task capture is not closed")
        name = raw["name"]
        actions = raw["actions"]
        triggers = raw["triggers"]
        if not isinstance(name, str) or not name.startswith("\\") or _CONTROL_RE.search(name):
            raise RevocationSurfaceError("Windows task name is not canonical")
        folded = unicodedata.normalize("NFKC", name).casefold()
        if folded in identities:
            raise RevocationSurfaceError("Windows task capture contains duplicate identity")
        identities.add(folded)
        if not isinstance(actions, list) or not isinstance(triggers, list):
            raise RevocationSurfaceError("Windows task actions/triggers must be lists")
        checked_actions: list[Mapping[str, str]] = []
        for action in actions:
            if not isinstance(action, dict) or set(action) != _ACTION_FIELDS:
                raise RevocationSurfaceError("Windows task action is not closed")
            if not all(isinstance(action[field], str) for field in _ACTION_FIELDS):
                raise RevocationSurfaceError("Windows task action fields must be text")
            checked_actions.append(dict(action))
        checked_triggers: list[Mapping[str, str]] = []
        for trigger in triggers:
            if not isinstance(trigger, dict) or set(trigger) != _TRIGGER_FIELDS:
                raise RevocationSurfaceError("Windows task trigger is not closed")
            if not all(isinstance(trigger[field], str) for field in _TRIGGER_FIELDS):
                raise RevocationSurfaceError("Windows task trigger fields must be text")
            checked_triggers.append(dict(trigger))
        rows.append({"name": name, "actions": checked_actions, "triggers": checked_triggers})
    return tuple(sorted(rows, key=lambda row: str(row["name"]).casefold()))


def _capture_windows_tasks() -> tuple[Mapping[str, object], ...]:
    if os.name != "nt":
        raise RevocationSurfaceError("production Windows task capture is Windows-only")
    powershell = Path(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
    _ordinary_os_executable(powershell)
    scheduled_tasks_module = Path(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ScheduledTasks\ScheduledTasks.psd1"
    )
    _ordinary_os_executable(scheduled_tasks_module)
    script = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$modulePath = 'C:\Windows\System32\WindowsPowerShell\v1.0\Modules\ScheduledTasks\ScheduledTasks.psd1'
Import-Module -Name $modulePath -Force -ErrorAction Stop
$taskCommand = Get-Command -Name Get-ScheduledTask -CommandType Function,Cmdlet -ErrorAction Stop
if ($taskCommand.ModuleName -ne 'ScheduledTasks') { throw 'Get-ScheduledTask provenance drifted' }
$rows = @(
  Get-ScheduledTask | Sort-Object TaskPath, TaskName | ForEach-Object {
    $actions = @($_.Actions | ForEach-Object {
      [ordered]@{
        kind = [string]$_.CimClass.CimClassName
        execute = [string]$_.Execute
        arguments = [string]$_.Arguments
        working_directory = [string]$_.WorkingDirectory
        class_id = [string]$_.ClassId
        data = [string]$_.Data
      }
    })
    $triggers = @($_.Triggers | ForEach-Object {
      [ordered]@{
        kind = [string]$_.CimClass.CimClassName
        repetition_interval = [string]$_.Repetition.Interval
        repetition_duration = [string]$_.Repetition.Duration
      }
    })
    [ordered]@{
      name = [string]($_.TaskPath + $_.TaskName)
      actions = $actions
      triggers = $triggers
    }
  }
)
ConvertTo-Json -InputObject $rows -Depth 8 -Compress
""".strip()
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    try:
        completed = subprocess.run(
            [
                str(powershell),
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
            shell=False,
            env={
                "SystemRoot": r"C:\Windows",
                "WINDIR": r"C:\Windows",
                "PATH": (
                    r"C:\Windows\System32;"
                    r"C:\Windows\System32\WindowsPowerShell\v1.0"
                ),
                "PSModulePath": str(scheduled_tasks_module.parent),
                "TEMP": str(Path(EXACT_PROJECT_ROOT) / "tmp"),
                "TMP": str(Path(EXACT_PROJECT_ROOT) / "tmp"),
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RevocationSurfaceError("Windows task capture did not complete") from error
    if completed.returncode != 0 or completed.stderr.strip():
        raise RevocationSurfaceError("Windows task capture failed closed")
    try:
        payload = json.loads(completed.stdout.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RevocationSurfaceError("Windows task capture is not canonical JSON data") from error
    return _canonical_task_rows(payload)


def _task_is_periodic(task: Mapping[str, object]) -> bool:
    triggers = task["triggers"]
    assert isinstance(triggers, list)
    for raw in triggers:
        assert isinstance(raw, Mapping)
        kind = str(raw["kind"]).casefold()
        interval = str(raw["repetition_interval"]).strip().upper()
        if interval not in {"", "PT0S"} or any(
            token in kind
            for token in (
                "boot",
                "daily",
                "event",
                "idle",
                "logon",
                "monthly",
                "sessionstatechange",
                "weekly",
            )
        ):
            return True
    return False


def _task_is_project_related(task: Mapping[str, object]) -> bool:
    actions = task["actions"]
    assert isinstance(actions, list)
    pieces = [str(task["name"])]
    for raw in actions:
        assert isinstance(raw, Mapping)
        pieces.extend(str(raw[field]) for field in sorted(_ACTION_FIELDS))
    combined = " ".join(pieces).replace("\\\\", "\\")
    folded = combined.casefold()
    tokens = set(_normalized_tokens(combined))
    return bool(
        EXACT_PROJECT_ROOT.casefold() in folded
        or r"c:\quant_platform" in folded
        or "quant_platform" in folded
        or "qrh" in tokens
        or _contains_legacy_identity(combined)
    )


def _inside_exact_root(path: str) -> bool:
    if not _canonical_windows_path(path):
        return False
    try:
        normalized = PureWindowsPath(ntpath.normpath(path))
        normalized.relative_to(PureWindowsPath(EXACT_PROJECT_ROOT))
    except (TypeError, ValueError):
        return False
    return True


def _canonical_windows_path(value: str) -> bool:
    if (
        not value
        or _CONTROL_RE.search(value)
        or unicodedata.normalize("NFKC", value) != value
        or "/" in value
        or ntpath.normpath(value) != value
    ):
        return False
    path = PureWindowsPath(value)
    if not path.is_absolute() or not path.drive or path.root != "\\":
        return False
    for part in path.parts[1:]:
        if (
            part in {"", ".", ".."}
            or part.endswith((" ", "."))
            or ":" in part
            or part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_NAMES
        ):
            return False
    return str(path) == value


def _allowed_external_read_path(
    value: str, *, allow_documented_reads: bool, allow_system: bool
) -> bool:
    path = PureWindowsPath(value)
    if allow_documented_reads and any(
        path == PureWindowsPath(item) for item in _LEGACY_READ_ONLY_SOURCES
    ):
        return True
    if not allow_system:
        return False
    try:
        path.relative_to(PureWindowsPath(r"C:\Windows"))
    except ValueError:
        return False
    return True


def _outside_project_paths(
    value: str,
    *,
    allow_documented_reads: bool = False,
    allow_system: bool = False,
    whole_value_path: bool = False,
) -> tuple[str, ...]:
    results: set[str] = set()

    def inspect_windows_path(rendered: str) -> None:
        if (
            not _canonical_windows_path(rendered)
            or (
                not _inside_exact_root(rendered)
                and not _allowed_external_read_path(
                    rendered,
                    allow_documented_reads=allow_documented_reads,
                    allow_system=allow_system,
                )
            )
        ):
            results.add(rendered)

    candidates = (value, value.replace("\\\\", "\\"))
    for candidate in candidates:
        stripped = candidate.strip()
        if (
            whole_value_path and re.match(r"(?i)^[a-z]:\\", stripped)
        ) or re.fullmatch(r"(?i)[a-z]:\\[^\s\"'<>|]+", stripped):
            inspect_windows_path(stripped.rstrip("),.;]}"))
        for match in _QUOTED_WINDOWS_PATH_RE.finditer(candidate):
            inspect_windows_path(match.group(1).rstrip("),.;]}"))
        for match in _UNC_PATH_RE.finditer(candidate):
            results.add(match.group(0).rstrip("),.;]}"))
        for match in _SLASH_DRIVE_PATH_RE.finditer(candidate):
            results.add(match.group(0).rstrip("),.;]}"))
        for match in _SLASH_UNC_PATH_RE.finditer(candidate):
            results.add(match.group(0).rstrip("),.;]}"))
        for match in _WINDOWS_PATH_RE.finditer(candidate):
            rendered = match.group(0).rstrip("),.;]}")
            inspect_windows_path(rendered)
    return tuple(sorted(results, key=str.casefold))


def _task_findings(tasks: Sequence[Mapping[str, object]]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for task in tasks:
        name = str(task["name"])
        action_text: list[str] = []
        actions = task["actions"]
        assert isinstance(actions, list)
        for raw in actions:
            assert isinstance(raw, Mapping)
            action_text.extend(str(raw[field]) for field in sorted(_ACTION_FIELDS))
            if "execaction" not in str(raw["kind"]).casefold():
                findings.append(
                    {
                        "category": "legacy_protection_export",
                        "location": f"windows-tasks:{name}:non-exec-action"[:1024],
                    }
                )
            for field in sorted(_ACTION_FIELDS):
                for path in _outside_project_paths(
                    str(raw[field]), allow_system=field == "execute"
                ):
                    findings.append(
                        {
                            "category": "outside_d_project_storage",
                            "location": f"windows-tasks:{name}:{field}:{path}"[:1024],
                        }
                    )
        combined = " ".join((name, *action_text))
        state_copy = _contains_state_copy_identity(combined)
        if state_copy and re.search(r"(?:^|[\s\"'])\.\.[\\/]", combined):
            findings.append(
                {
                    "category": "outside_d_project_storage",
                    "location": f"windows-tasks:{name}:relative-traversal",
                }
            )
        if state_copy:
            findings.append(
                {
                    "category": "legacy_protection_export",
                    "location": f"windows-tasks:{name}:state-copy-capability",
                }
            )
        if _task_is_periodic(task) and state_copy:
            findings.append(
                {"category": "periodic_state_copy_task", "location": f"windows-tasks:{name}"}
            )
    return findings


def _read_json(path: Path) -> Mapping[str, object]:
    _ordinary_path(path, kind="file")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RevocationSurfaceError(f"JSON surface is unreadable: {path}") from error
    if not isinstance(value, dict):
        raise RevocationSurfaceError(f"JSON surface is not an object: {path}")
    return value


def _protection_authority_reference(value: str) -> bool:
    tokens = set(_normalized_tokens(value))
    protection = tokens & {
        "backup",
        "copy",
        "external",
        "export",
        "mirror",
        "recovery",
        "replica",
        "restore",
        "snapshot",
        "sync",
    }
    location = tokens & {
        "destination",
        "database",
        "directory",
        "file",
        "folder",
        "host",
        "location",
        "path",
        "root",
        "state",
        "storage",
        "target",
        "vault",
        "workspace",
    }
    chinese_subject = (
        "(?:\u6570\u636e\u5e93|\u72b6\u6001|\u7814\u7a76\u6587\u4ef6|"
        "\u6587\u4ef6|\u76ee\u5f55)"
    )
    chinese_action = (
        "(?:\u590d\u5236|\u955c\u50cf|\u526f\u672c|\u540c\u6b65|"
        "\u5907\u4efd|\u53d1\u9001)"
    )
    chinese_protection = re.search(
        f"{chinese_subject}.{{0,12}}{chinese_action}"
        f"|{chinese_action}.{{0,12}}{chinese_subject}"
        "|\u53e6\u4e00\u4e3b\u673a",
        value,
    ) is not None
    return (
        bool(protection and location)
        or bool(chinese_protection)
        or re.search(
            "\u6062\u590d\u6839|\u6062\u590d\u76ee\u5f55|"
            "\u5907\u4efd\u6839|\u5907\u4efd\u76ee\u5f55|"
            "\u5916\u90e8\u5b58\u50a8",
            value,
        )
        is not None
    )


def _json_surface_findings(
    surface: str, root: Path, path: Path
) -> list[dict[str, str]]:
    value = _read_json(path)
    relative = path.relative_to(root).as_posix()
    findings: list[dict[str, str]] = []

    def walk(node: object, trail: tuple[str, ...], authority: bool) -> None:
        if isinstance(node, dict):
            for raw_key, child in node.items():
                key = str(raw_key)
                key_authority = _protection_authority_reference(key)
                if (
                    path.name == "release_closure_gate_evidence.schema.json"
                    and "revocation_surface" in trail
                ):
                    key_authority = False
                if key_authority or _contains_legacy_identity(key):
                    findings.append(
                        {
                            "category": "legacy_protection_export",
                            "location": (
                                f"{surface}:{relative}:json:{'.'.join((*trail, key))}"
                            )[:1024],
                        }
                    )
                key_tokens = set(_normalized_tokens(key))
                generic_path_key = bool(key_tokens & {
                    "destination",
                    "directory",
                    "path",
                    "root",
                    "storage",
                    "target",
                })
                walk(child, (*trail, key), authority or key_authority or generic_path_key)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, (*trail, str(index)), authority)
        elif isinstance(node, str):
            if _contains_legacy_identity(node):
                findings.append(
                    {
                        "category": "legacy_protection_export",
                        "location": (
                            f"{surface}:{relative}:json:{'.'.join(trail)}:value"
                        )[:1024],
                    }
                )
            metadata_field = bool(trail) and trail[-1].casefold() in {
                "$id",
                "$ref",
                "$schema",
                "description",
                "examples",
                "title",
            }
            if bool(trail) and trail[-1].casefold() == "pattern":
                # Regex syntax itself contains slash/backslash character
                # classes.  Treat it as path authority only when it embeds a
                # literal external drive/UNC root, not merely a relative-path
                # grammar such as ``[^\\/]+``.
                literal_drive = re.search(r"(?i)(?:\^)?([a-z]):\\+", node)
                literal_unc = re.match(
                    r"^\^?\\{2,}[A-Za-z0-9_.-]+\\+[A-Za-z0-9$_.-]+",
                    node,
                )
                pattern_external = bool(
                    literal_unc
                    or (
                        literal_drive
                        and literal_drive.group(1).casefold()
                        != PureWindowsPath(EXACT_PROJECT_ROOT).drive[0].casefold()
                    )
                )
                metadata_field = not (authority and pattern_external)
            if not metadata_field:
                external_paths = _outside_project_paths(
                    node,
                    allow_documented_reads=(
                        path.name == "production_vm_write_set.json"
                    ),
                    whole_value_path=authority,
                )
                for external in external_paths:
                    findings.append(
                        {
                            "category": "outside_d_project_storage",
                            "location": (
                                f"{surface}:{relative}:json:{'.'.join(trail)}:"
                                f"{external}"
                            )[:1024],
                        }
                    )
                if not external_paths and (
                    re.search(r"(?:^|[\\/])\.\.(?:[\\/]|$)", node)
                    or re.search(r"%[A-Za-z_][A-Za-z0-9_]*%", node)
                    or node.startswith("~")
                ):
                    findings.append(
                        {
                            "category": "outside_d_project_storage",
                            "location": (
                                f"{surface}:{relative}:json:{'.'.join(trail)}:"
                                "unresolved-path-authority"
                            )[:1024],
                        }
                    )

    walk(value, (), False)
    return findings


def _content_findings(
    surface: str, root: Path, paths: Sequence[Path]
) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    for path in paths:
        if surface in {"config", "schema"}:
            findings.extend(_json_surface_findings(surface, root, path))
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise RevocationSurfaceError(
                f"controlled text surface is not strict UTF-8: {path}"
            ) from error
        relative = path.relative_to(root).as_posix()
        if _contains_legacy_identity(content):
            findings.append(
                {
                    "category": "legacy_protection_export",
                    "location": f"{surface}:{relative}:content"[:1024],
                }
            )
        for line_number, line in enumerate(content.splitlines(), start=1):
            if not _protection_authority_reference(line):
                continue
            for external in _outside_project_paths(line):
                findings.append(
                    {
                        "category": "outside_d_project_storage",
                        "location": (
                            f"{surface}:{relative}:{line_number}:{external}"
                        )[:1024],
                    }
                )
    return findings


def _write_set_findings(path: Path) -> list[dict[str, str]]:
    value = _read_json(path)
    findings: list[dict[str, str]] = []
    expected_fields = {
        "schema_version",
        "root",
        "areas",
        "legacy_read_only_sources",
        "contract",
    }
    if set(value) != expected_fields:
        findings.append(
            {"category": "outside_d_project_storage", "location": "vm-write-set:closed-schema"}
        )
    if value.get("schema_version") != "qrh-production-vm-write-set/v1":
        findings.append(
            {"category": "outside_d_project_storage", "location": "vm-write-set:schema-version"}
        )
    if value.get("root") != EXACT_PROJECT_ROOT:
        findings.append(
            {"category": "outside_d_project_storage", "location": "vm-write-set:root"}
        )
    areas = value.get("areas")
    if areas != list(_EXPECTED_WRITE_AREAS):
        findings.append(
            {"category": "outside_d_project_storage", "location": "vm-write-set:areas"}
        )
    legacy = value.get("legacy_read_only_sources")
    if legacy != list(_LEGACY_READ_ONLY_SOURCES):
        findings.append(
            {
                "category": "outside_d_project_storage",
                "location": "vm-write-set:legacy-read-only-sources",
            }
        )
    if not _type_exact_equal(value.get("contract"), _EXPECTED_WRITE_CONTRACT):
        findings.append(
            {
                "category": "outside_d_project_storage",
                "location": "vm-write-set:contract",
            }
        )
    return findings


def _type_exact_equal(value: object, expected: object) -> bool:
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        assert isinstance(value, dict)
        return set(value) == set(expected) and all(
            _type_exact_equal(value[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        assert isinstance(value, list)
        return len(value) == len(expected) and all(
            _type_exact_equal(actual, wanted)
            for actual, wanted in zip(value, expected, strict=True)
        )
    return value == expected


def _project_entrypoints(root: Path) -> tuple[Mapping[str, str], ...]:
    path = root / "quant_hub" / "pyproject.toml"
    _ordinary_chain(root, path, kind="file")
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise RevocationSurfaceError("project CLI metadata is unreadable") from error
    project = document.get("project")
    scripts = project.get("scripts") if isinstance(project, dict) else None
    if not isinstance(scripts, dict):
        raise RevocationSurfaceError("project CLI metadata lacks [project.scripts]")
    rows: list[Mapping[str, str]] = []
    for name, target in sorted(scripts.items()):
        if not isinstance(name, str) or not isinstance(target, str):
            raise RevocationSurfaceError("project CLI entrypoint is not text")
        rows.append({"name": name, "target": target})
    return tuple(rows)


def _matching_wheel_distribution(wheel_root: Path) -> Path:
    site_packages = wheel_root.parent
    matches: list[Path] = []
    for metadata in sorted(site_packages.glob("*.dist-info/METADATA")):
        _ordinary_path(metadata.parent, kind="directory")
        _ordinary_path(metadata, kind="file")
        name = ""
        for line in metadata.read_text(encoding="utf-8").splitlines():
            if line.casefold().startswith("name:"):
                name = line.split(":", 1)[1].strip()
                break
        if name.replace("_", "-").casefold() != "quant-research-hub":
            continue
        matches.append(metadata.parent)
    if len(matches) != 1:
        raise RevocationSurfaceError(
            "fresh-wheel must contain exactly one matching distribution metadata directory"
        )
    return matches[0]


def _wheel_entrypoints(wheel_root: Path) -> tuple[Mapping[str, str], ...]:
    distribution = _matching_wheel_distribution(wheel_root)
    rows: list[Mapping[str, str]] = []
    entry_path = distribution / "entry_points.txt"
    if entry_path.exists():
        _ordinary_path(entry_path, kind="file")
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str
        parser.read_string(entry_path.read_text(encoding="utf-8"))
        if parser.has_section("console_scripts"):
            for entry_name, target in parser.items("console_scripts"):
                rows.append({"name": entry_name.strip(), "target": target.strip()})
    unique = {(row["name"], row["target"]): row for row in rows}
    return tuple(unique[key] for key in sorted(unique))


def _merge_entrypoints(
    *groups: Sequence[Mapping[str, str]],
) -> tuple[Mapping[str, str], ...]:
    """Collapse the expected source/wheel duplicate, retain real collisions."""

    rows: list[Mapping[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for group in groups:
        for row in group:
            identity = (str(row["name"]), str(row["target"]))
            if identity not in seen:
                seen.add(identity)
                rows.append({"name": identity[0], "target": identity[1]})
    return tuple(sorted(rows, key=lambda row: (row["name"].casefold(), row["target"])))


def _wheel_runtime_negative_replay(root: Path) -> tuple[Mapping[str, str], ...]:
    python = root / "tooling" / "python" / "python.exe"
    _ordinary_chain(root, python, kind="file")
    script = (
        "import importlib,json\n"
        f"names={list(CANCELLED_MODULE_SURFACES)!r}\n"
        "findings=[]\n"
        "ops=importlib.import_module('quant_hub.ops')\n"
        "for name in names:\n"
        " module_name='quant_hub.ops.'+name\n"
        " try:\n"
        "  importlib.import_module(module_name)\n"
        " except ModuleNotFoundError as error:\n"
        "  if error.name!=module_name: findings.append({'name':name,'kind':'import_dependency_error'})\n"
        " except Exception:\n"
        "  findings.append({'name':name,'kind':'import_probe_error'})\n"
        " else:\n"
        "  findings.append({'name':name,'kind':'module_importable'})\n"
        " try:\n"
        "  value=getattr(ops,name)\n"
        " except AttributeError:\n"
        "  pass\n"
        " except Exception:\n"
        "  findings.append({'name':name,'kind':'attribute_probe_error'})\n"
        " else:\n"
        "  findings.append({'name':name,'kind':'callable_attribute' if callable(value) else 'attribute_present'})\n"
        "print(json.dumps(findings,sort_keys=True,separators=(',',':')))\n"
    )
    try:
        completed = subprocess.run(
            [str(python), "-I", "-B", "-c", script],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RevocationSurfaceError(
            "fresh-wheel importability replay did not complete"
        ) from error
    if completed.returncode != 0 or completed.stderr.strip():
        raise RevocationSurfaceError("fresh-wheel importability replay failed closed")
    try:
        rows = json.loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RevocationSurfaceError(
            "fresh-wheel importability replay returned invalid JSON"
        ) from error
    if not isinstance(rows, list):
        raise RevocationSurfaceError("fresh-wheel importability replay is not a list")
    findings: list[Mapping[str, str]] = []
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"name", "kind"}
            or row["name"] not in CANCELLED_MODULE_SURFACES
            or row["kind"]
            not in {
                "attribute_present",
                "attribute_probe_error",
                "callable_attribute",
                "import_dependency_error",
                "import_probe_error",
                "module_importable",
            }
        ):
            raise RevocationSurfaceError(
                "fresh-wheel importability replay row is not closed"
            )
        findings.append(
            {
                "category": "legacy_protection_export",
                "location": f"fresh-wheel:runtime:{row['name']}:{row['kind']}",
            }
        )
    return tuple(findings)


def _load_production_inputs() -> _AuditInputs:
    if os.name != "nt":
        raise RevocationSurfaceError("production revocation scan is Windows-only")
    root = Path(EXACT_PROJECT_ROOT)
    _ordinary_path(root, kind="directory")
    resolved = root.resolve(strict=True)
    if PureWindowsPath(str(resolved)) != PureWindowsPath(EXACT_PROJECT_ROOT):
        raise RevocationSurfaceError("production root is not exact D")
    source_root = root / "quant_hub" / "src" / "quant_hub"
    wheel_root = root / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub"
    config_root = root / "config"
    runbook_root = root / "docs" / "runbooks"
    for directory in (source_root, wheel_root, config_root, runbook_root):
        _ordinary_chain(root, directory, kind="directory")
    config_paths = _regular_files(config_root)
    schema_paths = tuple(path for path in config_paths if path.name.casefold().endswith(".schema.json"))
    runbook_paths = _regular_files(runbook_root, suffixes=(".md",))
    if not config_paths or not schema_paths or not runbook_paths:
        raise RevocationSurfaceError("one or more fixed controlled surfaces are empty")
    return _AuditInputs(
        root=root,
        source_root=source_root,
        wheel_root=wheel_root,
        wheel_runtime_findings=_wheel_runtime_negative_replay(root),
        console_entrypoints=_merge_entrypoints(
            _project_entrypoints(root), _wheel_entrypoints(wheel_root)
        ),
        config_paths=config_paths,
        schema_paths=schema_paths,
        runbook_paths=runbook_paths,
        windows_tasks=_capture_windows_tasks(),
        write_set_path=root / "config" / "production_vm_write_set.json",
    )


def _scan(inputs: _AuditInputs) -> tuple[Mapping[str, object], ...]:
    scans: list[Mapping[str, object]] = []

    source_records = _source_records(inputs.source_root)
    source_files = _regular_files(inputs.source_root)
    source_findings = _legacy_findings(
        "source",
        _surface_report(inputs.root, source_tree=source_records),
    )
    source_findings.extend(_source_symbol_findings("source", source_records))
    source_findings.extend(
        _file_inventory_legacy_findings("source", inputs.source_root, source_files)
    )
    scans.append(_scan_record("source", source_findings))

    wheel_inventory_root = inputs.wheel_root.parent
    wheel_files = _regular_files(wheel_inventory_root)
    wheel_records = _source_records(inputs.wheel_root)
    wheel_findings = _legacy_findings(
        "fresh-wheel",
        _surface_report(
            inputs.root,
            source_tree=wheel_records,
            installed_wheel_entry_names=[
                path.relative_to(wheel_inventory_root).as_posix() for path in wheel_files
            ],
        ),
    )
    wheel_findings.extend(_source_symbol_findings("fresh-wheel", wheel_records))
    wheel_findings.extend(
        _file_inventory_legacy_findings(
            "fresh-wheel", wheel_inventory_root, wheel_files
        )
    )
    wheel_findings.extend(inputs.wheel_runtime_findings)
    scans.append(_scan_record("fresh-wheel", wheel_findings))

    cli_findings = _legacy_findings(
        "cli",
        _surface_report(inputs.root, console_entrypoints=list(inputs.console_entrypoints)),
    )
    scripts_root = inputs.wheel_root.parents[2] / "Scripts"
    if scripts_root.exists():
        _ordinary_chain(inputs.root, scripts_root, kind="directory")
        cli_findings.extend(
            _file_inventory_legacy_findings(
                "cli", scripts_root, _regular_files(scripts_root)
            )
        )
    scans.append(_scan_record("cli", cli_findings))

    schema_path_set = set(inputs.schema_paths)
    non_schema_config_paths = tuple(
        path
        for path in inputs.config_paths
        if path not in schema_path_set and path != inputs.write_set_path
    )
    config_findings = _legacy_findings(
        "config",
        _surface_report(
            inputs.root,
            config_schema_filenames=[path.name for path in non_schema_config_paths],
        ),
    )
    config_findings.extend(
        _content_findings("config", inputs.root, non_schema_config_paths)
    )
    scans.append(_scan_record("config", config_findings))

    schema_findings = _legacy_findings(
        "schema",
        _surface_report(
            inputs.root,
            config_schema_filenames=[path.name for path in inputs.schema_paths],
        ),
    )
    schema_findings.extend(
        _content_findings("schema", inputs.root, inputs.schema_paths)
    )
    scans.append(_scan_record("schema", schema_findings))

    project_tasks = tuple(
        task for task in inputs.windows_tasks if _task_is_project_related(task)
    )
    task_findings = _legacy_findings(
        "windows-tasks",
        _surface_report(
            inputs.root,
            scheduled_task_names=[str(task["name"]) for task in project_tasks],
        ),
    )
    task_findings += _task_findings(project_tasks)
    scans.append(_scan_record("windows-tasks", task_findings))

    runbook_findings = _legacy_findings(
        "runbook",
        _surface_report(
            inputs.root,
            runbook_filenames=[path.name for path in inputs.runbook_paths],
        ),
    )
    runbook_findings.extend(
        _content_findings("runbook", inputs.root, inputs.runbook_paths)
    )
    scans.append(_scan_record("runbook", runbook_findings))

    scans.append(_scan_record("vm-write-set", _write_set_findings(inputs.write_set_path)))
    by_id = {str(scan["id"]): scan for scan in scans}
    if set(by_id) != set(SURFACE_IDS) or len(scans) != len(SURFACE_IDS):
        raise RevocationSurfaceError("fixed revocation surface set drifted")
    return tuple(by_id[surface] for surface in SURFACE_IDS)


def _scan_record(surface: str, findings: Sequence[Mapping[str, str]]) -> Mapping[str, object]:
    unique = {
        (str(item["category"]), str(item["location"])): {
            "category": str(item["category"]),
            "location": str(item["location"]),
        }
        for item in findings
    }
    ordered = [unique[key] for key in sorted(unique)]
    return {"id": surface, "outcome": "pass" if not ordered else "fail", "findings": ordered}


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RevocationSurfaceError("produced_at must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def _report_id(produced_at: str) -> str:
    compact_time = re.sub(r"[^0-9]", "", produced_at)
    if len(compact_time) != 20:
        raise RevocationSurfaceError("produced_at does not carry canonical microseconds")
    return f"revocation-surface-{compact_time}"


def build_report(
    inputs: _AuditInputs,
    *,
    produced_at: datetime,
    test_fixture: bool = False,
) -> Mapping[str, object]:
    scans = list(_scan(inputs))
    counts = {category: 0 for category in FINDING_CATEGORIES}
    for scan in scans:
        findings = scan["findings"]
        assert isinstance(findings, list)
        for finding in findings:
            assert isinstance(finding, Mapping)
            counts[str(finding["category"])] += 1
    rendered_at = _timestamp(produced_at)
    schema_version = _TEST_REPORT_SCHEMA if test_fixture else REPORT_SCHEMA
    authority_scope = _TEST_AUTHORITY_SCOPE if test_fixture else AUTHORITY_SCOPE
    producer_name = _TEST_PRODUCER_NAME if test_fixture else PRODUCER_NAME
    observed_root = str(inputs.root) if test_fixture else EXACT_PROJECT_ROOT
    report: dict[str, object] = {
        "schema_version": schema_version,
        "report_id": _report_id(rendered_at),
        "gate_role": GATE_ROLE,
        "authority_scope": authority_scope,
        "producer": {"name": producer_name, "version": PRODUCER_VERSION},
        "produced_at": rendered_at,
        "exact_project_root": observed_root,
        "scans": scans,
        "result": {
            "surface_checks_total": len(scans),
            "surface_checks_passed": sum(scan["outcome"] == "pass" for scan in scans),
            "periodic_state_copy_tasks": counts["periodic_state_copy_task"],
            "outside_d_project_storage": counts["outside_d_project_storage"],
            "legacy_protection_exports": counts["legacy_protection_export"],
        },
    }
    report["report_sha256"] = hashlib.sha256(canonical_bytes(report)).hexdigest()
    return _validate_report(
        report,
        schema_version=schema_version,
        authority_scope=authority_scope,
        producer_name=producer_name,
        observed_root=observed_root,
    )


def validate_report(value: object) -> Mapping[str, object]:
    return _validate_report(
        value,
        schema_version=REPORT_SCHEMA,
        authority_scope=AUTHORITY_SCOPE,
        producer_name=PRODUCER_NAME,
        observed_root=EXACT_PROJECT_ROOT,
    )


def _validate_test_report(value: object, *, observed_root: str) -> Mapping[str, object]:
    return _validate_report(
        value,
        schema_version=_TEST_REPORT_SCHEMA,
        authority_scope=_TEST_AUTHORITY_SCOPE,
        producer_name=_TEST_PRODUCER_NAME,
        observed_root=observed_root,
    )


def _validate_report(
    value: object,
    *,
    schema_version: str,
    authority_scope: str,
    producer_name: str,
    observed_root: str,
) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != _REPORT_FIELDS:
        raise RevocationSurfaceError("revocation report is not closed")
    if (
        value["schema_version"] != schema_version
        or value["gate_role"] != GATE_ROLE
        or value["authority_scope"] != authority_scope
        or value["exact_project_root"] != observed_root
    ):
        raise RevocationSurfaceError("revocation report identity/scope drifted")
    if not isinstance(value["report_id"], str) or _IDENTIFIER_RE.fullmatch(value["report_id"]) is None:
        raise RevocationSurfaceError("revocation report_id is invalid")
    if value["producer"] != {"name": producer_name, "version": PRODUCER_VERSION}:
        raise RevocationSurfaceError("revocation producer identity drifted")
    produced_at = value["produced_at"]
    if not isinstance(produced_at, str):
        raise RevocationSurfaceError("revocation produced_at is invalid")
    try:
        parsed_time = datetime.fromisoformat(produced_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise RevocationSurfaceError("revocation produced_at is invalid") from error
    if produced_at != _timestamp(parsed_time) or value["report_id"] != _report_id(
        produced_at
    ):
        raise RevocationSurfaceError("revocation time/report identity is not canonical")
    scans = value["scans"]
    if not isinstance(scans, list) or len(scans) != len(SURFACE_IDS):
        raise RevocationSurfaceError("revocation scans are incomplete")
    counts = {category: 0 for category in FINDING_CATEGORIES}
    passed = 0
    for expected_id, scan in zip(SURFACE_IDS, scans, strict=True):
        if not isinstance(scan, dict) or set(scan) != _SCAN_FIELDS or scan["id"] != expected_id:
            raise RevocationSurfaceError("revocation scan schema/order drifted")
        findings = scan["findings"]
        if not isinstance(findings, list):
            raise RevocationSurfaceError("revocation findings must be a list")
        if scan["outcome"] not in {"pass", "fail"} or (scan["outcome"] == "pass") != (not findings):
            raise RevocationSurfaceError("revocation scan outcome differs from findings")
        passed += int(scan["outcome"] == "pass")
        identities: set[tuple[str, str]] = set()
        for finding in findings:
            if not isinstance(finding, dict) or set(finding) != _FINDING_FIELDS:
                raise RevocationSurfaceError("revocation finding is not closed")
            category = finding["category"]
            location = finding["location"]
            if category not in FINDING_CATEGORIES or not isinstance(location, str) or not location or len(location) > 1024:
                raise RevocationSurfaceError("revocation finding identity is invalid")
            identity = (str(category), location)
            if identity in identities:
                raise RevocationSurfaceError("revocation finding is duplicated")
            identities.add(identity)
            counts[str(category)] += 1
    result = value["result"]
    if not isinstance(result, dict) or set(result) != _RESULT_FIELDS:
        raise RevocationSurfaceError("revocation result is not closed")
    if any(type(result[field]) is not int or result[field] < 0 for field in _RESULT_FIELDS):
        raise RevocationSurfaceError("revocation result counters must be non-negative integers")
    expected_result = {
        "surface_checks_total": len(SURFACE_IDS),
        "surface_checks_passed": passed,
        "periodic_state_copy_tasks": counts["periodic_state_copy_task"],
        "outside_d_project_storage": counts["outside_d_project_storage"],
        "legacy_protection_exports": counts["legacy_protection_export"],
    }
    if result != expected_result:
        raise RevocationSurfaceError("revocation result does not derive from scans")
    claimed = value["report_sha256"]
    if not isinstance(claimed, str) or _SHA_RE.fullmatch(claimed) is None:
        raise RevocationSurfaceError("revocation report hash is invalid")
    material = dict(value)
    material.pop("report_sha256")
    if hashlib.sha256(canonical_bytes(material)).hexdigest() != claimed:
        raise RevocationSurfaceError("revocation report self-hash differs")
    return json.loads(canonical_bytes(value))


def _output_path(root: Path, relative_text: str) -> Path:
    try:
        relative = PurePosixPath(relative_text)
    except ValueError as error:
        raise RevocationSurfaceError("output path is invalid") from error
    if (
        _CONTROL_RE.search(relative_text)
        or unicodedata.normalize("NFKC", relative_text) != relative_text
        or "\\" in relative_text
        or ":" in relative_text
        or relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != relative_text
        or any(
            part.endswith((" ", "."))
            or part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_NAMES
            for part in relative.parts
        )
        or relative.suffix.casefold() != ".json"
        or relative.parts[:4] != ("audit", "release-closure", "results", "stage5")
    ):
        raise RevocationSurfaceError("output must be a Stage 5 audit JSON path")
    root_resolved = root.resolve(strict=True)
    output = root_resolved.joinpath(*relative.parts).resolve(strict=False)
    try:
        output.relative_to(root_resolved)
    except ValueError as error:
        raise RevocationSurfaceError("output escaped the exact project root") from error
    return output


def _create_parent_chain(root: Path, parent: Path) -> None:
    relative = parent.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if os.path.lexists(current):
            _ordinary_path(current, kind="directory")
        else:
            os.mkdir(current)
            _ordinary_path(current, kind="directory")


def write_report_create_only(
    root: Path, relative_path: str, report: Mapping[str, object]
) -> Path:
    validated = validate_report(report)
    _ordinary_path(root, kind="directory")
    output = _output_path(root, relative_path)
    _create_parent_chain(root, output.parent)
    if os.path.lexists(output):
        raise RevocationSurfaceError("revocation report output already exists")
    raw = canonical_bytes(validated)
    try:
        with output.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise RevocationSurfaceError("revocation report create-only write failed") from error
    _ordinary_chain(root, output, kind="file")
    if output.read_bytes() != raw:
        raise RevocationSurfaceError("revocation report readback differs")
    return output


def _write_test_report_create_only(
    root: Path, relative_path: str, report: Mapping[str, object]
) -> Path:
    validated = _validate_test_report(report, observed_root=str(root))
    _ordinary_path(root, kind="directory")
    output = _output_path(root, relative_path)
    _create_parent_chain(root, output.parent)
    if os.path.lexists(output):
        raise RevocationSurfaceError("revocation test report output already exists")
    raw = canonical_bytes(validated)
    try:
        with output.open("xb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise RevocationSurfaceError(
            "revocation test report create-only write failed"
        ) from error
    _ordinary_chain(root, output, kind="file")
    if output.read_bytes() != raw:
        raise RevocationSurfaceError("revocation test report readback differs")
    return output


def produce_production_report(*, output_relative_path: str) -> tuple[Path, Mapping[str, object]]:
    inputs = _load_production_inputs()
    report = build_report(inputs, produced_at=datetime.now(UTC))
    return write_report_create_only(inputs.root, output_relative_path, report), report


def replay_production_report(value: object) -> Mapping[str, object]:
    """Re-scan the live exact-D surfaces and match a persisted report."""

    report = validate_report(value)
    inputs = _load_production_inputs()
    scans = list(_scan(inputs))
    if report["scans"] != scans:
        raise RevocationSurfaceError(
            "revocation report scans differ from live exact-D replay"
        )
    counts = {category: 0 for category in FINDING_CATEGORIES}
    for scan in scans:
        findings = scan["findings"]
        assert isinstance(findings, list)
        for finding in findings:
            assert isinstance(finding, Mapping)
            counts[str(finding["category"])] += 1
    expected_result = {
        "surface_checks_total": len(scans),
        "surface_checks_passed": sum(scan["outcome"] == "pass" for scan in scans),
        "periodic_state_copy_tasks": counts["periodic_state_copy_task"],
        "outside_d_project_storage": counts["outside_d_project_storage"],
        "legacy_protection_exports": counts["legacy_protection_export"],
    }
    if report["result"] != expected_result:
        raise RevocationSurfaceError(
            "revocation report aggregate differs from live exact-D replay"
        )
    return report


def _inputs_for_test_only(
    root: Path, *, windows_tasks: Sequence[Mapping[str, object]]
) -> _AuditInputs:
    if PureWindowsPath(str(root)) == PureWindowsPath(EXACT_PROJECT_ROOT):
        raise RevocationSurfaceError("test-only adapter cannot target production exact D")
    physical = root.resolve(strict=True)
    if PureWindowsPath(str(physical)) == PureWindowsPath(EXACT_PROJECT_ROOT):
        raise RevocationSurfaceError(
            "test-only adapter cannot target production exact D through an alias"
        )
    source_root = physical / "quant_hub" / "src" / "quant_hub"
    wheel_root = physical / "tooling" / "python" / "Lib" / "site-packages" / "quant_hub"
    config_root = physical / "config"
    runbook_root = physical / "docs" / "runbooks"
    for directory in (source_root, wheel_root, config_root, runbook_root):
        _ordinary_chain(physical, directory, kind="directory")
    config_paths = _regular_files(config_root)
    return _AuditInputs(
        root=physical,
        source_root=source_root,
        wheel_root=wheel_root,
        wheel_runtime_findings=(),
        console_entrypoints=_merge_entrypoints(
            _project_entrypoints(physical), _wheel_entrypoints(wheel_root)
        ),
        config_paths=config_paths,
        schema_paths=tuple(path for path in config_paths if path.name.casefold().endswith(".schema.json")),
        runbook_paths=_regular_files(runbook_root, suffixes=(".md",)),
        windows_tasks=_canonical_task_rows(list(windows_tasks)),
        write_set_path=config_root / "production_vm_write_set.json",
    )


def produce_report_for_test_only(
    root: Path,
    *,
    windows_tasks: Sequence[Mapping[str, object]],
    produced_at: datetime,
    output_relative_path: str = DEFAULT_OUTPUT_RELATIVE_PATH,
) -> tuple[Path, Mapping[str, object]]:
    inputs = _inputs_for_test_only(root, windows_tasks=windows_tasks)
    report = build_report(inputs, produced_at=produced_at, test_fixture=True)
    return _write_test_report_create_only(
        inputs.root, output_relative_path, report
    ), report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-relative-path",
        default=DEFAULT_OUTPUT_RELATIVE_PATH,
        help="create-only JSON path below audit/release-closure/results/stage5",
    )
    args = parser.parse_args(argv)
    try:
        path, report = produce_production_report(
            output_relative_path=args.output_relative_path
        )
    except Exception as error:
        print(
            json.dumps(
                {
                    "schema_version": "qrh-stage5-revocation-producer-error/v1",
                    "status": "error",
                    "error_type": type(error).__name__,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "schema_version": "qrh-stage5-revocation-producer-result/v1",
                "status": "pass"
                if report["result"]["surface_checks_passed"] == len(SURFACE_IDS)  # type: ignore[index]
                else "fail",
                "relative_path": path.relative_to(Path(EXACT_PROJECT_ROOT)).as_posix(),
                "report_sha256": report["report_sha256"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if report["result"]["surface_checks_passed"] == len(SURFACE_IDS) else 2  # type: ignore[index]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = [
    "AUTHORITY_SCOPE",
    "DEFAULT_OUTPUT_RELATIVE_PATH",
    "EXACT_PROJECT_ROOT",
    "FINDING_CATEGORIES",
    "GATE_ROLE",
    "PRODUCER_NAME",
    "PRODUCER_VERSION",
    "REPORT_SCHEMA",
    "RevocationSurfaceError",
    "SURFACE_IDS",
    "produce_production_report",
    "replay_production_report",
    "validate_report",
    "write_report_create_only",
]
