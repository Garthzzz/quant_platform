"""Pure inventory gate for product surfaces removed from the local-prior product.

The caller supplies a logical root and a closed inventory.  This module performs
no filesystem, registry, scheduler, network, deployment, or deletion operation.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import PurePosixPath
import re
from typing import Mapping, Sequence
import unicodedata


CANCELLED_MODULE_SURFACES = (
    "cold_bundle",
    "cold_restore",
    "recovery_bundle",
    "failure_domain",
    "state_only_backup",
    "publish_recovery",
    "operational_source",
    "production_host_facts",
    "writer_handoff_client",
    "restore_cold_bundle",
    "checkpoint_cli",
)

LEGITIMATE_OPERATION_IDENTITIES = (
    "c_to_d_final_state_migration",
    "semantic_promotion_checkpoint",
    "mcp_installer_byte_rollback",
    "active_prior_rollback",
    "ds_campaign_replay",
)

_INVENTORY_FIELDS = {
    "source_tree",
    "installed_wheel_entry_names",
    "console_entrypoints",
    "config_schema_filenames",
    "runbook_filenames",
    "scheduled_task_names",
}
_SOURCE_RECORD_FIELDS = {"path", "source"}
_ENTRYPOINT_RECORD_FIELDS = {"name", "target"}
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_ACRONYM_BOUNDARY_RE = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ENTRYPOINT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")
_ENTRYPOINT_TARGET_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_.]*(?::[A-Za-z_][A-Za-z0-9_.]*)?$"
)

_CANCELLED_SIGNATURES = tuple(
    tuple(surface.split("_")) for surface in CANCELLED_MODULE_SURFACES
)
_CONFIG_SIGNATURES = (
    *_CANCELLED_SIGNATURES,
    ("recovery",),
    ("recovery", "protection"),
    ("checkpoint", "manifest"),
    ("state", "only", "task", "authority"),
    ("scheduled", "task", "authority"),
    ("backup",),
)
_RUNBOOK_SIGNATURES = (
    *_CANCELLED_SIGNATURES,
    ("recovery",),
    ("recovery", "protection"),
    ("cross", "host"),
    ("backup",),
)
_SCHEDULED_TASK_SIGNATURES = (
    *_CANCELLED_SIGNATURES,
    ("recovery",),
    ("recovery", "protection"),
    ("backup",),
)
_CONSOLE_SIGNATURES = (
    *_CANCELLED_SIGNATURES,
    ("recovery", "protection"),
)
_DYNAMIC_CAPABILITY_NAMES = {
    "__import__",
    "compile",
    "eval",
    "exec",
    "find_spec",
    "import_module",
}
_DYNAMIC_CAPABILITY_MODULE_NAMES = {"__builtins__", "builtins", "importlib"}
_ALLOWED_IMPORTLIB_RESOURCE_NAMES = {"as_file", "files"}
_ALLOWED_IMPORTLIB_METADATA_NAMES = {"metadata"}
_STATIC_CAPABILITY_IDENTIFIERS = (
    _DYNAMIC_CAPABILITY_NAMES
    | _DYNAMIC_CAPABILITY_MODULE_NAMES
    | {"__loader__", "load_module"}
)
_CapabilityAliases = tuple[
    frozenset[str],
    frozenset[str],
    frozenset[str],
    frozenset[str],
    frozenset[str],
]


@dataclass(frozen=True, slots=True, order=True)
class LocalProductSurfaceViolation:
    category: str
    code: str
    identity: str
    detail: str

    def render(self) -> str:
        return f"[{self.category}.{self.code}] {self.identity}: {self.detail}"


@dataclass(frozen=True, slots=True)
class LocalProductSurfaceReport:
    root: str
    source_file_count: int
    installed_wheel_entry_count: int
    console_entrypoint_count: int
    config_schema_count: int
    runbook_count: int
    scheduled_task_count: int
    violations: tuple[LocalProductSurfaceViolation, ...]

    @property
    def passed(self) -> bool:
        return not self.violations


class LocalProductSurfaceError(ValueError):
    def __init__(self, report: LocalProductSurfaceReport) -> None:
        self.report = report
        rendered = "; ".join(item.render() for item in report.violations)
        super().__init__(
            f"local product surface has {len(report.violations)} violation(s): "
            f"{rendered}"
        )


def _violation(
    violations: list[LocalProductSurfaceViolation],
    *,
    category: str,
    code: str,
    identity: object,
    detail: str,
) -> None:
    violations.append(
        LocalProductSurfaceViolation(
            category=category,
            code=code,
            identity=identity if isinstance(identity, str) else repr(identity),
            detail=detail,
        )
    )


def _tokens(value: str) -> tuple[str, ...]:
    normalized = unicodedata.normalize("NFKC", value)
    expanded = _ACRONYM_BOUNDARY_RE.sub("_", normalized)
    expanded = _CAMEL_BOUNDARY_RE.sub("_", expanded)
    tokens: list[str] = []
    current: list[str] = []
    for character in expanded:
        if character.isalnum():
            current.append(character.casefold())
        elif current:
            tokens.append("".join(current))
            current = []
    if current:
        tokens.append("".join(current))
    return tuple(tokens)


def _signature_match(
    value: str, signatures: Sequence[tuple[str, ...]]
) -> str | None:
    tokens = _tokens(value)
    for signature in signatures:
        compact = "".join(signature)
        for start in range(len(tokens)):
            maximum_width = min(len(signature), len(tokens) - start)
            for width in range(1, maximum_width + 1):
                if "".join(tokens[start : start + width]) == compact:
                    return "_".join(signature)
    return None


def _closed_mapping(
    value: object,
    fields: set[str],
    *,
    category: str,
    identity: str,
    violations: list[LocalProductSurfaceViolation],
) -> Mapping[str, object] | None:
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in value
    ):
        _violation(
            violations,
            category=category,
            code="closed_schema",
            identity=identity,
            detail="record must be a closed string-keyed object",
        )
        return None
    if set(value) != fields:
        missing = sorted(fields - set(value))
        extra = sorted(set(value) - fields)
        _violation(
            violations,
            category=category,
            code="closed_schema",
            identity=identity,
            detail=f"closed fields differ; missing={missing!r}, extra={extra!r}",
        )
    return value


def _list_field(
    inventory: Mapping[str, object],
    field: str,
    violations: list[LocalProductSurfaceViolation],
) -> list[object]:
    value = inventory.get(field)
    if not isinstance(value, list):
        _violation(
            violations,
            category=field.replace("_", " "),
            code="closed_schema",
            identity=field,
            detail="closed inventory field must be a list",
        )
        return []
    return list(value)


def _logical_path(
    value: object,
    *,
    category: str,
    identity: str,
    violations: list[LocalProductSurfaceViolation],
) -> tuple[str, str] | None:
    if not isinstance(value, str) or not value or _CONTROL_RE.search(value):
        _violation(
            violations,
            category=category,
            code="path_alias",
            identity=identity,
            detail="path must be non-empty control-free text",
        )
        return None
    normalized = unicodedata.normalize("NFKC", value)
    path = PurePosixPath(normalized)
    if (
        normalized != value
        or "\\" in value
        or path.is_absolute()
        or not path.parts
        or any(part in {".", ".."} for part in path.parts)
        or str(path) != normalized
    ):
        _violation(
            violations,
            category=category,
            code="path_alias",
            identity=value,
            detail="path is not exact canonical NFKC POSIX spelling",
        )
    return value, normalized.casefold()


def _root_identity(
    value: object, violations: list[LocalProductSurfaceViolation]
) -> str:
    result = _logical_path(
        value,
        category="root",
        identity="root",
        violations=violations,
    )
    if result is None:
        return "<invalid>"
    return result[0]


def _record_path_identity(
    identities: dict[str, str],
    *,
    normalized: str,
    rendered: str,
    category: str,
    violations: list[LocalProductSurfaceViolation],
) -> None:
    previous = identities.get(normalized)
    if previous is not None:
        _violation(
            violations,
            category=category,
            code="path_identity_collision",
            identity=rendered,
            detail=f"path identity collides with {previous!r}",
        )
    else:
        identities[normalized] = rendered


def _cancelled_path_surface(
    path: str,
    *,
    category: str,
    violations: list[LocalProductSurfaceViolation],
) -> None:
    normalized = unicodedata.normalize("NFKC", path).replace("\\", "/")
    for component in normalized.split("/"):
        match = _signature_match(component, _CANCELLED_SIGNATURES)
        if match is not None:
            _violation(
                violations,
                category=category,
                code="cancelled_surface",
                identity=path,
                detail=f"matches cancelled module surface {match}",
            )
            return


def _dynamic_capability_violation(
    source_path: str,
    node: ast.AST,
    capability: str,
    violations: list[LocalProductSurfaceViolation],
) -> None:
    _violation(
        violations,
        category="AST import",
        code="dynamic_capability_forbidden",
        identity=f"{source_path}:{getattr(node, 'lineno', 0)}",
        detail=(
            f"dynamic import/code capability {capability!r} is forbidden in "
            "the closed product source surface"
        ),
    )


def _cancelled_import(
    target: str,
    *,
    source_path: str,
    kind: str,
    violations: list[LocalProductSurfaceViolation],
) -> None:
    match = _signature_match(target, _CANCELLED_SIGNATURES)
    if match is not None:
        _violation(
            violations,
            category="AST import",
            code="cancelled_surface",
            identity=f"{source_path}:{target}",
            detail=f"{kind} reaches cancelled module surface {match}",
        )


def _static_string(node: ast.AST) -> str | None:
    """Fold only syntax whose string value is mechanically self-evident."""

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string(node.left)
        right = _static_string(node.right)
        return None if left is None or right is None else left + right
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                pieces.append(value.value)
                continue
            if (
                isinstance(value, ast.FormattedValue)
                and value.conversion in {-1, 115}
            ):
                format_spec = (
                    ""
                    if value.format_spec is None
                    else _static_string(value.format_spec)
                )
                folded = _static_string(value.value)
                if folded is not None and format_spec in {"", "s"}:
                    pieces.append(folded)
                    continue
            return None
        return "".join(pieces)
    return None


def _normalized_static_identity(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


def _static_lookup_key(node: ast.AST) -> str | None:
    value = _static_string(node)
    return None if value is None else _normalized_static_identity(value)


def _is_named_call(node: ast.AST, names: set[str]) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in names
    )


def _is_sys_modules(
    node: ast.AST,
    sys_names: set[str] | frozenset[str],
    sys_module_names: frozenset[str],
) -> bool:
    if isinstance(node, ast.Name) and node.id in sys_module_names:
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in sys_names
        and _static_lookup_key(node.args[1]) == "modules"
    ):
        return True
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in sys_names
        and node.attr == "modules"
    )


def _is_local_namespace_mapping(
    node: ast.AST,
    namespace_names: frozenset[str],
    namespace_factory_names: frozenset[str],
) -> bool:
    if isinstance(node, ast.Name) and node.id in namespace_names:
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id
        in ({"globals", "vars"} | set(namespace_factory_names))
        and not node.args
        and not node.keywords
    )


def _is_sys_state_mapping(
    node: ast.AST,
    sys_names: set[str] | frozenset[str],
    sys_state_names: set[str] | frozenset[str],
) -> bool:
    if isinstance(node, ast.Name) and node.id in sys_state_names:
        return True
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in sys_names
        and _static_lookup_key(node.args[1]) == "__dict__"
    ):
        return True
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in sys_names
        and node.attr == "__dict__"
    ):
        return True
    return (
        _is_named_call(node, {"vars"})
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in sys_names
    )


def _static_mapping_lookup(
    node: ast.AST,
    sys_names: set[str] | frozenset[str],
    sys_module_names: frozenset[str],
    sys_state_names: set[str] | frozenset[str],
    namespace_names: frozenset[str],
    namespace_factory_names: frozenset[str],
) -> tuple[str, str] | None:
    """Return (mapping kind, folded key) for a closed lookup expression."""

    if isinstance(node, ast.Subscript):
        key = _static_lookup_key(node.slice)
        if key is not None and _is_sys_modules(
            node.value, sys_names, sys_module_names
        ):
            return "sys.modules", key
        if key is not None and _is_sys_state_mapping(
            node.value, sys_names, sys_state_names
        ):
            return "sys.state", key
        if key is not None and _is_local_namespace_mapping(
            node.value, namespace_names, namespace_factory_names
        ):
            return "namespace", key
        return None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"__getitem__", "get", "pop", "setdefault"}
        and node.args
    ):
        key = _static_lookup_key(node.args[0])
        if key is not None and _is_sys_modules(
            node.func.value, sys_names, sys_module_names
        ):
            return "sys.modules", key
        if key is not None and _is_sys_state_mapping(
            node.func.value, sys_names, sys_state_names
        ):
            return "sys.state", key
        if key is not None and _is_local_namespace_mapping(
            node.func.value, namespace_names, namespace_factory_names
        ):
            return "namespace", key
    return None


def _is_sensitive_getattr_base(
    node: ast.AST,
    sys_names: set[str] | frozenset[str],
    sys_module_names: frozenset[str],
    sys_state_names: set[str] | frozenset[str],
    namespace_names: frozenset[str],
    namespace_factory_names: frozenset[str],
) -> bool:
    if _is_sys_modules(node, sys_names, sys_module_names):
        return True
    lookup = _static_mapping_lookup(
        node,
        sys_names,
        sys_module_names,
        sys_state_names,
        namespace_names,
        namespace_factory_names,
    )
    if lookup is None:
        return False
    kind, key = lookup
    if kind == "sys.modules":
        return True
    if kind == "sys.state":
        return key == "modules"
    return key in _DYNAMIC_CAPABILITY_MODULE_NAMES


def _capability_aliases_by_node(
    tree: ast.Module,
) -> dict[int, _CapabilityAliases]:
    """Bind presence-based simple aliases through bounded lexical scopes.

    Each scope first closes its own control-block Assign/AnnAssign fixed point.
    The resulting aliases flow only from a lexical parent into a child.  Class
    locals are visible while evaluating the class body and declarations, but
    are not ordinary closure cells for methods, nested classes, or lambdas.
    """

    bindings: dict[int, _CapabilityAliases] = {}
    scope_types = (
        ast.FunctionDef,
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.Lambda,
    )
    def declaration_expressions(node: ast.AST) -> tuple[ast.AST, ...]:
        expressions: list[ast.AST] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            expressions.extend(node.decorator_list)
            expressions.append(node.args)
            if node.returns is not None:
                expressions.append(node.returns)
            expressions.extend(getattr(node, "type_params", ()))
        elif isinstance(node, ast.ClassDef):
            expressions.extend(node.decorator_list)
            expressions.extend(node.bases)
            expressions.extend(node.keywords)
            expressions.extend(getattr(node, "type_params", ()))
        elif isinstance(node, ast.Lambda):
            expressions.append(node.args)
        return tuple(expressions)

    def scope_body(node: ast.AST) -> tuple[ast.AST, ...]:
        if isinstance(node, ast.Lambda):
            return (node.body,)
        if isinstance(
            node,
            (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            return tuple(node.body)
        raise TypeError(f"unsupported lexical scope {type(node).__name__}")

    def close_scope(scope: ast.AST, inherited: _CapabilityAliases) -> None:
        (
            inherited_sys_names,
            inherited_sys_module_names,
            inherited_sys_state_names,
            inherited_namespace_names,
            inherited_namespace_factory_names,
        ) = inherited
        sys_names = set(inherited_sys_names)
        sys_module_names = set(inherited_sys_module_names)
        sys_state_names = set(inherited_sys_state_names)
        namespace_names = set(inherited_namespace_names)
        namespace_factory_names = set(inherited_namespace_factory_names)
        assignments: list[tuple[str, ast.AST]] = []

        def collect_scope_facts(node: ast.AST) -> None:
            # if/try/loop/with/match stay in this lexical scope.  A real nested
            # scope is closed independently and never sends assignments back.
            if isinstance(node, scope_types):
                return
            if isinstance(node, ast.Import):
                for imported in node.names:
                    normalized = _normalized_static_identity(imported.name)
                    if normalized == "sys":
                        sys_names.add(imported.asname or "sys")
                    elif normalized == "sys.modules":
                        if imported.asname is None:
                            sys_names.add("sys")
                        else:
                            sys_module_names.add(imported.asname)
            elif (
                isinstance(node, ast.ImportFrom)
                and node.level == 0
                and _normalized_static_identity(node.module or "") == "sys"
            ):
                for imported in node.names:
                    if _normalized_static_identity(imported.name) == "__dict__":
                        sys_state_names.add(imported.asname or imported.name)

            target: ast.AST | None = None
            value: ast.AST | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target = node.targets[0]
                value = node.value
            elif isinstance(node, ast.AnnAssign):
                target = node.target
                value = node.value
            if isinstance(target, ast.Name) and value is not None:
                assignments.append((target.id, value))
            for child in ast.iter_child_nodes(node):
                collect_scope_facts(child)

        body = scope_body(scope)
        for statement in body:
            collect_scope_facts(statement)

        for _ in range(len(assignments) + 1):
            before = (
                len(sys_names),
                len(sys_module_names),
                len(sys_state_names),
                len(namespace_names),
                len(namespace_factory_names),
            )
            for name, value in assignments:
                if isinstance(value, ast.Name) and value.id in sys_names:
                    sys_names.add(name)
                if _is_sys_modules(
                    value, sys_names, frozenset(sys_module_names)
                ):
                    sys_module_names.add(name)
                if _is_sys_state_mapping(value, sys_names, sys_state_names):
                    sys_state_names.add(name)
                if _is_local_namespace_mapping(
                    value,
                    frozenset(namespace_names),
                    frozenset(namespace_factory_names),
                ):
                    namespace_names.add(name)
                if (
                    isinstance(value, ast.Name)
                    and value.id
                    in ({"globals", "vars"} | namespace_factory_names)
                ):
                    namespace_factory_names.add(name)
            after = (
                len(sys_names),
                len(sys_module_names),
                len(sys_state_names),
                len(namespace_names),
                len(namespace_factory_names),
            )
            if after == before:
                break

        frozen: _CapabilityAliases = (
            frozenset(sys_names),
            frozenset(sys_module_names),
            frozenset(sys_state_names),
            frozenset(namespace_names),
            frozenset(namespace_factory_names),
        )
        nested_inheritance = inherited if isinstance(scope, ast.ClassDef) else frozen
        if isinstance(scope, ast.Module):
            bindings[id(scope)] = frozen

        def bind(
            node: ast.AST,
            visible: _CapabilityAliases,
            child_inheritance: _CapabilityAliases,
        ) -> None:
            bindings[id(node)] = visible
            if isinstance(node, scope_types):
                for expression in declaration_expressions(node):
                    bind(expression, visible, child_inheritance)
                close_scope(node, child_inheritance)
                return
            for child in ast.iter_child_nodes(node):
                bind(child, visible, child_inheritance)

        for statement in body:
            bind(statement, frozen, nested_inheritance)

    empty_aliases: _CapabilityAliases = (
        frozenset({"sys"}),
        frozenset(),
        frozenset(),
        frozenset(),
        frozenset(),
    )
    close_scope(tree, empty_aliases)
    return bindings


def _scan_dynamic_capability_policy(
    tree: ast.AST,
    *,
    source_path: str,
    violations: list[LocalProductSurfaceViolation],
) -> None:
    """Reject dynamic import/code authority by presence, not target analysis.

    Product source has no need to manufacture Python import or code-execution
    authority.  The sole importlib exception is a closed, direct import of a
    known resource reader; it never binds the base ``importlib`` module.
    """

    alias_bindings = _capability_aliases_by_node(tree)
    default_aliases = (
        frozenset({"sys"}),
        frozenset(),
        frozenset(),
        frozenset(),
        frozenset(),
    )

    for node in ast.walk(tree):
        (
            scoped_sys_names,
            sys_module_names,
            scoped_sys_state_names,
            namespace_names,
            namespace_factory_names,
        ) = alias_bindings.get(
            id(node), default_aliases
        )
        if isinstance(node, ast.Import):
            for alias in node.names:
                components = _normalized_static_identity(alias.name).split(".")
                if any(
                    component in _STATIC_CAPABILITY_IDENTIFIERS
                    for component in components
                ):
                    _dynamic_capability_violation(
                        source_path, node, alias.name, violations
                    )
                elif (
                    alias.asname is not None
                    and _normalized_static_identity(alias.asname)
                    in _STATIC_CAPABILITY_IDENTIFIERS
                ):
                    _dynamic_capability_violation(
                        source_path, node, alias.asname, violations
                    )
            continue

        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            normalized_module = unicodedata.normalize("NFKC", module).casefold()
            resource_import_is_closed = (
                node.level == 0
                and module == "importlib.resources"
                and bool(node.names)
                and all(
                    alias.name in _ALLOWED_IMPORTLIB_RESOURCE_NAMES
                    and _normalized_static_identity(alias.asname or alias.name)
                    not in _STATIC_CAPABILITY_IDENTIFIERS
                    for alias in node.names
                )
            )
            metadata_import_is_closed = (
                node.level == 0
                and module == "importlib"
                and bool(node.names)
                and all(
                    alias.name in _ALLOWED_IMPORTLIB_METADATA_NAMES
                    and _normalized_static_identity(alias.asname or alias.name)
                    not in _STATIC_CAPABILITY_IDENTIFIERS
                    for alias in node.names
                )
            )
            if resource_import_is_closed or metadata_import_is_closed:
                continue
            for alias in node.names:
                normalized_alias = _normalized_static_identity(alias.name)
                normalized_binding = _normalized_static_identity(
                    alias.asname or alias.name
                )
                if (
                    normalized_alias in _STATIC_CAPABILITY_IDENTIFIERS
                    or normalized_binding in _STATIC_CAPABILITY_IDENTIFIERS
                ):
                    _dynamic_capability_violation(
                        source_path,
                        node,
                        alias.asname or alias.name,
                        violations,
                    )
            if any(
                component in _STATIC_CAPABILITY_IDENTIFIERS
                for component in normalized_module.split(".")
            ):
                _dynamic_capability_violation(
                    source_path, node, module or "<relative>", violations
                )
                continue
            if normalized_module == "sys" and any(
                _normalized_static_identity(alias.name) == "modules"
                for alias in node.names
            ):
                _dynamic_capability_violation(
                    source_path, node, "sys.modules", violations
                )
            continue

        if (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and _normalized_static_identity(node.id)
            in _STATIC_CAPABILITY_IDENTIFIERS
        ):
            _dynamic_capability_violation(
                source_path, node, node.id, violations
            )
            continue

        if isinstance(node, ast.Attribute):
            normalized_attribute = _normalized_static_identity(node.attr)
            if (
                normalized_attribute in _STATIC_CAPABILITY_IDENTIFIERS
                and normalized_attribute != "compile"
            ):
                _dynamic_capability_violation(
                    source_path, node, node.attr, violations
                )
            elif _is_sys_modules(
                node, scoped_sys_names, sys_module_names
            ):
                _dynamic_capability_violation(
                    source_path, node, "sys.modules", violations
                )
            continue

        lookup = _static_mapping_lookup(
            node,
            scoped_sys_names,
            sys_module_names,
            scoped_sys_state_names,
            namespace_names,
            namespace_factory_names,
        )
        if lookup is not None:
            mapping_kind, key = lookup
            if (
                mapping_kind in {"namespace", "sys.modules"}
                and key in _STATIC_CAPABILITY_IDENTIFIERS
            ) or (mapping_kind == "sys.state" and key == "modules"):
                _dynamic_capability_violation(
                    source_path,
                    node,
                    f"{mapping_kind}[{key!r}]",
                    violations,
                )

        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
        ):
            attribute = _static_lookup_key(node.args[1])
            if (
                attribute in _STATIC_CAPABILITY_IDENTIFIERS
                and attribute != "compile"
            ):
                _dynamic_capability_violation(
                    source_path,
                    node,
                    f"getattr(..., {attribute!r})",
                    violations,
                )
            elif (
                attribute == "modules"
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in scoped_sys_names
            ):
                _dynamic_capability_violation(
                    source_path, node, "getattr(sys, 'modules')", violations
                )
            elif attribute is None and _is_sensitive_getattr_base(
                node.args[0],
                scoped_sys_names,
                sys_module_names,
                scoped_sys_state_names,
                namespace_names,
                namespace_factory_names,
            ):
                _dynamic_capability_violation(
                    source_path,
                    node,
                    "dynamic getattr on a module-capability result",
                    violations,
                )


def _scan_source_ast(
    source_path: str,
    source: object,
    violations: list[LocalProductSurfaceViolation],
) -> None:
    if not isinstance(source, str):
        _violation(
            violations,
            category="source tree",
            code="closed_schema",
            identity=source_path,
            detail="source must be text",
        )
        return
    if not source_path.casefold().endswith((".py", ".pyi")):
        return
    try:
        tree = ast.parse(source, filename=source_path)
    except (SyntaxError, ValueError) as error:
        _violation(
            violations,
            category="AST import",
            code="parse_error",
            identity=source_path,
            detail=f"Python source cannot be parsed: {getattr(error, 'msg', str(error))}",
        )
        return

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                _cancelled_import(
                    alias.name,
                    source_path=source_path,
                    kind="import",
                    violations=violations,
                )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            _cancelled_import(
                module,
                source_path=source_path,
                kind="from import",
                violations=violations,
            )
            for alias in node.names:
                _cancelled_import(
                    f"{module}.{alias.name}",
                    source_path=source_path,
                    kind="from import",
                    violations=violations,
                )

    _scan_dynamic_capability_policy(
        tree,
        source_path=source_path,
        violations=violations,
    )


def _scan_source_tree(
    records: list[object], violations: list[LocalProductSurfaceViolation]
) -> None:
    path_identities: dict[str, str] = {}
    for index, raw in enumerate(records):
        record = _closed_mapping(
            raw,
            _SOURCE_RECORD_FIELDS,
            category="source tree",
            identity=f"source_tree[{index}]",
            violations=violations,
        )
        if record is None:
            continue
        path_result = _logical_path(
            record.get("path"),
            category="source tree",
            identity=f"source_tree[{index}].path",
            violations=violations,
        )
        if path_result is None:
            continue
        path, normalized = path_result
        _record_path_identity(
            path_identities,
            normalized=normalized,
            rendered=path,
            category="source tree",
            violations=violations,
        )
        _cancelled_path_surface(
            path,
            category="source tree",
            violations=violations,
        )
        _scan_source_ast(path, record.get("source"), violations)


def _scan_path_names(
    values: list[object],
    *,
    category: str,
    signatures: Sequence[tuple[str, ...]] | None,
    violations: list[LocalProductSurfaceViolation],
) -> None:
    path_identities: dict[str, str] = {}
    for index, raw in enumerate(values):
        result = _logical_path(
            raw,
            category=category,
            identity=f"{category}[{index}]",
            violations=violations,
        )
        if result is None:
            continue
        rendered, normalized = result
        _record_path_identity(
            path_identities,
            normalized=normalized,
            rendered=rendered,
            category=category,
            violations=violations,
        )
        if category == "installed wheel entry":
            _cancelled_path_surface(
                rendered,
                category=category,
                violations=violations,
            )
        elif signatures is not None:
            match = _signature_match(rendered, signatures)
            if match is not None:
                _violation(
                    violations,
                    category=category,
                    code="cancelled_surface",
                    identity=rendered,
                    detail=f"matches cancelled {category} identity {match}",
                )


def _scan_entrypoints(
    records: list[object], violations: list[LocalProductSurfaceViolation]
) -> None:
    name_identities: dict[str, str] = {}
    for index, raw in enumerate(records):
        record = _closed_mapping(
            raw,
            _ENTRYPOINT_RECORD_FIELDS,
            category="console entrypoint",
            identity=f"console_entrypoints[{index}]",
            violations=violations,
        )
        if record is None:
            continue
        name = record.get("name")
        if not isinstance(name, str):
            _violation(
                violations,
                category="console entrypoint",
                code="closed_schema",
                identity=f"console_entrypoints[{index}].name",
                detail="entrypoint name must be text",
            )
        else:
            normalized_name = unicodedata.normalize("NFKC", name)
            if (
                normalized_name != name
                or _ENTRYPOINT_NAME_RE.fullmatch(name) is None
                or _CONTROL_RE.search(name)
            ):
                _violation(
                    violations,
                    category="console entrypoint",
                    code="name_alias",
                    identity=name,
                    detail="entrypoint name is not exact canonical spelling",
                )
            identity = normalized_name.casefold()
            previous = name_identities.get(identity)
            if previous is not None:
                _violation(
                    violations,
                    category="console entrypoint",
                    code="name_identity_collision",
                    identity=name,
                    detail=f"name identity collides with {previous!r}",
                )
            else:
                name_identities[identity] = name
            match = _signature_match(name, _CONSOLE_SIGNATURES)
            if match is not None:
                _violation(
                    violations,
                    category="console entrypoint",
                    code="cancelled_surface",
                    identity=name,
                    detail=f"name exposes cancelled qrh surface {match}",
                )

        target = record.get("target")
        if not isinstance(target, str):
            _violation(
                violations,
                category="console entrypoint",
                code="closed_schema",
                identity=f"console_entrypoints[{index}].target",
                detail="entrypoint target must be text",
            )
            continue
        normalized_target = unicodedata.normalize("NFKC", target)
        if (
            normalized_target != target
            or _ENTRYPOINT_TARGET_RE.fullmatch(target) is None
            or _CONTROL_RE.search(target)
        ):
            _violation(
                violations,
                category="console entrypoint",
                code="target_alias",
                identity=target,
                detail="entrypoint target is not exact import mapping spelling",
            )
        module = normalized_target.split(":", 1)[0]
        match = _signature_match(module, _CONSOLE_SIGNATURES)
        if match is not None:
            _violation(
                violations,
                category="console entrypoint",
                code="cancelled_surface",
                identity=target,
                detail=f"target reaches cancelled module surface {match}",
            )


def _scheduled_task_name(
    value: object,
    *,
    index: int,
    violations: list[LocalProductSurfaceViolation],
) -> tuple[str, str] | None:
    identity = f"scheduled task[{index}]"
    if not isinstance(value, str) or not value or _CONTROL_RE.search(value):
        _violation(
            violations,
            category="scheduled task",
            code="path_alias",
            identity=identity,
            detail="task name must be non-empty control-free text",
        )
        return None
    normalized = unicodedata.normalize("NFKC", value)
    parts = normalized.split("\\")
    if (
        normalized != value
        or "/" in value
        or not value.startswith("\\")
        or value.startswith("\\\\")
        or len(parts) < 2
        or parts[0] != ""
        or any(not part or part in {".", ".."} for part in parts[1:])
        or "\\" + "\\".join(parts[1:]) != value
    ):
        _violation(
            violations,
            category="scheduled task",
            code="path_alias",
            identity=value,
            detail="task name is not exact canonical NFKC scheduler path",
        )
    return value, normalized.casefold()


def _scan_scheduled_tasks(
    values: list[object], violations: list[LocalProductSurfaceViolation]
) -> None:
    identities: dict[str, str] = {}
    for index, raw in enumerate(values):
        result = _scheduled_task_name(
            raw,
            index=index,
            violations=violations,
        )
        if result is None:
            continue
        rendered, normalized = result
        previous = identities.get(normalized)
        if previous is not None:
            _violation(
                violations,
                category="scheduled task",
                code="name_identity_collision",
                identity=rendered,
                detail=f"task name identity collides with {previous!r}",
            )
        else:
            identities[normalized] = rendered
        match = _signature_match(rendered, _SCHEDULED_TASK_SIGNATURES)
        if match is not None:
            _violation(
                violations,
                category="scheduled task",
                code="cancelled_surface",
                identity=rendered,
                detail=f"matches cancelled scheduled task identity {match}",
            )


def scan_local_product_surface(
    *,
    root: object,
    inventory: object,
) -> LocalProductSurfaceReport:
    """Scan only the supplied inventory and return every exact violation."""

    violations: list[LocalProductSurfaceViolation] = []
    rendered_root = _root_identity(root, violations)
    document = _closed_mapping(
        inventory,
        _INVENTORY_FIELDS,
        category="inventory",
        identity="inventory",
        violations=violations,
    )
    if document is None:
        document = {}

    source_tree = _list_field(document, "source_tree", violations)
    wheel_entries = _list_field(
        document, "installed_wheel_entry_names", violations
    )
    entrypoints = _list_field(document, "console_entrypoints", violations)
    config_schemas = _list_field(
        document, "config_schema_filenames", violations
    )
    runbooks = _list_field(document, "runbook_filenames", violations)
    scheduled_tasks = _list_field(
        document, "scheduled_task_names", violations
    )

    _scan_source_tree(source_tree, violations)
    _scan_path_names(
        wheel_entries,
        category="installed wheel entry",
        signatures=None,
        violations=violations,
    )
    _scan_entrypoints(entrypoints, violations)
    _scan_path_names(
        config_schemas,
        category="config schema",
        signatures=_CONFIG_SIGNATURES,
        violations=violations,
    )
    _scan_path_names(
        runbooks,
        category="runbook",
        signatures=_RUNBOOK_SIGNATURES,
        violations=violations,
    )
    _scan_scheduled_tasks(scheduled_tasks, violations)

    return LocalProductSurfaceReport(
        root=rendered_root,
        source_file_count=len(source_tree),
        installed_wheel_entry_count=len(wheel_entries),
        console_entrypoint_count=len(entrypoints),
        config_schema_count=len(config_schemas),
        runbook_count=len(runbooks),
        scheduled_task_count=len(scheduled_tasks),
        violations=tuple(sorted(set(violations))),
    )


def validate_local_product_surface(
    *,
    root: object,
    inventory: object,
) -> LocalProductSurfaceReport:
    report = scan_local_product_surface(root=root, inventory=inventory)
    if report.violations:
        raise LocalProductSurfaceError(report)
    return report


__all__ = [
    "CANCELLED_MODULE_SURFACES",
    "LEGITIMATE_OPERATION_IDENTITIES",
    "LocalProductSurfaceError",
    "LocalProductSurfaceReport",
    "LocalProductSurfaceViolation",
    "scan_local_product_surface",
    "validate_local_product_surface",
]
