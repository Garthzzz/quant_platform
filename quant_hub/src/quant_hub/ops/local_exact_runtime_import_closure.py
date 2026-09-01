"""Lease-bound exact-release import closure for the Windows service child.

The production constructor accepts only the live writer lease.  It derives the
one release from that lease record, verifies the persisted D-root tooling claim,
pins the release manifest and every inventory member, and only then changes the
already-loaded regular ``quant_hub`` package search path.  ``quant_hub.ops``
remains bound to the installed tooling package.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import inspect
import json
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import unicodedata

from .local_exact_runtime_tooling import (
    EXACT_RUNTIME_PACKAGE_RELATIVE_PATH,
    ExactRuntimeToolingManifest,
)
from .local_exact_runtime_tooling_scanner import (
    ExactRuntimeToolingScanError,
    ProductionExactRuntimeToolingVerifier,
    _WindowsNamespaceChangeMonitor,
    _WindowsReadGuardSet,
    _bounded_file_bytes,
    _closed_directory,
    _closed_existing_ancestor_chain,
    _file_digest,
    _identity,
    _is_reparse,
    _relative_path,
    _walk_package,
)
from .local_release_identity import (
    LocalReleaseIdentityError,
    PRODUCTION_VM_ROOT,
    canonical_bytes,
    identity_sha256,
    validate_release_manifest,
)
from .local_windows_writer_lease_holder import (
    LockedSteadyWindowsWriterLease,
    LockedWindowsWriterLease,
)


_PRODUCTION_ROOT = PureWindowsPath(PRODUCTION_VM_ROOT)
_PRODUCTION_TOOLING_PACKAGE = (
    _PRODUCTION_ROOT.joinpath(*PurePosixPath(EXACT_RUNTIME_PACKAGE_RELATIVE_PATH).parts)
)
_RELEASE_APPLICATION_RELATIVE = PurePosixPath(
    "runtime_contract/code/src/quant_hub"
)
_MAX_RELEASE_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_RELEASE_ENTRIES = 200_000
_CONSTRUCTION_TOKEN = object()
_TEST_ONLY_TOKEN = object()
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258

_REQUIRED_APPLICATION_FILES = {
    "runtime_contract/code/src/quant_hub/__init__.py",
    "runtime_contract/code/src/quant_hub/app.py",
    "runtime_contract/code/src/quant_hub/config.py",
    "runtime_contract/code/src/quant_hub/archive/contracts.py",
    "runtime_contract/code/src/quant_hub/collaboration/service.py",
    "runtime_contract/code/src/quant_hub/platform/db.py",
    "runtime_contract/code/src/quant_hub/research_workspace/service.py",
}
_ACCESS_GATE_APPLICATION_FILE = (
    "runtime_contract/code/src/quant_hub/web/access_gate.py"
)


class ExactRuntimeImportClosureError(RuntimeError):
    """The tooling/release/import lookup boundary could not be closed."""


def _path(root: Path, relative: str | PurePosixPath) -> Path:
    parsed = PurePosixPath(relative)
    return root.joinpath(*parsed.parts)


def _manifest(root: Path) -> tuple[bytes, dict[str, object]]:
    path = root / "release_manifest.json"
    try:
        raw = _bounded_file_bytes(path, maximum_bytes=_MAX_RELEASE_MANIFEST_BYTES)
        decoded = json.loads(raw.decode("utf-8"))
        if type(decoded) is not dict or canonical_bytes(decoded) != raw:
            raise ExactRuntimeImportClosureError(
                "exact release manifest bytes are not canonical"
            )
        validated = validate_release_manifest(decoded)
        document = json.loads(canonical_bytes(validated).decode("utf-8"))
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        LocalReleaseIdentityError,
        ExactRuntimeToolingScanError,
    ) as error:
        raise ExactRuntimeImportClosureError(
            "exact release manifest is invalid"
        ) from error
    if type(document) is not dict:
        raise ExactRuntimeImportClosureError(
            "exact release manifest clone is not an object"
        )
    return raw, document


def _expected_inventory(
    document: dict[str, object],
) -> tuple[tuple[dict[str, object], ...], frozenset[str]]:
    inventory = document.get("inventory")
    if type(inventory) is not dict or type(inventory.get("files")) is not list:
        raise ExactRuntimeImportClosureError("release inventory is unavailable")
    records = tuple(
        {
            "path": str(record["path"]),
            "bytes": int(record["bytes"]),
            "sha256": str(record["sha256"]),
        }
        for record in inventory["files"]
    )
    paths = {str(record["path"]) for record in records}
    application = document.get("application")
    source_kind = (
        application.get("source_kind") if type(application) is dict else None
    )
    required = set(_REQUIRED_APPLICATION_FILES)
    if source_kind == "git":
        required.add(_ACCESS_GATE_APPLICATION_FILE)
    elif source_kind != "legacy_broadcast":
        raise ExactRuntimeImportClosureError(
            "exact release application source kind is invalid"
        )
    if not required.issubset(paths):
        missing = sorted(required - paths)
        raise ExactRuntimeImportClosureError(
            "exact release lacks required application files: " + ",".join(missing)
        )
    directories = {""}
    for relative in paths:
        parts = PurePosixPath(relative).parts[:-1]
        for index in range(1, len(parts) + 1):
            directories.add(PurePosixPath(*parts[:index]).as_posix())
    return records, frozenset(directories)


def _scan_release_tree(
    root: Path,
) -> tuple[tuple[dict[str, object], ...], frozenset[str]]:
    members: list[dict[str, object]] = []
    directories = {""}
    identities: dict[str, tuple[str, str]] = {}

    def remember(relative: str, role: str) -> None:
        logical = unicodedata.normalize("NFKC", relative).casefold()
        previous = identities.get(logical)
        if previous is not None and previous != (relative, role):
            raise ExactRuntimeImportClosureError(
                "release tree has a path identity collision"
            )
        identities[logical] = (relative, role)

    def visit(directory: Path) -> None:
        before = _closed_directory(directory)
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise ExactRuntimeImportClosureError(
                f"release directory enumeration failed: {directory}"
            ) from error
        for child in children:
            relative = _relative_path(child, root)
            try:
                info = child.lstat()
            except OSError as error:
                raise ExactRuntimeImportClosureError(
                    f"release member is unreadable: {relative}"
                ) from error
            if _is_reparse(info):
                raise ExactRuntimeImportClosureError(
                    f"release tree contains a reparse member: {relative}"
                )
            if stat.S_ISDIR(info.st_mode):
                remember(relative, "directory")
                directories.add(relative)
                visit(child)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ExactRuntimeImportClosureError(
                    f"release tree contains a non-file member: {relative}"
                )
            remember(relative, "file")
            if relative == "release_manifest.json":
                continue
            size, sha256 = _file_digest(child, allow_empty=True)
            members.append({"path": relative, "bytes": size, "sha256": sha256})
            if len(members) > _MAX_RELEASE_ENTRIES:
                raise ExactRuntimeImportClosureError(
                    "release inventory exceeds the entry limit"
                )
        after = _closed_directory(directory)
        if _identity(before) != _identity(after):
            raise ExactRuntimeImportClosureError(
                f"release directory drifted during scan: {directory}"
            )

    visit(root)
    members.sort(key=lambda item: str(item["path"]))
    return tuple(members), frozenset(directories)


def _assert_release_snapshot(
    root: Path,
    *,
    expected_release_id: str,
    expected_manifest_sha256: str,
) -> tuple[dict[str, object], tuple[Path, ...]]:
    manifest_raw, document = _manifest(root)
    if (
        document.get("release_id") != expected_release_id
        or identity_sha256(document) != expected_manifest_sha256
    ):
        raise ExactRuntimeImportClosureError(
            "lease release identity differs from the exact manifest"
        )
    expected_records, expected_directories = _expected_inventory(document)
    observed_records, observed_directories = _scan_release_tree(root)
    if (
        observed_records != expected_records
        or observed_directories != expected_directories
    ):
        raise ExactRuntimeImportClosureError(
            "release filesystem differs from its complete inventory"
        )
    guard_paths = (root / "release_manifest.json",) + tuple(
        _path(root, str(record["path"])) for record in expected_records
    )
    if len(manifest_raw) < 1:
        raise ExactRuntimeImportClosureError("release manifest is empty")
    return document, guard_paths


def _source_under_root(value: object, source_root: Path, *, label: str) -> None:
    source_name = inspect.getsourcefile(value)
    if type(source_name) is not str:
        raise ExactRuntimeImportClosureError(f"{label} source is unavailable")
    try:
        source = Path(source_name).resolve(strict=True)
        source.relative_to(source_root.resolve(strict=True))
        info = source.lstat()
    except (OSError, ValueError) as error:
        raise ExactRuntimeImportClosureError(
            f"{label} was not imported from its exact source root"
        ) from error
    if _is_reparse(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ExactRuntimeImportClosureError(
            f"{label} source is not a regular single-link release file"
        )


def _namespace_checkpoint(
    monitor: _WindowsNamespaceChangeMonitor | None,
    *,
    label: str,
) -> None:
    if os.name != "nt":
        return
    if type(monitor) is not _WindowsNamespaceChangeMonitor:
        raise ExactRuntimeImportClosureError(f"{label} namespace monitor is absent")
    event_handle = getattr(monitor, "_event_handle", None)
    if type(event_handle) is not int or event_handle < 1:
        raise ExactRuntimeImportClosureError(f"{label} namespace monitor is invalid")
    try:
        kernel32 = ctypes.WinDLL(
            "kernel32.dll",
            use_last_error=True,
            winmode=0x00000800,
        )
        wait_for_single_object = kernel32.WaitForSingleObject
        wait_for_single_object.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        wait_for_single_object.restype = wintypes.DWORD
        result = wait_for_single_object(event_handle, 0)
    except (AttributeError, OSError, TypeError) as error:
        raise ExactRuntimeImportClosureError(
            f"{label} namespace checkpoint API failed"
        ) from error
    if result == _WAIT_OBJECT_0:
        raise ExactRuntimeImportClosureError(
            f"{label} namespace changed while runtime was live"
        )
    if result != _WAIT_TIMEOUT:
        raise ExactRuntimeImportClosureError(
            f"{label} namespace checkpoint was inconclusive: {result}"
        )


def _tooling_live_guards(
    tooling_package: Path,
    manifest: ExactRuntimeToolingManifest,
) -> _WindowsReadGuardSet:
    if type(manifest) is not ExactRuntimeToolingManifest:
        raise ExactRuntimeImportClosureError("tooling manifest type is not exact")
    document = manifest.as_dict()
    package = document.get("package")
    if type(package) is not dict:
        raise ExactRuntimeImportClosureError("tooling package claim is absent")
    inventory = _walk_package(tooling_package)
    if (
        package.get("entry_count") != len(inventory)
        or package.get("inventory_sha256")
        != identity_sha256(list(inventory))
    ):
        raise ExactRuntimeImportClosureError(
            "live tooling package differs from persisted inventory"
        )
    relative_package = PurePosixPath(EXACT_RUNTIME_PACKAGE_RELATIVE_PATH)
    tooling_root = tooling_package
    for _part in relative_package.parts:
        tooling_root = tooling_root.parent
    if _path(tooling_root, relative_package).resolve(strict=True) != (
        tooling_package.resolve(strict=True)
    ):
        raise ExactRuntimeImportClosureError("tooling package root derivation drifted")
    paths = [
        _path(tooling_package, str(record["relative_path"]))
        for record in inventory
    ]
    for field in (
        "python",
        "service_host",
        "service_python_runtime",
        "service_pywin32_runtime",
    ):
        binary = document.get(field)
        if type(binary) is not dict or type(binary.get("relative_path")) is not str:
            raise ExactRuntimeImportClosureError(
                f"tooling {field} claim is absent"
            )
        paths.append(_path(tooling_root, str(binary["relative_path"])))
    guards = _WindowsReadGuardSet(tuple(paths))
    try:
        confirmed = _walk_package(tooling_package)
        if confirmed != inventory:
            raise ExactRuntimeImportClosureError(
                "tooling package drifted while acquiring live guards"
            )
    except BaseException:
        guards.close()
        raise
    return guards


class _LockedExactRuntimeImportClosure:
    __slots__ = (
        "_guards",
        "_lease",
        "_manifest",
        "_monitor",
        "_production",
        "_release_package",
        "_release_root",
        "_state",
        "_tooling_package",
        "_tooling_guards",
        "_tooling_monitor",
    )

    def __init__(
        self,
        *,
        release_root: Path,
        tooling_package: Path,
        expected_release_id: str,
        expected_manifest_sha256: str,
        lease: LockedWindowsWriterLease | LockedSteadyWindowsWriterLease | None,
        tooling_manifest: ExactRuntimeToolingManifest | None,
        production: bool,
        token: object,
    ):
        if token not in {_CONSTRUCTION_TOKEN, _TEST_ONLY_TOKEN}:
            raise TypeError("exact runtime import closure provenance is invalid")
        self._release_root = release_root
        self._release_package = _path(release_root, _RELEASE_APPLICATION_RELATIVE)
        self._tooling_package = tooling_package
        self._lease = lease
        self._production = production
        self._state = "acquiring"
        self._monitor = None
        self._guards = None
        self._tooling_monitor = None
        self._tooling_guards = None
        self._manifest: dict[str, object] | None = None

        try:
            if production and type(tooling_manifest) is not ExactRuntimeToolingManifest:
                raise ExactRuntimeImportClosureError(
                    "production tooling manifest is not exact"
                )
            if tooling_manifest is not None:
                if type(tooling_manifest) is not ExactRuntimeToolingManifest:
                    raise ExactRuntimeImportClosureError(
                        "tooling manifest is not exact"
                    )
                tooling_monitor = _WindowsNamespaceChangeMonitor(tooling_package)
                self._tooling_monitor = tooling_monitor
                self._tooling_guards = _tooling_live_guards(
                    tooling_package, tooling_manifest
                )
                _namespace_checkpoint(tooling_monitor, label="tooling package")
            _closed_existing_ancestor_chain(release_root)
            _closed_directory(release_root)
            monitor = _WindowsNamespaceChangeMonitor(release_root)
            self._monitor = monitor
            document, guard_paths = _assert_release_snapshot(
                release_root,
                expected_release_id=expected_release_id,
                expected_manifest_sha256=expected_manifest_sha256,
            )
            guards = _WindowsReadGuardSet(guard_paths)
            self._guards = guards
            confirmed, confirmed_paths = _assert_release_snapshot(
                release_root,
                expected_release_id=expected_release_id,
                expected_manifest_sha256=expected_manifest_sha256,
            )
            if confirmed != document or confirmed_paths != guard_paths:
                raise ExactRuntimeImportClosureError(
                    "release changed while acquiring open-instance guards"
                )
            self._manifest = document
            self._state = "live"
        except BaseException as error:
            self._close_acquired()
            if isinstance(error, ExactRuntimeToolingScanError):
                raise ExactRuntimeImportClosureError(
                    "release filesystem failed its exact scanner boundary"
                ) from error
            raise

    def _assert_live(self) -> None:
        if self._state != "live":
            raise ExactRuntimeImportClosureError(
                "exact runtime import closure is not live"
            )
        _namespace_checkpoint(self._monitor, label="release")
        if self._tooling_monitor is not None:
            _namespace_checkpoint(self._tooling_monitor, label="tooling package")
        if self._production:
            lease = self._lease
            if type(lease) not in {
                LockedWindowsWriterLease,
                LockedSteadyWindowsWriterLease,
            }:
                raise ExactRuntimeImportClosureError(
                    "production import closure lost its exact lease"
                )
            lease._canary_checkpoint()

    def checkpoint(self) -> None:
        self._assert_live()

    @property
    def release_path(self) -> str:
        self._assert_live()
        return str(self._release_root)

    @property
    def manifest_sha256(self) -> str:
        self._assert_live()
        if type(self._manifest) is not dict:
            raise ExactRuntimeImportClosureError("release manifest is unavailable")
        return identity_sha256(self._manifest)

    @property
    def manifest_document(self) -> dict[str, object]:
        self._assert_live()
        if type(self._manifest) is not dict:
            raise ExactRuntimeImportClosureError("release manifest is unavailable")
        cloned = json.loads(canonical_bytes(self._manifest).decode("utf-8"))
        if type(cloned) is not dict:
            raise ExactRuntimeImportClosureError("release manifest clone drifted")
        return cloned

    def activate(self) -> None:
        self._assert_live()
        import quant_hub
        import quant_hub.ops

        try:
            package_file = Path(str(quant_hub.__file__)).resolve(strict=True)
            ops_file = Path(str(quant_hub.ops.__file__)).resolve(strict=True)
            tooling_package = self._tooling_package.resolve(strict=True)
            if (
                package_file != tooling_package / "__init__.py"
                or ops_file != tooling_package / "ops" / "__init__.py"
            ):
                raise ExactRuntimeImportClosureError(
                    "loaded quant_hub tooling package identity differs"
                )
            release_package = self._release_package.resolve(strict=True)
            _closed_directory(release_package)
            package_path = quant_hub.__path__
            ops_path = quant_hub.ops.__path__
            if type(package_path) is not list or type(ops_path) is not list:
                raise ExactRuntimeImportClosureError(
                    "regular package search paths are not mutable exact lists"
                )
            package_path[:] = [str(release_package), str(tooling_package)]
            ops_path[:] = [str(tooling_package / "ops")]
            spec = quant_hub.__spec__
            ops_spec = quant_hub.ops.__spec__
            if (
                spec is None
                or ops_spec is None
                or spec.submodule_search_locations is not package_path
                or ops_spec.submodule_search_locations is not ops_path
            ):
                raise ExactRuntimeImportClosureError(
                    "package specs do not share the exact search-path objects"
                )
            application = self._manifest.get("application")
            if (
                type(application) is dict
                and application.get("source_kind") == "legacy_broadcast"
            ):
                import quant_hub.web

                release_web = release_package / "web"
                tooling_web = tooling_package / "web"
                web_file = Path(str(quant_hub.web.__file__)).resolve(strict=True)
                web_path = quant_hub.web.__path__
                web_spec = quant_hub.web.__spec__
                if (
                    web_file != release_web / "__init__.py"
                    or type(web_path) is not list
                    or web_spec is None
                    or web_spec.submodule_search_locations is not web_path
                ):
                    raise ExactRuntimeImportClosureError(
                        "legacy web package was not imported from the exact release"
                    )
                web_path[:] = [str(release_web), str(tooling_web)]
        except OSError as error:
            raise ExactRuntimeImportClosureError(
                "exact package lookup paths are unavailable"
            ) from error
        self._assert_live()

    def assert_application_sources(self) -> None:
        self._assert_live()
        from quant_hub.app import create_app
        from quant_hub.archive.contracts import ActorInput
        from quant_hub.collaboration.service import ArchiveCollaboration
        from quant_hub.config import Settings
        from quant_hub.research_workspace.service import ResearchWorkspace
        from quant_hub.web.access_gate import install_access_gate

        application = self._manifest.get("application")
        legacy = (
            type(application) is dict
            and application.get("source_kind") == "legacy_broadcast"
        )
        for value, label in (
            (create_app, "create_app"),
            (ActorInput, "ActorInput"),
            (ArchiveCollaboration, "ArchiveCollaboration"),
            (Settings, "Settings"),
            (ResearchWorkspace, "ResearchWorkspace"),
        ):
            _source_under_root(value, self._release_root, label=label)
        _source_under_root(
            install_access_gate,
            self._tooling_package if legacy else self._release_root,
            label="install_access_gate",
        )
        self._assert_live()

    def _close_acquired(self) -> None:
        failure: BaseException | None = None
        guards = self._guards
        self._guards = None
        if guards is not None:
            try:
                guards.close()
            except BaseException as error:
                failure = error
        monitor = self._monitor
        self._monitor = None
        if monitor is not None:
            try:
                monitor.close()
            except BaseException as error:
                if failure is None:
                    failure = error
        tooling_guards = self._tooling_guards
        self._tooling_guards = None
        if tooling_guards is not None:
            try:
                tooling_guards.close()
            except BaseException as error:
                if failure is None:
                    failure = error
        tooling_monitor = self._tooling_monitor
        self._tooling_monitor = None
        if tooling_monitor is not None:
            try:
                tooling_monitor.close()
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            self._state = "owner_crash_only"
            raise ExactRuntimeImportClosureError(
                "exact runtime import closure close failed"
            ) from failure
        self._state = "closed"

    def close(self) -> None:
        if self._state != "live":
            raise ExactRuntimeImportClosureError(
                "exact runtime import closure is not live"
            )
        if self._production:
            lease = self._lease
            if type(lease) not in {
                LockedWindowsWriterLease,
                LockedSteadyWindowsWriterLease,
            }:
                raise ExactRuntimeImportClosureError(
                    "production import closure lost its exact lease"
                )
            lease._canary_checkpoint()
        self._close_acquired()

    def __enter__(self) -> "_LockedExactRuntimeImportClosure":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class ProductionExactRuntimeImportClosure:
    """No-root-injection constructor bound to the exact live writer lease."""

    __slots__ = ()

    @classmethod
    def load_exact_d(
        cls, lease: LockedWindowsWriterLease
    ) -> _LockedExactRuntimeImportClosure:
        if type(lease) is not LockedWindowsWriterLease:
            raise TypeError("production import closure requires exact live lease")
        return cls._load_exact_lease(lease)

    @classmethod
    def load_steady_exact_d(
        cls, lease: LockedSteadyWindowsWriterLease
    ) -> _LockedExactRuntimeImportClosure:
        if type(lease) is not LockedSteadyWindowsWriterLease:
            raise TypeError(
                "production steady import closure requires exact steady live lease"
            )
        return cls._load_exact_lease(lease)

    @classmethod
    def _load_exact_lease(
        cls,
        lease: LockedWindowsWriterLease | LockedSteadyWindowsWriterLease,
    ) -> _LockedExactRuntimeImportClosure:
        del cls
        if os.name != "nt":
            raise ExactRuntimeImportClosureError(
                "production import closure is Windows-only"
            )
        record_before, root, _api = lease._canary_checkpoint()
        if PureWindowsPath(str(root)) != _PRODUCTION_ROOT:
            raise ExactRuntimeImportClosureError("production root is not exact D")
        tooling_manifest = (
            ProductionExactRuntimeToolingVerifier.load_exact_d().verify_persisted()
        )
        release = record_before.get("release")
        if type(release) is not dict:
            raise ExactRuntimeImportClosureError("lease release binding is absent")
        release_id = release.get("release_id")
        release_path = release.get("release_path")
        manifest_sha256 = release.get("manifest_sha256")
        expected_path = root / "releases" / str(release_id)
        if (
            type(release_id) is not str
            or type(release_path) is not str
            or type(manifest_sha256) is not str
            or PureWindowsPath(release_path) != PureWindowsPath(str(expected_path))
        ):
            raise ExactRuntimeImportClosureError(
                "lease release reference is not the exact D path"
            )
        closure = _LockedExactRuntimeImportClosure(
            release_root=expected_path,
            tooling_package=Path(str(_PRODUCTION_TOOLING_PACKAGE)),
            expected_release_id=release_id,
            expected_manifest_sha256=manifest_sha256,
            lease=lease,
            tooling_manifest=tooling_manifest,
            production=True,
            token=_CONSTRUCTION_TOKEN,
        )
        try:
            record_after, root_after, _api_after = lease._canary_checkpoint()
            if record_after != record_before or root_after != root:
                raise ExactRuntimeImportClosureError(
                    "writer lease drifted during import-closure acquisition"
                )
        except BaseException:
            closure.close()
            raise
        return closure


class TestOnlyExactRuntimeImportClosureAdapter:
    """Explicit fixture adapter, intentionally excluded from ``__all__``."""

    __slots__ = ()

    @classmethod
    def for_test_only(
        cls, release_root: Path, tooling_package: Path
    ) -> _LockedExactRuntimeImportClosure:
        if (
            type(release_root) is not type(Path())
            or type(tooling_package) is not type(Path())
            or not release_root.is_absolute()
            or not tooling_package.is_absolute()
        ):
            raise TypeError("test-only import closure paths must be absolute Paths")
        _raw, document = _manifest(release_root)
        release_id = document.get("release_id")
        if type(release_id) is not str:
            raise ExactRuntimeImportClosureError("test release ID is unavailable")
        return _LockedExactRuntimeImportClosure(
            release_root=release_root,
            tooling_package=tooling_package,
            expected_release_id=release_id,
            expected_manifest_sha256=identity_sha256(document),
            lease=None,
            tooling_manifest=None,
            production=False,
            token=_TEST_ONLY_TOKEN,
        )

    @classmethod
    def with_tooling_manifest_for_test_only(
        cls,
        release_root: Path,
        tooling_package: Path,
        tooling_manifest: ExactRuntimeToolingManifest,
    ) -> _LockedExactRuntimeImportClosure:
        if type(tooling_manifest) is not ExactRuntimeToolingManifest:
            raise TypeError("test-only tooling manifest must be exact")
        _raw, document = _manifest(release_root)
        release_id = document.get("release_id")
        if type(release_id) is not str:
            raise ExactRuntimeImportClosureError("test release ID is unavailable")
        return _LockedExactRuntimeImportClosure(
            release_root=release_root,
            tooling_package=tooling_package,
            expected_release_id=release_id,
            expected_manifest_sha256=identity_sha256(document),
            lease=None,
            tooling_manifest=tooling_manifest,
            production=False,
            token=_TEST_ONLY_TOKEN,
        )


__all__ = [
    "ExactRuntimeImportClosureError",
    "ProductionExactRuntimeImportClosure",
]
