"""Filesystem scanner for the persistent exact-runtime tooling claim.

The production verifier has no caller-controlled path.  It recomputes the
fixed D-root binaries, installed ``quant_hub`` package inventory, and critical
file subset, then compares those bytes with the canonical persisted claim.
The returned manifest is replayable evidence only; it is not a live handle or
deployment qualification.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import os
from pathlib import Path, PurePosixPath, PureWindowsPath
import stat
import unicodedata

from .local_exact_runtime_tooling import (
    EXACT_RUNTIME_PACKAGE_INVENTORY_ALGORITHM,
    EXACT_RUNTIME_PACKAGE_RELATIVE_PATH,
    EXACT_RUNTIME_TOOLING_ROOT,
    EXACT_RUNTIME_TOOLING_SCHEMA,
    EXACT_RUNTIME_TOOLING_SCOPE,
    ExactRuntimeToolingError,
    ExactRuntimeToolingManifest,
    _BINARY_PATHS,
    _KEY_FILES,
    build_exact_runtime_tooling,
    parse_exact_runtime_tooling_bytes,
)
from .local_release_identity import identity_sha256


EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH = (
    "control/exact_runtime_tooling.json"
)

_MAX_FILE_BYTES = 8 * 1024 * 1024 * 1024
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_PACKAGE_ENTRIES = 200_000
_PRODUCTION_ROOT = PureWindowsPath(EXACT_RUNTIME_TOOLING_ROOT)
_CONSTRUCTION_TOKEN = object()
_TEST_ONLY_TOKEN = object()
_GENERIC_READ = 0x80000000
_FILE_LIST_DIRECTORY = 0x00000001
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_FLAG_OVERLAPPED = 0x40000000
_FILE_NOTIFY_CHANGE_FILE_NAME = 0x00000001
_FILE_NOTIFY_CHANGE_DIR_NAME = 0x00000002
_FILE_NOTIFY_CHANGE_ATTRIBUTES = 0x00000004
_FILE_NOTIFY_CHANGE_SIZE = 0x00000008
_FILE_NOTIFY_CHANGE_LAST_WRITE = 0x00000010
_NAMESPACE_NOTIFY_FILTER = (
    _FILE_NOTIFY_CHANGE_FILE_NAME
    | _FILE_NOTIFY_CHANGE_DIR_NAME
)
_SUBTREE_MUTATION_NOTIFY_FILTER = (
    _NAMESPACE_NOTIFY_FILTER
    | _FILE_NOTIFY_CHANGE_ATTRIBUTES
    | _FILE_NOTIFY_CHANGE_SIZE
    | _FILE_NOTIFY_CHANGE_LAST_WRITE
)
_ERROR_OPERATION_ABORTED = 995
_ERROR_NOT_FOUND = 1168
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


class ExactRuntimeToolingScanError(RuntimeError):
    """The fixed tooling tree or its persisted claim failed closed."""


class _Overlapped(ctypes.Structure):
    _fields_ = (
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD),
        ("OffsetHigh", wintypes.DWORD),
        ("hEvent", wintypes.HANDLE),
    )


class _WindowsNamespaceChangeMonitor:
    """Detect every package-subtree mutation until the claim is constructed.

    File read guards prevent an existing included member from being replaced.
    They cannot prevent a new directory member from being created.  A recursive
    overlapped ``ReadDirectoryChangesW`` request starts before enumeration and
    remains pending until after the canonical claim has been built in memory.
    ``CancelIoEx`` plus the waited completion result is the mechanical end of
    the observation interval: a delivered change or an inconclusive completion
    fails closed; only ``ERROR_OPERATION_ABORTED`` proves the unchanged pending
    request was cancelled.
    """

    __slots__ = (
        "_buffer",
        "_cancel_io_ex",
        "_close_handle",
        "_directory_handle",
        "_event_handle",
        "_get_overlapped_result",
        "_overlapped",
    )

    def __init__(
        self,
        package_root: Path,
        *,
        notify_filter: int = _NAMESPACE_NOTIFY_FILTER,
    ):
        self._buffer = None
        self._cancel_io_ex = None
        self._close_handle = None
        self._directory_handle: int | None = None
        self._event_handle: int | None = None
        self._get_overlapped_result = None
        self._overlapped = None
        if os.name != "nt":
            return
        try:
            kernel32 = ctypes.WinDLL(
                "kernel32.dll",
                use_last_error=True,
                winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            create_file = kernel32.CreateFileW
            create_file.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            create_file.restype = wintypes.HANDLE
            create_event = kernel32.CreateEventW
            create_event.argtypes = (
                ctypes.c_void_p,
                wintypes.BOOL,
                wintypes.BOOL,
                wintypes.LPCWSTR,
            )
            create_event.restype = wintypes.HANDLE
            read_changes = kernel32.ReadDirectoryChangesW
            read_changes.argtypes = (
                wintypes.HANDLE,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                ctypes.POINTER(_Overlapped),
                ctypes.c_void_p,
            )
            read_changes.restype = wintypes.BOOL
            cancel_io_ex = kernel32.CancelIoEx
            cancel_io_ex.argtypes = (
                wintypes.HANDLE,
                ctypes.POINTER(_Overlapped),
            )
            cancel_io_ex.restype = wintypes.BOOL
            get_overlapped_result = kernel32.GetOverlappedResult
            get_overlapped_result.argtypes = (
                wintypes.HANDLE,
                ctypes.POINTER(_Overlapped),
                ctypes.POINTER(wintypes.DWORD),
                wintypes.BOOL,
            )
            get_overlapped_result.restype = wintypes.BOOL
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = (wintypes.HANDLE,)
            close_handle.restype = wintypes.BOOL
        except (AttributeError, OSError, TypeError) as error:
            raise ExactRuntimeToolingScanError(
                "System32 tooling namespace-monitor API binding failed"
            ) from error

        invalid = ctypes.c_void_p(-1).value
        ctypes.set_last_error(0)
        directory_handle = create_file(
            str(package_root),
            _FILE_LIST_DIRECTORY,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS
            | _FILE_FLAG_OPEN_REPARSE_POINT
            | _FILE_FLAG_OVERLAPPED,
            None,
        )
        if directory_handle in {None, 0, -1, invalid}:
            raise ExactRuntimeToolingScanError(
                "tooling package namespace could not be monitored; "
                f"Windows error {ctypes.get_last_error()}"
            )
        self._directory_handle = int(directory_handle)
        self._close_handle = close_handle
        try:
            ctypes.set_last_error(0)
            event_handle = create_event(None, True, False, None)
            if event_handle in {None, 0, -1, invalid}:
                raise ExactRuntimeToolingScanError(
                    "tooling namespace monitor event creation failed; "
                    f"Windows error {ctypes.get_last_error()}"
                )
            self._event_handle = int(event_handle)
            self._buffer = ctypes.create_string_buffer(64 * 1024)
            overlapped = _Overlapped()
            overlapped.hEvent = event_handle
            self._overlapped = overlapped
            self._cancel_io_ex = cancel_io_ex
            self._get_overlapped_result = get_overlapped_result
            ctypes.set_last_error(0)
            started = read_changes(
                directory_handle,
                self._buffer,
                len(self._buffer),
                True,
                notify_filter,
                None,
                ctypes.byref(overlapped),
                None,
            )
            if type(started) is not int or started == 0:
                raise ExactRuntimeToolingScanError(
                    "tooling namespace monitor did not start; "
                    f"Windows error {ctypes.get_last_error()}"
                )
        except BaseException:
            self._close_handles()
            raise

    def _close_handles(self) -> None:
        close_handle = self._close_handle
        if os.name != "nt":
            return
        failure: BaseException | None = None
        for attribute in ("_event_handle", "_directory_handle"):
            handle = getattr(self, attribute)
            setattr(self, attribute, None)
            if handle is None:
                continue
            try:
                if close_handle is None:
                    raise ExactRuntimeToolingScanError(
                        "tooling namespace-monitor close binding is missing"
                    )
                result = close_handle(handle)
                if type(result) is not int or result == 0:
                    raise ExactRuntimeToolingScanError(
                        "tooling namespace-monitor handle close was not confirmed"
                    )
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise ExactRuntimeToolingScanError(
                "tooling namespace-monitor handle close failed"
            ) from failure

    def close(self) -> None:
        if os.name != "nt":
            return
        directory_handle = self._directory_handle
        overlapped = self._overlapped
        cancel_io_ex = self._cancel_io_ex
        get_overlapped_result = self._get_overlapped_result
        if (
            directory_handle is None
            or type(overlapped) is not _Overlapped
            or cancel_io_ex is None
            or get_overlapped_result is None
        ):
            self._close_handles()
            raise ExactRuntimeToolingScanError(
                "tooling namespace monitor is incomplete"
            )

        completion_error: BaseException | None = None
        change_detail: str | None = None
        try:
            ctypes.set_last_error(0)
            cancelled = cancel_io_ex(directory_handle, ctypes.byref(overlapped))
            cancel_error = ctypes.get_last_error()
            if (
                (type(cancelled) is not int or cancelled == 0)
                and cancel_error != _ERROR_NOT_FOUND
            ):
                raise ExactRuntimeToolingScanError(
                    "tooling namespace monitor cancellation failed; "
                    f"Windows error {cancel_error}"
                )
            transferred = wintypes.DWORD(0)
            ctypes.set_last_error(0)
            completed = get_overlapped_result(
                directory_handle,
                ctypes.byref(overlapped),
                ctypes.byref(transferred),
                True,
            )
            completion_code = ctypes.get_last_error()
            if type(completed) is int and completed != 0:
                raw_notice = bytes(self._buffer or b"")
                action = int.from_bytes(raw_notice[4:8], "little")
                name_bytes = int.from_bytes(raw_notice[8:12], "little")
                notice_name = raw_notice[12 : 12 + name_bytes].decode(
                    "utf-16-le", errors="replace"
                )
                change_detail = (
                    f"bytes={transferred.value}; action={action}; "
                    f"name={notice_name!r}"
                )
            elif completion_code != _ERROR_OPERATION_ABORTED:
                raise ExactRuntimeToolingScanError(
                    "tooling namespace monitor completion was inconclusive; "
                    f"Windows error {completion_code}"
                )
        except BaseException as error:
            completion_error = error
        try:
            self._close_handles()
        except BaseException as error:
            if completion_error is None:
                completion_error = error
        if completion_error is not None:
            raise ExactRuntimeToolingScanError(
                "tooling namespace monitor did not close cleanly"
            ) from completion_error
        if change_detail is not None:
            raise ExactRuntimeToolingScanError(
                "tooling package namespace changed during claim construction; "
                + change_detail
            )

    def __enter__(self) -> "_WindowsNamespaceChangeMonitor":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class _WindowsReadGuardSet:
    """Hold every included file without write/delete sharing during a scan."""

    __slots__ = ("_close_handle", "_create_file", "_handles")

    def __init__(self, paths: tuple[Path, ...]):
        self._handles: list[int] = []
        self._create_file = None
        self._close_handle = None
        if os.name != "nt":
            return
        try:
            kernel32 = ctypes.WinDLL(
                "kernel32.dll",
                use_last_error=True,
                winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            create_file = kernel32.CreateFileW
            create_file.argtypes = (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            )
            create_file.restype = wintypes.HANDLE
            close_handle = kernel32.CloseHandle
            close_handle.argtypes = (wintypes.HANDLE,)
            close_handle.restype = wintypes.BOOL
        except (AttributeError, OSError, TypeError) as error:
            raise ExactRuntimeToolingScanError(
                "System32 tooling read-guard API binding failed"
            ) from error
        self._create_file = create_file
        self._close_handle = close_handle
        try:
            for path in paths:
                ctypes.set_last_error(0)
                raw = create_file(
                    str(path),
                    _GENERIC_READ,
                    _FILE_SHARE_READ,
                    None,
                    _OPEN_EXISTING,
                    _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_SEQUENTIAL_SCAN,
                    None,
                )
                invalid = ctypes.c_void_p(-1).value
                if raw in {None, 0, -1, invalid}:
                    raise ExactRuntimeToolingScanError(
                        "tooling file could not be fixed against write/delete: "
                        f"{path}; Windows error {ctypes.get_last_error()}"
                    )
                self._handles.append(int(raw))
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if os.name != "nt":
            return
        close_handle = self._close_handle
        if close_handle is None:
            raise ExactRuntimeToolingScanError(
                "tooling read-guard close binding is missing"
            )
        failure: BaseException | None = None
        while self._handles:
            handle = self._handles.pop()
            try:
                result = close_handle(handle)
                if type(result) is not int or result == 0:
                    raise ExactRuntimeToolingScanError(
                        "tooling read-guard close was not mechanically confirmed"
                    )
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise ExactRuntimeToolingScanError(
                "tooling read-guard close failed"
            ) from failure

    def __enter__(self) -> "_WindowsReadGuardSet":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


def _is_reparse(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        int(info.st_dev),
        int(info.st_ino),
        int(stat.S_IFMT(info.st_mode)),
        int(info.st_nlink),
        int(info.st_size),
        int(info.st_mtime_ns),
    )


def _closed_directory(path: Path) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as error:
        raise ExactRuntimeToolingScanError(
            f"tooling directory 无法读取: {path}"
        ) from error
    if _is_reparse(info) or not stat.S_ISDIR(info.st_mode):
        raise ExactRuntimeToolingScanError(
            f"tooling directory 不是普通非 reparse 目录: {path}"
        )
    return info


def _closed_existing_ancestor_chain(path: Path) -> None:
    chain: list[Path] = []
    current = path.absolute()
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        if os.path.lexists(candidate):
            _closed_directory(candidate)


def _relative_path(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(root).as_posix()
    except ValueError as error:
        raise ExactRuntimeToolingScanError("tooling member escaped package root") from error
    if (
        not relative
        or relative == "."
        or "\\" in relative
        or PurePosixPath(relative).is_absolute()
        or ".." in PurePosixPath(relative).parts
        or unicodedata.normalize("NFC", relative) != relative
    ):
        raise ExactRuntimeToolingScanError(
            f"tooling package path is not canonical NFC POSIX: {relative!r}"
        )
    return relative


def _file_digest(
    path: Path,
    *,
    allow_empty: bool,
    maximum_bytes: int = _MAX_FILE_BYTES,
) -> tuple[int, str]:
    try:
        before = path.lstat()
    except OSError as error:
        raise ExactRuntimeToolingScanError(f"tooling file 无法读取: {path}") from error
    if (
        _is_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size < 0
        or before.st_size > maximum_bytes
        or (not allow_empty and before.st_size == 0)
    ):
        raise ExactRuntimeToolingScanError(
            f"tooling file 不是受限普通单链接文件: {path}"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    descriptor = -1
    digest = hashlib.sha256()
    observed_bytes = 0
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise ExactRuntimeToolingScanError(
                f"tooling file changed while opening: {path}"
            )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            observed_bytes += len(chunk)
            if observed_bytes > maximum_bytes:
                raise ExactRuntimeToolingScanError(
                    f"tooling file exceeds byte limit: {path}"
                )
            digest.update(chunk)
        after_handle = os.fstat(descriptor)
    except OSError as error:
        raise ExactRuntimeToolingScanError(f"tooling file read failed: {path}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after_path = path.lstat()
    except OSError as error:
        raise ExactRuntimeToolingScanError(
            f"tooling file disappeared after read: {path}"
        ) from error
    if (
        _identity(before) != _identity(after_handle)
        or _identity(before) != _identity(after_path)
        or observed_bytes != before.st_size
    ):
        raise ExactRuntimeToolingScanError(
            f"tooling file identity drifted during read: {path}"
        )
    return observed_bytes, digest.hexdigest()


def _bounded_file_bytes(path: Path, *, maximum_bytes: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise ExactRuntimeToolingScanError(f"tooling file 无法读取: {path}") from error
    if (
        _is_reparse(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= maximum_bytes
    ):
        raise ExactRuntimeToolingScanError(
            f"tooling bounded file 不是受限普通单链接文件: {path}"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
    descriptor = -1
    chunks: list[bytes] = []
    observed_bytes = 0
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise ExactRuntimeToolingScanError(
                f"tooling bounded file changed while opening: {path}"
            )
        while True:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1))
            if not chunk:
                break
            observed_bytes += len(chunk)
            if observed_bytes > maximum_bytes:
                raise ExactRuntimeToolingScanError(
                    f"tooling bounded file exceeds byte limit: {path}"
                )
            chunks.append(chunk)
        after_handle = os.fstat(descriptor)
    except OSError as error:
        raise ExactRuntimeToolingScanError(
            f"tooling bounded file read failed: {path}"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        after_path = path.lstat()
    except OSError as error:
        raise ExactRuntimeToolingScanError(
            f"tooling bounded file disappeared after read: {path}"
        ) from error
    if (
        _identity(before) != _identity(after_handle)
        or _identity(before) != _identity(after_path)
        or observed_bytes != before.st_size
    ):
        raise ExactRuntimeToolingScanError(
            f"tooling bounded file identity drifted during read: {path}"
        )
    return b"".join(chunks)


def _walk_package(package_root: Path) -> tuple[dict[str, object], ...]:
    identities: dict[str, str] = {}
    members: list[dict[str, object]] = []

    def remember(relative: str) -> None:
        identity = unicodedata.normalize("NFKC", relative).casefold()
        previous = identities.get(identity)
        if previous is not None and previous != relative:
            raise ExactRuntimeToolingScanError(
                f"tooling package path identity collision: {previous!r}, {relative!r}"
            )
        identities[identity] = relative

    def visit(directory: Path) -> None:
        before = _closed_directory(directory)
        try:
            children = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as error:
            raise ExactRuntimeToolingScanError(
                f"tooling package directory enumerate failed: {directory}"
            ) from error
        for child in children:
            relative = _relative_path(child, package_root)
            remember(relative)
            try:
                info = child.lstat()
            except OSError as error:
                raise ExactRuntimeToolingScanError(
                    f"tooling package member unreadable: {relative}"
                ) from error
            if _is_reparse(info):
                raise ExactRuntimeToolingScanError(
                    f"tooling package contains reparse member: {relative}"
                )
            if stat.S_ISDIR(info.st_mode):
                if child.name == "__pycache__":
                    continue
                visit(child)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ExactRuntimeToolingScanError(
                    f"tooling package contains non-file member: {relative}"
                )
            if child.suffix.casefold() in {".pyc", ".pyo"}:
                raise ExactRuntimeToolingScanError(
                    "tooling package contains discoverable legacy bytecode "
                    f"outside __pycache__: {relative}"
                )
            size, sha256 = _file_digest(child, allow_empty=True)
            members.append(
                {"relative_path": relative, "bytes": size, "sha256": sha256}
            )
            if len(members) > _MAX_PACKAGE_ENTRIES:
                raise ExactRuntimeToolingScanError(
                    "tooling package inventory exceeds entry limit"
                )
        after = _closed_directory(directory)
        if _identity(before) != _identity(after):
            raise ExactRuntimeToolingScanError(
                f"tooling package directory drifted during scan: {directory}"
            )

    visit(package_root)
    members.sort(key=lambda item: str(item["relative_path"]))
    if not members:
        raise ExactRuntimeToolingScanError("tooling package inventory is empty")
    return tuple(members)


def _path(root: Path, relative: str) -> Path:
    return root.joinpath(*PurePosixPath(relative).parts)


class _ExactRuntimeToolingScanner:
    __slots__ = ("_root", "_sealed")

    def __init__(self, root: Path, *, token: object):
        if token not in {_CONSTRUCTION_TOKEN, _TEST_ONLY_TOKEN} or type(root) is not type(Path()):
            raise TypeError("exact runtime tooling scanner provenance invalid")
        object.__setattr__(self, "_sealed", False)
        self._root = root
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("exact runtime tooling scanner is immutable")
        object.__setattr__(self, name, value)

    def _snapshot_payload(
        self,
    ) -> tuple[dict[str, object], _WindowsReadGuardSet]:
        _closed_existing_ancestor_chain(self._root)
        root_before = _closed_directory(self._root)
        package_root = _path(self._root, EXACT_RUNTIME_PACKAGE_RELATIVE_PATH)
        _closed_directory(package_root)

        preliminary = _walk_package(package_root)
        preliminary_paths = tuple(
            str(item["relative_path"]) for item in preliminary
        )
        guard_paths = tuple(
            [
                _path(self._root, relative)
                for _field, _logical_name, relative in _BINARY_PATHS
            ]
            + [
                _path(package_root, relative)
                for relative in preliminary_paths
            ]
        )
        guards = _WindowsReadGuardSet(guard_paths)
        try:
            binaries: dict[str, dict[str, object]] = {}
            for field, logical_name, relative in _BINARY_PATHS:
                size, sha256 = _file_digest(
                    _path(self._root, relative), allow_empty=False
                )
                binaries[field] = {
                    "logical_name": logical_name,
                    "relative_path": relative,
                    "bytes": size,
                    "sha256": sha256,
                }

            inventory = _walk_package(package_root)
            confirmed_inventory = _walk_package(package_root)
            if (
                tuple(str(item["relative_path"]) for item in inventory)
                != preliminary_paths
                or confirmed_inventory != inventory
            ):
                raise ExactRuntimeToolingScanError(
                    "tooling package changed across the guarded full scan"
                )
            key_files: list[dict[str, object]] = []
            inventory_by_path = {
                str(item["relative_path"]): item for item in inventory
            }
            for logical_name, relative in _KEY_FILES:
                member = inventory_by_path.get(relative)
                if member is None or int(member["bytes"]) < 1:
                    raise ExactRuntimeToolingScanError(
                        f"fixed tooling key file is missing or empty: {relative}"
                    )
                key_files.append(
                    {
                        "logical_name": logical_name,
                        "relative_path": relative,
                        "bytes": member["bytes"],
                        "sha256": member["sha256"],
                    }
                )

            root_after = _closed_directory(self._root)
            if _identity(root_before) != _identity(root_after):
                raise ExactRuntimeToolingScanError(
                    "tooling root drifted during snapshot"
                )
            return {
                "schema_version": EXACT_RUNTIME_TOOLING_SCHEMA,
                "scope": EXACT_RUNTIME_TOOLING_SCOPE,
                "root": EXACT_RUNTIME_TOOLING_ROOT,
                "python": binaries["python"],
                "service_host": binaries["service_host"],
                "package": {
                    "relative_path": EXACT_RUNTIME_PACKAGE_RELATIVE_PATH,
                    "inventory_algorithm": EXACT_RUNTIME_PACKAGE_INVENTORY_ALGORITHM,
                    "entry_count": len(inventory),
                    "inventory_sha256": identity_sha256(list(inventory)),
                },
                "files": key_files,
            }, guards
        except BaseException:
            guards.close()
            raise

    def build_claim(self) -> ExactRuntimeToolingManifest:
        _closed_existing_ancestor_chain(self._root)
        _closed_directory(self._root)
        package_root = _path(
            self._root, EXACT_RUNTIME_PACKAGE_RELATIVE_PATH
        )
        _closed_directory(package_root)
        with _WindowsNamespaceChangeMonitor(package_root):
            guards: _WindowsReadGuardSet | None = None
            try:
                payload, guards = self._snapshot_payload()
                document = build_exact_runtime_tooling(
                    payload
                )
                manifest = ExactRuntimeToolingManifest.from_document(document)
            except ExactRuntimeToolingError as error:
                raise ExactRuntimeToolingScanError(
                    "tooling snapshot did not satisfy persistent contract"
                ) from error
            finally:
                if guards is not None:
                    guards.close()
        return manifest

    def verify(self, manifest: ExactRuntimeToolingManifest) -> ExactRuntimeToolingManifest:
        if type(manifest) is not ExactRuntimeToolingManifest:
            raise TypeError("tooling verification requires the exact manifest type")
        observed = self.build_claim()
        if observed.canonical_bytes() != manifest.canonical_bytes():
            raise ExactRuntimeToolingScanError(
                "persisted tooling claim does not match current exact bytes"
            )
        return observed

    def verify_persisted(self) -> ExactRuntimeToolingManifest:
        manifest_path = _path(
            self._root, EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH
        )
        try:
            raw = _bounded_file_bytes(
                manifest_path, maximum_bytes=_MAX_MANIFEST_BYTES
            )
            manifest = parse_exact_runtime_tooling_bytes(raw)
        except ExactRuntimeToolingError as error:
            raise ExactRuntimeToolingScanError(
                "persisted tooling manifest is invalid"
            ) from error
        return self.verify(manifest)


class ProductionExactRuntimeToolingVerifier:
    """No-argument verifier for the one allowed production D root."""

    __slots__ = ("_scanner", "_sealed")

    def __init__(self, scanner: object, *, token: object):
        if token is not _CONSTRUCTION_TOKEN or type(scanner) is not _ExactRuntimeToolingScanner:
            raise TypeError("production tooling verifier must come from load_exact_d")
        object.__setattr__(self, "_sealed", False)
        self._scanner = scanner
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production tooling verifier is immutable")
        object.__setattr__(self, name, value)

    @classmethod
    def load_exact_d(cls) -> "ProductionExactRuntimeToolingVerifier":
        if os.name != "nt":
            raise ExactRuntimeToolingScanError(
                "production exact-runtime tooling is Windows-only"
            )
        root = Path(str(_PRODUCTION_ROOT))
        if PureWindowsPath(str(root)) != _PRODUCTION_ROOT:
            raise ExactRuntimeToolingScanError("production tooling root drifted")
        scanner = _ExactRuntimeToolingScanner(root, token=_CONSTRUCTION_TOKEN)
        return cls(scanner, token=_CONSTRUCTION_TOKEN)

    def verify_persisted(self) -> ExactRuntimeToolingManifest:
        return self._scanner.verify_persisted()


class TestOnlyExactRuntimeToolingAdapter:
    """Explicit filesystem fixture adapter; never exported as production API."""

    __slots__ = ("_scanner",)

    @classmethod
    def for_test_only(cls, root: Path) -> "TestOnlyExactRuntimeToolingAdapter":
        if type(root) is not type(Path()) or not root.is_absolute():
            raise TypeError("test-only tooling root must be an absolute concrete Path")
        instance = object.__new__(cls)
        instance._scanner = _ExactRuntimeToolingScanner(root, token=_TEST_ONLY_TOKEN)
        return instance

    def build_claim(self) -> ExactRuntimeToolingManifest:
        return self._scanner.build_claim()

    def verify(self, manifest: ExactRuntimeToolingManifest) -> ExactRuntimeToolingManifest:
        return self._scanner.verify(manifest)

    def verify_persisted(self) -> ExactRuntimeToolingManifest:
        return self._scanner.verify_persisted()


__all__ = [
    "EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH",
    "ExactRuntimeToolingScanError",
    "ProductionExactRuntimeToolingVerifier",
]
