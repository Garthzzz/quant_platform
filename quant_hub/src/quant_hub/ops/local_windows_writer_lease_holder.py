"""精确 D 根 Windows writer lease 的 child-side kernel lock holder。

产品入口没有 root、path、API、PID 或 hook 注入。它只在当前 exact runtime child
内取得固定 D 锁，原子发布 closed lease record，并把 handle 保持到进程退出。
本模块不观察 SCM/endpoint，不形成 canary 或部署资格。
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path, PureWindowsPath
import re
import secrets
import stat
import subprocess
import sys
from typing import Mapping

from .local_exact_runtime_admission import LockedExactRuntimeAdmissionGate
from .local_release_identity import canonical_bytes, identity_sha256
from .local_steady_runtime_identity import ExactSteadyRuntimeIdentity
from .local_steady_windows_writer_lease_evidence import (
    STEADY_WRITER_LEASE_RECORD_SCHEMA,
)
from .local_windows_writer_lease_evidence import (
    WRITER_LEASE_RECORD_SCHEMA,
    WRITER_LOCK_RELATIVE_PATH,
)


LIVE_WINDOWS_WRITER_LEASE_SCOPE = (
    "live_windows_writer_lease_not_canary_qualified"
)
LIVE_STEADY_WINDOWS_WRITER_LEASE_SCOPE = (
    "live_steady_windows_writer_lease_not_admission_qualified"
)

_PRODUCTION_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
_SERVICE_NAME = "QuantResearchHub"
_SCM_HOST_EXECUTABLE = (
    r"D:\quant\quant_platform\tooling\python\pythonservice.exe"
)
_CHILD_EXECUTABLE = r"D:\quant\quant_platform\tooling\python\python.exe"
_CHILD_MODULE = "quant_hub.ops.local_exact_runtime_entry"
_PYCACHE_PARENT = _PRODUCTION_ROOT / "tmp" / "service" / "pycache"
_SCM_PYTHON_CLASS = (
    "quant_hub.ops.windows_service.QuantResearchHubWindowsService"
)
_LOCK_RELATIVE = Path(*PureWindowsPath(WRITER_LOCK_RELATIVE_PATH).parts)
_RECORD_RELATIVE = Path("state") / "writer_lease.json"
_TMP_RELATIVE = Path("tmp") / "service"

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_CREATE_NEW = 1
_OPEN_EXISTING = 3
_OPEN_ALWAYS = 4
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_FLAG_WRITE_THROUGH = 0x80000000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ID_INFO_CLASS = 18
_FILE_STANDARD_INFO_CLASS = 1
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_TH32CS_SNAPPROCESS = 0x00000002
_WAIT_TIMEOUT = 258
_STILL_ACTIVE = 259
_MOVEFILE_REPLACE_EXISTING = 0x00000001
_MOVEFILE_WRITE_THROUGH = 0x00000008
_ERROR_FILE_NOT_FOUND = 2
_ERROR_PATH_NOT_FOUND = 3
_ERROR_FILE_EXISTS = 80
_ERROR_ALREADY_EXISTS = 183
_ERROR_NO_MORE_FILES = 18
_ERROR_SHARING_VIOLATION = 32
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
_MAX_RECORD_BYTES = 64 * 1024
_MAX_VOLUME_SERIAL_NUMBER = (1 << 64) - 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_128_RE = re.compile(r"^[0-9a-f]{32}$")
_NONCE_192_RE = re.compile(r"^[0-9a-f]{48}$")
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,179}$")

_PRODUCTION_API_TOKEN = object()
_PRODUCTION_HOLDER_TOKEN = object()
_LIVE_LEASE_TOKEN = object()
_LIVE_STEADY_LEASE_TOKEN = object()
_TEST_ONLY_TOKEN = object()


class WindowsWriterLeaseHolderError(RuntimeError):
    """child-side writer lease 无法以 exact Windows 语义闭合。"""


class WindowsWriterLeaseBusy(WindowsWriterLeaseHolderError):
    """已有不兼容 writer handle，当前 child 不得成为 writer。"""


class WindowsWriterLeaseOwnerCrashRequired(WindowsWriterLeaseHolderError):
    """handle close 结果未知；exact runtime 必须退出进程交给 kernel 回收。"""


def _stat_is_reparse_point(info: os.stat_result) -> bool:
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def _ensure_no_reparse_components(path: Path) -> None:
    chain: list[Path] = []
    current = path.absolute()
    while True:
        chain.append(current)
        if current.parent == current:
            break
        current = current.parent
    for candidate in reversed(chain):
        try:
            exists = os.path.lexists(candidate)
            info = candidate.lstat() if exists else None
        except OSError as error:
            raise WindowsWriterLeaseHolderError(
                f"writer lease path component 无法核验: {candidate}"
            ) from error
        if info is not None and _stat_is_reparse_point(info):
            raise WindowsWriterLeaseHolderError(
                f"writer lease path contains a reparse component: {candidate}"
            )


class _FILETIME(ctypes.Structure):
    _fields_ = (
        ("dwLowDateTime", wintypes.DWORD),
        ("dwHighDateTime", wintypes.DWORD),
    )


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = (
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    )


class _FILE_ID_128(ctypes.Structure):
    _fields_ = (("Identifier", ctypes.c_ubyte * 16),)


class _FILE_ID_INFO(ctypes.Structure):
    _fields_ = (
        ("VolumeSerialNumber", ctypes.c_ulonglong),
        ("FileId", _FILE_ID_128),
    )


class _FILE_STANDARD_INFO(ctypes.Structure):
    _fields_ = (
        ("AllocationSize", ctypes.c_longlong),
        ("EndOfFile", ctypes.c_longlong),
        ("NumberOfLinks", wintypes.DWORD),
        ("DeletePending", wintypes.BOOL),
        ("Directory", wintypes.BOOL),
    )


class _FILE_ATTRIBUTE_TAG_INFO(ctypes.Structure):
    _fields_ = (
        ("FileAttributes", wintypes.DWORD),
        ("ReparseTag", wintypes.DWORD),
    )


@dataclass(frozen=True, slots=True)
class _FileIdentity:
    final_path: str
    volume_serial_number: int
    file_id: str
    size: int


@dataclass(frozen=True, slots=True)
class _ProcessIdentity:
    host_pid: int
    host_creation_time_100ns: int
    child_pid: int
    child_creation_time_100ns: int


@dataclass(frozen=True, slots=True)
class ExactRuntimeLeaseIdentity:
    """由 exact runtime argv 携带的身份；自身不授予 writer authority。"""

    attempt_id: str
    nonce: str
    operation: str
    role: str
    start_nonce: str
    state_identity_sha256: str
    release_id: str
    manifest_sha256: str
    release_path: str = field(init=False)
    scm_identity_sha256: str = field(init=False)
    authorization_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        for field in ("attempt_id", "nonce", "start_nonce", "release_id"):
            value = getattr(self, field)
            if (
                type(value) is not str
                or _IDENTIFIER_RE.fullmatch(value) is None
                or value.endswith((".", " "))
            ):
                raise WindowsWriterLeaseHolderError(
                    f"runtime lease identity.{field} identifier 无效"
                )
        if self.operation not in {
            "activation",
            "rollback",
            "bootstrap_first_pair",
        }:
            raise WindowsWriterLeaseHolderError("runtime lease operation 无效")
        if self.operation == "bootstrap_first_pair":
            valid_role = self.role == "baseline"
        else:
            valid_role = self.role in {"prior", "candidate"}
        if not valid_role:
            raise WindowsWriterLeaseHolderError(
                "runtime lease role 与 operation 不匹配"
            )
        for field in (
            "state_identity_sha256",
            "manifest_sha256",
        ):
            value = getattr(self, field)
            if (
                type(value) is not str
                or _SHA256_RE.fullmatch(value) is None
                or value == "0" * 64
            ):
                raise WindowsWriterLeaseHolderError(
                    f"runtime lease identity.{field} SHA-256 无效"
                )
        release_path = str(_PRODUCTION_ROOT / "releases" / self.release_id)
        release = {
            "release_id": self.release_id,
            "release_path": release_path,
            "manifest_sha256": self.manifest_sha256,
        }
        child_argv = list(_expected_child_argv(self))
        service_start_arguments = list(_expected_service_start_arguments(self))
        scm_plan = {
            "schema_version": "qrh-exact-scm-start-plan/v1",
            "scope": "exact_scm_start_plan_input_only",
            "attempt": self.attempt_id,
            "nonce": self.nonce,
            "operation": self.operation,
            "role": self.role,
            "start_nonce": self.start_nonce,
            "state_identity_sha256": self.state_identity_sha256,
            "release": release,
            "service": {
                "service_name": _SERVICE_NAME,
                "binary_path": _SCM_HOST_EXECUTABLE,
                "python_class": _SCM_PYTHON_CLASS,
                "start_type": "automatic",
                "start_arguments": service_start_arguments,
            },
            "child": {
                "executable": _CHILD_EXECUTABLE,
                "module": _CHILD_MODULE,
                "argv": child_argv,
            },
        }
        scm_identity_sha256 = identity_sha256(scm_plan)
        authorization = {
            "schema_version": "qrh-exact-transient-start-authorization/v1",
            "scope": "exact_transient_start_authorization_input_only",
            "attempt": self.attempt_id,
            "nonce": self.nonce,
            "operation": self.operation,
            "authorization_phase": (
                "prior_start_authorized"
                if self.role == "prior"
                else "candidate_start_authorized"
            ),
            "role": self.role,
            "release": release,
            "start_nonce": self.start_nonce,
            "scm_identity_sha256": scm_identity_sha256,
            "state_identity_sha256": self.state_identity_sha256,
        }
        object.__setattr__(self, "release_path", release_path)
        object.__setattr__(self, "scm_identity_sha256", scm_identity_sha256)
        object.__setattr__(
            self, "authorization_sha256", identity_sha256(authorization)
        )

    @property
    def child_argv(self) -> tuple[str, ...]:
        return _expected_child_argv(self)

    @property
    def service_start_arguments(self) -> tuple[str, ...]:
        return _expected_service_start_arguments(self)


def _bind(
    library: object,
    name: str,
    argtypes: tuple[object, ...],
    restype: object,
) -> object:
    try:
        function = getattr(library, name)
        function.argtypes = argtypes
        function.restype = restype
    except (AttributeError, TypeError) as error:
        raise WindowsWriterLeaseHolderError(
            f"Windows API binding 缺失或签名不可固定: {name}"
        ) from error
    return function


def _handle_value(value: object, *, label: str) -> int:
    invalid = ctypes.c_void_p(-1).value
    if type(invalid) is not int:
        raise WindowsWriterLeaseHolderError("无法计算 INVALID_HANDLE_VALUE")
    if type(value) is not int or value < 1 or value >= invalid:
        raise WindowsWriterLeaseHolderError(f"{label} HANDLE 整数域无效")
    return value


def _filetime(value: _FILETIME) -> int:
    result = (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)
    if result < 1:
        raise WindowsWriterLeaseHolderError("process creation FILETIME 无效")
    return result


def _normal_final_path(value: str) -> str:
    if type(value) is not str or not value:
        raise WindowsWriterLeaseHolderError("Windows final path 为空")
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return str(PureWindowsPath(value))


def _closed_root(root: Path, *, production: bool) -> Path:
    if type(root) is not type(Path()) or not root.is_absolute():
        raise WindowsWriterLeaseHolderError("writer lease root 必须是 absolute Path")
    try:
        _ensure_no_reparse_components(root)
        resolved = root.resolve(strict=True)
        root_info = resolved.lstat()
    except (OSError, ValueError) as error:
        raise WindowsWriterLeaseHolderError("writer lease root 不可用") from error
    if _stat_is_reparse_point(root_info) or not stat.S_ISDIR(root_info.st_mode):
        raise WindowsWriterLeaseHolderError("writer lease root 不是普通目录")
    if production and PureWindowsPath(str(resolved)) != _PRODUCTION_ROOT:
        raise WindowsWriterLeaseHolderError(
            r"production writer lease root 必须精确为 D:\quant\quant_platform"
        )
    for relative in (Path("state"), _TMP_RELATIVE):
        path = resolved / relative
        try:
            _ensure_no_reparse_components(path)
            info = path.lstat()
        except (OSError, ValueError) as error:
            raise WindowsWriterLeaseHolderError(
                f"writer lease 固定目录不可用: {relative.as_posix()}"
            ) from error
        if _stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
            raise WindowsWriterLeaseHolderError(
                f"writer lease 固定目录不安全: {relative.as_posix()}"
            )
        if not path.resolve(strict=True).is_relative_to(resolved):
            raise WindowsWriterLeaseHolderError("writer lease 目录逃逸 root")
    for relative in (_LOCK_RELATIVE, _RECORD_RELATIVE):
        path = resolved / relative
        _ensure_no_reparse_components(path)
        if not path.resolve(strict=False).is_relative_to(resolved):
            raise WindowsWriterLeaseHolderError("writer lease 文件逃逸 root")
    return resolved


def _expected_child_argv(
    identity: ExactRuntimeLeaseIdentity | ExactSteadyRuntimeIdentity,
) -> tuple[str, ...]:
    if type(identity) is ExactSteadyRuntimeIdentity:
        return identity.child_argv
    if type(identity) is not ExactRuntimeLeaseIdentity:
        raise TypeError("writer lease child argv identity 类型不匹配")
    return (
        _CHILD_EXECUTABLE,
        "-I",
        "-B",
        "-X",
        "utf8",
        "-X",
        "pycache_prefix=" + str(_PYCACHE_PARENT / identity.start_nonce),
        "-m",
        _CHILD_MODULE,
        "--deployment-attempt",
        identity.attempt_id,
        "--deployment-nonce",
        identity.nonce,
        "--deployment-operation",
        identity.operation,
        "--deployment-role",
        identity.role,
        "--start-nonce",
        identity.start_nonce,
        "--release-id",
        identity.release_id,
        "--manifest-sha256",
        identity.manifest_sha256,
        "--state-identity-sha256",
        identity.state_identity_sha256,
    )


def _expected_service_start_arguments(
    identity: ExactRuntimeLeaseIdentity,
) -> tuple[str, ...]:
    child = _expected_child_argv(identity)
    return ("exact-runtime", *child[9:])


class _ProductionWindowsApi:
    """固定 System32 kernel32 ctypes table；构造后不可替换。"""

    __slots__ = (
        "_binding_token",
        "_sealed",
        "create_file_w",
        "close_handle",
        "get_final_path_name_by_handle_w",
        "get_file_information_by_handle_ex",
        "read_file",
        "write_file",
        "flush_file_buffers",
        "move_file_ex_w",
        "delete_file_w",
        "get_current_process",
        "get_current_process_id",
        "get_command_line_w",
        "query_full_process_image_name_w",
        "open_process",
        "get_process_times",
        "wait_for_single_object",
        "get_exit_code_process",
        "create_toolhelp32_snapshot",
        "process32_first_w",
        "process32_next_w",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production writer lease API table 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production writer lease API table 构造后不可替换")
        object.__setattr__(self, name, value)

    def _assert_exact_binding(self) -> None:
        if (
            type(self) is not _ProductionWindowsApi
            or getattr(self, "_binding_token", None) is not _PRODUCTION_API_TOKEN
            or getattr(self, "_sealed", None) is not True
        ):
            raise WindowsWriterLeaseHolderError(
                "production writer lease API table 来源未闭合"
            )

    @classmethod
    def load_exact_d(cls) -> "_ProductionWindowsApi":
        if os.name != "nt":
            raise WindowsWriterLeaseHolderError(
                "production writer lease 只允许 Windows"
            )
        try:
            kernel32 = ctypes.WinDLL(
                "kernel32.dll",
                use_last_error=True,
                winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        except OSError as error:
            raise WindowsWriterLeaseHolderError(
                "无法从 System32 加载 kernel32.dll"
            ) from error
        self = object.__new__(cls)
        object.__setattr__(self, "_sealed", False)
        self.create_file_w = _bind(
            kernel32,
            "CreateFileW",
            (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ),
            wintypes.HANDLE,
        )
        self.close_handle = _bind(
            kernel32, "CloseHandle", (wintypes.HANDLE,), wintypes.BOOL
        )
        self.get_final_path_name_by_handle_w = _bind(
            kernel32,
            "GetFinalPathNameByHandleW",
            (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD),
            wintypes.DWORD,
        )
        self.get_file_information_by_handle_ex = _bind(
            kernel32,
            "GetFileInformationByHandleEx",
            (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD),
            wintypes.BOOL,
        )
        self.read_file = _bind(
            kernel32,
            "ReadFile",
            (
                wintypes.HANDLE,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.LPDWORD,
                ctypes.c_void_p,
            ),
            wintypes.BOOL,
        )
        self.write_file = _bind(
            kernel32,
            "WriteFile",
            (
                wintypes.HANDLE,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.LPDWORD,
                ctypes.c_void_p,
            ),
            wintypes.BOOL,
        )
        self.flush_file_buffers = _bind(
            kernel32, "FlushFileBuffers", (wintypes.HANDLE,), wintypes.BOOL
        )
        self.move_file_ex_w = _bind(
            kernel32,
            "MoveFileExW",
            (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD),
            wintypes.BOOL,
        )
        self.delete_file_w = _bind(
            kernel32, "DeleteFileW", (wintypes.LPCWSTR,), wintypes.BOOL
        )
        self.get_current_process = _bind(
            kernel32, "GetCurrentProcess", (), wintypes.HANDLE
        )
        self.get_current_process_id = _bind(
            kernel32, "GetCurrentProcessId", (), wintypes.DWORD
        )
        self.get_command_line_w = _bind(
            kernel32, "GetCommandLineW", (), wintypes.LPWSTR
        )
        self.query_full_process_image_name_w = _bind(
            kernel32,
            "QueryFullProcessImageNameW",
            (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, wintypes.LPDWORD),
            wintypes.BOOL,
        )
        self.open_process = _bind(
            kernel32,
            "OpenProcess",
            (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD),
            wintypes.HANDLE,
        )
        self.get_process_times = _bind(
            kernel32,
            "GetProcessTimes",
            (
                wintypes.HANDLE,
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
                ctypes.POINTER(_FILETIME),
            ),
            wintypes.BOOL,
        )
        self.wait_for_single_object = _bind(
            kernel32,
            "WaitForSingleObject",
            (wintypes.HANDLE, wintypes.DWORD),
            wintypes.DWORD,
        )
        self.get_exit_code_process = _bind(
            kernel32,
            "GetExitCodeProcess",
            (wintypes.HANDLE, wintypes.LPDWORD),
            wintypes.BOOL,
        )
        self.create_toolhelp32_snapshot = _bind(
            kernel32,
            "CreateToolhelp32Snapshot",
            (wintypes.DWORD, wintypes.DWORD),
            wintypes.HANDLE,
        )
        self.process32_first_w = _bind(
            kernel32,
            "Process32FirstW",
            (wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)),
            wintypes.BOOL,
        )
        self.process32_next_w = _bind(
            kernel32,
            "Process32NextW",
            (wintypes.HANDLE, ctypes.POINTER(_PROCESSENTRY32W)),
            wintypes.BOOL,
        )
        object.__setattr__(self, "_binding_token", _PRODUCTION_API_TOKEN)
        object.__setattr__(self, "_sealed", True)
        self._assert_exact_binding()
        return self


def _close_known_handle(api: _ProductionWindowsApi, handle: int, *, label: str) -> None:
    try:
        result = api.close_handle(handle)
    except BaseException as error:
        raise WindowsWriterLeaseOwnerCrashRequired(
            f"{label} close outcome unknown"
        ) from error
    if type(result) is not int or result == 0:
        raise WindowsWriterLeaseOwnerCrashRequired(
            f"{label} close 未机械确认；必须退出 owner process"
        )


def _query_file_identity(
    api: _ProductionWindowsApi,
    handle: int,
    *,
    expected_path: Path,
) -> _FileIdentity:
    buffer = ctypes.create_unicode_buffer(32768)
    length = api.get_final_path_name_by_handle_w(handle, buffer, len(buffer), 0)
    if type(length) is not int or length < 1 or length >= len(buffer):
        raise WindowsWriterLeaseHolderError(
            "GetFinalPathNameByHandleW 未返回闭合路径"
        )
    final_path = _normal_final_path(buffer.value)
    if PureWindowsPath(final_path) != PureWindowsPath(str(expected_path)):
        raise WindowsWriterLeaseHolderError("open handle final path 漂移")

    file_id = _FILE_ID_INFO()
    if not api.get_file_information_by_handle_ex(
        handle, _FILE_ID_INFO_CLASS, ctypes.byref(file_id), ctypes.sizeof(file_id)
    ):
        raise WindowsWriterLeaseHolderError(
            f"FileIdInfo failed with Windows error {ctypes.get_last_error()}"
        )
    standard = _FILE_STANDARD_INFO()
    if not api.get_file_information_by_handle_ex(
        handle,
        _FILE_STANDARD_INFO_CLASS,
        ctypes.byref(standard),
        ctypes.sizeof(standard),
    ):
        raise WindowsWriterLeaseHolderError(
            f"FileStandardInfo failed with Windows error {ctypes.get_last_error()}"
        )
    attributes = _FILE_ATTRIBUTE_TAG_INFO()
    if not api.get_file_information_by_handle_ex(
        handle,
        _FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(attributes),
        ctypes.sizeof(attributes),
    ):
        raise WindowsWriterLeaseHolderError(
            f"FileAttributeTagInfo failed with Windows error {ctypes.get_last_error()}"
        )
    if (
        type(standard.NumberOfLinks) is not int
        or standard.NumberOfLinks != 1
        or bool(standard.DeletePending)
        or bool(standard.Directory)
        or int(attributes.FileAttributes) & _FILE_ATTRIBUTE_REPARSE_POINT
        or int(standard.EndOfFile) < 0
    ):
        raise WindowsWriterLeaseHolderError(
            "writer lease 文件不是单链接、非 reparse 普通文件"
        )
    volume = int(file_id.VolumeSerialNumber)
    if volume < 1:
        raise WindowsWriterLeaseHolderError("writer lease volume serial 无效")
    identifier = bytes(file_id.FileId.Identifier).hex()
    if len(identifier) != 32:
        raise WindowsWriterLeaseHolderError("writer lease FILE_ID_128 无效")
    return _FileIdentity(
        final_path=final_path,
        volume_serial_number=volume,
        file_id=identifier,
        size=int(standard.EndOfFile),
    )


def _read_exact_file(
    api: _ProductionWindowsApi,
    path: Path,
    *,
    allow_absent: bool,
) -> bytes | None:
    ctypes.set_last_error(0)
    raw_handle = api.create_file_w(
        str(path),
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL
        | _FILE_FLAG_OPEN_REPARSE_POINT
        | _FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if raw_handle in {None, 0, -1, invalid}:
        error = ctypes.get_last_error()
        if allow_absent and error in {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}:
            return None
        raise WindowsWriterLeaseHolderError(
            f"无法只读打开 writer lease record: Windows error {error}"
        )
    handle = _handle_value(raw_handle, label="writer lease record")
    close_required = True
    primary: BaseException | None = None
    try:
        before = _query_file_identity(api, handle, expected_path=path)
        if before.size > _MAX_RECORD_BYTES:
            raise WindowsWriterLeaseHolderError("writer lease record 超过固定上限")
        chunks: list[bytes] = []
        remaining = before.size
        while remaining:
            size = min(remaining, 16 * 1024)
            buffer = ctypes.create_string_buffer(size)
            read = wintypes.DWORD()
            if not api.read_file(
                handle, buffer, size, ctypes.byref(read), None
            ):
                raise WindowsWriterLeaseHolderError(
                    f"ReadFile failed with Windows error {ctypes.get_last_error()}"
                )
            count = int(read.value)
            if count < 1 or count > size:
                raise WindowsWriterLeaseHolderError("ReadFile 长度/EOF 不闭合")
            chunks.append(buffer.raw[:count])
            remaining -= count
        after = _query_file_identity(api, handle, expected_path=path)
        if after != before:
            raise WindowsWriterLeaseHolderError("writer lease record 读取期间漂移")
        return b"".join(chunks)
    except BaseException as error:
        primary = error
        raise
    finally:
        if close_required:
            try:
                _close_known_handle(api, handle, label="writer lease record")
            except BaseException as close_error:
                if primary is None:
                    raise
                raise WindowsWriterLeaseOwnerCrashRequired(
                    "writer lease record 读取失败且 close 不可闭合"
                ) from close_error


def _previous_steady_epoch(
    value: Mapping[str, object], *, expected_lock_path: Path
) -> int:
    required = {
        "schema_version",
        "authority_kind",
        "runtime_state_kind",
        "boot_nonce",
        "active_release_sha256",
        "binding_sha256",
        "retention_aggregate_sha256",
        "state_identity_sha256",
        "tooling_sha256",
        "receipt_lineage_aggregate_sha256",
        "legacy_c_live_fence_aggregate_sha256",
        "authorization_sha256",
        "scm_identity_sha256",
        "release",
        "lease_id",
        "lease_nonce",
        "lease_epoch",
        "holder",
        "lock",
        "job_identity_sha256",
        "admission_binding_sha256",
        "lease_record_sha256",
    }
    if set(value) != required:
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease record schema 不闭合"
        )
    claimed = value.get("lease_record_sha256")
    material = dict(value)
    material.pop("lease_record_sha256")
    if (
        type(claimed) is not str
        or _SHA256_RE.fullmatch(claimed) is None
        or claimed != identity_sha256(material)
    ):
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease record hash 无效"
        )
    if (
        value.get("authority_kind") != "steady_active"
        or value.get("runtime_state_kind") != "steady_current"
    ):
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease authority 类型漂移"
        )
    boot_nonce = value.get("boot_nonce")
    lease_nonce = value.get("lease_nonce")
    epoch = value.get("lease_epoch")
    if (
        type(boot_nonce) is not str
        or _NONCE_192_RE.fullmatch(boot_nonce) is None
        or type(lease_nonce) is not str
        or _NONCE_192_RE.fullmatch(lease_nonce) is None
        or type(epoch) is not int
        or not 1 <= epoch < (1 << 63) - 1
    ):
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease nonce/epoch 无效"
        )
    for field in (
        "active_release_sha256",
        "binding_sha256",
        "retention_aggregate_sha256",
        "state_identity_sha256",
        "tooling_sha256",
        "receipt_lineage_aggregate_sha256",
        "legacy_c_live_fence_aggregate_sha256",
        "authorization_sha256",
        "scm_identity_sha256",
        "job_identity_sha256",
        "admission_binding_sha256",
    ):
        observed = value.get(field)
        if type(observed) is not str or _SHA256_RE.fullmatch(observed) is None:
            raise WindowsWriterLeaseHolderError(
                f"previous steady writer lease {field} 无效"
            )
    release = value.get("release")
    if type(release) is not dict or set(release) != {
        "release_id",
        "release_path",
        "manifest_sha256",
    }:
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease release 不闭合"
        )
    release_id = release.get("release_id")
    if (
        type(release_id) is not str
        or _IDENTIFIER_RE.fullmatch(release_id) is None
        or release.get("release_path")
        != str(_PRODUCTION_ROOT / "releases" / release_id)
        or type(release.get("manifest_sha256")) is not str
        or _SHA256_RE.fullmatch(str(release.get("manifest_sha256"))) is None
    ):
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease release identity 无效"
        )
    expected_lease_id = "steady-lease-" + identity_sha256(
        {
            "boot_nonce": boot_nonce,
            "active_release_sha256": value["active_release_sha256"],
            "binding_sha256": value["binding_sha256"],
            "lease_nonce": lease_nonce,
            "lease_epoch": epoch,
            "job_identity_sha256": value["job_identity_sha256"],
        }
    )[:32]
    if value.get("lease_id") != expected_lease_id:
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease id 无效"
        )
    holder = value.get("holder")
    if type(holder) is not dict or set(holder) != {
        "service_name",
        "host_pid",
        "host_creation_time_100ns",
        "child_pid",
        "child_creation_time_100ns",
        "holder_identity_sha256",
    }:
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease holder 不闭合"
        )
    if holder.get("service_name") != _SERVICE_NAME:
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease service 漂移"
        )
    for field in (
        "host_pid",
        "host_creation_time_100ns",
        "child_pid",
        "child_creation_time_100ns",
    ):
        if type(holder.get(field)) is not int or int(holder[field]) < 1:
            raise WindowsWriterLeaseHolderError(
                f"previous steady writer lease holder.{field} 无效"
            )
    holder_material = dict(holder)
    holder_hash = holder_material.pop("holder_identity_sha256")
    if holder_hash != identity_sha256(holder_material):
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease holder hash 无效"
        )
    lock = value.get("lock")
    if type(lock) is not dict or set(lock) != {
        "relative_path",
        "final_path",
        "handle_value",
        "volume_serial_number",
        "file_id",
        "desired_access",
        "share_mode",
        "creation_disposition",
        "lock_identity_sha256",
    }:
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease lock 不闭合"
        )
    _handle_value(lock["handle_value"], label="previous steady writer lock")
    if (
        type(lock.get("volume_serial_number")) is not int
        or not 1 <= int(lock["volume_serial_number"]) <= _MAX_VOLUME_SERIAL_NUMBER
        or type(lock.get("file_id")) is not str
        or _HEX_128_RE.fullmatch(str(lock["file_id"])) is None
        or lock.get("relative_path") != WRITER_LOCK_RELATIVE_PATH
        or PureWindowsPath(str(lock.get("final_path")))
        != PureWindowsPath(str(expected_lock_path))
        or lock.get("desired_access") != "GENERIC_READ|GENERIC_WRITE"
        or lock.get("share_mode") != "FILE_SHARE_READ"
        or lock.get("creation_disposition") != "OPEN_ALWAYS"
    ):
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease lock identity 无效"
        )
    lock_material = dict(lock)
    lock_hash = lock_material.pop("lock_identity_sha256")
    if lock_hash != identity_sha256(lock_material):
        raise WindowsWriterLeaseHolderError(
            "previous steady writer lease lock hash 无效"
        )
    return epoch


def _previous_epoch(raw: bytes | None, *, expected_lock_path: Path) -> int:
    if raw is None:
        return 0
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsWriterLeaseHolderError(
            "previous writer lease record 不是 UTF-8 JSON"
        ) from error
    if canonical_bytes(value) != raw or type(value) is not dict:
        raise WindowsWriterLeaseHolderError(
            "previous writer lease record 不是 canonical object"
        )
    if value.get("schema_version") == STEADY_WRITER_LEASE_RECORD_SCHEMA:
        return _previous_steady_epoch(value, expected_lock_path=expected_lock_path)
    required = {
        "schema_version",
        "attempt_id",
        "nonce",
        "operation",
        "role",
        "start_nonce",
        "authorization_sha256",
        "scm_identity_sha256",
        "state_identity_sha256",
        "release",
        "lease_id",
        "lease_nonce",
        "lease_epoch",
        "holder",
        "lock",
        "lease_record_sha256",
    }
    if set(value) != required or value.get("schema_version") != WRITER_LEASE_RECORD_SCHEMA:
        raise WindowsWriterLeaseHolderError("previous writer lease record schema 不闭合")
    claimed = value.get("lease_record_sha256")
    material = dict(value)
    material.pop("lease_record_sha256")
    if (
        type(claimed) is not str
        or _SHA256_RE.fullmatch(claimed) is None
        or claimed != identity_sha256(material)
    ):
        raise WindowsWriterLeaseHolderError("previous writer lease record hash 无效")
    epoch = value.get("lease_epoch")
    if type(epoch) is not int or not 1 <= epoch < (1 << 63) - 1:
        raise WindowsWriterLeaseHolderError("previous writer lease epoch 无效")
    for field in ("attempt_id", "nonce", "start_nonce", "release_id"):
        field_value = (
            value.get("release", {}).get("release_id")
            if field == "release_id" and type(value.get("release")) is dict
            else value.get(field)
        )
        if (
            type(field_value) is not str
            or _IDENTIFIER_RE.fullmatch(field_value) is None
            or field_value.endswith((".", " "))
        ):
            raise WindowsWriterLeaseHolderError(
                f"previous writer lease {field} 无效"
            )
    operation = value.get("operation")
    role = value.get("role")
    if operation == "bootstrap_first_pair":
        valid_role = role == "baseline"
    else:
        valid_role = operation in {"activation", "rollback"} and role in {
            "prior",
            "candidate",
        }
    if not valid_role:
        raise WindowsWriterLeaseHolderError(
            "previous writer lease operation/role 无效"
        )
    for field in (
        "authorization_sha256",
        "scm_identity_sha256",
        "state_identity_sha256",
    ):
        field_value = value.get(field)
        if (
            type(field_value) is not str
            or _SHA256_RE.fullmatch(field_value) is None
            or field_value == "0" * 64
        ):
            raise WindowsWriterLeaseHolderError(
                f"previous writer lease {field} 无效"
            )
    release = value.get("release")
    if type(release) is not dict or set(release) != {
        "release_id",
        "release_path",
        "manifest_sha256",
    }:
        raise WindowsWriterLeaseHolderError("previous writer lease release 不闭合")
    release_id = release["release_id"]
    if release["release_path"] != str(
        _PRODUCTION_ROOT / "releases" / str(release_id)
    ):
        raise WindowsWriterLeaseHolderError(
            "previous writer lease release path 无效"
        )
    manifest = release["manifest_sha256"]
    if (
        type(manifest) is not str
        or _SHA256_RE.fullmatch(manifest) is None
        or manifest == "0" * 64
    ):
        raise WindowsWriterLeaseHolderError(
            "previous writer lease manifest hash 无效"
        )
    lease_nonce = value.get("lease_nonce")
    if type(lease_nonce) is not str or _NONCE_192_RE.fullmatch(lease_nonce) is None:
        raise WindowsWriterLeaseHolderError("previous writer lease nonce 无效")
    expected_lease_id = "lease-" + identity_sha256(
        {
            "attempt_id": value["attempt_id"],
            "nonce": value["nonce"],
            "role": value["role"],
            "start_nonce": value["start_nonce"],
            "lease_nonce": lease_nonce,
            "lease_epoch": epoch,
        }
    )[:32]
    if value.get("lease_id") != expected_lease_id:
        raise WindowsWriterLeaseHolderError("previous writer lease id 无效")
    holder = value.get("holder")
    if type(holder) is not dict or set(holder) != {
        "service_name",
        "host_pid",
        "host_creation_time_100ns",
        "child_pid",
        "child_creation_time_100ns",
        "holder_identity_sha256",
    }:
        raise WindowsWriterLeaseHolderError("previous writer lease holder 不闭合")
    if holder["service_name"] != _SERVICE_NAME:
        raise WindowsWriterLeaseHolderError("previous writer lease service 漂移")
    for field in (
        "host_pid",
        "host_creation_time_100ns",
        "child_pid",
        "child_creation_time_100ns",
    ):
        if type(holder[field]) is not int or holder[field] < 1:
            raise WindowsWriterLeaseHolderError(
                f"previous writer lease holder.{field} 无效"
            )
    holder_material = dict(holder)
    holder_hash = holder_material.pop("holder_identity_sha256")
    if holder_hash != identity_sha256(holder_material):
        raise WindowsWriterLeaseHolderError("previous writer lease holder hash 无效")
    lock = value.get("lock")
    if type(lock) is not dict or set(lock) != {
        "relative_path",
        "final_path",
        "handle_value",
        "volume_serial_number",
        "file_id",
        "desired_access",
        "share_mode",
        "creation_disposition",
        "lock_identity_sha256",
    }:
        raise WindowsWriterLeaseHolderError("previous writer lease lock 不闭合")
    _handle_value(lock["handle_value"], label="previous writer lock")
    if (
        type(lock["volume_serial_number"]) is not int
        or lock["volume_serial_number"] < 1
        or lock["volume_serial_number"] > _MAX_VOLUME_SERIAL_NUMBER
        or type(lock["file_id"]) is not str
        or _HEX_128_RE.fullmatch(lock["file_id"]) is None
        or lock["relative_path"] != WRITER_LOCK_RELATIVE_PATH
        or PureWindowsPath(str(lock["final_path"]))
        != PureWindowsPath(str(expected_lock_path))
        or lock["desired_access"] != "GENERIC_READ|GENERIC_WRITE"
        or lock["share_mode"] != "FILE_SHARE_READ"
        or lock["creation_disposition"] != "OPEN_ALWAYS"
    ):
        raise WindowsWriterLeaseHolderError("previous writer lease lock identity 无效")
    lock_material = dict(lock)
    lock_hash = lock_material.pop("lock_identity_sha256")
    if lock_hash != identity_sha256(lock_material):
        raise WindowsWriterLeaseHolderError("previous writer lease lock hash 无效")
    return epoch


def _write_through_replace(
    api: _ProductionWindowsApi,
    *,
    tmp_dir: Path,
    final_path: Path,
    raw: bytes,
    replace_existing: bool = True,
) -> None:
    if type(replace_existing) is not bool:
        raise WindowsWriterLeaseHolderError("write-through replace policy 无效")
    if not raw or len(raw) > _MAX_RECORD_BYTES:
        raise WindowsWriterLeaseHolderError("writer lease record bytes 长度无效")
    temp_path: Path | None = None
    handle: int | None = None
    for _ in range(8):
        candidate = tmp_dir / f"writer-lease-{secrets.token_hex(24)}.tmp"
        ctypes.set_last_error(0)
        raw_handle = api.create_file_w(
            str(candidate),
            _GENERIC_WRITE,
            0,
            None,
            _CREATE_NEW,
            _FILE_ATTRIBUTE_NORMAL
            | _FILE_FLAG_OPEN_REPARSE_POINT
            | _FILE_FLAG_WRITE_THROUGH,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if raw_handle not in {None, 0, -1, invalid}:
            temp_path = candidate
            handle = _handle_value(raw_handle, label="writer lease temp")
            break
        error = ctypes.get_last_error()
        if error not in {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}:
            raise WindowsWriterLeaseHolderError(
                f"无法创建 writer lease temp: Windows error {error}"
            )
    if temp_path is None or handle is None:
        raise WindowsWriterLeaseHolderError("writer lease temp nonce 连续碰撞")
    primary: BaseException | None = None
    try:
        identity = _query_file_identity(api, handle, expected_path=temp_path)
        if identity.size != 0:
            raise WindowsWriterLeaseHolderError("新 writer lease temp 非空")
        offset = 0
        while offset < len(raw):
            block = raw[offset : offset + 16 * 1024]
            buffer = ctypes.create_string_buffer(block)
            written = wintypes.DWORD()
            if not api.write_file(
                handle,
                buffer,
                len(block),
                ctypes.byref(written),
                None,
            ):
                raise WindowsWriterLeaseHolderError(
                    f"WriteFile failed with Windows error {ctypes.get_last_error()}"
                )
            count = int(written.value)
            if count < 1 or count > len(block):
                raise WindowsWriterLeaseHolderError("WriteFile 长度不闭合")
            offset += count
        if not api.flush_file_buffers(handle):
            raise WindowsWriterLeaseHolderError(
                f"FlushFileBuffers failed with Windows error {ctypes.get_last_error()}"
            )
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            _close_known_handle(api, handle, label="writer lease temp")
        except BaseException as close_error:
            if primary is None:
                raise
            raise WindowsWriterLeaseOwnerCrashRequired(
                "writer lease temp write 失败且 close 不可闭合"
            ) from close_error
    try:
        move_flags = _MOVEFILE_WRITE_THROUGH
        if replace_existing:
            move_flags |= _MOVEFILE_REPLACE_EXISTING
        if not api.move_file_ex_w(str(temp_path), str(final_path), move_flags):
            raise WindowsWriterLeaseHolderError(
                f"MoveFileExW failed with Windows error {ctypes.get_last_error()}"
            )
    except BaseException as move_error:
        # temp 是本调用在精确 tmp_dir 内以 CREATE_NEW 创建的唯一文件。
        try:
            deleted = api.delete_file_w(str(temp_path))
        except BaseException as cleanup_error:
            raise WindowsWriterLeaseHolderError(
                "writer lease replace 失败且 temp cleanup outcome unknown"
            ) from cleanup_error
        if type(deleted) is not int or deleted == 0:
            raise WindowsWriterLeaseHolderError(
                "writer lease replace 失败且 temp cleanup 未闭合"
            ) from move_error
        raise move_error


def _process_times(api: _ProductionWindowsApi, handle: int) -> int:
    creation = _FILETIME()
    exit_time = _FILETIME()
    kernel = _FILETIME()
    user = _FILETIME()
    if not api.get_process_times(
        handle,
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise WindowsWriterLeaseHolderError(
            f"GetProcessTimes failed with Windows error {ctypes.get_last_error()}"
        )
    return _filetime(creation)


def _parent_pid(api: _ProductionWindowsApi, child_pid: int) -> int:
    raw_snapshot = api.create_toolhelp32_snapshot(_TH32CS_SNAPPROCESS, 0)
    snapshot = _handle_value(raw_snapshot, label="process snapshot")
    primary: BaseException | None = None
    try:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        if not api.process32_first_w(snapshot, ctypes.byref(entry)):
            raise WindowsWriterLeaseHolderError(
                f"Process32FirstW failed with Windows error {ctypes.get_last_error()}"
            )
        matches: list[int] = []
        while True:
            if int(entry.th32ProcessID) == child_pid:
                matches.append(int(entry.th32ParentProcessID))
            entry.dwSize = ctypes.sizeof(entry)
            if not api.process32_next_w(snapshot, ctypes.byref(entry)):
                error = ctypes.get_last_error()
                if error != _ERROR_NO_MORE_FILES:
                    raise WindowsWriterLeaseHolderError(
                        f"Process32NextW failed with Windows error {error}"
                    )
                break
        if len(matches) != 1 or matches[0] < 1:
            raise WindowsWriterLeaseHolderError(
                "当前 child 的唯一 parent PID 不可闭合"
            )
        return matches[0]
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            _close_known_handle(api, snapshot, label="process snapshot")
        except BaseException as close_error:
            if primary is None:
                raise
            raise WindowsWriterLeaseOwnerCrashRequired(
                "process snapshot 查询失败且 close 不可闭合"
            ) from close_error


def _process_identity(
    api: _ProductionWindowsApi,
    *,
    expected_parent_executable: str | None = None,
) -> _ProcessIdentity:
    child_pid = int(api.get_current_process_id())
    if child_pid < 1:
        raise WindowsWriterLeaseHolderError("GetCurrentProcessId 无效")
    current = api.get_current_process()
    current_handle = ctypes.c_void_p(-1).value
    if type(current_handle) is not int or current != current_handle:
        raise WindowsWriterLeaseHolderError("GetCurrentProcess 未返回固定 pseudo handle")
    child_creation = _process_times(api, current_handle)
    host_pid = _parent_pid(api, child_pid)
    raw_host = api.open_process(
        _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE,
        False,
        host_pid,
    )
    host = _handle_value(raw_host, label="parent process")
    primary: BaseException | None = None
    try:
        host_creation = _process_times(api, host)
        if expected_parent_executable is not None:
            buffer = ctypes.create_unicode_buffer(32768)
            size = wintypes.DWORD(len(buffer))
            if not api.query_full_process_image_name_w(
                host, 0, buffer, ctypes.byref(size)
            ):
                raise WindowsWriterLeaseHolderError(
                    "无法查询 production parent executable"
                )
            if PureWindowsPath(_normal_final_path(buffer.value)) != PureWindowsPath(
                expected_parent_executable
            ):
                raise WindowsWriterLeaseHolderError(
                    "production writer lease parent 不是 exact SCM host"
                )
        wait = api.wait_for_single_object(host, 0)
        exit_code = wintypes.DWORD()
        if (
            type(wait) is not int
            or wait != _WAIT_TIMEOUT
            or not api.get_exit_code_process(host, ctypes.byref(exit_code))
            or int(exit_code.value) != _STILL_ACTIVE
        ):
            raise WindowsWriterLeaseHolderError(
                "parent process 在 lease acquisition 期间不是 live"
            )
        return _ProcessIdentity(
            host_pid=host_pid,
            host_creation_time_100ns=host_creation,
            child_pid=child_pid,
            child_creation_time_100ns=child_creation,
        )
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            _close_known_handle(api, host, label="parent process")
        except BaseException as close_error:
            if primary is None:
                raise
            raise WindowsWriterLeaseOwnerCrashRequired(
                "parent process 查询失败且 close 不可闭合"
            ) from close_error


def _assert_exact_production_process(
    api: _ProductionWindowsApi,
    identity: ExactRuntimeLeaseIdentity | ExactSteadyRuntimeIdentity,
    root: Path,
) -> None:
    if type(identity) not in {ExactRuntimeLeaseIdentity, ExactSteadyRuntimeIdentity}:
        raise TypeError("production writer lease runtime identity 类型不匹配")
    current = ctypes.c_void_p(-1).value
    if type(current) is not int or api.get_current_process() != current:
        raise WindowsWriterLeaseHolderError(
            "production writer lease current-process pseudo handle 漂移"
        )
    buffer = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(buffer))
    if not api.query_full_process_image_name_w(
        current, 0, buffer, ctypes.byref(size)
    ):
        raise WindowsWriterLeaseHolderError(
            "production writer lease 无法查询 current executable"
        )
    executable = _normal_final_path(buffer.value)
    if PureWindowsPath(executable) != PureWindowsPath(_CHILD_EXECUTABLE):
        raise WindowsWriterLeaseHolderError(
            "production writer lease current executable 不是 exact D child"
        )
    command_line = api.get_command_line_w()
    expected_argv = _expected_child_argv(identity)
    if (
        type(command_line) is not str
        or command_line != subprocess.list2cmdline(list(expected_argv))
    ):
        raise WindowsWriterLeaseHolderError(
            "production writer lease current argv 不是 exact SCM start plan"
        )
    expected_tmp = root / _TMP_RELATIVE
    for variable in ("TEMP", "TMP"):
        value = os.environ.get(variable)
        if type(value) is not str or PureWindowsPath(value) != PureWindowsPath(
            str(expected_tmp)
        ):
            raise WindowsWriterLeaseHolderError(
                f"production writer lease {variable} 不是 exact D service tmp"
            )
    steady = type(identity) is ExactSteadyRuntimeIdentity
    nonce = identity.boot_nonce if steady else identity.start_nonce
    expected_pycache = str(_PYCACHE_PARENT / nonce)
    if (
        os.environ.get("PYTHONDONTWRITEBYTECODE") != "1"
        or sys.dont_write_bytecode is not True
        or sys.flags.isolated != 1
        or sys.flags.utf8_mode != 1
        or type(sys.pycache_prefix) is not str
        or PureWindowsPath(sys.pycache_prefix)
        != PureWindowsPath(expected_pycache)
    ):
        raise WindowsWriterLeaseHolderError(
            "production writer lease 必须禁用 bytecode 写入"
        )
    pycache_sentinel = Path(str(_PYCACHE_PARENT / nonce))
    sentinel_identity = (
        {"boot_nonce": nonce} if steady else {"start_nonce": nonce}
    )
    expected_sentinel_raw = (
        json.dumps(
            {
                "schema_version": "qrh-exact-runtime-pycache-sentinel/v1",
                **sentinel_identity,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    try:
        _ensure_no_reparse_components(pycache_sentinel)
        sentinel_info = pycache_sentinel.lstat()
        sentinel_raw = pycache_sentinel.read_bytes()
    except OSError as error:
        raise WindowsWriterLeaseHolderError(
            "production writer lease pycache sentinel 不可用"
        ) from error
    if (
        _stat_is_reparse_point(sentinel_info)
        or not stat.S_ISREG(sentinel_info.st_mode)
        or sentinel_info.st_nlink != 1
        or sentinel_raw != expected_sentinel_raw
    ):
        raise WindowsWriterLeaseHolderError(
            "production writer lease pycache sentinel 未闭合"
        )


def _lease_record(
    identity: ExactRuntimeLeaseIdentity,
    process: _ProcessIdentity,
    file: _FileIdentity,
    *,
    handle: int,
    lease_nonce: str,
    lease_epoch: int,
) -> dict[str, object]:
    holder: dict[str, object] = {
        "service_name": _SERVICE_NAME,
        "host_pid": process.host_pid,
        "host_creation_time_100ns": process.host_creation_time_100ns,
        "child_pid": process.child_pid,
        "child_creation_time_100ns": process.child_creation_time_100ns,
    }
    holder["holder_identity_sha256"] = identity_sha256(holder)
    lock: dict[str, object] = {
        "relative_path": WRITER_LOCK_RELATIVE_PATH,
        "final_path": file.final_path,
        "handle_value": handle,
        "volume_serial_number": file.volume_serial_number,
        "file_id": file.file_id,
        "desired_access": "GENERIC_READ|GENERIC_WRITE",
        "share_mode": "FILE_SHARE_READ",
        "creation_disposition": "OPEN_ALWAYS",
    }
    lock["lock_identity_sha256"] = identity_sha256(lock)
    record: dict[str, object] = {
        "schema_version": WRITER_LEASE_RECORD_SCHEMA,
        "attempt_id": identity.attempt_id,
        "nonce": identity.nonce,
        "operation": identity.operation,
        "role": identity.role,
        "start_nonce": identity.start_nonce,
        "authorization_sha256": identity.authorization_sha256,
        "scm_identity_sha256": identity.scm_identity_sha256,
        "state_identity_sha256": identity.state_identity_sha256,
        "release": {
            "release_id": identity.release_id,
            "release_path": identity.release_path,
            "manifest_sha256": identity.manifest_sha256,
        },
        "lease_id": "pending",
        "lease_nonce": lease_nonce,
        "lease_epoch": lease_epoch,
        "holder": holder,
        "lock": lock,
    }
    record["lease_id"] = "lease-" + identity_sha256(
        {
            "attempt_id": record["attempt_id"],
            "nonce": record["nonce"],
            "role": record["role"],
            "start_nonce": record["start_nonce"],
            "lease_nonce": record["lease_nonce"],
            "lease_epoch": record["lease_epoch"],
        }
    )[:32]
    record["lease_record_sha256"] = identity_sha256(record)
    return record


def _steady_lease_record(
    identity: ExactSteadyRuntimeIdentity,
    process: _ProcessIdentity,
    file: _FileIdentity,
    *,
    handle: int,
    lease_nonce: str,
    lease_epoch: int,
    job_identity_sha256: str,
    admission_binding_sha256: str,
) -> dict[str, object]:
    if type(identity) is not ExactSteadyRuntimeIdentity:
        raise TypeError("steady writer record identity 类型不匹配")
    for label, value in (
        ("job_identity_sha256", job_identity_sha256),
        ("admission_binding_sha256", admission_binding_sha256),
    ):
        if type(value) is not str or _SHA256_RE.fullmatch(value) is None:
            raise WindowsWriterLeaseHolderError(f"steady writer {label} 无效")
    holder: dict[str, object] = {
        "service_name": _SERVICE_NAME,
        "host_pid": process.host_pid,
        "host_creation_time_100ns": process.host_creation_time_100ns,
        "child_pid": process.child_pid,
        "child_creation_time_100ns": process.child_creation_time_100ns,
    }
    holder["holder_identity_sha256"] = identity_sha256(holder)
    lock: dict[str, object] = {
        "relative_path": WRITER_LOCK_RELATIVE_PATH,
        "final_path": file.final_path,
        "handle_value": handle,
        "volume_serial_number": file.volume_serial_number,
        "file_id": file.file_id,
        "desired_access": "GENERIC_READ|GENERIC_WRITE",
        "share_mode": "FILE_SHARE_READ",
        "creation_disposition": "OPEN_ALWAYS",
    }
    lock["lock_identity_sha256"] = identity_sha256(lock)
    record: dict[str, object] = {
        "schema_version": STEADY_WRITER_LEASE_RECORD_SCHEMA,
        "authority_kind": "steady_active",
        "runtime_state_kind": "steady_current",
        "boot_nonce": identity.boot_nonce,
        "active_release_sha256": identity.active_release_sha256,
        "binding_sha256": identity.binding_sha256,
        "retention_aggregate_sha256": identity.retention_aggregate_sha256,
        "state_identity_sha256": identity.state_identity_sha256,
        "tooling_sha256": identity.tooling_sha256,
        "receipt_lineage_aggregate_sha256": (
            identity.receipt_lineage_aggregate_sha256
        ),
        "legacy_c_live_fence_aggregate_sha256": (
            identity.legacy_c_live_fence_aggregate_sha256
        ),
        "authorization_sha256": identity.authorization_sha256,
        "scm_identity_sha256": identity.scm_identity_sha256,
        "release": dict(identity.release_ref),
        "lease_id": "pending",
        "lease_nonce": lease_nonce,
        "lease_epoch": lease_epoch,
        "holder": holder,
        "lock": lock,
        "job_identity_sha256": job_identity_sha256,
        "admission_binding_sha256": admission_binding_sha256,
    }
    record["lease_id"] = "steady-lease-" + identity_sha256(
        {
            "boot_nonce": record["boot_nonce"],
            "active_release_sha256": record["active_release_sha256"],
            "binding_sha256": record["binding_sha256"],
            "lease_nonce": record["lease_nonce"],
            "lease_epoch": record["lease_epoch"],
            "job_identity_sha256": record["job_identity_sha256"],
        }
    )[:32]
    record["lease_record_sha256"] = identity_sha256(record)
    return record


@dataclass(frozen=True, slots=True)
class _CollectedWriterLease:
    api: _ProductionWindowsApi
    root: Path
    handle: int
    record_raw: bytes


class _WindowsWriterLeaseHolderRunner:
    __slots__ = ("_api",)

    def __init__(self, api: _ProductionWindowsApi):
        if type(api) is not _ProductionWindowsApi:
            raise TypeError("writer lease runner 拒绝 fake API table")
        api._assert_exact_binding()
        self._api = api

    def acquire(
        self,
        root: Path,
        identity: ExactRuntimeLeaseIdentity | LockedExactRuntimeAdmissionGate,
        *,
        production: bool,
    ) -> _CollectedWriterLease:
        steady_gate: LockedExactRuntimeAdmissionGate | None = None
        if type(identity) is LockedExactRuntimeAdmissionGate:
            if not production:
                raise WindowsWriterLeaseHolderError(
                    "steady writer lease 不允许 test-root runner"
                )
            steady_gate = identity
            runtime_identity = identity._identity  # noqa: SLF001
            if type(runtime_identity) is not ExactSteadyRuntimeIdentity:
                raise WindowsWriterLeaseHolderError(
                    "steady admission gate runtime identity 漂移"
                )
        elif type(identity) is ExactRuntimeLeaseIdentity:
            runtime_identity = identity
        else:
            raise WindowsWriterLeaseHolderError(
                "writer lease 只接受 exact runtime identity"
            )
        api = self._api
        api._assert_exact_binding()
        safe_root = _closed_root(root, production=production)
        if production:
            _assert_exact_production_process(api, runtime_identity, safe_root)
        process_before = _process_identity(
            api,
            expected_parent_executable=(
                _SCM_HOST_EXECUTABLE if production else None
            ),
        )
        if (
            steady_gate is not None
            and {
                "host_pid": process_before.host_pid,
                "host_creation_time_100ns": (
                    process_before.host_creation_time_100ns
                ),
                "child_pid": process_before.child_pid,
                "child_creation_time_100ns": (
                    process_before.child_creation_time_100ns
                ),
            }
            != steady_gate._process_identity  # noqa: SLF001
        ):
            raise WindowsWriterLeaseHolderError(
                "steady admission gate 与 writer process identity 不一致"
            )
        lock_path = safe_root / _LOCK_RELATIVE
        record_path = safe_root / _RECORD_RELATIVE
        tmp_dir = safe_root / _TMP_RELATIVE
        ctypes.set_last_error(0)
        raw_lock = api.create_file_w(
            str(lock_path),
            _GENERIC_READ | _GENERIC_WRITE,
            _FILE_SHARE_READ,
            None,
            _OPEN_ALWAYS,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if raw_lock in {None, 0, -1, invalid}:
            error = ctypes.get_last_error()
            if error == _ERROR_SHARING_VIOLATION:
                raise WindowsWriterLeaseBusy(
                    "writer_authority.lock 已由另一 writer 持有"
                )
            raise WindowsWriterLeaseHolderError(
                f"CreateFileW(writer lock) failed with Windows error {error}"
            )
        handle = _handle_value(raw_lock, label="writer authority lock")
        primary: BaseException | None = None
        try:
            file_before = _query_file_identity(api, handle, expected_path=lock_path)
            previous = _read_exact_file(api, record_path, allow_absent=True)
            epoch = _previous_epoch(previous, expected_lock_path=lock_path) + 1
            lease_nonce = secrets.token_hex(24)
            if steady_gate is None:
                if type(runtime_identity) is not ExactRuntimeLeaseIdentity:
                    raise WindowsWriterLeaseHolderError(
                        "transient writer runtime identity 漂移"
                    )
                record = _lease_record(
                    runtime_identity,
                    process_before,
                    file_before,
                    handle=handle,
                    lease_nonce=lease_nonce,
                    lease_epoch=epoch,
                )
            else:
                if type(runtime_identity) is not ExactSteadyRuntimeIdentity:
                    raise WindowsWriterLeaseHolderError(
                        "steady writer runtime identity 漂移"
                    )
                record = _steady_lease_record(
                    runtime_identity,
                    process_before,
                    file_before,
                    handle=handle,
                    lease_nonce=lease_nonce,
                    lease_epoch=epoch,
                    job_identity_sha256=steady_gate.job_identity_sha256,
                    admission_binding_sha256=(
                        steady_gate.admission_binding_sha256
                    ),
                )
            raw = canonical_bytes(record)
            _write_through_replace(
                api, tmp_dir=tmp_dir, final_path=record_path, raw=raw
            )
            observed = _read_exact_file(api, record_path, allow_absent=False)
            file_after = _query_file_identity(api, handle, expected_path=lock_path)
            process_after = _process_identity(
                api,
                expected_parent_executable=(
                    _SCM_HOST_EXECUTABLE if production else None
                ),
            )
            if observed != raw or file_after != file_before or process_after != process_before:
                raise WindowsWriterLeaseHolderError(
                    "writer lease publication 前后身份漂移"
                )
            return _CollectedWriterLease(api, safe_root, handle, raw)
        except BaseException as error:
            primary = error
            try:
                _close_known_handle(api, handle, label="writer authority lock")
            except BaseException as close_error:
                raise WindowsWriterLeaseOwnerCrashRequired(
                    "writer lease acquisition 失败且 lock close 不可闭合"
                ) from close_error
            raise primary


class LockedWindowsWriterLease:
    """生产 child 持有的 process-local lease；不是 canary/formal 资格。"""

    __slots__ = ("_api", "_root", "_handle", "_record_raw", "_state", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("live Windows writer lease 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("live Windows writer lease 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        collected: _CollectedWriterLease,
        *,
        _construction_token: object,
    ):
        if _construction_token is not _LIVE_LEASE_TOKEN:
            raise TypeError("live Windows writer lease 必须由 production holder 构造")
        if (
            type(collected) is not _CollectedWriterLease
            or type(collected.api) is not _ProductionWindowsApi
            or PureWindowsPath(str(collected.root)) != _PRODUCTION_ROOT
        ):
            raise TypeError("live Windows writer lease production provenance 无效")
        collected.api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._api = collected.api
        self._root = collected.root
        self._handle = collected.handle
        self._record_raw = collected.record_raw
        self._state = "live"
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("live Windows writer lease is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(self) -> None:
        self._api._assert_exact_binding()
        if self._state != "live":
            raise WindowsWriterLeaseHolderError("live writer lease 已撤销")
        _handle_value(self._handle, label="live writer authority lock")

    def _canary_checkpoint(
        self,
    ) -> tuple[dict[str, object], Path, _ProductionWindowsApi]:
        """Re-prove the live handle and exact frozen record for child canary use.

        This private seam does not expose a serializable capability.  The canary
        runner must call it before and after every SQLite side effect; a replaced
        or rewritten record fails before another write can be attempted.
        """

        self._assert_live()
        lock_identity = _query_file_identity(
            self._api,
            self._handle,
            expected_path=self._root / _LOCK_RELATIVE,
        )
        observed = _read_exact_file(
            self._api,
            self._root / _RECORD_RELATIVE,
            allow_absent=False,
        )
        if observed != self._record_raw:
            raise WindowsWriterLeaseHolderError(
                "live writer lease frozen record 已漂移"
            )
        document = self.record_document
        lock = document.get("lock")
        if (
            type(lock) is not dict
            or lock.get("handle_value") != self._handle
            or lock.get("final_path") != lock_identity.final_path
            or lock.get("volume_serial_number")
            != lock_identity.volume_serial_number
            or lock.get("file_id") != lock_identity.file_id
        ):
            raise WindowsWriterLeaseHolderError(
                "live writer lease lock identity 已漂移"
            )
        return document, self._root, self._api

    @property
    def scope(self) -> str:
        self._assert_live()
        return LIVE_WINDOWS_WRITER_LEASE_SCOPE

    @property
    def lease_claim(self) -> dict[str, object]:
        self._assert_live()
        record = self.record_document
        return {
            "lease_id": record["lease_id"],
            "lease_nonce": record["lease_nonce"],
            "lease_epoch": record["lease_epoch"],
            "lease_record_sha256": record["lease_record_sha256"],
            "authority": "claim_not_independently_observed",
        }

    @property
    def record_document(self) -> dict[str, object]:
        self._assert_live()
        value = json.loads(self._record_raw.decode("utf-8"))
        if type(value) is not dict or canonical_bytes(value) != self._record_raw:
            raise WindowsWriterLeaseHolderError("frozen writer lease record 损坏")
        return value

    def close(self) -> None:
        self._assert_live()
        handle = self._handle
        try:
            _close_known_handle(self._api, handle, label="writer authority lock")
        except BaseException:
            object.__setattr__(self, "_state", "owner_crash_only")
            object.__setattr__(self, "_handle", 0)
            raise
        object.__setattr__(self, "_handle", 0)
        object.__setattr__(self, "_state", "closed")

    def _retire_to_owner_crash_only(self) -> None:
        """Forget numeric close authority and leave kernel release to process exit."""

        if self._state != "live":
            raise WindowsWriterLeaseHolderError(
                "writer lease cannot enter owner-crash-only from current state"
            )
        object.__setattr__(self, "_state", "owner_crash_only")
        object.__setattr__(self, "_handle", 0)

    def _finalize_for_process_exit(self) -> None:
        """Close normally, or preserve an already-retired handle until process exit."""

        if self._state == "owner_crash_only":
            return
        self.close()

    def __enter__(self) -> "LockedWindowsWriterLease":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedSteadyWindowsWriterLease:
    """Steady child 的 distinct live writer lease；不接受 transient identity。"""

    __slots__ = ("_api", "_root", "_handle", "_record_raw", "_state", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("live steady Windows writer lease 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("live steady Windows writer lease 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        collected: _CollectedWriterLease,
        *,
        _construction_token: object,
    ):
        if _construction_token is not _LIVE_STEADY_LEASE_TOKEN:
            raise TypeError(
                "live steady Windows writer lease 必须由 production holder 构造"
            )
        if (
            type(collected) is not _CollectedWriterLease
            or type(collected.api) is not _ProductionWindowsApi
            or PureWindowsPath(str(collected.root)) != _PRODUCTION_ROOT
        ):
            raise TypeError(
                "live steady Windows writer lease production provenance 无效"
            )
        try:
            record = json.loads(collected.record_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise TypeError("live steady writer record 不可解析") from error
        if (
            type(record) is not dict
            or canonical_bytes(record) != collected.record_raw
            or record.get("schema_version") != STEADY_WRITER_LEASE_RECORD_SCHEMA
        ):
            raise TypeError("live steady writer record schema 不匹配")
        collected.api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._api = collected.api
        self._root = collected.root
        self._handle = collected.handle
        self._record_raw = collected.record_raw
        self._state = "live"
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("live steady Windows writer lease is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    _assert_live = LockedWindowsWriterLease._assert_live
    _canary_checkpoint = LockedWindowsWriterLease._canary_checkpoint
    lease_claim = LockedWindowsWriterLease.lease_claim
    record_document = LockedWindowsWriterLease.record_document
    close = LockedWindowsWriterLease.close
    _retire_to_owner_crash_only = (
        LockedWindowsWriterLease._retire_to_owner_crash_only
    )
    _finalize_for_process_exit = LockedWindowsWriterLease._finalize_for_process_exit

    @property
    def scope(self) -> str:
        self._assert_live()
        return LIVE_STEADY_WINDOWS_WRITER_LEASE_SCOPE

    def __enter__(self) -> "LockedSteadyWindowsWriterLease":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class ProductionWindowsWriterLeaseHolder:
    """无 root/API 注入的 exact-D child-side holder。"""

    __slots__ = ("_api", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production Windows writer lease holder 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production Windows writer lease holder 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, api: object, *, _construction_token: object):
        if (
            _construction_token is not _PRODUCTION_HOLDER_TOKEN
            or type(api) is not _ProductionWindowsApi
        ):
            raise TypeError("production holder 必须由 load_exact_d() 构造")
        api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._api = api
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production Windows writer lease holder is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionWindowsWriterLeaseHolder":
        api = _ProductionWindowsApi.load_exact_d()
        return cls(api, _construction_token=_PRODUCTION_HOLDER_TOKEN)

    def acquire_exact_d(
        self, identity: ExactRuntimeLeaseIdentity
    ) -> LockedWindowsWriterLease:
        if type(self._api) is not _ProductionWindowsApi:
            raise WindowsWriterLeaseHolderError("production holder API table 漂移")
        self._api._assert_exact_binding()
        collected = _WindowsWriterLeaseHolderRunner(self._api).acquire(
            Path(str(_PRODUCTION_ROOT)), identity, production=True
        )
        try:
            return LockedWindowsWriterLease(
                collected, _construction_token=_LIVE_LEASE_TOKEN
            )
        except BaseException as error:
            try:
                _close_known_handle(
                    collected.api,
                    collected.handle,
                    label="writer authority lock finalization",
                )
            except BaseException as close_error:
                raise WindowsWriterLeaseOwnerCrashRequired(
                    "writer lease finalization 失败且 lock close 不可闭合"
                ) from close_error
            raise error

    def acquire_steady_exact_d(
        self, gate: LockedExactRuntimeAdmissionGate
    ) -> LockedSteadyWindowsWriterLease:
        """只以当前 child 的 live admission gate 获取 steady v2 writer lease。"""

        if type(gate) is not LockedExactRuntimeAdmissionGate:
            raise TypeError("steady writer holder requires exact live admission gate")
        if type(self._api) is not _ProductionWindowsApi:
            raise WindowsWriterLeaseHolderError("production holder API table 漂移")
        self._api._assert_exact_binding()
        collected = _WindowsWriterLeaseHolderRunner(self._api).acquire(
            Path(str(_PRODUCTION_ROOT)), gate, production=True
        )
        try:
            return LockedSteadyWindowsWriterLease(
                collected, _construction_token=_LIVE_STEADY_LEASE_TOKEN
            )
        except BaseException as error:
            try:
                _close_known_handle(
                    collected.api,
                    collected.handle,
                    label="steady writer authority lock finalization",
                )
            except BaseException as close_error:
                raise WindowsWriterLeaseOwnerCrashRequired(
                    "steady writer lease finalization 失败且 lock close 不可闭合"
                ) from close_error
            raise error


class _TestOnlyLockedWriterLease:
    __slots__ = ("_api", "_root", "_handle", "_record_raw", "_state")

    def __init__(self, collected: _CollectedWriterLease, *, token: object):
        if token is not _TEST_ONLY_TOKEN:
            raise TypeError("test-only lease token 无效")
        self._api = collected.api
        self._root = collected.root
        self._handle = collected.handle
        self._record_raw = collected.record_raw
        self._state = "live"

    @property
    def record_document(self) -> dict[str, object]:
        if self._state != "live":
            raise WindowsWriterLeaseHolderError("test-only lease 已关闭")
        value = json.loads(self._record_raw.decode("utf-8"))
        if type(value) is not dict:
            raise WindowsWriterLeaseHolderError("test-only record 类型漂移")
        return value

    def _canary_checkpoint(
        self,
    ) -> tuple[dict[str, object], Path, _ProductionWindowsApi]:
        if self._state != "live":
            raise WindowsWriterLeaseHolderError("test-only lease 已关闭")
        _handle_value(self._handle, label="test-only live writer authority lock")
        lock_identity = _query_file_identity(
            self._api,
            self._handle,
            expected_path=self._root / _LOCK_RELATIVE,
        )
        observed = _read_exact_file(
            self._api,
            self._root / _RECORD_RELATIVE,
            allow_absent=False,
        )
        if observed != self._record_raw:
            raise WindowsWriterLeaseHolderError(
                "test-only writer lease frozen record 已漂移"
            )
        document = self.record_document
        lock = document.get("lock")
        if (
            type(lock) is not dict
            or lock.get("handle_value") != self._handle
            or lock.get("final_path") != lock_identity.final_path
            or lock.get("volume_serial_number")
            != lock_identity.volume_serial_number
            or lock.get("file_id") != lock_identity.file_id
        ):
            raise WindowsWriterLeaseHolderError(
                "test-only writer lease lock identity 已漂移"
            )
        return document, self._root, self._api

    def close(self) -> None:
        if self._state != "live":
            raise WindowsWriterLeaseHolderError("test-only lease 已关闭")
        _close_known_handle(self._api, self._handle, label="test-only writer lock")
        self._handle = 0
        self._state = "closed"


class _TestOnlyWindowsWriterLeaseHolderAdapter:
    """测试专用真实 Win32 adapter；无 production scope/claim/capability。"""

    __slots__ = ("_api",)

    @classmethod
    def load(cls) -> "_TestOnlyWindowsWriterLeaseHolderAdapter":
        instance = object.__new__(cls)
        instance._api = _ProductionWindowsApi.load_exact_d()
        return instance

    def acquire(
        self, root: Path, identity: ExactRuntimeLeaseIdentity
    ) -> _TestOnlyLockedWriterLease:
        collected = _WindowsWriterLeaseHolderRunner(self._api).acquire(
            root, identity, production=False
        )
        return _TestOnlyLockedWriterLease(collected, token=_TEST_ONLY_TOKEN)


__all__ = [
    "ExactRuntimeLeaseIdentity",
    "LIVE_STEADY_WINDOWS_WRITER_LEASE_SCOPE",
    "LIVE_WINDOWS_WRITER_LEASE_SCOPE",
    "LockedSteadyWindowsWriterLease",
    "LockedWindowsWriterLease",
    "ProductionWindowsWriterLeaseHolder",
    "WindowsWriterLeaseBusy",
    "WindowsWriterLeaseHolderError",
    "WindowsWriterLeaseOwnerCrashRequired",
]
