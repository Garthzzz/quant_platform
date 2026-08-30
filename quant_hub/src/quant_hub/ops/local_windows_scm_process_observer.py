"""精确 D 根 Windows SCM／host／child 的现场只读观察器。

产品入口没有路径、service、PID、API 或 hook 参数。所有 handle 在首次 Win32 open
之前已经进入 B2 attempt workspace tracking；返回的 live observation 不可序列化，
且只能生成 observation-only evidence，不能生成 writer lease 或部署资格。
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import json
import os
import subprocess
from typing import Callable, Mapping

from .local_deployment_persistence import (
    CrashReleasedFileLock,
    DeploymentLockBusy,
    LocalDeploymentPersistence,
    LocalDeploymentPersistenceError,
    LockedAttemptWorkspace,
    LockedExactScmProcessObservationInput,
    LockedSteadyBootWorkspace,
    LockedWindowsScmProcessHandleTracking,
    LockedWindowsSteadyScmProcessHandleTracking,
    LockedWindowsSteadyWriterLeaseHandleTracking,
    LockedWindowsWriterLeaseHandleTracking,
    UnsafeLocalPath,
)
from .local_steady_start_authorization import (
    LockedExactSteadyScmProcessObservationInput,
)
from .local_steady_windows_scm_process_evidence import (
    STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
    STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    SteadyWindowsScmProcessObservationEvidence,
)
from .local_release_identity import canonical_bytes, identity_sha256
from .local_windows_scm_process_evidence import (
    WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
    WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    WindowsScmProcessEvidenceError,
    WindowsScmProcessObservationEvidence,
)


LIVE_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE = (
    "live_windows_scm_process_observation_not_qualified"
)
LIVE_STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE = (
    "live_steady_windows_scm_process_observation_not_qualified"
)

_PRODUCTION_ROOT = r"D:\quant\quant_platform"
_SERVICE_NAME = "QuantResearchHub"


def _predefined_hkey_for_pointer_bits(raw_long: int, pointer_bits: int) -> int:
    if type(raw_long) is not int or raw_long < 0 or raw_long > 0xFFFFFFFF:
        raise ValueError("predefined HKEY 必须是 DWORD")
    if pointer_bits not in {32, 64}:
        raise ValueError("Windows pointer width 必须是 32 或 64")
    return ctypes.c_int32(raw_long).value & ((1 << pointer_bits) - 1)


def _predefined_hkey(raw_long: int) -> int:
    """按 WinNT.h 的 ``(LONG) -> (ULONG_PTR)`` 规则构造预定义 HKEY。"""

    pointer_bits = ctypes.sizeof(ctypes.c_void_p) * 8
    expected = _predefined_hkey_for_pointer_bits(raw_long, pointer_bits)
    pointer_value = ctypes.c_void_p(ctypes.c_int32(raw_long).value).value
    if type(pointer_value) is not int:
        raise RuntimeError("无法构造 pointer-width HKEY")
    if pointer_value != expected:
        raise RuntimeError("ctypes predefined HKEY 转换与 pointer-width 规则不一致")
    return pointer_value


_HKEY_LOCAL_MACHINE = _predefined_hkey(0x80000002)
_SC_MANAGER_CONNECT = 0x0001
_SERVICE_QUERY_CONFIG = 0x0001
_SERVICE_QUERY_STATUS = 0x0004
_KEY_QUERY_VALUE = 0x0001
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_PROCESS_DUP_HANDLE = 0x0040
_SYNCHRONIZE = 0x00100000
_TH32CS_SNAPPROCESS = 0x00000002
_FILE_READ_ATTRIBUTES = 0x0080
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_SC_STATUS_PROCESS_INFO = 0
_PROCESS_COMMAND_LINE_INFORMATION = 60
_FILE_ID_INFO_CLASS = 18
_WAIT_TIMEOUT = 258
_STILL_ACTIVE = 259
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_NO_MORE_FILES = 18
_REG_SZ = 1
_STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

_OBSERVATION_TOKEN = object()
_OBSERVER_TOKEN = object()
_PRODUCTION_API_TOKEN = object()
_TEST_ONLY_ADAPTER_TOKEN = object()

_ExactScmObservationInput = (
    LockedExactScmProcessObservationInput
    | LockedExactSteadyScmProcessObservationInput
)
_ExactScmHandleTracking = (
    LockedWindowsScmProcessHandleTracking
    | LockedWindowsSteadyScmProcessHandleTracking
)


class _SteadyObservationPlanView:
    """一次 live checkpoint 派生的 runner-local immutable plan view。"""

    __slots__ = ("_raw",)

    def __init__(self, plan: Mapping[str, object]):
        self._raw = canonical_bytes(plan)

    def _plan(self) -> Mapping[str, object]:
        value = json.loads(self._raw.decode("utf-8"))
        if type(value) is not dict:
            raise WindowsScmProcessObserverError("steady checkpoint plan 类型漂移")
        return value

    @property
    def service_name(self) -> str:
        return str(self._plan()["service"]["service_name"])

    @property
    def service_executable(self) -> str:
        return str(self._plan()["service"]["binary_path"])

    @property
    def python_class(self) -> str:
        return str(self._plan()["service"]["python_class"])

    @property
    def child_executable(self) -> str:
        return str(self._plan()["child"]["executable"])

    @property
    def child_argv(self) -> tuple[str, ...]:
        return tuple(str(value) for value in self._plan()["child"]["argv"])

    def assert_matches(self, plan: Mapping[str, object]) -> None:
        if canonical_bytes(plan) != self._raw:
            raise WindowsScmProcessObserverError(
                "steady SCM plan 在 observation checkpoint 间漂移"
            )


class WindowsScmProcessObserverError(RuntimeError):
    """现场 Windows SCM／process 观察无法机械闭合。"""


class _QUERY_SERVICE_CONFIGW(ctypes.Structure):
    _fields_ = (
        ("dwServiceType", wintypes.DWORD),
        ("dwStartType", wintypes.DWORD),
        ("dwErrorControl", wintypes.DWORD),
        ("lpBinaryPathName", wintypes.LPWSTR),
        ("lpLoadOrderGroup", wintypes.LPWSTR),
        ("dwTagId", wintypes.DWORD),
        ("lpDependencies", wintypes.LPWSTR),
        ("lpServiceStartName", wintypes.LPWSTR),
        ("lpDisplayName", wintypes.LPWSTR),
    )


class _SERVICE_STATUS_PROCESS(ctypes.Structure):
    _fields_ = (
        ("dwServiceType", wintypes.DWORD),
        ("dwCurrentState", wintypes.DWORD),
        ("dwControlsAccepted", wintypes.DWORD),
        ("dwWin32ExitCode", wintypes.DWORD),
        ("dwServiceSpecificExitCode", wintypes.DWORD),
        ("dwCheckPoint", wintypes.DWORD),
        ("dwWaitHint", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwServiceFlags", wintypes.DWORD),
    )


class _FILETIME(ctypes.Structure):
    _fields_ = (("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD))


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


class _UNICODE_STRING(ctypes.Structure):
    _fields_ = (
        ("Length", wintypes.USHORT),
        ("MaximumLength", wintypes.USHORT),
        ("Buffer", ctypes.c_void_p),
    )


@dataclass(frozen=True, slots=True)
class _ServiceConfig:
    service_type: int
    start_type: int
    error_control: int
    binary_path: str
    service_start_name: str


@dataclass(frozen=True, slots=True)
class _ServiceStatus:
    current_state: int
    controls_accepted: int
    win32_exit_code: int
    service_specific_exit_code: int
    checkpoint: int
    wait_hint_ms: int
    process_id: int
    service_flags: int


@dataclass(frozen=True, slots=True)
class _ProcessEntry:
    pid: int
    parent_pid: int


@dataclass(frozen=True, slots=True)
class _ProcessProbe:
    pid: int
    creation_time_100ns: int
    executable_final_path: str
    command_line: str
    live: bool


@dataclass(frozen=True, slots=True)
class _FileProbe:
    executable_final_path: str
    volume_identity_sha256: str
    file_identity_sha256: str


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
        raise WindowsScmProcessObserverError(
            f"Windows API binding 缺失或签名不可固定: {name}"
        ) from error
    return function


def _last_error(label: str) -> WindowsScmProcessObserverError:
    return WindowsScmProcessObserverError(
        f"{label} failed with Windows error {ctypes.get_last_error()}"
    )


def _exact_int(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise WindowsScmProcessObserverError(
            f"{label} 必须是 >= {minimum} 的 exact int"
        )
    return value


def _final_dos_path(value: str, *, label: str) -> str:
    if type(value) is not str or not value:
        raise WindowsScmProcessObserverError(f"{label} final path 为空")
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    if not value.startswith(_PRODUCTION_ROOT + "\\"):
        raise WindowsScmProcessObserverError(
            f"{label} final path 不在 exact D root"
        )
    return value


def _windows_command_line(argv: tuple[str, ...]) -> str:
    if not argv or any(type(item) is not str or not item for item in argv):
        raise WindowsScmProcessObserverError("expected argv 不是闭合非空字符串序列")
    return subprocess.list2cmdline(list(argv))


class _ProductionWindowsApi:
    """固定 ctypes table；不接受调用者提供的 DLL、函数或路径。"""

    __slots__ = (
        "_binding_token",
        "_sealed",
        "open_scm_manager_w",
        "open_service_w",
        "query_service_config_w",
        "query_service_status_ex",
        "reg_open_key_ex_w",
        "reg_query_value_ex_w",
        "open_process",
        "get_process_id",
        "get_process_times",
        "query_full_process_image_name_w",
        "wait_for_single_object",
        "get_exit_code_process",
        "create_toolhelp32_snapshot",
        "process32_first_w",
        "process32_next_w",
        "create_file_w",
        "get_final_path_name_by_handle_w",
        "get_file_information_by_handle_ex",
        "nt_query_information_process",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production Windows API table 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production Windows API table 构造后不可替换")
        object.__setattr__(self, name, value)

    def _assert_exact_binding(self) -> None:
        if (
            type(self) is not _ProductionWindowsApi
            or getattr(self, "_binding_token", None) is not _PRODUCTION_API_TOKEN
            or getattr(self, "_sealed", None) is not True
        ):
            raise WindowsScmProcessObserverError(
                "production Windows API table 来源未闭合"
            )

    @classmethod
    def load_exact_d(cls) -> "_ProductionWindowsApi":
        if os.name != "nt":
            raise WindowsScmProcessObserverError(
                "production Windows observer 只允许 Windows"
            )
        try:
            advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        except OSError as error:
            raise WindowsScmProcessObserverError(
                "无法加载固定 Windows system DLL"
            ) from error
        self = object.__new__(cls)
        object.__setattr__(self, "_sealed", False)
        self.open_scm_manager_w = _bind(
            advapi32,
            "OpenSCManagerW",
            (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD),
            wintypes.HANDLE,
        )
        self.open_service_w = _bind(
            advapi32,
            "OpenServiceW",
            (wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD),
            wintypes.HANDLE,
        )
        self.query_service_config_w = _bind(
            advapi32,
            "QueryServiceConfigW",
            (
                wintypes.HANDLE,
                ctypes.POINTER(_QUERY_SERVICE_CONFIGW),
                wintypes.DWORD,
                wintypes.LPDWORD,
            ),
            wintypes.BOOL,
        )
        self.query_service_status_ex = _bind(
            advapi32,
            "QueryServiceStatusEx",
            (
                wintypes.HANDLE,
                ctypes.c_int,
                ctypes.c_void_p,
                wintypes.DWORD,
                wintypes.LPDWORD,
            ),
            wintypes.BOOL,
        )
        self.reg_open_key_ex_w = _bind(
            advapi32,
            "RegOpenKeyExW",
            (
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.HANDLE),
            ),
            wintypes.LONG,
        )
        self.reg_query_value_ex_w = _bind(
            advapi32,
            "RegQueryValueExW",
            (
                wintypes.HANDLE,
                wintypes.LPCWSTR,
                ctypes.c_void_p,
                wintypes.LPDWORD,
                ctypes.c_void_p,
                wintypes.LPDWORD,
            ),
            wintypes.LONG,
        )
        self.open_process = _bind(
            kernel32,
            "OpenProcess",
            (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD),
            wintypes.HANDLE,
        )
        self.get_process_id = _bind(
            kernel32, "GetProcessId", (wintypes.HANDLE,), wintypes.DWORD
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
        self.query_full_process_image_name_w = _bind(
            kernel32,
            "QueryFullProcessImageNameW",
            (wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, wintypes.LPDWORD),
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
        self.nt_query_information_process = _bind(
            ntdll,
            "NtQueryInformationProcess",
            (
                wintypes.HANDLE,
                wintypes.ULONG,
                ctypes.c_void_p,
                wintypes.ULONG,
                ctypes.POINTER(wintypes.ULONG),
            ),
            wintypes.LONG,
        )
        object.__setattr__(self, "_binding_token", _PRODUCTION_API_TOKEN)
        object.__setattr__(self, "_sealed", True)
        self._assert_exact_binding()
        return self

    def query_service_config(self, handle: int) -> _ServiceConfig:
        needed = wintypes.DWORD()
        ctypes.set_last_error(0)
        first = self.query_service_config_w(handle, None, 0, ctypes.byref(needed))
        if first or ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER:
            raise _last_error("QueryServiceConfigW(size)")
        size = _exact_int(int(needed.value), label="service config size", minimum=1)
        buffer = ctypes.create_string_buffer(size)
        config = ctypes.cast(buffer, ctypes.POINTER(_QUERY_SERVICE_CONFIGW))
        if not self.query_service_config_w(handle, config, size, ctypes.byref(needed)):
            raise _last_error("QueryServiceConfigW")
        value = config.contents
        if value.lpBinaryPathName is None or value.lpServiceStartName is None:
            raise WindowsScmProcessObserverError("SCM config string 缺失")
        return _ServiceConfig(
            int(value.dwServiceType),
            int(value.dwStartType),
            int(value.dwErrorControl),
            str(value.lpBinaryPathName),
            str(value.lpServiceStartName),
        )

    def query_service_status(self, handle: int) -> _ServiceStatus:
        value = _SERVICE_STATUS_PROCESS()
        needed = wintypes.DWORD()
        if not self.query_service_status_ex(
            handle,
            _SC_STATUS_PROCESS_INFO,
            ctypes.byref(value),
            ctypes.sizeof(value),
            ctypes.byref(needed),
        ):
            raise _last_error("QueryServiceStatusEx")
        return _ServiceStatus(
            int(value.dwCurrentState),
            int(value.dwControlsAccepted),
            int(value.dwWin32ExitCode),
            int(value.dwServiceSpecificExitCode),
            int(value.dwCheckPoint),
            int(value.dwWaitHint),
            int(value.dwProcessId),
            int(value.dwServiceFlags),
        )

    def query_python_class(self, handle: int) -> str:
        value_type = wintypes.DWORD()
        size = wintypes.DWORD()
        status = int(
            self.reg_query_value_ex_w(
                handle,
                "PythonClass",
                None,
                ctypes.byref(value_type),
                None,
                ctypes.byref(size),
            )
        )
        if status != 0 or int(value_type.value) != _REG_SZ or int(size.value) < 2:
            raise WindowsScmProcessObserverError(
                f"RegQueryValueExW(size/type) failed with status {status}"
            )
        if int(size.value) % ctypes.sizeof(ctypes.c_wchar) != 0:
            raise WindowsScmProcessObserverError("PythonClass registry bytes 非 UTF-16 对齐")
        buffer = ctypes.create_unicode_buffer(
            int(size.value) // ctypes.sizeof(ctypes.c_wchar)
        )
        status = int(
            self.reg_query_value_ex_w(
                handle,
                "PythonClass",
                None,
                ctypes.byref(value_type),
                ctypes.cast(buffer, ctypes.c_void_p),
                ctypes.byref(size),
            )
        )
        if status != 0 or int(value_type.value) != _REG_SZ:
            raise WindowsScmProcessObserverError(
                f"RegQueryValueExW(value) failed with status {status}"
            )
        return buffer.value

    def _query_process_command_line(self, handle: int) -> str:
        needed = wintypes.ULONG()
        status = int(
            self.nt_query_information_process(
                handle,
                _PROCESS_COMMAND_LINE_INFORMATION,
                None,
                0,
                ctypes.byref(needed),
            )
        )
        if status & 0xFFFFFFFF != _STATUS_INFO_LENGTH_MISMATCH:
            raise WindowsScmProcessObserverError(
                f"NtQueryInformationProcess(size) status {status & 0xFFFFFFFF:#x}"
            )
        size = _exact_int(int(needed.value), label="process command line size", minimum=1)
        buffer = ctypes.create_string_buffer(size)
        status = int(
            self.nt_query_information_process(
                handle,
                _PROCESS_COMMAND_LINE_INFORMATION,
                buffer,
                size,
                ctypes.byref(needed),
            )
        )
        if status != 0:
            raise WindowsScmProcessObserverError(
                f"NtQueryInformationProcess(command line) status {status & 0xFFFFFFFF:#x}"
            )
        value = ctypes.cast(buffer, ctypes.POINTER(_UNICODE_STRING)).contents
        length = int(value.Length)
        address = int(value.Buffer or 0)
        start = ctypes.addressof(buffer)
        end = start + size
        if (
            length < 2
            or length % 2 != 0
            or address < start
            or address + length > end
        ):
            raise WindowsScmProcessObserverError("process command line buffer 越界")
        return ctypes.string_at(address, length).decode("utf-16-le")

    def query_process(self, handle: int, expected_pid: int) -> _ProcessProbe:
        actual_pid = int(self.get_process_id(handle))
        if actual_pid != expected_pid:
            raise WindowsScmProcessObserverError("process handle PID 漂移")
        creation = _FILETIME()
        exit_time = _FILETIME()
        kernel = _FILETIME()
        user = _FILETIME()
        if not self.get_process_times(
            handle,
            ctypes.byref(creation),
            ctypes.byref(exit_time),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise _last_error("GetProcessTimes")
        creation_time = (int(creation.dwHighDateTime) << 32) | int(
            creation.dwLowDateTime
        )
        capacity = 32768
        image = ctypes.create_unicode_buffer(capacity)
        length = wintypes.DWORD(capacity)
        if not self.query_full_process_image_name_w(
            handle, 0, image, ctypes.byref(length)
        ):
            raise _last_error("QueryFullProcessImageNameW")
        wait = int(self.wait_for_single_object(handle, 0))
        exit_code = wintypes.DWORD()
        if not self.get_exit_code_process(handle, ctypes.byref(exit_code)):
            raise _last_error("GetExitCodeProcess")
        live = wait == _WAIT_TIMEOUT and int(exit_code.value) == _STILL_ACTIVE
        return _ProcessProbe(
            expected_pid,
            creation_time,
            _final_dos_path(image.value[: int(length.value)], label="process image"),
            self._query_process_command_line(handle),
            live,
        )

    def enumerate_processes(self, snapshot_handle: int) -> tuple[_ProcessEntry, ...]:
        entry = _PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ctypes.set_last_error(0)
        if not self.process32_first_w(snapshot_handle, ctypes.byref(entry)):
            raise _last_error("Process32FirstW")
        result: list[_ProcessEntry] = []
        while True:
            result.append(
                _ProcessEntry(int(entry.th32ProcessID), int(entry.th32ParentProcessID))
            )
            entry.dwSize = ctypes.sizeof(entry)
            ctypes.set_last_error(0)
            if self.process32_next_w(snapshot_handle, ctypes.byref(entry)):
                continue
            if ctypes.get_last_error() != _ERROR_NO_MORE_FILES:
                raise _last_error("Process32NextW")
            return tuple(result)

    def query_file(self, handle: int) -> _FileProbe:
        capacity = 32768
        path = ctypes.create_unicode_buffer(capacity)
        length = int(
            self.get_final_path_name_by_handle_w(handle, path, capacity, 0)
        )
        if length < 1 or length >= capacity:
            raise _last_error("GetFinalPathNameByHandleW")
        info = _FILE_ID_INFO()
        if not self.get_file_information_by_handle_ex(
            handle,
            _FILE_ID_INFO_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            raise _last_error("GetFileInformationByHandleEx(FileIdInfo)")
        volume = int(info.VolumeSerialNumber)
        file_id = bytes(info.FileId.Identifier).hex()
        return _FileProbe(
            _final_dos_path(path.value[:length], label="executable"),
            identity_sha256(
                {
                    "schema_version": "qrh-windows-volume-identity/v1",
                    "volume_serial_number": str(volume),
                }
            ),
            identity_sha256(
                {
                    "schema_version": "qrh-windows-file-identity/v1",
                    "volume_serial_number": str(volume),
                    "file_id_128_hex": file_id,
                }
            ),
        )


def _service_document(
    inputs: object,
    config: _ServiceConfig,
    status: _ServiceStatus,
    python_class: str,
) -> dict[str, object]:
    if (
        config.service_type != 16
        or config.start_type != 2
        or config.error_control != 1
        or config.binary_path != _windows_command_line((inputs.service_executable,))
        or config.service_start_name != "LocalSystem"
        or python_class != inputs.python_class
        or status.current_state != 4
        or status.win32_exit_code != 0
        or status.service_specific_exit_code != 0
        or status.checkpoint != 0
        or status.wait_hint_ms != 0
        or status.service_flags != 0
        or status.process_id < 1
    ):
        raise WindowsScmProcessObserverError("SCM config/status/registry 与 exact plan 不一致")
    value: dict[str, object] = {
        "service_name": inputs.service_name,
        "service_type": config.service_type,
        "start_type": config.start_type,
        "error_control": config.error_control,
        "binary_path_argv": [inputs.service_executable],
        "service_start_name": config.service_start_name,
        "python_class": python_class,
        "status": {
            "current_state": status.current_state,
            "controls_accepted": status.controls_accepted,
            "win32_exit_code": status.win32_exit_code,
            "service_specific_exit_code": status.service_specific_exit_code,
            "checkpoint": status.checkpoint,
            "wait_hint_ms": status.wait_hint_ms,
            "process_id": status.process_id,
            "service_flags": status.service_flags,
        },
    }
    value["service_identity_sha256"] = identity_sha256(value)
    return value


def _process_document(
    probe: _ProcessProbe,
    file_probe: _FileProbe,
    *,
    parent_pid: int,
    expected_executable: str,
    expected_argv: tuple[str, ...],
) -> dict[str, object]:
    if (
        not probe.live
        or probe.pid < 1
        or parent_pid < 1
        or probe.creation_time_100ns < 1
        or probe.executable_final_path != expected_executable
        or file_probe.executable_final_path != expected_executable
        or probe.command_line != _windows_command_line(expected_argv)
    ):
        raise WindowsScmProcessObserverError(
            "process image/argv/start/live 与 exact plan 不一致"
        )
    value: dict[str, object] = {
        "pid": probe.pid,
        "parent_pid": parent_pid,
        "creation_time_100ns": probe.creation_time_100ns,
        "executable_final_path": file_probe.executable_final_path,
        "volume_identity_sha256": file_probe.volume_identity_sha256,
        "file_identity_sha256": file_probe.file_identity_sha256,
        "argv": list(expected_argv),
    }
    value["process_identity_sha256"] = identity_sha256(value)
    return value


def _unique_child(
    entries: tuple[_ProcessEntry, ...], host_pid: int
) -> tuple[int, int]:
    host_entries = [entry for entry in entries if entry.pid == host_pid]
    children = [entry.pid for entry in entries if entry.parent_pid == host_pid]
    if len(host_entries) != 1 or len(children) != 1 or children[0] == host_pid:
        raise WindowsScmProcessObserverError(
            "host 必须存在且恰有一个 direct child"
        )
    if host_entries[0].parent_pid < 1 or host_entries[0].parent_pid == host_pid:
        raise WindowsScmProcessObserverError("host parent PID 无效")
    return host_entries[0].parent_pid, children[0]


def _observe_current_topology(
    api: object,
    tracking: _ExactScmHandleTracking,
    *,
    slot_label: str,
    host_pid: int,
) -> tuple[int, int]:
    """用 B2 可轮换 slot 取得并机械关闭一次新的 Toolhelp snapshot。"""

    create_snapshot = getattr(api, "create_toolhelp32_snapshot", None)
    enumerate_processes = getattr(api, "enumerate_processes", None)
    if not callable(create_snapshot) or not callable(enumerate_processes):
        raise WindowsScmProcessObserverError("process topology API table 不闭合")
    tracking._capture_reusable_snapshot_handle(
        slot_label,
        create_snapshot,
        _TH32CS_SNAPPROCESS,
        0,
    )
    try:
        snapshot = tracking._borrow_handle(slot_label, "kernel")
        entries = enumerate_processes(snapshot)
        if type(entries) is not tuple or any(
            type(entry) is not _ProcessEntry for entry in entries
        ):
            raise WindowsScmProcessObserverError(
                "process topology 必须是 closed _ProcessEntry tuple"
            )
        return _unique_child(entries, host_pid)
    finally:
        tracking._release_reusable_snapshot_handle(slot_label)


@dataclass(frozen=True, slots=True)
class _CollectedWindowsScmProcessObservation:
    tracking: _ExactScmHandleTracking
    service_config: _ServiceConfig
    service_status: _ServiceStatus
    python_class: str
    host_parent_pid: int
    host_probe: _ProcessProbe
    child_probe: _ProcessProbe
    host_file: _FileProbe
    child_file: _FileProbe


def _assert_observation_components_live(
    *,
    inputs: _ExactScmObservationInput,
    tracking: _ExactScmHandleTracking,
    api: object,
    service_config: _ServiceConfig,
    service_status: _ServiceStatus,
    python_class: str,
    host_parent_pid: int,
    host_probe: _ProcessProbe,
    child_probe: _ProcessProbe,
    host_file_probe: _FileProbe,
    child_file_probe: _FileProbe,
) -> None:
    tracking._assert_context(states={"live"})
    inputs._assert_live()
    service = tracking._borrow_handle("scm_service", "scm")
    registry = tracking._borrow_handle("python_class_registry", "registry")
    host = tracking._borrow_handle("host_process", "kernel")
    child = tracking._borrow_handle("child_process", "kernel")
    host_file = tracking._borrow_handle("host_executable", "kernel")
    child_file = tracking._borrow_handle("child_executable", "kernel")
    query_service_config = getattr(api, "query_service_config", None)
    query_service_status = getattr(api, "query_service_status", None)
    query_python_class = getattr(api, "query_python_class", None)
    query_process = getattr(api, "query_process", None)
    query_file = getattr(api, "query_file", None)
    if not all(
        callable(function)
        for function in (
            query_service_config,
            query_service_status,
            query_python_class,
            query_process,
            query_file,
        )
    ):
        raise WindowsScmProcessObserverError("live observation API table 不闭合")
    if (
        query_service_config(service) != service_config
        or query_service_status(service) != service_status
        or query_python_class(registry) != python_class
        or query_process(host, host_probe.pid) != host_probe
        or query_process(child, child_probe.pid) != child_probe
        or query_file(host_file) != host_file_probe
        or query_file(child_file) != child_file_probe
    ):
        raise WindowsScmProcessObserverError(
            "live Windows observation 在 evidence build 前漂移"
        )
    current_parent, current_child = _observe_current_topology(
        api,
        tracking,
        slot_label="snapshot_after",
        host_pid=host_probe.pid,
    )
    if current_parent != host_parent_pid or current_child != child_probe.pid:
        raise WindowsScmProcessObserverError(
            "live Windows direct-child topology 在 evidence build 前漂移"
        )
    if (
        query_service_config(service) != service_config
        or query_service_status(service) != service_status
        or query_python_class(registry) != python_class
        or query_process(host, host_probe.pid) != host_probe
        or query_process(child, child_probe.pid) != child_probe
        or query_file(host_file) != host_file_probe
        or query_file(child_file) != child_file_probe
    ):
        raise WindowsScmProcessObserverError(
            "live Windows observation 在新鲜 topology 后漂移"
        )
    inputs._assert_live()


def _build_production_evidence_document(
    inputs: LockedExactScmProcessObservationInput,
    collected: _CollectedWindowsScmProcessObservation,
    *,
    _authority_token: object,
) -> dict[str, object]:
    """只允许 production façade 调用的正式 document finalizer。"""

    if _authority_token is not _PRODUCTION_API_TOKEN:
        raise WindowsScmProcessObserverError(
            "production evidence document authority 不匹配"
        )

    service_document = _service_document(
        inputs,
        collected.service_config,
        collected.service_status,
        collected.python_class,
    )
    host_document = _process_document(
        collected.host_probe,
        collected.host_file,
        parent_pid=collected.host_parent_pid,
        expected_executable=inputs.service_executable,
        expected_argv=(inputs.service_executable,),
    )
    child_document = _process_document(
        collected.child_probe,
        collected.child_file,
        parent_pid=collected.host_probe.pid,
        expected_executable=inputs.child_executable,
        expected_argv=inputs.child_argv,
    )
    topology: dict[str, object] = {
        "host_pid": collected.host_probe.pid,
        "direct_child_pids": [collected.child_probe.pid],
    }
    topology["topology_identity_sha256"] = identity_sha256(topology)
    document: dict[str, object] = {
        "schema_version": WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
        "evidence_scope": WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
        "attempt_id": inputs.attempt_id,
        "nonce": inputs.nonce,
        "operation": inputs.operation,
        "authorization_phase": (
            "prior_start_authorized"
            if inputs.role == "prior"
            else "candidate_start_authorized"
        ),
        "role": inputs.role,
        "start_nonce": inputs.start_nonce,
        "authorization_sha256": inputs.authorization_sha256,
        "scm_identity_sha256": inputs.scm_identity_sha256,
        "state_identity_sha256": inputs.state_identity_sha256,
        "release": dict(inputs.release_ref),
        "service": service_document,
        "host": host_document,
        "child": child_document,
        "direct_child_topology": topology,
        "observation_aggregate_sha256": identity_sha256(
            [
                {
                    "name": "service",
                    "sha256": service_document["service_identity_sha256"],
                },
                {
                    "name": "host",
                    "sha256": host_document["process_identity_sha256"],
                },
                {
                    "name": "child",
                    "sha256": child_document["process_identity_sha256"],
                },
                {
                    "name": "direct_child_topology",
                    "sha256": topology["topology_identity_sha256"],
                },
            ]
        ),
        "result": "identity_observed_not_writer_qualified",
    }
    document["evidence_sha256"] = identity_sha256(document)
    return document


def _build_steady_production_evidence_document(
    inputs: LockedExactSteadyScmProcessObservationInput,
    collected: _CollectedWindowsScmProcessObservation,
    *,
    _authority_token: object,
) -> dict[str, object]:
    """只允许 production steady façade 调用的 v2 document finalizer。"""

    if (
        _authority_token is not _PRODUCTION_API_TOKEN
        or type(collected.tracking)
        is not LockedWindowsSteadyScmProcessHandleTracking
    ):
        raise WindowsScmProcessObserverError(
            "production steady evidence authority 不匹配"
        )
    material = inputs._observation_checkpoint_material()
    plan_view = _SteadyObservationPlanView(material)
    service_document = _service_document(
        plan_view,
        collected.service_config,
        collected.service_status,
        collected.python_class,
    )
    host_document = _process_document(
        collected.host_probe,
        collected.host_file,
        parent_pid=collected.host_parent_pid,
        expected_executable=plan_view.service_executable,
        expected_argv=(plan_view.service_executable,),
    )
    child_document = _process_document(
        collected.child_probe,
        collected.child_file,
        parent_pid=collected.host_probe.pid,
        expected_executable=plan_view.child_executable,
        expected_argv=plan_view.child_argv,
    )
    topology: dict[str, object] = {
        "host_pid": collected.host_probe.pid,
        "direct_child_pids": [collected.child_probe.pid],
    }
    topology["topology_identity_sha256"] = identity_sha256(topology)
    document: dict[str, object] = {
        "schema_version": STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
        "evidence_scope": STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
        "authority_kind": material["authority_kind"],
        "runtime_state_kind": material["runtime_state_kind"],
        "boot_nonce": material["boot_nonce"],
        "active_release_sha256": material["active_release_sha256"],
        "binding_sha256": material["binding_sha256"],
        "retention_aggregate_sha256": material[
            "retention_aggregate_sha256"
        ],
        "state_identity_sha256": material["state_identity_sha256"],
        "tooling_sha256": material["tooling_sha256"],
        "receipt_lineage_aggregate_sha256": (
            material["receipt_lineage_aggregate_sha256"]
        ),
        "legacy_c_live_fence_aggregate_sha256": (
            material["legacy_c_live_fence_aggregate_sha256"]
        ),
        "authorization_sha256": material["authorization_sha256"],
        "scm_identity_sha256": material["scm_identity_sha256"],
        "release": dict(material["release"]),
        "service": service_document,
        "host": host_document,
        "child": child_document,
        "direct_child_topology": topology,
        "observation_aggregate_sha256": identity_sha256(
            [
                {
                    "name": "service",
                    "sha256": service_document["service_identity_sha256"],
                },
                {
                    "name": "host",
                    "sha256": host_document["process_identity_sha256"],
                },
                {
                    "name": "child",
                    "sha256": child_document["process_identity_sha256"],
                },
                {
                    "name": "direct_child_topology",
                    "sha256": topology["topology_identity_sha256"],
                },
            ]
        ),
        "result": "steady_identity_observed_not_writer_qualified",
    }
    document["evidence_sha256"] = identity_sha256(document)
    return document


class LockedWindowsScmProcessObservation:
    """由真实 tracked handles 支撑的 process-local observation capability。"""

    __slots__ = (
        "_sealed",
        "_inputs",
        "_tracking",
        "_api",
        "_document_raw",
        "_service_config",
        "_service_status",
        "_python_class",
        "_host_parent_pid",
        "_host_probe",
        "_child_probe",
        "_host_file",
        "_child_file",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("live Windows SCM/process observation 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("live Windows observation 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        inputs: LockedExactScmProcessObservationInput,
        tracking: LockedWindowsScmProcessHandleTracking,
        api: object,
        document: Mapping[str, object],
        service_config: _ServiceConfig,
        service_status: _ServiceStatus,
        python_class: str,
        host_parent_pid: int,
        host_probe: _ProcessProbe,
        child_probe: _ProcessProbe,
        host_file: _FileProbe,
        child_file: _FileProbe,
        _construction_token: object,
    ):
        if _construction_token is not _OBSERVATION_TOKEN:
            raise DeploymentLockBusy(
                "live Windows observation 必须由 production observer 构造"
            )
        if type(api) is not _ProductionWindowsApi:
            raise DeploymentLockBusy(
                "production live observation 拒绝非产品 API table"
            )
        api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._inputs = inputs
        self._tracking = tracking
        self._api = api
        self._document_raw = canonical_bytes(document)
        self._service_config = service_config
        self._service_status = service_status
        self._python_class = python_class
        self._host_parent_pid = host_parent_pid
        self._host_probe = host_probe
        self._child_probe = child_probe
        self._host_file = host_file
        self._child_file = child_file
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("live Windows observation is process-local and non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(self) -> None:
        if type(self._api) is not _ProductionWindowsApi:
            raise WindowsScmProcessObserverError(
                "production live observation API table 类型漂移"
            )
        self._api._assert_exact_binding()
        _assert_observation_components_live(
            inputs=self._inputs,
            tracking=self._tracking,
            api=self._api,
            service_config=self._service_config,
            service_status=self._service_status,
            python_class=self._python_class,
            host_parent_pid=self._host_parent_pid,
            host_probe=self._host_probe,
            child_probe=self._child_probe,
            host_file_probe=self._host_file,
            child_file_probe=self._child_file,
        )

    @property
    def scope(self) -> str:
        self._assert_live()
        return LIVE_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE

    def build_evidence(self) -> WindowsScmProcessObservationEvidence:
        self._assert_live()
        try:
            document = json.loads(self._document_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise WindowsScmProcessObserverError(
                "live observation frozen document 损坏"
            ) from error
        return WindowsScmProcessObservationEvidence.from_document(
            document, self._inputs
        )

    def _prepare_writer_lease_handle_tracking(
        self,
    ) -> LockedWindowsWriterLeaseHandleTracking:
        self._assert_live()
        return self._tracking._persistence.prepare_windows_writer_lease_handle_tracking(
            self._tracking._lock,
            self._tracking._workspace,
            self._tracking,
        )

    def _duplicate_child_handle_for_writer_lease(
        self,
        tracking: LockedWindowsWriterLeaseHandleTracking,
        duplicate_handle: Callable[..., object],
        source_handle_value: int,
        target_process: int,
        desired_access: int,
        inherit_handle: bool,
        options: int,
    ) -> None:
        self._assert_live()
        if (
            type(tracking) is not LockedWindowsWriterLeaseHandleTracking
            or tracking._scm_tracking is not self._tracking
        ):
            raise WindowsScmProcessObserverError(
                "writer lease tracking 未绑定当前 live SCM child"
            )
        child_process = self._tracking._borrow_handle(
            "child_process", "kernel"
        )
        tracking._capture_reusable_duplicate_handle(
            duplicate_handle,
            child_process,
            source_handle_value,
            target_process,
            desired_access,
            inherit_handle,
            options,
        )

    def close(self) -> None:
        self._tracking.close()

    def __enter__(self) -> "LockedWindowsScmProcessObservation":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedSteadyWindowsScmProcessObservation:
    """由 steady 专属 tracked handles 支撑的 process-local observation。"""

    __slots__ = (
        "_sealed",
        "_inputs",
        "_tracking",
        "_api",
        "_document_raw",
        "_service_config",
        "_service_status",
        "_python_class",
        "_host_parent_pid",
        "_host_probe",
        "_child_probe",
        "_host_file",
        "_child_file",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady live Windows SCM/process observation 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady live Windows observation 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        inputs: LockedExactSteadyScmProcessObservationInput,
        tracking: LockedWindowsSteadyScmProcessHandleTracking,
        api: object,
        document: Mapping[str, object],
        service_config: _ServiceConfig,
        service_status: _ServiceStatus,
        python_class: str,
        host_parent_pid: int,
        host_probe: _ProcessProbe,
        child_probe: _ProcessProbe,
        host_file: _FileProbe,
        child_file: _FileProbe,
        _construction_token: object,
    ):
        if (
            _construction_token is not _OBSERVATION_TOKEN
            or type(inputs)
            is not LockedExactSteadyScmProcessObservationInput
            or type(tracking)
            is not LockedWindowsSteadyScmProcessHandleTracking
            or tracking._inputs is not inputs
        ):
            raise DeploymentLockBusy(
                "steady live Windows observation 必须由 exact production observer 构造"
            )
        if type(api) is not _ProductionWindowsApi:
            raise DeploymentLockBusy(
                "production steady live observation 拒绝非产品 API table"
            )
        api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._inputs = inputs
        self._tracking = tracking
        self._api = api
        self._document_raw = canonical_bytes(document)
        self._service_config = service_config
        self._service_status = service_status
        self._python_class = python_class
        self._host_parent_pid = host_parent_pid
        self._host_probe = host_probe
        self._child_probe = child_probe
        self._host_file = host_file
        self._child_file = child_file
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError(
            "steady live Windows observation is process-local and non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(self) -> None:
        if type(self._api) is not _ProductionWindowsApi:
            raise WindowsScmProcessObserverError(
                "production steady observation API table 类型漂移"
            )
        self._api._assert_exact_binding()
        _assert_observation_components_live(
            inputs=self._inputs,
            tracking=self._tracking,
            api=self._api,
            service_config=self._service_config,
            service_status=self._service_status,
            python_class=self._python_class,
            host_parent_pid=self._host_parent_pid,
            host_probe=self._host_probe,
            child_probe=self._child_probe,
            host_file_probe=self._host_file,
            child_file_probe=self._child_file,
        )

    @property
    def scope(self) -> str:
        self._assert_live()
        return LIVE_STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE

    def build_evidence(self) -> SteadyWindowsScmProcessObservationEvidence:
        self._assert_live()
        try:
            document = json.loads(self._document_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise WindowsScmProcessObserverError(
                "steady live observation frozen document 损坏"
            ) from error
        return SteadyWindowsScmProcessObservationEvidence.from_document(
            document, self._inputs
        )

    def _prepare_writer_lease_handle_tracking(
        self,
    ) -> LockedWindowsSteadyWriterLeaseHandleTracking:
        self._assert_live()
        return (
            self._tracking._persistence.prepare_windows_steady_writer_lease_handle_tracking(
                self._tracking._lock,
                self._tracking._workspace,
                self._tracking,
            )
        )

    def _duplicate_child_handle_for_writer_lease(
        self,
        tracking: LockedWindowsSteadyWriterLeaseHandleTracking,
        duplicate_handle: Callable[..., object],
        source_handle_value: int,
        target_process: int,
        desired_access: int,
        inherit_handle: bool,
        options: int,
    ) -> None:
        self._assert_live()
        if (
            type(tracking)
            is not LockedWindowsSteadyWriterLeaseHandleTracking
            or tracking._scm_tracking is not self._tracking
        ):
            raise WindowsScmProcessObserverError(
                "steady writer tracking 未绑定当前 live SCM child"
            )
        child_process = self._tracking._borrow_handle(
            "child_process", "kernel"
        )
        tracking._capture_reusable_duplicate_handle(
            duplicate_handle,
            child_process,
            source_handle_value,
            target_process,
            desired_access,
            inherit_handle,
            options,
        )

    def close(self) -> None:
        self._tracking.close()

    def __enter__(self) -> "LockedSteadyWindowsScmProcessObservation":
        self._assert_live()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class _WindowsScmProcessObservationRunner:
    """production/test-only 共用的 closed 算法 runner；自身不授予证据权威。"""

    __slots__ = ("_api",)

    def __init__(self, *, api: object):
        self._api = api

    def _close_after_error(
        self,
        tracking: _ExactScmHandleTracking,
        error: BaseException,
    ) -> None:
        try:
            tracking.close()
        except BaseException as close_error:
            raise WindowsScmProcessObserverError(
                "Windows observation 失败且 handle cleanup 不可闭合"
            ) from close_error
        if isinstance(error, WindowsScmProcessObserverError):
            raise error
        if isinstance(
            error,
            (
                DeploymentLockBusy,
                LocalDeploymentPersistenceError,
                UnsafeLocalPath,
                WindowsScmProcessEvidenceError,
            ),
        ):
            raise WindowsScmProcessObserverError(
                "Windows observation capability／evidence 未闭合"
            ) from error
        raise WindowsScmProcessObserverError(
            "Windows observation syscall/query 失败"
        ) from error

    def observe(
        self,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace | LockedSteadyBootWorkspace,
        inputs: _ExactScmObservationInput,
    ) -> _CollectedWindowsScmProcessObservation:
        transient = (
            type(persistence) is not LocalDeploymentPersistence
            or type(lock) is not CrashReleasedFileLock
        )
        if transient:
            raise DeploymentLockBusy(
                "production observer 只接受 exact B2 persistence capabilities"
            )
        is_transient = (
            type(workspace) is LockedAttemptWorkspace
            and type(inputs) is LockedExactScmProcessObservationInput
        )
        is_steady = (
            type(workspace) is LockedSteadyBootWorkspace
            and type(inputs) is LockedExactSteadyScmProcessObservationInput
        )
        if not (is_transient or is_steady):
            raise DeploymentLockBusy(
                "SCM/process observer workspace 与 exact input authority 不匹配"
            )
        if is_steady:
            expected_inputs: object = _SteadyObservationPlanView(
                inputs._observation_checkpoint_plan()
            )
        else:
            inputs._assert_live()
            expected_inputs = inputs
        if expected_inputs.service_name != _SERVICE_NAME:
            raise WindowsScmProcessObserverError("production service identity 漂移")
        if is_transient:
            tracking = persistence.prepare_windows_scm_process_handle_tracking(
                lock, workspace, inputs
            )
        else:
            tracking = (
                persistence.prepare_windows_steady_scm_process_handle_tracking(
                    lock, workspace, inputs
                )
            )
        try:
            tracking._capture_returned_handle(
                "scm_manager",
                "scm",
                self._api.open_scm_manager_w,
                None,
                None,
                _SC_MANAGER_CONNECT,
            )
            manager = tracking._borrow_handle("scm_manager", "scm")
            tracking._capture_returned_handle(
                "scm_service",
                "scm",
                self._api.open_service_w,
                manager,
                expected_inputs.service_name,
                _SERVICE_QUERY_CONFIG | _SERVICE_QUERY_STATUS,
            )
            service = tracking._borrow_handle("scm_service", "scm")
            config_a = self._api.query_service_config(service)
            registry_key = (
                "SYSTEM\\CurrentControlSet\\Services\\"
                + expected_inputs.service_name
            )
            tracking._capture_registry_output_handle(
                "python_class_registry",
                self._api.reg_open_key_ex_w,
                _HKEY_LOCAL_MACHINE,
                registry_key,
                0,
                _KEY_QUERY_VALUE,
            )
            registry = tracking._borrow_handle(
                "python_class_registry", "registry"
            )
            python_class_a = self._api.query_python_class(registry)
            status_a = self._api.query_service_status(service)
            _service_document(
                expected_inputs, config_a, status_a, python_class_a
            )

            host_pid = _exact_int(
                status_a.process_id, label="SCM host PID", minimum=1
            )
            tracking._capture_returned_handle(
                "host_process",
                "kernel",
                self._api.open_process,
                _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE,
                False,
                host_pid,
            )
            host_handle = tracking._borrow_handle("host_process", "kernel")
            host_probe_a = self._api.query_process(host_handle, host_pid)
            tracking._capture_returned_handle(
                "host_executable",
                "kernel",
                self._api.create_file_w,
                expected_inputs.service_executable,
                _FILE_READ_ATTRIBUTES,
                _FILE_SHARE_READ,
                None,
                _OPEN_EXISTING,
                _FILE_ATTRIBUTE_NORMAL,
                None,
            )
            host_file_handle = tracking._borrow_handle(
                "host_executable", "kernel"
            )
            host_file_a = self._api.query_file(host_file_handle)

            host_parent_pid, child_pid = _observe_current_topology(
                self._api,
                tracking,
                slot_label="snapshot_before",
                host_pid=host_pid,
            )
            tracking._capture_returned_handle(
                "child_process",
                "kernel",
                self._api.open_process,
                _PROCESS_QUERY_LIMITED_INFORMATION
                | _PROCESS_DUP_HANDLE
                | _SYNCHRONIZE,
                False,
                child_pid,
            )
            child_handle = tracking._borrow_handle("child_process", "kernel")
            child_probe_a = self._api.query_process(child_handle, child_pid)
            tracking._capture_returned_handle(
                "child_executable",
                "kernel",
                self._api.create_file_w,
                expected_inputs.child_executable,
                _FILE_READ_ATTRIBUTES,
                _FILE_SHARE_READ,
                None,
                _OPEN_EXISTING,
                _FILE_ATTRIBUTE_NORMAL,
                None,
            )
            child_file_handle = tracking._borrow_handle(
                "child_executable", "kernel"
            )
            child_file_a = self._api.query_file(child_file_handle)

            host_parent_b, child_pid_b = _observe_current_topology(
                self._api,
                tracking,
                slot_label="snapshot_after",
                host_pid=host_pid,
            )
            config_b = self._api.query_service_config(service)
            status_b = self._api.query_service_status(service)
            python_class_b = self._api.query_python_class(registry)
            host_probe_b = self._api.query_process(host_handle, host_pid)
            child_probe_b = self._api.query_process(child_handle, child_pid)
            host_file_b = self._api.query_file(host_file_handle)
            child_file_b = self._api.query_file(child_file_handle)
            if is_steady:
                expected_inputs.assert_matches(
                    inputs._observation_checkpoint_plan()
                )
            else:
                inputs._assert_live()

            if (
                config_b != config_a
                or status_b != status_a
                or python_class_b != python_class_a
                or host_parent_b != host_parent_pid
                or child_pid_b != child_pid
                or host_probe_b != host_probe_a
                or child_probe_b != child_probe_a
                or host_file_b != host_file_a
                or child_file_b != child_file_a
            ):
                raise WindowsScmProcessObserverError(
                    "SCM/process/executable 在双重观察期间漂移"
                )
            _service_document(
                expected_inputs, config_a, status_a, python_class_a
            )
            _process_document(
                host_probe_a,
                host_file_a,
                parent_pid=host_parent_pid,
                expected_executable=expected_inputs.service_executable,
                expected_argv=(expected_inputs.service_executable,),
            )
            _process_document(
                child_probe_a,
                child_file_a,
                parent_pid=host_pid,
                expected_executable=expected_inputs.child_executable,
                expected_argv=expected_inputs.child_argv,
            )
            if (
                child_probe_a.creation_time_100ns
                < host_probe_a.creation_time_100ns
                or host_file_a.volume_identity_sha256
                != child_file_a.volume_identity_sha256
                or host_file_a.file_identity_sha256
                == child_file_a.file_identity_sha256
            ):
                raise WindowsScmProcessObserverError(
                    "host/child time 或 executable identity 不闭合"
                )
            tracking._seal_acquisition()
            return _CollectedWindowsScmProcessObservation(
                tracking=tracking,
                service_config=config_a,
                service_status=status_a,
                python_class=python_class_a,
                host_parent_pid=host_parent_pid,
                host_probe=host_probe_a,
                child_probe=child_probe_a,
                host_file=host_file_a,
                child_file=child_file_a,
            )
        except BaseException as error:
            self._close_after_error(tracking, error)
            raise AssertionError("unreachable")


class ProductionWindowsScmProcessObserver:
    """无参数加载、不可注入且不可替换 API table 的 exact-D observer。"""

    __slots__ = ("_api", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production Windows SCM/process observer 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production Windows observer 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, api: object, _construction_token: object):
        if _construction_token is not _OBSERVER_TOKEN:
            raise TypeError("production observer 必须由 load_exact_d() 构造")
        if type(api) is not _ProductionWindowsApi:
            raise TypeError("production observer 拒绝非产品 API table")
        api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._api = api
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production Windows observer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionWindowsScmProcessObserver":
        api = _ProductionWindowsApi.load_exact_d()
        if type(api) is not _ProductionWindowsApi:
            raise TypeError("production loader 拒绝 fake API table")
        api._assert_exact_binding()
        return cls(api=api, _construction_token=_OBSERVER_TOKEN)

    def observe(
        self,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        inputs: LockedExactScmProcessObservationInput,
    ) -> LockedWindowsScmProcessObservation:
        if type(self._api) is not _ProductionWindowsApi:
            raise WindowsScmProcessObserverError(
                "production observer API table 类型漂移"
            )
        self._api._assert_exact_binding()
        collected = _WindowsScmProcessObservationRunner(api=self._api).observe(
            persistence,
            lock,
            workspace,
            inputs,
        )
        try:
            document = _build_production_evidence_document(
                inputs,
                collected,
                _authority_token=_PRODUCTION_API_TOKEN,
            )
            WindowsScmProcessObservationEvidence.from_document(
                document,
                inputs,
            )
            return LockedWindowsScmProcessObservation(
                inputs=inputs,
                tracking=collected.tracking,
                api=self._api,
                document=document,
                service_config=collected.service_config,
                service_status=collected.service_status,
                python_class=collected.python_class,
                host_parent_pid=collected.host_parent_pid,
                host_probe=collected.host_probe,
                child_probe=collected.child_probe,
                host_file=collected.host_file,
                child_file=collected.child_file,
                _construction_token=_OBSERVATION_TOKEN,
            )
        except BaseException as error:
            try:
                collected.tracking.close()
            except BaseException as close_error:
                raise WindowsScmProcessObserverError(
                    "production observation finalization cleanup 不可闭合"
                ) from close_error
            if isinstance(error, WindowsScmProcessObserverError):
                raise
            raise WindowsScmProcessObserverError(
                "production observation finalization 失败"
            ) from error

    def observe_steady(
        self,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedSteadyBootWorkspace,
        inputs: LockedExactSteadyScmProcessObservationInput,
    ) -> LockedSteadyWindowsScmProcessObservation:
        """观察 exact steady active SCM／host／child；不接受 transient input。"""

        if (
            type(self._api) is not _ProductionWindowsApi
            or type(workspace) is not LockedSteadyBootWorkspace
            or type(inputs)
            is not LockedExactSteadyScmProcessObservationInput
        ):
            raise WindowsScmProcessObserverError(
                "production steady observer exact capability 类型不匹配"
            )
        self._api._assert_exact_binding()
        collected = _WindowsScmProcessObservationRunner(api=self._api).observe(
            persistence,
            lock,
            workspace,
            inputs,
        )
        try:
            if (
                type(collected.tracking)
                is not LockedWindowsSteadyScmProcessHandleTracking
            ):
                raise WindowsScmProcessObserverError(
                    "steady observer 未取得 steady 专属 handle owner"
                )
            document = _build_steady_production_evidence_document(
                inputs,
                collected,
                _authority_token=_PRODUCTION_API_TOKEN,
            )
            SteadyWindowsScmProcessObservationEvidence.from_document(
                document, inputs
            )
            return LockedSteadyWindowsScmProcessObservation(
                inputs=inputs,
                tracking=collected.tracking,
                api=self._api,
                document=document,
                service_config=collected.service_config,
                service_status=collected.service_status,
                python_class=collected.python_class,
                host_parent_pid=collected.host_parent_pid,
                host_probe=collected.host_probe,
                child_probe=collected.child_probe,
                host_file=collected.host_file,
                child_file=collected.child_file,
                _construction_token=_OBSERVATION_TOKEN,
            )
        except BaseException as error:
            try:
                collected.tracking.close()
            except BaseException as close_error:
                raise WindowsScmProcessObserverError(
                    "production steady observation cleanup 不可闭合"
                ) from close_error
            if isinstance(error, WindowsScmProcessObserverError):
                raise
            raise WindowsScmProcessObserverError(
                "production steady observation finalization 失败"
            ) from error


_TEST_ONLY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE = (
    "test_only_windows_scm_process_observation_not_evidence"
)


class _TestOnlyWindowsScmProcessObservation:
    """closed-fake 算法结果；没有生产 evidence 生成或升级出口。"""

    __slots__ = ("_api", "_inputs", "_collected")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("test-only Windows observation 不允许派生")

    def __init__(
        self,
        *,
        api: object,
        inputs: LockedExactScmProcessObservationInput,
        collected: _CollectedWindowsScmProcessObservation,
        _construction_token: object,
    ):
        if _construction_token is not _TEST_ONLY_ADAPTER_TOKEN:
            raise TypeError("test-only observation 构造权威不匹配")
        self._api = api
        self._inputs = inputs
        self._collected = collected

    def __reduce__(self) -> object:
        raise TypeError("test-only Windows observation is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def scope(self) -> str:
        self.validate_live_for_test_only()
        return _TEST_ONLY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE

    def validate_live_for_test_only(self) -> None:
        collected = self._collected
        _assert_observation_components_live(
            inputs=self._inputs,
            tracking=collected.tracking,
            api=self._api,
            service_config=collected.service_config,
            service_status=collected.service_status,
            python_class=collected.python_class,
            host_parent_pid=collected.host_parent_pid,
            host_probe=collected.host_probe,
            child_probe=collected.child_probe,
            host_file_probe=collected.host_file,
            child_file_probe=collected.child_file,
        )

    def close(self) -> None:
        self._collected.tracking.close()


class _TestOnlySteadyWindowsScmProcessObservation:
    """closed-fake steady 算法结果；没有 production evidence 出口。"""

    __slots__ = ("_api", "_inputs", "_collected")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("test-only steady Windows observation 不允许派生")

    def __init__(
        self,
        *,
        api: object,
        inputs: LockedExactSteadyScmProcessObservationInput,
        collected: _CollectedWindowsScmProcessObservation,
        _construction_token: object,
    ):
        if (
            _construction_token is not _TEST_ONLY_ADAPTER_TOKEN
            or type(inputs)
            is not LockedExactSteadyScmProcessObservationInput
            or type(collected.tracking)
            is not LockedWindowsSteadyScmProcessHandleTracking
        ):
            raise TypeError("test-only steady observation 构造权威不匹配")
        self._api = api
        self._inputs = inputs
        self._collected = collected

    def __reduce__(self) -> object:
        raise TypeError("test-only steady Windows observation is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def scope(self) -> str:
        self.validate_live_for_test_only()
        return "test_only_steady_windows_scm_process_observation_not_evidence"

    def validate_live_for_test_only(self) -> None:
        collected = self._collected
        _assert_observation_components_live(
            inputs=self._inputs,
            tracking=collected.tracking,
            api=self._api,
            service_config=collected.service_config,
            service_status=collected.service_status,
            python_class=collected.python_class,
            host_parent_pid=collected.host_parent_pid,
            host_probe=collected.host_probe,
            child_probe=collected.child_probe,
            host_file_probe=collected.host_file,
            child_file_probe=collected.child_file,
        )

    def close(self) -> None:
        self._collected.tracking.close()


class _TestOnlyWindowsScmProcessObserverAdapter:
    """测试专用 fake adapter；不继承、不构造任何 production surface。"""

    __slots__ = ("_api",)

    def __init__(self, *, api: object, _construction_token: object):
        if _construction_token is not _TEST_ONLY_ADAPTER_TOKEN:
            raise TypeError("test-only observer adapter 构造权威不匹配")
        if type(api) is _ProductionWindowsApi:
            raise TypeError("test-only adapter 不接受 production API table")
        self._api = api

    def __reduce__(self) -> object:
        raise TypeError("test-only Windows observer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def for_test_only(cls, *, api: object) -> "_TestOnlyWindowsScmProcessObserverAdapter":
        return cls(api=api, _construction_token=_TEST_ONLY_ADAPTER_TOKEN)

    def observe_test_only(
        self,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        inputs: LockedExactScmProcessObservationInput,
    ) -> _TestOnlyWindowsScmProcessObservation:
        collected = _WindowsScmProcessObservationRunner(api=self._api).observe(
            persistence,
            lock,
            workspace,
            inputs,
        )
        return _TestOnlyWindowsScmProcessObservation(
            api=self._api,
            inputs=inputs,
            collected=collected,
            _construction_token=_TEST_ONLY_ADAPTER_TOKEN,
        )

    def observe_steady_test_only(
        self,
        persistence: LocalDeploymentPersistence,
        lock: CrashReleasedFileLock,
        workspace: LockedSteadyBootWorkspace,
        inputs: LockedExactSteadyScmProcessObservationInput,
    ) -> _TestOnlySteadyWindowsScmProcessObservation:
        collected = _WindowsScmProcessObservationRunner(api=self._api).observe(
            persistence,
            lock,
            workspace,
            inputs,
        )
        return _TestOnlySteadyWindowsScmProcessObservation(
            api=self._api,
            inputs=inputs,
            collected=collected,
            _construction_token=_TEST_ONLY_ADAPTER_TOKEN,
        )


__all__ = [
    "LIVE_STEADY_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE",
    "LIVE_WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE",
    "LockedSteadyWindowsScmProcessObservation",
    "LockedWindowsScmProcessObservation",
    "ProductionWindowsScmProcessObserver",
    "WindowsScmProcessObserverError",
]
