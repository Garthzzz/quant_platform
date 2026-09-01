"""Windows service-host 的 fail-closed Job child launcher。

优先使用 STARTUPINFOEXW 的 JOB_LIST + HANDLE_LIST；当 SCM host 实测拒绝
creation-time JOB_LIST 时，child 保持 suspended，加入私有 Job 并核验后才恢复。
产品路径不使用 Popen。
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path, PureWindowsPath
import subprocess
import threading
from typing import Mapping

from .local_release_identity import identity_sha256
from .local_steady_runtime_identity import (
    ExactSteadyRuntimeIdentity,
    _parse_exact_steady_argv,
)
from .local_steady_start_authorization import LockedExactSteadyStartAuthorization
from .local_service_transient_journal_start_fence import (
    _LAUNCH_BIND_TOKEN,
    LockedServiceTransientJournalStartFence,
)
from .local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity


_API_TOKEN = object()
_LAUNCHER_TOKEN = object()
_LIFECYCLE_TOKEN = object()
_LIFETIME_TOKEN = object()
_TRANSIENT_LIFETIME_TOKEN = object()
_PROMOTION_TOKEN = object()
_ADMISSION_CONFIRM_TOKEN = object()
_PRODUCTION_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
_LOG_PATH = _PRODUCTION_ROOT / "logs" / "quant-research-hub.log"
_TMP_PATH = _PRODUCTION_ROOT / "tmp" / "service"

_GENERIC_WRITE = 0x40000000
_FILE_APPEND_DATA = 0x00000004
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_ALWAYS = 4
_CREATE_NEW = 1
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_FLAG_WRITE_THROUGH = 0x80000000
_HANDLE_FLAG_INHERIT = 0x00000001
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JOB_OBJECT_LIMIT_BREAKAWAY_OK = 0x00000800
_JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK = 0x00001000
_PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002
_PROC_THREAD_ATTRIBUTE_JOB_LIST = 0x0002000D
_STARTF_USESTDHANDLES = 0x00000100
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_CREATE_NO_WINDOW = 0x08000000
_DUPLICATE_CLOSE_SOURCE = 0x00000001
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_STILL_ACTIVE = 259
_FILE_END = 2
_ERROR_ALREADY_EXISTS = 183
_ERROR_INSUFFICIENT_BUFFER = 122
_FILE_STANDARD_INFO_CLASS = 1
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_IMAGE_FILE_MACHINE_UNKNOWN = 0x0000
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_MINIMUM_WINDOWS_BUILD = 14393
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


class WindowsJobChildLauncherError(RuntimeError):
    """Creation-time Job child 生命周期无法机械闭合。"""


class WindowsJobChildOwnerCrashRequired(WindowsJobChildLauncherError):
    """Win32 outcome unknown；service host 必须退出交由 OS 回收。"""


class _CreationTimeJobListRejected(WindowsJobChildLauncherError):
    """SCM host 实测拒绝 creation-time JOB_LIST。"""


class _FILETIME(ctypes.Structure):
    _fields_ = (("low", wintypes.DWORD), ("high", wintypes.DWORD))


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = (
        ("ReadOperationCount", ctypes.c_ulonglong),
        ("WriteOperationCount", ctypes.c_ulonglong),
        ("OtherOperationCount", ctypes.c_ulonglong),
        ("ReadTransferCount", ctypes.c_ulonglong),
        ("WriteTransferCount", ctypes.c_ulonglong),
        ("OtherTransferCount", ctypes.c_ulonglong),
    )


class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    )


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


class _SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = (
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", wintypes.LPVOID),
        ("bInheritHandle", wintypes.BOOL),
    )


class _STARTUPINFOW(ctypes.Structure):
    _fields_ = (
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    )


class _STARTUPINFOEXW(ctypes.Structure):
    _fields_ = (
        ("StartupInfo", _STARTUPINFOW),
        ("lpAttributeList", wintypes.LPVOID),
    )


class _PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
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


class _RTL_OSVERSIONINFOEXW(ctypes.Structure):
    _fields_ = (
        ("dwOSVersionInfoSize", wintypes.DWORD),
        ("dwMajorVersion", wintypes.DWORD),
        ("dwMinorVersion", wintypes.DWORD),
        ("dwBuildNumber", wintypes.DWORD),
        ("dwPlatformId", wintypes.DWORD),
        ("szCSDVersion", wintypes.WCHAR * 128),
        ("wServicePackMajor", wintypes.WORD),
        ("wServicePackMinor", wintypes.WORD),
        ("wSuiteMask", wintypes.WORD),
        ("wProductType", wintypes.BYTE),
        ("wReserved", wintypes.BYTE),
    )


def _handle(value: object, *, label: str) -> int:
    observed = int(value or 0)
    invalid = ctypes.c_void_p(-1).value
    if observed <= 0 or observed == invalid:
        raise WindowsJobChildLauncherError(f"{label} handle 无效")
    return observed


def _filetime(value: _FILETIME) -> int:
    result = (int(value.high) << 32) | int(value.low)
    if result <= 0:
        raise WindowsJobChildLauncherError("process creation time 无效")
    return result


class _ProductionJobApi:
    __slots__ = (
        "CreateJobObjectW",
        "SetInformationJobObject",
        "CreatePipe",
        "SetHandleInformation",
        "CreateFileW",
        "SetFilePointerEx",
        "FlushFileBuffers",
        "GetFinalPathNameByHandleW",
        "GetFileInformationByHandleEx",
        "InitializeProcThreadAttributeList",
        "UpdateProcThreadAttribute",
        "DeleteProcThreadAttributeList",
        "CreateProcessW",
        "AssignProcessToJobObject",
        "TerminateProcess",
        "ResumeThread",
        "IsProcessInJob",
        "GetProcessTimes",
        "GetCurrentProcess",
        "GetCurrentProcessId",
        "DuplicateHandle",
        "TerminateJobObject",
        "WaitForSingleObject",
        "GetExitCodeProcess",
        "WriteFile",
        "_kernel32",
        "_ntdll",
        "RtlGetVersion",
        "IsWow64Process2",
        "_platform_floor",
        "_host_in_outer_job",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production Job API table 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production Job API table 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, token: object) -> None:
        if token is not _API_TOKEN or os.name != "nt":
            raise TypeError("production Job API provenance 无效")
        object.__setattr__(self, "_sealed", False)
        kernel32 = ctypes.WinDLL(
            "kernel32.dll",
            use_last_error=True,
            winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        ntdll = ctypes.WinDLL(
            "ntdll.dll",
            use_last_error=True,
            winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        self._kernel32 = kernel32
        self._ntdll = ntdll
        self.CreateJobObjectW = kernel32.CreateJobObjectW
        self.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
        self.CreateJobObjectW.restype = wintypes.HANDLE
        self.SetInformationJobObject = kernel32.SetInformationJobObject
        self.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        )
        self.SetInformationJobObject.restype = wintypes.BOOL
        self.CreatePipe = kernel32.CreatePipe
        self.CreatePipe.argtypes = (
            ctypes.POINTER(wintypes.HANDLE),
            ctypes.POINTER(wintypes.HANDLE),
            ctypes.POINTER(_SECURITY_ATTRIBUTES),
            wintypes.DWORD,
        )
        self.CreatePipe.restype = wintypes.BOOL
        self.SetHandleInformation = kernel32.SetHandleInformation
        self.SetHandleInformation.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        self.SetHandleInformation.restype = wintypes.BOOL
        self.CreateFileW = kernel32.CreateFileW
        self.CreateFileW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(_SECURITY_ATTRIBUTES),
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        )
        self.CreateFileW.restype = wintypes.HANDLE
        self.SetFilePointerEx = kernel32.SetFilePointerEx
        self.SetFilePointerEx.argtypes = (
            wintypes.HANDLE,
            ctypes.c_longlong,
            ctypes.POINTER(ctypes.c_longlong),
            wintypes.DWORD,
        )
        self.SetFilePointerEx.restype = wintypes.BOOL
        self.FlushFileBuffers = kernel32.FlushFileBuffers
        self.FlushFileBuffers.argtypes = (wintypes.HANDLE,)
        self.FlushFileBuffers.restype = wintypes.BOOL
        self.GetFinalPathNameByHandleW = kernel32.GetFinalPathNameByHandleW
        self.GetFinalPathNameByHandleW.argtypes = (
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        self.GetFinalPathNameByHandleW.restype = wintypes.DWORD
        self.GetFileInformationByHandleEx = (
            kernel32.GetFileInformationByHandleEx
        )
        self.GetFileInformationByHandleEx.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            wintypes.LPVOID,
            wintypes.DWORD,
        )
        self.GetFileInformationByHandleEx.restype = wintypes.BOOL
        self.InitializeProcThreadAttributeList = (
            kernel32.InitializeProcThreadAttributeList
        )
        self.InitializeProcThreadAttributeList.argtypes = (
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_size_t),
        )
        self.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        self.UpdateProcThreadAttribute = kernel32.UpdateProcThreadAttribute
        self.UpdateProcThreadAttribute.argtypes = (
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.c_size_t,
            wintypes.LPVOID,
            ctypes.c_size_t,
            wintypes.LPVOID,
            wintypes.LPVOID,
        )
        self.UpdateProcThreadAttribute.restype = wintypes.BOOL
        self.DeleteProcThreadAttributeList = (
            kernel32.DeleteProcThreadAttributeList
        )
        self.DeleteProcThreadAttributeList.argtypes = (wintypes.LPVOID,)
        self.DeleteProcThreadAttributeList.restype = None
        self.CreateProcessW = kernel32.CreateProcessW
        self.CreateProcessW.argtypes = (
            wintypes.LPCWSTR,
            wintypes.LPWSTR,
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.LPCWSTR,
            ctypes.POINTER(_STARTUPINFOW),
            ctypes.POINTER(_PROCESS_INFORMATION),
        )
        self.CreateProcessW.restype = wintypes.BOOL
        self.AssignProcessToJobObject = kernel32.AssignProcessToJobObject
        self.AssignProcessToJobObject.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
        )
        self.AssignProcessToJobObject.restype = wintypes.BOOL
        self.TerminateProcess = kernel32.TerminateProcess
        self.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        self.TerminateProcess.restype = wintypes.BOOL
        self.ResumeThread = kernel32.ResumeThread
        self.ResumeThread.argtypes = (wintypes.HANDLE,)
        self.ResumeThread.restype = wintypes.DWORD
        self.IsProcessInJob = kernel32.IsProcessInJob
        self.IsProcessInJob.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        )
        self.IsProcessInJob.restype = wintypes.BOOL
        self.GetProcessTimes = kernel32.GetProcessTimes
        self.GetProcessTimes.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
        )
        self.GetProcessTimes.restype = wintypes.BOOL
        self.GetCurrentProcess = kernel32.GetCurrentProcess
        self.GetCurrentProcess.argtypes = ()
        self.GetCurrentProcess.restype = wintypes.HANDLE
        self.GetCurrentProcessId = kernel32.GetCurrentProcessId
        self.GetCurrentProcessId.argtypes = ()
        self.GetCurrentProcessId.restype = wintypes.DWORD
        self.IsWow64Process2 = kernel32.IsWow64Process2
        self.IsWow64Process2.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.USHORT),
            ctypes.POINTER(wintypes.USHORT),
        )
        self.IsWow64Process2.restype = wintypes.BOOL
        self.RtlGetVersion = ntdll.RtlGetVersion
        self.RtlGetVersion.argtypes = (ctypes.POINTER(_RTL_OSVERSIONINFOEXW),)
        self.RtlGetVersion.restype = ctypes.c_long
        self.DuplicateHandle = kernel32.DuplicateHandle
        self.DuplicateHandle.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.HANDLE),
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        )
        self.DuplicateHandle.restype = wintypes.BOOL
        self.TerminateJobObject = kernel32.TerminateJobObject
        self.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
        self.TerminateJobObject.restype = wintypes.BOOL
        self.WaitForSingleObject = kernel32.WaitForSingleObject
        self.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        self.WaitForSingleObject.restype = wintypes.DWORD
        self.GetExitCodeProcess = kernel32.GetExitCodeProcess
        self.GetExitCodeProcess.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        self.GetExitCodeProcess.restype = wintypes.BOOL
        self.WriteFile = kernel32.WriteFile
        self.WriteFile.argtypes = (
            wintypes.HANDLE,
            wintypes.LPCVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        )
        self.WriteFile.restype = wintypes.BOOL
        self._preflight_platform()
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "_ProductionJobApi":
        return cls(token=_API_TOKEN)

    def assert_exact(self) -> None:
        if (
            type(self) is not _ProductionJobApi
            or not self._sealed
            or type(self._platform_floor) is not tuple
            or len(self._platform_floor) != 5
            or type(self._host_in_outer_job) is not bool
        ):
            raise WindowsJobChildLauncherError("production Job API table 漂移")

    def _preflight_platform(self) -> None:
        version = _RTL_OSVERSIONINFOEXW()
        version.dwOSVersionInfoSize = ctypes.sizeof(version)
        if int(self.RtlGetVersion(ctypes.byref(version))) != 0:
            raise WindowsJobChildLauncherError("RtlGetVersion 预检失败")
        if (
            int(version.dwMajorVersion) < 10
            or int(version.dwBuildNumber) < _MINIMUM_WINDOWS_BUILD
        ):
            raise WindowsJobChildLauncherError(
                "creation-time JOB_LIST requires Windows 10/Server 2016+"
            )
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise WindowsJobChildLauncherError("production Job launcher requires 64-bit ABI")
        process_machine = wintypes.USHORT()
        native_machine = wintypes.USHORT()
        current = self.GetCurrentProcess()
        if not self.IsWow64Process2(
            current,
            ctypes.byref(process_machine),
            ctypes.byref(native_machine),
        ):
            raise WindowsJobChildLauncherError("IsWow64Process2 ABI 预检失败")
        if (
            int(process_machine.value) != _IMAGE_FILE_MACHINE_UNKNOWN
            or int(native_machine.value) != _IMAGE_FILE_MACHINE_AMD64
        ):
            raise WindowsJobChildLauncherError(
                "service host/Python 必须是 native AMD64，不允许 WOW64/ABI 漂移"
            )
        in_outer_job = wintypes.BOOL()
        if not self.IsProcessInJob(current, None, ctypes.byref(in_outer_job)):
            raise WindowsJobChildLauncherError("service host outer Job 预检失败")
        self._platform_floor = (
            int(version.dwMajorVersion),
            int(version.dwMinorVersion),
            int(version.dwBuildNumber),
            int(native_machine.value),
            ctypes.sizeof(ctypes.c_void_p) * 8,
        )
        # Production must not create a System32 probe child: the immediately
        # following all-machine process fence can still observe a fully exited
        # probe while the kernel retires its process-table entry.  Use the
        # failure-closed suspended-assignment path for every SCM host.  The
        # observed outer-Job bit remains part of the Win32 preflight above, but
        # it does not weaken or bypass private Job ownership.
        self._host_in_outer_job = True

    def _probe_nested_job_compatibility(self) -> None:
        """Prove JOB_LIST creation works from the service host's actual outer Job."""

        job = 0
        process = 0
        thread = 0
        attribute_buffer: object | None = None
        attribute_initialized = False
        primary: BaseException | None = None

        def close_source(value: int, *, label: str) -> None:
            if value <= 0:
                return
            current = self.GetCurrentProcess()
            try:
                closed = bool(
                    self.DuplicateHandle(
                        current,
                        wintypes.HANDLE(value),
                        current,
                        None,
                        0,
                        False,
                        _DUPLICATE_CLOSE_SOURCE,
                    )
                )
            except BaseException as error:
                raise WindowsJobChildOwnerCrashRequired(
                    f"nested-job probe {label} close outcome unknown"
                ) from error
            if not closed:
                raise WindowsJobChildOwnerCrashRequired(
                    f"nested-job probe {label} close failed"
                )

        try:
            job = _handle(self.CreateJobObjectW(None, None), label="probe job")
            limits = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
            limits.BasicLimitInformation.LimitFlags = (
                _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            if not self.SetInformationJobObject(
                wintypes.HANDLE(job),
                _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                ctypes.byref(limits),
                ctypes.sizeof(limits),
            ):
                raise WindowsJobChildLauncherError(
                    "nested-job probe cannot set KILL_ON_JOB_CLOSE"
                )
            size = ctypes.c_size_t()
            ctypes.set_last_error(0)
            if (
                self.InitializeProcThreadAttributeList(
                    None, 1, 0, ctypes.byref(size)
                )
                or ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER
                or size.value <= 0
            ):
                raise WindowsJobChildLauncherError(
                    "nested-job probe attribute sizing failed"
                )
            attribute_buffer = ctypes.create_string_buffer(size.value)
            attribute_pointer = ctypes.cast(attribute_buffer, wintypes.LPVOID)
            if not self.InitializeProcThreadAttributeList(
                attribute_pointer, 1, 0, ctypes.byref(size)
            ):
                raise WindowsJobChildLauncherError(
                    "nested-job probe attribute initialization failed"
                )
            attribute_initialized = True
            job_list = (wintypes.HANDLE * 1)(job)
            if not self.UpdateProcThreadAttribute(
                attribute_pointer,
                0,
                _PROC_THREAD_ATTRIBUTE_JOB_LIST,
                ctypes.cast(job_list, wintypes.LPVOID),
                ctypes.sizeof(job_list),
                None,
                None,
            ):
                raise WindowsJobChildLauncherError(
                    "nested-job probe JOB_LIST binding failed"
                )
            system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
            if type(system_root) is not str or not system_root:
                raise WindowsJobChildLauncherError(
                    "nested-job probe SystemRoot is unavailable"
                )
            executable = str(PureWindowsPath(system_root) / "System32" / "cmd.exe")
            command = ctypes.create_unicode_buffer(
                subprocess.list2cmdline((executable, "/d", "/s", "/c", "exit 0"))
            )
            startup = _STARTUPINFOEXW()
            startup.StartupInfo.cb = ctypes.sizeof(startup)
            startup.lpAttributeList = attribute_pointer
            information = _PROCESS_INFORMATION()
            created = False
            creation_error = 0
            try:
                ctypes.set_last_error(0)
                created = bool(
                    self.CreateProcessW(
                        executable,
                        command,
                        None,
                        None,
                        False,
                        _EXTENDED_STARTUPINFO_PRESENT
                        | _CREATE_SUSPENDED
                        | _CREATE_NO_WINDOW,
                        None,
                        str(_TMP_PATH),
                        ctypes.byref(startup.StartupInfo),
                        ctypes.byref(information),
                    )
                )
            finally:
                creation_error = ctypes.get_last_error()
                process = int(information.hProcess or 0)
                thread = int(information.hThread or 0)
            if not created or process <= 0 or thread <= 0:
                raise _CreationTimeJobListRejected(
                    "service host rejects creation-time JOB_LIST: "
                    f"winerror={creation_error}"
                )
            in_job = wintypes.BOOL()
            if not self.IsProcessInJob(
                wintypes.HANDLE(process),
                wintypes.HANDLE(job),
                ctypes.byref(in_job),
            ) or not bool(in_job.value):
                raise WindowsJobChildLauncherError(
                    "nested-job probe child is not in the private Job"
                )
        except BaseException as error:
            primary = error
        cleanup_error: BaseException | None = None
        if process > 0:
            try:
                if not self.TerminateJobObject(wintypes.HANDLE(job), 97):
                    raise WindowsJobChildOwnerCrashRequired(
                        "nested-job probe TerminateJobObject failed"
                    )
                waited = int(
                    self.WaitForSingleObject(wintypes.HANDLE(process), 30_000)
                )
                exit_code = wintypes.DWORD()
                if (
                    waited != _WAIT_OBJECT_0
                    or not self.GetExitCodeProcess(
                        wintypes.HANDLE(process), ctypes.byref(exit_code)
                    )
                    or int(exit_code.value) == _STILL_ACTIVE
                ):
                    raise WindowsJobChildOwnerCrashRequired(
                        "nested-job probe child termination not proven"
                    )
            except BaseException as error:
                if isinstance(error, WindowsJobChildOwnerCrashRequired):
                    cleanup_error = error
                else:
                    owner_crash = WindowsJobChildOwnerCrashRequired(
                        "nested-job probe TerminateJobObject outcome unknown"
                    )
                    owner_crash.__cause__ = error
                    cleanup_error = owner_crash
        for value, label in ((thread, "thread"), (process, "process"), (job, "job")):
            try:
                close_source(value, label=label)
            except BaseException as error:
                cleanup_error = cleanup_error or error
                break
        if attribute_initialized:
            try:
                self.DeleteProcThreadAttributeList(
                    ctypes.cast(attribute_buffer, wintypes.LPVOID)
                )
            except BaseException as error:
                cleanup_error = cleanup_error or WindowsJobChildOwnerCrashRequired(
                    "nested-job probe attribute delete outcome unknown"
                )
        if cleanup_error is not None:
            raise cleanup_error
        if primary is not None:
            raise primary


def _creation_time(api: _ProductionJobApi, handle: int) -> int:
    creation = _FILETIME()
    exit_time = _FILETIME()
    kernel = _FILETIME()
    user = _FILETIME()
    if not api.GetProcessTimes(
        wintypes.HANDLE(handle),
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel),
        ctypes.byref(user),
    ):
        raise WindowsJobChildLauncherError("无法查询 process creation time")
    return _filetime(creation)


def _environment_block(
    identity: ExactSteadyRuntimeIdentity | ExactRuntimeLeaseIdentity,
) -> str:
    if type(identity) not in {
        ExactSteadyRuntimeIdentity,
        ExactRuntimeLeaseIdentity,
    }:
        raise TypeError("steady environment identity 类型不匹配")
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if type(system_root) is not str or not system_root:
        raise WindowsJobChildLauncherError("SystemRoot 不可用")
    values = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONPYCACHEPREFIX": (
            identity.pycache_prefix
            if type(identity) is ExactSteadyRuntimeIdentity
            else str(_TMP_PATH / "pycache" / identity.start_nonce)
        ),
        "PYTHONUTF8": "1",
        "SystemRoot": system_root,
        "TEMP": str(_TMP_PATH),
        "TMP": str(_TMP_PATH),
        "WINDIR": system_root,
    }
    entries = [f"{key}={values[key]}" for key in sorted(values, key=str.casefold)]
    return "\0".join(entries) + "\0\0"


def _assert_exact_regular_file_handle(
    api: _ProductionJobApi,
    handle: int,
    *,
    expected_path: PureWindowsPath,
    label: str,
) -> None:
    path = ctypes.create_unicode_buffer(32768)
    length = int(
        api.GetFinalPathNameByHandleW(
            wintypes.HANDLE(handle), path, len(path), 0
        )
    )
    if not 1 <= length < len(path):
        raise WindowsJobChildLauncherError(f"{label} final path 无法闭合")
    observed = path.value[:length]
    if observed.startswith("\\\\?\\"):
        observed = observed[4:]
    if PureWindowsPath(observed) != expected_path:
        raise WindowsJobChildLauncherError(f"{label} handle 不属于 fixed D path")
    standard = _FILE_STANDARD_INFO()
    attributes = _FILE_ATTRIBUTE_TAG_INFO()
    if not api.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_STANDARD_INFO_CLASS,
        ctypes.byref(standard),
        ctypes.sizeof(standard),
    ) or not api.GetFileInformationByHandleEx(
        wintypes.HANDLE(handle),
        _FILE_ATTRIBUTE_TAG_INFO_CLASS,
        ctypes.byref(attributes),
        ctypes.sizeof(attributes),
    ):
        raise WindowsJobChildLauncherError(f"{label} file identity 查询失败")
    if (
        int(standard.NumberOfLinks) != 1
        or bool(standard.DeletePending)
        or bool(standard.Directory)
        or int(standard.EndOfFile) < 0
        or int(attributes.FileAttributes) & _FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise WindowsJobChildLauncherError(
            f"{label} 不是 single-link regular non-reparse file"
        )


class LockedServiceChildLaunchLifecycle:
    """Steady workspace 登记的 service-host-local Job/process owner。"""

    __slots__ = (
        "_api",
        "_workspace",
        "_authorization",
        "_identity",
        "_handles",
        "_attribute_buffer",
        "_attribute_initialized",
        "_process_id",
        "_host_creation_time_100ns",
        "_child_creation_time_100ns",
        "_job_identity_sha256",
        "_admission_binding_sha256",
        "_prelaunch_fence_sha256",
        "_owner_thread",
        "_state",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("service child launch lifecycle 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("service child launch lifecycle 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        api: _ProductionJobApi,
        authorization: (
            LockedExactSteadyStartAuthorization
            | LockedServiceTransientJournalStartFence
        ),
        identity: ExactSteadyRuntimeIdentity | ExactRuntimeLeaseIdentity,
        *,
        token: object,
    ) -> None:
        steady = (
            type(authorization) is LockedExactSteadyStartAuthorization
            and type(identity) is ExactSteadyRuntimeIdentity
        )
        transient = (
            type(authorization) is LockedServiceTransientJournalStartFence
            and type(identity) is ExactRuntimeLeaseIdentity
            and authorization._bind_launcher_identity(  # noqa: SLF001
                token=_LAUNCH_BIND_TOKEN
            )
            is identity
        )
        if (
            token is not _LIFECYCLE_TOKEN
            or type(api) is not _ProductionJobApi
            or not (steady or transient)
        ):
            raise TypeError("service child lifecycle provenance 无效")
        api.assert_exact()
        workspace = authorization._workspace if steady else None  # noqa: SLF001
        if steady:
            authorization._assert_live()  # noqa: SLF001
        object.__setattr__(self, "_sealed", False)
        self._api = api
        self._workspace = workspace
        self._authorization = authorization
        self._identity = identity
        self._handles: dict[str, int] = {
            "job": 0,
            "admission_read": 0,
            "admission_write": 0,
            "log": 0,
            "pycache_sentinel": 0,
            "process": 0,
            "thread": 0,
        }
        self._attribute_buffer = None
        self._attribute_initialized = False
        self._process_id = 0
        self._host_creation_time_100ns = 0
        self._child_creation_time_100ns = 0
        self._job_identity_sha256 = ""
        self._admission_binding_sha256 = ""
        self._prelaunch_fence_sha256 = ""
        self._owner_thread = threading.get_ident()
        self._state = "launching"
        if steady:
            workspace._register_steady_service_child_lifecycle(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("service child launch lifecycle is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_owner(self, *states: str) -> None:
        if threading.get_ident() != self._owner_thread:
            raise WindowsJobChildLauncherError("service lifecycle thread owner 漂移")
        if type(self._authorization) is LockedExactSteadyStartAuthorization:
            self._authorization._assert_live()  # noqa: SLF001
            self._workspace._assert_live()  # noqa: SLF001
        if self._state not in states:
            raise WindowsJobChildLauncherError("service lifecycle state 不允许该操作")

    def _record_handle(self, label: str, value: object) -> int:
        if label not in self._handles or self._handles[label] != 0:
            raise WindowsJobChildLauncherError(f"{label} handle slot 状态无效")
        observed = _handle(value, label=label)
        self._handles[label] = observed
        return observed

    def _retire_numeric_authority(self) -> None:
        for label in self._handles:
            self._handles[label] = 0
        object.__setattr__(self, "_state", "owner_crash_only")

    def _close_handle(self, label: str) -> None:
        value = self._handles[label]
        if value == 0:
            return
        current = self._api.GetCurrentProcess()
        try:
            closed = bool(self._api.DuplicateHandle(
                current,
                wintypes.HANDLE(value),
                current,
                None,
                0,
                False,
                _DUPLICATE_CLOSE_SOURCE,
            ))
        except BaseException as error:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                f"{label} close outcome unknown"
            ) from error
        if not closed:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                f"{label} close failed"
            )
        self._handles[label] = 0

    def _delete_attributes(self) -> None:
        if self._attribute_initialized:
            try:
                self._api.DeleteProcThreadAttributeList(
                    ctypes.cast(self._attribute_buffer, wintypes.LPVOID)
                )
            except BaseException as error:
                self._retire_numeric_authority()
                raise WindowsJobChildOwnerCrashRequired(
                    "attribute-list delete outcome unknown"
                ) from error
            object.__setattr__(self, "_attribute_initialized", False)
        object.__setattr__(self, "_attribute_buffer", None)

    def _terminate_job(self) -> None:
        job = self._handles["job"]
        if not job:
            return
        try:
            terminated = bool(
                self._api.TerminateJobObject(wintypes.HANDLE(job), 97)
            )
        except BaseException as error:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                "TerminateJobObject outcome unknown"
            ) from error
        if not terminated:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired("TerminateJobObject 失败")

    def _wait_and_reprove_absence(self) -> None:
        process = self._handles["process"]
        if process <= 0:
            return
        try:
            outcome = int(
                self._api.WaitForSingleObject(
                    wintypes.HANDLE(process), 30_000
                )
            )
        except BaseException as error:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                "terminated child wait outcome unknown"
            ) from error
        if outcome != _WAIT_OBJECT_0:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                "terminated child did not reach exact process exit"
            )
        exit_code = wintypes.DWORD()
        try:
            observed = bool(
                self._api.GetExitCodeProcess(
                    wintypes.HANDLE(process), ctypes.byref(exit_code)
                )
            )
        except BaseException as error:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                "terminated child exit-code outcome unknown"
            ) from error
        if not observed or int(exit_code.value) == _STILL_ACTIVE:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                "terminated child exit code is not closed"
            )
        try:
            from .local_windows_exact_runtime_process_fence import (
                ProductionWindowsExactRuntimeProcessFence,
            )

            ProductionWindowsExactRuntimeProcessFence.load_exact_d().assert_absent_after_termination(
                self
            )
        except BaseException as error:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                "post-termination writer/listener/old-child absence is unproven"
            ) from error

    def _close_all(self, *, terminate: bool) -> None:
        if self._state == "owner_crash_only":
            raise WindowsJobChildOwnerCrashRequired(
                "service child lifecycle numeric authority is permanently retired"
            )
        if terminate and self._handles["process"] and not self._handles["job"]:
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                "live child has no executable Job termination authority"
            )
        if (
            terminate
            and self._state in {"live", "promoted", "transient_owned"}
            and not self._handles["process"]
        ):
            self._retire_numeric_authority()
            raise WindowsJobChildOwnerCrashRequired(
                "live lifecycle has no exact child process authority"
            )
        if terminate and self._handles["job"]:
            self._terminate_job()
            self._wait_and_reprove_absence()
        failure: BaseException | None = None
        for label in (
            "thread",
            "admission_read",
            "admission_write",
            "process",
            "pycache_sentinel",
            "log",
            "job",
        ):
            try:
                self._close_handle(label)
            except BaseException as error:
                failure = failure or error
                break
        if failure is None:
            try:
                self._delete_attributes()
            except BaseException as error:
                failure = error
        if failure is not None:
            raise failure

    def _close_from_workspace(self, workspace: object) -> None:
        if (
            type(self._authorization) is not LockedExactSteadyStartAuthorization
            or workspace is not self._workspace
        ):
            raise WindowsJobChildLauncherError("service lifecycle workspace 漂移")
        if self._state == "promoted":
            raise WindowsJobChildLauncherError(
                "promoted service lifetime 不属于 boot workspace close"
            )
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise WindowsJobChildOwnerCrashRequired(
                "steady service child lifecycle requires owner crash"
            )
        self._close_all(terminate=bool(self._handles["process"]))
        object.__setattr__(self, "_state", "closed")
        workspace._release_steady_service_child_lifecycle(self)  # noqa: SLF001

    def _close_transient(self, *, terminate: bool) -> None:
        if type(self._authorization) is not LockedServiceTransientJournalStartFence:
            raise WindowsJobChildLauncherError(
                "transient lifecycle provenance is invalid"
            )
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise WindowsJobChildOwnerCrashRequired(
                "transient service child lifecycle requires owner crash"
            )
        self._close_all(terminate=terminate)
        object.__setattr__(self, "_state", "closed")
        if self._authorization._state not in {  # noqa: SLF001
            "closed",
            "consumed",
            "owner_crash_only",
        }:
            self._authorization.close()

    @property
    def process_id(self) -> int:
        self._assert_owner("live")
        return self._process_id

    @property
    def child_creation_time_100ns(self) -> int:
        self._assert_owner("live")
        return self._child_creation_time_100ns

    @property
    def job_identity_sha256(self) -> str:
        self._assert_owner("live")
        return self._job_identity_sha256

    @property
    def admission_binding_sha256(self) -> str:
        self._assert_owner("live")
        return self._admission_binding_sha256

    def _commit_registered_promotion(
        self,
        lifetime: "LockedServiceChildLifetime",
        authorization: object,
        *,
        token: object,
    ) -> None:
        from .local_steady_admission_authorization import (
            LockedSteadyAdmissionPrepareAuthorization,
        )

        self._assert_owner("live")
        if (
            token is not _PROMOTION_TOKEN
            or type(lifetime) is not LockedServiceChildLifetime
            or type(authorization) is not LockedSteadyAdmissionPrepareAuthorization
            or lifetime._lifecycle is not self  # noqa: SLF001
            or authorization._lifetime is not lifetime  # noqa: SLF001
            or authorization
            not in self._workspace._steady_admission_authorizations  # noqa: SLF001
            or lifetime._chain_aggregate_sha256  # noqa: SLF001
            != authorization._chain_aggregate_sha256  # noqa: SLF001
        ):
            raise WindowsJobChildLauncherError(
                "service child promotion destination 未先登记"
            )
        object.__setattr__(self, "_state", "promoted")
        self._workspace._release_steady_service_child_lifecycle(self)  # noqa: SLF001


class LockedServiceChildLifetime:
    """Promotion 后仍由同一 service host 独占的 Job/pipe/process owner。"""

    __slots__ = (
        "_lifecycle",
        "_chain_aggregate_sha256",
        "_state",
        "_owner_thread",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("service child lifetime 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("service child lifetime 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        lifecycle: LockedServiceChildLaunchLifecycle,
        *,
        chain_aggregate_sha256: str,
        token: object,
    ) -> None:
        if (
            token is not _LIFETIME_TOKEN
            or type(lifecycle) is not LockedServiceChildLaunchLifecycle
            or lifecycle._state != "live"  # noqa: SLF001
            or type(chain_aggregate_sha256) is not str
            or len(chain_aggregate_sha256) != 64
        ):
            raise TypeError("service child lifetime promotion provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._lifecycle = lifecycle
        self._chain_aggregate_sha256 = chain_aggregate_sha256
        self._state = "promotion_pending_admission"
        self._owner_thread = threading.get_ident()
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("service child lifetime is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_owner(self, *states: str) -> None:
        if threading.get_ident() != self._owner_thread or self._state not in states:
            raise WindowsJobChildLauncherError("service lifetime state/owner 无效")

    def _write_frame(self, frame: bytes) -> None:
        if type(frame) is not bytes or not frame or len(frame) > 256:
            raise WindowsJobChildLauncherError("admission frame 不闭合")
        lifecycle = self._lifecycle
        handle = lifecycle._handles["admission_write"]  # noqa: SLF001
        if handle <= 0:
            raise WindowsJobChildLauncherError("admission write handle 已撤销")
        payload = ctypes.create_string_buffer(frame)
        written = wintypes.DWORD()
        try:
            succeeded = bool(
                lifecycle._api.WriteFile(  # noqa: SLF001
                    wintypes.HANDLE(handle),
                    ctypes.cast(payload, wintypes.LPCVOID),
                    len(frame),
                    ctypes.byref(written),
                    None,
                )
            )
        except BaseException as error:
            lifecycle._retire_numeric_authority()  # noqa: SLF001
            object.__setattr__(self, "_state", "owner_crash_only")
            raise WindowsJobChildOwnerCrashRequired(
                "admission WriteFile outcome unknown"
            ) from error
        if not succeeded or int(written.value) != len(frame):
            try:
                lifecycle._close_all(terminate=True)  # noqa: SLF001
            except WindowsJobChildOwnerCrashRequired:
                object.__setattr__(self, "_state", "owner_crash_only")
                raise
            else:
                object.__setattr__(self, "_state", "closed")
            raise WindowsJobChildLauncherError(
                "admission WriteFile 未完成 exact fixed frame"
            )

    @property
    def job_identity_sha256(self) -> str:
        if self._state not in {
            "promotion_pending_admission",
            "prepare_sent",
            "commit_sent_waiting_observation",
            "admitted",
        }:
            raise WindowsJobChildLauncherError("service lifetime 已撤销")
        return self._lifecycle._job_identity_sha256  # noqa: SLF001

    @property
    def admission_binding_sha256(self) -> str:
        if self._state not in {
            "promotion_pending_admission",
            "prepare_sent",
            "commit_sent_waiting_observation",
            "admitted",
        }:
            raise WindowsJobChildLauncherError("service lifetime 已撤销")
        return self._lifecycle._admission_binding_sha256  # noqa: SLF001

    @property
    def chain_aggregate_sha256(self) -> str:
        self._assert_owner(
            "promotion_pending_admission",
            "prepare_sent",
            "commit_sent_waiting_observation",
            "admitted",
        )
        return self._chain_aggregate_sha256

    def prepare_admission_after_promotion(self, authorization: object) -> None:
        from .local_exact_runtime_admission import build_prepare_frame
        from .local_steady_admission_authorization import (
            LockedSteadyAdmissionPrepareAuthorization,
        )

        self._assert_owner("promotion_pending_admission")
        if type(authorization) is not LockedSteadyAdmissionPrepareAuthorization:
            raise TypeError("PREPARE requires exact steady authorization")
        authorization._assert_for_prepare(self)  # noqa: SLF001
        self._write_frame(
            build_prepare_frame(self._lifecycle._admission_binding_sha256)  # noqa: SLF001
        )
        authorization._mark_prepared(self)  # noqa: SLF001
        object.__setattr__(self, "_state", "prepare_sent")

    def commit_admission_after_ready_ack(self, authorization: object) -> None:
        from .local_exact_runtime_admission import build_commit_frame
        from .local_steady_admission_authorization import (
            LockedSteadyAdmissionCommitAuthorization,
        )

        self._assert_owner("prepare_sent")
        if type(authorization) is not LockedSteadyAdmissionCommitAuthorization:
            raise TypeError("COMMIT requires exact steady authorization")
        ready_ack = authorization._assert_for_commit(self)  # noqa: SLF001
        self._write_frame(
            build_commit_frame(
                self._lifecycle._admission_binding_sha256,  # noqa: SLF001
                ready_ack,
            )
        )
        self._lifecycle._close_handle("admission_write")  # noqa: SLF001
        authorization._mark_commit_sent(self)  # noqa: SLF001
        object.__setattr__(self, "_state", "commit_sent_waiting_observation")

    def _mark_admitted_after_observation(self, *, token: object) -> None:
        self._assert_owner("commit_sent_waiting_observation")
        if token is not _ADMISSION_CONFIRM_TOKEN:
            raise WindowsJobChildLauncherError(
                "post-commit admitted observation token 无效"
            )
        object.__setattr__(self, "_state", "admitted")

    def wait_for_exit(self, timeout_ms: int) -> int | None:
        if self._state == "owner_crash_only":
            raise WindowsJobChildOwnerCrashRequired(
                "service child lifetime requires owner crash"
            )
        self._assert_owner("admitted")
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 60_000:
            raise WindowsJobChildLauncherError("service child wait timeout 无效")
        process = self._lifecycle._handles["process"]  # noqa: SLF001
        if process <= 0:
            raise WindowsJobChildLauncherError("service child process handle 已撤销")
        try:
            outcome = int(
                self._lifecycle._api.WaitForSingleObject(  # noqa: SLF001
                    wintypes.HANDLE(process), timeout_ms
                )
            )
        except BaseException as error:
            self._lifecycle._retire_numeric_authority()  # noqa: SLF001
            object.__setattr__(self, "_state", "owner_crash_only")
            raise WindowsJobChildOwnerCrashRequired(
                "WaitForSingleObject outcome unknown"
            ) from error
        if outcome == _WAIT_TIMEOUT:
            return None
        if outcome != _WAIT_OBJECT_0:
            self._lifecycle._retire_numeric_authority()  # noqa: SLF001
            object.__setattr__(self, "_state", "owner_crash_only")
            raise WindowsJobChildOwnerCrashRequired(
                "WaitForSingleObject outcome unknown"
            )
        exit_code = wintypes.DWORD()
        try:
            exit_observed = bool(
                self._lifecycle._api.GetExitCodeProcess(  # noqa: SLF001
                    wintypes.HANDLE(process), ctypes.byref(exit_code)
                )
            )
        except BaseException as error:
            self._lifecycle._retire_numeric_authority()  # noqa: SLF001
            object.__setattr__(self, "_state", "owner_crash_only")
            raise WindowsJobChildOwnerCrashRequired(
                "GetExitCodeProcess outcome unknown"
            ) from error
        if not exit_observed:
            self._lifecycle._retire_numeric_authority()  # noqa: SLF001
            object.__setattr__(self, "_state", "owner_crash_only")
            raise WindowsJobChildOwnerCrashRequired(
                "GetExitCodeProcess outcome unknown"
            )
        observed = int(exit_code.value)
        if observed == _STILL_ACTIVE:
            raise WindowsJobChildLauncherError(
                "signaled child 仍报告 STILL_ACTIVE"
            )
        try:
            self._lifecycle._wait_and_reprove_absence()  # noqa: SLF001
            self._lifecycle._close_all(terminate=False)  # noqa: SLF001
        except WindowsJobChildOwnerCrashRequired:
            object.__setattr__(self, "_state", "owner_crash_only")
            raise
        object.__setattr__(self, "_state", "closed")
        return observed

    def terminate(self) -> None:
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise WindowsJobChildOwnerCrashRequired(
                "service child lifetime requires owner crash"
            )
        self._assert_owner(
            "promotion_pending_admission",
            "prepare_sent",
            "commit_sent_waiting_observation",
            "admitted",
        )
        try:
            self._lifecycle._close_all(terminate=True)  # noqa: SLF001
        except WindowsJobChildOwnerCrashRequired:
            object.__setattr__(self, "_state", "owner_crash_only")
            raise
        object.__setattr__(self, "_state", "closed")


class LockedTransientServiceChildLifetime:
    """Transient child Job owner; it has no admission/promotion capability."""

    __slots__ = ("_lifecycle", "_owner_thread", "_state", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("transient service child lifetime cannot be subclassed")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("transient service child lifetime is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        lifecycle: LockedServiceChildLaunchLifecycle,
        *,
        token: object,
    ) -> None:
        if (
            token is not _TRANSIENT_LIFETIME_TOKEN
            or type(lifecycle) is not LockedServiceChildLaunchLifecycle
            or type(lifecycle._authorization)  # noqa: SLF001
            is not LockedServiceTransientJournalStartFence
            or lifecycle._state != "live"  # noqa: SLF001
            or lifecycle._authorization._state != "consumed"  # noqa: SLF001
        ):
            raise TypeError("transient service child lifetime provenance is invalid")
        object.__setattr__(self, "_sealed", False)
        self._lifecycle = lifecycle
        self._owner_thread = threading.get_ident()
        self._state = "live"
        object.__setattr__(lifecycle, "_state", "transient_owned")
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("transient service child lifetime is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_live(self) -> None:
        if threading.get_ident() != self._owner_thread or self._state != "live":
            raise WindowsJobChildLauncherError(
                "transient service child lifetime owner/state drifted"
            )

    @property
    def process_id(self) -> int:
        self._assert_live()
        return self._lifecycle._process_id  # noqa: SLF001

    def wait_for_exit(self, timeout_ms: int) -> int | None:
        if self._state == "owner_crash_only":
            raise WindowsJobChildOwnerCrashRequired(
                "transient service child lifetime requires owner crash"
            )
        self._assert_live()
        if type(timeout_ms) is not int or not 0 <= timeout_ms <= 60_000:
            raise WindowsJobChildLauncherError(
                "transient service child wait timeout is invalid"
            )
        lifecycle = self._lifecycle
        process = lifecycle._handles["process"]  # noqa: SLF001
        if process <= 0:
            raise WindowsJobChildLauncherError(
                "transient service child process handle is revoked"
            )
        try:
            outcome = int(
                lifecycle._api.WaitForSingleObject(  # noqa: SLF001
                    wintypes.HANDLE(process), timeout_ms
                )
            )
        except BaseException as error:
            lifecycle._retire_numeric_authority()  # noqa: SLF001
            object.__setattr__(self, "_state", "owner_crash_only")
            raise WindowsJobChildOwnerCrashRequired(
                "transient WaitForSingleObject outcome is unknown"
            ) from error
        if outcome == _WAIT_TIMEOUT:
            return None
        if outcome != _WAIT_OBJECT_0:
            lifecycle._retire_numeric_authority()  # noqa: SLF001
            object.__setattr__(self, "_state", "owner_crash_only")
            raise WindowsJobChildOwnerCrashRequired(
                "transient WaitForSingleObject outcome is unknown"
            )
        exit_code = wintypes.DWORD()
        try:
            exit_observed = bool(
                lifecycle._api.GetExitCodeProcess(  # noqa: SLF001
                    wintypes.HANDLE(process), ctypes.byref(exit_code)
                )
            )
        except BaseException as error:
            lifecycle._retire_numeric_authority()  # noqa: SLF001
            object.__setattr__(self, "_state", "owner_crash_only")
            raise WindowsJobChildOwnerCrashRequired(
                "transient GetExitCodeProcess outcome is unknown"
            ) from error
        if not exit_observed:
            lifecycle._retire_numeric_authority()  # noqa: SLF001
            object.__setattr__(self, "_state", "owner_crash_only")
            raise WindowsJobChildOwnerCrashRequired(
                "transient GetExitCodeProcess outcome is unknown"
            )
        observed = int(exit_code.value)
        if observed == _STILL_ACTIVE:
            raise WindowsJobChildLauncherError(
                "signaled transient child still reports STILL_ACTIVE"
            )
        try:
            lifecycle._wait_and_reprove_absence()  # noqa: SLF001
            lifecycle._close_transient(terminate=False)  # noqa: SLF001
        except WindowsJobChildOwnerCrashRequired:
            object.__setattr__(self, "_state", "owner_crash_only")
            raise
        object.__setattr__(self, "_state", "closed")
        return observed

    def terminate(self) -> None:
        if self._state == "closed":
            return
        if self._state == "owner_crash_only":
            raise WindowsJobChildOwnerCrashRequired(
                "transient service child lifetime requires owner crash"
            )
        self._assert_live()
        try:
            self._lifecycle._close_transient(terminate=True)  # noqa: SLF001
        except WindowsJobChildOwnerCrashRequired:
            object.__setattr__(self, "_state", "owner_crash_only")
            raise
        object.__setattr__(self, "_state", "closed")


class ProductionWindowsJobChildLauncher:
    """无参数产品 loader；只接受 same-host live steady authorization。"""

    __slots__ = ("_api", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production Windows Job launcher 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production Windows Job launcher 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, api: _ProductionJobApi, *, token: object) -> None:
        if token is not _LAUNCHER_TOKEN or type(api) is not _ProductionJobApi:
            raise TypeError("production Windows Job launcher provenance 无效")
        api.assert_exact()
        object.__setattr__(self, "_sealed", False)
        self._api = api
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "ProductionWindowsJobChildLauncher":
        return cls(_ProductionJobApi.load_exact_d(), token=_LAUNCHER_TOKEN)

    def launch_transient(
        self,
        fence: LockedServiceTransientJournalStartFence,
    ) -> LockedTransientServiceChildLifetime:
        if type(fence) is not LockedServiceTransientJournalStartFence:
            raise TypeError("transient Job launcher requires exact live fence")
        identity = fence._bind_launcher_identity(  # noqa: SLF001
            token=_LAUNCH_BIND_TOKEN
        )
        lifecycle = LockedServiceChildLaunchLifecycle(
            self._api,
            fence,
            identity,
            token=_LIFECYCLE_TOKEN,
        )
        try:
            from .local_windows_exact_runtime_process_fence import (
                ProductionWindowsExactRuntimeProcessFence,
            )

            fence_sha256 = (
                ProductionWindowsExactRuntimeProcessFence.load_exact_d()
                .assert_absent_before_launch(lifecycle)
            )
            object.__setattr__(
                lifecycle, "_prelaunch_fence_sha256", fence_sha256
            )
            fence.checkpoint_before_create_job()
            self._launch(lifecycle)
            return LockedTransientServiceChildLifetime(
                lifecycle, token=_TRANSIENT_LIFETIME_TOKEN
            )
        except BaseException as primary:
            if lifecycle._state not in {"closed", "owner_crash_only"}:  # noqa: SLF001
                try:
                    lifecycle._close_transient(  # noqa: SLF001
                        terminate=bool(lifecycle._handles["process"])  # noqa: SLF001
                    )
                except BaseException as cleanup_error:
                    raise cleanup_error from primary
            raise primary

    def launch_steady(
        self, authorization: LockedExactSteadyStartAuthorization
    ) -> LockedServiceChildLaunchLifecycle:
        if type(authorization) is not LockedExactSteadyStartAuthorization:
            raise TypeError("steady Job launcher requires exact live authorization")
        try:
            authorization._assert_live()  # noqa: SLF001
        except Exception as error:
            raise WindowsJobChildLauncherError(
                "steady Job launcher authorization is not live"
            ) from error
        service_arguments = authorization.service_start_arguments
        if not service_arguments or service_arguments[0] != "steady-exact-runtime":
            raise WindowsJobChildLauncherError("steady service arguments 不闭合")
        identity = ExactSteadyRuntimeIdentity(
            **_parse_exact_steady_argv(tuple(service_arguments[1:]))
        )
        if identity.child_argv != authorization.child_argv:
            raise WindowsJobChildLauncherError(
                "steady identity child argv 与 live authorization 不一致"
            )
        lifecycle = LockedServiceChildLaunchLifecycle(
            self._api,
            authorization,
            identity,
            token=_LIFECYCLE_TOKEN,
        )
        try:
            from .local_windows_exact_runtime_process_fence import (
                ProductionWindowsExactRuntimeProcessFence,
            )

            fence_sha256 = (
                ProductionWindowsExactRuntimeProcessFence.load_exact_d()
                .assert_absent_before_launch(lifecycle)
            )
            object.__setattr__(
                lifecycle, "_prelaunch_fence_sha256", fence_sha256
            )
            self._launch(lifecycle)
            return lifecycle
        except BaseException as primary:
            if lifecycle._state not in {"closed", "owner_crash_only"}:  # noqa: SLF001
                try:
                    lifecycle._close_from_workspace(  # noqa: SLF001
                        lifecycle._workspace  # noqa: SLF001
                    )
                except BaseException as cleanup_error:
                    raise cleanup_error from primary
            raise primary

    def _launch(self, lifecycle: LockedServiceChildLaunchLifecycle) -> None:
        lifecycle._assert_owner("launching")  # noqa: SLF001
        api = self._api
        api.assert_exact()
        identity = lifecycle._identity  # noqa: SLF001
        transient = type(identity) is ExactRuntimeLeaseIdentity
        ctypes.set_last_error(0)
        job = lifecycle._record_handle(  # noqa: SLF001
            "job", api.CreateJobObjectW(None, None)
        )
        if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
            raise WindowsJobChildLauncherError("private Job namespace 发生碰撞")
        limits = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        limits.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        if limits.BasicLimitInformation.LimitFlags & (
            _JOB_OBJECT_LIMIT_BREAKAWAY_OK
            | _JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK
        ):
            raise WindowsJobChildLauncherError("private Job 不得允许 breakaway")
        if not api.SetInformationJobObject(
            wintypes.HANDLE(job),
            _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        ):
            raise WindowsJobChildLauncherError("无法设置 KILL_ON_JOB_CLOSE")
        security = _SECURITY_ATTRIBUTES(
            ctypes.sizeof(_SECURITY_ATTRIBUTES), None, True
        )
        read_output = wintypes.HANDLE()
        write_output = wintypes.HANDLE()
        try:
            pipe_ok = api.CreatePipe(
                ctypes.byref(read_output),
                ctypes.byref(write_output),
                ctypes.byref(security),
                0,
            )
        finally:
            if read_output.value:
                lifecycle._record_handle(  # noqa: SLF001
                    "admission_read", read_output.value
                )
            if write_output.value:
                lifecycle._record_handle(  # noqa: SLF001
                    "admission_write", write_output.value
                )
        if not pipe_ok:
            raise WindowsJobChildLauncherError("CreatePipe 失败")
        read_handle = lifecycle._handles["admission_read"]  # noqa: SLF001
        write_handle = lifecycle._handles["admission_write"]  # noqa: SLF001
        if not api.SetHandleInformation(
            wintypes.HANDLE(read_handle),
            _HANDLE_FLAG_INHERIT,
            _HANDLE_FLAG_INHERIT,
        ) or not api.SetHandleInformation(
            wintypes.HANDLE(write_handle), _HANDLE_FLAG_INHERIT, 0
        ):
            raise WindowsJobChildLauncherError(
                "admission pipe inherit flags 无法闭合"
            )
        log_security = _SECURITY_ATTRIBUTES(
            ctypes.sizeof(_SECURITY_ATTRIBUTES), None, True
        )
        log_handle = lifecycle._record_handle(  # noqa: SLF001
            "log",
            api.CreateFileW(
                str(_LOG_PATH),
                _GENERIC_WRITE | _FILE_APPEND_DATA,
                _FILE_SHARE_READ | _FILE_SHARE_WRITE,
                ctypes.byref(log_security),
                _OPEN_ALWAYS,
                _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_WRITE_THROUGH,
                None,
            ),
        )
        if not api.SetHandleInformation(
            wintypes.HANDLE(log_handle),
            _HANDLE_FLAG_INHERIT,
            _HANDLE_FLAG_INHERIT,
        ) or not api.SetFilePointerEx(
            wintypes.HANDLE(log_handle), 0, None, _FILE_END
        ):
            raise WindowsJobChildLauncherError("service log handle 无法闭合")
        _assert_exact_regular_file_handle(
            api,
            log_handle,
            expected_path=_LOG_PATH,
            label="service log",
        )
        sentinel_path = (
            PureWindowsPath(identity.pycache_prefix)
            if type(identity) is ExactSteadyRuntimeIdentity
            else _TMP_PATH / "pycache" / identity.start_nonce
        )
        sentinel_handle = lifecycle._record_handle(  # noqa: SLF001
            "pycache_sentinel",
            api.CreateFileW(
                str(sentinel_path),
                _GENERIC_WRITE,
                _FILE_SHARE_READ,
                None,
                _CREATE_NEW,
                _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_WRITE_THROUGH,
                None,
            ),
        )
        sentinel_raw = (
            json.dumps(
                {
                    "schema_version": "qrh-exact-runtime-pycache-sentinel/v1",
                    **(
                        {"start_nonce": identity.start_nonce}
                        if transient
                        else {"boot_nonce": identity.boot_nonce}
                    ),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        sentinel_buffer = ctypes.create_string_buffer(sentinel_raw)
        sentinel_written = wintypes.DWORD()
        if not api.WriteFile(
            wintypes.HANDLE(sentinel_handle),
            ctypes.cast(sentinel_buffer, wintypes.LPCVOID),
            len(sentinel_raw),
            ctypes.byref(sentinel_written),
            None,
        ) or int(sentinel_written.value) != len(sentinel_raw):
            raise WindowsJobChildLauncherError(
                "steady pycache sentinel exact write 失败"
            )
        if not api.FlushFileBuffers(wintypes.HANDLE(sentinel_handle)):
            raise WindowsJobChildLauncherError("steady pycache sentinel fsync 失败")
        _assert_exact_regular_file_handle(
            api,
            sentinel_handle,
            expected_path=sentinel_path,
            label="steady pycache sentinel",
        )
        lifecycle._close_handle("pycache_sentinel")  # noqa: SLF001

        size = ctypes.c_size_t()
        ctypes.set_last_error(0)
        attribute_count = 1 if api._host_in_outer_job else 2
        sizing_result = api.InitializeProcThreadAttributeList(
            None, attribute_count, 0, ctypes.byref(size)
        )
        if (
            sizing_result
            or ctypes.get_last_error() != _ERROR_INSUFFICIENT_BUFFER
            or size.value <= 0
        ):
            raise WindowsJobChildLauncherError("attribute-list size 无效")
        attribute_buffer = ctypes.create_string_buffer(size.value)
        object.__setattr__(lifecycle, "_attribute_buffer", attribute_buffer)
        attribute_pointer = ctypes.cast(attribute_buffer, wintypes.LPVOID)
        if not api.InitializeProcThreadAttributeList(
            attribute_pointer, attribute_count, 0, ctypes.byref(size)
        ):
            raise WindowsJobChildLauncherError("attribute-list 初始化失败")
        object.__setattr__(lifecycle, "_attribute_initialized", True)
        job_list = (wintypes.HANDLE * 1)(job)
        handle_list = (wintypes.HANDLE * 2)(read_handle, log_handle)
        if (
            not api._host_in_outer_job
            and not api.UpdateProcThreadAttribute(
                attribute_pointer,
                0,
                _PROC_THREAD_ATTRIBUTE_JOB_LIST,
                ctypes.cast(job_list, wintypes.LPVOID),
                ctypes.sizeof(job_list),
                None,
                None,
            )
        ) or not api.UpdateProcThreadAttribute(
            attribute_pointer,
            0,
            _PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            ctypes.cast(handle_list, wintypes.LPVOID),
            ctypes.sizeof(handle_list),
            None,
            None,
        ):
            raise WindowsJobChildLauncherError(
                "JOB_LIST/HANDLE_LIST attribute 绑定失败"
            )
        if transient:
            lifecycle._authorization.checkpoint_before_create_process()  # noqa: SLF001
        startup = _STARTUPINFOEXW()
        startup.StartupInfo.cb = ctypes.sizeof(startup)
        startup.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
        startup.StartupInfo.hStdInput = wintypes.HANDLE(read_handle)
        startup.StartupInfo.hStdOutput = wintypes.HANDLE(log_handle)
        startup.StartupInfo.hStdError = wintypes.HANDLE(log_handle)
        startup.lpAttributeList = attribute_pointer
        command_line = ctypes.create_unicode_buffer(
            subprocess.list2cmdline(list(identity.child_argv))
        )
        environment = ctypes.create_unicode_buffer(_environment_block(identity))
        process_info = _PROCESS_INFORMATION()
        created = False
        try:
            created = bool(
                api.CreateProcessW(
                    identity.child_argv[0],
                    command_line,
                    None,
                    None,
                    True,
                    _EXTENDED_STARTUPINFO_PRESENT
                    | _CREATE_SUSPENDED
                    | _CREATE_UNICODE_ENVIRONMENT,
                    environment,
                    str(_TMP_PATH),
                    ctypes.byref(startup.StartupInfo),
                    ctypes.byref(process_info),
                )
            )
        finally:
            if process_info.hProcess:
                lifecycle._record_handle(  # noqa: SLF001
                    "process", process_info.hProcess
                )
            if process_info.hThread:
                lifecycle._record_handle(  # noqa: SLF001
                    "thread", process_info.hThread
                )
            if process_info.dwProcessId:
                object.__setattr__(
                    lifecycle, "_process_id", int(process_info.dwProcessId)
                )
        if not created:
            raise WindowsJobChildLauncherError("CreateProcessW 失败")
        process_handle = lifecycle._handles["process"]  # noqa: SLF001
        thread_handle = lifecycle._handles["thread"]  # noqa: SLF001
        if api._host_in_outer_job:
            ctypes.set_last_error(0)
            if not api.AssignProcessToJobObject(
                wintypes.HANDLE(job), wintypes.HANDLE(process_handle)
            ):
                assignment_error = ctypes.get_last_error()
                try:
                    terminated = bool(
                        api.TerminateProcess(wintypes.HANDLE(process_handle), 97)
                    )
                    waited = int(
                        api.WaitForSingleObject(
                            wintypes.HANDLE(process_handle), 30_000
                        )
                    )
                except BaseException as error:
                    lifecycle._retire_numeric_authority()  # noqa: SLF001
                    raise WindowsJobChildOwnerCrashRequired(
                        "unassigned suspended child termination outcome is unknown"
                    ) from error
                if not terminated or waited != _WAIT_OBJECT_0:
                    lifecycle._retire_numeric_authority()  # noqa: SLF001
                    raise WindowsJobChildOwnerCrashRequired(
                        "unassigned suspended child could not be retired"
                    )
                raise WindowsJobChildLauncherError(
                    "outer-Job suspended child assignment failed: "
                    f"winerror={assignment_error}"
                )
        in_job = wintypes.BOOL()
        if not api.IsProcessInJob(
            wintypes.HANDLE(process_handle),
            wintypes.HANDLE(job),
            ctypes.byref(in_job),
        ) or not bool(in_job.value):
            raise WindowsJobChildLauncherError(
                "child is not in the exact private Job before resume"
            )
        # GetCurrentProcess 返回的是约定值 -1，而不是可按普通 HANDLE 规则
        # 校验/关闭的真实内核句柄；它只用于本进程 GetProcessTimes 调用。
        host_handle = int(api.GetCurrentProcess() or 0)
        if host_handle != ctypes.c_void_p(-1).value:
            raise WindowsJobChildLauncherError(
                "GetCurrentProcess 未返回预期 pseudo handle"
            )
        host_creation = _creation_time(api, host_handle)
        child_creation = _creation_time(api, process_handle)
        if child_creation < host_creation:
            raise WindowsJobChildLauncherError("child creation time 早于 service host")
        process_identity: Mapping[str, int] = {
            "host_pid": int(api.GetCurrentProcessId()),
            "host_creation_time_100ns": host_creation,
            "child_pid": lifecycle._process_id,  # noqa: SLF001
            "child_creation_time_100ns": child_creation,
        }
        if transient:
            job_material = {
                "schema_version": "qrh-transient-service-job-identity/v1",
                "attempt": identity.attempt_id,
                "nonce": identity.nonce,
                "role": identity.role,
                "start_nonce": identity.start_nonce,
                "scm_identity_sha256": identity.scm_identity_sha256,
                **process_identity,
            }
            admission_material = {
                "schema_version": "qrh-transient-admission-binding/v1",
                "attempt": identity.attempt_id,
                "nonce": identity.nonce,
                "role": identity.role,
                "start_nonce": identity.start_nonce,
                "state_identity_sha256": identity.state_identity_sha256,
                "release": {
                    "release_id": identity.release_id,
                    "release_path": identity.release_path,
                    "manifest_sha256": identity.manifest_sha256,
                },
            }
        else:
            job_material = {
                "schema_version": "qrh-steady-service-job-identity/v1",
                "boot_nonce": identity.boot_nonce,
                "scm_identity_sha256": identity.scm_identity_sha256,
                **process_identity,
            }
            admission_material = {
                "schema_version": "qrh-steady-admission-binding/v1",
                "boot_nonce": identity.boot_nonce,
                "state_identity_sha256": identity.state_identity_sha256,
                "release": dict(identity.release_ref),
            }
        job_identity = identity_sha256(job_material)
        admission_binding = identity_sha256(
            {**admission_material, "job_identity_sha256": job_identity}
        )
        object.__setattr__(
            lifecycle, "_host_creation_time_100ns", host_creation
        )
        object.__setattr__(
            lifecycle, "_child_creation_time_100ns", child_creation
        )
        object.__setattr__(lifecycle, "_job_identity_sha256", job_identity)
        object.__setattr__(
            lifecycle, "_admission_binding_sha256", admission_binding
        )
        lifecycle._close_handle("admission_read")  # noqa: SLF001
        if transient:
            lifecycle._authorization.checkpoint_before_resume()  # noqa: SLF001
        previous_count = int(api.ResumeThread(wintypes.HANDLE(thread_handle)))
        if previous_count != 1:
            raise WindowsJobChildLauncherError(
                "ResumeThread suspend count 不是精确 1→0"
            )
        post_resume_wait = int(
            api.WaitForSingleObject(wintypes.HANDLE(process_handle), 0)
        )
        if post_resume_wait != _WAIT_TIMEOUT:
            if post_resume_wait != _WAIT_OBJECT_0:
                lifecycle._retire_numeric_authority()  # noqa: SLF001
                raise WindowsJobChildOwnerCrashRequired(
                    "post-Resume child wait outcome is unknown"
                )
            raise WindowsJobChildLauncherError(
                "child exited before post-Resume prelaunch facts"
            )
        post_resume_exit = wintypes.DWORD()
        if not api.GetExitCodeProcess(
            wintypes.HANDLE(process_handle), ctypes.byref(post_resume_exit)
        ):
            lifecycle._retire_numeric_authority()  # noqa: SLF001
            raise WindowsJobChildOwnerCrashRequired(
                "post-Resume child exit query outcome is unknown"
            )
        post_resume_in_job = wintypes.BOOL()
        if (
            int(post_resume_exit.value) != _STILL_ACTIVE
            or not api.IsProcessInJob(
                wintypes.HANDLE(process_handle),
                wintypes.HANDLE(job),
                ctypes.byref(post_resume_in_job),
            )
            or not bool(post_resume_in_job.value)
            or _creation_time(api, process_handle) != child_creation
        ):
            raise WindowsJobChildLauncherError(
                "post-Resume child live/Job/creation facts drifted"
            )
        if not transient:
            lifecycle._authorization._assert_live()  # noqa: SLF001
        if transient:
            lifecycle._authorization.checkpoint_after_resume_and_consume()  # noqa: SLF001
        lifecycle._close_handle("thread")  # noqa: SLF001
        object.__setattr__(lifecycle, "_state", "live")


__all__ = [
    "LockedServiceChildLaunchLifecycle",
    "LockedServiceChildLifetime",
    "LockedTransientServiceChildLifetime",
    "ProductionWindowsJobChildLauncher",
    "WindowsJobChildLauncherError",
    "WindowsJobChildOwnerCrashRequired",
]
