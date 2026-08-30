"""Whole-machine old exact-D runtime child and writer-lock prelaunch fence."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from pathlib import PureWindowsPath
import os
import socket
import threading

from .local_release_identity import identity_sha256
from .local_windows_scm_process_observer import (
    WindowsScmProcessObserverError,
    _PROCESSENTRY32W,
    _ProductionWindowsApi,
)
from .local_windows_writer_lease_evidence import WRITER_LOCK_RELATIVE_PATH


_API_TOKEN = object()
_FENCE_TOKEN = object()
_PRODUCTION_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
_CHILD_EXECUTABLE = _PRODUCTION_ROOT / "tooling" / "python" / "python.exe"
_ENTRY_MODULE = "quant_hub.ops.local_exact_runtime_entry"
_WRITER_LOCK = _PRODUCTION_ROOT / PureWindowsPath(WRITER_LOCK_RELATIVE_PATH)
_TH32CS_SNAPPROCESS = 0x00000002
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_SYNCHRONIZE = 0x00100000
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_OPEN_ALWAYS = 4
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_DUPLICATE_CLOSE_SOURCE = 0x00000001
_ERROR_NO_MORE_FILES = 18
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


class WindowsExactRuntimeProcessFenceError(RuntimeError):
    """Old exact runtime absence or writer availability cannot be proven."""


class WindowsExactRuntimeProcessFenceOwnerCrashRequired(
    WindowsExactRuntimeProcessFenceError
):
    """A process-fence handle close outcome is unknown."""


def _handle(value: object, *, label: str) -> int:
    observed = int(value or 0)
    if observed <= 0 or observed == ctypes.c_void_p(-1).value:
        raise WindowsExactRuntimeProcessFenceError(f"{label} handle 无效")
    return observed


class _FenceApi:
    __slots__ = (
        "scm",
        "DuplicateHandle",
        "GetCurrentProcess",
        "CommandLineToArgvW",
        "LocalFree",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("exact runtime process fence API 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("exact runtime process fence API 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, token: object) -> None:
        if token is not _API_TOKEN or os.name != "nt":
            raise TypeError("exact runtime process fence API provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self.scm = _ProductionWindowsApi.load_exact_d()
        kernel32 = ctypes.WinDLL(
            "kernel32.dll",
            use_last_error=True,
            winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
        shell32 = ctypes.WinDLL(
            "shell32.dll",
            use_last_error=True,
            winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
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
        self.GetCurrentProcess = kernel32.GetCurrentProcess
        self.GetCurrentProcess.argtypes = ()
        self.GetCurrentProcess.restype = wintypes.HANDLE
        self.CommandLineToArgvW = shell32.CommandLineToArgvW
        self.CommandLineToArgvW.argtypes = (
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_int),
        )
        self.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
        self.LocalFree = kernel32.LocalFree
        self.LocalFree.argtypes = (wintypes.HLOCAL,)
        self.LocalFree.restype = wintypes.HLOCAL
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "_FenceApi":
        return cls(token=_API_TOKEN)

    def assert_exact(self) -> None:
        if type(self) is not _FenceApi or not self._sealed:
            raise WindowsExactRuntimeProcessFenceError("process fence API 漂移")
        self.scm._assert_exact_binding()  # noqa: SLF001

    def close_handle(self, handle: int) -> None:
        current = self.GetCurrentProcess()
        try:
            closed = bool(self.DuplicateHandle(
                current,
                wintypes.HANDLE(handle),
                current,
                None,
                0,
                False,
                _DUPLICATE_CLOSE_SOURCE,
            ))
        except BaseException as error:
            raise WindowsExactRuntimeProcessFenceOwnerCrashRequired(
                "process fence handle close outcome unknown"
            ) from error
        if not closed:
            raise WindowsExactRuntimeProcessFenceOwnerCrashRequired(
                "process fence handle close failed"
            )

    def argv(self, command_line: str) -> tuple[str, ...]:
        count = ctypes.c_int()
        pointer = self.CommandLineToArgvW(command_line, ctypes.byref(count))
        if not pointer or not 1 <= int(count.value) <= 128:
            raise WindowsExactRuntimeProcessFenceError(
                "exact D process command line 无法闭合解析"
            )
        try:
            values = tuple(str(pointer[index]) for index in range(count.value))
        finally:
            if self.LocalFree(ctypes.cast(pointer, wintypes.HLOCAL)):
                raise WindowsExactRuntimeProcessFenceError(
                    "CommandLineToArgvW buffer close 失败"
                )
        return values


class ProductionWindowsExactRuntimeProcessFence:
    __slots__ = ("_api", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production exact runtime process fence 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production exact runtime process fence 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, api: _FenceApi, *, token: object) -> None:
        if token is not _FENCE_TOKEN or type(api) is not _FenceApi:
            raise TypeError("production process fence provenance 无效")
        api.assert_exact()
        object.__setattr__(self, "_sealed", False)
        self._api = api
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "ProductionWindowsExactRuntimeProcessFence":
        return cls(_FenceApi.load_exact_d(), token=_FENCE_TOKEN)

    def _snapshot(self) -> tuple[tuple[int, int, str], ...]:
        api = self._api
        api.assert_exact()
        raw_snapshot = api.scm.create_toolhelp32_snapshot(
            _TH32CS_SNAPPROCESS, 0
        )
        snapshot = _handle(raw_snapshot, label="process snapshot")
        matches: list[tuple[int, int, str]] = []
        primary: BaseException | None = None
        try:
            entry = _PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(entry)
            ctypes.set_last_error(0)
            if not api.scm.process32_first_w(snapshot, ctypes.byref(entry)):
                raise WindowsExactRuntimeProcessFenceError(
                    "Process32FirstW 无法枚举全机 process"
                )
            while True:
                pid = int(entry.th32ProcessID)
                executable_name = str(entry.szExeFile)
                if pid > 0 and executable_name.casefold() == "python.exe":
                    self._inspect_candidate(pid, matches)
                entry.dwSize = ctypes.sizeof(entry)
                ctypes.set_last_error(0)
                if api.scm.process32_next_w(snapshot, ctypes.byref(entry)):
                    continue
                if ctypes.get_last_error() != _ERROR_NO_MORE_FILES:
                    raise WindowsExactRuntimeProcessFenceError(
                        "Process32NextW 全机枚举发生漂移"
                    )
                break
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                api.close_handle(snapshot)
            except BaseException as close_error:
                if primary is None:
                    raise
                if isinstance(
                    close_error,
                    WindowsExactRuntimeProcessFenceOwnerCrashRequired,
                ):
                    raise close_error from primary
                raise
        return tuple(sorted(matches))

    def _inspect_candidate(
        self, pid: int, matches: list[tuple[int, int, str]]
    ) -> None:
        api = self._api
        raw_process = api.scm.open_process(
            _PROCESS_QUERY_LIMITED_INFORMATION | _SYNCHRONIZE,
            False,
            pid,
        )
        process = _handle(raw_process, label=f"python process {pid}")
        primary: BaseException | None = None
        try:
            probe = api.scm.query_process(process, pid)
            executable = PureWindowsPath(probe.executable_final_path)
            if executable != _CHILD_EXECUTABLE:
                return
            argv = api.argv(probe.command_line)
            if (
                len(argv) >= 9
                and PureWindowsPath(argv[0]) == _CHILD_EXECUTABLE
                and argv[1:6] == ("-I", "-B", "-X", "utf8", "-X")
                and argv[6].startswith(
                    "pycache_prefix="
                    + str(_PRODUCTION_ROOT / "tmp" / "service" / "pycache")
                    + "\\"
                )
                and argv[7:9] == ("-m", _ENTRY_MODULE)
            ):
                from .local_exact_runtime_entry import (
                    ExactRuntimeEntryError,
                    _parse_exact_argv,
                )
                from .local_steady_runtime_identity import (
                    ExactSteadyRuntimeIdentity,
                    ExactSteadyRuntimeIdentityError,
                    _parse_exact_steady_argv,
                )
                from .local_windows_writer_lease_holder import (
                    ExactRuntimeLeaseIdentity,
                    WindowsWriterLeaseHolderError,
                )

                closed = False
                try:
                    transient = ExactRuntimeLeaseIdentity(
                        **_parse_exact_argv(tuple(argv[9:]))
                    )
                    closed = transient.child_argv == argv
                except (
                    ExactRuntimeEntryError,
                    TypeError,
                    ValueError,
                    WindowsWriterLeaseHolderError,
                ):
                    pass
                if not closed:
                    try:
                        steady = ExactSteadyRuntimeIdentity(
                            **_parse_exact_steady_argv(tuple(argv[9:]))
                        )
                        closed = steady.child_argv == argv
                    except (
                        ExactSteadyRuntimeIdentityError,
                        TypeError,
                        ValueError,
                    ):
                        pass
                if not closed:
                    raise WindowsExactRuntimeProcessFenceError(
                        "exact D runtime process has a non-closed argv"
                    )
                if not probe.live:
                    raise WindowsExactRuntimeProcessFenceError(
                        "exact D runtime child 正在退出，absence 尚未成立"
                    )
                matches.append(
                    (pid, int(probe.creation_time_100ns), probe.command_line)
                )
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                api.close_handle(process)
            except BaseException as close_error:
                if primary is None:
                    raise
                if isinstance(
                    close_error,
                    WindowsExactRuntimeProcessFenceOwnerCrashRequired,
                ):
                    raise close_error from primary
                raise

    def _probe_writer_lock(self) -> str:
        api = self._api
        ctypes.set_last_error(0)
        raw = api.scm.create_file_w(
            str(_WRITER_LOCK),
            _GENERIC_READ | _GENERIC_WRITE,
            _FILE_SHARE_READ,
            None,
            _OPEN_ALWAYS,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        handle = _handle(raw, label="writer availability probe")
        primary: BaseException | None = None
        try:
            observed = api.scm.query_file(handle)
            if PureWindowsPath(observed.executable_final_path) != _WRITER_LOCK:
                raise WindowsExactRuntimeProcessFenceError(
                    "writer availability probe final path 漂移"
                )
            return identity_sha256(
                {
                    "schema_version": "qrh-writer-prelaunch-absence/v1",
                    "final_path": observed.executable_final_path,
                    "volume_identity_sha256": observed.volume_identity_sha256,
                    "file_identity_sha256": observed.file_identity_sha256,
                    "sharing": "GENERIC_READ|GENERIC_WRITE + FILE_SHARE_READ",
                }
            )
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                api.close_handle(handle)
            except BaseException as close_error:
                if primary is None:
                    raise
                if isinstance(
                    close_error,
                    WindowsExactRuntimeProcessFenceOwnerCrashRequired,
                ):
                    raise close_error from primary
                raise

    @staticmethod
    def _probe_listener_absence() -> str:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        primary: BaseException | None = None
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(("0.0.0.0", 8765))
            if listener.getsockname() != ("0.0.0.0", 8765):
                raise WindowsExactRuntimeProcessFenceError(
                    "production listener absence probe identity drifted"
                )
            return identity_sha256(
                {
                    "schema_version": "qrh-production-listener-absence/v1",
                    "local_address": "0.0.0.0",
                    "local_port": 8765,
                    "exclusive_bind": True,
                }
            )
        except OSError as error:
            primary = error
            raise WindowsExactRuntimeProcessFenceError(
                "production listener is not absent"
            ) from error
        finally:
            try:
                listener.close()
            except BaseException as close_error:
                if primary is None:
                    raise WindowsExactRuntimeProcessFenceOwnerCrashRequired(
                        "listener absence probe close outcome unknown"
                    ) from close_error
                raise WindowsExactRuntimeProcessFenceOwnerCrashRequired(
                    "listener absence probe failed and close is unknown"
                ) from close_error

    def assert_absent_before_launch(self, lifecycle: object) -> str:
        from .local_windows_job_child_launcher import (
            LockedServiceChildLaunchLifecycle,
        )

        if type(lifecycle) is not LockedServiceChildLaunchLifecycle:
            raise TypeError("process fence requires exact registered lifecycle")
        lifecycle._assert_owner("launching")  # noqa: SLF001
        before = self._snapshot()
        writer = self._probe_writer_lock()
        listener = self._probe_listener_absence()
        after = self._snapshot()
        if before != after or before:
            raise WindowsExactRuntimeProcessFenceError(
                "全机 old exact D runtime child absence 未闭合"
            )
        lifecycle._assert_owner("launching")  # noqa: SLF001
        return identity_sha256(
            {
                "schema_version": "qrh-exact-runtime-prelaunch-fence/v1",
                "process_snapshot": [],
                "writer_absence_sha256": writer,
                "listener_absence_sha256": listener,
            }
        )

    def assert_absent_after_termination(self, lifecycle: object) -> str:
        """Reprove machine-wide closure before a Job owner can release B2/SCM."""

        from .local_windows_job_child_launcher import (
            LockedServiceChildLaunchLifecycle,
        )

        if type(lifecycle) is not LockedServiceChildLaunchLifecycle:
            raise TypeError("post-termination fence requires exact lifecycle")
        if (
            lifecycle._owner_thread != threading.get_ident()  # noqa: SLF001
            or lifecycle._state  # noqa: SLF001
            not in {"launching", "live", "promoted", "transient_owned"}
        ):
            raise WindowsExactRuntimeProcessFenceError(
                "post-termination lifecycle owner/state drifted"
            )
        before = self._snapshot()
        writer = self._probe_writer_lock()
        listener = self._probe_listener_absence()
        after = self._snapshot()
        if before != after or before:
            raise WindowsExactRuntimeProcessFenceError(
                "post-termination exact D child absence is not closed"
            )
        return identity_sha256(
            {
                "schema_version": "qrh-exact-runtime-post-termination-fence/v1",
                "process_snapshot": [],
                "writer_absence_sha256": writer,
                "listener_absence_sha256": listener,
                "terminated_child_pid": lifecycle._process_id,  # noqa: SLF001
                "terminated_child_creation_time_100ns": lifecycle._child_creation_time_100ns,  # noqa: SLF001,E501
            }
        )


__all__ = [
    "ProductionWindowsExactRuntimeProcessFence",
    "WindowsExactRuntimeProcessFenceError",
    "WindowsExactRuntimeProcessFenceOwnerCrashRequired",
]
