"""Steady child 的匿名管道 admission gate 与不可重放状态机。"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import os
import re
import sys
import threading
from typing import Callable, Mapping

from .local_release_identity import canonical_bytes, identity_sha256
from .local_steady_runtime_identity import (
    ExactSteadyRuntimeIdentity,
    ExactSteadyRuntimeIdentityError,
    _parse_exact_steady_argv,
)


_GATE_TOKEN = object()
_TRANSIENT_GATE_TOKEN = object()
_CORE_TOKEN = object()
_PRODUCT_API_TOKEN = object()
_PREPARE_PREFIX = b"qrh-steady-admission-prepare/v1 "
_COMMIT_PREFIX = b"qrh-steady-admission-commit/v1 "
_SHA256_BYTES_RE = re.compile(rb"^[0-9a-f]{64}$")
_CHALLENGE_RE = re.compile(r"^[0-9a-f]{48}$")
_MAX_FRAME_BYTES = 256
_FILE_TYPE_PIPE = 0x0003
_ERROR_BROKEN_PIPE = 109
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_FATAL_EXIT_CODE = 0xE0440001
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


class ExactRuntimeAdmissionError(RuntimeError):
    """Admission 管道、现场身份或状态序列不闭合。"""


class _FILETIME(ctypes.Structure):
    _fields_ = (("low", wintypes.DWORD), ("high", wintypes.DWORD))


class _PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2_0", ctypes.c_void_p),
        ("Reserved2_1", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    )


def _filetime(value: _FILETIME) -> int:
    result = (int(value.high) << 32) | int(value.low)
    if result <= 0:
        raise ExactRuntimeAdmissionError("process creation time 无效")
    return result


class _ProductionAdmissionApi:
    __slots__ = (
        "_kernel32",
        "_ntdll",
        "ReadFile",
        "GetFileType",
        "GetCurrentProcess",
        "GetCurrentProcessId",
        "OpenProcess",
        "GetProcessTimes",
        "CloseHandle",
        "IsProcessInJob",
        "TerminateProcess",
        "NtQueryInformationProcess",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production admission API table 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production admission API table 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, token: object) -> None:
        if token is not _PRODUCT_API_TOKEN or os.name != "nt":
            raise TypeError("production admission API provenance 无效")
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
        self.ReadFile = kernel32.ReadFile
        self.ReadFile.argtypes = (
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        )
        self.ReadFile.restype = wintypes.BOOL
        self.GetFileType = kernel32.GetFileType
        self.GetFileType.argtypes = (wintypes.HANDLE,)
        self.GetFileType.restype = wintypes.DWORD
        self.GetCurrentProcess = kernel32.GetCurrentProcess
        self.GetCurrentProcess.argtypes = ()
        self.GetCurrentProcess.restype = wintypes.HANDLE
        self.GetCurrentProcessId = kernel32.GetCurrentProcessId
        self.GetCurrentProcessId.argtypes = ()
        self.GetCurrentProcessId.restype = wintypes.DWORD
        self.OpenProcess = kernel32.OpenProcess
        self.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        self.OpenProcess.restype = wintypes.HANDLE
        self.GetProcessTimes = kernel32.GetProcessTimes
        self.GetProcessTimes.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
            ctypes.POINTER(_FILETIME),
        )
        self.GetProcessTimes.restype = wintypes.BOOL
        self.CloseHandle = kernel32.CloseHandle
        self.CloseHandle.argtypes = (wintypes.HANDLE,)
        self.CloseHandle.restype = wintypes.BOOL
        self.IsProcessInJob = kernel32.IsProcessInJob
        self.IsProcessInJob.argtypes = (
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.BOOL),
        )
        self.IsProcessInJob.restype = wintypes.BOOL
        self.TerminateProcess = kernel32.TerminateProcess
        self.TerminateProcess.argtypes = (wintypes.HANDLE, wintypes.UINT)
        self.TerminateProcess.restype = wintypes.BOOL
        self.NtQueryInformationProcess = ntdll.NtQueryInformationProcess
        self.NtQueryInformationProcess.argtypes = (
            wintypes.HANDLE,
            wintypes.ULONG,
            wintypes.LPVOID,
            wintypes.ULONG,
            ctypes.POINTER(wintypes.ULONG),
        )
        self.NtQueryInformationProcess.restype = wintypes.LONG
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "_ProductionAdmissionApi":
        return cls(token=_PRODUCT_API_TOKEN)

    def assert_exact(self) -> None:
        if type(self) is not _ProductionAdmissionApi or not self._sealed:
            raise ExactRuntimeAdmissionError("production admission API 漂移")


def _creation_time(api: _ProductionAdmissionApi, handle: int) -> int:
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
        raise ExactRuntimeAdmissionError("无法查询 process creation time")
    return _filetime(creation)


def _live_process_identity(api: _ProductionAdmissionApi) -> dict[str, int]:
    api.assert_exact()
    current_handle = int(api.GetCurrentProcess())
    current_pid = int(api.GetCurrentProcessId())
    if current_pid <= 0:
        raise ExactRuntimeAdmissionError("current PID 无效")
    basic = _PROCESS_BASIC_INFORMATION()
    returned = wintypes.ULONG()
    status = int(
        api.NtQueryInformationProcess(
            wintypes.HANDLE(current_handle),
            wintypes.ULONG(0),
            ctypes.byref(basic),
            wintypes.ULONG(ctypes.sizeof(basic)),
            ctypes.byref(returned),
        )
    )
    parent_pid = int(basic.InheritedFromUniqueProcessId or 0)
    if status != 0 or parent_pid <= 0 or parent_pid == current_pid:
        raise ExactRuntimeAdmissionError("SCM host parent identity 不可用")
    parent_raw = api.OpenProcess(
        _PROCESS_QUERY_LIMITED_INFORMATION, False, parent_pid
    )
    parent_handle = int(parent_raw or 0)
    if parent_handle <= 0:
        raise ExactRuntimeAdmissionError("无法打开 SCM host process")
    in_job = wintypes.BOOL()
    try:
        child_creation = _creation_time(api, current_handle)
        parent_creation = _creation_time(api, parent_handle)
        if not api.IsProcessInJob(
            wintypes.HANDLE(current_handle),
            wintypes.HANDLE(0),
            ctypes.byref(in_job),
        ) or not bool(in_job.value):
            raise ExactRuntimeAdmissionError("steady child 未观察到 Job membership")
    finally:
        if not api.CloseHandle(wintypes.HANDLE(parent_handle)):
            raise ExactRuntimeAdmissionError("SCM host process handle close 失败")
    if child_creation < parent_creation:
        raise ExactRuntimeAdmissionError("steady child creation time 早于 SCM host")
    return {
        "host_pid": parent_pid,
        "host_creation_time_100ns": parent_creation,
        "child_pid": current_pid,
        "child_creation_time_100ns": child_creation,
    }


class _AdmissionStateCore:
    __slots__ = (
        "_admission_binding_sha256",
        "_job_identity_sha256",
        "_state",
        "_ready_ack_binding_sha256",
        "_fatal",
        "_lock",
        "_sealed",
    )

    def __init__(
        self,
        admission_binding_sha256: str,
        job_identity_sha256: str,
        fatal: Callable[[str], None],
        *,
        token: object,
    ) -> None:
        if token is not _CORE_TOKEN or not callable(fatal):
            raise TypeError("admission state core provenance 无效")
        if (
            type(admission_binding_sha256) is not str
            or _SHA256_BYTES_RE.fullmatch(admission_binding_sha256.encode("ascii")) is None
            or type(job_identity_sha256) is not str
            or _SHA256_BYTES_RE.fullmatch(job_identity_sha256.encode("ascii")) is None
        ):
            raise ExactRuntimeAdmissionError("admission identity hash 无效")
        self._sealed = False
        self._admission_binding_sha256 = admission_binding_sha256
        self._job_identity_sha256 = job_identity_sha256
        self._state = "closed_pending_promotion"
        self._ready_ack_binding_sha256: str | None = None
        self._fatal = fatal
        self._lock = threading.RLock()
        self._sealed = True

    @property
    def state(self) -> str:
        with self._lock:
            return self._state

    @property
    def ready_ack_binding_sha256(self) -> str | None:
        with self._lock:
            return self._ready_ack_binding_sha256

    def accept_prepare(self, binding: bytes) -> None:
        with self._lock:
            if (
                self._state != "closed_pending_promotion"
                or binding.decode("ascii", errors="strict")
                != self._admission_binding_sha256
            ):
                self._fatal("admission PREPARE 次序或 binding 不匹配")
                return
            self._state = "ack_pending"

    def acknowledge_ready(self, challenge: str) -> str:
        with self._lock:
            if (
                self._state != "ack_pending"
                or self._ready_ack_binding_sha256 is not None
                or type(challenge) is not str
                or _CHALLENGE_RE.fullmatch(challenge) is None
            ):
                raise ExactRuntimeAdmissionError("readiness acknowledgement 不可派生")
            value = identity_sha256(
                {
                    "schema_version": "qrh-steady-ready-ack-binding/v1",
                    "admission_binding_sha256": self._admission_binding_sha256,
                    "job_identity_sha256": self._job_identity_sha256,
                    "challenge": challenge,
                    "state": "ack_pending",
                }
            )
            self._ready_ack_binding_sha256 = value
            return value

    def accept_commit(self, binding: bytes, ready_ack: bytes) -> None:
        with self._lock:
            expected_ready = self._ready_ack_binding_sha256
            if (
                self._state != "ack_pending"
                or expected_ready is None
                or binding.decode("ascii", errors="strict")
                != self._admission_binding_sha256
                or ready_ack.decode("ascii", errors="strict") != expected_ready
            ):
                self._fatal("admission COMMIT 次序或 binding 不匹配")
                return
            self._state = "commit_received_waiting_eof"

    def accept_eof(self) -> None:
        with self._lock:
            if self._state != "commit_received_waiting_eof":
                self._fatal("admission EOF 早于 exact COMMIT")
                return
            self._state = "admitted"


class _PipeFrameReader:
    __slots__ = ("_read_chunk", "_pending")

    def __init__(self, read_chunk: Callable[[], bytes]) -> None:
        self._read_chunk = read_chunk
        self._pending = bytearray()

    def read_frame(self) -> bytes | None:
        while True:
            newline = self._pending.find(b"\n")
            if newline >= 0:
                frame = bytes(self._pending[:newline])
                del self._pending[: newline + 1]
                if not frame or len(frame) > _MAX_FRAME_BYTES:
                    raise ExactRuntimeAdmissionError("admission frame 长度无效")
                return frame
            if len(self._pending) > _MAX_FRAME_BYTES:
                raise ExactRuntimeAdmissionError("admission frame 超过固定上限")
            chunk = self._read_chunk()
            if type(chunk) is not bytes:
                raise ExactRuntimeAdmissionError("admission pipe reader 类型漂移")
            if not chunk:
                if self._pending:
                    raise ExactRuntimeAdmissionError("admission pipe 出现截断 frame")
                return None
            self._pending.extend(chunk)


def _run_protocol(reader: _PipeFrameReader, core: _AdmissionStateCore) -> None:
    first = reader.read_frame()
    if first is None or not first.startswith(_PREPARE_PREFIX):
        raise ExactRuntimeAdmissionError("admission 首帧不是 PREPARE")
    prepare_binding = first[len(_PREPARE_PREFIX) :]
    if _SHA256_BYTES_RE.fullmatch(prepare_binding) is None:
        raise ExactRuntimeAdmissionError("admission PREPARE binding 无效")
    core.accept_prepare(prepare_binding)
    second = reader.read_frame()
    if second is None or not second.startswith(_COMMIT_PREFIX):
        raise ExactRuntimeAdmissionError("admission 第二帧不是 COMMIT")
    parts = second[len(_COMMIT_PREFIX) :].split(b" ")
    if len(parts) != 2 or any(_SHA256_BYTES_RE.fullmatch(part) is None for part in parts):
        raise ExactRuntimeAdmissionError("admission COMMIT binding 无效")
    core.accept_commit(parts[0], parts[1])
    if reader.read_frame() is not None:
        raise ExactRuntimeAdmissionError("admission COMMIT 后存在额外 frame")
    core.accept_eof()


class LockedTransientRuntimeAdmissionGate:
    """Transient child gate: permanently closed and incapable of PREPARE/COMMIT."""

    __slots__ = (
        "_identity",
        "_process_identity",
        "_job_identity_sha256",
        "_admission_binding_sha256",
        "_thread",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("transient runtime admission gate cannot be subclassed")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("transient runtime admission gate is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        identity: "ExactRuntimeLeaseIdentity",
        process_identity: Mapping[str, int],
        reader: _PipeFrameReader,
        fatal: Callable[[str], None],
        *,
        token: object,
    ) -> None:
        from .local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity

        if (
            token is not _TRANSIENT_GATE_TOKEN
            or type(identity) is not ExactRuntimeLeaseIdentity
            or not callable(fatal)
        ):
            raise TypeError("transient runtime admission gate provenance is invalid")
        object.__setattr__(self, "_sealed", False)
        self._identity = identity
        self._process_identity = dict(process_identity)
        self._job_identity_sha256 = identity_sha256(
            {
                "schema_version": "qrh-transient-service-job-identity/v1",
                "attempt": identity.attempt_id,
                "nonce": identity.nonce,
                "role": identity.role,
                "start_nonce": identity.start_nonce,
                "scm_identity_sha256": identity.scm_identity_sha256,
                **self._process_identity,
            }
        )
        self._admission_binding_sha256 = identity_sha256(
            {
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
                "job_identity_sha256": self._job_identity_sha256,
            }
        )

        def run() -> None:
            try:
                frame = reader.read_frame()
                fatal(
                    "transient admission pipe reached EOF"
                    if frame is None
                    else "transient admission pipe received forbidden bytes"
                )
            except BaseException as error:
                fatal(f"transient admission reader fatal: {type(error).__name__}")

        self._thread = threading.Thread(
            target=run,
            name="qrh-transient-admission-reader",
            daemon=True,
        )
        self._thread.start()
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("transient runtime admission gate is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def state(self) -> str:
        return "closed_pending_promotion"

    @property
    def job_identity_sha256(self) -> str:
        return self._job_identity_sha256

    @property
    def admission_binding_sha256(self) -> str:
        return self._admission_binding_sha256

    def identity_claim(self) -> Mapping[str, object]:
        return {
            "job_identity_sha256": self._job_identity_sha256,
            "admission_binding_sha256": self._admission_binding_sha256,
            "admission_state": "closed_pending_promotion",
            "authority": "claim_not_independently_observed",
        }


class LockedExactRuntimeAdmissionGate:
    """Child process-local gate；HTTP 只能读取状态或登记一次 ready ack。"""

    __slots__ = (
        "_identity",
        "_process_identity",
        "_job_identity_sha256",
        "_admission_binding_sha256",
        "_core",
        "_thread",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("exact runtime admission gate 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("exact runtime admission gate 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        identity: ExactSteadyRuntimeIdentity,
        process_identity: Mapping[str, int],
        reader: _PipeFrameReader,
        fatal: Callable[[str], None],
        *,
        token: object,
    ) -> None:
        if token is not _GATE_TOKEN or type(identity) is not ExactSteadyRuntimeIdentity:
            raise TypeError("exact runtime admission gate provenance 无效")
        object.__setattr__(self, "_sealed", False)
        self._identity = identity
        self._process_identity = dict(process_identity)
        self._job_identity_sha256 = identity_sha256(
            {
                "schema_version": "qrh-steady-service-job-identity/v1",
                "boot_nonce": identity.boot_nonce,
                "scm_identity_sha256": identity.scm_identity_sha256,
                **self._process_identity,
            }
        )
        self._admission_binding_sha256 = identity_sha256(
            {
                "schema_version": "qrh-steady-admission-binding/v1",
                "boot_nonce": identity.boot_nonce,
                "state_identity_sha256": identity.state_identity_sha256,
                "release": dict(identity.release_ref),
                "job_identity_sha256": self._job_identity_sha256,
            }
        )
        self._core = _AdmissionStateCore(
            self._admission_binding_sha256,
            self._job_identity_sha256,
            fatal,
            token=_CORE_TOKEN,
        )

        def run() -> None:
            try:
                _run_protocol(reader, self._core)
            except BaseException as error:
                fatal(f"admission reader fatal: {type(error).__name__}")

        self._thread = threading.Thread(
            target=run,
            name="qrh-steady-admission-reader",
            daemon=True,
        )
        self._thread.start()
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("exact runtime admission gate is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def state(self) -> str:
        return self._core.state

    @property
    def job_identity_sha256(self) -> str:
        return self._job_identity_sha256

    @property
    def admission_binding_sha256(self) -> str:
        return self._admission_binding_sha256

    def acknowledge_ready(self, challenge: str) -> str:
        return self._core.acknowledge_ready(challenge)

    def identity_claim(self) -> Mapping[str, object]:
        return {
            "job_identity_sha256": self._job_identity_sha256,
            "admission_binding_sha256": self._admission_binding_sha256,
            "admission_state": self.state,
            "authority": "claim_not_independently_observed",
        }


class ProductionTransientRuntimeAdmissionGate:
    """Zero-argument loader for the inherited transient admission read pipe."""

    __slots__ = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production transient admission loader cannot be subclassed")

    @classmethod
    def load_from_service_stdin(cls) -> LockedTransientRuntimeAdmissionGate:
        if os.name != "nt":
            raise ExactRuntimeAdmissionError(
                "production transient admission gate requires Windows"
            )
        from .local_exact_runtime_entry import ExactRuntimeEntryError, _parse_exact_argv
        from .local_windows_writer_lease_holder import (
            ExactRuntimeLeaseIdentity,
            WindowsWriterLeaseHolderError,
        )

        try:
            values = _parse_exact_argv(tuple(sys.argv[1:]))
            identity = ExactRuntimeLeaseIdentity(**values)
        except (
            ExactRuntimeEntryError,
            TypeError,
            ValueError,
            WindowsWriterLeaseHolderError,
        ) as error:
            raise ExactRuntimeAdmissionError(
                "transient child argv is not closed"
            ) from error
        api = _ProductionAdmissionApi.load_exact_d()
        try:
            import msvcrt

            pipe_handle = int(msvcrt.get_osfhandle(sys.stdin.fileno()))
        except (ImportError, OSError, ValueError) as error:
            raise ExactRuntimeAdmissionError(
                "transient service stdin pipe is unavailable"
            ) from error
        if (
            pipe_handle <= 0
            or int(api.GetFileType(wintypes.HANDLE(pipe_handle))) != _FILE_TYPE_PIPE
        ):
            raise ExactRuntimeAdmissionError(
                "transient service stdin is not an anonymous pipe"
            )
        process_identity = _live_process_identity(api)

        def read_chunk() -> bytes:
            buffer = ctypes.create_string_buffer(512)
            read = wintypes.DWORD()
            ctypes.set_last_error(0)
            ok = api.ReadFile(
                wintypes.HANDLE(pipe_handle),
                buffer,
                wintypes.DWORD(len(buffer)),
                ctypes.byref(read),
                None,
            )
            if not ok:
                error = ctypes.get_last_error()
                if error == _ERROR_BROKEN_PIPE:
                    return b""
                raise ExactRuntimeAdmissionError(
                    f"transient admission ReadFile failed: Windows error {error}"
                )
            return bytes(buffer.raw[: int(read.value)])

        def fatal(_reason: str) -> None:
            current = api.GetCurrentProcess()
            if not api.TerminateProcess(current, _FATAL_EXIT_CODE):
                os._exit(97)

        return LockedTransientRuntimeAdmissionGate(
            identity,
            process_identity,
            _PipeFrameReader(read_chunk),
            fatal,
            token=_TRANSIENT_GATE_TOKEN,
        )


class ProductionExactRuntimeAdmissionGate:
    """无参产品 loader：只消费 exact argv、当前 Job 现场和继承 stdin pipe。"""

    __slots__ = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production admission gate loader 不允许派生")

    @classmethod
    def load_from_service_stdin(cls) -> LockedExactRuntimeAdmissionGate:
        if os.name != "nt":
            raise ExactRuntimeAdmissionError("production admission gate 只允许 Windows")
        try:
            parsed = _parse_exact_steady_argv(tuple(sys.argv[1:]))
            identity = ExactSteadyRuntimeIdentity(**parsed)
        except (ExactSteadyRuntimeIdentityError, TypeError, ValueError) as error:
            raise ExactRuntimeAdmissionError("steady child argv 不闭合") from error
        api = _ProductionAdmissionApi.load_exact_d()
        try:
            import msvcrt

            pipe_handle = int(msvcrt.get_osfhandle(sys.stdin.fileno()))
        except (ImportError, OSError, ValueError) as error:
            raise ExactRuntimeAdmissionError("service stdin pipe 不可用") from error
        if pipe_handle <= 0 or int(api.GetFileType(wintypes.HANDLE(pipe_handle))) != _FILE_TYPE_PIPE:
            raise ExactRuntimeAdmissionError("service stdin 不是 anonymous pipe")
        process_identity = _live_process_identity(api)

        def read_chunk() -> bytes:
            buffer = ctypes.create_string_buffer(512)
            read = wintypes.DWORD()
            ctypes.set_last_error(0)
            ok = api.ReadFile(
                wintypes.HANDLE(pipe_handle),
                buffer,
                wintypes.DWORD(len(buffer)),
                ctypes.byref(read),
                None,
            )
            if not ok:
                error = ctypes.get_last_error()
                if error == _ERROR_BROKEN_PIPE:
                    return b""
                raise ExactRuntimeAdmissionError(
                    f"admission ReadFile failed: Windows error {error}"
                )
            return bytes(buffer.raw[: int(read.value)])

        def fatal(_reason: str) -> None:
            current = api.GetCurrentProcess()
            if not api.TerminateProcess(current, _FATAL_EXIT_CODE):
                os._exit(97)

        return LockedExactRuntimeAdmissionGate(
            identity,
            process_identity,
            _PipeFrameReader(read_chunk),
            fatal,
            token=_GATE_TOKEN,
        )


def build_prepare_frame(admission_binding_sha256: str) -> bytes:
    """Service-lifetime owner 使用的固定 PREPARE 编码；返回值本身无发送权限。"""

    raw = admission_binding_sha256.encode("ascii", errors="strict")
    if _SHA256_BYTES_RE.fullmatch(raw) is None:
        raise ExactRuntimeAdmissionError("PREPARE binding 无效")
    return _PREPARE_PREFIX + raw + b"\n"


def build_commit_frame(
    admission_binding_sha256: str, ready_ack_binding_sha256: str
) -> bytes:
    """Service-lifetime owner 使用的固定 COMMIT 编码；返回值本身无发送权限。"""

    binding = admission_binding_sha256.encode("ascii", errors="strict")
    ready = ready_ack_binding_sha256.encode("ascii", errors="strict")
    if any(_SHA256_BYTES_RE.fullmatch(value) is None for value in (binding, ready)):
        raise ExactRuntimeAdmissionError("COMMIT binding 无效")
    return _COMMIT_PREFIX + binding + b" " + ready + b"\n"


__all__ = [
    "ExactRuntimeAdmissionError",
    "LockedExactRuntimeAdmissionGate",
    "LockedTransientRuntimeAdmissionGate",
    "ProductionExactRuntimeAdmissionGate",
    "ProductionTransientRuntimeAdmissionGate",
    "build_commit_frame",
    "build_prepare_frame",
]
