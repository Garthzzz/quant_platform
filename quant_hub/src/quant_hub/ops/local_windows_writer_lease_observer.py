"""精确 D 根 Windows writer lease 的控制侧现场观察器。

产品入口只接受同一条 live SCM/process 与 endpoint capability。它读取固定租约记录，
从已观察 child 进程 ``DuplicateHandle`` 出记录中的锁 handle，核验精确 D 文件身份，
关闭副本后再证明冲突 writer open 得到 ``ERROR_SHARING_VIOLATION``。结果仍是
observation-only；canary 与 formal deployment qualification 属于后续 gate。
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import PureWindowsPath
from typing import Mapping

from .local_deployment_persistence import (
    LocalDeploymentPersistenceError,
    LockedWindowsSteadyWriterLeaseHandleTracking,
    LockedWindowsWriterLeaseHandleTracking,
)
from .local_release_identity import canonical_bytes, identity_sha256
from .local_windows_endpoint_evidence import WindowsEndpointObservationEvidence
from .local_windows_endpoint_observer import (
    LockedSteadyWindowsEndpointObservation,
    LockedWindowsEndpointObservation,
)
from .local_windows_scm_process_evidence import WindowsScmProcessObservationEvidence
from .local_windows_scm_process_observer import (
    LockedSteadyWindowsScmProcessObservation,
    LockedWindowsScmProcessObservation,
)
from .local_steady_windows_endpoint_evidence import (
    SteadyWindowsEndpointObservationEvidence,
)
from .local_steady_windows_scm_process_evidence import (
    SteadyWindowsScmProcessObservationEvidence,
)
from .local_steady_windows_writer_lease_evidence import (
    STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA,
    STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE,
    SteadyWindowsWriterLeaseObservationEvidence,
    validate_steady_writer_lease_record,
)
from .local_windows_writer_lease_evidence import (
    WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA,
    WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE,
    WRITER_LEASE_RECORD_FINAL_PATH,
    WRITER_LOCK_FINAL_PATH,
    WindowsWriterLeaseEvidenceError,
    WindowsWriterLeaseObservationEvidence,
    validate_writer_lease_record,
)


LIVE_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE = (
    "live_windows_writer_lease_observation_not_canary_qualified"
)
LIVE_STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE = (
    "live_steady_windows_writer_lease_observation_not_admission_qualified"
)

_WriterTracking = (
    LockedWindowsWriterLeaseHandleTracking
    | LockedWindowsSteadyWriterLeaseHandleTracking
)

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_ID_INFO_CLASS = 18
_FILE_STANDARD_INFO_CLASS = 1
_FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
_ERROR_SHARING_VIOLATION = 32
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800
_MAX_RECORD_BYTES = 64 * 1024

_API_TOKEN = object()
_OBSERVER_TOKEN = object()
_LIVE_TOKEN = object()


class WindowsWriterLeaseObserverError(RuntimeError):
    """writer lease 现场观察没有机械闭合。"""


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
class _FileObservation:
    final_path: str
    volume_serial_number: int
    file_id: str
    size: int


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
        raise WindowsWriterLeaseObserverError(
            f"Windows API binding 缺失或签名不可固定: {name}"
        ) from error
    return function


def _normal_final_path(value: object) -> str:
    if type(value) is not str or not value:
        raise WindowsWriterLeaseObserverError("Windows final path 为空")
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return str(PureWindowsPath(value))


def _exact_positive(value: object, *, label: str) -> int:
    if type(value) is not int or value < 1:
        raise WindowsWriterLeaseObserverError(f"{label} 必须是 exact positive int")
    return value


class _ProductionWindowsWriterLeaseObserverApi:
    """固定 System32 kernel32 table；不接受 caller DLL/function 注入。"""

    __slots__ = (
        "_binding_token",
        "_sealed",
        "create_file_w",
        "read_file",
        "get_final_path_name_by_handle_w",
        "get_file_information_by_handle_ex",
        "duplicate_handle",
        "get_current_process",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production writer observer API table 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production writer observer API table 构造后不可替换")
        object.__setattr__(self, name, value)

    def _assert_exact_binding(self) -> None:
        if (
            type(self) is not _ProductionWindowsWriterLeaseObserverApi
            or getattr(self, "_binding_token", None) is not _API_TOKEN
            or getattr(self, "_sealed", None) is not True
        ):
            raise WindowsWriterLeaseObserverError(
                "production writer observer API table 来源未闭合"
            )

    @classmethod
    def load_exact_d(cls) -> "_ProductionWindowsWriterLeaseObserverApi":
        if os.name != "nt":
            raise WindowsWriterLeaseObserverError(
                "production writer lease observer 只允许 Windows"
            )
        try:
            kernel32 = ctypes.WinDLL(
                "kernel32.dll",
                use_last_error=True,
                winmode=_LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        except OSError as error:
            raise WindowsWriterLeaseObserverError(
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
        self.duplicate_handle = _bind(
            kernel32,
            "DuplicateHandle",
            (
                wintypes.HANDLE,
                wintypes.HANDLE,
                wintypes.HANDLE,
                ctypes.POINTER(wintypes.HANDLE),
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ),
            wintypes.BOOL,
        )
        self.get_current_process = _bind(
            kernel32, "GetCurrentProcess", (), wintypes.HANDLE
        )
        object.__setattr__(self, "_binding_token", _API_TOKEN)
        object.__setattr__(self, "_sealed", True)
        self._assert_exact_binding()
        return self


def _query_file(
    api: _ProductionWindowsWriterLeaseObserverApi,
    handle: int,
    *,
    expected_path: str,
) -> _FileObservation:
    buffer = ctypes.create_unicode_buffer(32768)
    length = api.get_final_path_name_by_handle_w(handle, buffer, len(buffer), 0)
    if type(length) is not int or length < 1 or length >= len(buffer):
        raise WindowsWriterLeaseObserverError(
            "GetFinalPathNameByHandleW 未返回闭合路径"
        )
    final_path = _normal_final_path(buffer.value)
    if PureWindowsPath(final_path) != PureWindowsPath(expected_path):
        raise WindowsWriterLeaseObserverError("observed file final path 漂移")
    file_id = _FILE_ID_INFO()
    standard = _FILE_STANDARD_INFO()
    attributes = _FILE_ATTRIBUTE_TAG_INFO()
    for info_class, output in (
        (_FILE_ID_INFO_CLASS, file_id),
        (_FILE_STANDARD_INFO_CLASS, standard),
        (_FILE_ATTRIBUTE_TAG_INFO_CLASS, attributes),
    ):
        if not api.get_file_information_by_handle_ex(
            handle, info_class, ctypes.byref(output), ctypes.sizeof(output)
        ):
            raise WindowsWriterLeaseObserverError(
                "GetFileInformationByHandleEx failed"
            )
    if (
        type(standard.NumberOfLinks) is not int
        or standard.NumberOfLinks != 1
        or bool(standard.DeletePending)
        or bool(standard.Directory)
        or int(attributes.FileAttributes) & _FILE_ATTRIBUTE_REPARSE_POINT
        or int(standard.EndOfFile) < 0
    ):
        raise WindowsWriterLeaseObserverError(
            "observed file 不是单链接、非 reparse 普通文件"
        )
    volume = int(file_id.VolumeSerialNumber)
    identifier = bytes(file_id.FileId.Identifier).hex()
    if volume < 1 or len(identifier) != 32:
        raise WindowsWriterLeaseObserverError("observed file identity 无效")
    return _FileObservation(
        final_path=final_path,
        volume_serial_number=volume,
        file_id=identifier,
        size=int(standard.EndOfFile),
    )


def _strict_json(raw: bytes) -> dict[str, object]:
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise WindowsWriterLeaseObserverError(
                    "writer lease record 含 duplicate JSON key"
                )
            result[key] = value
        return result

    def reject_constant(value: str) -> object:
        raise WindowsWriterLeaseObserverError(
            f"writer lease record 含非有限常量: {value}"
        )

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WindowsWriterLeaseObserverError(
            "writer lease record 不是严格 UTF-8 JSON"
        ) from error
    if type(value) is not dict or canonical_bytes(value) != raw:
        raise WindowsWriterLeaseObserverError(
            "writer lease record 不是 exact canonical object"
        )
    return value


def _read_record(
    api: _ProductionWindowsWriterLeaseObserverApi,
    tracking: _WriterTracking,
    *,
    slot_label: str,
) -> dict[str, object]:
    tracking._capture_reusable_returned_handle(
        slot_label,
        api.create_file_w,
        WRITER_LEASE_RECORD_FINAL_PATH,
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_ATTRIBUTE_NORMAL
        | _FILE_FLAG_OPEN_REPARSE_POINT
        | _FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    handle = tracking._borrow_handle(slot_label)
    primary: BaseException | None = None
    try:
        before = _query_file(
            api, handle, expected_path=WRITER_LEASE_RECORD_FINAL_PATH
        )
        if before.size < 1 or before.size > _MAX_RECORD_BYTES:
            raise WindowsWriterLeaseObserverError(
                "writer lease record size 超出闭合集"
            )
        remaining = before.size
        chunks: list[bytes] = []
        while remaining:
            size = min(remaining, 16 * 1024)
            buffer = ctypes.create_string_buffer(size)
            read = wintypes.DWORD()
            if not api.read_file(
                handle, buffer, size, ctypes.byref(read), None
            ):
                raise WindowsWriterLeaseObserverError("ReadFile(record) failed")
            count = int(read.value)
            if count < 1 or count > size:
                raise WindowsWriterLeaseObserverError(
                    "ReadFile(record) 长度/EOF 不闭合"
                )
            chunks.append(buffer.raw[:count])
            remaining -= count
        after = _query_file(
            api, handle, expected_path=WRITER_LEASE_RECORD_FINAL_PATH
        )
        if after != before:
            raise WindowsWriterLeaseObserverError(
                "writer lease record 读取期间漂移"
            )
        return _strict_json(b"".join(chunks))
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            tracking._release_reusable_handle(slot_label)
        except BaseException as close_error:
            if primary is None:
                raise
            raise WindowsWriterLeaseObserverError(
                "writer lease record 读取失败且 handle close 不可闭合"
            ) from close_error


def _endpoint_stable_identity(
    evidence: WindowsEndpointObservationEvidence,
) -> dict[str, object]:
    document = evidence.as_dict()
    probe = document.get("probe")
    if type(probe) is not dict:
        raise WindowsWriterLeaseObserverError("endpoint probe 结构漂移")
    response = probe.get("response")
    if type(response) is not dict:
        raise WindowsWriterLeaseObserverError("endpoint response 结构漂移")
    lease = response.get("writer_lease")
    if type(lease) is not dict:
        raise WindowsWriterLeaseObserverError("endpoint lease claim 结构漂移")
    return {
        "scm_process_evidence_sha256": document.get(
            "scm_process_evidence_sha256"
        ),
        "attempt_id": document.get("attempt_id"),
        "nonce": document.get("nonce"),
        "operation": document.get("operation"),
        "role": document.get("role"),
        "start_nonce": document.get("start_nonce"),
        "state_identity_sha256": document.get("state_identity_sha256"),
        "release": document.get("release"),
        "listener_before": document.get("listener_before"),
        "listener_after": document.get("listener_after"),
        "writer_lease": lease,
    }


def _steady_endpoint_stable_identity(
    evidence: SteadyWindowsEndpointObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not SteadyWindowsEndpointObservationEvidence:
        raise WindowsWriterLeaseObserverError(
            "steady endpoint evidence 类型漂移"
        )
    document = evidence.as_dict()
    probe = document.get("probe")
    if type(probe) is not dict:
        raise WindowsWriterLeaseObserverError("steady endpoint probe 结构漂移")
    response = probe.get("response")
    if type(response) is not dict:
        raise WindowsWriterLeaseObserverError(
            "steady endpoint response 结构漂移"
        )
    lease = response.get("writer_lease")
    if type(lease) is not dict:
        raise WindowsWriterLeaseObserverError(
            "steady endpoint lease claim 结构漂移"
        )
    return {
        field: document.get(field)
        for field in (
            "scm_process_evidence_sha256",
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
            "release",
            "listener_before",
            "listener_after",
        )
    } | {
        "writer_lease": lease,
        "job_identity_sha256": response.get("job_identity_sha256"),
        "admission_binding_sha256": response.get(
            "admission_binding_sha256"
        ),
        "admission_state": response.get("admission_state"),
    }


@dataclass(frozen=True, slots=True)
class _CollectedWriterLeaseObservation:
    scm_evidence: WindowsScmProcessObservationEvidence
    endpoint_evidence: WindowsEndpointObservationEvidence
    lease_record: Mapping[str, object]
    kernel_observation: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _CollectedSteadyWriterLeaseObservation:
    scm_evidence: SteadyWindowsScmProcessObservationEvidence
    endpoint_evidence: SteadyWindowsEndpointObservationEvidence
    lease_record: Mapping[str, object]
    kernel_observation: Mapping[str, object]


def _build_evidence_document(
    collected: _CollectedWriterLeaseObservation,
    *,
    _authority_token: object,
) -> dict[str, object]:
    if _authority_token is not _API_TOKEN:
        raise WindowsWriterLeaseObserverError(
            "writer lease evidence finalizer authority 不匹配"
        )
    scm = collected.scm_evidence.as_dict()
    endpoint = collected.endpoint_evidence.as_dict()
    record = dict(collected.lease_record)
    kernel = dict(collected.kernel_observation)
    document: dict[str, object] = {
        "schema_version": WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA,
        "evidence_scope": WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE,
        "scm_process_evidence_sha256": scm["evidence_sha256"],
        "endpoint_evidence_sha256": endpoint["evidence_sha256"],
        "attempt_id": scm["attempt_id"],
        "nonce": scm["nonce"],
        "operation": scm["operation"],
        "role": scm["role"],
        "start_nonce": scm["start_nonce"],
        "state_identity_sha256": scm["state_identity_sha256"],
        "release": scm["release"],
        "lease_record": record,
        "kernel_lock_observation": kernel,
        "observation_aggregate_sha256": identity_sha256(
            [
                {"name": "scm_process", "sha256": scm["evidence_sha256"]},
                {"name": "endpoint", "sha256": endpoint["evidence_sha256"]},
                {
                    "name": "lease_record",
                    "sha256": record["lease_record_sha256"],
                },
                {
                    "name": "kernel_lock",
                    "sha256": kernel["kernel_observation_sha256"],
                },
            ]
        ),
        "result": "writer_lease_observed_not_canary_qualified",
    }
    document["evidence_sha256"] = identity_sha256(document)
    return document


def _build_steady_evidence_document(
    collected: _CollectedSteadyWriterLeaseObservation,
    *,
    _authority_token: object,
) -> dict[str, object]:
    if _authority_token is not _API_TOKEN:
        raise WindowsWriterLeaseObserverError(
            "steady writer evidence finalizer authority 不匹配"
        )
    scm = collected.scm_evidence.as_dict()
    endpoint = collected.endpoint_evidence.as_dict()
    record = dict(collected.lease_record)
    kernel = dict(collected.kernel_observation)
    document: dict[str, object] = {
        "schema_version": STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCHEMA,
        "evidence_scope": STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE,
        "scm_process_evidence_sha256": scm["evidence_sha256"],
        "endpoint_evidence_sha256": endpoint["evidence_sha256"],
        "authority_kind": scm["authority_kind"],
        "runtime_state_kind": scm["runtime_state_kind"],
        "boot_nonce": scm["boot_nonce"],
        "active_release_sha256": scm["active_release_sha256"],
        "binding_sha256": scm["binding_sha256"],
        "retention_aggregate_sha256": scm[
            "retention_aggregate_sha256"
        ],
        "state_identity_sha256": scm["state_identity_sha256"],
        "tooling_sha256": scm["tooling_sha256"],
        "receipt_lineage_aggregate_sha256": scm[
            "receipt_lineage_aggregate_sha256"
        ],
        "legacy_c_live_fence_aggregate_sha256": scm[
            "legacy_c_live_fence_aggregate_sha256"
        ],
        "release": scm["release"],
        "lease_record": record,
        "kernel_lock_observation": kernel,
        "observation_aggregate_sha256": identity_sha256(
            [
                {"name": "scm_process", "sha256": scm["evidence_sha256"]},
                {"name": "endpoint", "sha256": endpoint["evidence_sha256"]},
                {
                    "name": "lease_record",
                    "sha256": record["lease_record_sha256"],
                },
                {
                    "name": "kernel_lock",
                    "sha256": kernel["kernel_observation_sha256"],
                },
            ]
        ),
        "result": "steady_writer_lease_observed_not_admission_qualified",
    }
    document["evidence_sha256"] = identity_sha256(document)
    return document


class _WriterLeaseObservationRunner:
    __slots__ = ("_api",)

    def __init__(self, api: _ProductionWindowsWriterLeaseObserverApi):
        if type(api) is not _ProductionWindowsWriterLeaseObserverApi:
            raise TypeError("writer lease runner 拒绝 fake API table")
        api._assert_exact_binding()
        self._api = api

    def observe(
        self,
        scm: LockedWindowsScmProcessObservation,
        endpoint: LockedWindowsEndpointObservation,
        tracking: LockedWindowsWriterLeaseHandleTracking,
    ) -> _CollectedWriterLeaseObservation:
        if (
            type(scm) is not LockedWindowsScmProcessObservation
            or type(endpoint) is not LockedWindowsEndpointObservation
            or type(tracking) is not LockedWindowsWriterLeaseHandleTracking
            or endpoint._scm_observation is not scm
        ):
            raise WindowsWriterLeaseObserverError(
                "writer lease runner 只接受同链 exact live capabilities"
            )
        api = self._api
        api._assert_exact_binding()
        scm_before = scm.build_evidence()
        endpoint_before = endpoint.build_evidence()
        record_before = _read_record(
            api, tracking, slot_label="lease_record_before"
        )
        validated_record = validate_writer_lease_record(
            record_before, scm_before, endpoint_before
        )
        lock = validated_record.get("lock")
        if type(lock) is not dict:
            raise WindowsWriterLeaseObserverError("writer lease lock 结构漂移")
        handle_value = _exact_positive(
            lock.get("handle_value"), label="writer child source handle"
        )
        pointer_invalid = ctypes.c_void_p(-1).value
        if type(pointer_invalid) is not int or handle_value >= pointer_invalid:
            raise WindowsWriterLeaseObserverError(
                "writer child source handle 超出当前 pointer width"
            )
        target_process = api.get_current_process()
        if type(target_process) is not int or target_process != pointer_invalid:
            raise WindowsWriterLeaseObserverError(
                "GetCurrentProcess 未返回固定 pseudo handle"
            )
        scm._duplicate_child_handle_for_writer_lease(
            tracking,
            api.duplicate_handle,
            handle_value,
            target_process,
            _GENERIC_READ | _GENERIC_WRITE,
            False,
            0,
        )
        duplicate = tracking._borrow_handle("duplicated_writer_lock")
        primary: BaseException | None = None
        try:
            duplicate_file = _query_file(
                api, duplicate, expected_path=WRITER_LOCK_FINAL_PATH
            )
            if (
                duplicate_file.volume_serial_number
                != lock.get("volume_serial_number")
                or duplicate_file.file_id != lock.get("file_id")
            ):
                raise WindowsWriterLeaseObserverError(
                    "duplicated child handle 文件身份与 lease record 不同"
                )
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                tracking._release_reusable_handle("duplicated_writer_lock")
            except BaseException as close_error:
                if primary is None:
                    raise
                raise WindowsWriterLeaseObserverError(
                    "duplicated writer lock 查询失败且 close 不可闭合"
                ) from close_error

        ctypes.set_last_error(0)
        conflict_error = tracking._capture_expected_conflict(
            api.create_file_w,
            ctypes.get_last_error,
            WRITER_LOCK_FINAL_PATH,
            _GENERIC_WRITE,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if conflict_error != _ERROR_SHARING_VIOLATION:
            raise WindowsWriterLeaseObserverError(
                "writer lock conflict fence 未闭合"
            )
        record_after = _read_record(
            api, tracking, slot_label="lease_record_after"
        )
        endpoint_after = endpoint.build_evidence()
        scm_after = scm.build_evidence()
        if (
            canonical_bytes(record_after) != canonical_bytes(validated_record)
            or scm_after.evidence_sha256 != scm_before.evidence_sha256
            or _endpoint_stable_identity(endpoint_after)
            != _endpoint_stable_identity(endpoint_before)
        ):
            raise WindowsWriterLeaseObserverError(
                "writer lease observation 前后 identity/record 漂移"
            )
        validate_writer_lease_record(
            record_after, scm_after, endpoint_after
        )
        scm_document = scm_before.as_dict()
        child = scm_document.get("child")
        if type(child) is not dict:
            raise WindowsWriterLeaseObserverError("SCM child identity 结构漂移")
        kernel: dict[str, object] = {
            "source_process_pid": child.get("pid"),
            "source_process_creation_time_100ns": child.get(
                "creation_time_100ns"
            ),
            "source_handle_value": handle_value,
            "duplicate_final_path": duplicate_file.final_path,
            "duplicate_volume_serial_number": (
                duplicate_file.volume_serial_number
            ),
            "duplicate_file_id": duplicate_file.file_id,
            "duplicate_close_result": "closed_before_conflict_probe",
            "conflict_open_result": "sharing_violation",
            "conflict_open_error_code": conflict_error,
        }
        kernel["kernel_observation_sha256"] = identity_sha256(kernel)
        return _CollectedWriterLeaseObservation(
            scm_evidence=scm_before,
            endpoint_evidence=endpoint_before,
            lease_record=validated_record,
            kernel_observation=kernel,
        )


class _SteadyWriterLeaseObservationRunner:
    __slots__ = ("_api",)

    def __init__(self, api: _ProductionWindowsWriterLeaseObserverApi):
        if type(api) is not _ProductionWindowsWriterLeaseObserverApi:
            raise TypeError("steady writer runner 拒绝 fake API table")
        api._assert_exact_binding()
        self._api = api

    def observe(
        self,
        scm: LockedSteadyWindowsScmProcessObservation,
        endpoint: LockedSteadyWindowsEndpointObservation,
        tracking: LockedWindowsSteadyWriterLeaseHandleTracking,
    ) -> _CollectedSteadyWriterLeaseObservation:
        if (
            type(scm) is not LockedSteadyWindowsScmProcessObservation
            or type(endpoint) is not LockedSteadyWindowsEndpointObservation
            or type(tracking)
            is not LockedWindowsSteadyWriterLeaseHandleTracking
            or endpoint._scm_observation is not scm
            or tracking._scm_tracking is not scm._tracking
        ):
            raise WindowsWriterLeaseObserverError(
                "steady writer runner 只接受同链 exact live capabilities"
            )
        api = self._api
        api._assert_exact_binding()
        scm_before = scm.build_evidence()
        endpoint_before = endpoint.build_evidence()
        record_before = _read_record(
            api, tracking, slot_label="lease_record_before"
        )
        validated_record = validate_steady_writer_lease_record(
            record_before, scm_before, endpoint_before
        )
        lock = validated_record.get("lock")
        if type(lock) is not dict:
            raise WindowsWriterLeaseObserverError(
                "steady writer lease lock 结构漂移"
            )
        handle_value = _exact_positive(
            lock.get("handle_value"), label="steady writer child source handle"
        )
        pointer_invalid = ctypes.c_void_p(-1).value
        if type(pointer_invalid) is not int or handle_value >= pointer_invalid:
            raise WindowsWriterLeaseObserverError(
                "steady writer child handle 超出 pointer width"
            )
        target_process = api.get_current_process()
        if type(target_process) is not int or target_process != pointer_invalid:
            raise WindowsWriterLeaseObserverError(
                "GetCurrentProcess 未返回固定 pseudo handle"
            )
        scm._duplicate_child_handle_for_writer_lease(
            tracking,
            api.duplicate_handle,
            handle_value,
            target_process,
            _GENERIC_READ | _GENERIC_WRITE,
            False,
            0,
        )
        duplicate = tracking._borrow_handle("duplicated_writer_lock")
        primary: BaseException | None = None
        try:
            duplicate_file = _query_file(
                api, duplicate, expected_path=WRITER_LOCK_FINAL_PATH
            )
            if (
                duplicate_file.volume_serial_number
                != lock.get("volume_serial_number")
                or duplicate_file.file_id != lock.get("file_id")
            ):
                raise WindowsWriterLeaseObserverError(
                    "steady duplicated child handle 文件身份与 record 不同"
                )
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                tracking._release_reusable_handle("duplicated_writer_lock")
            except BaseException as close_error:
                if primary is None:
                    raise
                raise WindowsWriterLeaseObserverError(
                    "steady duplicated writer handle close 不可闭合"
                ) from close_error
        ctypes.set_last_error(0)
        conflict_error = tracking._capture_expected_conflict(
            api.create_file_w,
            ctypes.get_last_error,
            WRITER_LOCK_FINAL_PATH,
            _GENERIC_WRITE,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if conflict_error != _ERROR_SHARING_VIOLATION:
            raise WindowsWriterLeaseObserverError(
                "steady writer conflict fence 未闭合"
            )
        record_after = _read_record(
            api, tracking, slot_label="lease_record_after"
        )
        endpoint_after = endpoint.build_evidence()
        scm_after = scm.build_evidence()
        if (
            canonical_bytes(record_after) != canonical_bytes(validated_record)
            or scm_after.evidence_sha256 != scm_before.evidence_sha256
            or _steady_endpoint_stable_identity(endpoint_after)
            != _steady_endpoint_stable_identity(endpoint_before)
        ):
            raise WindowsWriterLeaseObserverError(
                "steady writer observation 前后 identity/record 漂移"
            )
        validate_steady_writer_lease_record(
            record_after, scm_after, endpoint_after
        )
        scm_document = scm_before.as_dict()
        child = scm_document.get("child")
        if type(child) is not dict:
            raise WindowsWriterLeaseObserverError(
                "steady SCM child identity 结构漂移"
            )
        kernel: dict[str, object] = {
            "source_process_pid": child.get("pid"),
            "source_process_creation_time_100ns": child.get(
                "creation_time_100ns"
            ),
            "source_handle_value": handle_value,
            "duplicate_final_path": duplicate_file.final_path,
            "duplicate_volume_serial_number": (
                duplicate_file.volume_serial_number
            ),
            "duplicate_file_id": duplicate_file.file_id,
            "duplicate_close_result": "closed_before_conflict_probe",
            "conflict_open_result": "sharing_violation",
            "conflict_open_error_code": conflict_error,
        }
        kernel["kernel_observation_sha256"] = identity_sha256(kernel)
        return _CollectedSteadyWriterLeaseObservation(
            scm_evidence=scm_before,
            endpoint_evidence=endpoint_before,
            lease_record=validated_record,
            kernel_observation=kernel,
        )

    def observe_after_ready_ack(
        self,
        scm: LockedSteadyWindowsScmProcessObservation,
        endpoint: LockedSteadyWindowsEndpointObservation,
        tracking: LockedWindowsSteadyWriterLeaseHandleTracking,
        ready_endpoint: SteadyWindowsEndpointObservationEvidence,
    ) -> _CollectedSteadyWriterLeaseObservation:
        """Fresh writer fence using the single endpoint probe that created ready-ack.

        ``ack_pending`` permits exactly one challenge, so the ordinary writer
        sandwich cannot probe endpoint twice at this cut.  This variant binds
        that one already-validated evidence object to fresh SCM, lease-record,
        duplicated-kernel-handle and sharing-conflict observations.
        """

        if (
            type(scm) is not LockedSteadyWindowsScmProcessObservation
            or type(endpoint) is not LockedSteadyWindowsEndpointObservation
            or type(tracking)
            is not LockedWindowsSteadyWriterLeaseHandleTracking
            or type(ready_endpoint)
            is not SteadyWindowsEndpointObservationEvidence
            or endpoint._scm_observation is not scm
            or tracking._scm_tracking is not scm._tracking
        ):
            raise WindowsWriterLeaseObserverError(
                "ready-ack writer runner 只接受同链 exact live capabilities"
            )
        api = self._api
        api._assert_exact_binding()
        scm_before = scm.build_evidence()
        endpoint_before = SteadyWindowsEndpointObservationEvidence.from_document(
            ready_endpoint.as_dict(), scm_before
        )
        record_before = _read_record(
            api, tracking, slot_label="lease_record_before"
        )
        validated_record = validate_steady_writer_lease_record(
            record_before, scm_before, endpoint_before
        )
        lock = validated_record.get("lock")
        if type(lock) is not dict:
            raise WindowsWriterLeaseObserverError(
                "ready-ack steady writer lease lock 结构漂移"
            )
        handle_value = _exact_positive(
            lock.get("handle_value"), label="steady writer child source handle"
        )
        pointer_invalid = ctypes.c_void_p(-1).value
        if type(pointer_invalid) is not int or handle_value >= pointer_invalid:
            raise WindowsWriterLeaseObserverError(
                "ready-ack writer child handle 超出 pointer width"
            )
        target_process = api.get_current_process()
        if type(target_process) is not int or target_process != pointer_invalid:
            raise WindowsWriterLeaseObserverError(
                "GetCurrentProcess 未返回固定 pseudo handle"
            )
        scm._duplicate_child_handle_for_writer_lease(
            tracking,
            api.duplicate_handle,
            handle_value,
            target_process,
            _GENERIC_READ | _GENERIC_WRITE,
            False,
            0,
        )
        duplicate = tracking._borrow_handle("duplicated_writer_lock")
        primary: BaseException | None = None
        try:
            duplicate_file = _query_file(
                api, duplicate, expected_path=WRITER_LOCK_FINAL_PATH
            )
            if (
                duplicate_file.volume_serial_number
                != lock.get("volume_serial_number")
                or duplicate_file.file_id != lock.get("file_id")
            ):
                raise WindowsWriterLeaseObserverError(
                    "ready-ack duplicated child handle 文件身份漂移"
                )
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                tracking._release_reusable_handle("duplicated_writer_lock")
            except BaseException as close_error:
                if primary is None:
                    raise
                raise WindowsWriterLeaseObserverError(
                    "ready-ack duplicated writer handle close 不可闭合"
                ) from close_error
        ctypes.set_last_error(0)
        conflict_error = tracking._capture_expected_conflict(
            api.create_file_w,
            ctypes.get_last_error,
            WRITER_LOCK_FINAL_PATH,
            _GENERIC_WRITE,
            _FILE_SHARE_READ,
            None,
            _OPEN_EXISTING,
            _FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        if conflict_error != _ERROR_SHARING_VIOLATION:
            raise WindowsWriterLeaseObserverError(
                "ready-ack writer conflict fence 未闭合"
            )
        record_after = _read_record(
            api, tracking, slot_label="lease_record_after"
        )
        scm_after = scm.build_evidence()
        if (
            canonical_bytes(record_after) != canonical_bytes(validated_record)
            or scm_after.evidence_sha256 != scm_before.evidence_sha256
        ):
            raise WindowsWriterLeaseObserverError(
                "ready-ack writer observation 前后 SCM/record 漂移"
            )
        validate_steady_writer_lease_record(
            record_after, scm_after, endpoint_before
        )
        scm_document = scm_before.as_dict()
        child = scm_document.get("child")
        if type(child) is not dict:
            raise WindowsWriterLeaseObserverError(
                "ready-ack steady SCM child identity 结构漂移"
            )
        kernel: dict[str, object] = {
            "source_process_pid": child.get("pid"),
            "source_process_creation_time_100ns": child.get(
                "creation_time_100ns"
            ),
            "source_handle_value": handle_value,
            "duplicate_final_path": duplicate_file.final_path,
            "duplicate_volume_serial_number": duplicate_file.volume_serial_number,
            "duplicate_file_id": duplicate_file.file_id,
            "duplicate_close_result": "closed_before_conflict_probe",
            "conflict_open_result": "sharing_violation",
            "conflict_open_error_code": conflict_error,
        }
        kernel["kernel_observation_sha256"] = identity_sha256(kernel)
        return _CollectedSteadyWriterLeaseObservation(
            scm_evidence=scm_before,
            endpoint_evidence=endpoint_before,
            lease_record=validated_record,
            kernel_observation=kernel,
        )


class LockedWindowsWriterLeaseObservation:
    """由 B2 tracked handles 支撑的 live observation；仍非 canary 资格。"""

    __slots__ = (
        "_api",
        "_scm",
        "_endpoint",
        "_tracking",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("live Windows writer lease observation 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("live Windows writer lease observation 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        api: object,
        scm: LockedWindowsScmProcessObservation,
        endpoint: LockedWindowsEndpointObservation,
        tracking: LockedWindowsWriterLeaseHandleTracking,
        _construction_token: object,
    ):
        if (
            _construction_token is not _LIVE_TOKEN
            or type(api) is not _ProductionWindowsWriterLeaseObserverApi
            or type(scm) is not LockedWindowsScmProcessObservation
            or type(endpoint) is not LockedWindowsEndpointObservation
            or type(tracking) is not LockedWindowsWriterLeaseHandleTracking
        ):
            raise TypeError("live writer lease observation provenance 无效")
        api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._api = api
        self._scm = scm
        self._endpoint = endpoint
        self._tracking = tracking
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("live Windows writer lease observation is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _collect(self) -> _CollectedWriterLeaseObservation:
        self._api._assert_exact_binding()
        return _WriterLeaseObservationRunner(self._api).observe(
            self._scm, self._endpoint, self._tracking
        )

    @property
    def scope(self) -> str:
        self._tracking._assert_context()
        return LIVE_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE

    def build_evidence(self) -> WindowsWriterLeaseObservationEvidence:
        try:
            collected = self._collect()
            document = _build_evidence_document(
                collected, _authority_token=_API_TOKEN
            )
            return WindowsWriterLeaseObservationEvidence.from_document(
                document,
                collected.scm_evidence,
                collected.endpoint_evidence,
            )
        except BaseException as error:
            try:
                self._tracking.close()
            except BaseException as close_error:
                raise WindowsWriterLeaseObserverError(
                    "writer lease observation 失败且 tracking cleanup 不可闭合"
                ) from close_error
            if isinstance(error, WindowsWriterLeaseObserverError):
                raise
            raise WindowsWriterLeaseObserverError(
                "writer lease evidence finalization 失败"
            ) from error

    def close(self) -> None:
        self._tracking.close()

    def __enter__(self) -> "LockedWindowsWriterLeaseObservation":
        self._tracking._assert_context()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedSteadyWindowsWriterLeaseObservation:
    """Steady SCM→endpoint→kernel writer 同链 live observation。"""

    __slots__ = ("_api", "_scm", "_endpoint", "_tracking", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady live writer lease observation 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady live writer observation 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        api: object,
        scm: LockedSteadyWindowsScmProcessObservation,
        endpoint: LockedSteadyWindowsEndpointObservation,
        tracking: LockedWindowsSteadyWriterLeaseHandleTracking,
        _construction_token: object,
    ):
        if (
            _construction_token is not _LIVE_TOKEN
            or type(api) is not _ProductionWindowsWriterLeaseObserverApi
            or type(scm) is not LockedSteadyWindowsScmProcessObservation
            or type(endpoint) is not LockedSteadyWindowsEndpointObservation
            or type(tracking)
            is not LockedWindowsSteadyWriterLeaseHandleTracking
            or endpoint._scm_observation is not scm
            or tracking._scm_tracking is not scm._tracking
        ):
            raise TypeError("steady live writer observation provenance 无效")
        api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._api = api
        self._scm = scm
        self._endpoint = endpoint
        self._tracking = tracking
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("steady live writer observation is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _collect(self) -> _CollectedSteadyWriterLeaseObservation:
        self._api._assert_exact_binding()
        return _SteadyWriterLeaseObservationRunner(self._api).observe(
            self._scm, self._endpoint, self._tracking
        )

    @property
    def scope(self) -> str:
        self._tracking._assert_context()
        return LIVE_STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE

    def build_evidence(
        self,
    ) -> SteadyWindowsWriterLeaseObservationEvidence:
        try:
            collected = self._collect()
            document = _build_steady_evidence_document(
                collected, _authority_token=_API_TOKEN
            )
            return SteadyWindowsWriterLeaseObservationEvidence.from_document(
                document,
                collected.scm_evidence,
                collected.endpoint_evidence,
            )
        except BaseException as error:
            try:
                self._tracking.close()
            except BaseException as close_error:
                raise WindowsWriterLeaseObserverError(
                    "steady writer observation 失败且 cleanup 不可闭合"
                ) from close_error
            if isinstance(error, WindowsWriterLeaseObserverError):
                raise
            raise WindowsWriterLeaseObserverError(
                "steady writer evidence finalization 失败"
            ) from error

    def build_evidence_after_ready_ack(
        self, endpoint_evidence: SteadyWindowsEndpointObservationEvidence
    ) -> SteadyWindowsWriterLeaseObservationEvidence:
        try:
            collected = _SteadyWriterLeaseObservationRunner(
                self._api
            ).observe_after_ready_ack(
                self._scm,
                self._endpoint,
                self._tracking,
                endpoint_evidence,
            )
            document = _build_steady_evidence_document(
                collected, _authority_token=_API_TOKEN
            )
            return SteadyWindowsWriterLeaseObservationEvidence.from_document(
                document,
                collected.scm_evidence,
                collected.endpoint_evidence,
            )
        except BaseException as error:
            try:
                self._tracking.close()
            except BaseException as close_error:
                raise WindowsWriterLeaseObserverError(
                    "ready-ack writer observation 失败且 cleanup 不可闭合"
                ) from close_error
            if isinstance(error, WindowsWriterLeaseObserverError):
                raise
            raise WindowsWriterLeaseObserverError(
                "ready-ack writer evidence finalization 失败"
            ) from error

    def close(self) -> None:
        self._tracking.close()

    def __enter__(self) -> "LockedSteadyWindowsWriterLeaseObservation":
        self._tracking._assert_context()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class ProductionWindowsWriterLeaseObserver:
    """无参数加载、不可注入的 exact-D writer lease observer。"""

    __slots__ = ("_api", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production Windows writer lease observer 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production Windows writer lease observer 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, api: object, *, _construction_token: object):
        if (
            _construction_token is not _OBSERVER_TOKEN
            or type(api) is not _ProductionWindowsWriterLeaseObserverApi
        ):
            raise TypeError("production writer observer 必须由 load_exact_d() 构造")
        api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._api = api
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production Windows writer lease observer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionWindowsWriterLeaseObserver":
        api = _ProductionWindowsWriterLeaseObserverApi.load_exact_d()
        return cls(api, _construction_token=_OBSERVER_TOKEN)

    def observe(
        self,
        scm: LockedWindowsScmProcessObservation,
        endpoint: LockedWindowsEndpointObservation,
    ) -> LockedWindowsWriterLeaseObservation:
        if (
            type(self._api) is not _ProductionWindowsWriterLeaseObserverApi
            or type(scm) is not LockedWindowsScmProcessObservation
            or type(endpoint) is not LockedWindowsEndpointObservation
            or endpoint._scm_observation is not scm
        ):
            raise WindowsWriterLeaseObserverError(
                "production writer observer 只接受同链 exact live capabilities"
            )
        self._api._assert_exact_binding()
        tracking = scm._prepare_writer_lease_handle_tracking()
        try:
            collected = _WriterLeaseObservationRunner(self._api).observe(
                scm, endpoint, tracking
            )
            document = _build_evidence_document(
                collected, _authority_token=_API_TOKEN
            )
            WindowsWriterLeaseObservationEvidence.from_document(
                document,
                collected.scm_evidence,
                collected.endpoint_evidence,
            )
            return LockedWindowsWriterLeaseObservation(
                api=self._api,
                scm=scm,
                endpoint=endpoint,
                tracking=tracking,
                _construction_token=_LIVE_TOKEN,
            )
        except BaseException as error:
            try:
                tracking.close()
            except BaseException as close_error:
                raise WindowsWriterLeaseObserverError(
                    "production writer observation 失败且 cleanup 不可闭合"
                ) from close_error
            if isinstance(error, WindowsWriterLeaseObserverError):
                raise
            if isinstance(error, (WindowsWriterLeaseEvidenceError, LocalDeploymentPersistenceError)):
                raise WindowsWriterLeaseObserverError(
                    "production writer observation capability/evidence 未闭合"
                ) from error
            raise WindowsWriterLeaseObserverError(
                "production writer observation syscall/query 失败"
            ) from error

    def observe_steady(
        self,
        scm: LockedSteadyWindowsScmProcessObservation,
        endpoint: LockedSteadyWindowsEndpointObservation,
    ) -> LockedSteadyWindowsWriterLeaseObservation:
        if (
            type(self._api) is not _ProductionWindowsWriterLeaseObserverApi
            or type(scm) is not LockedSteadyWindowsScmProcessObservation
            or type(endpoint) is not LockedSteadyWindowsEndpointObservation
            or endpoint._scm_observation is not scm
        ):
            raise WindowsWriterLeaseObserverError(
                "production steady writer 只接受同链 exact live capabilities"
            )
        self._api._assert_exact_binding()
        tracking = scm._prepare_writer_lease_handle_tracking()
        try:
            collected = _SteadyWriterLeaseObservationRunner(self._api).observe(
                scm, endpoint, tracking
            )
            document = _build_steady_evidence_document(
                collected, _authority_token=_API_TOKEN
            )
            SteadyWindowsWriterLeaseObservationEvidence.from_document(
                document,
                collected.scm_evidence,
                collected.endpoint_evidence,
            )
            return LockedSteadyWindowsWriterLeaseObservation(
                api=self._api,
                scm=scm,
                endpoint=endpoint,
                tracking=tracking,
                _construction_token=_LIVE_TOKEN,
            )
        except BaseException as error:
            try:
                tracking.close()
            except BaseException as close_error:
                raise WindowsWriterLeaseObserverError(
                    "production steady writer cleanup 不可闭合"
                ) from close_error
            if isinstance(error, WindowsWriterLeaseObserverError):
                raise
            if isinstance(
                error,
                (
                    WindowsWriterLeaseEvidenceError,
                    LocalDeploymentPersistenceError,
                ),
            ):
                raise WindowsWriterLeaseObserverError(
                    "production steady writer capability/evidence 未闭合"
                ) from error
            raise WindowsWriterLeaseObserverError(
                "production steady writer syscall/query 失败"
            ) from error


__all__ = [
    "LIVE_STEADY_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE",
    "LIVE_WINDOWS_WRITER_LEASE_OBSERVATION_SCOPE",
    "LockedSteadyWindowsWriterLeaseObservation",
    "LockedWindowsWriterLeaseObservation",
    "ProductionWindowsWriterLeaseObserver",
    "WindowsWriterLeaseObserverError",
]
