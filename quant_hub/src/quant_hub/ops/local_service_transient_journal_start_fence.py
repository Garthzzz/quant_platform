"""Service-host-local、existing-only 的 transient journal/artifact 启动门禁。

该模块不构造 B2 persistence façade、不取得 controller lock，也没有任何创建、
修补或清理接口。产品 loader 固定读取生产 D 根；所有文件均以 OPEN_EXISTING、
只读且仅 FILE_SHARE_READ 的方式 pin 住，并在 child resume 前后重复核对同一
journal/history/workspace/artifact namespace。
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import PureWindowsPath
import re
import subprocess
import threading
from typing import Mapping
import unicodedata

from .local_deployment_persistence import (
    _journal_is_closed,
    _transient_start_authorization_evidence_field,
    _transient_start_authorization_sha256,
    _validate_attempt_evidence,
    _validate_attempt_workspace_binding,
    validate_deployment_journal,
    validate_journal_history,
)
from .local_release_identity import canonical_bytes, identity_sha256
from .local_runtime_qualification_evidence import (
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
    LocalRuntimeQualificationEvidenceError,
    parse_local_runtime_qualification_evidence_bytes,
)
from .local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity


_PRODUCTION_ROOT = PureWindowsPath(r"D:\quant\quant_platform")
_JOURNAL_DIRECTORY = _PRODUCTION_ROOT / "audit" / "deployment_attempts"
_WORKSPACE_PARENT = _PRODUCTION_ROOT / "tmp" / "deployment-attempts"
_JOURNAL_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]{0,179})\.r([0-9]{20})\.json$"
)
_EVIDENCE_DIRECTORY_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]{0,179})\.evidence$"
)
_EVIDENCE_FILE_RE = re.compile(
    r"^([A-Za-z0-9][A-Za-z0-9._-]{0,179})\.json$"
)
_MAX_FILE_BYTES = 16 * 1024 * 1024

_API_TOKEN = object()
_FACTORY_TOKEN = object()
_FENCE_TOKEN = object()
_LAUNCH_BIND_TOKEN = object()

_GENERIC_READ = 0x80000000
_FILE_LIST_DIRECTORY = 0x0001
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_FILE_SHARE_DELETE = 0x00000004
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_FILE_BEGIN = 0
_ERROR_FILE_NOT_FOUND = 2
_ERROR_NO_MORE_FILES = 18
_DUPLICATE_CLOSE_SOURCE = 0x00000001


class ServiceTransientJournalStartFenceError(RuntimeError):
    """Durable transient start state cannot be pinned or revalidated."""


class ServiceTransientJournalStartFenceOwnerCrashRequired(
    ServiceTransientJournalStartFenceError
):
    """A close/read outcome is unknown; the service host must exit."""


class _FILETIME(ctypes.Structure):
    _fields_ = (("low", wintypes.DWORD), ("high", wintypes.DWORD))


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("attributes", wintypes.DWORD),
        ("creation_time", _FILETIME),
        ("last_access_time", _FILETIME),
        ("last_write_time", _FILETIME),
        ("volume_serial_number", wintypes.DWORD),
        ("file_size_high", wintypes.DWORD),
        ("file_size_low", wintypes.DWORD),
        ("number_of_links", wintypes.DWORD),
        ("file_index_high", wintypes.DWORD),
        ("file_index_low", wintypes.DWORD),
    )


class _WIN32_FIND_DATAW(ctypes.Structure):
    _fields_ = (
        ("dwFileAttributes", wintypes.DWORD),
        ("ftCreationTime", _FILETIME),
        ("ftLastAccessTime", _FILETIME),
        ("ftLastWriteTime", _FILETIME),
        ("nFileSizeHigh", wintypes.DWORD),
        ("nFileSizeLow", wintypes.DWORD),
        ("dwReserved0", wintypes.DWORD),
        ("dwReserved1", wintypes.DWORD),
        ("cFileName", wintypes.WCHAR * 260),
        ("cAlternateFileName", wintypes.WCHAR * 14),
    )


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
        raise ServiceTransientJournalStartFenceError(
            f"existing-only System32 API binding is incomplete: {name}"
        ) from error
    return function


def _handle(value: object, *, label: str) -> int:
    observed = int(value or 0)
    if observed <= 0 or observed == ctypes.c_void_p(-1).value:
        raise ServiceTransientJournalStartFenceError(f"{label} handle is invalid")
    return observed


def _validate_qualification_artifact(
    *,
    name: str,
    raw: bytes,
    document: Mapping[str, object],
    directory_attempt: str,
    history: tuple[Mapping[str, object], ...],
    current_attempt: str,
    current_role: str,
) -> None:
    fixed_names = {
        _physical_key(f"runtime-qualification-{role}.json"): role
        for role in ("prior", "candidate", "baseline")
    }
    reserved = (
        document.get("schema_version")
        == LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA
        or document.get("scope") == LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE
        or _physical_key(name) in fixed_names
    )
    if not reserved:
        return
    try:
        qualification = parse_local_runtime_qualification_evidence_bytes(raw)
    except LocalRuntimeQualificationEvidenceError as error:
        raise ServiceTransientJournalStartFenceError(
            "reserved runtime qualification artifact is malformed"
        ) from error
    qualification_document = qualification.as_dict()
    evidence_role = str(qualification_document["role"])
    expected_name = f"runtime-qualification-{evidence_role}.json"
    if (
        name != expected_name
        or qualification_document["attempt_id"] != directory_attempt
    ):
        raise ServiceTransientJournalStartFenceError(
            "runtime qualification artifact has a filename/attempt alias"
        )
    if directory_attempt == current_attempt and evidence_role == current_role:
        raise ServiceTransientJournalStartFenceError(
            "current role runtime qualification already exists"
        )
    historical_phase = (
        "prior_verified" if evidence_role == "prior" else "candidate_verified"
    )
    historical_field = (
        "prior_runtime_qualification_sha256"
        if evidence_role == "prior"
        else "candidate_runtime_qualification_sha256"
    )
    if not any(
        revision.get("phase") == historical_phase
        and revision.get("evidence_hashes", {}).get(historical_field)
        == qualification.aggregate_sha256
        for revision in history
    ):
        raise ServiceTransientJournalStartFenceError(
            "foreign-role runtime qualification lacks an exact verified revision"
        )


def _normal_final_path(value: str) -> PureWindowsPath:
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return PureWindowsPath(value)


def _physical_key(value: str) -> str:
    return unicodedata.normalize("NFKC", value).casefold()


class _ExistingOnlyApi:
    __slots__ = (
        "CreateFileW",
        "ReadFile",
        "SetFilePointerEx",
        "GetFileSizeEx",
        "GetFileInformationByHandle",
        "GetFinalPathNameByHandleW",
        "FindFirstFileW",
        "FindNextFileW",
        "FindClose",
        "DuplicateHandle",
        "GetCurrentProcess",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("existing-only production API cannot be subclassed")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("existing-only production API is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, kernel32: object, *, token: object) -> None:
        if token is not _API_TOKEN:
            raise TypeError("existing-only production API provenance is invalid")
        object.__setattr__(self, "_sealed", False)
        self.CreateFileW = _bind(
            kernel32,
            "CreateFileW",
            (
                wintypes.LPCWSTR,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.DWORD,
                wintypes.HANDLE,
            ),
            wintypes.HANDLE,
        )
        self.ReadFile = _bind(
            kernel32,
            "ReadFile",
            (
                wintypes.HANDLE,
                wintypes.LPVOID,
                wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
                wintypes.LPVOID,
            ),
            wintypes.BOOL,
        )
        self.SetFilePointerEx = _bind(
            kernel32,
            "SetFilePointerEx",
            (wintypes.HANDLE, ctypes.c_longlong, wintypes.LPVOID, wintypes.DWORD),
            wintypes.BOOL,
        )
        self.GetFileSizeEx = _bind(
            kernel32,
            "GetFileSizeEx",
            (wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)),
            wintypes.BOOL,
        )
        self.GetFileInformationByHandle = _bind(
            kernel32,
            "GetFileInformationByHandle",
            (wintypes.HANDLE, ctypes.POINTER(_BY_HANDLE_FILE_INFORMATION)),
            wintypes.BOOL,
        )
        self.GetFinalPathNameByHandleW = _bind(
            kernel32,
            "GetFinalPathNameByHandleW",
            (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD),
            wintypes.DWORD,
        )
        self.FindFirstFileW = _bind(
            kernel32,
            "FindFirstFileW",
            (wintypes.LPCWSTR, ctypes.POINTER(_WIN32_FIND_DATAW)),
            wintypes.HANDLE,
        )
        self.FindNextFileW = _bind(
            kernel32,
            "FindNextFileW",
            (wintypes.HANDLE, ctypes.POINTER(_WIN32_FIND_DATAW)),
            wintypes.BOOL,
        )
        self.FindClose = _bind(
            kernel32, "FindClose", (wintypes.HANDLE,), wintypes.BOOL
        )
        self.DuplicateHandle = _bind(
            kernel32,
            "DuplicateHandle",
            (
                wintypes.HANDLE,
                wintypes.HANDLE,
                wintypes.HANDLE,
                wintypes.LPVOID,
                wintypes.DWORD,
                wintypes.BOOL,
                wintypes.DWORD,
            ),
            wintypes.BOOL,
        )
        self.GetCurrentProcess = _bind(
            kernel32, "GetCurrentProcess", (), wintypes.HANDLE
        )
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "_ExistingOnlyApi":
        if os.name != "nt":
            raise ServiceTransientJournalStartFenceError(
                "existing-only production fence requires Windows"
            )
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
        if type(system_root) is not str or not system_root:
            raise ServiceTransientJournalStartFenceError("SystemRoot is unavailable")
        system32 = PureWindowsPath(system_root) / "System32" / "kernel32.dll"
        kernel32 = ctypes.WinDLL(
            str(system32),
            use_last_error=True,
            winmode=0x00000800,  # LOAD_LIBRARY_SEARCH_SYSTEM32
        )
        return cls(kernel32, token=_API_TOKEN)


class _PinnedExisting:
    __slots__ = ("path", "handle", "directory", "identity", "raw_sha256")

    def __init__(
        self,
        path: PureWindowsPath,
        handle: int,
        directory: bool,
        identity: tuple[int, int, int, int, int],
        raw_sha256: str | None,
    ) -> None:
        self.path = path
        self.handle = handle
        self.directory = directory
        self.identity = identity
        self.raw_sha256 = raw_sha256


class LockedServiceTransientJournalStartFence:
    """One service-host owner for one exact durable transient start."""

    __slots__ = (
        "_api",
        "_identity",
        "_pins",
        "_directory_snapshots",
        "_journal_raw",
        "_seal_sha256",
        "_owner_thread",
        "_state",
        "_checkpoint_index",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("transient journal start fence cannot be subclassed")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("transient journal start fence is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        api: _ExistingOnlyApi,
        identity: ExactRuntimeLeaseIdentity,
        *,
        token: object,
    ) -> None:
        if (
            token is not _FENCE_TOKEN
            or type(api) is not _ExistingOnlyApi
            or type(identity) is not ExactRuntimeLeaseIdentity
        ):
            raise TypeError("transient journal start fence provenance is invalid")
        object.__setattr__(self, "_sealed", False)
        self._api = api
        self._identity = identity
        self._pins: dict[str, _PinnedExisting] = {}
        self._directory_snapshots: dict[str, tuple[tuple[str, int], ...]] = {}
        self._journal_raw: dict[str, bytes] = {}
        self._seal_sha256 = ""
        self._owner_thread = threading.get_ident()
        self._state = "constructing"
        self._checkpoint_index = 0
        try:
            self._pin_initial_state()
        except BaseException as primary:
            try:
                self._close_all()
            except BaseException as cleanup_error:
                object.__setattr__(self, "_state", "owner_crash_only")
                raise cleanup_error from primary
            raise primary
        object.__setattr__(self, "_state", "live")
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("transient journal start fence is process-local")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _assert_owner(self, *states: str) -> None:
        if threading.get_ident() != self._owner_thread or self._state not in states:
            raise ServiceTransientJournalStartFenceError(
                "transient journal start fence owner/state drifted"
            )

    def _file_identity(
        self, handle: int, expected_path: PureWindowsPath, directory: bool
    ) -> tuple[int, int, int, int, int]:
        information = _BY_HANDLE_FILE_INFORMATION()
        if not self._api.GetFileInformationByHandle(
            wintypes.HANDLE(handle), ctypes.byref(information)
        ):
            raise ServiceTransientJournalStartFenceError(
                "existing-only file identity query failed"
            )
        is_directory = bool(information.attributes & _FILE_ATTRIBUTE_DIRECTORY)
        if (
            is_directory != directory
            or information.attributes & _FILE_ATTRIBUTE_REPARSE_POINT
            or (not directory and int(information.number_of_links) != 1)
        ):
            raise ServiceTransientJournalStartFenceError(
                "existing-only target is not the exact regular/directory object"
            )
        buffer = ctypes.create_unicode_buffer(32768)
        length = int(
            self._api.GetFinalPathNameByHandleW(
                wintypes.HANDLE(handle), buffer, len(buffer), 0
            )
        )
        if not 1 <= length < len(buffer) or _normal_final_path(
            buffer.value[:length]
        ) != expected_path:
            raise ServiceTransientJournalStartFenceError(
                "existing-only handle final path differs from fixed D target"
            )
        return (
            int(information.volume_serial_number),
            (int(information.file_index_high) << 32)
            | int(information.file_index_low),
            (int(information.file_size_high) << 32)
            | int(information.file_size_low),
            (int(information.last_write_time.high) << 32)
            | int(information.last_write_time.low),
            int(information.attributes),
        )

    def _open_pin(
        self,
        label: str,
        path: PureWindowsPath,
        *,
        directory: bool,
        cooperative_controller_owner: bool = False,
    ) -> None:
        if label in self._pins:
            raise ServiceTransientJournalStartFenceError(
                "existing-only pin slot is already occupied"
            )
        access = _FILE_LIST_DIRECTORY if directory else _GENERIC_READ
        flags = _FILE_FLAG_OPEN_REPARSE_POINT | (
            _FILE_FLAG_BACKUP_SEMANTICS if directory else _FILE_ATTRIBUTE_NORMAL
        )
        share_mode = _FILE_SHARE_READ
        if cooperative_controller_owner:
            # The same authorized controller transaction deliberately keeps
            # DELETE guards on its root/workspace directories and live write
            # handles on isolated canary databases. The service fence observes
            # those owners while its four checkpoints prove identities,
            # namespaces, and bytes. Journal/evidence stays read-share-only.
            share_mode |= _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
        handle = _handle(
            self._api.CreateFileW(
                str(path),
                access,
                share_mode,
                None,
                _OPEN_EXISTING,
                flags,
                None,
            ),
            label=label,
        )
        # First-state commit precedes identity/read validation.
        self._pins[label] = _PinnedExisting(path, handle, directory, (0, 0, 0, 0, 0), None)
        identity = self._file_identity(handle, path, directory)
        raw_hash = None if directory else hashlib.sha256(self._read_handle(handle)).hexdigest()
        pin = self._pins[label]
        pin.identity = identity
        pin.raw_sha256 = raw_hash

    def _read_handle(self, handle: int) -> bytes:
        size = ctypes.c_longlong()
        if not self._api.GetFileSizeEx(wintypes.HANDLE(handle), ctypes.byref(size)):
            raise ServiceTransientJournalStartFenceError(
                "existing-only file size query failed"
            )
        if not 0 <= int(size.value) <= _MAX_FILE_BYTES:
            raise ServiceTransientJournalStartFenceError(
                "existing-only file exceeds the fixed read limit"
            )
        if not self._api.SetFilePointerEx(
            wintypes.HANDLE(handle), 0, None, _FILE_BEGIN
        ):
            raise ServiceTransientJournalStartFenceError(
                "existing-only file rewind failed"
            )
        remaining = int(size.value)
        chunks: list[bytes] = []
        while remaining:
            request = min(remaining, 64 * 1024)
            buffer = ctypes.create_string_buffer(request)
            observed = wintypes.DWORD()
            if not self._api.ReadFile(
                wintypes.HANDLE(handle),
                buffer,
                request,
                ctypes.byref(observed),
                None,
            ):
                raise ServiceTransientJournalStartFenceError(
                    "existing-only file read failed"
                )
            count = int(observed.value)
            if not 1 <= count <= request:
                raise ServiceTransientJournalStartFenceError(
                    "existing-only file produced a short/zero read"
                )
            chunks.append(bytes(buffer.raw[:count]))
            remaining -= count
        return b"".join(chunks)

    def _enumerate(self, path: PureWindowsPath) -> tuple[tuple[str, int], ...]:
        data = _WIN32_FIND_DATAW()
        ctypes.set_last_error(0)
        raw_handle = self._api.FindFirstFileW(str(path / "*"), ctypes.byref(data))
        invalid = ctypes.c_void_p(-1).value
        if int(raw_handle or 0) == invalid:
            if ctypes.get_last_error() == _ERROR_FILE_NOT_FOUND:
                return ()
            raise ServiceTransientJournalStartFenceError(
                "existing-only directory enumeration failed"
            )
        find_handle = _handle(raw_handle, label="directory enumeration")
        entries: list[tuple[str, int]] = []
        primary: BaseException | None = None
        try:
            while True:
                name = str(data.cFileName)
                if name not in {".", ".."}:
                    entries.append((name, int(data.dwFileAttributes)))
                ctypes.set_last_error(0)
                if self._api.FindNextFileW(
                    wintypes.HANDLE(find_handle), ctypes.byref(data)
                ):
                    continue
                if ctypes.get_last_error() != _ERROR_NO_MORE_FILES:
                    raise ServiceTransientJournalStartFenceError(
                        "existing-only directory enumeration drifted"
                    )
                break
        except BaseException as error:
            primary = error
            raise
        finally:
            try:
                if not self._api.FindClose(wintypes.HANDLE(find_handle)):
                    raise ServiceTransientJournalStartFenceOwnerCrashRequired(
                        "FindClose outcome is unknown"
                    )
            except BaseException as close_error:
                if primary is None:
                    raise
                raise ServiceTransientJournalStartFenceOwnerCrashRequired(
                    "enumeration failed and FindClose is unknown"
                ) from close_error
        keys = [_physical_key(item[0]) for item in entries]
        if len(keys) != len(set(keys)):
            raise ServiceTransientJournalStartFenceError(
                "directory contains a case/NFKC alias"
            )
        return tuple(sorted(entries, key=lambda item: _physical_key(item[0])))

    @staticmethod
    def _parse_canonical(raw: bytes, validator: object, *, label: str) -> Mapping[str, object]:
        try:
            parsed = json.loads(raw.decode("utf-8"))
            validated = validator(parsed)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise ServiceTransientJournalStartFenceError(
                f"{label} is not valid canonical JSON"
            ) from error
        if not isinstance(validated, Mapping) or canonical_bytes(validated) != raw:
            raise ServiceTransientJournalStartFenceError(
                f"{label} bytes are not exact canonical JSON"
            )
        return validated

    def _pin_directory(
        self,
        label: str,
        path: PureWindowsPath,
        *,
        cooperative_controller_owner: bool = False,
    ) -> tuple[tuple[str, int], ...]:
        self._open_pin(
            label,
            path,
            directory=True,
            cooperative_controller_owner=cooperative_controller_owner,
        )
        first = self._enumerate(path)
        second = self._enumerate(path)
        if first != second:
            raise ServiceTransientJournalStartFenceError(
                f"{label} namespace drifted during double enumeration"
            )
        self._directory_snapshots[label] = first
        return first

    def _pin_file(
        self,
        label: str,
        path: PureWindowsPath,
        *,
        cooperative_controller_owner: bool = False,
    ) -> bytes:
        self._open_pin(
            label,
            path,
            directory=False,
            cooperative_controller_owner=cooperative_controller_owner,
        )
        pin = self._pins[label]
        raw = self._read_handle(pin.handle)
        if hashlib.sha256(raw).hexdigest() != pin.raw_sha256:
            raise ServiceTransientJournalStartFenceError(
                f"{label} changed during initial pin"
            )
        return raw

    def _pin_initial_state(self) -> None:
        identity = self._identity
        for label, path, cooperative in (
            ("root", _PRODUCTION_ROOT, True),
            ("control", _PRODUCTION_ROOT / "control", True),
            ("audit", _PRODUCTION_ROOT / "audit", False),
            ("tmp", _PRODUCTION_ROOT / "tmp", True),
            ("journal_directory", _JOURNAL_DIRECTORY, False),
            ("workspace_parent", _WORKSPACE_PARENT, True),
        ):
            self._pin_directory(
                label,
                path,
                cooperative_controller_owner=cooperative,
            )

        journal_entries = self._directory_snapshots["journal_directory"]
        grouped: dict[str, list[tuple[int, Mapping[str, object]]]] = {}
        attempt_names: dict[str, str] = {}
        evidence_directories: dict[str, str] = {}
        for name, attributes in journal_entries:
            match = _JOURNAL_RE.fullmatch(name)
            if match is not None:
                if attributes & _FILE_ATTRIBUTE_DIRECTORY:
                    raise ServiceTransientJournalStartFenceError(
                        "journal revision is a directory"
                    )
                attempt, revision_text = match.groups()
                folded = attempt.casefold()
                prior = attempt_names.get(folded)
                if prior is not None and prior != attempt:
                    raise ServiceTransientJournalStartFenceError(
                        "journal attempt aliases by case"
                    )
                attempt_names[folded] = attempt
                raw = self._pin_file(
                    f"journal:{name}", _JOURNAL_DIRECTORY / name
                )
                document = self._parse_canonical(
                    raw, validate_deployment_journal, label="journal revision"
                )
                revision = int(revision_text)
                if document["attempt"] != attempt or document["revision"] != revision:
                    raise ServiceTransientJournalStartFenceError(
                        "journal filename/payload identity differs"
                    )
                grouped.setdefault(folded, []).append((revision, document))
                self._journal_raw[name] = raw
                continue
            evidence_match = _EVIDENCE_DIRECTORY_RE.fullmatch(name)
            if evidence_match is None or not attributes & _FILE_ATTRIBUTE_DIRECTORY:
                raise ServiceTransientJournalStartFenceError(
                    "journal directory contains an unknown member"
                )
            attempt = evidence_match.group(1)
            folded = attempt.casefold()
            prior = attempt_names.get(folded)
            if prior is not None and prior != attempt:
                raise ServiceTransientJournalStartFenceError(
                    "journal/evidence attempt aliases by case"
                )
            attempt_names[folded] = attempt
            evidence_directories[folded] = name

        histories: dict[str, tuple[Mapping[str, object], ...]] = {}
        for folded, values in grouped.items():
            values.sort(key=lambda item: item[0])
            if [item[0] for item in values] != list(range(len(values))):
                raise ServiceTransientJournalStartFenceError(
                    "journal history has a revision gap"
                )
            try:
                histories[folded] = validate_journal_history(
                    [item[1] for item in values]
                )
            except (TypeError, ValueError) as error:
                raise ServiceTransientJournalStartFenceError(
                    "journal history is invalid"
                ) from error
        if set(evidence_directories) - set(histories):
            raise ServiceTransientJournalStartFenceError(
                "evidence directory has no journal history"
            )

        current_folded = identity.attempt_id.casefold()
        history = histories.get(current_folded)
        if history is None:
            raise ServiceTransientJournalStartFenceError(
                "matching durable journal history is absent"
            )
        active = [value[-1] for value in histories.values() if not _journal_is_closed(value[-1])]
        if len(active) != 1 or active[0] is not history[-1]:
            raise ServiceTransientJournalStartFenceError(
                "durable journal does not contain exactly one matching active attempt"
            )
        latest = history[-1]
        expected_phase = (
            "prior_start_authorized"
            if identity.role == "prior"
            else "candidate_start_authorized"
        )
        starts = latest.get("transient_start")
        matching = (
            [item for item in starts if item.get("role") == identity.role]
            if isinstance(starts, list)
            else []
        )
        if len(matching) != 1:
            raise ServiceTransientJournalStartFenceError(
                "durable journal lacks one exact transient start record"
            )
        start = matching[0]
        release = {
            "release_id": identity.release_id,
            "release_path": identity.release_path,
            "manifest_sha256": identity.manifest_sha256,
        }
        evidence_field = _transient_start_authorization_evidence_field(identity.role)
        if (
            latest.get("attempt") != identity.attempt_id
            or latest.get("nonce") != identity.nonce
            or latest.get("operation") != identity.operation
            or latest.get("phase") != expected_phase
            or latest.get("state_plan", {}).get("state_identity_sha256")
            != identity.state_identity_sha256
            or start.get("start_nonce") != identity.start_nonce
            or start.get("release") != release
            or start.get("scm_identity_sha256") != identity.scm_identity_sha256
            or _transient_start_authorization_sha256(latest, start)
            != identity.authorization_sha256
            or latest.get("evidence_hashes", {}).get(evidence_field)
            != identity.authorization_sha256
        ):
            raise ServiceTransientJournalStartFenceError(
                "closed SCM identity differs from the durable journal"
            )

        for folded, directory_name in evidence_directories.items():
            directory_path = _JOURNAL_DIRECTORY / directory_name
            entries = self._pin_directory(
                f"evidence_directory:{directory_name}", directory_path
            )
            for name, attributes in entries:
                match = _EVIDENCE_FILE_RE.fullmatch(name)
                if match is None or attributes & _FILE_ATTRIBUTE_DIRECTORY:
                    raise ServiceTransientJournalStartFenceError(
                        "attempt evidence directory contains an unknown member"
                    )
                raw = self._pin_file(
                    f"evidence:{directory_name}:{name}", directory_path / name
                )
                document = self._parse_canonical(
                    raw, _validate_attempt_evidence, label="attempt evidence"
                )
                directory_attempt = directory_name[: -len(".evidence")]
                evidence_history = histories.get(folded)
                if evidence_history is None:
                    raise ServiceTransientJournalStartFenceError(
                        "runtime qualification artifact has no durable history"
                    )
                _validate_qualification_artifact(
                    name=name,
                    raw=raw,
                    document=document,
                    directory_attempt=directory_attempt,
                    history=evidence_history,
                    current_attempt=identity.attempt_id,
                    current_role=identity.role,
                )

        component = f"{identity.attempt_id}-{identity.nonce}"
        workspace = _WORKSPACE_PARENT / component
        workspace_entries = self._pin_directory(
            "workspace", workspace, cooperative_controller_owner=True
        )
        if {name for name, _ in workspace_entries} != {
            "workspace_binding.json",
            "runtime-canary",
        }:
            raise ServiceTransientJournalStartFenceError(
                "attempt workspace namespace is not closed"
            )
        binding_raw = self._pin_file(
            "workspace_binding", workspace / "workspace_binding.json"
        )
        binding = self._parse_canonical(
            binding_raw,
            _validate_attempt_workspace_binding,
            label="attempt workspace binding",
        )
        if binding != {
            "schema_version": "qrh-deployment-attempt-workspace/v1",
            "attempt_id": identity.attempt_id,
            "nonce": identity.nonce,
        }:
            raise ServiceTransientJournalStartFenceError(
                "attempt workspace binding differs from durable identity"
            )
        canary = workspace / "runtime-canary"
        canary_entries = self._pin_directory(
            "runtime_canary", canary, cooperative_controller_owner=True
        )
        roles = {name for name, attributes in canary_entries if attributes & _FILE_ATTRIBUTE_DIRECTORY}
        if identity.role not in roles or len(roles) != len(canary_entries):
            raise ServiceTransientJournalStartFenceError(
                "runtime-canary role namespace is not closed"
            )
        role_path = canary / identity.role
        role_entries = self._pin_directory(
            "runtime_canary_role", role_path, cooperative_controller_owner=True
        )
        if {name for name, _ in role_entries} != {"request.json", "state", "tmp"}:
            raise ServiceTransientJournalStartFenceError(
                "current runtime-canary role is not in pre-result state"
            )
        self._pin_file("runtime_canary_request", role_path / "request.json")
        state_path = role_path / "state"
        state_entries = self._pin_directory(
            "runtime_canary_state", state_path, cooperative_controller_owner=True
        )
        if {name for name, _ in state_entries} != {
            "comments.sqlite3",
            "research_workspace.sqlite3",
        }:
            raise ServiceTransientJournalStartFenceError(
                "runtime-canary state namespace is not closed"
            )
        for name, _attributes in state_entries:
            self._pin_file(
                f"runtime_canary_state:{name}",
                state_path / name,
                cooperative_controller_owner=True,
            )
        temporary_path = role_path / "tmp"
        if self._pin_directory(
            "runtime_canary_tmp",
            temporary_path,
            cooperative_controller_owner=True,
        ):
            raise ServiceTransientJournalStartFenceError(
                "runtime-canary tmp must be empty before child launch"
            )

        material = {
            "schema_version": "qrh-service-transient-journal-start-fence/v1",
            "attempt": identity.attempt_id,
            "nonce": identity.nonce,
            "role": identity.role,
            "start_nonce": identity.start_nonce,
            "authorization_sha256": identity.authorization_sha256,
            "journal_latest_sha256": latest["journal_sha256"],
            "directories": {
                key: list(value)
                for key, value in sorted(self._directory_snapshots.items())
            },
            "pins": {
                key: {
                    "path": str(value.path),
                    "identity": list(value.identity),
                    "raw_sha256": value.raw_sha256,
                }
                for key, value in sorted(self._pins.items())
            },
        }
        object.__setattr__(self, "_seal_sha256", identity_sha256(material))

    def _checkpoint(self, expected_index: int) -> None:
        self._assert_owner("live")
        if self._checkpoint_index != expected_index:
            raise ServiceTransientJournalStartFenceError(
                "transient journal checkpoint order is invalid"
            )
        try:
            for label, expected in self._directory_snapshots.items():
                pin = self._pins[label]
                if self._file_identity(pin.handle, pin.path, True) != pin.identity:
                    raise ServiceTransientJournalStartFenceError(
                        f"{label} directory identity drifted"
                    )
                first = self._enumerate(pin.path)
                second = self._enumerate(pin.path)
                if first != second or first != expected:
                    raise ServiceTransientJournalStartFenceError(
                        f"{label} directory namespace drifted"
                    )
            for label, pin in self._pins.items():
                if pin.directory:
                    continue
                if self._file_identity(pin.handle, pin.path, False) != pin.identity:
                    raise ServiceTransientJournalStartFenceError(
                        f"{label} file identity drifted"
                    )
                raw = self._read_handle(pin.handle)
                if hashlib.sha256(raw).hexdigest() != pin.raw_sha256:
                    raise ServiceTransientJournalStartFenceError(
                        f"{label} file bytes drifted"
                    )
        except BaseException as error:
            if isinstance(
                error, ServiceTransientJournalStartFenceOwnerCrashRequired
            ):
                object.__setattr__(self, "_state", "owner_crash_only")
            else:
                object.__setattr__(self, "_state", "revoked")
            raise
        object.__setattr__(self, "_checkpoint_index", expected_index + 1)

    def _bind_launcher_identity(self, *, token: object) -> ExactRuntimeLeaseIdentity:
        self._assert_owner("live")
        if token is not _LAUNCH_BIND_TOKEN:
            raise ServiceTransientJournalStartFenceError(
                "transient launch identity bind token is invalid"
            )
        return self._identity

    def checkpoint_before_create_job(self) -> None:
        self._checkpoint(0)

    def checkpoint_before_create_process(self) -> None:
        self._checkpoint(1)

    def checkpoint_before_resume(self) -> None:
        self._checkpoint(2)

    def checkpoint_after_resume_and_consume(self) -> str:
        self._checkpoint(3)
        seal = self._seal_sha256
        self._close_all()
        object.__setattr__(self, "_state", "consumed")
        return seal

    def close(self) -> None:
        if self._state in {"closed", "consumed"}:
            return
        self._assert_owner("live", "revoked")
        self._close_all()
        object.__setattr__(self, "_state", "closed")

    def _close_all(self) -> None:
        failure: BaseException | None = None
        try:
            current = self._api.GetCurrentProcess()
        except BaseException as error:
            object.__setattr__(self, "_state", "owner_crash_only")
            raise ServiceTransientJournalStartFenceOwnerCrashRequired(
                "existing-only current-process handle outcome is unknown"
            ) from error
        for pin in reversed(tuple(self._pins.values())):
            if pin.handle <= 0:
                continue
            try:
                if not self._api.DuplicateHandle(
                    current,
                    wintypes.HANDLE(pin.handle),
                    current,
                    None,
                    0,
                    False,
                    _DUPLICATE_CLOSE_SOURCE,
                ):
                    raise ServiceTransientJournalStartFenceOwnerCrashRequired(
                        "existing-only pin close outcome is unknown"
                    )
                pin.handle = 0
            except BaseException as error:
                if isinstance(
                    error, ServiceTransientJournalStartFenceOwnerCrashRequired
                ):
                    failure = failure or error
                else:
                    owner_crash = (
                        ServiceTransientJournalStartFenceOwnerCrashRequired(
                            "existing-only pin close outcome is unknown"
                        )
                    )
                    owner_crash.__cause__ = error
                    failure = failure or owner_crash
                break
        if failure is not None:
            object.__setattr__(self, "_state", "owner_crash_only")
            raise failure


class ProductionServiceTransientJournalStartFence:
    """Zero-argument product factory fixed to the existing production D layout."""

    __slots__ = ("_api", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production transient journal fence cannot be subclassed")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production transient journal fence is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, api: _ExistingOnlyApi, *, token: object) -> None:
        if token is not _FACTORY_TOKEN or type(api) is not _ExistingOnlyApi:
            raise TypeError("production transient journal fence provenance is invalid")
        object.__setattr__(self, "_sealed", False)
        self._api = api
        object.__setattr__(self, "_sealed", True)

    @classmethod
    def load_exact_d(cls) -> "ProductionServiceTransientJournalStartFence":
        return cls(_ExistingOnlyApi.load_exact_d(), token=_FACTORY_TOKEN)

    def pin_exact_identity(
        self, identity: ExactRuntimeLeaseIdentity
    ) -> LockedServiceTransientJournalStartFence:
        if type(identity) is not ExactRuntimeLeaseIdentity:
            raise TypeError("transient journal fence requires exact runtime identity")
        if tuple(identity.service_start_arguments)[0] != "exact-runtime":
            raise ServiceTransientJournalStartFenceError(
                "transient identity service arguments are not closed"
            )
        if subprocess.list2cmdline(list(identity.child_argv)) == "":
            raise ServiceTransientJournalStartFenceError(
                "transient identity child command line is empty"
            )
        return LockedServiceTransientJournalStartFence(
            self._api, identity, token=_FENCE_TOKEN
        )


__all__ = [
    "LockedServiceTransientJournalStartFence",
    "ProductionServiceTransientJournalStartFence",
    "ServiceTransientJournalStartFenceError",
    "ServiceTransientJournalStartFenceOwnerCrashRequired",
]
