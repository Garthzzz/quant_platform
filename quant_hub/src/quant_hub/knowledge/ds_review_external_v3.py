"""Fake-only external DS review v3 contract and durable state machine.

This module deliberately contains no HTTP, socket, TLS, Keyring, environment,
or subprocess implementation.  It models the irreversible boundaries needed
by a future independently approved transport while accepting only the sealed
``ScriptedFakeTransport`` used by public zero-network tests.

The existing :mod:`quant_hub.knowledge.ds_review` module remains the normative
zero-network v2 preregistration.  Nothing in this module can enable it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Final

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point

from .contracts import canonical_json
from .ds_review import (
    DS_REVIEW_DOSSIER_SCHEMA,
    DS_REVIEW_MODEL_ALIAS,
    DS_REVIEW_OUTPUT_SCHEMA,
    DS_REVIEW_PROVIDER_REVISION,
    ROUND_IDS,
    ProviderPin,
    default_synthetic_dossier,
    validate_review_output,
)


EXTERNAL_V3_MANIFEST_SCHEMA = "qrh-ds-public-synthetic-external-campaign/v3"
EXTERNAL_V3_RECEIPT_SCHEMA = "qrh-ds-public-synthetic-external-receipt/v3"
EXTERNAL_V3_LEDGER_SCHEMA = "qrh-ds-public-synthetic-external-ledger/v3"
EXTERNAL_V3_REQUEST_DERIVATION = "QRH_DS_EXTERNAL_DIALOGUE_DERIVATION_V3"
EXTERNAL_V3_TRANSPORT_STATE = "DISABLED_FAKE_ONLY"
EXTERNAL_V3_AUTHORITY = "ADVISORY_ONLY"
EXTERNAL_V3_MAX_JSON_DEPTH = 32
EXTERNAL_V3_ROUND_COUNT = 4
EXTERNAL_V3_PRIOR_FINDING_LIMIT = 8
EXTERNAL_V3_PRIOR_DISSENT_LIMIT = 4
EXTERNAL_V3_OUTPUT_ALLOWLIST = "QRH_DS_EXTERNAL_PUBLIC_OUTPUT_ALLOWLIST_V1"
EXTERNAL_V3_SUCCESS_REPLAY_SCHEMA = "qrh-ds-public-success-replay/v1"
EXTERNAL_V3_TERMINAL_COMMITMENT_SCHEMA = "qrh-ds-terminal-commitment/v1"
EXTERNAL_V3_DURABLE_WRITE_PROTOCOL = "QRH_DS_LOCAL_DURABLE_WRITE_V2"
EXTERNAL_V3_LEDGER_PLATFORM_STATE = "WINDOWS_DIRECTORY_STREAM_GUARDED_ONLY"

_LEDGER_APPLICATION_ID: Final[int] = 0x51524833
_LEDGER_USER_VERSION: Final[int] = 4
_SQLITE_INTEGER_MAX: Final[int] = (1 << 63) - 1
_STORAGE_VALIDATION_ATTEMPTS: Final[int] = 16
_SQLITE_PREINIT_SCHEMA: Final[str] = "qrh-ds-external-sqlite-preinit/v1"
_SQLITE_INITIALIZED_SCHEMA: Final[str] = "qrh-ds-external-sqlite-initialized/v1"
_SQLITE_BOOTSTRAP_MAX_BYTES: Final[int] = 16 * 1024 * 1024
_SQLITE_LOGICAL_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")
_SUCCESS_REPLAY_ROOT_NAME: Final[str] = ".ds-external-v3-success-replay"
_TERMINAL_COMMITMENT_ROOT_NAME: Final[str] = ".ds-external-v3-terminal-commitments"
_TERMINAL_COMMITMENT_MAX_BYTES: Final[int] = 16 * 1024
_SUCCESS_AUDIT_STATE: Final[str] = "VERIFIABLE_BY_PUBLIC_RAW_REPLAY"
_TERMINAL_AUDIT_STATE: Final[str] = "UNVERIFIABLE_NO_TRUSTED_ANCHOR"
_DURABLE_WRITE_KINDS: Final[frozenset[str]] = frozenset(
    {"SUCCESS_REPLAY", "TERMINAL_COMMITMENT"}
)
_DURABLE_WRITE_PHASES: Final[frozenset[str]] = frozenset(
    {"INTENT_DURABLE", "RECOVERY_REQUIRED", "SEALED_COMMITTED"}
)
_ARTIFACT_TARGET = re.compile(
    r"^(?:success|terminal)_dsext3_[0-9a-f]{32}_[0-3]_[0-9a-f]{64}_g[0-9]+\.(?:raw|json)$"
)

_TERMINAL_STATUS_ERROR_PAIRS: Final[frozenset[tuple[str, str]]] = frozenset(
    {
        ("FAILED_NO_RETRY", "KNOWN_RESPONSE_INVALID"),
        ("AMBIGUOUS_NO_RETRY", "WALL_CLOCK_TIMEOUT_AFTER_INTENT"),
        ("AMBIGUOUS_NO_RETRY", "PROCESS_LOST_AFTER_INTENT"),
        ("AMBIGUOUS_NO_RETRY", "TRANSPORT_RESULT_AMBIGUOUS"),
    }
)

_ZERO_SHA256: Final[str] = "0" * 64
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_CLAIM_NONCE = re.compile(r"^claim_[0-9a-f]{32}$")
_SAFE_PUBLIC_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SECRETISH = (
    re.compile(r"\bBearer\b", re.I),
    re.compile(r"\bsk-[A-Za-z0-9_-]+", re.I),
    re.compile(r"\b(?:password|passwd|secret|credential|authorization)\b", re.I),
    re.compile(r"\bapi[ _-]?key\b", re.I),
)

# External v3 intentionally accepts an enum-like, reviewed vocabulary rather
# than arbitrary free prose.  This is separate from the v2 scanner: v2 remains
# byte-for-byte unchanged, while the future external boundary gets a positive
# policy whose identity is frozen in every campaign manifest.
_PUBLIC_OUTPUT_WORDS: Final[frozenset[str]] = frozenset(
    """
    A AFTER AGAINST ALL AMBIGUOUS AN AND ARCHITECTURE ASSUME ASSUMPTION
    ASSUMPTIONS AT ATOMIC ATTEMPT ATTEMPTS AUTHORITY BARRIER BEFORE BEHAVIOR
    BIND BINDING BLOCK BOUNDED BREAK BY CAN CANNOT CAS CHANGE CHANGES CHECK
    CLAIM COMMIT CONDITIONAL CONFLICT CONSUME COST COUNT CRASH CRITIQUE CURRENT
    DATA DEADLINE DECISION DISPATCH DO DOES DURABLE EFFECT ENUM EVIDENCE EXACT
    EXCEED EXTERNAL FAIL FAILURE FALSIFICATION FINAL FINDING FINDINGS FIXED FOR
    FROM GATE HASH IDENTIFIER IDENTITY IDEMPOTENCY IF IMPACT IN INCOMPLETE
    INCONSISTENT INTENT INVALID INVARIANT IS JOB KILL LEDGER LIMIT LOCAL LOSS
    MATRIX MEANS MECHANISM MINIMAL MISSING MODEL MUST NEXT NO NONCE NOT OF ON
    ONCE ONE ONLY OUTPUT OWN OWNER PATH PER PERMIT PERSISTED POLICY PRIOR PROCESS
    PROJECTION PROPOSE PROVIDER PUBLIC RAW RECOMMENDATION RECOMMENDATIONS
    RELEASE REMAINS REQUEST RESPONSE RETRY REVIEW RISK ROUND SAFE SCENARIO
    SCENARIOS SCHEMA SEND SHALL SIDE SQLITE STATE STATUS STRESS SUCCESS
    SYNTHETIC TEST TESTS THE THIRTY TIMEOUT TO TOKEN TOTAL TRANSITION TRANSPORT
    TWO UPDATE USAGE USE VALIDATE VALIDATED VERIFIER WALL WHEN WHY WITH WITHOUT
    WORKER WORKERS WRITE ZERO
    """.split()
)
_PUBLIC_OUTPUT_TEXT = re.compile(r"^[A-Z0-9][A-Z0-9 .,;:()'?!+=*_-]{0,1199}$")
_PUBLIC_OUTPUT_IDENTIFIER = re.compile(r"^(?:F-[0-9]{3}|M[0-9]{2}|[0-9]+)$")
_PUBLIC_OUTPUT_LOCATORS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"),
    re.compile(r"(?<![0-9A-F])(?:[0-9A-F]{1,4}:){2,}[0-9A-F:]{0,39}(?![0-9A-F])", re.I),
    re.compile(r"(?<![0-9A-F])::[0-9A-F]{1,4}(?![0-9A-F])", re.I),
    re.compile(
        r"\b(?:LOCALHOST|[A-Z0-9-]+(?:\.[A-Z0-9-]+)*):[0-9]{1,5}\b",
        re.I,
    ),
    re.compile(r"\b[A-Z][A-Z0-9+.-]{1,15}://", re.I),
    re.compile(r"\b(?:[A-Z0-9-]{1,63}\.)+[A-Z]{2,63}\b", re.I),
    re.compile(r"%[0-9A-F]{2}", re.I),
)


if os.name == "nt":
    # ``os.open(..., dir_fd=...)`` is not implemented on Windows.  Artifact
    # creation therefore uses NT's RootDirectory contract: every child is a
    # single relative name opened beneath a pinned, already-validated
    # directory handle.  No provider input reaches these names.
    class _WinUnicodeString(ctypes.Structure):
        _fields_ = (
            ("Length", wintypes.USHORT),
            ("MaximumLength", wintypes.USHORT),
            ("Buffer", wintypes.LPWSTR),
        )


    class _WinObjectAttributes(ctypes.Structure):
        _fields_ = (
            ("Length", wintypes.ULONG),
            ("RootDirectory", wintypes.HANDLE),
            ("ObjectName", ctypes.POINTER(_WinUnicodeString)),
            ("Attributes", wintypes.ULONG),
            ("SecurityDescriptor", wintypes.LPVOID),
            ("SecurityQualityOfService", wintypes.LPVOID),
        )


    class _WinIoStatusBlock(ctypes.Structure):
        _fields_ = (
            ("Status", ctypes.c_ssize_t),
            ("Information", ctypes.c_size_t),
        )


    class _WinFileTime(ctypes.Structure):
        _fields_ = (("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD))


    class _WinHandleInformation(ctypes.Structure):
        _fields_ = (
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", _WinFileTime),
            ("ftLastAccessTime", _WinFileTime),
            ("ftLastWriteTime", _WinFileTime),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        )


    class _WinFileBasicInfo(ctypes.Structure):
        _fields_ = (
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
        )


    _WIN_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _WIN_NTDLL = ctypes.WinDLL("ntdll", use_last_error=True)
    _WIN_INVALID_HANDLE = ctypes.c_void_p(-1).value
    _WIN_FILE_ATTRIBUTE_READONLY = 0x00000001
    _WIN_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _WIN_FILE_ATTRIBUTE_NORMAL = 0x00000080
    _WIN_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _WIN_FILE_READ_DATA = 0x0001
    _WIN_FILE_LIST_DIRECTORY = 0x0001
    _WIN_FILE_WRITE_DATA = 0x0002
    _WIN_FILE_READ_ATTRIBUTES = 0x0080
    _WIN_FILE_WRITE_ATTRIBUTES = 0x0100
    _WIN_SYNCHRONIZE = 0x00100000
    _WIN_FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
    _WIN_FILE_OPEN = 0x00000001
    _WIN_FILE_CREATE = 0x00000002
    _WIN_FILE_OPEN_IF = 0x00000003
    _WIN_FILE_DIRECTORY_FILE = 0x00000001
    _WIN_FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
    _WIN_FILE_NON_DIRECTORY_FILE = 0x00000040
    _WIN_FILE_OPEN_REPARSE_POINT = 0x00200000
    _WIN_OBJ_CASE_INSENSITIVE = 0x00000040
    _WIN_OPEN_EXISTING = 3
    _WIN_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _WIN_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _WIN_ERROR_FILE_EXISTS = 80
    _WIN_ERROR_ALREADY_EXISTS = 183
    _WIN_ERROR_FILE_NOT_FOUND = 2
    _WIN_ERROR_PATH_NOT_FOUND = 3
    _WIN_FILE_BASIC_INFO_CLASS = 0

    _WIN_KERNEL32.CreateFileW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    _WIN_KERNEL32.CreateFileW.restype = wintypes.HANDLE
    _WIN_KERNEL32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _WIN_KERNEL32.CloseHandle.restype = wintypes.BOOL
    _WIN_KERNEL32.GetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_WinHandleInformation),
    )
    _WIN_KERNEL32.GetFileInformationByHandle.restype = wintypes.BOOL
    _WIN_KERNEL32.GetFileInformationByHandleEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    _WIN_KERNEL32.GetFileInformationByHandleEx.restype = wintypes.BOOL
    _WIN_KERNEL32.SetFileInformationByHandle.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    )
    _WIN_KERNEL32.SetFileInformationByHandle.restype = wintypes.BOOL
    _WIN_KERNEL32.ReadFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    _WIN_KERNEL32.ReadFile.restype = wintypes.BOOL
    _WIN_KERNEL32.WriteFile.argtypes = (
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    )
    _WIN_KERNEL32.WriteFile.restype = wintypes.BOOL
    _WIN_KERNEL32.FlushFileBuffers.argtypes = (wintypes.HANDLE,)
    _WIN_KERNEL32.FlushFileBuffers.restype = wintypes.BOOL
    _WIN_KERNEL32.SetFilePointerEx.argtypes = (
        wintypes.HANDLE,
        ctypes.c_longlong,
        ctypes.POINTER(ctypes.c_longlong),
        wintypes.DWORD,
    )
    _WIN_KERNEL32.SetFilePointerEx.restype = wintypes.BOOL
    _WIN_NTDLL.NtCreateFile.argtypes = (
        ctypes.POINTER(wintypes.HANDLE),
        wintypes.DWORD,
        ctypes.POINTER(_WinObjectAttributes),
        ctypes.POINTER(_WinIoStatusBlock),
        wintypes.LPVOID,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.ULONG,
        wintypes.LPVOID,
        wintypes.ULONG,
    )
    _WIN_NTDLL.NtCreateFile.restype = ctypes.c_long
    _WIN_NTDLL.RtlNtStatusToDosError.argtypes = (ctypes.c_long,)
    _WIN_NTDLL.RtlNtStatusToDosError.restype = wintypes.ULONG


    def _win_close(handle: int) -> None:
        if handle not in {0, _WIN_INVALID_HANDLE}:
            _WIN_KERNEL32.CloseHandle(wintypes.HANDLE(handle))


    def _win_handle_information(handle: int) -> _WinHandleInformation:
        value = _WinHandleInformation()
        if not _WIN_KERNEL32.GetFileInformationByHandle(
            wintypes.HANDLE(handle), ctypes.byref(value)
        ):
            raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle failed")
        return value


    def _win_handle_identity(handle: int) -> tuple[int, int]:
        value = _win_handle_information(handle)
        return (
            int(value.dwVolumeSerialNumber),
            (int(value.nFileIndexHigh) << 32) | int(value.nFileIndexLow),
        )


    def _win_open_absolute(
        path: Path, *, directory: bool, prevent_delete: bool = False
    ) -> int:
        access = _WIN_FILE_READ_ATTRIBUTES | _WIN_SYNCHRONIZE
        flags = _WIN_FILE_FLAG_OPEN_REPARSE_POINT
        if directory:
            access |= _WIN_FILE_LIST_DIRECTORY | 0x0002 | 0x0004
            flags |= _WIN_FILE_FLAG_BACKUP_SEMANTICS
        share = _WIN_FILE_SHARE_ALL
        if prevent_delete:
            share &= ~0x00000004
        handle = _WIN_KERNEL32.CreateFileW(
            str(path),
            access,
            share,
            None,
            _WIN_OPEN_EXISTING,
            flags,
            None,
        )
        value = int(handle) if handle is not None else 0
        if value in {0, _WIN_INVALID_HANDLE}:
            raise OSError(ctypes.get_last_error(), "CreateFileW failed")
        return value


    def _win_nt_open_relative(
        parent_handle: int,
        name: str,
        *,
        directory: bool,
        create: bool,
        writable: bool,
        share_delete: bool = True,
    ) -> tuple[int, int]:
        if (
            type(name) is not str
            or not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or "\x00" in name
        ):
            raise OSError(_WIN_ERROR_PATH_NOT_FOUND, "relative object name is invalid")
        buffer = ctypes.create_unicode_buffer(name)
        encoded_length = len(name.encode("utf-16-le"))
        unicode_name = _WinUnicodeString(
            encoded_length,
            encoded_length + 2,
            ctypes.cast(buffer, wintypes.LPWSTR),
        )
        attributes = _WinObjectAttributes(
            ctypes.sizeof(_WinObjectAttributes),
            wintypes.HANDLE(parent_handle),
            ctypes.pointer(unicode_name),
            _WIN_OBJ_CASE_INSENSITIVE,
            None,
            None,
        )
        iosb = _WinIoStatusBlock()
        result = wintypes.HANDLE()
        access = _WIN_FILE_READ_ATTRIBUTES | _WIN_SYNCHRONIZE
        if directory:
            access |= _WIN_FILE_LIST_DIRECTORY | 0x0002 | 0x0004
        else:
            access |= _WIN_FILE_READ_DATA
            if writable:
                access |= _WIN_FILE_WRITE_DATA | _WIN_FILE_WRITE_ATTRIBUTES
        options = (
            _WIN_FILE_SYNCHRONOUS_IO_NONALERT
            | _WIN_FILE_OPEN_REPARSE_POINT
            | (
                _WIN_FILE_DIRECTORY_FILE
                if directory
                else _WIN_FILE_NON_DIRECTORY_FILE
            )
        )
        disposition = (
            _WIN_FILE_OPEN_IF if directory and create else
            _WIN_FILE_CREATE if create else
            _WIN_FILE_OPEN
        )
        status = int(
            _WIN_NTDLL.NtCreateFile(
                ctypes.byref(result),
                access,
                ctypes.byref(attributes),
                ctypes.byref(iosb),
                None,
                _WIN_FILE_ATTRIBUTE_NORMAL,
                (
                    _WIN_FILE_SHARE_ALL
                    if share_delete
                    else _WIN_FILE_SHARE_ALL & ~0x00000004
                ),
                disposition,
                options,
                None,
                0,
            )
        )
        if status < 0:
            error = int(_WIN_NTDLL.RtlNtStatusToDosError(status))
            raise OSError(error, "NtCreateFile relative open failed", name)
        if result.value in {None, 0, _WIN_INVALID_HANDLE}:
            raise OSError(6, "NtCreateFile returned an invalid handle", name)
        return int(result.value), int(iosb.Information)


    def _win_require_directory_handle(handle: int) -> None:
        value = _win_handle_information(handle)
        if (
            not int(value.dwFileAttributes) & _WIN_FILE_ATTRIBUTE_DIRECTORY
            or int(value.dwFileAttributes) & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise OSError(4390, "managed directory handle is unsafe")


    def _win_require_file_handle(handle: int, *, readonly: bool) -> _WinHandleInformation:
        value = _win_handle_information(handle)
        attributes = int(value.dwFileAttributes)
        if (
            attributes & _WIN_FILE_ATTRIBUTE_DIRECTORY
            or attributes & _WIN_FILE_ATTRIBUTE_REPARSE_POINT
            or int(value.nNumberOfLinks) != 1
            or (readonly and not attributes & _WIN_FILE_ATTRIBUTE_READONLY)
        ):
            raise OSError(4390, "managed file handle is unsafe")
        return value


    def _win_verify_absolute_identity(
        path: Path,
        expected_handle: int,
        *,
        directory: bool,
        readonly: bool = True,
    ) -> None:
        observed = _win_open_absolute(path, directory=directory)
        try:
            if directory:
                _win_require_directory_handle(observed)
            else:
                _win_require_file_handle(observed, readonly=readonly)
            if _win_handle_identity(observed) != _win_handle_identity(expected_handle):
                raise OSError(4390, "managed path identity changed")
        finally:
            _win_close(observed)


    def _win_read_all(handle: int, *, max_bytes: int) -> bytes:
        position = ctypes.c_longlong()
        if not _WIN_KERNEL32.SetFilePointerEx(
            wintypes.HANDLE(handle),
            ctypes.c_longlong(0),
            ctypes.byref(position),
            0,
        ):
            raise OSError(ctypes.get_last_error(), "SetFilePointerEx failed")
        chunks: list[bytes] = []
        observed = 0
        while True:
            capacity = min(64 * 1024, max_bytes + 1 - observed)
            if capacity <= 0:
                raise OSError(223, "managed file exceeds byte cap")
            buffer = ctypes.create_string_buffer(capacity)
            read = wintypes.DWORD()
            if not _WIN_KERNEL32.ReadFile(
                wintypes.HANDLE(handle), buffer, capacity, ctypes.byref(read), None
            ):
                raise OSError(ctypes.get_last_error(), "ReadFile failed")
            if read.value == 0:
                break
            chunks.append(buffer.raw[: read.value])
            observed += int(read.value)
            if observed > max_bytes:
                raise OSError(223, "managed file exceeds byte cap")
        return b"".join(chunks)


    def _win_write_all(handle: int, content: bytes) -> None:
        offset = 0
        while offset < len(content):
            chunk = content[offset : offset + 64 * 1024]
            buffer = ctypes.create_string_buffer(chunk)
            written = wintypes.DWORD()
            if not _WIN_KERNEL32.WriteFile(
                wintypes.HANDLE(handle),
                buffer,
                len(chunk),
                ctypes.byref(written),
                None,
            ):
                raise OSError(ctypes.get_last_error(), "WriteFile failed")
            if written.value <= 0:
                raise OSError(29, "WriteFile made no progress")
            offset += int(written.value)


    def _win_flush(handle: int) -> None:
        if not _WIN_KERNEL32.FlushFileBuffers(wintypes.HANDLE(handle)):
            raise OSError(ctypes.get_last_error(), "FlushFileBuffers failed")


    def _win_seal_readonly(handle: int) -> None:
        value = _WinFileBasicInfo()
        if not _WIN_KERNEL32.GetFileInformationByHandleEx(
            wintypes.HANDLE(handle),
            _WIN_FILE_BASIC_INFO_CLASS,
            ctypes.byref(value),
            ctypes.sizeof(value),
        ):
            raise OSError(ctypes.get_last_error(), "file attribute read failed")
        attributes = int(value.FileAttributes) | _WIN_FILE_ATTRIBUTE_READONLY
        if attributes != _WIN_FILE_ATTRIBUTE_NORMAL:
            attributes &= ~_WIN_FILE_ATTRIBUTE_NORMAL
        value.FileAttributes = attributes
        if not _WIN_KERNEL32.SetFileInformationByHandle(
            wintypes.HANDLE(handle),
            _WIN_FILE_BASIC_INFO_CLASS,
            ctypes.byref(value),
            ctypes.sizeof(value),
        ):
            raise OSError(ctypes.get_last_error(), "readonly seal failed")
        _win_require_file_handle(handle, readonly=True)

_ROUND_OBJECTIVES: Final[dict[str, str]] = {
    ROUND_IDS[0]: "FIND_FLAWS_AND_MISSING_FALSIFICATION_TESTS_WITHOUT_FORMAL_MAPPING_OR_OBSERVED_OUTCOME.",
    ROUND_IDS[1]: "DISCUSS_THE_PRIOR_BLIND_FINDINGS_AND_CRITIQUE_THE_DISCLOSED_STRESS_MATRIX.",
    ROUND_IDS[2]: "DISCUSS_THE_PRIOR_CRITIQUE_AND_PROPOSE_MINIMAL_CHANGES_FROM_SYNTHETIC_OUTCOME_CODES.",
    ROUND_IDS[3]: "DISCUSS_THE_PRIOR_RECOMMENDATIONS_AND_GIVE_FINAL_DISSENT_WITHOUT_RELEASE_AUTHORITY.",
}

_SYSTEM_INSTRUCTION: Final[str] = (
    "INDEPENDENT_ARCHITECTURE_VERIFIER. PAYLOAD_PUBLIC_SYNTHETIC_ENUM_ONLY. "
    "RETURN_EXACT_JSON_SCHEMA. FORBID_TOOLS_URLS_PATHS_SENSITIVE_MATERIAL_"
    "PERSONAL_IDENTIFIERS_EXTERNAL_FACTS_SOURCE_QUOTES. PRINTABLE_ASCII_ONLY. "
    "FINDINGS_ADVISORY_ONLY_NO_RELEASE_AUTHORITY. "
    "DISCUSS_ONLY_THE_PRIOR_VALIDATED_ADVISORY_WHEN_PRESENT. "
    "FREE_PROSE_USE_UPPERCASE_ENUM_SYMBOLS."
)


class ExternalV3Error(RuntimeError):
    """Base fail-closed v3 error."""


class ExternalV3PolicyError(ExternalV3Error):
    """A canonical identity, budget, request, or response was invalid."""


class ExternalV3StateError(ExternalV3Error):
    """A durable state transition failed its compare-and-swap."""


class ExternalV3Disabled(ExternalV3Error):
    """A caller attempted to reach a real external transport."""


class _FakeAmbiguousAfterIntent(ExternalV3Error):
    """Internal scripted cut after the durable dispatch intent."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_json(value: object) -> str:
    return _sha256_bytes(canonical_json(value).encode("utf-8"))


def _require_sha256(value: object, *, label: str) -> str:
    if type(value) is not str or not _SHA256.fullmatch(value):
        raise ExternalV3PolicyError(f"{label} must be a canonical SHA-256")
    return value


def _require_exact_int(value: object, *, label: str, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise ExternalV3PolicyError(f"{label} must be an exact bounded integer")
    return value


def _require_finite_float(value: object, *, label: str, minimum: float = 0.0) -> float:
    if type(value) is not float or not math.isfinite(value) or value < minimum:
        raise ExternalV3PolicyError(f"{label} must be a finite bounded float")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ExternalV3PolicyError("JSON contains a duplicate object key")
        result[key] = value
    return result


def _prescan_json_depth(text: str, *, label: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > EXTERNAL_V3_MAX_JSON_DEPTH:
                raise ExternalV3PolicyError(f"{label} exceeds the JSON depth limit")
        elif character in "]}":
            depth -= 1
            if depth < 0:
                raise ExternalV3PolicyError(f"{label} has invalid JSON nesting")
    if depth != 0 or in_string:
        raise ExternalV3PolicyError(f"{label} has invalid JSON nesting")


def _validate_json_tree(value: object, *, label: str, depth: int = 1) -> None:
    if depth > EXTERNAL_V3_MAX_JSON_DEPTH:
        raise ExternalV3PolicyError(f"{label} exceeds the JSON depth limit")
    if value is None or type(value) in (str, int, bool):
        return
    if type(value) is float:
        if value != value or value in (float("inf"), float("-inf")):
            raise ExternalV3PolicyError(f"{label} contains a non-finite number")
        return
    if type(value) is list:
        for member in value:
            _validate_json_tree(member, label=label, depth=depth + 1)
        return
    if type(value) is dict:
        for key, member in value.items():
            if type(key) is not str:
                raise ExternalV3PolicyError(f"{label} contains a non-string key")
            _validate_json_tree(member, label=label, depth=depth + 1)
        return
    raise ExternalV3PolicyError(f"{label} contains an unsupported JSON value")


def _strict_json_loads(raw: bytes | str, *, label: str) -> object:
    try:
        text = raw.decode("utf-8") if type(raw) is bytes else raw
        if type(text) is not str:
            raise TypeError
        _prescan_json_depth(text, label=label)
        value = json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except ExternalV3PolicyError:
        raise
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError):
        raise ExternalV3PolicyError(f"{label} is not strict UTF-8 JSON") from None
    _validate_json_tree(value, label=label)
    return value


def _scan_public_token(value: object, *, label: str) -> str:
    if type(value) is not str or not _SAFE_PUBLIC_TOKEN.fullmatch(value):
        raise ExternalV3PolicyError(f"{label} is not a safe public token")
    if any(pattern.search(value) for pattern in _SECRETISH):
        raise ExternalV3PolicyError(f"{label} resembles protected material")
    return value


def _reject_network_locators(value: object, *, depth: int = 0) -> None:
    """Reject locator syntax independently of the structural/vocabulary parser."""

    if depth > EXTERNAL_V3_MAX_JSON_DEPTH:
        return
    if type(value) is str:
        if any(pattern.search(value) for pattern in _PUBLIC_OUTPUT_LOCATORS):
            raise ExternalV3PolicyError(
                "advisory prose contains a network locator"
            )
        return
    if type(value) is list:
        for member in value:
            _reject_network_locators(member, depth=depth + 1)
        return
    if type(value) is dict:
        for member in value.values():
            _reject_network_locators(member, depth=depth + 1)


def _validate_external_public_advisory(
    value: object, *, round_id: str
) -> dict[str, object]:
    """Apply the external positive vocabulary after the unchanged v2 scanner."""

    _reject_network_locators(value)
    try:
        advisory = validate_review_output(value, round_id=round_id)
    except Exception:
        raise ExternalV3PolicyError(
            "advisory failed the public-output contract"
        ) from None
    prose: list[str] = []
    for finding in advisory["findings"]:
        assert type(finding) is dict
        prose.extend(
            str(finding[name])
            for name in (
                "rationale",
                "falsification_test",
                "minimal_change",
                "residual_risk",
            )
        )
    dissent = advisory["dissent"]
    assert type(dissent) is dict
    for name in ("why_not_release", "missing_stress_cases", "assumptions_to_break"):
        rows = dissent[name]
        assert type(rows) is list
        prose.extend(str(row) for row in rows)
    for text in prose:
        if any(pattern.search(text) for pattern in _PUBLIC_OUTPUT_LOCATORS):
            raise ExternalV3PolicyError(
                "advisory prose contains a network locator"
            )
        if not _PUBLIC_OUTPUT_TEXT.fullmatch(text):
            raise ExternalV3PolicyError(
                "advisory prose is outside the external positive text policy"
            )
        for token in re.findall(r"[A-Z][A-Z0-9-]*|[0-9]+", text):
            if token not in _PUBLIC_OUTPUT_WORDS and not _PUBLIC_OUTPUT_IDENTIFIER.fullmatch(
                token
            ):
                raise ExternalV3PolicyError(
                    "advisory prose contains a token outside the external allowlist"
                )
    return advisory


@dataclass(frozen=True, slots=True)
class PricingBudgetV3:
    """Integer-only preregistered usage and cost envelope.

    Rates are micro-units of ``currency`` per one million tokens.  They are
    meaningless without the independently pinned pricing evidence hash.
    """

    currency: str
    prompt_micros_per_million: int
    completion_micros_per_million: int
    pricing_evidence_sha256: str
    max_campaign_cost_micros: int
    max_prompt_tokens_per_round: int
    max_completion_tokens_per_round: int
    max_campaign_total_tokens: int
    max_request_bytes: int
    max_response_bytes: int
    per_round_deadline_seconds: int
    campaign_deadline_seconds: int

    def validate(self) -> None:
        if self.currency not in {"USD_MICRO", "CNY_MICRO"}:
            raise ExternalV3PolicyError("pricing currency is not an approved integer unit")
        for label in (
            "prompt_micros_per_million",
            "completion_micros_per_million",
            "max_campaign_cost_micros",
            "max_prompt_tokens_per_round",
            "max_completion_tokens_per_round",
            "max_campaign_total_tokens",
            "max_request_bytes",
            "max_response_bytes",
            "per_round_deadline_seconds",
            "campaign_deadline_seconds",
        ):
            _require_exact_int(getattr(self, label), label=label, minimum=1)
        _require_sha256(
            self.pricing_evidence_sha256, label="pricing evidence hash"
        )
        if not 1024 <= self.max_request_bytes <= 256 * 1024:
            raise ExternalV3PolicyError("request byte cap is outside the reviewed range")
        if not 1024 <= self.max_response_bytes <= 256 * 1024:
            raise ExternalV3PolicyError("response byte cap is outside the reviewed range")
        if not 1 <= self.per_round_deadline_seconds <= 600:
            raise ExternalV3PolicyError("per-round deadline is outside the reviewed range")
        if self.campaign_deadline_seconds > self.per_round_deadline_seconds * 4:
            raise ExternalV3PolicyError("campaign deadline exceeds four bounded rounds")
        worst_tokens = EXTERNAL_V3_ROUND_COUNT * (
            self.max_prompt_tokens_per_round
            + self.max_completion_tokens_per_round
        )
        if self.max_campaign_total_tokens < worst_tokens:
            raise ExternalV3PolicyError("campaign token budget cannot cover its frozen rounds")
        if self.max_campaign_cost_micros < EXTERNAL_V3_ROUND_COUNT * self.worst_round_cost_micros():
            raise ExternalV3PolicyError("campaign cost budget cannot cover its frozen rounds")
        if any(
            value > _SQLITE_INTEGER_MAX
            for value in (
                self.prompt_micros_per_million,
                self.completion_micros_per_million,
                self.max_campaign_cost_micros,
                self.max_prompt_tokens_per_round,
                self.max_completion_tokens_per_round,
                self.max_campaign_total_tokens,
                self.worst_round_cost_micros(),
            )
        ):
            raise ExternalV3PolicyError("pricing budget exceeds the durable integer range")

    def cost_micros(self, *, prompt_tokens: int, completion_tokens: int) -> int:
        _require_exact_int(prompt_tokens, label="prompt usage")
        _require_exact_int(completion_tokens, label="completion usage")
        prompt_cost = (
            prompt_tokens * self.prompt_micros_per_million + 999_999
        ) // 1_000_000
        completion_cost = (
            completion_tokens * self.completion_micros_per_million + 999_999
        ) // 1_000_000
        return prompt_cost + completion_cost

    def worst_round_cost_micros(self) -> int:
        return self.cost_micros(
            prompt_tokens=self.max_prompt_tokens_per_round,
            completion_tokens=self.max_completion_tokens_per_round,
        )


@dataclass(frozen=True, slots=True)
class ExternalCampaignV3:
    campaign_id: str
    manifest_bytes: bytes
    manifest_sha256: str
    pin: ProviderPin
    identity_evidence_sha256: str
    pricing: PricingBudgetV3
    transport_build_sha256: str


@dataclass(frozen=True, slots=True)
class BoundExternalRoundV3:
    campaign_id: str
    manifest_sha256: str
    round_id: str
    ordinal: int
    request_bytes: bytes
    request_sha256: str
    prior_output_sha256: str
    prior_output_chain_sha256: str


@dataclass(frozen=True, slots=True)
class ClaimedExternalRoundV3:
    bound: BoundExternalRoundV3
    owner_nonce: str
    owner_nonce_sha256: str


@dataclass(frozen=True, slots=True)
class DispatchIntentV3:
    bound: BoundExternalRoundV3
    owner_nonce_sha256: str
    dispatch_intent_sha256: str
    reserved_cost_micros: int
    campaign_elapsed_seconds: float


@dataclass(frozen=True, slots=True)
class ParsedExternalResponseV3:
    advisory: dict[str, object]
    advisory_bytes: bytes
    advisory_sha256: str
    raw_response_sha256: str
    response_id_sha256: str
    created_at: str
    returned_model: str
    system_fingerprint_sha256: str
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int
    cost_micros: int
    elapsed_seconds: float
    response_bytes: int


def _provider_projection(pin: ProviderPin) -> dict[str, str]:
    pin.validate()
    return asdict(pin)


def _dossier_projection() -> list[dict[str, object]]:
    dossier = default_synthetic_dossier()
    dossier.validate()
    return [asdict(row) for row in dossier.observations]


def _round_template_rows() -> list[dict[str, object]]:
    rows = []
    for ordinal, round_id in enumerate(ROUND_IDS):
        template = {
            "ordinal": ordinal,
            "round_id": round_id,
            "objective": _ROUND_OBJECTIVES[round_id],
            "disclosure": (
                "BLIND_BEHAVIOR"
                if ordinal == 0
                else "MAPPING_AND_MATRIX"
                if ordinal == 1
                else "MAPPING_MATRIX_AND_OUTCOMES"
            ),
            "prior_advisory_required": ordinal > 0,
        }
        rows.append({**template, "template_sha256": _sha256_json(template)})
    return rows


def _public_output_locator_policy_sha256() -> str:
    return _sha256_json(
        [
            {"pattern": pattern.pattern, "flags": pattern.flags}
            for pattern in _PUBLIC_OUTPUT_LOCATORS
        ]
    )


def prepare_external_campaign_v3(
    *,
    pin: ProviderPin,
    identity_evidence_sha256: str,
    pricing: PricingBudgetV3,
    transport_build_sha256: str,
) -> ExternalCampaignV3:
    """Freeze a fake-only external campaign without touching any credential."""

    campaign = prepare_external_campaign_v3_unchecked(
        pin=pin,
        identity_evidence_sha256=identity_evidence_sha256,
        pricing=pricing,
        transport_build_sha256=transport_build_sha256,
    )
    validate_external_campaign_v3(campaign)
    return campaign


def validate_external_campaign_v3(campaign: ExternalCampaignV3) -> None:
    if type(campaign) is not ExternalCampaignV3:
        raise ExternalV3PolicyError("external campaign type is invalid")
    _require_sha256(campaign.manifest_sha256, label="campaign manifest hash")
    if _sha256_bytes(campaign.manifest_bytes) != campaign.manifest_sha256:
        raise ExternalV3PolicyError("campaign manifest bytes drifted")
    value = _strict_json_loads(campaign.manifest_bytes, label="campaign manifest")
    if type(value) is not dict or canonical_json(value).encode("utf-8") != campaign.manifest_bytes:
        raise ExternalV3PolicyError("campaign manifest is not canonical")
    expected = prepare_external_campaign_v3_unchecked(
        pin=campaign.pin,
        identity_evidence_sha256=campaign.identity_evidence_sha256,
        pricing=campaign.pricing,
        transport_build_sha256=campaign.transport_build_sha256,
    )
    if expected != campaign:
        raise ExternalV3PolicyError("campaign manifest does not match frozen construction")


def prepare_external_campaign_v3_unchecked(
    *,
    pin: ProviderPin,
    identity_evidence_sha256: str,
    pricing: PricingBudgetV3,
    transport_build_sha256: str,
) -> ExternalCampaignV3:
    """Internal non-recursive campaign constructor used by validation."""

    pin.validate()
    pricing.validate()
    _require_sha256(identity_evidence_sha256, label="identity evidence hash")
    _require_sha256(transport_build_sha256, label="transport build hash")
    provider = _provider_projection(pin)
    dossier = _dossier_projection()
    core = {
        "schema_version": EXTERNAL_V3_MANIFEST_SCHEMA,
        "provider_pin": provider,
        "provider_pin_sha256": _sha256_json(provider),
        "identity_evidence_sha256": identity_evidence_sha256,
        "pricing_budget": asdict(pricing),
        "pricing_budget_sha256": _sha256_json(asdict(pricing)),
        "transport_build_sha256": transport_build_sha256,
        "request_derivation": EXTERNAL_V3_REQUEST_DERIVATION,
        "public_output_allowlist": EXTERNAL_V3_OUTPUT_ALLOWLIST,
        "public_output_allowlist_sha256": _sha256_json(
            sorted(_PUBLIC_OUTPUT_WORDS)
        ),
        "public_output_locator_policy_sha256": (
            _public_output_locator_policy_sha256()
        ),
        "success_replay_schema": EXTERNAL_V3_SUCCESS_REPLAY_SCHEMA,
        "terminal_commitment_schema": EXTERNAL_V3_TERMINAL_COMMITMENT_SCHEMA,
        "durable_write_protocol": EXTERNAL_V3_DURABLE_WRITE_PROTOCOL,
        "ledger_platform_state": EXTERNAL_V3_LEDGER_PLATFORM_STATE,
        "terminal_audit_verifiability": _TERMINAL_AUDIT_STATE,
        "dossier_schema": DS_REVIEW_DOSSIER_SCHEMA,
        "dossier_sha256": _sha256_json(dossier),
        "rounds": _round_template_rows(),
        "external_transport_state": EXTERNAL_V3_TRANSPORT_STATE,
        "authority": EXTERNAL_V3_AUTHORITY,
    }
    campaign_id = "dsext3_" + _sha256_json(core)[:32]
    raw = canonical_json({"campaign_id": campaign_id, **core}).encode("utf-8")
    return ExternalCampaignV3(
        campaign_id,
        raw,
        _sha256_bytes(raw),
        pin,
        identity_evidence_sha256,
        pricing,
        transport_build_sha256,
    )


def _prior_advisory_projection(value: dict[str, object]) -> dict[str, object]:
    findings = value["findings"]
    dissent = value["dissent"]
    assert type(findings) is list and type(dissent) is dict
    return {
        "schema_version": value["schema_version"],
        "round_id": value["round_id"],
        "release_position": value["release_position"],
        "findings": findings[:EXTERNAL_V3_PRIOR_FINDING_LIMIT],
        "dissent": {
            key: dissent[key][:EXTERNAL_V3_PRIOR_DISSENT_LIMIT]
            for key in (
                "why_not_release",
                "missing_stress_cases",
                "assumptions_to_break",
            )
        },
    }


def _scenario_projection(ordinal: int) -> list[dict[str, object]]:
    rows = _dossier_projection()
    projected: list[dict[str, object]] = []
    for row in rows:
        if ordinal == 0:
            projected.append(
                {
                    "scenario_id": row["scenario_id"],
                    "mechanism_id": row["mechanism_id"],
                    "invariant_id": row["invariant_id"],
                    "behavior": row["behavior"],
                    "risk_class": row["risk_class"],
                }
            )
            continue
        member = dict(row)
        if ordinal == 1:
            member.pop("outcome")
        projected.append(member)
    return projected


def _request_value(
    campaign: ExternalCampaignV3,
    *,
    ordinal: int,
    prior_advisory: dict[str, object] | None,
    prior_output_sha256: str,
    prior_output_chain_sha256: str,
) -> dict[str, object]:
    round_id = ROUND_IDS[ordinal]
    user_payload: dict[str, object] = {
        "contract": {
            "request_derivation": EXTERNAL_V3_REQUEST_DERIVATION,
            "dossier_schema": DS_REVIEW_DOSSIER_SCHEMA,
            "output_schema": DS_REVIEW_OUTPUT_SCHEMA,
            "provider_revision": DS_REVIEW_PROVIDER_REVISION,
            "round_id": round_id,
            "objective": _ROUND_OBJECTIVES[round_id],
            "authority": EXTERNAL_V3_AUTHORITY,
            "prior_output_sha256": prior_output_sha256,
            "prior_output_chain_sha256": prior_output_chain_sha256,
        },
        "synthetic_scenarios": _scenario_projection(ordinal),
        "prior_advisory": prior_advisory,
    }
    return {
        "model": DS_REVIEW_MODEL_ALIAS,
        "messages": [
            {"role": "system", "content": _SYSTEM_INSTRUCTION},
            {"role": "user", "content": canonical_json(user_payload)},
        ],
        "response_format": {"type": "json_object"},
        "stream": False,
        "max_tokens": campaign.pricing.max_completion_tokens_per_round,
    }


def derive_external_round_v3(
    campaign: ExternalCampaignV3,
    *,
    ordinal: int,
    prior_advisory: dict[str, object] | None = None,
    prior_output_chain_sha256: str = _ZERO_SHA256,
) -> BoundExternalRoundV3:
    """Derive one canonical request from only frozen synthetic data and prior output."""

    validate_external_campaign_v3(campaign)
    if type(ordinal) is not int or not 0 <= ordinal < EXTERNAL_V3_ROUND_COUNT:
        raise ExternalV3PolicyError("round ordinal is invalid")
    _require_sha256(prior_output_chain_sha256, label="prior output chain hash")
    if ordinal == 0:
        if prior_advisory is not None or prior_output_chain_sha256 != _ZERO_SHA256:
            raise ExternalV3PolicyError("blind round cannot carry prior advisory state")
        prior_projection = None
        prior_sha = _ZERO_SHA256
    else:
        if type(prior_advisory) is not dict:
            raise ExternalV3PolicyError("later round requires a validated prior advisory")
        expected_prior_round = ROUND_IDS[ordinal - 1]
        validated = _validate_external_public_advisory(
            prior_advisory, round_id=expected_prior_round
        )
        prior_projection = _prior_advisory_projection(validated)
        prior_sha = _sha256_json(validated)
    raw = canonical_json(
        _request_value(
            campaign,
            ordinal=ordinal,
            prior_advisory=prior_projection,
            prior_output_sha256=prior_sha,
            prior_output_chain_sha256=prior_output_chain_sha256,
        )
    ).encode("utf-8")
    if len(raw) > campaign.pricing.max_request_bytes:
        raise ExternalV3PolicyError("derived request exceeds the preregistered byte cap")
    if len(raw) > campaign.pricing.max_prompt_tokens_per_round:
        raise ExternalV3PolicyError("conservative prompt-token reserve is too small")
    try:
        raw.decode("ascii")
    except UnicodeError:
        raise ExternalV3PolicyError("derived request must remain printable ASCII JSON") from None
    decoded = _strict_json_loads(raw, label="derived external request")
    if canonical_json(decoded).encode("utf-8") != raw:
        raise ExternalV3PolicyError("derived request is not canonical")
    if type(decoded) is not dict or set(decoded) != {
        "model",
        "messages",
        "response_format",
        "stream",
        "max_tokens",
    }:
        raise ExternalV3PolicyError("derived request transport contract is invalid")
    return BoundExternalRoundV3(
        campaign_id=campaign.campaign_id,
        manifest_sha256=campaign.manifest_sha256,
        round_id=ROUND_IDS[ordinal],
        ordinal=ordinal,
        request_bytes=raw,
        request_sha256=_sha256_bytes(raw),
        prior_output_sha256=prior_sha,
        prior_output_chain_sha256=prior_output_chain_sha256,
    )


def _validate_bound_round(
    campaign: ExternalCampaignV3, bound: BoundExternalRoundV3
) -> None:
    if (
        type(bound) is not BoundExternalRoundV3
        or bound.campaign_id != campaign.campaign_id
        or bound.manifest_sha256 != campaign.manifest_sha256
        or type(bound.ordinal) is not int
        or not 0 <= bound.ordinal < EXTERNAL_V3_ROUND_COUNT
        or bound.round_id != ROUND_IDS[bound.ordinal]
        or type(bound.request_bytes) is not bytes
        or len(bound.request_bytes) > campaign.pricing.max_request_bytes
        or type(bound.request_sha256) is not str
        or _sha256_bytes(bound.request_bytes) != bound.request_sha256
        or type(bound.prior_output_sha256) is not str
        or not _SHA256.fullmatch(bound.prior_output_sha256)
        or type(bound.prior_output_chain_sha256) is not str
        or not _SHA256.fullmatch(bound.prior_output_chain_sha256)
    ):
        raise ExternalV3PolicyError("bound external request identity is invalid")
    decoded = _strict_json_loads(bound.request_bytes, label="bound external request")
    if canonical_json(decoded).encode("utf-8") != bound.request_bytes:
        raise ExternalV3PolicyError("bound external request is not canonical")


def advance_output_chain(previous_chain_sha256: str, advisory_sha256: str) -> str:
    _require_sha256(previous_chain_sha256, label="previous output chain hash")
    _require_sha256(advisory_sha256, label="advisory hash")
    return _sha256_json(
        {
            "previous_chain_sha256": previous_chain_sha256,
            "advisory_sha256": advisory_sha256,
        }
    )


def parse_external_response_v3(
    raw: bytes,
    *,
    campaign: ExternalCampaignV3,
    bound: BoundExternalRoundV3,
    elapsed_seconds: float,
) -> ParsedExternalResponseV3:
    """Parse a fake response with the exact identity, usage, and cost contract."""

    validate_external_campaign_v3(campaign)
    _validate_bound_round(campaign, bound)
    if type(raw) is not bytes or len(raw) > campaign.pricing.max_response_bytes:
        raise ExternalV3PolicyError("provider response exceeds the preregistered byte cap")
    _require_finite_float(elapsed_seconds, label="provider elapsed seconds")
    if elapsed_seconds > campaign.pricing.per_round_deadline_seconds:
        raise ExternalV3PolicyError("provider response exceeded the per-round deadline")
    outer = _strict_json_loads(raw, label="provider response")
    if type(outer) is not dict or set(outer) != {
        "id",
        "created",
        "model",
        "system_fingerprint",
        "choices",
        "usage",
    }:
        raise ExternalV3PolicyError("provider response top-level contract is invalid")
    response_id = _scan_public_token(outer["id"], label="provider response id")
    if type(outer["created"]) is not int:
        raise ExternalV3PolicyError("provider response timestamp is invalid")
    if (
        outer["model"] != campaign.pin.expected_returned_model
        or outer["system_fingerprint"] != campaign.pin.expected_system_fingerprint
    ):
        raise ExternalV3PolicyError("provider response identity drifted")
    choices = outer["choices"]
    if type(choices) is not list or len(choices) != 1:
        raise ExternalV3PolicyError("provider response choices are invalid")
    choice = choices[0]
    if (
        type(choice) is not dict
        or set(choice) != {"index", "message", "finish_reason"}
        or type(choice["index"]) is not int
        or choice["index"] != 0
        or choice["finish_reason"] != "stop"
        or type(choice["message"]) is not dict
        or set(choice["message"]) != {"role", "content"}
        or choice["message"].get("role") != "assistant"
        or type(choice["message"].get("content")) is not str
    ):
        raise ExternalV3PolicyError("provider response contains invalid choice or tool surface")
    usage = outer["usage"]
    if type(usage) is not dict or set(usage) != {
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
    }:
        raise ExternalV3PolicyError("provider usage contract is invalid")
    prompt_tokens = _require_exact_int(
        usage["prompt_tokens"], label="prompt usage"
    )
    completion_tokens = _require_exact_int(
        usage["completion_tokens"], label="completion usage"
    )
    total_tokens = _require_exact_int(usage["total_tokens"], label="total usage")
    if total_tokens != prompt_tokens + completion_tokens:
        raise ExternalV3PolicyError("provider total usage is inconsistent")
    if (
        prompt_tokens > campaign.pricing.max_prompt_tokens_per_round
        or completion_tokens > campaign.pricing.max_completion_tokens_per_round
    ):
        raise ExternalV3PolicyError("provider usage exceeded a preregistered cap")
    output = _strict_json_loads(
        choice["message"]["content"], label="provider advisory"
    )
    advisory = _validate_external_public_advisory(output, round_id=bound.round_id)
    advisory_bytes = canonical_json(advisory).encode("utf-8")
    try:
        created_at = datetime.fromtimestamp(outer["created"], tz=UTC).isoformat().replace(
            "+00:00", "Z"
        )
    except (OverflowError, OSError, ValueError):
        raise ExternalV3PolicyError("provider response timestamp is invalid") from None
    return ParsedExternalResponseV3(
        advisory=advisory,
        advisory_bytes=advisory_bytes,
        advisory_sha256=_sha256_bytes(advisory_bytes),
        raw_response_sha256=_sha256_bytes(raw),
        response_id_sha256=_sha256_bytes(response_id.encode("ascii")),
        created_at=created_at,
        returned_model=outer["model"],
        system_fingerprint_sha256=_sha256_bytes(
            outer["system_fingerprint"].encode("ascii")
        ),
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        cost_micros=campaign.pricing.cost_micros(
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens
        ),
        elapsed_seconds=elapsed_seconds,
        response_bytes=len(raw),
    )


class ScriptedFakeTransport:
    """Sealed, data-only transport double; it cannot execute callbacks or I/O."""

    __slots__ = ("_kind", "_response_bytes", "_elapsed_seconds", "_calls")

    def __init__(
        self,
        *,
        kind: str,
        response_bytes: bytes = b"",
        elapsed_seconds: float = 0.0,
    ) -> None:
        if kind not in {"RESPONSE", "AMBIGUOUS_AFTER_INTENT", "TIMEOUT_AFTER_INTENT"}:
            raise ExternalV3PolicyError("fake transport script kind is invalid")
        if type(response_bytes) is not bytes:
            raise ExternalV3PolicyError("fake transport script fields are invalid")
        _require_finite_float(elapsed_seconds, label="fake transport elapsed seconds")
        self._kind = kind
        self._response_bytes = response_bytes
        self._elapsed_seconds = elapsed_seconds
        self._calls = 0

    @property
    def calls(self) -> int:
        return self._calls



def _consume_scripted_fake(
    transport: ScriptedFakeTransport, request_bytes: bytes
) -> tuple[bytes, float]:
    """Consume sealed data without invoking a caller-replaceable transport method."""

    if type(transport) is not ScriptedFakeTransport:
        raise ExternalV3Disabled("only the sealed scripted fake is accepted")
    if transport._calls != 0:
        raise ExternalV3StateError("fake transport is once-only")
    if type(request_bytes) is not bytes:
        raise ExternalV3PolicyError("fake transport request must be bytes")
    if transport._kind not in {
        "RESPONSE",
        "AMBIGUOUS_AFTER_INTENT",
        "TIMEOUT_AFTER_INTENT",
    } or type(transport._response_bytes) is not bytes:
        raise ExternalV3PolicyError("fake transport data drifted")
    _require_finite_float(
        transport._elapsed_seconds, label="fake transport elapsed seconds"
    )
    transport._calls += 1
    if transport._kind in {"AMBIGUOUS_AFTER_INTENT", "TIMEOUT_AFTER_INTENT"}:
        raise _FakeAmbiguousAfterIntent(transport._kind)
    return transport._response_bytes, transport._elapsed_seconds


class ExternalCampaignLedgerV3:
    """SQLite CAS ledger for fake-only external state-machine tests."""

    def __init__(self, path: Path, *, data_root: Path) -> None:
        self._managed_root_guard_handle = 0
        self._sqlite_guard_handle = 0
        self._preinit_guard_handle = 0
        self._initialized_guard_handle = 0
        if not isinstance(path, Path) or not isinstance(data_root, Path):
            raise TypeError("external campaign ledger path and data root must be Paths")
        if not path.is_absolute() or not data_root.is_absolute():
            raise ExternalV3StateError("external campaign storage paths must be absolute")
        ensure_no_reparse_components(data_root)
        root = data_root.resolve(strict=True)
        if not root.is_dir():
            raise ExternalV3StateError("managed external campaign data root is unavailable")
        if os.name != "nt":
            # Python's sqlite3 API has no directory-fd/handle constructor and
            # POSIX directory fds do not prevent rename.  Enabling writes here
            # would reintroduce a namespace-check -> sqlite3.connect window.
            raise ExternalV3Disabled(
                "external v3 writable ledger requires Windows handle guards"
            )
        ensure_no_reparse_components(path.parent)
        parent = path.parent.resolve(strict=True)
        try:
            parent.relative_to(root)
        except ValueError:
            raise ExternalV3StateError(
                "external campaign ledger escapes its managed data root"
            ) from None
        if (
            not parent.is_dir()
            or parent != root
            or path.name in {"", ".", ".."}
            or "/" in path.name
            or "\\" in path.name
            or not _SQLITE_LOGICAL_NAME.fullmatch(path.name)
        ):
            raise ExternalV3StateError("external campaign ledger parent is unavailable")
        self.data_root = root
        self.path = root / path.name
        self._sqlite_stream_name = ":" + path.name
        self._sqlite_path = Path(str(root) + self._sqlite_stream_name)
        marker_digest = hashlib.sha256(path.name.encode("ascii")).hexdigest()
        self._preinit_marker_path = root / (
            f".ds-external-v3-{marker_digest}.preinit.json"
        )
        self._initialized_marker_path = root / (
            f".ds-external-v3-{marker_digest}.initialized.json"
        )
        self._success_replay_root = root / _SUCCESS_REPLAY_ROOT_NAME
        self._terminal_commitment_root = root / _TERMINAL_COMMITMENT_ROOT_NAME
        try:
            self._managed_root_guard_handle = _win_open_absolute(
                root, directory=True, prevent_delete=True
            )
            _win_require_directory_handle(self._managed_root_guard_handle)
            _win_verify_absolute_identity(
                root, self._managed_root_guard_handle, directory=True
            )
            self._managed_root_identity = _win_handle_identity(
                self._managed_root_guard_handle
            )
            existing, needs_initialized_marker = (
                self._prepare_windows_sqlite_guard()
            )
            self._validate_storage_path()
            self._sqlite_initialize_cutpoint("BEFORE_FIRST_CONNECT")
            self._initialize(existing=existing)
            if not existing:
                self._sqlite_initialize_cutpoint("AFTER_SCHEMA_COMMIT")
            self._ensure_windows_initialized_marker(
                allow_create=needs_initialized_marker or not existing
            )
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        sqlite_handle = getattr(self, "_sqlite_guard_handle", 0)
        preinit_handle = getattr(self, "_preinit_guard_handle", 0)
        initialized_handle = getattr(self, "_initialized_guard_handle", 0)
        root_handle = getattr(self, "_managed_root_guard_handle", 0)
        self._sqlite_guard_handle = 0
        self._preinit_guard_handle = 0
        self._initialized_guard_handle = 0
        self._managed_root_guard_handle = 0
        if os.name == "nt":
            _win_close(sqlite_handle)
            _win_close(initialized_handle)
            _win_close(preinit_handle)
            _win_close(root_handle)

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    @staticmethod
    def _sqlite_initialize_cutpoint(phase: str) -> None:
        """Named no-op for deterministic bootstrap restart tests."""

        if phase not in {
            "AFTER_PREINIT_MARKER",
            "AFTER_ZERO_STREAM",
            "BEFORE_FIRST_CONNECT",
            "AFTER_SCHEMA_COMMIT",
        }:
            raise ExternalV3StateError("SQLite initialize cutpoint is invalid")

    def _bootstrap_marker_bytes(self, *, initialized: bool) -> bytes:
        state = "INITIALIZED" if initialized else "PREINIT"
        schema = (
            _SQLITE_INITIALIZED_SCHEMA if initialized else _SQLITE_PREINIT_SCHEMA
        )
        payload: dict[str, object] = {
            "schema_version": schema,
            "state": state,
            "ledger_schema": EXTERNAL_V3_LEDGER_SCHEMA,
            "logical_name": self.path.name,
            "sqlite_stream_name": self._sqlite_stream_name,
            "managed_root_volume": self._managed_root_identity[0],
            "managed_root_file_id": self._managed_root_identity[1],
            "application_id": _LEDGER_APPLICATION_ID,
            "user_version": _LEDGER_USER_VERSION,
        }
        if initialized:
            payload["preinit_sha256"] = hashlib.sha256(
                self._bootstrap_marker_bytes(initialized=False)
            ).hexdigest()
        return canonical_json(payload).encode("ascii")

    def _open_windows_bootstrap_marker(
        self, *, initialized: bool, allow_create: bool
    ) -> tuple[int, bool]:
        path = (
            self._initialized_marker_path
            if initialized
            else self._preinit_marker_path
        )
        expected = self._bootstrap_marker_bytes(initialized=initialized)
        handle = 0
        created = False
        try:
            if allow_create:
                try:
                    handle, _ = _win_nt_open_relative(
                        self._managed_root_guard_handle,
                        path.name,
                        directory=False,
                        create=True,
                        writable=True,
                        share_delete=False,
                    )
                    created = True
                except OSError as error:
                    if error.errno not in {
                        _WIN_ERROR_FILE_EXISTS,
                        _WIN_ERROR_ALREADY_EXISTS,
                    }:
                        raise
            if not handle:
                handle, _ = _win_nt_open_relative(
                    self._managed_root_guard_handle,
                    path.name,
                    directory=False,
                    create=False,
                    writable=False,
                    share_delete=False,
                )
            if created:
                before = _win_require_file_handle(handle, readonly=False)
                if (int(before.nFileSizeHigh) << 32) | int(before.nFileSizeLow):
                    raise OSError(1392, "new bootstrap marker is not empty")
                _win_write_all(handle, expected)
                _win_flush(handle)
                _win_seal_readonly(handle)
            info = _win_require_file_handle(handle, readonly=True)
            size = (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)
            if size != len(expected):
                raise OSError(1392, "bootstrap marker size drifted")
            _win_verify_absolute_identity(path, handle, directory=False)
            if _win_read_all(handle, max_bytes=len(expected)) != expected:
                raise OSError(1392, "bootstrap marker bytes drifted")
            return handle, created
        except OSError:
            _win_close(handle)
            raise ExternalV3StateError(
                "external SQLite bootstrap marker is invalid"
            ) from None

    def _revalidate_windows_bootstrap_marker(
        self, *, initialized: bool
    ) -> None:
        handle = (
            self._initialized_guard_handle
            if initialized
            else self._preinit_guard_handle
        )
        path = (
            self._initialized_marker_path
            if initialized
            else self._preinit_marker_path
        )
        expected = self._bootstrap_marker_bytes(initialized=initialized)
        if not handle:
            if initialized:
                return
            raise ExternalV3StateError("external SQLite PREINIT marker is absent")
        try:
            info = _win_require_file_handle(handle, readonly=True)
            size = (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)
            if size != len(expected):
                raise OSError(1392, "bootstrap marker size drifted")
            _win_verify_absolute_identity(path, handle, directory=False)
            if _win_read_all(handle, max_bytes=len(expected)) != expected:
                raise OSError(1392, "bootstrap marker bytes drifted")
        except OSError:
            raise ExternalV3StateError(
                "external SQLite bootstrap marker drifted"
            ) from None

    def _ensure_windows_initialized_marker(self, *, allow_create: bool) -> None:
        if self._initialized_guard_handle:
            self._revalidate_windows_bootstrap_marker(initialized=True)
            return
        handle, _ = self._open_windows_bootstrap_marker(
            initialized=True, allow_create=allow_create
        )
        self._initialized_guard_handle = handle

    def _validate_existing_sqlite_image_before_write(
        self, raw: bytes, *, require_empty: bool
    ) -> None:
        if (
            not raw.startswith(b"SQLite format 3\x00")
            or len(raw) > _SQLITE_BOOTSTRAP_MAX_BYTES
        ):
            raise ExternalV3StateError(
                "external SQLite image is invalid before writable open"
            )
        # A cleanly closed WAL database retains header read/write versions 2/2
        # even after its sidecars have been checkpointed away.  ``deserialize``
        # cannot attach a WAL to an in-memory target, so replay an immutable
        # copy with only those two header bytes normalized to rollback mode.
        # The on-disk directory stream is never changed by this validation.
        if raw[18:20] == b"\x02\x02":
            replay = raw[:18] + b"\x01\x01" + raw[20:]
        elif raw[18:20] == b"\x01\x01":
            replay = raw
        else:
            raise ExternalV3StateError(
                "external SQLite image has an invalid journal header"
            )
        memory = sqlite3.connect(":memory:", isolation_level=None)
        try:
            memory.row_factory = sqlite3.Row
            memory.deserialize(replay)
            integrity = memory.execute("PRAGMA integrity_check").fetchall()
            if len(integrity) != 1 or integrity[0][0] != "ok":
                raise ExternalV3StateError(
                    "external SQLite image failed integrity replay"
                )
            self._validate_schema(memory)
            if require_empty and (
                memory.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
                or memory.execute("SELECT COUNT(*) FROM rounds").fetchone()[0]
            ):
                raise ExternalV3StateError(
                    "unfinished SQLite initialization contains durable rows"
                )
        except (sqlite3.Error, ExternalV3StateError):
            raise ExternalV3StateError(
                "external SQLite image is invalid before writable open"
            ) from None
        finally:
            memory.close()

    def _observe_windows_bootstrap_set(self) -> tuple[bool, bool, bool, int]:
        """Open and pin the complete bootstrap set without creating anything."""

        handles: list[int] = []

        def optional_open(name: str) -> int:
            try:
                handle, _ = _win_nt_open_relative(
                    self._managed_root_guard_handle,
                    name,
                    directory=False,
                    create=False,
                    writable=False,
                    share_delete=False,
                )
                handles.append(handle)
                return handle
            except OSError as error:
                if error.errno in {
                    _WIN_ERROR_FILE_NOT_FOUND,
                    _WIN_ERROR_PATH_NOT_FOUND,
                }:
                    return 0
                raise

        try:
            preinit = optional_open(self._preinit_marker_path.name)
            initialized = optional_open(self._initialized_marker_path.name)
            stream = optional_open(self._sqlite_stream_name)
            self._preinit_guard_handle = preinit
            self._initialized_guard_handle = initialized
            self._sqlite_guard_handle = stream
            if preinit:
                self._revalidate_windows_bootstrap_marker(initialized=False)
            if initialized:
                self._revalidate_windows_bootstrap_marker(initialized=True)
            size = 0
            if stream:
                info = _win_require_file_handle(stream, readonly=False)
                if int(info.dwFileAttributes) & _WIN_FILE_ATTRIBUTE_READONLY:
                    raise ExternalV3StateError(
                        "SQLite stream readonly state drifted"
                    )
                if _win_handle_identity(stream) != self._managed_root_identity:
                    raise ExternalV3StateError(
                        "SQLite stream is not attached to managed root"
                    )
                _win_verify_absolute_identity(
                    self._sqlite_path,
                    stream,
                    directory=False,
                    readonly=False,
                )
                size = (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)
            return bool(preinit), bool(initialized), bool(stream), size
        except Exception:
            for handle in handles:
                _win_close(handle)
            self._preinit_guard_handle = 0
            self._initialized_guard_handle = 0
            self._sqlite_guard_handle = 0
            raise

    def _prepare_windows_sqlite_guard(self) -> tuple[bool, bool]:
        if os.name != "nt" or not self._managed_root_guard_handle:
            raise ExternalV3Disabled("Windows SQLite guard is unavailable")
        try:
            preinit_exists, initialized_exists, stream_exists, size = (
                self._observe_windows_bootstrap_set()
            )
        except OSError:
            raise ExternalV3StateError(
                "external SQLite bootstrap set cannot be observed"
            ) from None

        if not preinit_exists:
            if initialized_exists or stream_exists:
                raise ExternalV3StateError(
                    "existing SQLite state has no durable PREINIT authority"
                )
            self._preinit_guard_handle, created = (
                self._open_windows_bootstrap_marker(
                    initialized=False, allow_create=True
                )
            )
            if not created:
                raise ExternalV3StateError(
                    "SQLite PREINIT state changed after observation"
                )
            preinit_exists = True

        self._sqlite_initialize_cutpoint("AFTER_PREINIT_MARKER")

        if initialized_exists:
            if not stream_exists or size == 0:
                raise ExternalV3StateError(
                    "INITIALIZED marker does not bind a complete SQLite stream"
                )
            if size > _SQLITE_BOOTSTRAP_MAX_BYTES:
                raise ExternalV3StateError(
                    "external SQLite bootstrap image exceeds byte cap"
                )
            raw = _win_read_all(self._sqlite_guard_handle, max_bytes=size)
            self._validate_existing_sqlite_image_before_write(
                raw, require_empty=False
            )
            return True, False

        if not stream_exists:
            handle = 0
            try:
                handle, _ = _win_nt_open_relative(
                    self._managed_root_guard_handle,
                    self._sqlite_stream_name,
                    directory=False,
                    create=True,
                    writable=True,
                    share_delete=False,
                )
            except OSError:
                _win_close(handle)
                raise ExternalV3StateError(
                    "SQLite stream state changed after bootstrap observation"
                ) from None
            self._sqlite_guard_handle = handle
            stream_exists = True
            size = 0

        try:
            info = _win_require_file_handle(
                self._sqlite_guard_handle, readonly=False
            )
            if int(info.dwFileAttributes) & _WIN_FILE_ATTRIBUTE_READONLY:
                raise OSError(19, "SQLite guard file is readonly")
            size = (int(info.nFileSizeHigh) << 32) | int(info.nFileSizeLow)
            self._revalidate_windows_sqlite_guard()
            if size == 0:
                self._sqlite_initialize_cutpoint("AFTER_ZERO_STREAM")
                return False, True
            if size > _SQLITE_BOOTSTRAP_MAX_BYTES:
                raise ExternalV3StateError(
                    "external SQLite bootstrap image exceeds byte cap"
                )
            raw = _win_read_all(self._sqlite_guard_handle, max_bytes=size)
            self._validate_existing_sqlite_image_before_write(
                raw, require_empty=True
            )
            # Exact PREINIT + a fully initialized, empty image is the only
            # recoverable post-schema/pre-marker restart state.
            return True, True
        except OSError:
            _win_close(self._sqlite_guard_handle)
            self._sqlite_guard_handle = 0
            raise ExternalV3StateError(
                "external campaign SQLite handle guard is unavailable"
            ) from None

    def _revalidate_windows_sqlite_guard(self) -> None:
        if (
            os.name != "nt"
            or not self._managed_root_guard_handle
            or not self._sqlite_guard_handle
        ):
            raise ExternalV3StateError("external SQLite handle guard is closed")
        try:
            _win_require_directory_handle(self._managed_root_guard_handle)
            if (
                _win_handle_identity(self._managed_root_guard_handle)
                != self._managed_root_identity
            ):
                raise ExternalV3StateError(
                    "managed data root guard identity drifted"
                )
            _win_verify_absolute_identity(
                self.data_root,
                self._managed_root_guard_handle,
                directory=True,
            )
            info = _win_require_file_handle(
                self._sqlite_guard_handle, readonly=False
            )
            if int(info.dwFileAttributes) & _WIN_FILE_ATTRIBUTE_READONLY:
                raise ExternalV3StateError("SQLite guard readonly state drifted")
            if (
                _win_handle_identity(self._sqlite_guard_handle)[0]
                != self._managed_root_identity[0]
            ):
                raise ExternalV3StateError("SQLite guard volume drifted")
            if (
                _win_handle_identity(self._sqlite_guard_handle)
                != self._managed_root_identity
            ):
                raise ExternalV3StateError(
                    "SQLite stream is not attached to managed root"
                )
            _win_verify_absolute_identity(
                self._sqlite_path,
                self._sqlite_guard_handle,
                directory=False,
                readonly=False,
            )
            self._revalidate_windows_bootstrap_marker(initialized=False)
            self._revalidate_windows_bootstrap_marker(initialized=True)
        except OSError:
            raise ExternalV3StateError(
                "external SQLite handle identity validation failed"
            ) from None

    @staticmethod
    def _artifact_write_cutpoint(kind: str, phase: str) -> None:
        """Named no-op used only for deterministic local restart-cut tests."""

        if kind not in _DURABLE_WRITE_KINDS or phase not in {
            "AFTER_PREPARE_COMMIT",
            "AFTER_PAYLOAD_FSYNC",
            "AFTER_READONLY_SEAL",
            "BEFORE_FINALIZE_COMMIT",
            "AFTER_FINALIZE_COMMIT",
        }:
            raise ExternalV3StateError("durable write cutpoint is invalid")

    @staticmethod
    def _require_artifact_target_name(name: str) -> None:
        if type(name) is not str or not _ARTIFACT_TARGET.fullmatch(name):
            raise ExternalV3StateError("external artifact target is invalid")

    def _ensure_artifact_root(self, root: Path, *, create: bool) -> None:
        """Path-level audit helper; payload I/O never relies on this alone."""

        if root.parent != self.data_root:
            raise ExternalV3StateError("external artifact root escaped managed data")
        if create:
            try:
                root.mkdir(mode=0o700, exist_ok=True)
            except OSError:
                raise ExternalV3StateError(
                    "external artifact root cannot be created"
                ) from None
        try:
            ensure_no_reparse_components(root)
            resolved = root.resolve(strict=True)
            resolved.relative_to(self.data_root)
            info = root.lstat()
        except (FileNotFoundError, OSError, ValueError):
            raise ExternalV3StateError("external artifact root is unavailable") from None
        if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
            raise ExternalV3StateError("external artifact root is unsafe")

    @staticmethod
    def _require_safe_artifact_stat(
        info: os.stat_result, *, readonly: bool = True
    ) -> None:
        if (
            stat_is_reparse_point(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or (readonly and info.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        ):
            raise ExternalV3StateError("external replay artifact is unsafe")

    def _validate_artifact_path(self, path: Path, *, root: Path) -> os.stat_result:
        self._ensure_artifact_root(root, create=False)
        if path.parent != root or path.name in {"", ".", ".."}:
            raise ExternalV3StateError("external replay artifact path is invalid")
        try:
            ensure_no_reparse_components(path)
            info = path.lstat()
        except (FileNotFoundError, OSError):
            raise ExternalV3StateError("external replay artifact is unavailable") from None
        self._require_safe_artifact_stat(info, readonly=True)
        return info

    def _open_windows_artifact_roots(
        self, root: Path, *, create: bool
    ) -> tuple[int, int]:
        if os.name != "nt":
            raise ExternalV3Disabled("Windows handle backend is unavailable")
        if root.parent != self.data_root or root.name not in {
            _SUCCESS_REPLAY_ROOT_NAME,
            _TERMINAL_COMMITMENT_ROOT_NAME,
        }:
            raise ExternalV3StateError("external artifact root escaped managed data")
        data_handle = 0
        root_handle = 0
        try:
            data_handle = _win_open_absolute(self.data_root, directory=True)
            _win_require_directory_handle(data_handle)
            root_handle, _ = _win_nt_open_relative(
                data_handle,
                root.name,
                directory=True,
                create=create,
                writable=False,
                share_delete=False,
            )
            _win_require_directory_handle(root_handle)
            self._revalidate_windows_artifact_roots(
                root,
                data_handle=data_handle,
                root_handle=root_handle,
            )
            return data_handle, root_handle
        except OSError:
            _win_close(root_handle)
            _win_close(data_handle)
            raise ExternalV3StateError(
                "external artifact root handle is unavailable"
            ) from None

    def _revalidate_windows_artifact_roots(
        self, root: Path, *, data_handle: int, root_handle: int
    ) -> None:
        """Rebind both namespace paths to the pinned volume/file identities."""

        if os.name != "nt":
            raise ExternalV3Disabled("Windows handle backend is unavailable")
        _win_require_directory_handle(data_handle)
        _win_require_directory_handle(root_handle)
        if _win_handle_identity(data_handle) != self._managed_root_identity:
            raise OSError(4390, "managed data root identity changed")
        _win_verify_absolute_identity(
            self.data_root, data_handle, directory=True
        )
        _win_verify_absolute_identity(root, root_handle, directory=True)

    def _revalidate_posix_artifact_roots(
        self,
        root: Path,
        *,
        data_descriptor: int,
        root_descriptor: int,
    ) -> None:
        if os.name == "nt":
            raise ExternalV3Disabled("POSIX directory-fd backend is unavailable")
        data_info = os.fstat(data_descriptor)
        root_info = os.fstat(root_descriptor)
        current_data = os.stat(self.data_root, follow_symlinks=False)
        if (
            not stat.S_ISDIR(data_info.st_mode)
            or not stat.S_ISDIR(root_info.st_mode)
            or (data_info.st_dev, data_info.st_ino) != self._managed_root_identity
            or (current_data.st_dev, current_data.st_ino)
            != (data_info.st_dev, data_info.st_ino)
        ):
            raise ExternalV3StateError("managed directory handle identity drifted")
        current_root = os.stat(
            root.name,
            dir_fd=data_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(current_root.st_mode)
            or (current_root.st_dev, current_root.st_ino)
            != (root_info.st_dev, root_info.st_ino)
        ):
            raise ExternalV3StateError("artifact root handle identity drifted")

    def _read_managed_artifact_windows(
        self, path: Path, *, root: Path, max_bytes: int
    ) -> bytes:
        self._require_artifact_target_name(path.name)
        if path.parent != root:
            raise ExternalV3StateError("external replay artifact path is invalid")
        data_handle = root_handle = file_handle = 0
        try:
            data_handle, root_handle = self._open_windows_artifact_roots(
                root, create=False
            )
            file_handle, _ = _win_nt_open_relative(
                root_handle,
                path.name,
                directory=False,
                create=False,
                writable=False,
                share_delete=False,
            )
            before = _win_require_file_handle(file_handle, readonly=True)
            self._revalidate_windows_artifact_roots(
                root,
                data_handle=data_handle,
                root_handle=root_handle,
            )
            _win_verify_absolute_identity(path, file_handle, directory=False)
            content = _win_read_all(file_handle, max_bytes=max_bytes)
            after = _win_require_file_handle(file_handle, readonly=True)
            if (
                _win_handle_identity(file_handle)
                != (
                    int(after.dwVolumeSerialNumber),
                    (int(after.nFileIndexHigh) << 32) | int(after.nFileIndexLow),
                )
                or int(after.nFileSizeHigh) << 32 | int(after.nFileSizeLow)
                != len(content)
                or (
                    int(before.dwVolumeSerialNumber),
                    (int(before.nFileIndexHigh) << 32) | int(before.nFileIndexLow),
                )
                != _win_handle_identity(file_handle)
            ):
                raise ExternalV3StateError(
                    "external replay artifact changed during read"
                )
            self._revalidate_windows_artifact_roots(
                root,
                data_handle=data_handle,
                root_handle=root_handle,
            )
            _win_verify_absolute_identity(path, file_handle, directory=False)
            return content
        except (OSError, FileNotFoundError):
            raise ExternalV3StateError(
                "external replay artifact is unavailable or unsafe"
            ) from None
        finally:
            _win_close(file_handle)
            _win_close(root_handle)
            _win_close(data_handle)

    def _write_managed_artifact_windows(
        self,
        path: Path,
        *,
        root: Path,
        content: bytes,
        max_bytes: int,
        kind: str,
    ) -> None:
        self._require_artifact_target_name(path.name)
        if path.parent != root:
            raise ExternalV3StateError("external replay artifact path is invalid")
        data_handle = root_handle = file_handle = 0
        try:
            data_handle, root_handle = self._open_windows_artifact_roots(
                root, create=True
            )
            try:
                file_handle, _ = _win_nt_open_relative(
                    root_handle,
                    path.name,
                    directory=False,
                    create=True,
                    writable=True,
                    share_delete=False,
                )
            except OSError as error:
                if error.errno not in {_WIN_ERROR_FILE_EXISTS, _WIN_ERROR_ALREADY_EXISTS}:
                    raise
                existing = self._read_managed_artifact_windows(
                    path, root=root, max_bytes=max_bytes
                )
                if existing != content:
                    raise ExternalV3StateError(
                        "append-only external artifact conflicts with durable bytes"
                    )
                return
            opened = _win_require_file_handle(file_handle, readonly=False)
            if (int(opened.nFileSizeHigh) << 32 | int(opened.nFileSizeLow)) != 0:
                raise ExternalV3StateError("new external artifact is not empty")
            # This is the decisive pre-payload boundary.  Both namespace paths
            # must still name the exact pinned directory handles; the file was
            # opened as one relative component beneath the pinned root handle.
            self._revalidate_windows_artifact_roots(
                root,
                data_handle=data_handle,
                root_handle=root_handle,
            )
            _win_verify_absolute_identity(
                path, file_handle, directory=False, readonly=False
            )
            _win_write_all(file_handle, content)
            _win_flush(file_handle)
            self._artifact_write_cutpoint(kind, "AFTER_PAYLOAD_FSYNC")
            _win_seal_readonly(file_handle)
            sealed = _win_require_file_handle(file_handle, readonly=True)
            if (int(sealed.nFileSizeHigh) << 32 | int(sealed.nFileSizeLow)) != len(content):
                raise ExternalV3StateError("sealed external artifact size drifted")
            self._artifact_write_cutpoint(kind, "AFTER_READONLY_SEAL")
            self._revalidate_windows_artifact_roots(
                root,
                data_handle=data_handle,
                root_handle=root_handle,
            )
            _win_verify_absolute_identity(path, file_handle, directory=False)
        except ExternalV3StateError:
            raise
        except OSError:
            raise ExternalV3StateError(
                "append-only external artifact handle write failed"
            ) from None
        finally:
            _win_close(file_handle)
            _win_close(root_handle)
            _win_close(data_handle)

    def _read_managed_artifact(
        self, path: Path, *, root: Path, max_bytes: int
    ) -> bytes:
        if os.name == "nt":
            return self._read_managed_artifact_windows(
                path, root=root, max_bytes=max_bytes
            )
        before = self._validate_artifact_path(path, root=root)
        flags = (
            os.O_RDONLY
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        data_descriptor = root_descriptor = 0
        try:
            data_descriptor = os.open(
                self.data_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            root_descriptor = os.open(
                root.name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=data_descriptor,
            )
            descriptor = os.open(path.name, flags, dir_fd=root_descriptor)
        except OSError:
            if root_descriptor:
                os.close(root_descriptor)
            if data_descriptor:
                os.close(data_descriptor)
            raise ExternalV3StateError("external replay artifact cannot be opened") from None
        try:
            self._revalidate_posix_artifact_roots(
                root,
                data_descriptor=data_descriptor,
                root_descriptor=root_descriptor,
            )
            opened = os.fstat(descriptor)
            self._require_safe_artifact_stat(opened, readonly=True)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ExternalV3StateError(
                    "external replay artifact changed before open"
                )
            chunks: list[bytes] = []
            observed = 0
            while True:
                chunk = os.read(descriptor, min(64 * 1024, max_bytes + 1 - observed))
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
                if observed > max_bytes:
                    raise ExternalV3StateError(
                        "external replay artifact exceeds its byte cap"
                    )
            after = os.fstat(descriptor)
            self._require_safe_artifact_stat(after, readonly=True)
            if (
                (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or after.st_size != observed
            ):
                raise ExternalV3StateError(
                    "external replay artifact changed during read"
                )
            current = os.stat(
                path.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            if (current.st_dev, current.st_ino) != (
                opened.st_dev,
                opened.st_ino,
            ):
                raise ExternalV3StateError(
                    "external replay artifact path changed during read"
                )
            self._revalidate_posix_artifact_roots(
                root,
                data_descriptor=data_descriptor,
                root_descriptor=root_descriptor,
            )
        finally:
            os.close(descriptor)
            os.close(root_descriptor)
            os.close(data_descriptor)
        final = self._validate_artifact_path(path, root=root)
        if (final.st_dev, final.st_ino, final.st_size) != (
            before.st_dev,
            before.st_ino,
            observed,
        ):
            raise ExternalV3StateError("external replay artifact path was replaced")
        return b"".join(chunks)

    def _write_once_managed_artifact(
        self,
        path: Path,
        *,
        root: Path,
        content: bytes,
        max_bytes: int,
        kind: str,
    ) -> None:
        if (
            type(content) is not bytes
            or len(content) > max_bytes
            or kind not in _DURABLE_WRITE_KINDS
        ):
            raise ExternalV3StateError("external replay artifact content is invalid")
        if os.name == "nt":
            self._write_managed_artifact_windows(
                path,
                root=root,
                content=content,
                max_bytes=max_bytes,
                kind=kind,
            )
            return
        self._ensure_artifact_root(root, create=True)
        if path.parent != root or path.name in {"", ".", ".."}:
            raise ExternalV3StateError("external replay artifact path is invalid")
        self._require_artifact_target_name(path.name)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        data_descriptor = root_descriptor = 0
        try:
            data_descriptor = os.open(
                self.data_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            root_descriptor = os.open(
                root.name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=data_descriptor,
            )
            descriptor = os.open(path.name, flags, 0o600, dir_fd=root_descriptor)
        except FileExistsError:
            if root_descriptor:
                os.close(root_descriptor)
            if data_descriptor:
                os.close(data_descriptor)
            if self._read_managed_artifact(
                path, root=root, max_bytes=max_bytes
            ) != content:
                raise ExternalV3StateError(
                    "append-only external artifact conflicts with durable bytes"
                )
            return
        except OSError:
            if root_descriptor:
                os.close(root_descriptor)
            if data_descriptor:
                os.close(data_descriptor)
            raise ExternalV3StateError(
                "append-only external artifact cannot be created"
            ) from None
        try:
            self._revalidate_posix_artifact_roots(
                root,
                data_descriptor=data_descriptor,
                root_descriptor=root_descriptor,
            )
            opened = os.fstat(descriptor)
            self._require_safe_artifact_stat(opened, readonly=False)
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise ExternalV3StateError(
                        "append-only external artifact write was incomplete"
                    )
                offset += written
            os.fsync(descriptor)
            self._artifact_write_cutpoint(kind, "AFTER_PAYLOAD_FSYNC")
            os.fchmod(descriptor, stat.S_IREAD)
            os.fsync(descriptor)
            self._require_safe_artifact_stat(os.fstat(descriptor), readonly=True)
            self._artifact_write_cutpoint(kind, "AFTER_READONLY_SEAL")
            current = os.stat(
                path.name,
                dir_fd=root_descriptor,
                follow_symlinks=False,
            )
            sealed = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != (
                sealed.st_dev,
                sealed.st_ino,
            ):
                raise ExternalV3StateError(
                    "sealed external artifact path identity drifted"
                )
            self._revalidate_posix_artifact_roots(
                root,
                data_descriptor=data_descriptor,
                root_descriptor=root_descriptor,
            )
            os.fsync(root_descriptor)
        except OSError:
            raise ExternalV3StateError(
                "append-only external artifact cannot be sealed"
            ) from None
        finally:
            os.close(descriptor)
            os.close(root_descriptor)
            os.close(data_descriptor)
        if self._read_managed_artifact(
            path, root=root, max_bytes=max_bytes
        ) != content:
            raise ExternalV3StateError("append-only external artifact did not seal")

    def _success_replay_path(
        self,
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        *,
        generation: int = 0,
    ) -> Path:
        _validate_bound_round(campaign, bound)
        if type(generation) is not int or generation < 0:
            raise ExternalV3StateError("external artifact generation is invalid")
        return self._success_replay_root / (
            f"success_{campaign.campaign_id}_{bound.ordinal}_{bound.request_sha256}_g{generation}.raw"
        )

    def _terminal_commitment_path(
        self,
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        *,
        generation: int = 0,
    ) -> Path:
        _validate_bound_round(campaign, bound)
        if type(generation) is not int or generation < 0:
            raise ExternalV3StateError("external artifact generation is invalid")
        return self._terminal_commitment_root / (
            f"terminal_{campaign.campaign_id}_{bound.ordinal}_{bound.request_sha256}_g{generation}.json"
        )

    def _artifact_exists(self, path: Path, *, root: Path) -> bool:
        self._require_artifact_target_name(path.name)
        if os.name == "nt":
            try:
                root.lstat()
            except FileNotFoundError:
                return False
            data_handle = root_handle = file_handle = 0
            try:
                data_handle, root_handle = self._open_windows_artifact_roots(
                    root, create=False
                )
                try:
                    file_handle, _ = _win_nt_open_relative(
                        root_handle,
                        path.name,
                        directory=False,
                        create=False,
                        writable=False,
                        share_delete=False,
                    )
                except OSError as error:
                    if error.errno in {
                        _WIN_ERROR_FILE_NOT_FOUND,
                        _WIN_ERROR_PATH_NOT_FOUND,
                    }:
                        return False
                    raise
                _win_require_file_handle(file_handle, readonly=True)
                self._revalidate_windows_artifact_roots(
                    root,
                    data_handle=data_handle,
                    root_handle=root_handle,
                )
                _win_verify_absolute_identity(path, file_handle, directory=False)
                return True
            except ExternalV3StateError:
                raise
            except OSError:
                raise ExternalV3StateError(
                    "external replay artifact presence is unsafe"
                ) from None
            finally:
                _win_close(file_handle)
                _win_close(root_handle)
                _win_close(data_handle)
        try:
            root.lstat()
        except FileNotFoundError:
            return False
        self._ensure_artifact_root(root, create=False)
        try:
            path.lstat()
        except FileNotFoundError:
            return False
        self._validate_artifact_path(path, root=root)
        return True

    def _validate_storage_path(self) -> None:
        # WAL and SHM are transient SQLite files.  Another process may remove
        # either one after ``exists`` but before the component walk or lstat.
        # Restart the *whole* validation on that benign race; never skip only
        # the raced component, because a replacement still has to pass the
        # reparse/regular/single-link checks.
        for attempt in range(_STORAGE_VALIDATION_ATTEMPTS):
            try:
                ensure_no_reparse_components(self.data_root)
                _win_verify_absolute_identity(
                    self.data_root,
                    self._managed_root_guard_handle,
                    directory=True,
                )
                for candidate in (
                    self._sqlite_path,
                    Path(str(self._sqlite_path) + "-wal"),
                    Path(str(self._sqlite_path) + "-shm"),
                ):
                    handle = 0
                    try:
                        try:
                            handle = _win_open_absolute(
                                candidate, directory=False
                            )
                        except OSError as error:
                            if (
                                candidate != self._sqlite_path
                                and error.errno
                                in {
                                    _WIN_ERROR_FILE_NOT_FOUND,
                                    _WIN_ERROR_PATH_NOT_FOUND,
                                }
                            ):
                                continue
                            raise
                        _win_require_file_handle(handle, readonly=False)
                        if (
                            _win_handle_identity(handle)
                            != self._managed_root_identity
                        ):
                            raise ExternalV3StateError(
                                "SQLite stream escaped managed directory identity"
                            )
                        _win_verify_absolute_identity(
                            candidate,
                            handle,
                            directory=False,
                            readonly=False,
                        )
                    finally:
                        _win_close(handle)
                return
            except (FileNotFoundError, PermissionError, OSError):
                if attempt + 1 == _STORAGE_VALIDATION_ATTEMPTS:
                    raise ExternalV3StateError(
                        "external campaign ledger files changed during validation"
                    ) from None

    def _connect(self) -> sqlite3.Connection:
        self._revalidate_windows_sqlite_guard()
        self._validate_storage_path()
        # The no-delete root and database handles remain open for the whole
        # ledger lifetime.  Consequently the namespace cannot be replaced in
        # the interval between this last identity check and sqlite3.connect.
        self._revalidate_windows_sqlite_guard()
        connection = sqlite3.connect(
            self._sqlite_path, timeout=10.0, isolation_level=None
        )
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA busy_timeout = 10000")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute("PRAGMA foreign_keys = ON")
            # The open connection pins its SQLite sidecars.  Revalidate after
            # SQLite has materialized them so the pre-open check is not the
            # only security boundary.
            self._validate_storage_path()
            self._revalidate_windows_sqlite_guard()
            return connection
        except Exception:
            connection.close()
            raise

    def _initialize(self, *, existing: bool) -> None:
        connection = self._connect()
        try:
            if existing:
                connection.execute("BEGIN")
                self._validate_schema(connection)
                connection.rollback()
            else:
                connection.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS campaigns (
                        campaign_id TEXT PRIMARY KEY,
                        manifest_sha256 TEXT NOT NULL UNIQUE,
                        manifest_bytes BLOB NOT NULL,
                        state TEXT NOT NULL CHECK (state IN (
                            'PREREGISTERED','FAKE_EXTERNAL_APPROVED','RUNNING',
                            'COMPLETE','FAILED','AMBIGUOUS'
                        )),
                        approval_evidence_sha256 TEXT,
                        approval_binding_sha256 TEXT,
                        reserved_cost_micros INTEGER NOT NULL DEFAULT 0,
                        actual_cost_micros INTEGER NOT NULL DEFAULT 0,
                        total_tokens INTEGER NOT NULL DEFAULT 0,
                        elapsed_seconds REAL NOT NULL DEFAULT 0,
                        schema_version TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS rounds (
                        campaign_id TEXT NOT NULL REFERENCES campaigns(campaign_id),
                        ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 3),
                        round_id TEXT NOT NULL,
                        template_sha256 TEXT NOT NULL,
                        state TEXT NOT NULL CHECK (state IN (
                            'TEMPLATE_BOUND','REQUEST_BOUND','CLAIMED','DISPATCH_INTENT',
                            'ARTIFACT_PREPARED','ARTIFACT_RECOVERY_REQUIRED',
                            'COMMITMENT_PREPARED','COMMITMENT_RECOVERY_REQUIRED',
                            'RESPONSE_COMMITTED','CONSUMED','FAILED_NO_RETRY',
                            'AMBIGUOUS_NO_RETRY'
                        )),
                        request_bytes BLOB,
                        request_sha256 TEXT,
                        prior_output_sha256 TEXT,
                        prior_output_chain_sha256 TEXT,
                        owner_nonce_sha256 TEXT,
                        dispatch_intent_sha256 TEXT,
                        campaign_elapsed_before_dispatch_seconds REAL,
                        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 1),
                        reserved_cost_micros INTEGER NOT NULL DEFAULT 0,
                        actual_cost_micros INTEGER,
                        total_tokens INTEGER,
                        advisory_bytes BLOB,
                        advisory_sha256 TEXT,
                        output_chain_sha256 TEXT,
                        receipt_bytes BLOB,
                        receipt_sha256 TEXT,
                        raw_response_sha256 TEXT,
                        response_bytes INTEGER,
                        elapsed_seconds REAL,
                        durable_write_kind TEXT,
                        durable_write_generation INTEGER,
                        durable_write_request_sha256 TEXT,
                        durable_write_raw_sha256 TEXT,
                        durable_write_raw_size INTEGER,
                        durable_write_target TEXT,
                        durable_write_payload_sha256 TEXT,
                        durable_write_payload_size INTEGER,
                        durable_write_phase TEXT,
                        PRIMARY KEY (campaign_id, ordinal),
                        UNIQUE (campaign_id, round_id),
                        UNIQUE (campaign_id, request_sha256),
                        UNIQUE (campaign_id, dispatch_intent_sha256)
                    );
                    PRAGMA application_id = 1364346931;
                    PRAGMA user_version = 4;
                    """
                )
                self._validate_schema(connection)
        finally:
            connection.close()
        if existing:
            self._reconcile_prepared_rounds()
            connection = self._connect()
            try:
                connection.execute("BEGIN")
                self._validate_all_durable_campaigns(connection)
                connection.rollback()
            finally:
                connection.close()

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0]
            != _LEDGER_APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0]
            != _LEDGER_USER_VERSION
        ):
            raise ExternalV3StateError("external campaign ledger identity is invalid")
        expected = {
            "campaigns": {
                "campaign_id", "manifest_sha256", "manifest_bytes", "state",
                "approval_evidence_sha256", "approval_binding_sha256",
                "reserved_cost_micros", "actual_cost_micros", "total_tokens",
                "elapsed_seconds", "schema_version",
            },
            "rounds": {
                "campaign_id", "ordinal", "round_id", "template_sha256", "state",
                "request_bytes", "request_sha256", "prior_output_sha256",
                "prior_output_chain_sha256", "owner_nonce_sha256",
                "dispatch_intent_sha256", "campaign_elapsed_before_dispatch_seconds",
                "attempts", "reserved_cost_micros", "actual_cost_micros",
                "total_tokens", "advisory_bytes", "advisory_sha256",
                "output_chain_sha256", "receipt_bytes", "receipt_sha256",
                "raw_response_sha256", "response_bytes", "elapsed_seconds",
                "durable_write_kind", "durable_write_generation",
                "durable_write_request_sha256", "durable_write_raw_sha256",
                "durable_write_raw_size", "durable_write_target",
                "durable_write_payload_sha256", "durable_write_payload_size",
                "durable_write_phase",
            },
        }
        observed_tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if observed_tables != set(expected):
            raise ExternalV3StateError(
                "external campaign ledger table set is not closed"
            )
        for table, columns in expected.items():
            observed = {
                str(row[1]) for row in connection.execute(f"PRAGMA table_info({table})")
            }
            if observed != columns:
                raise ExternalV3StateError(
                    f"external campaign ledger {table} schema is not closed"
                )

    def _mark_prepared_recovery(
        self, *, campaign_id: str, ordinal: int, prepared_state: str
    ) -> None:
        recovery_state = {
            "ARTIFACT_PREPARED": "ARTIFACT_RECOVERY_REQUIRED",
            "COMMITMENT_PREPARED": "COMMITMENT_RECOVERY_REQUIRED",
        }.get(prepared_state)
        if recovery_state is None:
            raise ExternalV3StateError("prepared recovery state is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE rounds SET state=?,durable_write_phase='RECOVERY_REQUIRED'
                 WHERE campaign_id=? AND ordinal=? AND state=?
                   AND durable_write_phase='INTENT_DURABLE'
                """,
                (recovery_state, campaign_id, ordinal, prepared_state),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("prepared recovery CAS failed")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _reconcile_prepared_rounds(self) -> None:
        """Resolve every durable PREPARED row without repeating a dispatch.

        A complete, readonly artifact is replayed and finalized.  Missing,
        partial, writable, or identity-drifted bytes become an explicit
        RECOVERY_REQUIRED state; the ledger remains constructible and a caller
        holding the exact synthetic response can retry onto a fresh generation.
        """

        connection = self._connect()
        try:
            prepared = connection.execute(
                """
                SELECT campaign_id,ordinal,state FROM rounds
                 WHERE state IN ('ARTIFACT_PREPARED','COMMITMENT_PREPARED')
                 ORDER BY campaign_id,ordinal
                """
            ).fetchall()
        finally:
            connection.close()
        for candidate in prepared:
            connection = self._connect()
            database_intent_validated = False
            prepared_snapshot: tuple[object, ...] | None = None
            try:
                connection.execute("BEGIN")
                campaign_row = connection.execute(
                    "SELECT * FROM campaigns WHERE campaign_id=?",
                    (candidate["campaign_id"],),
                ).fetchone()
                if campaign_row is None:
                    raise ExternalV3StateError(
                        "prepared write campaign is unavailable"
                    )
                campaign = self._campaign_from_durable_row(campaign_row)
                # This validates all DB-side intent and receipt fields without
                # granting release authority to the not-yet-final artifact.
                self._validate_campaign_durable_state(connection, campaign)
                row = connection.execute(
                    "SELECT * FROM rounds WHERE campaign_id=? AND ordinal=?",
                    (campaign.campaign_id, candidate["ordinal"]),
                ).fetchone()
                if row is None or row["state"] != candidate["state"]:
                    raise ExternalV3StateError("prepared write state changed")
                prepared_snapshot = tuple(row)
                bound = BoundExternalRoundV3(
                    campaign_id=campaign.campaign_id,
                    manifest_sha256=campaign.manifest_sha256,
                    round_id=row["round_id"],
                    ordinal=row["ordinal"],
                    request_bytes=row["request_bytes"],
                    request_sha256=row["request_sha256"],
                    prior_output_sha256=row["prior_output_sha256"],
                    prior_output_chain_sha256=row[
                        "prior_output_chain_sha256"
                    ],
                )
                approval = self._approval_rows(connection, campaign)
                database_intent_validated = True
                if row["state"] == "ARTIFACT_PREPARED":
                    replayed = self._replay_success_response(
                        campaign,
                        bound,
                        row,
                        phases=frozenset({"INTENT_DURABLE"}),
                    )
                    self._validate_durable_receipt(
                        campaign,
                        row,
                        expected_status="SUCCEEDED",
                        approval_evidence_sha256=approval[
                            "approval_evidence_sha256"
                        ],
                        approval_binding_sha256=approval[
                            "approval_binding_sha256"
                        ],
                        parsed_response=replayed,
                    )
                else:
                    prepared_receipt_raw = _strict_json_loads(
                        row["receipt_bytes"], label="prepared terminal receipt"
                    )
                    if type(prepared_receipt_raw) is not dict:
                        raise ExternalV3StateError(
                            "prepared terminal receipt is invalid"
                        )
                    prepared_receipt = self._validate_durable_receipt(
                        campaign,
                        row,
                        expected_status=prepared_receipt_raw["status"],
                        approval_evidence_sha256=approval[
                            "approval_evidence_sha256"
                        ],
                        approval_binding_sha256=approval[
                            "approval_binding_sha256"
                        ],
                    )
                    self._validate_terminal_commitment(
                        campaign,
                        bound,
                        row,
                        prepared_receipt,
                        phases=frozenset({"INTENT_DURABLE"}),
                    )
                connection.rollback()
            except ExternalV3StateError:
                connection.rollback()
                if not database_intent_validated:
                    raise
                connection.close()
                self._mark_prepared_recovery(
                    campaign_id=candidate["campaign_id"],
                    ordinal=candidate["ordinal"],
                    prepared_state=candidate["state"],
                )
                continue
            finally:
                try:
                    connection.close()
                except Exception:
                    pass

            connection = self._connect()
            second_database_validated = False
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM rounds WHERE campaign_id=? AND ordinal=?",
                    (candidate["campaign_id"], candidate["ordinal"]),
                ).fetchone()
                if row is None or row["state"] != candidate["state"]:
                    raise ExternalV3StateError("prepared finalize state changed")
                if prepared_snapshot is None or tuple(row) != prepared_snapshot:
                    raise ExternalV3StateError(
                        "prepared write changed between reconciliation phases"
                    )
                campaign_row = connection.execute(
                    "SELECT * FROM campaigns WHERE campaign_id=? AND state='RUNNING'",
                    (candidate["campaign_id"],),
                ).fetchone()
                if campaign_row is None:
                    raise ExternalV3StateError(
                        "prepared finalize campaign is not running"
                    )
                campaign = self._campaign_from_durable_row(campaign_row)
                second_database_validated = True
                bound = BoundExternalRoundV3(
                    campaign_id=campaign.campaign_id,
                    manifest_sha256=campaign.manifest_sha256,
                    round_id=row["round_id"],
                    ordinal=row["ordinal"],
                    request_bytes=row["request_bytes"],
                    request_sha256=row["request_sha256"],
                    prior_output_sha256=row["prior_output_sha256"],
                    prior_output_chain_sha256=row[
                        "prior_output_chain_sha256"
                    ],
                )
                if candidate["state"] == "ARTIFACT_PREPARED":
                    self._replay_success_response(
                        campaign,
                        bound,
                        row,
                        phases=frozenset({"INTENT_DURABLE"}),
                    )
                    new_cost = campaign_row["actual_cost_micros"] + row[
                        "actual_cost_micros"
                    ]
                    new_tokens = campaign_row["total_tokens"] + row["total_tokens"]
                    if (
                        new_cost > campaign.pricing.max_campaign_cost_micros
                        or new_tokens > campaign.pricing.max_campaign_total_tokens
                    ):
                        raise ExternalV3StateError(
                            "prepared success exceeds campaign budget"
                        )
                    connection.execute(
                        """
                        UPDATE rounds SET state='RESPONSE_COMMITTED',
                                          durable_write_phase='SEALED_COMMITTED'
                         WHERE campaign_id=? AND ordinal=? AND state='ARTIFACT_PREPARED'
                        """,
                        (candidate["campaign_id"], candidate["ordinal"]),
                    )
                    connection.execute(
                        """
                        UPDATE campaigns SET actual_cost_micros=?,total_tokens=?,elapsed_seconds=?
                         WHERE campaign_id=? AND state='RUNNING'
                        """,
                        (
                            new_cost,
                            new_tokens,
                            row["campaign_elapsed_before_dispatch_seconds"]
                            + row["elapsed_seconds"],
                            candidate["campaign_id"],
                        ),
                    )
                else:
                    receipt = _strict_json_loads(
                        row["receipt_bytes"], label="prepared terminal receipt"
                    )
                    self._validate_terminal_commitment(
                        campaign,
                        bound,
                        row,
                        receipt,
                        phases=frozenset({"INTENT_DURABLE"}),
                    )
                    final_state = receipt["status"]
                    campaign_state = (
                        "AMBIGUOUS"
                        if final_state == "AMBIGUOUS_NO_RETRY"
                        else "FAILED"
                    )
                    connection.execute(
                        """
                        UPDATE rounds SET state=?,durable_write_phase='SEALED_COMMITTED'
                         WHERE campaign_id=? AND ordinal=? AND state='COMMITMENT_PREPARED'
                        """,
                        (
                            final_state,
                            candidate["campaign_id"],
                            candidate["ordinal"],
                        ),
                    )
                    connection.execute(
                        """
                        UPDATE campaigns SET state=?,elapsed_seconds=?
                         WHERE campaign_id=? AND state='RUNNING'
                        """,
                        (
                            campaign_state,
                            row["campaign_elapsed_before_dispatch_seconds"]
                            + (row["elapsed_seconds"] or 0.0),
                            candidate["campaign_id"],
                        ),
                    )
                connection.commit()
            except ExternalV3StateError:
                connection.rollback()
                if not second_database_validated:
                    raise
                connection.close()
                self._mark_prepared_recovery(
                    campaign_id=candidate["campaign_id"],
                    ordinal=candidate["ordinal"],
                    prepared_state=candidate["state"],
                )
                continue
            except Exception:
                connection.rollback()
                raise
            finally:
                connection.close()

    @staticmethod
    def _campaign_from_durable_row(row: sqlite3.Row) -> ExternalCampaignV3:
        """Reconstruct a campaign from canonical public manifest bytes only."""

        raw = row["manifest_bytes"]
        try:
            if type(raw) is not bytes:
                raise TypeError("manifest is not bytes")
            value = _strict_json_loads(raw, label="durable campaign manifest")
            if type(value) is not dict:
                raise TypeError("manifest is not an object")
            provider = value["provider_pin"]
            pricing_value = value["pricing_budget"]
            if type(provider) is not dict or type(pricing_value) is not dict:
                raise TypeError("manifest projections are not objects")
            campaign = ExternalCampaignV3(
                campaign_id=row["campaign_id"],
                manifest_bytes=raw,
                manifest_sha256=row["manifest_sha256"],
                pin=ProviderPin(**provider),
                identity_evidence_sha256=value["identity_evidence_sha256"],
                pricing=PricingBudgetV3(**pricing_value),
                transport_build_sha256=value["transport_build_sha256"],
            )
            validate_external_campaign_v3(campaign)
            return campaign
        except Exception:
            raise ExternalV3StateError(
                "durable campaign manifest cannot be reconstructed"
            ) from None

    @staticmethod
    def _require_null_round_fields(
        row: sqlite3.Row, fields: tuple[str, ...], *, label: str
    ) -> None:
        if any(row[field] is not None for field in fields):
            raise ExternalV3StateError(f"{label} carries forbidden durable fields")

    @staticmethod
    def _durable_write_fields() -> tuple[str, ...]:
        return (
            "durable_write_kind",
            "durable_write_generation",
            "durable_write_request_sha256",
            "durable_write_raw_sha256",
            "durable_write_raw_size",
            "durable_write_target",
            "durable_write_payload_sha256",
            "durable_write_payload_size",
            "durable_write_phase",
        )

    def _validate_durable_write_metadata(
        self,
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        row: sqlite3.Row,
        *,
        kind: str,
        phases: frozenset[str],
    ) -> Path:
        if kind not in _DURABLE_WRITE_KINDS or not phases <= _DURABLE_WRITE_PHASES:
            raise ExternalV3StateError("durable write validation policy is invalid")
        generation = row["durable_write_generation"]
        target = row["durable_write_target"]
        raw_sha = row["durable_write_raw_sha256"]
        raw_size = row["durable_write_raw_size"]
        payload_sha = row["durable_write_payload_sha256"]
        payload_size = row["durable_write_payload_size"]
        if (
            row["durable_write_kind"] != kind
            or type(generation) is not int
            or generation < 0
            or row["durable_write_request_sha256"] != bound.request_sha256
            or type(target) is not str
            or not _ARTIFACT_TARGET.fullmatch(target)
            or row["durable_write_phase"] not in phases
            or raw_sha != row["raw_response_sha256"]
            or raw_size != row["response_bytes"]
            or (raw_sha is not None and not _SHA256.fullmatch(raw_sha))
            or (raw_size is not None and (type(raw_size) is not int or raw_size < 0))
            or type(payload_sha) is not str
            or not _SHA256.fullmatch(payload_sha)
            or type(payload_size) is not int
            or payload_size < 0
        ):
            raise ExternalV3StateError("durable write intent drifted")
        expected = (
            self._success_replay_path(campaign, bound, generation=generation)
            if kind == "SUCCESS_REPLAY"
            else self._terminal_commitment_path(
                campaign, bound, generation=generation
            )
        )
        if target != expected.name:
            raise ExternalV3StateError("durable write target drifted")
        if kind == "SUCCESS_REPLAY" and (
            payload_sha != raw_sha or payload_size != raw_size
        ):
            raise ExternalV3StateError("success replay write intent drifted")
        return expected

    def _validate_all_durable_campaigns(
        self, connection: sqlite3.Connection
    ) -> None:
        for row in connection.execute(
            "SELECT * FROM campaigns ORDER BY campaign_id"
        ).fetchall():
            campaign = self._campaign_from_durable_row(row)
            self._validate_campaign_durable_state(connection, campaign)

    def _validate_campaign_durable_state(
        self,
        connection: sqlite3.Connection,
        campaign: ExternalCampaignV3,
    ) -> None:
        """Replay a complete campaign snapshot, including closed terminal rows."""

        campaign_row = self._require_campaign_row(connection, campaign)
        rows = connection.execute(
            "SELECT * FROM rounds WHERE campaign_id=? ORDER BY ordinal",
            (campaign.campaign_id,),
        ).fetchall()
        templates = _round_template_rows()
        if len(rows) != EXTERNAL_V3_ROUND_COUNT:
            raise ExternalV3StateError("durable campaign round count drifted")
        for ordinal, (row, template) in enumerate(zip(rows, templates, strict=True)):
            if (
                row["ordinal"] != ordinal
                or row["round_id"] != template["round_id"]
                or row["template_sha256"] != template["template_sha256"]
            ):
                raise ExternalV3StateError("durable round template drifted")

        campaign_state = campaign_row["state"]
        approval_evidence = campaign_row["approval_evidence_sha256"]
        approval_binding = campaign_row["approval_binding_sha256"]
        if campaign_state == "PREREGISTERED":
            if approval_evidence is not None or approval_binding is not None:
                raise ExternalV3StateError("preregistered campaign carries approval")
        else:
            try:
                evidence = _require_sha256(
                    approval_evidence, label="durable approval evidence hash"
                )
                expected_approval = _sha256_json(
                    {
                        "campaign_manifest_sha256": campaign.manifest_sha256,
                        "approval_evidence_sha256": evidence,
                        "transport_state": EXTERNAL_V3_TRANSPORT_STATE,
                    }
                )
            except Exception:
                raise ExternalV3StateError(
                    "durable campaign approval cannot be replayed"
                ) from None
            if approval_binding != expected_approval:
                raise ExternalV3StateError("durable campaign approval drifted")

        prefix_count = 0
        while (
            prefix_count < EXTERNAL_V3_ROUND_COUNT
            and rows[prefix_count]["state"] == "CONSUMED"
        ):
            prefix_count += 1
        previous, chain, actual_cost, total_tokens, elapsed = (
            self._replay_consumed_prefix(
                connection, campaign, count=prefix_count
            )
        )

        request_fields = (
            "request_bytes",
            "request_sha256",
            "prior_output_sha256",
            "prior_output_chain_sha256",
        )
        ownership_fields = (
            "owner_nonce_sha256",
            "dispatch_intent_sha256",
            "campaign_elapsed_before_dispatch_seconds",
        )
        response_fields = (
            "actual_cost_micros",
            "total_tokens",
            "advisory_bytes",
            "advisory_sha256",
            "output_chain_sha256",
            "receipt_bytes",
            "receipt_sha256",
            "raw_response_sha256",
            "response_bytes",
            "elapsed_seconds",
        )
        durable_write_fields = self._durable_write_fields()
        attempted_states = frozenset(
            {
                "DISPATCH_INTENT",
                "ARTIFACT_PREPARED",
                "ARTIFACT_RECOVERY_REQUIRED",
                "COMMITMENT_PREPARED",
                "COMMITMENT_RECOVERY_REQUIRED",
                "RESPONSE_COMMITTED",
                "CONSUMED",
                "FAILED_NO_RETRY",
                "AMBIGUOUS_NO_RETRY",
            }
        )
        reserve = campaign.pricing.worst_round_cost_micros()
        attempted_count = 0
        for row in rows:
            attempted = row["state"] in attempted_states
            if row["attempts"] != (1 if attempted else 0):
                raise ExternalV3StateError("durable round attempt count drifted")
            if row["reserved_cost_micros"] != (reserve if attempted else 0):
                raise ExternalV3StateError("durable round reservation drifted")
            attempted_count += int(attempted)

        for row in rows[prefix_count + 1 :]:
            if row["state"] != "TEMPLATE_BOUND":
                raise ExternalV3StateError("durable round sequence is not closed")
            self._require_null_round_fields(
                row,
                request_fields
                + ownership_fields
                + response_fields
                + durable_write_fields,
                label="future template round",
            )

        if prefix_count == EXTERNAL_V3_ROUND_COUNT:
            if campaign_state != "COMPLETE":
                raise ExternalV3StateError("fully consumed campaign is not complete")
        else:
            current = rows[prefix_count]
            current_state = current["state"]
            expected_campaign_state = {
                "FAILED_NO_RETRY": "FAILED",
                "AMBIGUOUS_NO_RETRY": "AMBIGUOUS",
            }.get(current_state)
            if expected_campaign_state is not None:
                if campaign_state != expected_campaign_state:
                    raise ExternalV3StateError(
                        "terminal campaign and round states disagree"
                    )
            elif campaign_state == "PREREGISTERED":
                if prefix_count != 0 or current_state != "TEMPLATE_BOUND":
                    raise ExternalV3StateError(
                        "preregistered campaign has advanced durable state"
                    )
            elif campaign_state == "FAKE_EXTERNAL_APPROVED":
                if prefix_count != 0 or current_state not in {
                    "TEMPLATE_BOUND",
                    "REQUEST_BOUND",
                    "CLAIMED",
                }:
                    raise ExternalV3StateError(
                        "approved campaign state is inconsistent"
                    )
            elif campaign_state == "RUNNING":
                if current_state not in {
                    "TEMPLATE_BOUND",
                    "REQUEST_BOUND",
                    "CLAIMED",
                    "DISPATCH_INTENT",
                    "ARTIFACT_PREPARED",
                    "ARTIFACT_RECOVERY_REQUIRED",
                    "COMMITMENT_PREPARED",
                    "COMMITMENT_RECOVERY_REQUIRED",
                    "RESPONSE_COMMITTED",
                }:
                    raise ExternalV3StateError("running campaign state is inconsistent")
            else:
                raise ExternalV3StateError("campaign terminal state is inconsistent")

            if current_state == "TEMPLATE_BOUND":
                template_bound = derive_external_round_v3(
                    campaign,
                    ordinal=prefix_count,
                    prior_advisory=previous,
                    prior_output_chain_sha256=chain,
                )
                if self._artifact_exists(
                    self._success_replay_path(campaign, template_bound),
                    root=self._success_replay_root,
                ) or self._artifact_exists(
                    self._terminal_commitment_path(campaign, template_bound),
                    root=self._terminal_commitment_root,
                ):
                    raise ExternalV3StateError(
                        "template round unexpectedly carries a durable artifact"
                    )
                self._require_null_round_fields(
                    current,
                    request_fields
                    + ownership_fields
                    + response_fields
                    + durable_write_fields,
                    label="template round",
                )
            else:
                expected_bound = derive_external_round_v3(
                    campaign,
                    ordinal=prefix_count,
                    prior_advisory=previous,
                    prior_output_chain_sha256=chain,
                )
                if any(
                    current[field] != expected
                    for field, expected in (
                        ("request_bytes", expected_bound.request_bytes),
                        ("request_sha256", expected_bound.request_sha256),
                        ("prior_output_sha256", expected_bound.prior_output_sha256),
                        (
                            "prior_output_chain_sha256",
                            expected_bound.prior_output_chain_sha256,
                        ),
                    )
                ):
                    raise ExternalV3StateError(
                        "current durable request cannot be re-derived"
                    )
                terminal_states = {
                    "FAILED_NO_RETRY",
                    "AMBIGUOUS_NO_RETRY",
                }
                success_write_states = {
                    "ARTIFACT_PREPARED",
                    "ARTIFACT_RECOVERY_REQUIRED",
                    "RESPONSE_COMMITTED",
                    "CONSUMED",
                }
                terminal_write_states = {
                    "COMMITMENT_PREPARED",
                    "COMMITMENT_RECOVERY_REQUIRED",
                    *terminal_states,
                }
                if current_state not in success_write_states and self._artifact_exists(
                    self._success_replay_path(campaign, expected_bound),
                    root=self._success_replay_root,
                ):
                    raise ExternalV3StateError(
                        "non-success round carries a success replay artifact"
                    )
                if current_state not in terminal_write_states and self._artifact_exists(
                    self._terminal_commitment_path(campaign, expected_bound),
                    root=self._terminal_commitment_root,
                ):
                    raise ExternalV3StateError(
                        "non-terminal round carries a terminal commitment"
                    )
                if current_state == "REQUEST_BOUND":
                    self._require_null_round_fields(
                        current,
                        ownership_fields + response_fields + durable_write_fields,
                        label="request-bound round",
                    )
                else:
                    try:
                        owner_hash = _require_sha256(
                            current["owner_nonce_sha256"],
                            label="durable owner hash",
                        )
                    except Exception:
                        raise ExternalV3StateError(
                            "durable owner identity drifted"
                        ) from None
                    if current_state == "CLAIMED":
                        self._require_null_round_fields(
                            current,
                            (
                                "dispatch_intent_sha256",
                                "campaign_elapsed_before_dispatch_seconds",
                            )
                            + response_fields
                            + durable_write_fields,
                            label="claimed round",
                        )
                    else:
                        expected_intent_sha = _sha256_json(
                            {
                                "campaign_manifest_sha256": campaign.manifest_sha256,
                                "round_id": expected_bound.round_id,
                                "ordinal": expected_bound.ordinal,
                                "request_sha256": expected_bound.request_sha256,
                                "owner_nonce_sha256": owner_hash,
                                "attempt": 1,
                                "reserved_cost_micros": reserve,
                            }
                        )
                        if (
                            current["dispatch_intent_sha256"]
                            != expected_intent_sha
                            or current[
                                "campaign_elapsed_before_dispatch_seconds"
                            ]
                            != elapsed
                        ):
                            raise ExternalV3StateError(
                                "durable dispatch intent cannot be replayed"
                            )
                        if current_state == "DISPATCH_INTENT":
                            self._require_null_round_fields(
                                current,
                                response_fields + durable_write_fields,
                                label="dispatch-intent round",
                            )
                        elif current_state in {
                            "ARTIFACT_PREPARED",
                            "ARTIFACT_RECOVERY_REQUIRED",
                        }:
                            self._validate_durable_write_metadata(
                                campaign,
                                expected_bound,
                                current,
                                kind="SUCCESS_REPLAY",
                                phases=frozenset(
                                    {
                                        "INTENT_DURABLE"
                                        if current_state == "ARTIFACT_PREPARED"
                                        else "RECOVERY_REQUIRED"
                                    }
                                ),
                            )
                            self._decode_durable_advisory(
                                current, expected_round_id=expected_bound.round_id
                            )
                            self._validate_durable_receipt(
                                campaign,
                                current,
                                expected_status="SUCCEEDED",
                                approval_evidence_sha256=approval_evidence,
                                approval_binding_sha256=approval_binding,
                            )
                        elif current_state in {
                            "COMMITMENT_PREPARED",
                            "COMMITMENT_RECOVERY_REQUIRED",
                        }:
                            self._validate_durable_write_metadata(
                                campaign,
                                expected_bound,
                                current,
                                kind="TERMINAL_COMMITMENT",
                                phases=frozenset(
                                    {
                                        "INTENT_DURABLE"
                                        if current_state == "COMMITMENT_PREPARED"
                                        else "RECOVERY_REQUIRED"
                                    }
                                ),
                            )
                            self._validate_durable_receipt(
                                campaign,
                                current,
                                expected_status=(
                                    _strict_json_loads(
                                        current["receipt_bytes"],
                                        label="prepared terminal receipt",
                                    )["status"]
                                ),
                                approval_evidence_sha256=approval_evidence,
                                approval_binding_sha256=approval_binding,
                            )
                        elif current_state == "RESPONSE_COMMITTED":
                            self._validate_durable_write_metadata(
                                campaign,
                                expected_bound,
                                current,
                                kind="SUCCESS_REPLAY",
                                phases=frozenset({"SEALED_COMMITTED"}),
                            )
                            parsed = self._replay_success_response(
                                campaign, expected_bound, current
                            )
                            advisory = self._decode_durable_advisory(
                                current, expected_round_id=expected_bound.round_id
                            )
                            advisory_sha = _sha256_bytes(
                                canonical_json(advisory).encode("utf-8")
                            )
                            if current["output_chain_sha256"] != advance_output_chain(
                                chain, advisory_sha
                            ):
                                raise ExternalV3StateError(
                                    "committed output chain drifted"
                                )
                            self._validate_durable_receipt(
                                campaign,
                                current,
                                expected_status="SUCCEEDED",
                                approval_evidence_sha256=approval_evidence,
                                approval_binding_sha256=approval_binding,
                                parsed_response=parsed,
                            )
                            actual_cost += _require_exact_int(
                                current["actual_cost_micros"],
                                label="committed actual cost",
                            )
                            total_tokens += _require_exact_int(
                                current["total_tokens"],
                                label="committed total tokens",
                            )
                            elapsed += _require_finite_float(
                                current["elapsed_seconds"],
                                label="committed elapsed seconds",
                            )
                        elif current_state in {
                            "FAILED_NO_RETRY",
                            "AMBIGUOUS_NO_RETRY",
                        }:
                            self._validate_durable_write_metadata(
                                campaign,
                                expected_bound,
                                current,
                                kind="TERMINAL_COMMITMENT",
                                phases=frozenset({"SEALED_COMMITTED"}),
                            )
                            terminal_receipt = self._validate_durable_receipt(
                                campaign,
                                current,
                                expected_status=current_state,
                                approval_evidence_sha256=approval_evidence,
                                approval_binding_sha256=approval_binding,
                            )
                            self._validate_terminal_commitment(
                                campaign,
                                expected_bound,
                                current,
                                terminal_receipt,
                            )
                            terminal_elapsed = current["elapsed_seconds"]
                            if terminal_elapsed is not None:
                                elapsed += _require_finite_float(
                                    terminal_elapsed,
                                    label="terminal elapsed seconds",
                                )
                        else:
                            raise ExternalV3StateError(
                                "current durable round state is invalid"
                            )

        if (
            campaign_row["reserved_cost_micros"] != attempted_count * reserve
            or campaign_row["actual_cost_micros"] != actual_cost
            or campaign_row["total_tokens"] != total_tokens
            or campaign_row["elapsed_seconds"] != elapsed
        ):
            raise ExternalV3StateError("durable campaign aggregates drifted")

    def install(self, campaign: ExternalCampaignV3) -> None:
        validate_external_campaign_v3(campaign)
        templates = _round_template_rows()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT INTO campaigns VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    campaign.campaign_id,
                    campaign.manifest_sha256,
                    campaign.manifest_bytes,
                    "PREREGISTERED",
                    None,
                    None,
                    0,
                    0,
                    0,
                    0.0,
                    EXTERNAL_V3_LEDGER_SCHEMA,
                ),
            )
            connection.executemany(
                "INSERT INTO rounds (campaign_id,ordinal,round_id,template_sha256,state) VALUES (?,?,?,?,?)",
                [
                    (
                        campaign.campaign_id,
                        row["ordinal"],
                        row["round_id"],
                        row["template_sha256"],
                        "TEMPLATE_BOUND",
                    )
                    for row in templates
                ],
            )
            connection.commit()
        except sqlite3.IntegrityError:
            connection.rollback()
            raise ExternalV3StateError("external campaign is already installed") from None
        finally:
            connection.close()

    def approve_fake(
        self,
        campaign: ExternalCampaignV3,
        *,
        approval_evidence_sha256: str,
    ) -> str:
        validate_external_campaign_v3(campaign)
        _require_sha256(approval_evidence_sha256, label="approval evidence hash")
        approval_binding = _sha256_json(
            {
                "campaign_manifest_sha256": campaign.manifest_sha256,
                "approval_evidence_sha256": approval_evidence_sha256,
                "transport_state": EXTERNAL_V3_TRANSPORT_STATE,
            }
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE campaigns
                   SET state='FAKE_EXTERNAL_APPROVED',
                       approval_evidence_sha256=?, approval_binding_sha256=?
                 WHERE campaign_id=? AND manifest_sha256=? AND state='PREREGISTERED'
                """,
                (
                    approval_evidence_sha256,
                    approval_binding,
                    campaign.campaign_id,
                    campaign.manifest_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("fake approval CAS failed")
            connection.commit()
            return approval_binding
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def approve_external(self, *_args: object, **_kwargs: object) -> None:
        raise ExternalV3Disabled("real external approval is absent from the v3 skeleton")

    def _require_campaign_row(
        self,
        connection: sqlite3.Connection,
        campaign: ExternalCampaignV3,
        *,
        states: frozenset[str] | None = None,
    ) -> sqlite3.Row:
        validate_external_campaign_v3(campaign)
        row = connection.execute(
            "SELECT * FROM campaigns WHERE campaign_id=?", (campaign.campaign_id,)
        ).fetchone()
        if (
            row is None
            or row["manifest_sha256"] != campaign.manifest_sha256
            or row["manifest_bytes"] != campaign.manifest_bytes
            or row["schema_version"] != EXTERNAL_V3_LEDGER_SCHEMA
            or (states is not None and row["state"] not in states)
        ):
            raise ExternalV3StateError("durable campaign identity or state drifted")
        return row

    @staticmethod
    def _decode_durable_advisory(
        row: sqlite3.Row, *, expected_round_id: str
    ) -> dict[str, object]:
        raw = row["advisory_bytes"]
        if type(raw) is not bytes:
            raise ExternalV3StateError("durable advisory bytes are unavailable")
        decoded = _strict_json_loads(raw, label="durable prior advisory")
        advisory = _validate_external_public_advisory(
            decoded, round_id=expected_round_id
        )
        canonical = canonical_json(advisory).encode("utf-8")
        if (
            canonical != raw
            or row["advisory_sha256"] != _sha256_bytes(canonical)
        ):
            raise ExternalV3StateError("durable advisory identity drifted")
        return advisory

    def _replay_consumed_prefix(
        self,
        connection: sqlite3.Connection,
        campaign: ExternalCampaignV3,
        *,
        count: int,
    ) -> tuple[dict[str, object] | None, str, int, int, float]:
        """Re-derive every request/advisory/receipt link before later use."""

        previous: dict[str, object] | None = None
        chain = _ZERO_SHA256
        actual_cost = 0
        total_tokens = 0
        elapsed_seconds = 0.0
        approval = self._approval_rows(connection, campaign) if count else None
        for ordinal in range(count):
            assert approval is not None
            row = connection.execute(
                "SELECT * FROM rounds WHERE campaign_id=? AND ordinal=?",
                (campaign.campaign_id, ordinal),
            ).fetchone()
            if row is None or row["state"] != "CONSUMED":
                raise ExternalV3StateError("durable prior round is not consumed")
            expected = derive_external_round_v3(
                campaign,
                ordinal=ordinal,
                prior_advisory=previous,
                prior_output_chain_sha256=chain,
            )
            template = _round_template_rows()[ordinal]
            if (
                row["round_id"] != expected.round_id
                or row["template_sha256"] != template["template_sha256"]
                or row["request_bytes"] != expected.request_bytes
                or row["request_sha256"] != expected.request_sha256
                or row["prior_output_sha256"] != expected.prior_output_sha256
                or row["prior_output_chain_sha256"]
                != expected.prior_output_chain_sha256
            ):
                raise ExternalV3StateError("durable request derivation drifted")
            advisory = self._decode_durable_advisory(
                row, expected_round_id=expected.round_id
            )
            self._validate_durable_write_metadata(
                campaign,
                expected,
                row,
                kind="SUCCESS_REPLAY",
                phases=frozenset({"SEALED_COMMITTED"}),
            )
            parsed = self._replay_success_response(campaign, expected, row)
            advisory_sha = _sha256_bytes(canonical_json(advisory).encode("utf-8"))
            next_chain = advance_output_chain(chain, advisory_sha)
            if row["output_chain_sha256"] != next_chain:
                raise ExternalV3StateError("durable output chain drifted")
            if row["campaign_elapsed_before_dispatch_seconds"] != elapsed_seconds:
                raise ExternalV3StateError(
                    "durable dispatch elapsed prefix drifted"
                )
            self._validate_durable_receipt(
                campaign,
                row,
                expected_status="SUCCEEDED",
                approval_evidence_sha256=approval["approval_evidence_sha256"],
                approval_binding_sha256=approval["approval_binding_sha256"],
                parsed_response=parsed,
            )
            actual_cost += _require_exact_int(
                row["actual_cost_micros"], label="durable actual cost"
            )
            total_tokens += _require_exact_int(
                row["total_tokens"], label="durable total tokens"
            )
            elapsed_seconds += _require_finite_float(
                row["elapsed_seconds"], label="durable round elapsed seconds"
            )
            previous = advisory
            chain = next_chain
        return previous, chain, actual_cost, total_tokens, elapsed_seconds

    def _require_exact_bound(
        self,
        connection: sqlite3.Connection,
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        *,
        states: frozenset[str],
    ) -> sqlite3.Row:
        _validate_bound_round(campaign, bound)
        previous, chain, actual_cost, total_tokens, elapsed_seconds = self._replay_consumed_prefix(
            connection, campaign, count=bound.ordinal
        )
        expected = derive_external_round_v3(
            campaign,
            ordinal=bound.ordinal,
            prior_advisory=previous,
            prior_output_chain_sha256=chain,
        )
        row = connection.execute(
            "SELECT * FROM rounds WHERE campaign_id=? AND ordinal=?",
            (campaign.campaign_id, bound.ordinal),
        ).fetchone()
        if (
            expected != bound
            or row is None
            or row["state"] not in states
            or row["round_id"] != expected.round_id
            or row["request_bytes"] != expected.request_bytes
            or row["request_sha256"] != expected.request_sha256
            or row["prior_output_sha256"] != expected.prior_output_sha256
            or row["prior_output_chain_sha256"]
            != expected.prior_output_chain_sha256
        ):
            raise ExternalV3StateError("bound request is not the durable derivation")
        campaign_row = self._require_campaign_row(connection, campaign)
        if row["state"] == "RESPONSE_COMMITTED":
            actual_cost += _require_exact_int(
                row["actual_cost_micros"], label="committed actual cost"
            )
            total_tokens += _require_exact_int(
                row["total_tokens"], label="committed total tokens"
            )
            elapsed_seconds += _require_finite_float(
                row["elapsed_seconds"], label="committed round elapsed seconds"
            )
        if (
            campaign_row["actual_cost_micros"] != actual_cost
            or campaign_row["total_tokens"] != total_tokens
            or campaign_row["elapsed_seconds"] != elapsed_seconds
        ):
            raise ExternalV3StateError("durable campaign aggregates drifted")
        return row

    def bind_next_request(self, campaign: ExternalCampaignV3) -> BoundExternalRoundV3:
        validate_external_campaign_v3(campaign)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_campaign_row(
                connection,
                campaign,
                states=frozenset({"FAKE_EXTERNAL_APPROVED", "RUNNING"}),
            )
            row = connection.execute(
                "SELECT * FROM rounds WHERE campaign_id=? AND state!='CONSUMED' ORDER BY ordinal LIMIT 1",
                (campaign.campaign_id,),
            ).fetchone()
            if row is None or row["state"] != "TEMPLATE_BOUND":
                raise ExternalV3StateError("next round is not available for request binding")
            ordinal = row["ordinal"]
            prior, chain, actual_cost, total_tokens, elapsed_seconds = self._replay_consumed_prefix(
                connection, campaign, count=ordinal
            )
            campaign_totals = self._require_campaign_row(connection, campaign)
            if (
                campaign_totals["actual_cost_micros"] != actual_cost
                or campaign_totals["total_tokens"] != total_tokens
                or campaign_totals["elapsed_seconds"] != elapsed_seconds
            ):
                raise ExternalV3StateError("durable campaign aggregates drifted")
            bound = derive_external_round_v3(
                campaign,
                ordinal=ordinal,
                prior_advisory=prior,
                prior_output_chain_sha256=chain,
            )
            cursor = connection.execute(
                """
                UPDATE rounds
                   SET state='REQUEST_BOUND', request_bytes=?, request_sha256=?,
                       prior_output_sha256=?, prior_output_chain_sha256=?
                 WHERE campaign_id=? AND ordinal=? AND state='TEMPLATE_BOUND'
                """,
                (
                    bound.request_bytes,
                    bound.request_sha256,
                    bound.prior_output_sha256,
                    bound.prior_output_chain_sha256,
                    campaign.campaign_id,
                    ordinal,
                ),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("request binding CAS failed")
            connection.commit()
            return bound
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def claim(
        self,
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        *,
        owner_nonce: str,
    ) -> ClaimedExternalRoundV3:
        validate_external_campaign_v3(campaign)
        if type(owner_nonce) is not str or not _CLAIM_NONCE.fullmatch(owner_nonce):
            raise ExternalV3StateError("claim owner nonce is invalid")
        if type(bound) is not BoundExternalRoundV3 or bound.campaign_id != campaign.campaign_id or bound.manifest_sha256 != campaign.manifest_sha256:
            raise ExternalV3StateError("bound request belongs to another campaign")
        owner_hash = _sha256_bytes(owner_nonce.encode("ascii"))
        _validate_bound_round(campaign, bound)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_campaign_row(
                connection,
                campaign,
                states=frozenset({"FAKE_EXTERNAL_APPROVED", "RUNNING"}),
            )
            self._require_exact_bound(
                connection,
                campaign,
                bound,
                states=frozenset({"REQUEST_BOUND"}),
            )
            cursor = connection.execute(
                """
                UPDATE rounds SET state='CLAIMED', owner_nonce_sha256=?
                 WHERE campaign_id=? AND ordinal=? AND round_id=?
                   AND state='REQUEST_BOUND' AND request_sha256=? AND request_bytes=?
                """,
                (
                    owner_hash,
                    campaign.campaign_id,
                    bound.ordinal,
                    bound.round_id,
                    bound.request_sha256,
                    bound.request_bytes,
                ),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("round claim CAS failed")
            connection.commit()
            return ClaimedExternalRoundV3(bound, owner_nonce, owner_hash)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def recover_claim_before_dispatch(
        self, campaign: ExternalCampaignV3, *, ordinal: int
    ) -> BoundExternalRoundV3:
        """Release a crashed owner only while no dispatch intent exists."""

        if type(ordinal) is not int or not 0 <= ordinal < EXTERNAL_V3_ROUND_COUNT:
            raise ExternalV3StateError("claim recovery ordinal is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_campaign_row(
                connection,
                campaign,
                states=frozenset({"FAKE_EXTERNAL_APPROVED", "RUNNING"}),
            )
            row = connection.execute(
                "SELECT * FROM rounds WHERE campaign_id=? AND ordinal=?",
                (campaign.campaign_id, ordinal),
            ).fetchone()
            if row is None or row["state"] != "CLAIMED" or row["attempts"] != 0:
                raise ExternalV3StateError("pre-dispatch claim is not recoverable")
            bound = BoundExternalRoundV3(
                campaign_id=campaign.campaign_id,
                manifest_sha256=campaign.manifest_sha256,
                round_id=row["round_id"],
                ordinal=ordinal,
                request_bytes=row["request_bytes"],
                request_sha256=row["request_sha256"],
                prior_output_sha256=row["prior_output_sha256"],
                prior_output_chain_sha256=row["prior_output_chain_sha256"],
            )
            self._require_exact_bound(
                connection,
                campaign,
                bound,
                states=frozenset({"CLAIMED"}),
            )
            cursor = connection.execute(
                """
                UPDATE rounds SET state='REQUEST_BOUND',owner_nonce_sha256=NULL
                 WHERE campaign_id=? AND ordinal=? AND state='CLAIMED'
                   AND attempts=0 AND dispatch_intent_sha256 IS NULL
                """,
                (campaign.campaign_id, ordinal),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("pre-dispatch claim recovery CAS failed")
            connection.commit()
            return bound
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def mark_dispatch_intent(
        self,
        campaign: ExternalCampaignV3,
        claim: ClaimedExternalRoundV3,
    ) -> DispatchIntentV3:
        validate_external_campaign_v3(campaign)
        if (
            type(claim) is not ClaimedExternalRoundV3
            or type(claim.owner_nonce) is not str
            or not _CLAIM_NONCE.fullmatch(claim.owner_nonce)
            or claim.owner_nonce_sha256
            != _sha256_bytes(claim.owner_nonce.encode("ascii"))
        ):
            raise ExternalV3StateError("dispatch claim identity is invalid")
        _validate_bound_round(campaign, claim.bound)
        reserve = campaign.pricing.worst_round_cost_micros()
        intent_hash = _sha256_json(
            {
                "campaign_manifest_sha256": campaign.manifest_sha256,
                "round_id": claim.bound.round_id,
                "ordinal": claim.bound.ordinal,
                "request_sha256": claim.bound.request_sha256,
                "owner_nonce_sha256": claim.owner_nonce_sha256,
                "attempt": 1,
                "reserved_cost_micros": reserve,
            }
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            campaign_row = self._require_campaign_row(
                connection,
                campaign,
                states=frozenset({"FAKE_EXTERNAL_APPROVED", "RUNNING"}),
            )
            self._require_exact_bound(
                connection,
                campaign,
                claim.bound,
                states=frozenset({"CLAIMED"}),
            )
            campaign_elapsed_seconds = _require_finite_float(
                campaign_row["elapsed_seconds"], label="durable campaign elapsed seconds"
            )
            if campaign_elapsed_seconds > campaign.pricing.campaign_deadline_seconds:
                raise ExternalV3StateError(
                    "campaign wall-clock deadline was exceeded before dispatch"
                )
            new_reserved = campaign_row["reserved_cost_micros"] + reserve
            if new_reserved > campaign.pricing.max_campaign_cost_micros:
                raise ExternalV3StateError("campaign cost reservation exceeds its cap")
            cursor = connection.execute(
                """
                UPDATE rounds
                   SET state='DISPATCH_INTENT', attempts=1,
                       dispatch_intent_sha256=?, reserved_cost_micros=?,
                       campaign_elapsed_before_dispatch_seconds=?
                 WHERE campaign_id=? AND ordinal=? AND state='CLAIMED'
                   AND owner_nonce_sha256=? AND request_sha256=? AND attempts=0
                """,
                (
                    intent_hash,
                    reserve,
                    campaign_elapsed_seconds,
                    campaign.campaign_id,
                    claim.bound.ordinal,
                    claim.owner_nonce_sha256,
                    claim.bound.request_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("dispatch-intent CAS failed")
            connection.execute(
                "UPDATE campaigns SET state='RUNNING',reserved_cost_micros=? WHERE campaign_id=?",
                (new_reserved, campaign.campaign_id),
            )
            connection.commit()
            return DispatchIntentV3(
                claim.bound,
                claim.owner_nonce_sha256,
                intent_hash,
                reserve,
                campaign_elapsed_seconds,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _approval_rows(
        self, connection: sqlite3.Connection, campaign: ExternalCampaignV3
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT approval_evidence_sha256,approval_binding_sha256 FROM campaigns WHERE campaign_id=?",
            (campaign.campaign_id,),
        ).fetchone()
        if (
            row is None
            or type(row["approval_evidence_sha256"]) is not str
            or type(row["approval_binding_sha256"]) is not str
        ):
            raise ExternalV3StateError("campaign approval binding is unavailable")
        return row

    def _receipt_core(
        self,
        connection: sqlite3.Connection,
        campaign: ExternalCampaignV3,
        intent: DispatchIntentV3,
    ) -> dict[str, object]:
        approval = self._approval_rows(connection, campaign)
        provider_pin_sha = _sha256_json(_provider_projection(campaign.pin))
        return {
            "schema_version": EXTERNAL_V3_RECEIPT_SCHEMA,
            "campaign_id": campaign.campaign_id,
            "campaign_manifest_sha256": campaign.manifest_sha256,
            "round_id": intent.bound.round_id,
            "ordinal": intent.bound.ordinal,
            "request_sha256": intent.bound.request_sha256,
            "request_bytes": len(intent.bound.request_bytes),
            "prior_output_sha256": intent.bound.prior_output_sha256,
            "prior_output_chain_sha256": intent.bound.prior_output_chain_sha256,
            "dispatch_intent_sha256": intent.dispatch_intent_sha256,
            "owner_nonce_sha256": intent.owner_nonce_sha256,
            "approval_evidence_sha256": approval["approval_evidence_sha256"],
            "approval_binding_sha256": approval["approval_binding_sha256"],
            "provider_pin_sha256": provider_pin_sha,
            "identity_evidence_sha256": campaign.identity_evidence_sha256,
            "pricing_evidence_sha256": campaign.pricing.pricing_evidence_sha256,
            "transport_build_sha256": campaign.transport_build_sha256,
            "public_output_allowlist_sha256": _sha256_json(
                sorted(_PUBLIC_OUTPUT_WORDS)
            ),
            "public_output_locator_policy_sha256": (
                _public_output_locator_policy_sha256()
            ),
            "reserved_cost_micros": intent.reserved_cost_micros,
            "campaign_elapsed_before_dispatch_seconds": intent.campaign_elapsed_seconds,
            "currency": campaign.pricing.currency,
            "attempt_count": 1,
            "redirects_followed": 0,
            "tools_enabled": False,
            "transport_mode": "SCRIPTED_FAKE_NO_NETWORK",
            "authority": EXTERNAL_V3_AUTHORITY,
        }

    def _write_success_replay_artifact(
        self,
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        raw_response_bytes: bytes,
        *,
        generation: int,
    ) -> None:
        self._write_once_managed_artifact(
            self._success_replay_path(campaign, bound, generation=generation),
            root=self._success_replay_root,
            content=raw_response_bytes,
            max_bytes=campaign.pricing.max_response_bytes,
            kind="SUCCESS_REPLAY",
        )

    def _replay_success_response(
        self,
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        row: sqlite3.Row,
        *,
        phases: frozenset[str] = frozenset({"SEALED_COMMITTED"}),
    ) -> ParsedExternalResponseV3:
        replay_path = self._validate_durable_write_metadata(
            campaign,
            bound,
            row,
            kind="SUCCESS_REPLAY",
            phases=phases,
        )
        if self._artifact_exists(
            self._terminal_commitment_path(campaign, bound),
            root=self._terminal_commitment_root,
        ):
            raise ExternalV3StateError(
                "successful round unexpectedly carries a terminal commitment"
            )
        raw = self._read_managed_artifact(
            replay_path,
            root=self._success_replay_root,
            max_bytes=campaign.pricing.max_response_bytes,
        )
        try:
            elapsed = _require_finite_float(
                row["elapsed_seconds"], label="durable success elapsed seconds"
            )
            parsed = parse_external_response_v3(
                raw,
                campaign=campaign,
                bound=bound,
                elapsed_seconds=elapsed,
            )
        except ExternalV3PolicyError:
            raise ExternalV3StateError(
                "durable success replay artifact failed the closed parser"
            ) from None
        if (
            row["raw_response_sha256"] != parsed.raw_response_sha256
            or row["response_bytes"] != parsed.response_bytes
            or row["advisory_bytes"] != parsed.advisory_bytes
            or row["advisory_sha256"] != parsed.advisory_sha256
            or row["actual_cost_micros"] != parsed.cost_micros
            or row["total_tokens"] != parsed.total_tokens
        ):
            raise ExternalV3StateError(
                "durable success row disagrees with replayed raw response"
            )
        return parsed

    @staticmethod
    def _terminal_commitment_value(
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        *,
        dispatch_intent_sha256: str,
        receipt: dict[str, object],
        receipt_sha256: str,
    ) -> dict[str, object]:
        return {
            "schema_version": EXTERNAL_V3_TERMINAL_COMMITMENT_SCHEMA,
            "campaign_id": campaign.campaign_id,
            "campaign_manifest_sha256": campaign.manifest_sha256,
            "ordinal": bound.ordinal,
            "round_id": bound.round_id,
            "request_sha256": bound.request_sha256,
            "dispatch_intent_sha256": dispatch_intent_sha256,
            "status": receipt["status"],
            "error_code": receipt["error_code"],
            "raw_response_sha256": receipt["raw_response_sha256"],
            "response_bytes": receipt["response_bytes"],
            "elapsed_seconds": receipt["elapsed_seconds"],
            "receipt_sha256": receipt_sha256,
            "audit_verifiability": _TERMINAL_AUDIT_STATE,
            "authority": EXTERNAL_V3_AUTHORITY,
        }

    def _write_terminal_commitment(
        self,
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        *,
        dispatch_intent_sha256: str,
        receipt: dict[str, object],
        receipt_sha256: str,
        generation: int,
    ) -> None:
        value = self._terminal_commitment_value(
            campaign,
            bound,
            dispatch_intent_sha256=dispatch_intent_sha256,
            receipt=receipt,
            receipt_sha256=receipt_sha256,
        )
        content = canonical_json(value).encode("utf-8")
        self._write_once_managed_artifact(
            self._terminal_commitment_path(
                campaign, bound, generation=generation
            ),
            root=self._terminal_commitment_root,
            content=content,
            max_bytes=_TERMINAL_COMMITMENT_MAX_BYTES,
            kind="TERMINAL_COMMITMENT",
        )

    def _validate_terminal_commitment(
        self,
        campaign: ExternalCampaignV3,
        bound: BoundExternalRoundV3,
        row: sqlite3.Row,
        receipt: dict[str, object],
        *,
        phases: frozenset[str] = frozenset({"SEALED_COMMITTED"}),
    ) -> None:
        commitment_path = self._validate_durable_write_metadata(
            campaign,
            bound,
            row,
            kind="TERMINAL_COMMITMENT",
            phases=phases,
        )
        content = self._read_managed_artifact(
            commitment_path,
            root=self._terminal_commitment_root,
            max_bytes=_TERMINAL_COMMITMENT_MAX_BYTES,
        )
        try:
            observed = _strict_json_loads(
                content, label="terminal commitment authority"
            )
        except ExternalV3PolicyError:
            raise ExternalV3StateError(
                "terminal commitment authority is invalid"
            ) from None
        expected = self._terminal_commitment_value(
            campaign,
            bound,
            dispatch_intent_sha256=row["dispatch_intent_sha256"],
            receipt=receipt,
            receipt_sha256=row["receipt_sha256"],
        )
        if (
            type(observed) is not dict
            or canonical_json(observed).encode("utf-8") != content
            or observed != expected
            or row["durable_write_payload_sha256"] != _sha256_bytes(content)
            or row["durable_write_payload_size"] != len(content)
        ):
            raise ExternalV3StateError(
                "terminal commitment disagrees with durable terminal state"
            )
        if self._artifact_exists(
            self._success_replay_path(campaign, bound),
            root=self._success_replay_root,
        ):
            raise ExternalV3StateError(
                "terminal round unexpectedly carries a success replay artifact"
            )

    @staticmethod
    def _validate_durable_receipt(
        campaign: ExternalCampaignV3,
        row: sqlite3.Row,
        *,
        expected_status: str,
        approval_evidence_sha256: str,
        approval_binding_sha256: str,
        parsed_response: ParsedExternalResponseV3 | None = None,
    ) -> dict[str, object]:
        raw = row["receipt_bytes"]
        if type(raw) is not bytes or row["receipt_sha256"] != _sha256_bytes(raw):
            raise ExternalV3StateError("durable receipt identity drifted")
        value = _strict_json_loads(raw, label="durable receipt")
        if type(value) is not dict or canonical_json(value).encode("utf-8") != raw:
            raise ExternalV3StateError("durable receipt is not canonical")
        success_fields = {
            "status", "error_code", "response_id_sha256", "raw_response_sha256",
            "created_at", "returned_model", "system_fingerprint_sha256",
            "response_bytes", "advisory_sha256", "output_chain_sha256",
            "prompt_tokens", "completion_tokens", "total_tokens",
            "actual_cost_micros", "elapsed_seconds",
            "audit_verifiability",
        }
        core_fields = {
            "schema_version", "campaign_id", "campaign_manifest_sha256",
            "round_id", "ordinal", "request_sha256", "request_bytes",
            "prior_output_sha256", "prior_output_chain_sha256",
            "dispatch_intent_sha256", "owner_nonce_sha256",
            "approval_evidence_sha256", "approval_binding_sha256",
            "provider_pin_sha256", "identity_evidence_sha256",
            "pricing_evidence_sha256", "transport_build_sha256",
            "public_output_allowlist_sha256", "reserved_cost_micros",
            "public_output_locator_policy_sha256",
            "campaign_elapsed_before_dispatch_seconds", "currency",
            "attempt_count", "redirects_followed", "tools_enabled",
            "transport_mode", "authority",
        }
        if set(value) != core_fields | success_fields:
            raise ExternalV3StateError("durable receipt fields are not closed")
        approval_evidence = _require_sha256(
            approval_evidence_sha256, label="durable approval evidence hash"
        )
        expected_approval = _sha256_json(
            {
                "campaign_manifest_sha256": campaign.manifest_sha256,
                "approval_evidence_sha256": approval_evidence,
                "transport_state": EXTERNAL_V3_TRANSPORT_STATE,
            }
        )
        expected_core = {
            "schema_version": EXTERNAL_V3_RECEIPT_SCHEMA,
            "campaign_id": campaign.campaign_id,
            "campaign_manifest_sha256": campaign.manifest_sha256,
            "round_id": row["round_id"],
            "ordinal": row["ordinal"],
            "request_sha256": row["request_sha256"],
            "request_bytes": len(row["request_bytes"]),
            "prior_output_sha256": row["prior_output_sha256"],
            "prior_output_chain_sha256": row["prior_output_chain_sha256"],
            "dispatch_intent_sha256": row["dispatch_intent_sha256"],
            "owner_nonce_sha256": row["owner_nonce_sha256"],
            "approval_evidence_sha256": approval_evidence,
            "approval_binding_sha256": expected_approval,
            "provider_pin_sha256": _sha256_json(_provider_projection(campaign.pin)),
            "identity_evidence_sha256": campaign.identity_evidence_sha256,
            "pricing_evidence_sha256": campaign.pricing.pricing_evidence_sha256,
            "transport_build_sha256": campaign.transport_build_sha256,
            "public_output_allowlist_sha256": _sha256_json(
                sorted(_PUBLIC_OUTPUT_WORDS)
            ),
            "public_output_locator_policy_sha256": (
                _public_output_locator_policy_sha256()
            ),
            "reserved_cost_micros": row["reserved_cost_micros"],
            "campaign_elapsed_before_dispatch_seconds": row[
                "campaign_elapsed_before_dispatch_seconds"
            ],
            "currency": campaign.pricing.currency,
            "attempt_count": 1,
            "redirects_followed": 0,
            "tools_enabled": False,
            "transport_mode": "SCRIPTED_FAKE_NO_NETWORK",
            "authority": EXTERNAL_V3_AUTHORITY,
        }
        if (
            approval_binding_sha256 != expected_approval
            or any(value[name] != expected for name, expected in expected_core.items())
        ):
            raise ExternalV3StateError("durable receipt core drifted")
        if expected_status == "SUCCEEDED":
            prepared_without_replay = row["state"] in {
                "ARTIFACT_PREPARED",
                "ARTIFACT_RECOVERY_REQUIRED",
            }
            if type(parsed_response) is not ParsedExternalResponseV3 and not prepared_without_replay:
                raise ExternalV3StateError(
                    "durable success receipt lacks raw replay evidence"
                )
            expected_success = {
                "status": "SUCCEEDED",
                "error_code": None,
                "response_id_sha256": (
                    value["response_id_sha256"]
                    if prepared_without_replay
                    else parsed_response.response_id_sha256
                ),
                "raw_response_sha256": (
                    row["raw_response_sha256"]
                    if prepared_without_replay
                    else parsed_response.raw_response_sha256
                ),
                "created_at": (
                    value["created_at"]
                    if prepared_without_replay
                    else parsed_response.created_at
                ),
                "returned_model": (
                    campaign.pin.model_alias
                    if prepared_without_replay
                    else parsed_response.returned_model
                ),
                "system_fingerprint_sha256": (
                    value["system_fingerprint_sha256"]
                    if prepared_without_replay
                    else parsed_response.system_fingerprint_sha256
                ),
                "response_bytes": (
                    row["response_bytes"]
                    if prepared_without_replay
                    else parsed_response.response_bytes
                ),
                "advisory_sha256": (
                    row["advisory_sha256"]
                    if prepared_without_replay
                    else parsed_response.advisory_sha256
                ),
                "output_chain_sha256": row["output_chain_sha256"],
                "prompt_tokens": (
                    value["prompt_tokens"]
                    if prepared_without_replay
                    else parsed_response.prompt_tokens
                ),
                "completion_tokens": (
                    value["completion_tokens"]
                    if prepared_without_replay
                    else parsed_response.completion_tokens
                ),
                "total_tokens": (
                    row["total_tokens"]
                    if prepared_without_replay
                    else parsed_response.total_tokens
                ),
                "actual_cost_micros": (
                    row["actual_cost_micros"]
                    if prepared_without_replay
                    else parsed_response.cost_micros
                ),
                "elapsed_seconds": (
                    row["elapsed_seconds"]
                    if prepared_without_replay
                    else parsed_response.elapsed_seconds
                ),
                "audit_verifiability": _SUCCESS_AUDIT_STATE,
            }
            if prepared_without_replay and (
                type(value["response_id_sha256"]) is not str
                or not _SHA256.fullmatch(value["response_id_sha256"])
                or type(value["system_fingerprint_sha256"]) is not str
                or not _SHA256.fullmatch(value["system_fingerprint_sha256"])
                or type(value["created_at"]) is not str
            ):
                raise ExternalV3StateError("prepared success identity is invalid")
            if any(value[name] != expected for name, expected in expected_success.items()):
                raise ExternalV3StateError("durable success receipt drifted")
            prompt = _require_exact_int(value["prompt_tokens"], label="receipt prompt usage")
            completion = _require_exact_int(
                value["completion_tokens"], label="receipt completion usage"
            )
            if (
                value["total_tokens"] != prompt + completion
                or value["actual_cost_micros"]
                != campaign.pricing.cost_micros(
                    prompt_tokens=prompt, completion_tokens=completion
                )
            ):
                raise ExternalV3StateError("durable receipt usage drifted")
        else:
            pair = (value["status"], value["error_code"])
            terminal_row_state = (
                value["status"]
                if row["state"] in {
                    "COMMITMENT_PREPARED",
                    "COMMITMENT_RECOVERY_REQUIRED",
                }
                else row["state"]
            )
            if (
                expected_status not in {"FAILED_NO_RETRY", "AMBIGUOUS_NO_RETRY"}
                or terminal_row_state != expected_status
                or value["status"] != expected_status
                or pair not in _TERMINAL_STATUS_ERROR_PAIRS
            ):
                raise ExternalV3StateError(
                    "durable terminal receipt status/error drifted"
                )
            if (
                parsed_response is not None
                or value["audit_verifiability"] != _TERMINAL_AUDIT_STATE
            ):
                raise ExternalV3StateError(
                    "durable terminal receipt overstates audit verifiability"
                )
            for name in (
                "response_id_sha256",
                "created_at",
                "returned_model",
                "system_fingerprint_sha256",
                "advisory_sha256",
                "output_chain_sha256",
                "prompt_tokens",
                "completion_tokens",
                "total_tokens",
                "actual_cost_micros",
            ):
                if value[name] is not None:
                    raise ExternalV3StateError(
                        "durable terminal receipt claims success metadata"
                    )
            if any(
                row[name] is not None
                for name in (
                    "actual_cost_micros",
                    "total_tokens",
                    "advisory_bytes",
                    "advisory_sha256",
                    "output_chain_sha256",
                )
            ):
                raise ExternalV3StateError(
                    "durable terminal row claims success metadata"
                )
            if value["error_code"] == "KNOWN_RESPONSE_INVALID":
                raw_sha = value["raw_response_sha256"]
                response_bytes = value["response_bytes"]
                elapsed = value["elapsed_seconds"]
                if (
                    type(raw_sha) is not str
                    or not _SHA256.fullmatch(raw_sha)
                    or type(response_bytes) is not int
                    or response_bytes < 0
                    or type(elapsed) is not float
                    or not math.isfinite(elapsed)
                    or elapsed < 0.0
                    or elapsed > campaign.pricing.per_round_deadline_seconds
                    or value["campaign_elapsed_before_dispatch_seconds"] + elapsed
                    > campaign.pricing.campaign_deadline_seconds
                    or row["raw_response_sha256"] != raw_sha
                    or row["response_bytes"] != response_bytes
                    or row["elapsed_seconds"] != elapsed
                ):
                    raise ExternalV3StateError(
                        "durable rejected-response metadata drifted"
                    )
            else:
                if (
                    value["raw_response_sha256"] is not None
                    or value["response_bytes"] is not None
                    or row["raw_response_sha256"] is not None
                    or row["response_bytes"] is not None
                ):
                    raise ExternalV3StateError(
                        "durable ambiguous receipt claims response metadata"
                    )
                elapsed = value["elapsed_seconds"]
                if value["error_code"] == "PROCESS_LOST_AFTER_INTENT":
                    if elapsed is not None or row["elapsed_seconds"] is not None:
                        raise ExternalV3StateError(
                            "durable process-loss receipt invents elapsed metadata"
                        )
                elif (
                    type(elapsed) is not float
                    or not math.isfinite(elapsed)
                    or elapsed < 0.0
                    or row["elapsed_seconds"] != elapsed
                ):
                    raise ExternalV3StateError(
                        "durable ambiguous elapsed metadata drifted"
                    )
        return value

    def _require_intent_row(
        self,
        connection: sqlite3.Connection,
        campaign: ExternalCampaignV3,
        intent: DispatchIntentV3,
        *,
        states: frozenset[str] = frozenset({"DISPATCH_INTENT"}),
    ) -> sqlite3.Row:
        if (
            type(intent) is not DispatchIntentV3
            or intent.bound.campaign_id != campaign.campaign_id
            or intent.bound.manifest_sha256 != campaign.manifest_sha256
            or intent.reserved_cost_micros != campaign.pricing.worst_round_cost_micros()
            or type(intent.owner_nonce_sha256) is not str
            or not _SHA256.fullmatch(intent.owner_nonce_sha256)
        ):
            raise ExternalV3StateError("dispatch intent identity is invalid")
        _require_finite_float(
            intent.campaign_elapsed_seconds,
            label="dispatch campaign elapsed seconds",
        )
        campaign_row = self._require_campaign_row(
            connection, campaign, states=frozenset({"RUNNING"})
        )
        row = self._require_exact_bound(
            connection,
            campaign,
            intent.bound,
            states=states,
        )
        if (
            row is None
            or row["request_sha256"] != intent.bound.request_sha256
            or row["owner_nonce_sha256"] != intent.owner_nonce_sha256
            or row["dispatch_intent_sha256"] != intent.dispatch_intent_sha256
            or row["attempts"] != 1
            or row["reserved_cost_micros"] != intent.reserved_cost_micros
            or row["campaign_elapsed_before_dispatch_seconds"]
            != intent.campaign_elapsed_seconds
            or campaign_row["elapsed_seconds"] != intent.campaign_elapsed_seconds
        ):
            raise ExternalV3StateError("dispatch intent does not match durable state")
        return row

    def load_dispatch_intent(
        self, campaign: ExternalCampaignV3, *, ordinal: int
    ) -> DispatchIntentV3:
        """Reconstruct a post-intent recovery token using durable data only."""

        if type(ordinal) is not int or not 0 <= ordinal < EXTERNAL_V3_ROUND_COUNT:
            raise ExternalV3StateError("dispatch recovery ordinal is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._require_campaign_row(
                connection, campaign, states=frozenset({"RUNNING"})
            )
            row = connection.execute(
                "SELECT * FROM rounds WHERE campaign_id=? AND ordinal=?",
                (campaign.campaign_id, ordinal),
            ).fetchone()
            if (
                row is None
                or row["state"] not in {
                    "DISPATCH_INTENT",
                    "ARTIFACT_RECOVERY_REQUIRED",
                    "COMMITMENT_RECOVERY_REQUIRED",
                }
                or type(row["request_bytes"]) is not bytes
                or type(row["request_sha256"]) is not str
                or type(row["prior_output_sha256"]) is not str
                or type(row["prior_output_chain_sha256"]) is not str
                or type(row["owner_nonce_sha256"]) is not str
                or type(row["dispatch_intent_sha256"]) is not str
                or type(row["reserved_cost_micros"]) is not int
            ):
                raise ExternalV3StateError("durable dispatch intent is unavailable")
            elapsed = _require_finite_float(
                row["campaign_elapsed_before_dispatch_seconds"],
                label="durable dispatch elapsed seconds",
            )
            bound = BoundExternalRoundV3(
                campaign_id=campaign.campaign_id,
                manifest_sha256=campaign.manifest_sha256,
                round_id=str(row["round_id"]),
                ordinal=ordinal,
                request_bytes=row["request_bytes"],
                request_sha256=row["request_sha256"],
                prior_output_sha256=row["prior_output_sha256"],
                prior_output_chain_sha256=row["prior_output_chain_sha256"],
            )
            intent = DispatchIntentV3(
                bound=bound,
                owner_nonce_sha256=row["owner_nonce_sha256"],
                dispatch_intent_sha256=row["dispatch_intent_sha256"],
                reserved_cost_micros=row["reserved_cost_micros"],
                campaign_elapsed_seconds=elapsed,
            )
            self._require_intent_row(
                connection,
                campaign,
                intent,
                states=frozenset({row["state"]}),
            )
            return intent
        finally:
            connection.close()

    @staticmethod
    def _validate_parsed_response(
        campaign: ExternalCampaignV3,
        intent: DispatchIntentV3,
        parsed: ParsedExternalResponseV3,
    ) -> None:
        if type(parsed) is not ParsedExternalResponseV3:
            raise ExternalV3StateError("parsed response type is invalid")
        if (
            type(parsed.response_id_sha256) is not str
            or not _SHA256.fullmatch(parsed.response_id_sha256)
            or type(parsed.raw_response_sha256) is not str
            or not _SHA256.fullmatch(parsed.raw_response_sha256)
            or type(parsed.system_fingerprint_sha256) is not str
            or not _SHA256.fullmatch(parsed.system_fingerprint_sha256)
            or type(parsed.created_at) is not str
            or not parsed.created_at.endswith("Z")
            or type(parsed.prompt_tokens) is not int
            or type(parsed.completion_tokens) is not int
            or type(parsed.total_tokens) is not int
            or type(parsed.cost_micros) is not int
        ):
            raise ExternalV3StateError("parsed response scalar binding is invalid")
        try:
            advisory = _validate_external_public_advisory(
                parsed.advisory, round_id=intent.bound.round_id
            )
        except Exception:
            raise ExternalV3StateError("parsed advisory cannot be replayed") from None
        expected_bytes = canonical_json(advisory).encode("utf-8")
        expected_fingerprint_hash = _sha256_bytes(
            campaign.pin.expected_system_fingerprint.encode("ascii")
        )
        if (
            parsed.advisory_bytes != expected_bytes
            or parsed.advisory_sha256 != _sha256_bytes(expected_bytes)
            or parsed.returned_model != campaign.pin.expected_returned_model
            or parsed.system_fingerprint_sha256 != expected_fingerprint_hash
            or parsed.total_tokens != parsed.prompt_tokens + parsed.completion_tokens
            or parsed.prompt_tokens > campaign.pricing.max_prompt_tokens_per_round
            or parsed.completion_tokens
            > campaign.pricing.max_completion_tokens_per_round
            or parsed.cost_micros
            != campaign.pricing.cost_micros(
                prompt_tokens=parsed.prompt_tokens,
                completion_tokens=parsed.completion_tokens,
            )
            or type(parsed.elapsed_seconds) is not float
            or not 0.0 <= parsed.elapsed_seconds
            <= campaign.pricing.per_round_deadline_seconds
            or type(parsed.response_bytes) is not int
            or not 0 <= parsed.response_bytes <= campaign.pricing.max_response_bytes
        ):
            raise ExternalV3StateError("parsed response binding is invalid")

    def commit_success(
        self,
        campaign: ExternalCampaignV3,
        intent: DispatchIntentV3,
        *,
        raw_response_bytes: bytes,
        elapsed_seconds: float,
    ) -> dict[str, object]:
        if type(raw_response_bytes) is not bytes:
            raise ExternalV3StateError("raw response bytes are required for commit")
        parsed = parse_external_response_v3(
            raw_response_bytes,
            campaign=campaign,
            bound=intent.bound,
            elapsed_seconds=elapsed_seconds,
        )
        if parsed.raw_response_sha256 != _sha256_bytes(raw_response_bytes):
            raise ExternalV3StateError("raw response binding drifted")
        self._validate_parsed_response(campaign, intent, parsed)
        if parsed.cost_micros > intent.reserved_cost_micros:
            raise ExternalV3StateError("actual cost exceeded the durable reservation")
        if (
            intent.campaign_elapsed_seconds + parsed.elapsed_seconds
            > campaign.pricing.campaign_deadline_seconds
        ):
            raise ExternalV3PolicyError("campaign deadline expired after dispatch")
        # Transaction 1 makes the exact write intent durable before any target
        # is created.  A recovery retry advances to a fresh append-only target;
        # it never truncates or replaces the prior partial file.
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            prior = self._require_intent_row(
                connection,
                campaign,
                intent,
                states=frozenset(
                    {"DISPATCH_INTENT", "ARTIFACT_RECOVERY_REQUIRED"}
                ),
            )
            campaign_row = connection.execute(
                "SELECT actual_cost_micros,total_tokens FROM campaigns WHERE campaign_id=? AND state='RUNNING'",
                (campaign.campaign_id,),
            ).fetchone()
            if campaign_row is None:
                raise ExternalV3StateError("campaign is not running")
            new_cost = campaign_row["actual_cost_micros"] + parsed.cost_micros
            new_tokens = campaign_row["total_tokens"] + parsed.total_tokens
            if (
                new_cost > campaign.pricing.max_campaign_cost_micros
                or new_tokens > campaign.pricing.max_campaign_total_tokens
            ):
                raise ExternalV3StateError("actual campaign usage exceeded its cap")
            output_chain = advance_output_chain(
                intent.bound.prior_output_chain_sha256,
                parsed.advisory_sha256,
            )
            receipt = {
                **self._receipt_core(connection, campaign, intent),
                "status": "SUCCEEDED",
                "error_code": None,
                "response_id_sha256": parsed.response_id_sha256,
                "raw_response_sha256": parsed.raw_response_sha256,
                "created_at": parsed.created_at,
                "returned_model": parsed.returned_model,
                "system_fingerprint_sha256": parsed.system_fingerprint_sha256,
                "response_bytes": parsed.response_bytes,
                "advisory_sha256": parsed.advisory_sha256,
                "output_chain_sha256": output_chain,
                "prompt_tokens": parsed.prompt_tokens,
                "completion_tokens": parsed.completion_tokens,
                "total_tokens": parsed.total_tokens,
                "actual_cost_micros": parsed.cost_micros,
                "elapsed_seconds": parsed.elapsed_seconds,
                "audit_verifiability": _SUCCESS_AUDIT_STATE,
            }
            receipt_bytes = canonical_json(receipt).encode("utf-8")
            receipt_sha = _sha256_bytes(receipt_bytes)
            generation = (
                0
                if prior["state"] == "DISPATCH_INTENT"
                else _require_exact_int(
                    prior["durable_write_generation"],
                    label="recovery artifact generation",
                )
                + 1
            )
            if prior["state"] == "ARTIFACT_RECOVERY_REQUIRED" and (
                prior["raw_response_sha256"] != parsed.raw_response_sha256
                or prior["response_bytes"] != parsed.response_bytes
                or prior["receipt_bytes"] != receipt_bytes
                or prior["receipt_sha256"] != receipt_sha
            ):
                raise ExternalV3StateError(
                    "success recovery bytes disagree with prepared intent"
                )
            target = self._success_replay_path(
                campaign, intent.bound, generation=generation
            )
            cursor = connection.execute(
                """
                UPDATE rounds
                   SET state='ARTIFACT_PREPARED', actual_cost_micros=?, total_tokens=?,
                       advisory_bytes=?, advisory_sha256=?, output_chain_sha256=?,
                       receipt_bytes=?, receipt_sha256=?, raw_response_sha256=?,
                       response_bytes=?, elapsed_seconds=?,
                       durable_write_kind='SUCCESS_REPLAY',
                       durable_write_generation=?,durable_write_request_sha256=?,
                       durable_write_raw_sha256=?,durable_write_raw_size=?,
                       durable_write_target=?,durable_write_payload_sha256=?,
                       durable_write_payload_size=?,durable_write_phase='INTENT_DURABLE'
                 WHERE campaign_id=? AND ordinal=? AND state=?
                   AND dispatch_intent_sha256=? AND attempts=1
                """,
                (
                    parsed.cost_micros,
                    parsed.total_tokens,
                    parsed.advisory_bytes,
                    parsed.advisory_sha256,
                    output_chain,
                    receipt_bytes,
                    receipt_sha,
                    parsed.raw_response_sha256,
                    parsed.response_bytes,
                    parsed.elapsed_seconds,
                    generation,
                    intent.bound.request_sha256,
                    parsed.raw_response_sha256,
                    parsed.response_bytes,
                    target.name,
                    parsed.raw_response_sha256,
                    parsed.response_bytes,
                    campaign.campaign_id,
                    intent.bound.ordinal,
                    prior["state"],
                    intent.dispatch_intent_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("success write prepare CAS failed")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

        self._artifact_write_cutpoint("SUCCESS_REPLAY", "AFTER_PREPARE_COMMIT")
        self._write_success_replay_artifact(
            campaign,
            intent.bound,
            raw_response_bytes,
            generation=generation,
        )
        self._artifact_write_cutpoint("SUCCESS_REPLAY", "BEFORE_FINALIZE_COMMIT")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_intent_row(
                connection,
                campaign,
                intent,
                states=frozenset({"ARTIFACT_PREPARED"}),
            )
            self._validate_durable_write_metadata(
                campaign,
                intent.bound,
                row,
                kind="SUCCESS_REPLAY",
                phases=frozenset({"INTENT_DURABLE"}),
            )
            replayed = self._replay_success_response(
                campaign,
                intent.bound,
                row,
                phases=frozenset({"INTENT_DURABLE"}),
            )
            approval = self._approval_rows(connection, campaign)
            self._validate_durable_receipt(
                campaign,
                row,
                expected_status="SUCCEEDED",
                approval_evidence_sha256=approval["approval_evidence_sha256"],
                approval_binding_sha256=approval["approval_binding_sha256"],
                parsed_response=replayed,
            )
            cursor = connection.execute(
                """
                UPDATE rounds
                   SET state='RESPONSE_COMMITTED',durable_write_phase='SEALED_COMMITTED'
                 WHERE campaign_id=? AND ordinal=? AND state='ARTIFACT_PREPARED'
                   AND durable_write_generation=? AND durable_write_target=?
                """,
                (
                    campaign.campaign_id,
                    intent.bound.ordinal,
                    generation,
                    target.name,
                ),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("success finalize CAS failed")
            connection.execute(
                "UPDATE campaigns SET actual_cost_micros=?,total_tokens=?,elapsed_seconds=? WHERE campaign_id=? AND state='RUNNING'",
                (
                    new_cost,
                    new_tokens,
                    intent.campaign_elapsed_seconds + parsed.elapsed_seconds,
                    campaign.campaign_id,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        self._artifact_write_cutpoint("SUCCESS_REPLAY", "AFTER_FINALIZE_COMMIT")
        return {**receipt, "receipt_sha256": receipt_sha}

    def consume_committed(
        self, campaign: ExternalCampaignV3, *, ordinal: int
    ) -> dict[str, object]:
        validate_external_campaign_v3(campaign)
        if type(ordinal) is not int or not 0 <= ordinal < EXTERNAL_V3_ROUND_COUNT:
            raise ExternalV3StateError("response consumption ordinal is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_campaign_row(
                connection, campaign, states=frozenset({"RUNNING"})
            )
            row = connection.execute(
                "SELECT * FROM rounds WHERE campaign_id=? AND ordinal=? AND state='RESPONSE_COMMITTED'",
                (campaign.campaign_id, ordinal),
            ).fetchone()
            if row is None or type(row["request_bytes"]) is not bytes:
                raise ExternalV3StateError("committed response is unavailable")
            bound = BoundExternalRoundV3(
                campaign_id=campaign.campaign_id,
                manifest_sha256=campaign.manifest_sha256,
                round_id=row["round_id"],
                ordinal=ordinal,
                request_bytes=row["request_bytes"],
                request_sha256=row["request_sha256"],
                prior_output_sha256=row["prior_output_sha256"],
                prior_output_chain_sha256=row["prior_output_chain_sha256"],
            )
            self._require_exact_bound(
                connection,
                campaign,
                bound,
                states=frozenset({"RESPONSE_COMMITTED"}),
            )
            advisory = self._decode_durable_advisory(
                row, expected_round_id=bound.round_id
            )
            parsed = self._replay_success_response(campaign, bound, row)
            advisory_sha = _sha256_bytes(canonical_json(advisory).encode("utf-8"))
            if row["output_chain_sha256"] != advance_output_chain(
                bound.prior_output_chain_sha256, advisory_sha
            ):
                raise ExternalV3StateError("committed output chain drifted")
            value = self._validate_durable_receipt(
                campaign,
                row,
                expected_status="SUCCEEDED",
                approval_evidence_sha256=self._approval_rows(
                    connection, campaign
                )["approval_evidence_sha256"],
                approval_binding_sha256=self._approval_rows(
                    connection, campaign
                )["approval_binding_sha256"],
                parsed_response=parsed,
            )
            cursor = connection.execute(
                "UPDATE rounds SET state='CONSUMED' WHERE campaign_id=? AND ordinal=? AND state='RESPONSE_COMMITTED'",
                (campaign.campaign_id, ordinal),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("response consumption CAS failed")
            remaining = connection.execute(
                "SELECT COUNT(*) FROM rounds WHERE campaign_id=? AND state!='CONSUMED'",
                (campaign.campaign_id,),
            ).fetchone()[0]
            if remaining == 0:
                connection.execute(
                    "UPDATE campaigns SET state='COMPLETE' WHERE campaign_id=? AND state='RUNNING'",
                    (campaign.campaign_id,),
                )
            connection.commit()
            return {**value, "receipt_sha256": row["receipt_sha256"]}
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def commit_terminal_no_retry(
        self,
        campaign: ExternalCampaignV3,
        intent: DispatchIntentV3,
        *,
        status: str,
        error_code: str,
        raw_response_bytes: bytes | None = None,
        elapsed_seconds: float | None = None,
    ) -> dict[str, object]:
        if (status, error_code) not in _TERMINAL_STATUS_ERROR_PAIRS:
            raise ExternalV3StateError("terminal no-retry status/error pair is invalid")
        if error_code == "KNOWN_RESPONSE_INVALID":
            if type(raw_response_bytes) is not bytes or elapsed_seconds is None:
                raise ExternalV3StateError(
                    "known invalid response requires immutable response metadata"
                )
            elapsed = _require_finite_float(
                elapsed_seconds, label="invalid response elapsed seconds"
            )
            if (
                elapsed > campaign.pricing.per_round_deadline_seconds
                or intent.campaign_elapsed_seconds + elapsed
                > campaign.pricing.campaign_deadline_seconds
            ):
                raise ExternalV3StateError(
                    "known invalid response metadata exceeds its deadline"
                )
            # This is the only authority for a known-invalid terminal result.
            # Re-run the exact closed parser over the immutable bytes; a caller
            # cannot turn a valid response into a failure receipt merely by
            # selecting an error enum.
            try:
                parse_external_response_v3(
                    raw_response_bytes,
                    campaign=campaign,
                    bound=intent.bound,
                    elapsed_seconds=elapsed,
                )
            except ExternalV3PolicyError:
                pass
            else:
                raise ExternalV3StateError(
                    "known invalid response was not rejected by the parser"
                )
            raw_response_sha256: str | None = _sha256_bytes(raw_response_bytes)
            response_bytes: int | None = len(raw_response_bytes)
        else:
            if raw_response_bytes is not None:
                raise ExternalV3StateError(
                    "ambiguous terminal receipt cannot claim response bytes"
                )
            if error_code == "PROCESS_LOST_AFTER_INTENT":
                if elapsed_seconds is not None:
                    raise ExternalV3StateError(
                        "process-loss receipt cannot invent elapsed metadata"
                    )
                elapsed = None
            else:
                if elapsed_seconds is None:
                    raise ExternalV3StateError(
                        "transport terminal receipt requires elapsed metadata"
                    )
                elapsed = _require_finite_float(
                    elapsed_seconds, label="ambiguous response elapsed seconds"
                )
            raw_response_sha256 = None
            response_bytes = None
        campaign_state = "AMBIGUOUS" if status == "AMBIGUOUS_NO_RETRY" else "FAILED"
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            prior = self._require_intent_row(
                connection,
                campaign,
                intent,
                states=frozenset(
                    {"DISPATCH_INTENT", "COMMITMENT_RECOVERY_REQUIRED"}
                ),
            )
            receipt = {
                **self._receipt_core(connection, campaign, intent),
                "status": status,
                "error_code": error_code,
                "response_id_sha256": None,
                "raw_response_sha256": raw_response_sha256,
                "created_at": None,
                "returned_model": None,
                "system_fingerprint_sha256": None,
                "response_bytes": response_bytes,
                "advisory_sha256": None,
                "output_chain_sha256": None,
                "prompt_tokens": None,
                "completion_tokens": None,
                "total_tokens": None,
                "actual_cost_micros": None,
                "elapsed_seconds": elapsed,
                "audit_verifiability": _TERMINAL_AUDIT_STATE,
            }
            receipt_bytes = canonical_json(receipt).encode("utf-8")
            receipt_sha = _sha256_bytes(receipt_bytes)
            commitment_value = self._terminal_commitment_value(
                campaign,
                intent.bound,
                dispatch_intent_sha256=intent.dispatch_intent_sha256,
                receipt=receipt,
                receipt_sha256=receipt_sha,
            )
            commitment_bytes = canonical_json(commitment_value).encode("utf-8")
            generation = (
                0
                if prior["state"] == "DISPATCH_INTENT"
                else _require_exact_int(
                    prior["durable_write_generation"],
                    label="recovery commitment generation",
                )
                + 1
            )
            if prior["state"] == "COMMITMENT_RECOVERY_REQUIRED" and (
                prior["raw_response_sha256"] != raw_response_sha256
                or prior["response_bytes"] != response_bytes
                or prior["receipt_bytes"] != receipt_bytes
                or prior["receipt_sha256"] != receipt_sha
            ):
                raise ExternalV3StateError(
                    "terminal recovery disagrees with prepared intent"
                )
            target = self._terminal_commitment_path(
                campaign, intent.bound, generation=generation
            )
            cursor = connection.execute(
                """
                UPDATE rounds SET state='COMMITMENT_PREPARED',
                                  receipt_bytes=?,receipt_sha256=?,
                                  raw_response_sha256=?,response_bytes=?,elapsed_seconds=?,
                                  durable_write_kind='TERMINAL_COMMITMENT',
                                  durable_write_generation=?,durable_write_request_sha256=?,
                                  durable_write_raw_sha256=?,durable_write_raw_size=?,
                                  durable_write_target=?,durable_write_payload_sha256=?,
                                  durable_write_payload_size=?,durable_write_phase='INTENT_DURABLE'
                 WHERE campaign_id=? AND ordinal=? AND state=?
                   AND dispatch_intent_sha256=? AND attempts=1
                """,
                (
                    receipt_bytes,
                    receipt_sha,
                    raw_response_sha256,
                    response_bytes,
                    elapsed,
                    generation,
                    intent.bound.request_sha256,
                    raw_response_sha256,
                    response_bytes,
                    target.name,
                    _sha256_bytes(commitment_bytes),
                    len(commitment_bytes),
                    campaign.campaign_id,
                    intent.bound.ordinal,
                    prior["state"],
                    intent.dispatch_intent_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("terminal write prepare CAS failed")
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

        self._artifact_write_cutpoint(
            "TERMINAL_COMMITMENT", "AFTER_PREPARE_COMMIT"
        )
        self._write_terminal_commitment(
            campaign,
            intent.bound,
            dispatch_intent_sha256=intent.dispatch_intent_sha256,
            receipt=receipt,
            receipt_sha256=receipt_sha,
            generation=generation,
        )
        self._artifact_write_cutpoint(
            "TERMINAL_COMMITMENT", "BEFORE_FINALIZE_COMMIT"
        )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_intent_row(
                connection,
                campaign,
                intent,
                states=frozenset({"COMMITMENT_PREPARED"}),
            )
            approval = self._approval_rows(connection, campaign)
            prepared_receipt = self._validate_durable_receipt(
                campaign,
                row,
                expected_status=status,
                approval_evidence_sha256=approval["approval_evidence_sha256"],
                approval_binding_sha256=approval["approval_binding_sha256"],
            )
            self._validate_terminal_commitment(
                campaign,
                intent.bound,
                row,
                prepared_receipt,
                phases=frozenset({"INTENT_DURABLE"}),
            )
            cursor = connection.execute(
                """
                UPDATE rounds SET state=?,durable_write_phase='SEALED_COMMITTED'
                 WHERE campaign_id=? AND ordinal=? AND state='COMMITMENT_PREPARED'
                   AND durable_write_generation=? AND durable_write_target=?
                """,
                (
                    status,
                    campaign.campaign_id,
                    intent.bound.ordinal,
                    generation,
                    target.name,
                ),
            )
            if cursor.rowcount != 1:
                raise ExternalV3StateError("terminal finalize CAS failed")
            connection.execute(
                "UPDATE campaigns SET state=?,elapsed_seconds=? WHERE campaign_id=? AND state='RUNNING'",
                (
                    campaign_state,
                    intent.campaign_elapsed_seconds + (elapsed or 0.0),
                    campaign.campaign_id,
                ),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        self._artifact_write_cutpoint(
            "TERMINAL_COMMITMENT", "AFTER_FINALIZE_COMMIT"
        )
        return {**receipt, "receipt_sha256": receipt_sha}

    def load_terminal_receipt(
        self, campaign: ExternalCampaignV3, *, ordinal: int
    ) -> dict[str, object]:
        """Load a closed terminal receipt only after replaying the campaign."""

        validate_external_campaign_v3(campaign)
        if type(ordinal) is not int or not 0 <= ordinal < EXTERNAL_V3_ROUND_COUNT:
            raise ExternalV3StateError("terminal receipt ordinal is invalid")
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_campaign_durable_state(connection, campaign)
            row = connection.execute(
                "SELECT * FROM rounds WHERE campaign_id=? AND ordinal=?",
                (campaign.campaign_id, ordinal),
            ).fetchone()
            if row is None or row["state"] not in {
                "FAILED_NO_RETRY",
                "AMBIGUOUS_NO_RETRY",
            }:
                raise ExternalV3StateError("terminal receipt is unavailable")
            approval = self._approval_rows(connection, campaign)
            receipt = self._validate_durable_receipt(
                campaign,
                row,
                expected_status=row["state"],
                approval_evidence_sha256=approval["approval_evidence_sha256"],
                approval_binding_sha256=approval["approval_binding_sha256"],
            )
            return {**receipt, "receipt_sha256": row["receipt_sha256"]}
        finally:
            connection.close()

    def snapshot(self, campaign: ExternalCampaignV3) -> dict[str, object]:
        validate_external_campaign_v3(campaign)
        connection = self._connect()
        try:
            connection.execute("BEGIN")
            self._validate_campaign_durable_state(connection, campaign)
            campaign_row = connection.execute(
                """
                SELECT state,manifest_sha256,approval_evidence_sha256,
                       approval_binding_sha256,reserved_cost_micros,
                       actual_cost_micros,total_tokens,elapsed_seconds
                  FROM campaigns WHERE campaign_id=?
                """,
                (campaign.campaign_id,),
            ).fetchone()
            if campaign_row is None:
                raise ExternalV3StateError("campaign is unavailable")
            rows = connection.execute(
                """
                SELECT ordinal,round_id,state,request_sha256,prior_output_sha256,
                       prior_output_chain_sha256,dispatch_intent_sha256,attempts,
                       reserved_cost_micros,actual_cost_micros,total_tokens,
                       advisory_sha256,output_chain_sha256,receipt_sha256,
                       raw_response_sha256,response_bytes,elapsed_seconds,
                       campaign_elapsed_before_dispatch_seconds
                  FROM rounds WHERE campaign_id=? ORDER BY ordinal
                """,
                (campaign.campaign_id,),
            ).fetchall()
        finally:
            connection.close()
        return {
            "schema_version": EXTERNAL_V3_LEDGER_SCHEMA,
            "campaign_id": campaign.campaign_id,
            **dict(campaign_row),
            "rounds": [dict(row) for row in rows],
            "external_transport_state": EXTERNAL_V3_TRANSPORT_STATE,
            "authority": EXTERNAL_V3_AUTHORITY,
        }


def execute_scripted_fake_round_v3(
    *,
    ledger: ExternalCampaignLedgerV3,
    campaign: ExternalCampaignV3,
    claim: ClaimedExternalRoundV3,
    transport: ScriptedFakeTransport,
) -> dict[str, object]:
    """Exercise one irreversible boundary with a sealed no-I/O fake only."""

    if type(ledger) is not ExternalCampaignLedgerV3:
        raise ExternalV3Disabled("only the exact v3 ledger is reachable in the runner")
    if type(campaign) is not ExternalCampaignV3 or type(claim) is not ClaimedExternalRoundV3:
        raise ExternalV3PolicyError("fake runner campaign or claim type is invalid")
    if type(transport) is not ScriptedFakeTransport:
        raise ExternalV3Disabled("only ScriptedFakeTransport is reachable in v3")
    intent = ledger.mark_dispatch_intent(campaign, claim)
    try:
        raw, elapsed = _consume_scripted_fake(transport, claim.bound.request_bytes)
    except _FakeAmbiguousAfterIntent as error:
        error_code = (
            "WALL_CLOCK_TIMEOUT_AFTER_INTENT"
            if str(error) == "TIMEOUT_AFTER_INTENT"
            else "TRANSPORT_RESULT_AMBIGUOUS"
        )
        return ledger.commit_terminal_no_retry(
            campaign,
            intent,
            status="AMBIGUOUS_NO_RETRY",
            error_code=error_code,
            elapsed_seconds=transport._elapsed_seconds,
        )
    if (
        elapsed > campaign.pricing.per_round_deadline_seconds
        or intent.campaign_elapsed_seconds + elapsed
        > campaign.pricing.campaign_deadline_seconds
    ):
        return ledger.commit_terminal_no_retry(
            campaign,
            intent,
            status="AMBIGUOUS_NO_RETRY",
            error_code="WALL_CLOCK_TIMEOUT_AFTER_INTENT",
            elapsed_seconds=elapsed,
        )
    try:
        ledger.commit_success(
            campaign,
            intent,
            raw_response_bytes=raw,
            elapsed_seconds=elapsed,
        )
    except ExternalV3PolicyError:
        return ledger.commit_terminal_no_retry(
            campaign,
            intent,
            status="FAILED_NO_RETRY",
            error_code="KNOWN_RESPONSE_INVALID",
            raw_response_bytes=raw,
            elapsed_seconds=elapsed,
        )
    return ledger.consume_committed(campaign, ordinal=claim.bound.ordinal)


def mark_orphaned_dispatch_ambiguous_v3(
    *,
    ledger: ExternalCampaignLedgerV3,
    campaign: ExternalCampaignV3,
    ordinal: int,
) -> dict[str, object]:
    """Recover a post-intent crash without ever retrying the side effect."""

    if type(ledger) is not ExternalCampaignLedgerV3:
        raise ExternalV3Disabled("only the exact v3 ledger can recover dispatch state")
    intent = ledger.load_dispatch_intent(campaign, ordinal=ordinal)
    return ledger.commit_terminal_no_retry(
        campaign,
        intent,
        status="AMBIGUOUS_NO_RETRY",
        error_code="PROCESS_LOST_AFTER_INTENT",
    )


def external_review(*_args: object, **_kwargs: object) -> None:
    """Real credential and network transport is intentionally unreachable."""

    raise ExternalV3Disabled("real external transport is absent from the v3 skeleton")


__all__ = [
    "BoundExternalRoundV3",
    "ClaimedExternalRoundV3",
    "DispatchIntentV3",
    "EXTERNAL_V3_AUTHORITY",
    "EXTERNAL_V3_LEDGER_SCHEMA",
    "EXTERNAL_V3_MANIFEST_SCHEMA",
    "EXTERNAL_V3_OUTPUT_ALLOWLIST",
    "EXTERNAL_V3_RECEIPT_SCHEMA",
    "EXTERNAL_V3_SUCCESS_REPLAY_SCHEMA",
    "EXTERNAL_V3_TERMINAL_COMMITMENT_SCHEMA",
    "EXTERNAL_V3_DURABLE_WRITE_PROTOCOL",
    "EXTERNAL_V3_LEDGER_PLATFORM_STATE",
    "EXTERNAL_V3_TRANSPORT_STATE",
    "ExternalCampaignLedgerV3",
    "ExternalCampaignV3",
    "ExternalV3Disabled",
    "ExternalV3Error",
    "ExternalV3PolicyError",
    "ExternalV3StateError",
    "ParsedExternalResponseV3",
    "PricingBudgetV3",
    "ScriptedFakeTransport",
    "advance_output_chain",
    "derive_external_round_v3",
    "execute_scripted_fake_round_v3",
    "external_review",
    "mark_orphaned_dispatch_ambiguous_v3",
    "parse_external_response_v3",
    "prepare_external_campaign_v3",
    "validate_external_campaign_v3",
]
