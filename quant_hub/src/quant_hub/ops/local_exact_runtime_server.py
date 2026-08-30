"""Fixed Flask/WSGI runtime and lease-bound deployment endpoints."""

from __future__ import annotations

import hashlib
from http import HTTPStatus
import json
import os
import ctypes
from ctypes import wintypes
from pathlib import Path
from pathlib import PureWindowsPath
import re
import socket
import stat
import threading
from typing import Mapping

from flask import Response, request
from werkzeug.serving import WSGIRequestHandler

from .local_exact_runtime_admission import (
    ExactRuntimeAdmissionError,
    LockedExactRuntimeAdmissionGate,
    LockedTransientRuntimeAdmissionGate,
    ProductionTransientRuntimeAdmissionGate,
)
from .local_exact_runtime_canary_runner import ExactRuntimeCanaryRunner
from .local_exact_runtime_import_closure import _LockedExactRuntimeImportClosure
from .local_exact_runtime_tooling_scanner import _WindowsReadGuardSet
from .local_release_identity import (
    LocalReleaseIdentityError,
    canonical_bytes,
    identity_sha256,
)
from .local_windows_endpoint_evidence import EXACT_RUNTIME_ENDPOINT_SCHEMA
from .local_steady_windows_endpoint_evidence import (
    STEADY_EXACT_RUNTIME_ENDPOINT_SCHEMA,
)
from .local_windows_writer_lease_holder import (
    LockedSteadyWindowsWriterLease,
    LockedWindowsWriterLease,
)


_BIND_HOST = "0.0.0.0"
_PROBE_HOST = "127.0.0.1:8765"
_PORT = 8765
_CHALLENGE_RE = re.compile(r"^[0-9a-f]{48}$")
_CANONICAL_REQUEST_LINE_RE = re.compile(
    rb"(?P<method>[!#$%&'*+\-.^_`|~0-9A-Za-z]+) "
    rb"(?P<target>[\x21-\x7e]{1,4096}) HTTP/1\.1\r\n\Z"
)
_MAX_CANONICAL_REQUEST_LINE_BYTES = 8192
_MAX_CANARY_REQUEST_BYTES = 512
_READ_ONLY_DATABASE_ROOT_ENV = "QUANT_HUB_READ_ONLY_DATABASE_ROOT"


class ExactRuntimeServerError(RuntimeError):
    """The exact application/server contract failed before listening."""


class _FatalExactRuntime(BaseException):
    """Escape Flask's application error handler and terminate the child."""


def _canonical_request_line(raw: object) -> tuple[bytes, bytes] | None:
    """Parse one bounded ASCII HTTP/1.1 request-line without normalization."""

    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_CANONICAL_REQUEST_LINE_BYTES:
        return None
    matched = _CANONICAL_REQUEST_LINE_RE.fullmatch(raw)
    if matched is None:
        return None
    return matched.group("method"), matched.group("target")


class _ExactRuntimeRequestHandler(WSGIRequestHandler):
    """Preserve the request target before BaseHTTPRequestHandler rewrites it."""

    _exact_raw_request_target = b""

    def parse_request(self) -> bool:
        parsed_line = _canonical_request_line(self.raw_requestline)
        if parsed_line is None:
            self.requestline = "<non-canonical request-line>"
            self.request_version = "HTTP/1.1"
            self.command = None
            self.close_connection = True
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Non-canonical HTTP/1.1 request-line",
            )
            return False
        raw_method, raw_target = parsed_line
        self._exact_raw_request_target = raw_target
        accepted = super().parse_request()
        if not accepted:
            self._exact_raw_request_target = b""
            return False
        if (
            type(self.command) is not str
            or self.command.encode("ascii", errors="strict") != raw_method
            or self.request_version != "HTTP/1.1"
        ):
            self._exact_raw_request_target = b""
            self.send_error(
                HTTPStatus.BAD_REQUEST,
                "Request-line identity drifted during parsing",
            )
            return False
        return True

    def make_environ(self) -> dict[str, object]:
        environ = super().make_environ()
        raw_target = self._exact_raw_request_target
        if type(raw_target) is not bytes:
            raise ExactRuntimeServerError("raw request target provenance drifted")
        target = raw_target.decode("ascii", errors="strict")
        environ["RAW_URI"] = target
        environ["REQUEST_URI"] = target
        return environ


class _RuntimeStateCheckpoint:
    """Pin state path identity while allowing same-file SQLite transactions."""

    __slots__ = ("_database_paths", "_expected", "_protected_paths")

    def __init__(
        self,
        *,
        protected_paths: tuple[Path, ...],
        database_paths: tuple[Path, ...],
    ):
        self._protected_paths = protected_paths
        self._database_paths = database_paths
        self._expected = self._capture()

    @staticmethod
    def _identity(path: Path, *, include_content: bool) -> tuple[object, ...]:
        resolved = _regular_file(path)
        info = resolved.lstat()
        content_sha256 = None
        if include_content:
            try:
                content_sha256 = hashlib.sha256(resolved.read_bytes()).hexdigest()
            except OSError as error:
                raise ExactRuntimeServerError(
                    "protected runtime state is unreadable"
                ) from error
        return (
            str(resolved),
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_nlink),
            content_sha256,
        )

    def _capture(self) -> tuple[tuple[object, ...], ...]:
        return tuple(
            self._identity(path, include_content=True)
            for path in self._protected_paths
        ) + tuple(
            self._identity(path, include_content=False)
            for path in self._database_paths
        )

    def checkpoint(self) -> None:
        if self._capture() != self._expected:
            raise ExactRuntimeServerError("runtime state path identity drifted")


class _WindowsMutableStateGuardSet:
    """Allow same-file writes while denying database replacement until shutdown."""

    __slots__ = ("_close_handle", "_handles")

    def __init__(self, paths: tuple[Path, ...]):
        self._handles: list[int] = []
        self._close_handle = None
        if os.name != "nt":
            return
        try:
            kernel32 = ctypes.WinDLL(
                "kernel32.dll",
                use_last_error=True,
                winmode=0x00000800,
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
            raise ExactRuntimeServerError(
                "System32 mutable state guard binding failed"
            ) from error
        self._close_handle = close_handle
        try:
            for path in paths:
                ctypes.set_last_error(0)
                raw = create_file(
                    str(path),
                    0x80000000,  # GENERIC_READ
                    0x00000001 | 0x00000002,  # share read/write, deny delete
                    None,
                    3,  # OPEN_EXISTING
                    0x00200000 | 0x08000000,  # OPEN_REPARSE_POINT | SEQUENTIAL_SCAN
                    None,
                )
                invalid = ctypes.c_void_p(-1).value
                if raw in {None, 0, -1, invalid}:
                    raise ExactRuntimeServerError(
                        "mutable runtime database could not be fixed against replacement; "
                        f"Windows error {ctypes.get_last_error()}"
                    )
                self._handles.append(int(raw))
                _regular_file(path)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if os.name != "nt":
            return
        close_handle = self._close_handle
        if close_handle is None:
            raise ExactRuntimeServerError("mutable state guard close binding is missing")
        failure: BaseException | None = None
        while self._handles:
            handle = self._handles.pop()
            try:
                result = close_handle(handle)
                if type(result) is not int or result == 0:
                    raise ExactRuntimeServerError(
                        "mutable state guard close was not mechanically confirmed"
                    )
            except BaseException as error:
                if failure is None:
                    failure = error
        if failure is not None:
            raise ExactRuntimeServerError("mutable state guard close failed") from failure


class _RuntimeStateGuardSet:
    __slots__ = ("_mutable", "_protected")

    def __init__(
        self,
        *,
        protected_paths: tuple[Path, ...],
        database_paths: tuple[Path, ...],
    ):
        self._protected = _WindowsReadGuardSet(protected_paths)
        try:
            self._mutable = _WindowsMutableStateGuardSet(database_paths)
        except BaseException:
            self._protected.close()
            raise

    def close(self) -> None:
        failure: BaseException | None = None
        try:
            self._mutable.close()
        except BaseException as error:
            failure = error
        try:
            self._protected.close()
        except BaseException as error:
            if failure is None:
                failure = error
        if failure is not None:
            raise ExactRuntimeServerError("runtime state guards did not close") from failure


def _regular_file(path: Path) -> Path:
    try:
        absolute = path.absolute()
        chain: list[Path] = []
        current = absolute.parent
        while True:
            chain.append(current)
            if current.parent == current:
                break
            current = current.parent
        for directory in reversed(chain):
            if not os.path.lexists(directory):
                continue
            directory_info = directory.lstat()
            if (
                stat.S_ISLNK(directory_info.st_mode)
                or bool(getattr(directory_info, "st_file_attributes", 0) & 0x400)
                or not stat.S_ISDIR(directory_info.st_mode)
            ):
                raise ExactRuntimeServerError(
                    f"required exact runtime ancestor is unsafe: {directory}"
                )
        info = absolute.lstat()
        resolved = absolute.resolve(strict=True)
        resolved_info = resolved.lstat()
    except OSError as error:
        raise ExactRuntimeServerError(
            f"required exact runtime file is unavailable: {path}"
        ) from error
    reparse = stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )
    same_path = (
        PureWindowsPath(str(resolved)) == PureWindowsPath(str(absolute))
        if os.name == "nt"
        else resolved == absolute
    )
    same_identity = (
        info.st_dev == resolved_info.st_dev
        and info.st_ino == resolved_info.st_ino
        and stat.S_IFMT(info.st_mode) == stat.S_IFMT(resolved_info.st_mode)
        and info.st_nlink == resolved_info.st_nlink
    )
    if (
        reparse
        or not same_path
        or not same_identity
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
    ):
        raise ExactRuntimeServerError(
            f"required exact runtime file is not regular single-link: {path}"
        )
    return resolved


def _secret(path: Path) -> str:
    try:
        value = _regular_file(path).read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as error:
        raise ExactRuntimeServerError("session secret is unreadable") from error
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ExactRuntimeServerError("session secret is not fixed 256-bit lowercase hex")
    return value


def _fix_release_read_only_root(runtime: Path) -> None:
    resolved = runtime.resolve(strict=True)
    if not resolved.is_dir():
        raise ExactRuntimeServerError("release runtime root is unavailable")
    os.environ[_READ_ONLY_DATABASE_ROOT_ENV] = str(resolved)


def _trusted_origins() -> tuple[str, ...]:
    hosts = {"localhost", "127.0.0.1"}
    for value in (socket.gethostname(), socket.getfqdn()):
        if value:
            hosts.add(value)
    try:
        hosts.update(
            item[4][0]
            for item in socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET
            )
        )
    except socket.gaierror:
        pass
    return tuple(sorted(f"http://{host}:{_PORT}" for host in hosts))


def _json_response(document: dict[str, object], status: int) -> Response:
    raw = canonical_bytes(document)
    response = Response(raw, status=status, content_type="application/json")
    response.headers["Cache-Control"] = "no-store"
    response.headers["Connection"] = "close"
    return response


def _reject(code: str, status: int) -> Response:
    return _json_response(
        {
            "schema_version": "qrh-exact-runtime-rejection/v1",
            "status": "rejected",
            "code": code,
        },
        status,
    )


def _strict_common_request(expected_method: str, expected_path: str) -> str | None:
    from quant_hub.web.access_gate import _exact_raw_request_target

    if not _exact_raw_request_target(expected_path):
        return "request_target"
    if request.method != expected_method:
        return "method"
    if request.query_string != b"":
        return "query"
    if request.remote_addr not in {"127.0.0.1", "::1"}:
        return "non_loopback"
    if request.host != _PROBE_HOST:
        return "host"
    if request.headers.get("Accept") != "application/json":
        return "accept"
    if request.headers.get("Cache-Control") != "no-store":
        return "cache_control"
    if request.headers.get("Connection", "").casefold() != "close":
        return "connection"
    if request.headers.get("Accept-Encoding") not in {None, "identity"}:
        return "accept_encoding"
    if request.headers.get("Content-Encoding") is not None:
        return "content_encoding"
    if request.headers.get("Transfer-Encoding") is not None:
        return "transfer_encoding"
    proxy_headers = {
        "forwarded",
        "proxy-connection",
        "via",
        "x-real-ip",
    }
    if any(
        name.casefold() in proxy_headers
        or name.casefold().startswith("x-forwarded-")
        for name in request.headers.keys()
    ):
        return "proxy"
    return None


def _checkpoint(
    lease: object,
    closure: _LockedExactRuntimeImportClosure | None = None,
) -> dict[str, object]:
    if closure is not None:
        try:
            closure.checkpoint()
        except Exception as error:
            raise _FatalExactRuntime(
                "exact import closure checkpoint failed"
            ) from error
    try:
        record, _root, _api = lease._canary_checkpoint()
    except Exception as error:
        raise _FatalExactRuntime("writer lease checkpoint failed") from error
    if type(record) is not dict:
        raise _FatalExactRuntime("writer lease record type drifted")
    return record


def _checkpoint_state(checkpoint: _RuntimeStateCheckpoint) -> None:
    try:
        checkpoint.checkpoint()
    except Exception as error:
        raise _FatalExactRuntime("runtime state checkpoint failed") from error


def _endpoint_claim(
    lease: object,
    challenge: str,
    closure: _LockedExactRuntimeImportClosure | None = None,
) -> dict[str, object]:
    before = _checkpoint(lease, closure)
    holder = before.get("holder")
    release = before.get("release")
    if type(holder) is not dict or type(release) is not dict:
        raise _FatalExactRuntime("writer lease process/release identity is absent")
    try:
        lease_claim = lease.lease_claim
    except Exception as error:
        raise _FatalExactRuntime("writer lease claim is unavailable") from error
    document: dict[str, object] = {
        "schema_version": EXACT_RUNTIME_ENDPOINT_SCHEMA,
        "status": "identity_claim_only",
        "probe_challenge": challenge,
        "attempt_id": before["attempt_id"],
        "nonce": before["nonce"],
        "operation": before["operation"],
        "role": before["role"],
        "start_nonce": before["start_nonce"],
        "authorization_sha256": before["authorization_sha256"],
        "scm_identity_sha256": before["scm_identity_sha256"],
        "state_identity_sha256": before["state_identity_sha256"],
        "release": release,
        "service": {
            "service_name": holder["service_name"],
            "host_pid": holder["host_pid"],
            "host_creation_time_100ns": holder["host_creation_time_100ns"],
        },
        "child": {
            "child_pid": holder["child_pid"],
            "child_creation_time_100ns": holder["child_creation_time_100ns"],
        },
        "listener": {"local_address": _BIND_HOST, "local_port": _PORT},
        "writer_lease": lease_claim,
    }
    document["endpoint_claim_sha256"] = identity_sha256(document)
    after = _checkpoint(lease, closure)
    if after != before:
        raise _FatalExactRuntime("writer lease drifted while building endpoint claim")
    return document


def _steady_endpoint_claim(
    lease: LockedSteadyWindowsWriterLease,
    gate: LockedExactRuntimeAdmissionGate,
    challenge: str,
    closure: _LockedExactRuntimeImportClosure,
) -> dict[str, object]:
    if (
        type(lease) is not LockedSteadyWindowsWriterLease
        or type(gate) is not LockedExactRuntimeAdmissionGate
        or type(closure) is not _LockedExactRuntimeImportClosure
    ):
        raise TypeError("steady endpoint requires exact live capabilities")
    before = _checkpoint(lease, closure)
    holder = before.get("holder")
    release = before.get("release")
    if type(holder) is not dict or type(release) is not dict:
        raise _FatalExactRuntime(
            "steady writer lease process/release identity is absent"
        )
    if (
        before.get("schema_version") != "qrh-writer-lease-record/v2"
        or before.get("authority_kind") != "steady_active"
        or before.get("runtime_state_kind") != "steady_current"
        or before.get("job_identity_sha256") != gate.job_identity_sha256
        or before.get("admission_binding_sha256")
        != gate.admission_binding_sha256
    ):
        raise _FatalExactRuntime("steady writer lease 未绑定 live admission gate")
    state_before = gate.state
    if state_before == "ack_pending":
        try:
            gate.acknowledge_ready(challenge)
        except ExactRuntimeAdmissionError as error:
            raise _FatalExactRuntime(
                "steady readiness acknowledgement 无法登记"
            ) from error
    state_after = gate.state
    if state_before == "ack_pending" and state_after != "ack_pending":
        raise _FatalExactRuntime("steady readiness acknowledgement 改变 gate state")
    try:
        lease_claim = lease.lease_claim
    except Exception as error:
        raise _FatalExactRuntime("steady writer lease claim 不可用") from error
    document: dict[str, object] = {
        "schema_version": STEADY_EXACT_RUNTIME_ENDPOINT_SCHEMA,
        "status": "steady_identity_claim_only",
        "probe_challenge": challenge,
        "authority_kind": before["authority_kind"],
        "runtime_state_kind": before["runtime_state_kind"],
        "boot_nonce": before["boot_nonce"],
        "active_release_sha256": before["active_release_sha256"],
        "binding_sha256": before["binding_sha256"],
        "retention_aggregate_sha256": before["retention_aggregate_sha256"],
        "state_identity_sha256": before["state_identity_sha256"],
        "tooling_sha256": before["tooling_sha256"],
        "receipt_lineage_aggregate_sha256": before[
            "receipt_lineage_aggregate_sha256"
        ],
        "legacy_c_live_fence_aggregate_sha256": before[
            "legacy_c_live_fence_aggregate_sha256"
        ],
        "authorization_sha256": before["authorization_sha256"],
        "scm_identity_sha256": before["scm_identity_sha256"],
        "release": release,
        "service": {
            "service_name": holder["service_name"],
            "host_pid": holder["host_pid"],
            "host_creation_time_100ns": holder["host_creation_time_100ns"],
        },
        "child": {
            "child_pid": holder["child_pid"],
            "child_creation_time_100ns": holder[
                "child_creation_time_100ns"
            ],
        },
        "listener": {"local_address": _BIND_HOST, "local_port": _PORT},
        "writer_lease": lease_claim,
        "job_identity_sha256": gate.job_identity_sha256,
        "admission_binding_sha256": gate.admission_binding_sha256,
        "admission_state": state_after,
    }
    document["endpoint_claim_sha256"] = identity_sha256(document)
    after = _checkpoint(lease, closure)
    if after != before or gate.state != state_after:
        raise _FatalExactRuntime(
            "steady writer/admission identity drifted while building endpoint claim"
        )
    return document


def _canary_challenge() -> str | Response:
    problem = _strict_common_request("POST", "/deployment-canaryz")
    if problem is not None:
        return _reject(problem, 404)
    if request.mimetype != "application/json" or request.content_type != "application/json":
        return _reject("content_type", 415)
    content_length = request.content_length
    content_length_header = request.headers.get("Content-Length")
    if (
        type(content_length) is not int
        or content_length < 1
        or content_length > _MAX_CANARY_REQUEST_BYTES
        or content_length_header != str(content_length)
    ):
        return _reject("content_length", 400)
    raw = request.get_data(cache=False, as_text=False)
    if len(raw) != content_length:
        return _reject("content_length", 400)
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _reject("json", 400)
    try:
        canonical = canonical_bytes(document)
    except LocalReleaseIdentityError:
        return _reject("body_schema", 400)
    if (
        type(document) is not dict
        or set(document) != {"challenge_nonce"}
        or canonical != raw
        or type(document["challenge_nonce"]) is not str
        or _CHALLENGE_RE.fullmatch(document["challenge_nonce"]) is None
    ):
        return _reject("body_schema", 400)
    return str(document["challenge_nonce"])


def _register_exact_endpoints(
    app: object,
    lease: object,
    runner: object,
    closure: _LockedExactRuntimeImportClosure,
) -> None:
    if (
        type(lease) is not LockedWindowsWriterLease
        or type(runner) is not ExactRuntimeCanaryRunner
        or type(closure) is not _LockedExactRuntimeImportClosure
    ):
        raise TypeError("production endpoints require exact lease and runner")
    canary_lock = threading.Lock()

    @app.route(
        "/deploymentz", methods=["GET"], provide_automatic_options=False
    )
    def exact_deployment_identity() -> Response:
        problem = _strict_common_request("GET", "/deploymentz")
        challenge = request.headers.get("X-Quant-Hub-Endpoint-Challenge")
        if (
            problem is not None
            or type(challenge) is not str
            or _CHALLENGE_RE.fullmatch(challenge) is None
            or request.content_length is not None
            or request.headers.get("Content-Length") is not None
        ):
            return _reject(problem or "challenge", 404)
        return _json_response(_endpoint_claim(lease, challenge, closure), 200)

    @app.route(
        "/deployment-canaryz", methods=["POST"], provide_automatic_options=False
    )
    def exact_deployment_canary() -> Response:
        challenge = _canary_challenge()
        if isinstance(challenge, Response):
            return challenge
        if not canary_lock.acquire(blocking=False):
            return _reject("canary_busy", 409)
        try:
            _checkpoint(lease, closure)
            try:
                evidence = runner.run(lease, challenge)
                raw = evidence.canonical_bytes()
            except Exception as error:
                raise _FatalExactRuntime("exact canary execution failed") from error
            _checkpoint(lease, closure)
            response = Response(raw, status=200, content_type="application/json")
            response.headers["Cache-Control"] = "no-store"
            response.headers["Connection"] = "close"
            return response
        finally:
            canary_lock.release()


def _register_steady_endpoint(
    app: object,
    lease: LockedSteadyWindowsWriterLease,
    gate: LockedExactRuntimeAdmissionGate,
    closure: _LockedExactRuntimeImportClosure,
) -> None:
    if (
        type(lease) is not LockedSteadyWindowsWriterLease
        or type(gate) is not LockedExactRuntimeAdmissionGate
        or type(closure) is not _LockedExactRuntimeImportClosure
    ):
        raise TypeError("steady endpoint requires exact live capabilities")

    @app.route(
        "/deploymentz", methods=["GET"], provide_automatic_options=False
    )
    def steady_deployment_identity() -> Response:
        problem = _strict_common_request("GET", "/deploymentz")
        challenge = request.headers.get("X-Quant-Hub-Endpoint-Challenge")
        if (
            problem is not None
            or type(challenge) is not str
            or _CHALLENGE_RE.fullmatch(challenge) is None
            or request.content_length is not None
            or request.headers.get("Content-Length") is not None
        ):
            return _reject(problem or "challenge", 404)
        return _json_response(
            _steady_endpoint_claim(lease, gate, challenge, closure), 200
        )


class _TransientAdmissionWsgiGate:
    """Outermost gate: transient serves only exact identity/canary probes."""

    __slots__ = ("_application", "_gate")

    def __init__(
        self, application: object, gate: LockedTransientRuntimeAdmissionGate
    ) -> None:
        if (
            not callable(application)
            or type(gate) is not LockedTransientRuntimeAdmissionGate
        ):
            raise TypeError("transient outer gate requires exact live gate")
        self._application = application
        self._gate = gate

    @staticmethod
    def _common(environ: Mapping[str, object]) -> bool:
        return (
            environ.get("QUERY_STRING") == ""
            and environ.get("HTTP_HOST") == _PROBE_HOST
            and environ.get("REMOTE_ADDR") == "127.0.0.1"
            and not any(
                key in environ
                for key in (
                    "HTTP_FORWARDED",
                    "HTTP_PROXY_CONNECTION",
                    "HTTP_VIA",
                    "HTTP_X_FORWARDED_FOR",
                    "HTTP_X_FORWARDED_HOST",
                    "HTTP_X_FORWARDED_PROTO",
                    "HTTP_X_REAL_IP",
                )
            )
        )

    @classmethod
    def _exact_probe(cls, environ: Mapping[str, object]) -> bool:
        raw = environ.get("RAW_URI")
        request_uri = environ.get("REQUEST_URI")
        path = environ.get("PATH_INFO")
        if not cls._common(environ) or raw != request_uri or raw != path:
            return False
        if environ.get("REQUEST_METHOD") == "GET" and path == "/deploymentz":
            challenge = environ.get("HTTP_X_QUANT_HUB_ENDPOINT_CHALLENGE")
            return (
                type(challenge) is str
                and _CHALLENGE_RE.fullmatch(challenge) is not None
                and environ.get("CONTENT_LENGTH") in {None, ""}
                and environ.get("CONTENT_TYPE") in {None, ""}
            )
        if (
            environ.get("REQUEST_METHOD") == "POST"
            and path == "/deployment-canaryz"
        ):
            return (
                environ.get("CONTENT_TYPE") == "application/json"
                and type(environ.get("CONTENT_LENGTH")) is str
            )
        return False

    def __call__(self, environ: object, start_response: object) -> object:
        if type(environ) is not dict or not callable(start_response):
            raise ExactRuntimeServerError(
                "transient WSGI environ/start_response is invalid"
            )
        if self._gate.state == "closed_pending_promotion" and self._exact_probe(
            environ
        ):
            return self._application(environ, start_response)
        raw = canonical_bytes(
            {
                "code": "starting_not_admitted",
                "schema_version": "qrh-exact-runtime-rejection/v1",
                "status": "rejected",
            }
        )
        start_response(
            "503 Service Unavailable",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(raw))),
                ("Cache-Control", "no-store"),
                ("Connection", "close"),
            ],
        )
        return [raw]


class _SteadyAdmissionWsgiGate:
    """位于 Flask/session/业务之前的 fixed closed-state WSGI gate。"""

    __slots__ = ("_application", "_gate")

    def __init__(
        self, application: object, gate: LockedExactRuntimeAdmissionGate
    ) -> None:
        if not callable(application) or type(gate) is not LockedExactRuntimeAdmissionGate:
            raise TypeError("steady outer gate requires exact application and gate")
        self._application = application
        self._gate = gate

    @staticmethod
    def _exact_probe(environ: Mapping[str, object]) -> bool:
        challenge = environ.get("HTTP_X_QUANT_HUB_ENDPOINT_CHALLENGE")
        return (
            environ.get("REQUEST_METHOD") == "GET"
            and environ.get("RAW_URI") == "/deploymentz"
            and environ.get("REQUEST_URI") == "/deploymentz"
            and environ.get("PATH_INFO") == "/deploymentz"
            and environ.get("QUERY_STRING") == ""
            and environ.get("HTTP_HOST") == _PROBE_HOST
            and environ.get("REMOTE_ADDR") == "127.0.0.1"
            and type(challenge) is str
            and _CHALLENGE_RE.fullmatch(challenge) is not None
            and environ.get("CONTENT_LENGTH") in {None, ""}
            and environ.get("CONTENT_TYPE") in {None, ""}
            and not any(
                key in environ
                for key in (
                    "HTTP_FORWARDED",
                    "HTTP_PROXY_CONNECTION",
                    "HTTP_VIA",
                    "HTTP_X_FORWARDED_FOR",
                    "HTTP_X_FORWARDED_HOST",
                    "HTTP_X_FORWARDED_PROTO",
                    "HTTP_X_REAL_IP",
                )
            )
        )

    def __call__(self, environ: object, start_response: object) -> object:
        if type(environ) is not dict or not callable(start_response):
            raise ExactRuntimeServerError("steady WSGI environ/start_response 无效")
        state = self._gate.state
        if state == "admitted" or self._exact_probe(environ):
            return self._application(environ, start_response)
        raw = canonical_bytes(
            {
                "code": "starting_not_admitted",
                "schema_version": "qrh-exact-runtime-rejection/v1",
                "status": "rejected",
            }
        )
        start_response(
            "503 Service Unavailable",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(raw))),
                ("Cache-Control", "no-store"),
                ("Connection", "close"),
            ],
        )
        return [raw]


def _build_application(
    lease: LockedWindowsWriterLease | LockedSteadyWindowsWriterLease,
    closure: _LockedExactRuntimeImportClosure,
    gate: (
        LockedExactRuntimeAdmissionGate
        | LockedTransientRuntimeAdmissionGate
        | None
    ) = None,
) -> tuple[object, _RuntimeStateCheckpoint, _RuntimeStateGuardSet]:
    steady = type(lease) is LockedSteadyWindowsWriterLease
    if (
        type(lease) not in {
            LockedWindowsWriterLease,
            LockedSteadyWindowsWriterLease,
        }
        or type(closure) is not _LockedExactRuntimeImportClosure
        or (steady and type(gate) is not LockedExactRuntimeAdmissionGate)
        or (
            not steady
            and gate is not None
            and type(gate) is not LockedTransientRuntimeAdmissionGate
        )
    ):
        raise TypeError("application build live capability 类型不匹配")
    record, root, _api = lease._canary_checkpoint()
    release = Path(closure.release_path)
    manifest = closure.manifest_document
    release_ref = record.get("release")
    if (
        type(release_ref) is not dict
        or release_ref.get("manifest_sha256") != closure.manifest_sha256
        or release_ref.get("release_path") != str(release)
    ):
        raise ExactRuntimeServerError("application release differs from writer lease")

    from quant_hub.app import create_app
    from quant_hub.config import Settings
    from quant_hub.web.access_gate import install_access_gate, load_password_digest

    runtime = release / "runtime"
    settings = Settings(
        project_root=release,
        archive_root=release / "reference" / "archive",
        var_root=runtime,
        database_path=runtime / "db" / "platform.sqlite3",
        object_root=runtime / "objects",
        migration_root=release / "runtime_contract" / "migrations" / "platform",
    )
    settings.validate()
    _fix_release_read_only_root(runtime)
    state = root / "state"
    session = state / "viewer_secret.key"
    digest = state / "viewer_access_password.digest"
    comment_database = _regular_file(state / "comments.sqlite3")
    workspace_database = _regular_file(state / "research_workspace.sqlite3")
    application = manifest.get("application")
    if type(application) is not dict:
        raise ExactRuntimeServerError("release application identity is absent")
    source_kind = application.get("source_kind")
    if source_kind not in {"git", "legacy_broadcast"}:
        raise ExactRuntimeServerError("release application source kind is invalid")
    state_checkpoint = _RuntimeStateCheckpoint(
        protected_paths=(session, digest),
        database_paths=(comment_database, workspace_database),
    )
    state_guards = _RuntimeStateGuardSet(
        protected_paths=(session, digest),
        database_paths=(comment_database, workspace_database),
    )
    try:
        state_checkpoint.checkpoint()
        config: dict[str, object] = {
            "SECRET_KEY": _secret(session),
            "TRUSTED_ORIGINS": _trusted_origins(),
            "SESSION_COOKIE_SECURE": False,
            "SESSION_COOKIE_HTTPONLY": True,
            "SESSION_COOKIE_SAMESITE": "Lax",
            "SESSION_COOKIE_NAME": "quant_hub_broadcast_session",
            "INITIALIZE_ARCHIVE_CATALOG": False,
            "COMMENT_DATABASE_PATH": comment_database,
            "RESEARCH_WORKSPACE_DATABASE_PATH": workspace_database,
        }
        if source_kind == "git":
            config["GENERIC_RESEARCH_RELEASE_ROOT"] = release
        app = create_app(settings, config)

        @app.before_request
        def exact_runtime_request_checkpoint() -> None:
            _checkpoint(lease, closure)
            _checkpoint_state(state_checkpoint)

        @app.after_request
        def exact_runtime_response_checkpoint(response: Response) -> Response:
            _checkpoint_state(state_checkpoint)
            _checkpoint(lease, closure)
            return response

        install_access_gate(app, load_password_digest(_regular_file(digest)))
        if steady:
            _register_steady_endpoint(app, lease, gate, closure)
        else:
            _register_exact_endpoints(
                app,
                lease,
                ExactRuntimeCanaryRunner.load_exact_d(),
                closure,
            )
        state_checkpoint.checkpoint()
        if lease._canary_checkpoint()[0] != record:
            raise ExactRuntimeServerError(
                "writer lease drifted while building application"
            )
        return app, state_checkpoint, state_guards
    except BaseException:
        state_guards.close()
        raise


def _serve_built_application(
    lease: LockedWindowsWriterLease | LockedSteadyWindowsWriterLease,
    closure: _LockedExactRuntimeImportClosure,
    application: object,
    state_checkpoint: _RuntimeStateCheckpoint,
    state_guards: _RuntimeStateGuardSet,
) -> int:
    from werkzeug.serving import make_server

    server = None
    try:
        closure.checkpoint()
        _checkpoint_state(state_checkpoint)
        server = make_server(
            _BIND_HOST,
            _PORT,
            application,
            threaded=False,
            processes=1,
            request_handler=_ExactRuntimeRequestHandler,
            passthrough_errors=True,
        )
        _checkpoint(lease, closure)
        _checkpoint_state(state_checkpoint)
        server.serve_forever()
        return 0
    finally:
        try:
            if server is not None:
                server.server_close()
        finally:
            state_guards.close()


def serve_exact_runtime(
    lease: LockedWindowsWriterLease,
    closure: _LockedExactRuntimeImportClosure,
) -> int:
    if (
        type(lease) is not LockedWindowsWriterLease
        or type(closure) is not _LockedExactRuntimeImportClosure
    ):
        raise TypeError("exact runtime server requires exact live capabilities")
    gate = ProductionTransientRuntimeAdmissionGate.load_from_service_stdin()
    app, state_checkpoint, state_guards = _build_application(
        lease, closure, gate
    )
    outer_application = _TransientAdmissionWsgiGate(app, gate)
    return _serve_built_application(
        lease,
        closure,
        outer_application,
        state_checkpoint,
        state_guards,
    )


def serve_steady_exact_runtime(
    lease: LockedSteadyWindowsWriterLease,
    gate: LockedExactRuntimeAdmissionGate,
    closure: _LockedExactRuntimeImportClosure,
) -> int:
    if (
        type(lease) is not LockedSteadyWindowsWriterLease
        or type(gate) is not LockedExactRuntimeAdmissionGate
        or type(closure) is not _LockedExactRuntimeImportClosure
    ):
        raise TypeError("steady runtime server requires exact live capabilities")
    app, state_checkpoint, state_guards = _build_application(
        lease, closure, gate
    )
    outer_application = _SteadyAdmissionWsgiGate(app, gate)
    return _serve_built_application(
        lease,
        closure,
        outer_application,
        state_checkpoint,
        state_guards,
    )


__all__ = [
    "ExactRuntimeServerError",
    "serve_exact_runtime",
    "serve_steady_exact_runtime",
]
