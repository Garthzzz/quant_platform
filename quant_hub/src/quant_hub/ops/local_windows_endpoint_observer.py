"""固定 production IPv4 listener 与 loopback HTTP 身份的现场观察器。

产品入口不接受地址、端口、路径、API、HTTP client 或 hook。Windows IP Helper
listener 表与 challenge-bound ``/deploymentz`` 响应必须由同一 live SCM/process
能力前后夹住。结果仍是 observation-only，不形成 writer lease 或部署资格。
"""

from __future__ import annotations

from dataclasses import dataclass
import ctypes
from ctypes import wintypes
import hashlib
import http.client
import json
import os
import secrets
import socket
from typing import Callable, Mapping

from .local_release_identity import canonical_bytes, identity_sha256
from .local_windows_endpoint_evidence import (
    EXACT_RUNTIME_ENDPOINT_SCHEMA,
    WINDOWS_ENDPOINT_OBSERVATION_SCHEMA,
    WINDOWS_ENDPOINT_OBSERVATION_SCOPE,
    WindowsEndpointEvidenceError,
    WindowsEndpointObservationEvidence,
)
from .local_windows_scm_process_evidence import (
    WindowsScmProcessObservationEvidence,
)
from .local_windows_scm_process_observer import (
    LockedSteadyWindowsScmProcessObservation,
    LockedWindowsScmProcessObservation,
)
from .local_steady_windows_scm_process_evidence import (
    SteadyWindowsScmProcessObservationEvidence,
)
from .local_steady_windows_endpoint_evidence import (
    STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCHEMA,
    STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCOPE,
    SteadyWindowsEndpointObservationEvidence,
    _expected as _steady_expected,
    _steady_claim,
    _upstream as _steady_upstream,
)


LIVE_WINDOWS_ENDPOINT_OBSERVATION_SCOPE = (
    "live_windows_endpoint_observation_not_qualified"
)
LIVE_STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCOPE = (
    "live_steady_windows_endpoint_observation_not_qualified"
)

_PRODUCTION_HOST = "127.0.0.1"
_PRODUCTION_BIND_ADDRESS = "0.0.0.0"
_PRODUCTION_PORT = 8765
_DEPLOYMENT_PATH = "/deploymentz"
_MAX_ENDPOINT_BODY_BYTES = 64 * 1024
_MAX_TCP_TABLE_BYTES = 16 * 1024 * 1024
_AF_INET = 2
_TCP_TABLE_OWNER_PID_LISTENER = 3
_MIB_TCP_STATE_LISTEN = 2
_NO_ERROR = 0
_ERROR_INSUFFICIENT_BUFFER = 122

_API_TOKEN = object()
_OBSERVER_TOKEN = object()
_LIVE_TOKEN = object()
_TEST_ONLY_TOKEN = object()


class WindowsEndpointObserverError(RuntimeError):
    """Windows listener/HTTP endpoint 身份无法机械闭合。"""


class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = (
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
        ("dwOwningPid", wintypes.DWORD),
    )


class _MIB_TCPTABLE_OWNER_PID_ONE(ctypes.Structure):
    _fields_ = (
        ("dwNumEntries", wintypes.DWORD),
        ("table", _MIB_TCPROW_OWNER_PID * 1),
    )


@dataclass(frozen=True, slots=True)
class _Ipv4Listener:
    local_address: str
    local_port: int
    state: int
    owning_pid: int


@dataclass(frozen=True, slots=True)
class _HttpProbe:
    status_code: int
    content_type: str
    body: bytes
    response: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class _CollectedEndpointObservation:
    scm_evidence: WindowsScmProcessObservationEvidence
    listener_before: _Ipv4Listener
    probe: _HttpProbe
    listener_after: _Ipv4Listener


@dataclass(frozen=True, slots=True)
class _CollectedSteadyEndpointObservation:
    scm_evidence: SteadyWindowsScmProcessObservationEvidence
    listener_before: _Ipv4Listener
    probe: _HttpProbe
    listener_after: _Ipv4Listener


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
        raise WindowsEndpointObserverError(
            f"Windows endpoint API binding 缺失或签名不可固定: {name}"
        ) from error
    return function


def _strict_json_object(raw: bytes) -> dict[str, object]:
    def closed_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        value: dict[str, object] = {}
        for key, item in pairs:
            if key in value:
                raise WindowsEndpointObserverError("endpoint JSON 含重复字段")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=closed_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                WindowsEndpointObserverError(f"endpoint JSON 非有限常量: {token}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise WindowsEndpointObserverError("endpoint body 不是严格 UTF-8 JSON") from error
    if type(value) is not dict:
        raise WindowsEndpointObserverError("endpoint body 必须是 JSON object")
    try:
        expected = canonical_bytes(value)
    except Exception as error:
        raise WindowsEndpointObserverError("endpoint body 不能 canonicalize") from error
    if raw != expected:
        raise WindowsEndpointObserverError("endpoint body 不是逐字节 canonical JSON")
    return value


def _parse_ipv4_listener_table(raw: bytes) -> tuple[_Ipv4Listener, ...]:
    """按当前 ctypes Windows ABI 解析一个完整 MIB_TCPTABLE_OWNER_PID。"""

    if type(raw) is not bytes:
        raise WindowsEndpointObserverError("IPv4 TCP listener table 必须是 bytes")
    offset = int(_MIB_TCPTABLE_OWNER_PID_ONE.table.offset)
    row_size = ctypes.sizeof(_MIB_TCPROW_OWNER_PID)
    if len(raw) < offset:
        raise WindowsEndpointObserverError("IPv4 TCP listener table header 截断")
    count = int(wintypes.DWORD.from_buffer_copy(raw).value)
    if count > (len(raw) - offset) // row_size:
        raise WindowsEndpointObserverError("IPv4 TCP listener table row count 越界")
    rows: list[_Ipv4Listener] = []
    for index in range(count):
        row = _MIB_TCPROW_OWNER_PID.from_buffer_copy(raw, offset + index * row_size)
        raw_port = int(row.dwLocalPort)
        if raw_port >> 16:
            raise WindowsEndpointObserverError("IPv4 TCP listener port 高位非零")
        port = int(socket.ntohs(raw_port))
        address = (
            _PRODUCTION_BIND_ADDRESS
            if int(row.dwLocalAddr) == 0
            else socket.inet_ntoa(int(row.dwLocalAddr).to_bytes(4, "little"))
        )
        pid = int(row.dwOwningPid)
        if pid < 1 or port < 1:
            raise WindowsEndpointObserverError("IPv4 TCP listener PID/port 无效")
        rows.append(_Ipv4Listener(address, port, int(row.dwState), pid))
    return tuple(rows)


class _ProductionWindowsEndpointApi:
    """固定 System32 Iphlpapi 与 stdlib direct-loopback HTTP client。"""

    __slots__ = ("_binding_token", "_sealed", "get_extended_tcp_table")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production Windows endpoint API table 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production Windows endpoint API table 构造后不可替换")
        object.__setattr__(self, name, value)

    def _assert_exact_binding(self) -> None:
        if (
            type(self) is not _ProductionWindowsEndpointApi
            or getattr(self, "_binding_token", None) is not _API_TOKEN
            or getattr(self, "_sealed", None) is not True
        ):
            raise WindowsEndpointObserverError(
                "production Windows endpoint API table 来源未闭合"
            )

    @classmethod
    def load_exact_d(cls) -> "_ProductionWindowsEndpointApi":
        if os.name != "nt":
            raise WindowsEndpointObserverError(
                "production Windows endpoint observer 只允许 Windows"
            )
        try:
            iphlpapi = ctypes.WinDLL(
                "iphlpapi.dll",
                use_last_error=True,
                winmode=0x00000800,  # LOAD_LIBRARY_SEARCH_SYSTEM32
            )
        except OSError as error:
            raise WindowsEndpointObserverError(
                "无法从 System32 加载 Iphlpapi.dll"
            ) from error
        self = object.__new__(cls)
        object.__setattr__(self, "_sealed", False)
        self.get_extended_tcp_table = _bind(
            iphlpapi,
            "GetExtendedTcpTable",
            (
                ctypes.c_void_p,
                wintypes.LPDWORD,
                wintypes.BOOL,
                wintypes.ULONG,
                ctypes.c_int,
                wintypes.ULONG,
            ),
            wintypes.DWORD,
        )
        object.__setattr__(self, "_binding_token", _API_TOKEN)
        object.__setattr__(self, "_sealed", True)
        self._assert_exact_binding()
        return self

    def query_ipv4_listeners(self) -> tuple[_Ipv4Listener, ...]:
        self._assert_exact_binding()
        size = wintypes.DWORD(0)
        first = int(
            self.get_extended_tcp_table(
                None,
                ctypes.byref(size),
                False,
                _AF_INET,
                _TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        )
        if first != _ERROR_INSUFFICIENT_BUFFER:
            raise WindowsEndpointObserverError(
                "GetExtendedTcpTable(size) 未返回固定 insufficient-buffer 状态"
            )
        byte_count = int(size.value)
        if byte_count < ctypes.sizeof(wintypes.DWORD) or byte_count > _MAX_TCP_TABLE_BYTES:
            raise WindowsEndpointObserverError("IPv4 TCP listener table size 越界")
        buffer = ctypes.create_string_buffer(byte_count)
        second = int(
            self.get_extended_tcp_table(
                buffer,
                ctypes.byref(size),
                False,
                _AF_INET,
                _TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        )
        if second != _NO_ERROR or int(size.value) > byte_count:
            raise WindowsEndpointObserverError("GetExtendedTcpTable(listener) 失败或发生竞态扩容")
        return _parse_ipv4_listener_table(bytes(buffer.raw[: int(size.value)]))

    def probe_endpoint(self, challenge: str) -> _HttpProbe:
        self._assert_exact_binding()
        connection = http.client.HTTPConnection(
            _PRODUCTION_HOST,
            _PRODUCTION_PORT,
            timeout=5.0,
        )
        try:
            connection.request(
                "GET",
                _DEPLOYMENT_PATH,
                headers={
                    "Accept": "application/json",
                    "Cache-Control": "no-store",
                    "Connection": "close",
                    "Host": f"{_PRODUCTION_HOST}:{_PRODUCTION_PORT}",
                    "X-Quant-Hub-Endpoint-Challenge": challenge,
                },
            )
            response = connection.getresponse()
            status = int(response.status)
            content_type = response.getheader("Content-Type")
            content_length_raw = response.getheader("Content-Length")
            if response.getheader("Content-Encoding") is not None:
                raise WindowsEndpointObserverError("endpoint response 不得压缩")
            if response.getheader("Transfer-Encoding") is not None:
                raise WindowsEndpointObserverError("endpoint response 不得使用 transfer encoding")
            body = response.read(_MAX_ENDPOINT_BODY_BYTES + 1)
        except (OSError, http.client.HTTPException) as error:
            raise WindowsEndpointObserverError("loopback endpoint probe 失败") from error
        finally:
            connection.close()
        if len(body) > _MAX_ENDPOINT_BODY_BYTES:
            raise WindowsEndpointObserverError("endpoint response 超过固定上限")
        if content_type != "application/json":
            raise WindowsEndpointObserverError("endpoint Content-Type 必须精确为 application/json")
        if (
            content_length_raw is None
            or not content_length_raw.isascii()
            or not content_length_raw.isdecimal()
            or int(content_length_raw) != len(body)
        ):
            raise WindowsEndpointObserverError("endpoint Content-Length 不闭合")
        value = _strict_json_object(body)
        return _HttpProbe(status, content_type, body, value)


def _scm_material(
    evidence: WindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not WindowsScmProcessObservationEvidence:
        raise WindowsEndpointObserverError("SCM evidence provider 返回非 exact typed evidence")
    try:
        document = evidence.as_dict()
        service = document["service"]
        host = document["host"]
        child = document["child"]
        if not all(type(value) is dict for value in (service, host, child)):
            raise TypeError
        status = service["status"]  # type: ignore[index]
        if type(status) is not dict:
            raise TypeError
        material = {
            "evidence_sha256": document["evidence_sha256"],
            "child_pid": child["pid"],  # type: ignore[index]
        }
    except (KeyError, TypeError) as error:
        raise WindowsEndpointObserverError("SCM evidence identity 结构无效") from error
    if type(material["evidence_sha256"]) is not str or type(material["child_pid"]) is not int:
        raise WindowsEndpointObserverError("SCM evidence hash/child PID 类型无效")
    return document


def _production_listener(
    rows: object,
    *,
    child_pid: int,
) -> _Ipv4Listener:
    if type(rows) is not tuple or any(type(row) is not _Ipv4Listener for row in rows):
        raise WindowsEndpointObserverError("IPv4 listener API 返回类型不闭合")
    matches = tuple(row for row in rows if row.local_port == _PRODUCTION_PORT)
    if len(matches) != 1:
        raise WindowsEndpointObserverError("production port 必须恰有一个 IPv4 listener")
    listener = matches[0]
    if (
        type(listener.local_address) is not str
        or type(listener.local_port) is not int
        or type(listener.state) is not int
        or type(listener.owning_pid) is not int
        or listener.local_address != _PRODUCTION_BIND_ADDRESS
        or listener.state != _MIB_TCP_STATE_LISTEN
        or listener.owning_pid != child_pid
    ):
        raise WindowsEndpointObserverError(
            "production listener 未绑定 live SCM child PID/wildcard address"
        )
    return listener


def _assert_probe_claim_bound(
    response: Mapping[str, object],
    scm: Mapping[str, object],
    *,
    challenge: str,
) -> None:
    """在 shared runner 内拒绝 endpoint 自报的核心身份漂移。"""

    try:
        service = scm["service"]
        host = scm["host"]
        child = scm["child"]
        if not all(type(value) is dict for value in (service, host, child)):
            raise TypeError
        expected = {
            "attempt_id": scm["attempt_id"],
            "nonce": scm["nonce"],
            "operation": scm["operation"],
            "role": scm["role"],
            "start_nonce": scm["start_nonce"],
            "authorization_sha256": scm["authorization_sha256"],
            "scm_identity_sha256": scm["scm_identity_sha256"],
            "state_identity_sha256": scm["state_identity_sha256"],
            "release": scm["release"],
            "service": {
                "service_name": service["service_name"],  # type: ignore[index]
                "host_pid": host["pid"],  # type: ignore[index]
                "host_creation_time_100ns": host["creation_time_100ns"],  # type: ignore[index]
            },
            "child": {
                "child_pid": child["pid"],  # type: ignore[index]
                "child_creation_time_100ns": child["creation_time_100ns"],  # type: ignore[index]
            },
            "listener": {
                "local_address": _PRODUCTION_BIND_ADDRESS,
                "local_port": _PRODUCTION_PORT,
            },
        }
    except (KeyError, TypeError) as error:
        raise WindowsEndpointObserverError("SCM evidence identity 结构无效") from error
    response_service = response.get("service")
    response_child = response.get("child")
    response_listener = response.get("listener")
    response_lease = response.get("writer_lease")
    if not all(
        type(value) is dict
        for value in (
            response_service,
            response_child,
            response_listener,
            response_lease,
        )
    ):
        raise WindowsEndpointObserverError("endpoint response identity 结构无效")
    numeric_fields = (
        (response_service, "host_pid"),
        (response_service, "host_creation_time_100ns"),
        (response_child, "child_pid"),
        (response_child, "child_creation_time_100ns"),
        (response_listener, "local_port"),
        (response_lease, "lease_epoch"),
    )
    if any(
        type(container.get(field)) is not int or int(container[field]) < 1
        for container, field in numeric_fields
    ):
        raise WindowsEndpointObserverError(
            "endpoint response numeric identity 必须是 exact positive integer"
        )
    if (
        response.get("schema_version") != EXACT_RUNTIME_ENDPOINT_SCHEMA
        or response.get("status") != "identity_claim_only"
        or response.get("probe_challenge") != challenge
    ):
        raise WindowsEndpointObserverError("endpoint response schema/status/challenge 不闭合")
    for field, value in expected.items():
        if response.get(field) != value:
            raise WindowsEndpointObserverError(
                f"endpoint response.{field} 未绑定 live SCM observation"
            )
    if response_lease.get("authority") != "claim_not_independently_observed":
        raise WindowsEndpointObserverError("endpoint response 不得自授 writer lease authority")


class _WindowsEndpointObservationRunner:
    """production/test-only 共用的只读算法；自身不授予 evidence 权威。"""

    __slots__ = ("_api",)

    def __init__(self, *, api: object):
        self._api = api

    def observe(
        self,
        evidence_provider: Callable[[], WindowsScmProcessObservationEvidence],
        *,
        challenge: str,
    ) -> _CollectedEndpointObservation:
        if (
            type(challenge) is not str
            or len(challenge) != 48
            or any(character not in "0123456789abcdef" for character in challenge)
        ):
            raise WindowsEndpointObserverError("endpoint challenge 不是 192-bit lowercase hex")
        query = getattr(self._api, "query_ipv4_listeners", None)
        probe = getattr(self._api, "probe_endpoint", None)
        if not callable(query) or not callable(probe):
            raise WindowsEndpointObserverError("endpoint observer API table 不闭合")
        before_scm = evidence_provider()
        before_document = _scm_material(before_scm)
        child_pid = int(before_document["child"]["pid"])  # type: ignore[index]
        listener_before = _production_listener(query(), child_pid=child_pid)
        observed_probe = probe(challenge)
        if type(observed_probe) is not _HttpProbe:
            raise WindowsEndpointObserverError("endpoint probe API 返回类型不闭合")
        if (
            type(observed_probe.status_code) is not int
            or observed_probe.status_code != 200
            or observed_probe.content_type != "application/json"
            or type(observed_probe.body) is not bytes
            or not 0 < len(observed_probe.body) <= _MAX_ENDPOINT_BODY_BYTES
            or type(observed_probe.response) is not dict
        ):
            raise WindowsEndpointObserverError("endpoint probe response envelope 不闭合")
        parsed = _strict_json_object(observed_probe.body)
        if (
            parsed != observed_probe.response
            or parsed.get("probe_challenge") != challenge
        ):
            raise WindowsEndpointObserverError(
                "endpoint probe response 未绑定本次 challenge"
            )
        _assert_probe_claim_bound(parsed, before_document, challenge=challenge)
        listener_after = _production_listener(query(), child_pid=child_pid)
        after_scm = evidence_provider()
        after_document = _scm_material(after_scm)
        if (
            listener_after != listener_before
            or after_scm.canonical_bytes() != before_scm.canonical_bytes()
            or after_document["evidence_sha256"] != before_document["evidence_sha256"]
        ):
            raise WindowsEndpointObserverError(
                "HTTP probe 前后 SCM/process/listener identity 漂移"
            )
        return _CollectedEndpointObservation(
            before_scm,
            listener_before,
            observed_probe,
            listener_after,
        )


def _steady_scm_material(
    evidence: SteadyWindowsScmProcessObservationEvidence,
) -> dict[str, object]:
    if type(evidence) is not SteadyWindowsScmProcessObservationEvidence:
        raise WindowsEndpointObserverError(
            "steady SCM evidence provider 返回非 exact typed evidence"
        )
    try:
        document = _steady_upstream(evidence)
        expected = _steady_expected(document)
    except WindowsEndpointEvidenceError as error:
        raise WindowsEndpointObserverError(
            "steady SCM evidence identity 结构无效"
        ) from error
    if (
        type(document.get("evidence_sha256")) is not str
        or type(expected.get("child_pid")) is not int
    ):
        raise WindowsEndpointObserverError(
            "steady SCM evidence hash/child PID 类型无效"
        )
    return document


class _WindowsSteadyEndpointObservationRunner:
    """Steady v2 claim 的前后 SCM/listener 夹逼算法。"""

    __slots__ = ("_api",)

    def __init__(self, *, api: object):
        self._api = api

    def observe(
        self,
        evidence_provider: Callable[
            [], SteadyWindowsScmProcessObservationEvidence
        ],
        *,
        challenge: str,
    ) -> _CollectedSteadyEndpointObservation:
        if (
            type(challenge) is not str
            or len(challenge) != 48
            or any(
                character not in "0123456789abcdef"
                for character in challenge
            )
        ):
            raise WindowsEndpointObserverError(
                "steady endpoint challenge 不是 192-bit lowercase hex"
            )
        query = getattr(self._api, "query_ipv4_listeners", None)
        probe = getattr(self._api, "probe_endpoint", None)
        if not callable(query) or not callable(probe):
            raise WindowsEndpointObserverError(
                "steady endpoint observer API table 不闭合"
            )
        before_scm = evidence_provider()
        before_document = _steady_scm_material(before_scm)
        child = before_document.get("child")
        if type(child) is not dict or type(child.get("pid")) is not int:
            raise WindowsEndpointObserverError("steady SCM child PID 结构无效")
        child_pid = int(child["pid"])
        listener_before = _production_listener(query(), child_pid=child_pid)
        observed_probe = probe(challenge)
        if (
            type(observed_probe) is not _HttpProbe
            or type(observed_probe.status_code) is not int
            or observed_probe.status_code != 200
            or observed_probe.content_type != "application/json"
            or type(observed_probe.body) is not bytes
            or not 0 < len(observed_probe.body) <= _MAX_ENDPOINT_BODY_BYTES
            or type(observed_probe.response) is not dict
        ):
            raise WindowsEndpointObserverError(
                "steady endpoint probe response envelope 不闭合"
            )
        parsed = _strict_json_object(observed_probe.body)
        if (
            parsed != observed_probe.response
            or parsed.get("probe_challenge") != challenge
        ):
            raise WindowsEndpointObserverError(
                "steady endpoint response 未绑定本次 challenge"
            )
        try:
            _steady_claim(
                parsed,
                challenge=challenge,
                expected=_steady_expected(before_document),
            )
        except WindowsEndpointEvidenceError as error:
            raise WindowsEndpointObserverError(
                "steady endpoint self claim 未绑定 SCM observation"
            ) from error
        listener_after = _production_listener(query(), child_pid=child_pid)
        after_scm = evidence_provider()
        after_document = _steady_scm_material(after_scm)
        if (
            listener_after != listener_before
            or after_scm.canonical_bytes() != before_scm.canonical_bytes()
            or after_document.get("evidence_sha256")
            != before_document.get("evidence_sha256")
        ):
            raise WindowsEndpointObserverError(
                "steady HTTP probe 前后 SCM/process/listener identity 漂移"
            )
        return _CollectedSteadyEndpointObservation(
            before_scm,
            listener_before,
            observed_probe,
            listener_after,
        )


def _listener_document(listener: _Ipv4Listener) -> dict[str, object]:
    document: dict[str, object] = {
        "address_family": "AF_INET",
        "local_address": listener.local_address,
        "local_port": listener.local_port,
        "state": "LISTEN" if listener.state == _MIB_TCP_STATE_LISTEN else str(listener.state),
        "owning_pid": listener.owning_pid,
    }
    document["listener_identity_sha256"] = identity_sha256(document)
    return document


def _build_evidence_document(
    collected: _CollectedEndpointObservation,
    *,
    challenge: str,
    _authority_token: object,
) -> dict[str, object]:
    if _authority_token is not _API_TOKEN:
        raise WindowsEndpointObserverError("production endpoint evidence authority 不匹配")
    scm = collected.scm_evidence.as_dict()
    before = _listener_document(collected.listener_before)
    after = _listener_document(collected.listener_after)
    probe: dict[str, object] = {
        "scheme": "http",
        "host": _PRODUCTION_HOST,
        "port": _PRODUCTION_PORT,
        "path": _DEPLOYMENT_PATH,
        "method": "GET",
        "challenge": challenge,
        "status_code": collected.probe.status_code,
        "content_type": collected.probe.content_type,
        "content_length": len(collected.probe.body),
        "body_sha256": hashlib.sha256(collected.probe.body).hexdigest(),
        "response": dict(collected.probe.response),
    }
    probe["probe_identity_sha256"] = identity_sha256(probe)
    document: dict[str, object] = {
        "schema_version": WINDOWS_ENDPOINT_OBSERVATION_SCHEMA,
        "evidence_scope": WINDOWS_ENDPOINT_OBSERVATION_SCOPE,
        "scm_process_evidence_sha256": scm["evidence_sha256"],
        "attempt_id": scm["attempt_id"],
        "nonce": scm["nonce"],
        "operation": scm["operation"],
        "role": scm["role"],
        "start_nonce": scm["start_nonce"],
        "state_identity_sha256": scm["state_identity_sha256"],
        "release": dict(scm["release"]),  # type: ignore[arg-type]
        "listener_before": before,
        "probe": probe,
        "listener_after": after,
        "observation_aggregate_sha256": identity_sha256(
            [
                {"name": "scm_process", "sha256": scm["evidence_sha256"]},
                {"name": "listener_before", "sha256": before["listener_identity_sha256"]},
                {"name": "probe", "sha256": probe["probe_identity_sha256"]},
                {"name": "listener_after", "sha256": after["listener_identity_sha256"]},
            ]
        ),
        "result": "endpoint_observed_not_writer_qualified",
    }
    document["evidence_sha256"] = identity_sha256(document)
    return document


def _build_steady_evidence_document(
    collected: _CollectedSteadyEndpointObservation,
    *,
    challenge: str,
    _authority_token: object,
) -> dict[str, object]:
    if _authority_token is not _API_TOKEN:
        raise WindowsEndpointObserverError(
            "production steady endpoint evidence authority 不匹配"
        )
    scm = collected.scm_evidence.as_dict()
    before = _listener_document(collected.listener_before)
    after = _listener_document(collected.listener_after)
    probe: dict[str, object] = {
        "scheme": "http",
        "host": _PRODUCTION_HOST,
        "port": _PRODUCTION_PORT,
        "path": _DEPLOYMENT_PATH,
        "method": "GET",
        "challenge": challenge,
        "status_code": collected.probe.status_code,
        "content_type": collected.probe.content_type,
        "content_length": len(collected.probe.body),
        "body_sha256": hashlib.sha256(collected.probe.body).hexdigest(),
        "response": dict(collected.probe.response),
    }
    probe["probe_identity_sha256"] = identity_sha256(probe)
    document: dict[str, object] = {
        "schema_version": STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCHEMA,
        "evidence_scope": STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCOPE,
        "scm_process_evidence_sha256": scm["evidence_sha256"],
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
        "release": dict(scm["release"]),  # type: ignore[arg-type]
        "listener_before": before,
        "probe": probe,
        "listener_after": after,
        "observation_aggregate_sha256": identity_sha256(
            [
                {"name": "scm_process", "sha256": scm["evidence_sha256"]},
                {
                    "name": "listener_before",
                    "sha256": before["listener_identity_sha256"],
                },
                {"name": "probe", "sha256": probe["probe_identity_sha256"]},
                {
                    "name": "listener_after",
                    "sha256": after["listener_identity_sha256"],
                },
            ]
        ),
        "result": "steady_endpoint_observed_not_writer_qualified",
    }
    document["evidence_sha256"] = identity_sha256(document)
    return document


class LockedWindowsEndpointObservation:
    """由 exact production API 与 live SCM capability 支撑的不可派生现场能力。"""

    __slots__ = ("_api", "_scm_observation", "_closed", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("live Windows endpoint observation 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("live Windows endpoint observation 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        api: object,
        scm_observation: LockedWindowsScmProcessObservation,
        _construction_token: object,
    ):
        if _construction_token is not _LIVE_TOKEN:
            raise TypeError("live endpoint observation 必须由 production observer 构造")
        if type(api) is not _ProductionWindowsEndpointApi:
            raise TypeError("live endpoint observation 拒绝非产品 API table")
        if type(scm_observation) is not LockedWindowsScmProcessObservation:
            raise TypeError("live endpoint observation 拒绝非产品 SCM capability")
        api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._api = api
        self._scm_observation = scm_observation
        self._closed = False
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("live Windows endpoint observation is process-local and non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _collect(self) -> _CollectedEndpointObservation:
        if self._closed:
            raise WindowsEndpointObserverError("live endpoint observation 已撤销")
        if type(self._api) is not _ProductionWindowsEndpointApi:
            raise WindowsEndpointObserverError("live endpoint API table 类型漂移")
        if type(self._scm_observation) is not LockedWindowsScmProcessObservation:
            raise WindowsEndpointObserverError("live endpoint SCM capability 类型漂移")
        self._api._assert_exact_binding()
        return _WindowsEndpointObservationRunner(api=self._api).observe(
            self._scm_observation.build_evidence,
            challenge=secrets.token_hex(24),
        )

    @property
    def scope(self) -> str:
        self._collect()
        return LIVE_WINDOWS_ENDPOINT_OBSERVATION_SCOPE

    def build_evidence(self) -> WindowsEndpointObservationEvidence:
        if self._closed:
            raise WindowsEndpointObserverError("live endpoint observation 已撤销")
        if type(self._api) is not _ProductionWindowsEndpointApi:
            raise WindowsEndpointObserverError("live endpoint API table 类型漂移")
        if type(self._scm_observation) is not LockedWindowsScmProcessObservation:
            raise WindowsEndpointObserverError("live endpoint SCM capability 类型漂移")
        self._api._assert_exact_binding()
        challenge = secrets.token_hex(24)
        collected = _WindowsEndpointObservationRunner(api=self._api).observe(
            self._scm_observation.build_evidence,
            challenge=challenge,
        )
        document = _build_evidence_document(
            collected,
            challenge=challenge,
            _authority_token=_API_TOKEN,
        )
        try:
            return WindowsEndpointObservationEvidence.from_document(
                document,
                collected.scm_evidence,
            )
        except WindowsEndpointEvidenceError as error:
            raise WindowsEndpointObserverError(
                "live endpoint evidence finalization 失败"
            ) from error

    def close(self) -> None:
        object.__setattr__(self, "_closed", True)

    def __enter__(self) -> "LockedWindowsEndpointObservation":
        self._collect()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class LockedSteadyWindowsEndpointObservation:
    """Steady SCM live capability 支撑的 v2 endpoint observation owner。"""

    __slots__ = (
        "_api",
        "_scm_observation",
        "_workspace",
        "_closed",
        "_sealed",
    )

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("steady live Windows endpoint observation 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("steady live endpoint observation 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        api: object,
        scm_observation: LockedSteadyWindowsScmProcessObservation,
        _construction_token: object,
    ):
        if (
            _construction_token is not _LIVE_TOKEN
            or type(api) is not _ProductionWindowsEndpointApi
            or type(scm_observation)
            is not LockedSteadyWindowsScmProcessObservation
        ):
            raise TypeError(
                "steady live endpoint observation 必须由 exact production observer 构造"
            )
        api._assert_exact_binding()
        workspace = scm_observation._tracking._workspace  # noqa: SLF001
        object.__setattr__(self, "_sealed", False)
        self._api = api
        self._scm_observation = scm_observation
        self._workspace = workspace
        self._closed = False
        workspace._register_steady_windows_endpoint_observation(self)  # noqa: SLF001
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError(
            "steady live Windows endpoint observation is process-local and non-serializable"
        )

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    def _collect(self) -> _CollectedSteadyEndpointObservation:
        return self._collect_for_challenge(secrets.token_hex(24))

    def _collect_for_challenge(
        self, challenge: str
    ) -> _CollectedSteadyEndpointObservation:
        if self._closed:
            raise WindowsEndpointObserverError(
                "steady live endpoint observation 已撤销"
            )
        if (
            type(self._api) is not _ProductionWindowsEndpointApi
            or type(self._scm_observation)
            is not LockedSteadyWindowsScmProcessObservation
            or self._scm_observation._tracking._workspace  # noqa: SLF001
            is not self._workspace
        ):
            raise WindowsEndpointObserverError(
                "steady live endpoint provenance 漂移"
            )
        self._api._assert_exact_binding()
        return _WindowsSteadyEndpointObservationRunner(api=self._api).observe(
            self._scm_observation.build_evidence,
            challenge=challenge,
        )

    @property
    def scope(self) -> str:
        self._collect()
        return LIVE_STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCOPE

    def build_evidence(self) -> SteadyWindowsEndpointObservationEvidence:
        challenge = secrets.token_hex(24)
        collected = self._collect_for_challenge(challenge)
        document = _build_steady_evidence_document(
            collected,
            challenge=challenge,
            _authority_token=_API_TOKEN,
        )
        try:
            return SteadyWindowsEndpointObservationEvidence.from_document(
                document, collected.scm_evidence
            )
        except WindowsEndpointEvidenceError as error:
            raise WindowsEndpointObserverError(
                "steady live endpoint evidence finalization 失败"
            ) from error

    def _close_from_workspace(self, workspace: object) -> None:
        if workspace is not self._workspace:
            raise WindowsEndpointObserverError(
                "steady endpoint close workspace 漂移"
            )
        if self._closed:
            return
        object.__setattr__(self, "_closed", True)
        workspace._release_steady_windows_endpoint_observation(self)  # type: ignore[attr-defined]

    def close(self) -> None:
        if self._closed:
            return
        self._workspace._close_steady_windows_endpoint_observation_public(  # noqa: SLF001
            self
        )

    def __enter__(self) -> "LockedSteadyWindowsEndpointObservation":
        self._collect()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()


class ProductionWindowsEndpointObserver:
    """无参数加载且不可注入的 exact production endpoint observer。"""

    __slots__ = ("_api", "_sealed")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production Windows endpoint observer 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production Windows endpoint observer 构造后不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, api: object, _construction_token: object):
        if _construction_token is not _OBSERVER_TOKEN:
            raise TypeError("production endpoint observer 必须由 load_exact_d() 构造")
        if type(api) is not _ProductionWindowsEndpointApi:
            raise TypeError("production endpoint observer 拒绝非产品 API table")
        api._assert_exact_binding()
        object.__setattr__(self, "_sealed", False)
        self._api = api
        object.__setattr__(self, "_sealed", True)

    def __reduce__(self) -> object:
        raise TypeError("production Windows endpoint observer is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionWindowsEndpointObserver":
        api = _ProductionWindowsEndpointApi.load_exact_d()
        if type(api) is not _ProductionWindowsEndpointApi:
            raise TypeError("production endpoint loader 拒绝 fake API table")
        api._assert_exact_binding()
        return cls(api=api, _construction_token=_OBSERVER_TOKEN)

    def observe(
        self,
        scm_observation: LockedWindowsScmProcessObservation,
    ) -> LockedWindowsEndpointObservation:
        if type(self._api) is not _ProductionWindowsEndpointApi:
            raise WindowsEndpointObserverError("production endpoint API table 类型漂移")
        if type(scm_observation) is not LockedWindowsScmProcessObservation:
            raise WindowsEndpointObserverError(
                "production endpoint observer 只接受 exact live SCM capability"
            )
        self._api._assert_exact_binding()
        challenge = secrets.token_hex(24)
        collected = _WindowsEndpointObservationRunner(api=self._api).observe(
            scm_observation.build_evidence,
            challenge=challenge,
        )
        document = _build_evidence_document(
            collected,
            challenge=challenge,
            _authority_token=_API_TOKEN,
        )
        WindowsEndpointObservationEvidence.from_document(
            document,
            collected.scm_evidence,
        )
        return LockedWindowsEndpointObservation(
            api=self._api,
            scm_observation=scm_observation,
            _construction_token=_LIVE_TOKEN,
        )

    def observe_steady(
        self,
        scm_observation: LockedSteadyWindowsScmProcessObservation,
    ) -> LockedSteadyWindowsEndpointObservation:
        if type(self._api) is not _ProductionWindowsEndpointApi:
            raise WindowsEndpointObserverError(
                "production steady endpoint API table 类型漂移"
            )
        if (
            type(scm_observation)
            is not LockedSteadyWindowsScmProcessObservation
        ):
            raise WindowsEndpointObserverError(
                "production steady endpoint 只接受 exact steady live SCM capability"
            )
        self._api._assert_exact_binding()
        capability = LockedSteadyWindowsEndpointObservation(
            api=self._api,
            scm_observation=scm_observation,
            _construction_token=_LIVE_TOKEN,
        )
        challenge = secrets.token_hex(24)
        try:
            collected = capability._collect_for_challenge(challenge)  # noqa: SLF001
            document = _build_steady_evidence_document(
                collected,
                challenge=challenge,
                _authority_token=_API_TOKEN,
            )
            SteadyWindowsEndpointObservationEvidence.from_document(
                document, collected.scm_evidence
            )
            return capability
        except BaseException:
            capability.close()
            raise


_TEST_ONLY_SCOPE = "test_only_windows_endpoint_observation_not_evidence"


class _TestOnlyWindowsEndpointObservation:
    __slots__ = ("_api", "_scm_evidence", "_challenge")

    def __init__(
        self,
        *,
        api: object,
        scm_evidence: WindowsScmProcessObservationEvidence,
        challenge: str,
        _construction_token: object,
    ):
        if _construction_token is not _TEST_ONLY_TOKEN:
            raise TypeError("test-only endpoint observation authority 不匹配")
        self._api = api
        self._scm_evidence = scm_evidence
        self._challenge = challenge

    def __reduce__(self) -> object:
        raise TypeError("test-only endpoint observation is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def scope(self) -> str:
        self.validate_live_for_test_only()
        return _TEST_ONLY_SCOPE

    def validate_live_for_test_only(self) -> None:
        _WindowsEndpointObservationRunner(api=self._api).observe(
            lambda: self._scm_evidence,
            challenge=self._challenge,
        )


class _TestOnlySteadyWindowsEndpointObservation:
    __slots__ = ("_api", "_scm_evidence", "_challenge")

    def __init__(
        self,
        *,
        api: object,
        scm_evidence: SteadyWindowsScmProcessObservationEvidence,
        challenge: str,
        _construction_token: object,
    ):
        if (
            _construction_token is not _TEST_ONLY_TOKEN
            or type(scm_evidence)
            is not SteadyWindowsScmProcessObservationEvidence
        ):
            raise TypeError("test-only steady endpoint authority 不匹配")
        self._api = api
        self._scm_evidence = scm_evidence
        self._challenge = challenge

    def __reduce__(self) -> object:
        raise TypeError("test-only steady endpoint is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @property
    def scope(self) -> str:
        self.validate_live_for_test_only()
        return "test_only_steady_windows_endpoint_observation_not_evidence"

    def validate_live_for_test_only(self) -> None:
        _WindowsSteadyEndpointObservationRunner(api=self._api).observe(
            lambda: self._scm_evidence,
            challenge=self._challenge,
        )


class _TestOnlyWindowsEndpointObserverAdapter:
    __slots__ = ("_api",)

    def __init__(self, *, api: object, _construction_token: object):
        if _construction_token is not _TEST_ONLY_TOKEN:
            raise TypeError("test-only endpoint adapter authority 不匹配")
        if type(api) is _ProductionWindowsEndpointApi:
            raise TypeError("test-only endpoint adapter 不接受 production API table")
        self._api = api

    @classmethod
    def for_test_only(cls, *, api: object) -> "_TestOnlyWindowsEndpointObserverAdapter":
        return cls(api=api, _construction_token=_TEST_ONLY_TOKEN)

    def observe_test_only(
        self,
        scm_evidence: WindowsScmProcessObservationEvidence,
        *,
        challenge: str,
    ) -> _TestOnlyWindowsEndpointObservation:
        _WindowsEndpointObservationRunner(api=self._api).observe(
            lambda: scm_evidence,
            challenge=challenge,
        )
        return _TestOnlyWindowsEndpointObservation(
            api=self._api,
            scm_evidence=scm_evidence,
            challenge=challenge,
            _construction_token=_TEST_ONLY_TOKEN,
        )

    def observe_steady_test_only(
        self,
        scm_evidence: SteadyWindowsScmProcessObservationEvidence,
        *,
        challenge: str,
    ) -> _TestOnlySteadyWindowsEndpointObservation:
        _WindowsSteadyEndpointObservationRunner(api=self._api).observe(
            lambda: scm_evidence,
            challenge=challenge,
        )
        return _TestOnlySteadyWindowsEndpointObservation(
            api=self._api,
            scm_evidence=scm_evidence,
            challenge=challenge,
            _construction_token=_TEST_ONLY_TOKEN,
        )


__all__ = [
    "LIVE_STEADY_WINDOWS_ENDPOINT_OBSERVATION_SCOPE",
    "LIVE_WINDOWS_ENDPOINT_OBSERVATION_SCOPE",
    "LockedSteadyWindowsEndpointObservation",
    "LockedWindowsEndpointObservation",
    "ProductionWindowsEndpointObserver",
    "WindowsEndpointObserverError",
]
