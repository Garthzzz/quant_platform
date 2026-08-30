"""e.4.2 fixed loopback canary transport 与现场观察基础合同。

本切片先闭合不可注入的单次 HTTP POST。产品类型固定 127.0.0.1:8765、原始
target、headers、canonical body、超时与响应上限；不接受 URL、port、backend、
proxy、header、body 或 timeout 接缝。后续 live observation 在此传输外再夹住
SCM/endpoint/writer 与两库复验。
"""

from __future__ import annotations

from dataclasses import dataclass
from email.utils import parsedate_to_datetime
import re
import socket

from .local_release_identity import canonical_bytes


_TRANSPORT_TOKEN = object()
_TEST_TRANSPORT_TOKEN = object()
_HOST = "127.0.0.1"
_PORT = 8765
_TARGET = "/deployment-canaryz"
_TIMEOUT_SECONDS = 10.0
_MAX_RESPONSE_BYTES = 64 * 1024 * 1024
_CHALLENGE_RE = re.compile(r"^[0-9a-f]{48}$")
_STATUS_RE = re.compile(rb"^HTTP/1\.1 ([0-9]{3}) ([\x20-\x7e]+)$")
_HEADER_NAME_RE = re.compile(rb"^[A-Za-z0-9-]+$")
_ALLOWED_RESPONSE_HEADERS = {
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "date",
    "server",
}


class ExactRuntimeCanaryTransportError(RuntimeError):
    """fixed canary POST 未形成唯一闭合响应。"""


class ExactRuntimeCanaryBusy(ExactRuntimeCanaryTransportError):
    """409 表示本次没有取得 observation，不是第三种成功。"""


@dataclass(frozen=True, slots=True)
class ExactRuntimeCanaryHttpResponse:
    status: int
    body: bytes


def _request_bytes(challenge_nonce: str, *, port: int) -> bytes:
    if type(challenge_nonce) is not str or _CHALLENGE_RE.fullmatch(
        challenge_nonce
    ) is None:
        raise ExactRuntimeCanaryTransportError("challenge nonce 必须是 fresh 192-bit hex")
    body = canonical_bytes({"challenge_nonce": challenge_nonce})
    host = f"{_HOST}:{port}"
    lines = (
        f"POST {_TARGET} HTTP/1.1",
        f"Host: {host}",
        "Accept: application/json",
        "Cache-Control: no-store",
        "Connection: close",
        "Content-Type: application/json",
        "Accept-Encoding: identity",
        f"Content-Length: {len(body)}",
    )
    return "\r\n".join(lines).encode("ascii") + b"\r\n\r\n" + body


def _parse_response(raw: bytes) -> ExactRuntimeCanaryHttpResponse:
    if type(raw) is not bytes or not raw or len(raw) > _MAX_RESPONSE_BYTES:
        raise ExactRuntimeCanaryTransportError("canary HTTP response 长度不闭合")
    if raw.count(b"\r\n\r\n") != 1:
        raise ExactRuntimeCanaryTransportError("canary HTTP header/body framing 不闭合")
    header_raw, body = raw.split(b"\r\n\r\n", 1)
    if b"\n" in header_raw.replace(b"\r\n", b""):
        raise ExactRuntimeCanaryTransportError("canary HTTP 使用了非 CRLF framing")
    lines = header_raw.split(b"\r\n")
    match = _STATUS_RE.fullmatch(lines[0]) if lines else None
    if match is None:
        raise ExactRuntimeCanaryTransportError("canary HTTP status line 不闭合")
    status = int(match.group(1))
    if status not in {200, 409}:
        raise ExactRuntimeCanaryTransportError("canary HTTP status 不是 200/409")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if line.startswith((b" ", b"\t")) or b":" not in line:
            raise ExactRuntimeCanaryTransportError("canary HTTP header 行不闭合")
        name_raw, value_raw = line.split(b":", 1)
        if _HEADER_NAME_RE.fullmatch(name_raw) is None:
            raise ExactRuntimeCanaryTransportError("canary HTTP header name 无效")
        try:
            name = name_raw.decode("ascii").casefold()
            value = value_raw.decode("ascii")
        except UnicodeDecodeError as error:
            raise ExactRuntimeCanaryTransportError(
                "canary HTTP header 不是 ASCII"
            ) from error
        if value != " " + value.strip() or name in headers:
            raise ExactRuntimeCanaryTransportError(
                "canary HTTP header whitespace/duplicate 漂移"
            )
        headers[name] = value.strip()
    if not set(headers).issubset(_ALLOWED_RESPONSE_HEADERS) or not {
        "cache-control",
        "connection",
        "content-length",
        "content-type",
    }.issubset(headers):
        raise ExactRuntimeCanaryTransportError("canary HTTP response header 集合不闭合")
    if (
        headers["cache-control"] != "no-store"
        or headers["connection"].casefold() != "close"
        or headers["content-type"] != "application/json"
        or headers["content-length"] != str(len(body))
    ):
        raise ExactRuntimeCanaryTransportError("canary HTTP response header 值漂移")
    if "server" in headers and (
        not headers["server"] or len(headers["server"]) > 256
    ):
        raise ExactRuntimeCanaryTransportError("canary HTTP Server header 无效")
    if "date" in headers:
        try:
            parsed = parsedate_to_datetime(headers["date"])
        except (TypeError, ValueError) as error:
            raise ExactRuntimeCanaryTransportError(
                "canary HTTP Date header 无效"
            ) from error
        if parsed.tzinfo is None:
            raise ExactRuntimeCanaryTransportError("canary HTTP Date 缺 timezone")
    if status == 409:
        raise ExactRuntimeCanaryBusy("canary_busy；本次未取得 observation")
    return ExactRuntimeCanaryHttpResponse(status=status, body=body)


def _post(challenge_nonce: str, *, port: int) -> ExactRuntimeCanaryHttpResponse:
    request = _request_bytes(challenge_nonce, port=port)
    blocks: list[bytes] = []
    total = 0
    try:
        with socket.create_connection(
            (_HOST, port), timeout=_TIMEOUT_SECONDS
        ) as connection:
            connection.settimeout(_TIMEOUT_SECONDS)
            connection.sendall(request)
            connection.shutdown(socket.SHUT_WR)
            while True:
                block = connection.recv(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > _MAX_RESPONSE_BYTES:
                    raise ExactRuntimeCanaryTransportError(
                        "canary HTTP response 超过固定上限"
                    )
                blocks.append(block)
    except ExactRuntimeCanaryTransportError:
        raise
    except (OSError, TimeoutError) as error:
        raise ExactRuntimeCanaryTransportError(
            "fixed loopback canary POST 失败"
        ) from error
    return _parse_response(b"".join(blocks))


class ProductionExactRuntimeCanaryTransport:
    """无参 exact-D transport；调用面只接受 fresh challenge nonce。"""

    __slots__ = ()

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production canary transport 不允许派生")

    def __init__(self, *, _construction_token: object):
        if _construction_token is not _TRANSPORT_TOKEN:
            raise TypeError("production canary transport 必须由 load_exact_d 构造")

    def __reduce__(self) -> object:
        raise TypeError("production canary transport is non-serializable")

    def __reduce_ex__(self, protocol: int) -> object:
        del protocol
        return self.__reduce__()

    @classmethod
    def load_exact_d(cls) -> "ProductionExactRuntimeCanaryTransport":
        return cls(_construction_token=_TRANSPORT_TOKEN)

    def post(self, challenge_nonce: str) -> ExactRuntimeCanaryHttpResponse:
        return _post(challenge_nonce, port=_PORT)


class _TestOnlyExactRuntimeCanaryTransportAdapter:
    __slots__ = ("_port", "_test_token")

    def __init__(self, port: int, *, _test_token: object):
        if (
            _test_token is not _TEST_TRANSPORT_TOKEN
            or type(port) is not int
            or port < 1
            or port > 65535
        ):
            raise TypeError("test-only canary transport port 无效")
        self._port = port
        self._test_token = _test_token

    @classmethod
    def for_test_only(
        cls, port: int
    ) -> "_TestOnlyExactRuntimeCanaryTransportAdapter":
        return cls(port, _test_token=_TEST_TRANSPORT_TOKEN)

    @property
    def scope(self) -> str:
        return "test_only_fixed_loopback_canary_transport"

    def post(self, challenge_nonce: str) -> ExactRuntimeCanaryHttpResponse:
        return _post(challenge_nonce, port=self._port)


__all__ = [
    "ExactRuntimeCanaryBusy",
    "ExactRuntimeCanaryHttpResponse",
    "ExactRuntimeCanaryTransportError",
    "ProductionExactRuntimeCanaryTransport",
]
