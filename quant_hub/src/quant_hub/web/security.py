from __future__ import annotations

from collections.abc import Iterable
import hmac
import ipaddress
import re
import secrets

from flask import Request, session


IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$", re.ASCII)
CSRF_TOKEN = re.compile(r"^[A-Za-z0-9_-]{43}$", re.ASCII)
_SERIALIZED_ORIGIN = re.compile(
    r"(?P<scheme>https?)://"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)"
    r"(?::(?P<port>0|[1-9][0-9]{0,4}))?",
    re.ASCII | re.IGNORECASE,
)
_DNS_LABEL = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
    re.ASCII,
)
OriginTuple = tuple[str, str, int]


class WriteSecurityError(ValueError):
    def __init__(self, code: str, message: str, status: int):
        super().__init__(message)
        self.code = code
        self.status = status


def csrf_token() -> str:
    value = session.get("csrf_token")
    if not isinstance(value, str) or CSRF_TOKEN.fullmatch(value) is None:
        value = secrets.token_urlsafe(32)
        session["csrf_token"] = value
    return value


def _normalized_host(raw: str) -> str | None:
    if raw.startswith("["):
        if not raw.endswith("]"):
            return None
        try:
            return ipaddress.IPv6Address(raw[1:-1]).compressed
        except ipaddress.AddressValueError:
            return None
    host = raw.lower()
    if len(host) > 253 or host.startswith(".") or host.endswith("."):
        return None
    try:
        return str(ipaddress.IPv4Address(host))
    except ipaddress.AddressValueError:
        pass
    labels = host.split(".")
    final = labels[-1] if labels else ""
    browser_numeric = final.isdigit() or (
        final.lower().startswith("0x")
        and len(final) > 2
        and all(character in "0123456789abcdef" for character in final.lower()[2:])
    )
    if (
        not labels
        or browser_numeric
        or any(not _DNS_LABEL.fullmatch(label) or label.lower().startswith("xn--") for label in labels)
    ):
        return None
    return host


def normalized_origin(value: object) -> OriginTuple | None:
    if not isinstance(value, str) or not value or len(value) > 300:
        return None
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        return None
    match = _SERIALIZED_ORIGIN.fullmatch(value)
    if match is None:
        return None
    scheme = match.group("scheme").lower()
    host = _normalized_host(match.group("host"))
    if host is None:
        return None
    raw_port = match.group("port")
    port = int(raw_port) if raw_port is not None else (443 if scheme == "https" else 80)
    return None if port > 65_535 else (scheme, host, port)


def compile_trusted_origins(values: object) -> frozenset[OriginTuple]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise ValueError("TRUSTED_ORIGINS must be a non-empty iterable")
    compiled: set[OriginTuple] = set()
    for value in values:
        normalized = normalized_origin(value)
        if normalized is None:
            raise ValueError(f"invalid trusted origin: {value!r}")
        compiled.add(normalized)
    if not compiled:
        raise ValueError("TRUSTED_ORIGINS must not be empty")
    return frozenset(compiled)


def require_write_security(
    request: Request,
    trusted_origins: frozenset[OriginTuple],
) -> str:
    origins = request.headers.getlist("Origin")
    actual = normalized_origin(origins[0]) if len(origins) == 1 else None
    if actual is None or actual not in trusted_origins:
        raise WriteSecurityError("origin_rejected", "写请求必须来自同源页面。", 403)
    supplied = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf_token", "")
    if (
        not isinstance(expected, str)
        or CSRF_TOKEN.fullmatch(expected) is None
        or CSRF_TOKEN.fullmatch(supplied) is None
        or not hmac.compare_digest(supplied, expected)
    ):
        raise WriteSecurityError("csrf_rejected", "CSRF token 缺失或无效。", 403)
    key = request.headers.get("Idempotency-Key", "")
    if not IDEMPOTENCY_KEY.fullmatch(key):
        raise WriteSecurityError(
            "invalid_idempotency_key",
            "所有写 command 必须提供 8–128 位安全 Idempotency-Key。",
            428 if not key else 400,
        )
    return key
