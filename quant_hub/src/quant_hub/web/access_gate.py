"""V39-compatible intranet access gate without release-embedded credentials."""

from __future__ import annotations

import base64
from collections import deque
import hashlib
from pathlib import Path
import secrets
from threading import Lock
import time
from urllib.parse import urlsplit

from flask import jsonify, redirect, render_template_string, request, session, url_for


ACCESS_SESSION_KEY = "quant_hub_broadcast_authenticated"
ACCESS_SESSION_MARKER_PREFIX = "pbkdf2-sha256-v1"
ACCESS_PASSWORD_SALT = bytes.fromhex("ae829f253a022e21e2b53ddd97c712b8")
ACCESS_PASSWORD_ITERATIONS = 600_000
AUTH_FAILURE_LIMIT = 8
AUTH_FAILURE_WINDOW_SECONDS = 300.0
_AUTH_FAILURES: dict[str, deque[float]] = {}
_AUTH_FAILURES_LOCK = Lock()
_EXACT_UNAUTHENTICATED_PATHS = frozenset(
    {"/deploymentz", "/deployment-canaryz"}
)

# This is the reviewed V39 login surface.  The application templates, CSS and
# JavaScript behind it are supplied by the active immutable release unchanged.
LOGIN_TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex,nofollow">
  <title>访问验证 · Quant Research Hub</title>
  <style>
    :root {
      color-scheme: light;
      --ink: #17211b;
      --muted: #65726a;
      --line: #d9e1dc;
      --surface: #ffffff;
      --canvas: #f3f6f4;
      --accent: #1d694b;
      --accent-hover: #15553c;
      --danger: #a33737;
    }
    * { box-sizing: border-box; }
    html, body { min-height: 100%; }
    body {
      margin: 0;
      display: grid;
      place-items: center;
      padding: 32px 20px;
      color: var(--ink);
      background:
        radial-gradient(circle at 15% 10%, rgba(29, 105, 75, .08), transparent 32rem),
        var(--canvas);
      font-family: "Microsoft YaHei UI", "PingFang SC", "Noto Sans CJK SC", sans-serif;
      line-height: 1.65;
    }
    main {
      width: min(100%, 430px);
      padding: 36px;
      border: 1px solid var(--line);
      border-radius: 16px;
      background: var(--surface);
      box-shadow: 0 18px 48px rgba(28, 46, 36, .10);
    }
    .eyebrow {
      margin: 0 0 8px;
      color: var(--accent);
      font-size: 12px;
      font-weight: 700;
      letter-spacing: .12em;
      text-transform: uppercase;
    }
    h1 { margin: 0; font-size: 25px; line-height: 1.35; letter-spacing: -.02em; }
    .intro { margin: 12px 0 26px; color: var(--muted); font-size: 14px; }
    label { display: block; margin-bottom: 8px; font-size: 14px; font-weight: 650; }
    input {
      width: 100%;
      min-height: 46px;
      padding: 10px 13px;
      border: 1px solid #bcc8c1;
      border-radius: 9px;
      color: var(--ink);
      background: #fff;
      font: inherit;
      outline: none;
    }
    input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px rgba(29, 105, 75, .14); }
    button {
      width: 100%;
      min-height: 46px;
      margin-top: 16px;
      border: 0;
      border-radius: 9px;
      color: #fff;
      background: var(--accent);
      font: inherit;
      font-weight: 700;
      cursor: pointer;
    }
    button:hover { background: var(--accent-hover); }
    .error {
      margin: 0 0 16px;
      padding: 10px 12px;
      border-left: 3px solid var(--danger);
      color: var(--danger);
      background: #fff4f4;
      font-size: 13px;
      overflow-wrap: anywhere;
    }
    .privacy { margin: 18px 0 0; color: var(--muted); font-size: 12px; text-align: center; }
    @media (max-width: 520px) { main { padding: 28px 22px; } }
  </style>
</head>
<body>
  <main aria-labelledby="login-title">
    <p class="eyebrow">Quant Research Hub</p>
    <h1 id="login-title">访问验证</h1>
    <p class="intro">请输入访问密码后进入量化研究知识中枢。</p>
    {% if error %}<p class="error" role="alert">{{ error }}</p>{% endif %}
    <form method="post" action="{{ url_for('broadcast_login') }}">
      <input type="hidden" name="next" value="{{ next_path }}">
      <label for="password">访问密码</label>
      <input id="password" name="password" type="password" required autofocus
             autocomplete="current-password" maxlength="256">
      <button type="submit">进入网站</button>
    </form>
    <p class="privacy">密码仅提交至当前内网服务，不会写入浏览器页面或访问日志。</p>
  </main>
</body>
</html>
"""
LOGIN_STYLE_SOURCE = LOGIN_TEMPLATE.split("<style>", 1)[1].split("</style>", 1)[0]
LOGIN_STYLE_HASH = "sha256-" + base64.b64encode(
    hashlib.sha256(LOGIN_STYLE_SOURCE.encode("utf-8")).digest()
).decode("ascii")


class AccessGateError(RuntimeError):
    pass


def _exact_raw_request_target(expected_path: str) -> bool:
    """Accept only one exact ASCII origin-form path with no hidden query."""

    if expected_path not in _EXACT_UNAUTHENTICATED_PATHS:
        return False
    environ = request.environ
    raw_uri = environ.get("RAW_URI")
    request_uri = environ.get("REQUEST_URI")
    path_info = environ.get("PATH_INFO")
    query_string = environ.get("QUERY_STRING")
    server_protocol = environ.get("SERVER_PROTOCOL")
    return (
        type(raw_uri) is str
        and type(request_uri) is str
        and type(path_info) is str
        and type(query_string) is str
        and type(server_protocol) is str
        and raw_uri == expected_path
        and request_uri == expected_path
        and path_info == expected_path
        and query_string == ""
        and server_protocol == "HTTP/1.1"
        and request.path == expected_path
        and request.query_string == b""
    )


def load_password_digest(path: Path) -> bytes:
    """Load a protected PBKDF2 digest; never fall back to a release constant."""

    try:
        value = path.read_text(encoding="ascii").strip()
    except OSError as error:
        raise AccessGateError("protected access password digest is unavailable") from error
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise AccessGateError("protected access password digest is invalid")
    return bytes.fromhex(value)


def derive_password_digest(password: str) -> bytes:
    if not password or len(password) > 256:
        raise AccessGateError("access password is out of bounds")
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), ACCESS_PASSWORD_SALT,
        ACCESS_PASSWORD_ITERATIONS,
    )


def _safe_return_path(value: str | None) -> str:
    candidate = (value or "/").strip()
    parts = urlsplit(candidate)
    if (
        len(candidate) > 2048
        or not candidate.startswith("/")
        or candidate.startswith("//")
        or parts.scheme
        or parts.netloc
    ):
        return "/"
    return candidate


def _failure_count(client: str, now: float) -> int:
    cutoff = now - AUTH_FAILURE_WINDOW_SECONDS
    with _AUTH_FAILURES_LOCK:
        failures = _AUTH_FAILURES.get(client)
        if failures is None:
            return 0
        while failures and failures[0] < cutoff:
            failures.popleft()
        if not failures:
            _AUTH_FAILURES.pop(client, None)
            return 0
        return len(failures)


def install_access_gate(app, expected_digest: bytes) -> None:
    if not isinstance(expected_digest, bytes) or len(expected_digest) != 32:
        raise AccessGateError("access password digest contract is invalid")
    marker = ACCESS_SESSION_MARKER_PREFIX + ":" + hashlib.sha256(
        expected_digest
    ).hexdigest()[:24]

    @app.before_request
    def require_broadcast_password():
        exact_probe = any(
            _exact_raw_request_target(path)
            for path in _EXACT_UNAUTHENTICATED_PATHS
        )
        if exact_probe or request.endpoint in {
            "broadcast_login", "broadcast_logout",
        }:
            return None
        if session.get(ACCESS_SESSION_KEY) == marker:
            return None
        if request.path.startswith("/api/"):
            return jsonify({"error": "authentication_required"}), 401
        return redirect(
            url_for(
                "broadcast_login",
                next=_safe_return_path(request.full_path.rstrip("?")),
            ),
            code=302,
        )

    @app.route("/login", methods=["GET", "POST"])
    def broadcast_login():
        if session.get(ACCESS_SESSION_KEY) == marker:
            return redirect(_safe_return_path(request.values.get("next")), code=303)
        next_path = _safe_return_path(request.values.get("next"))
        error = None
        status = 200
        if request.method == "POST":
            client = request.remote_addr or "unknown"
            now = time.monotonic()
            if _failure_count(client, now) >= AUTH_FAILURE_LIMIT:
                error, status = "尝试次数过多，请五分钟后重试。", 429
            else:
                candidate = request.form.get("password", "")
                valid = len(candidate) <= 256 and secrets.compare_digest(
                    derive_password_digest(candidate), expected_digest
                ) if candidate else False
                if valid:
                    with _AUTH_FAILURES_LOCK:
                        _AUTH_FAILURES.pop(client, None)
                    session.clear()
                    session[ACCESS_SESSION_KEY] = marker
                    return redirect(next_path, code=303)
                with _AUTH_FAILURES_LOCK:
                    _AUTH_FAILURES.setdefault(client, deque()).append(now)
                error, status = "访问密码不正确，请重新输入。", 401
        return render_template_string(
            LOGIN_TEMPLATE, error=error, next_path=next_path
        ), status

    @app.route("/logout", methods=["GET", "POST"])
    def broadcast_logout():
        session.clear()
        return redirect(url_for("broadcast_login"), code=303)

    @app.after_request
    def access_control_headers(response):
        if request.path in {"/login", "/logout"} or response.status_code == 401:
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        if request.path == "/login":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; "
                f"style-src 'self' '{LOGIN_STYLE_HASH}'; "
                "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
                "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
                "form-action 'self'"
            )
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        return response


__all__ = [
    "AccessGateError", "derive_password_digest", "install_access_gate",
    "load_password_digest",
]
