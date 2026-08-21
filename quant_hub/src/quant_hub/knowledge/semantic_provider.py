"""Production DeepSeek semantic provider with fail-closed secret handling.

The transport is intentionally small: one fixed HTTPS origin, no redirect
following, no tool calls and no provider credential in any persisted contract.
The semantic compiler remains responsible for source policy, partition
identity, evidence validation and atomic document aggregation.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import http.client
import json
import os
import ssl
from typing import Any, Callable, Protocol

from .contracts import canonical_json
from .semantic import ProviderResponse, REQUESTED_MODEL_ALIAS, SemanticRequestEnvelope


DEEPSEEK_API_HOST = "api.deepseek.com"
DEEPSEEK_API_PATH = "/chat/completions"


class SemanticProviderError(ConnectionError):
    """A retryable or contract-breaking provider transport failure."""


class SecretUnavailable(SemanticProviderError):
    """The protected credential source is absent or unavailable."""


class SecretProvider(Protocol):
    def get_secret(self) -> str: ...


@dataclass(frozen=True, slots=True)
class EnvironmentSecretProvider:
    """Read a credential only when a request is about to be sent."""

    variable: str = "DEEPSEEK_API_KEY"

    def get_secret(self) -> str:
        value = os.environ.get(self.variable)
        if value is None or not value.strip():
            raise SecretUnavailable("DeepSeek credential is unavailable")
        return value.strip()


@dataclass(frozen=True, slots=True)
class KeyringSecretProvider:
    """Optional OS-keyring adapter; missing support fails closed."""

    service: str
    username: str

    def get_secret(self) -> str:
        try:
            import keyring  # type: ignore[import-not-found]
        except ImportError:
            raise SecretUnavailable("protected keyring support is unavailable") from None
        try:
            value = keyring.get_password(self.service, self.username)
        except Exception:
            raise SecretUnavailable("protected keyring lookup failed") from None
        if value is None or not value.strip():
            raise SecretUnavailable("DeepSeek credential is unavailable")
        return value.strip()


class _HTTPSResponse(Protocol):
    status: int

    def read(self, amount: int | None = None) -> bytes: ...


class _HTTPSConnection(Protocol):
    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None: ...

    def getresponse(self) -> _HTTPSResponse: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[[str, float, ssl.SSLContext], _HTTPSConnection]


def _default_connection_factory(
    host: str, timeout: float, context: ssl.SSLContext
) -> _HTTPSConnection:
    return http.client.HTTPSConnection(host, timeout=timeout, context=context)


class DeepSeekV4ProProvider:
    """Fixed-origin JSON-only adapter for the approved model alias.

    ``connection_factory`` exists for deterministic offline transport tests;
    production callers should not override it.  The secret provider object is
    retained, but the secret value is fetched per call and never stored on this
    instance or included in exceptions/repr.
    """

    __slots__ = (
        "_secret_provider",
        "_timeout_seconds",
        "_max_response_bytes",
        "_connection_factory",
        "_ssl_context",
    )

    def __init__(
        self,
        secret_provider: SecretProvider,
        *,
        timeout_seconds: float = 45.0,
        max_response_bytes: int = 4 * 1024 * 1024,
        connection_factory: ConnectionFactory = _default_connection_factory,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("provider timeout must be positive")
        if max_response_bytes < 1024:
            raise ValueError("provider response cap is too small")
        self._secret_provider = secret_provider
        self._timeout_seconds = float(timeout_seconds)
        self._max_response_bytes = int(max_response_bytes)
        self._connection_factory = connection_factory
        self._ssl_context = ssl_context or ssl.create_default_context()

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(host={DEEPSEEK_API_HOST!r}, "
            f"timeout_seconds={self._timeout_seconds!r}, "
            f"max_response_bytes={self._max_response_bytes!r}, credential=<protected>)"
        )

    @staticmethod
    def _request_payload(envelope: SemanticRequestEnvelope) -> bytes:
        if envelope.requested_model_alias != REQUESTED_MODEL_ALIAS:
            raise ValueError("semantic envelope requests an unapproved model alias")
        if (
            envelope.tools
            or envelope.network_access
            or envelope.filesystem_access
            or envelope.credential_access
        ):
            raise ValueError("semantic envelope requests forbidden capabilities")
        # The source is serialized under an explicit untrusted-data key in a
        # user message.  It is never interpolated into the system instruction,
        # which prevents research prose from becoming a higher-priority prompt.
        user_payload = {
            "contract": {
                "schema_version": envelope.schema_version,
                "prompt_version": envelope.prompt_version,
                "output_schema_version": envelope.output_schema_version,
                "partition_manifest_hash": envelope.partition_manifest_hash,
                "part_index": envelope.part_index,
                "part_count": envelope.part_count,
                "allowed_span_ids": list(envelope.allowed_span_ids),
                "output_schema": envelope.output_schema,
            },
            "untrusted_source_data": envelope.source_data,
        }
        payload = {
            "model": envelope.requested_model_alias,
            "messages": [
                {"role": "system", "content": envelope.system_instruction},
                {"role": "user", "content": canonical_json(user_payload)},
            ],
            "response_format": {"type": "json_object"},
            "stream": False,
        }
        # Deliberately omit max_tokens and tools.  The partitioner's input cap
        # and the HTTP response body cap are the safety boundaries.
        return canonical_json(payload).encode("utf-8")

    def generate(self, envelope: SemanticRequestEnvelope) -> ProviderResponse:
        body = self._request_payload(envelope)
        try:
            secret = self._secret_provider.get_secret()
        except Exception:
            raise SecretUnavailable("protected credential lookup failed") from None
        connection: _HTTPSConnection | None = None
        try:
            connection = self._connection_factory(
                DEEPSEEK_API_HOST, self._timeout_seconds, self._ssl_context
            )
            connection.request(
                "POST",
                DEEPSEEK_API_PATH,
                body=body,
                headers={
                    "Authorization": "Bearer " + secret,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "quant-research-hub-semantic/1",
                },
            )
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise SemanticProviderError("DeepSeek redirect response is forbidden")
            if response.status < 200 or response.status >= 300:
                raise SemanticProviderError(
                    f"DeepSeek request failed with HTTP status {response.status}"
                )
            raw = response.read(self._max_response_bytes + 1)
            if len(raw) > self._max_response_bytes:
                raise SemanticProviderError("DeepSeek response exceeded the configured body cap")
        except SemanticProviderError:
            raise
        except (TimeoutError, OSError, http.client.HTTPException):
            raise SemanticProviderError("DeepSeek transport failed") from None
        finally:
            # Drop the only local value reference before any response parsing.
            secret = ""
            if connection is not None:
                connection.close()

        try:
            decoded = json.loads(raw.decode("utf-8"))
            if type(decoded) is not dict:
                raise ValueError
            response_id = decoded["id"]
            created = decoded["created"]
            model = decoded["model"]
            fingerprint = decoded["system_fingerprint"]
            choices = decoded["choices"]
            if (
                type(response_id) is not str
                or not response_id
                or type(created) is not int
                or type(model) is not str
                or not model
                or type(fingerprint) is not str
                or not fingerprint
                or type(choices) is not list
                or len(choices) != 1
                or type(choices[0]) is not dict
                or type(choices[0].get("message")) is not dict
                or type(choices[0]["message"].get("content")) is not str
            ):
                raise ValueError
            output = json.loads(choices[0]["message"]["content"])
            if type(output) is not dict:
                raise ValueError
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError):
            # Never include the raw provider body: it can contain source text,
            # reflected instructions, or upstream diagnostic details.
            raise SemanticProviderError("DeepSeek response structure is invalid") from None
        try:
            created_at = datetime.fromtimestamp(created, tz=UTC).isoformat().replace(
                "+00:00", "Z"
            )
        except (OverflowError, OSError, ValueError):
            raise SemanticProviderError("DeepSeek response timestamp is invalid") from None
        return ProviderResponse(
            response_id=response_id,
            created_at=created_at,
            model=model,
            system_fingerprint=fingerprint,
            output=output,
        )


__all__ = [
    "DEEPSEEK_API_HOST",
    "DEEPSEEK_API_PATH",
    "DeepSeekV4ProProvider",
    "EnvironmentSecretProvider",
    "KeyringSecretProvider",
    "SecretProvider",
    "SecretUnavailable",
    "SemanticProviderError",
]
