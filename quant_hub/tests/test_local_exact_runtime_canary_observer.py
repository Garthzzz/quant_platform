from __future__ import annotations

import inspect
import pickle
import socketserver
import threading
import unittest

from quant_hub.ops import local_exact_runtime_canary_observer as observer_module
from quant_hub.ops.local_exact_runtime_canary_observer import (
    ExactRuntimeCanaryBusy,
    ExactRuntimeCanaryTransportError,
    ProductionExactRuntimeCanaryTransport,
)
from quant_hub.ops.local_release_identity import canonical_bytes


class _OneRequestHandler(socketserver.BaseRequestHandler):
    response = b""
    captured: list[bytes] = []

    def handle(self) -> None:
        received = bytearray()
        while b"\r\n\r\n" not in received:
            block = self.request.recv(4096)
            if not block:
                break
            received.extend(block)
        header, separator, body = bytes(received).partition(b"\r\n\r\n")
        content_length = 0
        if separator:
            for line in header.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    content_length = int(line.split(b":", 1)[1].strip())
            while len(body) < content_length:
                block = self.request.recv(content_length - len(body))
                if not block:
                    break
                body += block
        type(self).captured.append(header + separator + body)
        self.request.sendall(type(self).response)


def _response(body: bytes, *, status: int = 200, extra: bytes = b"") -> bytes:
    reason = b"OK" if status == 200 else b"CONFLICT"
    return (
        b"HTTP/1.1 "
        + str(status).encode("ascii")
        + b" "
        + reason
        + b"\r\n"
        + b"Content-Type: application/json\r\n"
        + b"Content-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n"
        + b"Cache-Control: no-store\r\n"
        + b"Connection: close\r\n"
        + extra
        + b"\r\n"
        + body
    )


class ExactRuntimeCanaryTransportTests(unittest.TestCase):
    challenge = "ab" * 24

    def call(self, response: bytes):
        _OneRequestHandler.response = response
        _OneRequestHandler.captured = []
        with socketserver.TCPServer(("127.0.0.1", 0), _OneRequestHandler) as server:
            thread = threading.Thread(target=server.handle_request)
            thread.start()
            try:
                port = int(server.server_address[1])
                adapter = (
                    observer_module._TestOnlyExactRuntimeCanaryTransportAdapter.for_test_only(
                        port
                    )
                )
                result = adapter.post(self.challenge)
            finally:
                thread.join(timeout=5)
        return result, _OneRequestHandler.captured

    def test_fixed_request_and_canonical_200_response(self) -> None:
        body = canonical_bytes({"result": "closed"})
        result, captured = self.call(
            _response(
                body,
                extra=b"Date: Fri, 28 Aug 2026 00:00:00 GMT\r\nServer: fixture\r\n",
            )
        )
        self.assertEqual(200, result.status)
        self.assertEqual(body, result.body)
        self.assertEqual(1, len(captured))
        expected_body = canonical_bytes({"challenge_nonce": self.challenge})
        self.assertEqual(
            (
                b"POST /deployment-canaryz HTTP/1.1\r\n"
                + b"Host: 127.0.0.1:"
            ),
            captured[0][
                : len(b"POST /deployment-canaryz HTTP/1.1\r\nHost: 127.0.0.1:")
            ],
        )
        self.assertIn(b"Accept: application/json\r\n", captured[0])
        self.assertIn(b"Accept-Encoding: identity\r\n", captured[0])
        self.assertIn(b"Cache-Control: no-store\r\n", captured[0])
        self.assertIn(b"Connection: close\r\n", captured[0])
        self.assertTrue(captured[0].endswith(expected_body))

    def test_busy_is_explicit_failure_not_success(self) -> None:
        body = canonical_bytes({"code": "canary_busy"})
        with self.assertRaises(ExactRuntimeCanaryBusy):
            self.call(_response(body, status=409))

    def test_response_header_and_framing_matrix_fails_closed(self) -> None:
        body = canonical_bytes({"result": "closed"})
        valid = _response(body)
        cases = {
            "unknown": valid.replace(
                b"\r\n\r\n", b"\r\nX-Injected: yes\r\n\r\n", 1
            ),
            "charset": valid.replace(
                b"Content-Type: application/json",
                b"Content-Type: application/json; charset=utf-8",
            ),
            "keepalive": valid.replace(
                b"Connection: close", b"Connection: keep-alive"
            ),
            "length": valid.replace(
                b"Content-Length: " + str(len(body)).encode("ascii"),
                b"Content-Length: 1",
            ),
            "duplicate": valid.replace(
                b"Cache-Control: no-store\r\n",
                b"Cache-Control: no-store\r\nCache-Control: no-store\r\n",
            ),
            "chunked": valid.replace(
                b"\r\n\r\n", b"\r\nTransfer-Encoding: chunked\r\n\r\n", 1
            ),
            "extra_body": valid + b"third",
            "http10": valid.replace(b"HTTP/1.1", b"HTTP/1.0", 1),
        }
        for label, response in cases.items():
            with self.subTest(label=label), self.assertRaises(
                ExactRuntimeCanaryTransportError
            ):
                self.call(response)

    def test_product_surface_has_no_url_port_headers_timeout_or_backend(self) -> None:
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    ProductionExactRuntimeCanaryTransport.load_exact_d
                ).parameters
            ),
        )
        self.assertEqual(
            ["self", "challenge_nonce"],
            list(
                inspect.signature(
                    ProductionExactRuntimeCanaryTransport.post
                ).parameters
            ),
        )
        self.assertNotIn(
            "_TestOnlyExactRuntimeCanaryTransportAdapter",
            observer_module.__all__,
        )
        product = ProductionExactRuntimeCanaryTransport.load_exact_d()
        with self.assertRaises(TypeError):
            pickle.dumps(product)
        for injected in (
            {"url": "http://example.invalid"},
            {"port": 1},
            {"headers": {}},
            {"timeout": 0},
            {"backend": object()},
        ):
            with self.subTest(injected=tuple(injected)), self.assertRaises(TypeError):
                product.post(self.challenge, **injected)  # type: ignore[call-arg]


if __name__ == "__main__":
    unittest.main()
