from __future__ import annotations

import ast
from dataclasses import fields
import http.client
import inspect
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from flask import Flask

from quant_hub.ops import local_exact_runtime_server as subject
from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256
from quant_hub.ops.local_windows_writer_lease_holder import (
    ExactRuntimeLeaseIdentity,
    WindowsWriterLeaseBusy,
    _TestOnlyWindowsWriterLeaseHolderAdapter,
)
from quant_hub.web.access_gate import derive_password_digest, install_access_gate
from tests.helpers import install_public_archive_presentation


def _record() -> dict[str, object]:
    return {
        "attempt_id": "attempt-1",
        "nonce": "deployment-nonce-1",
        "operation": "activation",
        "role": "candidate",
        "start_nonce": "start-nonce-1",
        "authorization_sha256": "a" * 64,
        "scm_identity_sha256": "b" * 64,
        "state_identity_sha256": "c" * 64,
        "release": {
            "release_id": "release-r1",
            "release_path": r"D:\quant\quant_platform\releases\release-r1",
            "manifest_sha256": "d" * 64,
        },
        "holder": {
            "service_name": "QuantResearchHub",
            "host_pid": 4100,
            "host_creation_time_100ns": 100_000,
            "child_pid": 4200,
            "child_creation_time_100ns": 100_100,
        },
    }


class _FakeLease:
    def __init__(self) -> None:
        self.record = _record()
        self.checkpoints = 0

    def _canary_checkpoint(self):  # type: ignore[no-untyped-def]
        self.checkpoints += 1
        return self.record.copy(), Path(r"D:\quant\quant_platform"), object()

    @property
    def lease_claim(self) -> dict[str, object]:
        return {
            "lease_id": "lease-attempt-1",
            "lease_nonce": "lease-nonce-1",
            "lease_epoch": 1,
            "lease_record_sha256": "e" * 64,
            "authority": "claim_not_independently_observed",
        }


class _Evidence:
    def __init__(self, challenge: str):
        self.raw = canonical_bytes(
            {
                "schema_version": "qrh-test-canary/v1",
                "challenge_nonce": challenge,
            }
        )

    def canonical_bytes(self) -> bytes:
        return self.raw


class _FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[object, str]] = []

    def run(self, lease: object, challenge: str) -> _Evidence:
        self.calls.append((lease, challenge))
        return _Evidence(challenge)


class ExactRuntimeServerTests(unittest.TestCase):
    challenge = "1" * 48

    def setUp(self) -> None:
        install_public_archive_presentation(self)
        self.app = Flask(__name__)
        self.app.testing = True
        self.lease = _FakeLease()
        self.runner = _FakeRunner()
        self._register(self.app, self.lease, self.runner)
        self.client = self.app.test_client()

    @staticmethod
    def _register(app: Flask, lease: _FakeLease, runner: object) -> None:
        with patch.multiple(
            subject,
            LockedWindowsWriterLease=_FakeLease,
            ExactRuntimeCanaryRunner=type(runner),
            _LockedExactRuntimeImportClosure=type(None),
        ):
            subject._register_exact_endpoints(app, lease, runner, None)  # type: ignore[arg-type]

    @staticmethod
    def _headers() -> dict[str, str]:
        return {
            "Host": "127.0.0.1:8765",
            "Accept": "application/json",
            "Cache-Control": "no-store",
            "Connection": "close",
        }

    def test_deployment_endpoint_returns_exact_canonical_identity(self) -> None:
        headers = self._headers()
        headers["X-Quant-Hub-Endpoint-Challenge"] = self.challenge
        response = self.client.get(
            "/deploymentz",
            headers=headers,
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual("application/json", response.headers["Content-Type"])
        self.assertEqual(str(len(response.data)), response.headers["Content-Length"])
        self.assertIsNone(response.headers.get("Content-Encoding"))
        self.assertIsNone(response.headers.get("Transfer-Encoding"))
        document = response.get_json()
        self.assertEqual(self.challenge, document["probe_challenge"])
        self.assertEqual("0.0.0.0", document["listener"]["local_address"])
        self.assertEqual(8765, document["listener"]["local_port"])
        claimed = document.pop("endpoint_claim_sha256")
        self.assertEqual(identity_sha256(document), claimed)
        document["endpoint_claim_sha256"] = claimed
        self.assertEqual(canonical_bytes(document), response.data)
        self.assertGreaterEqual(self.lease.checkpoints, 2)

    def test_access_gate_preserves_both_exact_unauthenticated_probes(self) -> None:
        app = Flask("exact-access-gate")
        app.secret_key = "test-only-secret"
        install_access_gate(app, derive_password_digest("test-only-password"))
        lease = _FakeLease()
        runner = _FakeRunner()
        self._register(app, lease, runner)
        client = app.test_client()
        headers = self._headers()
        headers["X-Quant-Hub-Endpoint-Challenge"] = self.challenge
        deployment = client.get(
            "/deploymentz",
            headers=headers,
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        canary = client.post(
            "/deployment-canaryz",
            data=canonical_bytes({"challenge_nonce": self.challenge}),
            headers={**self._headers(), "Content-Type": "application/json"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        self.assertEqual(200, deployment.status_code)
        self.assertEqual(200, canary.status_code)
        self.assertIsNone(deployment.headers.get("Location"))
        self.assertIsNone(canary.headers.get("Location"))
        for alias in ("/deployment%7a", "/%64eploymentz"):
            with self.subTest(alias=alias):
                rejected = client.get(
                    alias,
                    headers=headers,
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
                self.assertEqual(302, rejected.status_code)
                self.assertIn("/login", rejected.headers["Location"])
        before_calls = len(runner.calls)
        for alias in ("/deployment-canary%7a", "/deployment-%63anaryz"):
            with self.subTest(alias=alias):
                rejected = client.post(
                    alias,
                    data=canonical_bytes({"challenge_nonce": self.challenge}),
                    headers={**self._headers(), "Content-Type": "application/json"},
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
                self.assertEqual(302, rejected.status_code)
                self.assertIn("/login", rejected.headers["Location"])
        self.assertEqual(before_calls, len(runner.calls))
        missing_raw = client.get(
            "/deploymentz",
            headers=headers,
            environ_overrides={
                "REMOTE_ADDR": "127.0.0.1",
                "RAW_URI": None,
                "REQUEST_URI": None,
            },
        )
        self.assertEqual(302, missing_raw.status_code)
        self.assertIn("/login", missing_raw.headers["Location"])

    def test_canonical_request_line_parser_is_bounded_and_exact(self) -> None:
        accepted = {
            b"GET /deploymentz HTTP/1.1\r\n": (b"GET", b"/deploymentz"),
            b"POST /deployment-canaryz HTTP/1.1\r\n": (
                b"POST",
                b"/deployment-canaryz",
            ),
            b"GET //deploymentz HTTP/1.1\r\n": (b"GET", b"//deploymentz"),
            b"CUSTOM-TOKEN /ordinary HTTP/1.1\r\n": (
                b"CUSTOM-TOKEN",
                b"/ordinary",
            ),
        }
        for raw, expected in accepted.items():
            with self.subTest(raw=raw):
                self.assertEqual(expected, subject._canonical_request_line(raw))

        rejected: tuple[object, ...] = (
            None,
            "GET /deploymentz HTTP/1.1\r\n",
            b"GET  /deploymentz HTTP/1.1\r\n",
            b"GET\t/deploymentz\tHTTP/1.1\r\n",
            b"GET /deploymentz HTTP/1.1 \r\n",
            b"GET /deploymentz HTTP/1.0\r\n",
            b"GET /deploymentz HTTP/1.01\r\n",
            b"GET /deploymentz HTTP/2.0\r\n",
            b"GET /deploymentz http/1.1\r\n",
            b"GET /deploymentz HTTP/1.1\n",
            b"GET /deploy\xffmentz HTTP/1.1\r\n",
            b"GET /deploy\x00mentz HTTP/1.1\r\n",
            b"GET /deploy\x1fmentz HTTP/1.1\r\n",
            b"GET /" + b"a" * 4097 + b" HTTP/1.1\r\n",
        )
        for raw in rejected:
            with self.subTest(raw=raw):
                self.assertIsNone(subject._canonical_request_line(raw))

    @unittest.skipUnless(os.name == "nt", "real lease/HTTP closure is a Win32 contract")
    def test_real_transport_holds_writer_lock_until_child_exit(self) -> None:
        test_temporary_root = Path(__file__).resolve().parents[2] / "tmp"
        test_temporary_root.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="qrh-exact-server-process-", dir=test_temporary_root
        ) as directory:
            root = Path(directory).resolve(strict=True)
            (root / "state").mkdir()
            (root / "tmp" / "service").mkdir(parents=True)
            source_root = Path(__file__).resolve().parents[1] / "src"
            identity = ExactRuntimeLeaseIdentity(
                attempt_id="exact-server-attempt",
                nonce="exact-server-deployment-nonce",
                operation="activation",
                role="candidate",
                start_nonce="exact-server-start-nonce",
                state_identity_sha256="c" * 64,
                release_id="release-r1",
                manifest_sha256="d" * 64,
            )
            payload = json.dumps(
                {
                    field.name: getattr(identity, field.name)
                    for field in fields(identity)
                    if field.init
                }
            )
            script = r'''
import json,sys
from pathlib import Path
sys.path.insert(0,sys.argv[3])
from flask import Flask
from quant_hub.ops import local_exact_runtime_server as server
from quant_hub.ops.local_release_identity import canonical_bytes
from quant_hub.ops.local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity,_TestOnlyWindowsWriterLeaseHolderAdapter

identity=ExactRuntimeLeaseIdentity(**json.loads(sys.argv[2]))
held_lease=_TestOnlyWindowsWriterLeaseHolderAdapter.load().acquire(Path(sys.argv[1]),identity)

class Lease:
    def _canary_checkpoint(self):
        return held_lease._canary_checkpoint()
    @property
    def lease_claim(self):
        record=held_lease.record_document
        return {
            "lease_id":record["lease_id"],
            "lease_nonce":record["lease_nonce"],
            "lease_epoch":record["lease_epoch"],
            "lease_record_sha256":record["lease_record_sha256"],
            "authority":"claim_not_independently_observed",
        }

lease=Lease()

class Closure:
    release_path=r"D:\quant\quant_platform\releases\release-r1"
    manifest_sha256="d"*64
    def checkpoint(self):
        return None

class Evidence:
    def __init__(self,challenge):
        self._raw=canonical_bytes({"schema_version":"qrh-real-http-canary/v1","challenge_nonce":challenge})
    def canonical_bytes(self):
        return self._raw

class Runner:
    def run(self,actual_lease,challenge):
        if actual_lease is not lease:
            raise RuntimeError("lease changed")
        if challenge != "6"*48:
            raise RuntimeError("non-canonical request reached the canary runner")
        return Evidence(challenge)

class State:
    def checkpoint(self):
        return None

class Guards:
    def close(self):
        return None

closure=Closure()
runner=Runner()
server.LockedWindowsWriterLease=type(lease)
server.ExactRuntimeCanaryRunner=Runner
server._LockedExactRuntimeImportClosure=Closure
app=Flask("real-exact-transport")
server._register_exact_endpoints(app,lease,runner,closure)
server._build_application=lambda *_args:(app,State(),Guards())
transient_gate=object.__new__(server.LockedTransientRuntimeAdmissionGate)
class AdmissionLoader:
    @classmethod
    def load_from_service_stdin(cls):
        return transient_gate
server.ProductionTransientRuntimeAdmissionGate=AdmissionLoader
print("READY",flush=True)
try:
    server.serve_exact_runtime(lease,closure)
finally:
    held_lease.close()
'''
            environment = {
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "TEMP": str(root / "tmp" / "service"),
                "TMP": str(root / "tmp" / "service"),
            }
            process = subprocess.Popen(
                (
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    script,
                    str(root),
                    payload,
                    str(source_root),
                ),
                cwd=root,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            try:
                line = process.stdout.readline() if process.stdout is not None else ""
                if line.strip() != "READY":
                    stderr = process.stderr.read() if process.stderr is not None else ""
                    self.fail(f"exact transport child did not start: {stderr}")
                adapter = _TestOnlyWindowsWriterLeaseHolderAdapter.load()
                with self.assertRaises(WindowsWriterLeaseBusy):
                    adapter.acquire(root, identity)

                challenge = "2" * 48
                response = None
                last_error: OSError | None = None
                for _attempt in range(40):
                    connection = http.client.HTTPConnection(
                        "127.0.0.1", 8765, timeout=0.1
                    )
                    try:
                        connection.request(
                            "GET",
                            "/deploymentz",
                            headers={
                                **self._headers(),
                                "X-Quant-Hub-Endpoint-Challenge": challenge,
                            },
                        )
                        response = connection.getresponse()
                        raw = response.read()
                        break
                    except OSError as error:
                        last_error = error
                        time.sleep(0.025)
                    finally:
                        connection.close()
                if response is None:
                    self.fail(f"exact transport did not listen: {last_error}")
                self.assertEqual(200, response.status)
                document = json.loads(raw.decode("utf-8"))
                self.assertEqual(challenge, document["probe_challenge"])
                self.assertEqual(identity.scm_identity_sha256, document["scm_identity_sha256"])

                def raw_line_status(
                    request_line: bytes,
                    *,
                    canary: bool,
                    body: bytes = b"",
                    line_ending: bytes = b"\r\n",
                ) -> int:
                    headers = [
                        "Host: 127.0.0.1:8765",
                        "Accept: application/json",
                        "Cache-Control: no-store",
                        "Connection: close",
                        "Accept-Encoding: identity",
                    ]
                    if not canary:
                        headers.append(
                            "X-Quant-Hub-Endpoint-Challenge: " + "5" * 48
                        )
                    else:
                        headers.extend(
                            (
                                "Content-Type: application/json",
                                f"Content-Length: {len(body)}",
                            )
                        )
                    request_raw = (
                        request_line
                        + line_ending
                        + ("\r\n".join(headers) + "\r\n\r\n").encode("ascii")
                        + body
                    )
                    with socket.create_connection(("127.0.0.1", 8765), timeout=2) as stream:
                        stream.sendall(request_raw)
                        response_raw = b""
                        while b"\r\n" not in response_raw:
                            try:
                                part = stream.recv(4096)
                            except ConnectionResetError:
                                break
                            if not part:
                                break
                            response_raw += part
                    status_line = response_raw.split(b"\r\n", 1)[0]
                    self.assertTrue(status_line.startswith(b"HTTP/1."), status_line)
                    return int(status_line.split(b" ", 2)[1])

                def raw_status(method: str, target: str, body: bytes = b"") -> int:
                    return raw_line_status(
                        f"{method} {target} HTTP/1.1".encode("ascii"),
                        canary=method == "POST",
                        body=body,
                    )

                self.assertEqual(200, raw_status("GET", "/deploymentz"))
                for target in (
                    "//deploymentz",
                    "///deploymentz",
                    "/deployment%7a",
                    "/deployment%7A",
                    "/%64eploymentz",
                    "/deployment//z",
                    "/deploymentz/",
                    "/deploymentz/.",
                    "/deploymentz%2f",
                    "http://127.0.0.1:8765/deploymentz",
                    "127.0.0.1:8765",
                    "*",
                    "/deploymentz?visible=1",
                    "/deploymentz?",
                    "/deploymentz#fragment",
                ):
                    with self.subTest(real_target=target):
                            self.assertEqual(503, raw_status("GET", target))
                canary_body = canonical_bytes({"challenge_nonce": "6" * 48})
                self.assertEqual(
                    200,
                    raw_status("POST", "/deployment-canaryz", canary_body),
                )
                rejected_canary_body = canonical_bytes(
                    {"challenge_nonce": "7" * 48}
                )
                for target in (
                    "//deployment-canaryz",
                    "///deployment-canaryz",
                    "/deployment-canary%7a",
                    "/deployment-canary%7A",
                    "/deployment-%63anaryz",
                    "/deployment//canaryz",
                    "/deployment-canaryz/",
                    "/deployment-canaryz/.",
                    "/deployment-canaryz%2f",
                    "http://127.0.0.1:8765/deployment-canaryz",
                    "127.0.0.1:8765",
                    "*",
                    "/deployment-canaryz?visible=1",
                    "/deployment-canaryz?",
                    "/deployment-canaryz#fragment",
                ):
                    with self.subTest(real_target=target):
                            self.assertEqual(
                                503,
                                raw_status("POST", target, rejected_canary_body),
                            )

                malformed_lines = (
                    lambda method, target: f"{method}  {target} HTTP/1.1".encode("ascii"),
                    lambda method, target: f"{method}\t{target}\tHTTP/1.1".encode("ascii"),
                    lambda method, target: f"{method} {target} HTTP/1.1 ".encode("ascii"),
                    lambda method, target: f"{method} {target} HTTP/1.0".encode("ascii"),
                    lambda method, target: f"{method} {target} HTTP/1.01".encode("ascii"),
                    lambda method, target: f"{method} {target} HTTP/2.0".encode("ascii"),
                    lambda method, target: f"{method} {target} http/1.1".encode("ascii"),
                    lambda method, target: method.encode("ascii") + b" /deploy\xffmentz HTTP/1.1",
                    lambda method, target: method.encode("ascii") + b" /deploy\x00mentz HTTP/1.1",
                    lambda method, target: method.encode("ascii") + b" /deploy\x1fmentz HTTP/1.1",
                )
                endpoint_cases = (
                    ("GET", "/deploymentz", False, b""),
                    ("POST", "/deployment-canaryz", True, rejected_canary_body),
                )
                for method, target, canary, body in endpoint_cases:
                    for build_line in malformed_lines:
                        request_line = build_line(method, target)
                        with self.subTest(
                            endpoint=target,
                            malformed_line=request_line,
                        ):
                            self.assertNotEqual(
                                200,
                                raw_line_status(
                                    request_line,
                                    canary=canary,
                                    body=body,
                                ),
                            )
                    with self.subTest(endpoint=target, malformed_line="LF-only"):
                        self.assertNotEqual(
                            200,
                            raw_line_status(
                                f"{method} {target} HTTP/1.1".encode("ascii"),
                                canary=canary,
                                body=body,
                                line_ending=b"\n",
                            ),
                        )

                for method, _target, canary, body in endpoint_cases:
                    oversized = (
                        method.encode("ascii")
                        + b" /"
                        + b"a" * (70 * 1024)
                        + b" HTTP/1.1"
                    )
                    with self.subTest(endpoint=method, malformed_line="oversized"):
                        self.assertNotEqual(
                            200,
                            raw_line_status(
                                oversized,
                                canary=canary,
                                body=body,
                            ),
                        )
                self.assertEqual(
                    200,
                    raw_status("POST", "/deployment-canaryz", canary_body),
                )
                record_path = root / "state" / "writer_lease.json"
                original_record = record_path.read_bytes()
                record_path.write_bytes(b"drifted-record\n")
                drift_connection = http.client.HTTPConnection(
                    "127.0.0.1", 8765, timeout=2.0
                )
                try:
                    drift_connection.request(
                        "GET",
                        "/deploymentz",
                        headers={
                            **self._headers(),
                            "X-Quant-Hub-Endpoint-Challenge": "4" * 48,
                        },
                    )
                    drift_response = drift_connection.getresponse()
                    drift_raw = drift_response.read()
                    self.fail(
                        "drifted lease returned an HTTP response: "
                        f"{drift_response.status} {drift_raw!r}"
                    )
                except (OSError, http.client.HTTPException):
                    pass
                finally:
                    drift_connection.close()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=10)
                    self.fail("drifted writer lease did not terminate the exact runtime")
                self.assertNotEqual(0, process.returncode)
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
                if "record_path" in locals() and "original_record" in locals():
                    record_path.write_bytes(original_record)
                for pipe in (process.stdout,):
                    if pipe is not None:
                        pipe.close()

            recovered = _TestOnlyWindowsWriterLeaseHolderAdapter.load().acquire(
                root, identity
            )
            recovered.close()

    def test_deployment_endpoint_rejects_non_exact_envelope(self) -> None:
        cases = (
            ("missing_challenge", {}, "127.0.0.1"),
            (
                "bad_accept",
                {"X-Quant-Hub-Endpoint-Challenge": self.challenge, "Accept": "*/*"},
                "127.0.0.1",
            ),
            (
                "non_loopback",
                {"X-Quant-Hub-Endpoint-Challenge": self.challenge},
                "10.0.0.8",
            ),
            (
                "proxied",
                {
                    "X-Quant-Hub-Endpoint-Challenge": self.challenge,
                    "X-Forwarded-For": "127.0.0.1",
                },
                "127.0.0.1",
            ),
            (
                "bad_host",
                {
                    "X-Quant-Hub-Endpoint-Challenge": self.challenge,
                    "Host": "localhost:8765",
                },
                "127.0.0.1",
            ),
            (
                "bad_cache_control",
                {
                    "X-Quant-Hub-Endpoint-Challenge": self.challenge,
                    "Cache-Control": "max-age=0",
                },
                "127.0.0.1",
            ),
            (
                "keep_alive",
                {
                    "X-Quant-Hub-Endpoint-Challenge": self.challenge,
                    "Connection": "keep-alive",
                },
                "127.0.0.1",
            ),
            (
                "content_encoding",
                {
                    "X-Quant-Hub-Endpoint-Challenge": self.challenge,
                    "Content-Encoding": "gzip",
                },
                "127.0.0.1",
            ),
            (
                "accept_encoding",
                {
                    "X-Quant-Hub-Endpoint-Challenge": self.challenge,
                    "Accept-Encoding": "gzip",
                },
                "127.0.0.1",
            ),
            (
                "transfer_encoding",
                {
                    "X-Quant-Hub-Endpoint-Challenge": self.challenge,
                    "Transfer-Encoding": "chunked",
                },
                "127.0.0.1",
            ),
        )
        for label, changes, remote in cases:
            with self.subTest(label=label):
                headers = self._headers()
                headers.update(changes)
                if label == "missing_challenge":
                    headers.pop("X-Quant-Hub-Endpoint-Challenge", None)
                response = self.client.get(
                    "/deploymentz",
                    headers=headers,
                    environ_base={"REMOTE_ADDR": remote},
                )
                self.assertEqual(404, response.status_code)
        headers = self._headers()
        headers["X-Quant-Hub-Endpoint-Challenge"] = self.challenge
        self.assertEqual(
            404,
            self.client.head(
                "/deploymentz",
                headers=headers,
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            ).status_code,
        )
        self.assertEqual(
            405,
            self.client.options(
                "/deploymentz",
                headers=headers,
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            ).status_code,
        )
        self.assertEqual(
            404,
            self.client.get(
                "/deploymentz?unexpected=1",
                headers=headers,
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            ).status_code,
        )
        self.assertEqual(
            404,
            self.client.get(
                "/deploymentz",
                data=b"unexpected",
                headers=headers,
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            ).status_code,
        )
        self.assertEqual(
            405,
            self.client.options(
                "/deployment-canaryz",
                headers=self._headers(),
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            ).status_code,
        )

    def test_both_endpoints_require_exact_raw_request_target(self) -> None:
        deployment_headers = {
            **self._headers(),
            "X-Quant-Hub-Endpoint-Challenge": self.challenge,
        }
        canary_body = canonical_bytes({"challenge_nonce": self.challenge})
        for alias in (
            "/deployment%7a",
            "/deployment%7A",
            "/%64eploymentz",
            "/%64%65ploymentz",
        ):
            with self.subTest(endpoint="deployment", alias=alias):
                response = self.client.get(
                    alias,
                    headers=deployment_headers,
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
                self.assertEqual(404, response.status_code)
        for alias in (
            "/deployment-canary%7a",
            "/deployment-canary%7A",
            "/deployment-%63anaryz",
            "/%64eployment-canaryz",
        ):
            with self.subTest(endpoint="canary", alias=alias):
                response = self.client.post(
                    alias,
                    data=canary_body,
                    headers={**self._headers(), "Content-Type": "application/json"},
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
                self.assertEqual(404, response.status_code)

        environments = (
            {"RAW_URI": None, "REQUEST_URI": None},
            {"RAW_URI": None, "REQUEST_URI": "/deploymentz"},
            {"RAW_URI": "/deploymentz", "REQUEST_URI": None},
            {"RAW_URI": "/different", "REQUEST_URI": "/deploymentz"},
            {"RAW_URI": "/deploymentz", "REQUEST_URI": "/different"},
            {
                "RAW_URI": "/deploymentz?hidden=1",
                "REQUEST_URI": "/deploymentz?hidden=1",
                "QUERY_STRING": "",
            },
            {
                "RAW_URI": "http://127.0.0.1:8765/deploymentz",
                "REQUEST_URI": "http://127.0.0.1:8765/deploymentz",
            },
            {"SERVER_PROTOCOL": None},
            {"SERVER_PROTOCOL": 1},
            {"SERVER_PROTOCOL": "HTTP/1.0"},
            {"SERVER_PROTOCOL": "HTTP/1.01"},
            {"SERVER_PROTOCOL": "HTTP/2.0"},
        )
        for environment in environments:
            with self.subTest(environment=environment):
                response = self.client.get(
                    "/deploymentz",
                    headers=deployment_headers,
                    environ_overrides={
                        "REMOTE_ADDR": "127.0.0.1",
                        **environment,
                    },
                )
                self.assertEqual(404, response.status_code)
        self.assertEqual([], self.runner.calls)

    def test_canary_endpoint_accepts_only_canonical_closed_body(self) -> None:
        body = canonical_bytes({"challenge_nonce": self.challenge})
        response = self.client.post(
            "/deployment-canaryz",
            data=body,
            headers={**self._headers(), "Content-Type": "application/json"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual(
            canonical_bytes(
                {
                    "schema_version": "qrh-test-canary/v1",
                    "challenge_nonce": self.challenge,
                }
            ),
            response.data,
        )
        self.assertEqual([(self.lease, self.challenge)], self.runner.calls)

        for invalid in (
            body + b"\n",
            canonical_bytes({"challenge_nonce": self.challenge, "extra": 1}),
            canonical_bytes({"challenge_nonce": "A" * 48}),
            b'{"challenge_nonce":NaN}',
            (
                b'{"challenge_nonce":"' + self.challenge.encode("ascii")
                + b'","challenge_nonce":"' + self.challenge.encode("ascii")
                + b'"}'
            ),
        ):
            with self.subTest(invalid=invalid):
                rejected = self.client.post(
                    "/deployment-canaryz",
                    data=invalid,
                    headers={**self._headers(), "Content-Type": "application/json"},
                    environ_base={"REMOTE_ADDR": "127.0.0.1"},
                )
                self.assertEqual(400, rejected.status_code)
        self.assertEqual(1, len(self.runner.calls))

        wrong_type = self.client.post(
            "/deployment-canaryz",
            data=body,
            headers={
                **self._headers(),
                "Content-Type": "application/json; charset=utf-8",
            },
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        self.assertEqual(415, wrong_type.status_code)
        non_loopback = self.client.post(
            "/deployment-canaryz",
            data=body,
            headers={**self._headers(), "Content-Type": "application/json"},
            environ_base={"REMOTE_ADDR": "10.0.0.8"},
        )
        self.assertEqual(404, non_loopback.status_code)
        noncanonical_length = self.client.open(
            "/deployment-canaryz",
            method="POST",
            data=body,
            headers={**self._headers(), "Content-Type": "application/json"},
            environ_overrides={
                "REMOTE_ADDR": "127.0.0.1",
                "CONTENT_LENGTH": "0" + str(len(body)),
            },
        )
        self.assertEqual(400, noncanonical_length.status_code)

    def test_canary_lock_rejects_concurrent_third_state(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class _BlockingRunner(_FakeRunner):
            def run(self, lease: object, challenge: str) -> _Evidence:
                self.calls.append((lease, challenge))
                entered.set()
                if not release.wait(timeout=5):
                    raise RuntimeError("test canary release timed out")
                return _Evidence(challenge)

        app = Flask("exact-concurrent-canary")
        lease = _FakeLease()
        runner = _BlockingRunner()
        self._register(app, lease, runner)
        first_status: list[int] = []

        def first_request() -> None:
            response = app.test_client().post(
                "/deployment-canaryz",
                data=canonical_bytes({"challenge_nonce": self.challenge}),
                headers={**self._headers(), "Content-Type": "application/json"},
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            )
            first_status.append(response.status_code)

        thread = threading.Thread(target=first_request)
        thread.start()
        self.assertTrue(entered.wait(timeout=5))
        second = app.test_client().post(
            "/deployment-canaryz",
            data=canonical_bytes({"challenge_nonce": "3" * 48}),
            headers={**self._headers(), "Content-Type": "application/json"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        )
        self.assertEqual(409, second.status_code)
        self.assertEqual("canary_busy", second.get_json()["code"])
        release.set()
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual([200], first_status)
        self.assertEqual(1, len(runner.calls))

    def test_lease_drift_escapes_flask_error_handling(self) -> None:
        headers = self._headers()
        headers["X-Quant-Hub-Endpoint-Challenge"] = self.challenge
        original = self.lease._canary_checkpoint

        def drift():  # type: ignore[no-untyped-def]
            value = original()
            if self.lease.checkpoints >= 2:
                self.lease.record["nonce"] = "drifted-nonce"
                value[0]["nonce"] = "drifted-nonce"
            return value

        self.lease._canary_checkpoint = drift  # type: ignore[method-assign]
        with self.assertRaises(subject._FatalExactRuntime):
            self.client.get(
                "/deploymentz",
                headers=headers,
                environ_base={"REMOTE_ADDR": "127.0.0.1"},
            )

    def test_runtime_state_checkpoint_allows_same_database_file_but_not_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qrh-runtime-state-") as directory:
            root = Path(directory).resolve(strict=True)
            secret = root / "viewer_secret.key"
            digest = root / "viewer_access_password.digest"
            comments = root / "comments.sqlite3"
            workspace = root / "research_workspace.sqlite3"
            secret.write_bytes(b"a" * 64)
            digest.write_bytes(b"b" * 64)
            comments.write_bytes(b"comments")
            workspace.write_bytes(b"workspace")
            checkpoint = subject._RuntimeStateCheckpoint(
                protected_paths=(secret, digest),
                database_paths=(comments, workspace),
            )
            comments.write_bytes(b"same-file-content-change")
            checkpoint.checkpoint()
            replacement = root / "comments.replacement"
            replacement.write_bytes(b"replacement")
            replacement.replace(comments)
            with self.assertRaisesRegex(
                subject.ExactRuntimeServerError, "identity drifted"
            ):
                checkpoint.checkpoint()

    def test_session_secret_is_exclusively_created_once(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qrh-runtime-secret-create-") as directory:
            path = Path(directory).resolve(strict=True) / "viewer_secret.key"
            first = subject._secret(path)
            second = subject._secret(path)
            self.assertEqual(first, second)
            self.assertRegex(first, r"^[0-9a-f]{64}$")
            self.assertEqual(first + "\n", path.read_text(encoding="ascii"))

    @unittest.skipUnless(os.name == "nt", "mutable state guard is a Win32 contract")
    def test_mutable_state_guard_allows_write_but_blocks_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qrh-runtime-db-guard-") as directory:
            root = Path(directory).resolve(strict=True)
            comments = root / "comments.sqlite3"
            workspace = root / "research_workspace.sqlite3"
            comments.write_bytes(b"comments")
            workspace.write_bytes(b"workspace")
            guard = subject._WindowsMutableStateGuardSet((comments, workspace))
            replacement = root / "comments.replacement"
            replacement.write_bytes(b"replacement")
            try:
                comments.write_bytes(b"same-file-write")
                with self.assertRaises(PermissionError):
                    replacement.replace(comments)
            finally:
                guard.close()
            replacement.replace(comments)
            self.assertEqual(b"replacement", comments.read_bytes())

    def test_runtime_state_checkpoint_detects_protected_content_drift(self) -> None:
        with tempfile.TemporaryDirectory(prefix="qrh-runtime-secret-") as directory:
            root = Path(directory).resolve(strict=True)
            secret = root / "viewer_secret.key"
            digest = root / "viewer_access_password.digest"
            comments = root / "comments.sqlite3"
            workspace = root / "research_workspace.sqlite3"
            for path, raw in (
                (secret, b"a" * 64),
                (digest, b"b" * 64),
                (comments, b"comments"),
                (workspace, b"workspace"),
            ):
                path.write_bytes(raw)
            checkpoint = subject._RuntimeStateCheckpoint(
                protected_paths=(secret, digest),
                database_paths=(comments, workspace),
            )
            secret.write_bytes(b"c" * 64)
            with self.assertRaisesRegex(
                subject.ExactRuntimeServerError, "identity drifted"
            ):
                checkpoint.checkpoint()

    def test_release_runtime_databases_are_fixed_read_only(self) -> None:
        from quant_hub.platform.db import connect_database, connection_is_read_only

        with tempfile.TemporaryDirectory(prefix="qrh-release-read-only-") as directory:
            runtime = Path(directory).resolve(strict=True)
            database = runtime / "platform.sqlite3"
            initial = sqlite3.connect(database)
            try:
                initial.execute("CREATE TABLE sample(value TEXT NOT NULL)")
                initial.execute("INSERT INTO sample(value) VALUES ('fixed')")
                initial.commit()
            finally:
                initial.close()
            previous = os.environ.get(subject._READ_ONLY_DATABASE_ROOT_ENV)
            try:
                subject._fix_release_read_only_root(runtime)
                connection = connect_database(database)
                try:
                    self.assertTrue(connection_is_read_only(connection))
                    self.assertEqual(
                        "fixed",
                        connection.execute("SELECT value FROM sample").fetchone()[0],
                    )
                    with self.assertRaises(sqlite3.OperationalError):
                        connection.execute("INSERT INTO sample(value) VALUES ('drift')")
                finally:
                    connection.close()
            finally:
                if previous is None:
                    os.environ.pop(subject._READ_ONLY_DATABASE_ROOT_ENV, None)
                else:
                    os.environ[subject._READ_ONLY_DATABASE_ROOT_ENV] = previous
            self.assertFalse(Path(str(database) + "-wal").exists())
            self.assertFalse(Path(str(database) + "-shm").exists())

    def test_full_application_build_reads_release_and_uses_external_state(self) -> None:
        from quant_hub.app import create_app
        from quant_hub.collaboration.comment_store import initialize_comment_store
        from quant_hub.config import Settings
        from quant_hub.research_workspace.database import (
            initialize_research_workspace_database,
        )

        with tempfile.TemporaryDirectory(prefix="qrh-exact-app-build-") as directory:
            root = Path(directory).resolve(strict=True)
            release = root / "releases" / "release-r1"
            archive = release / "reference" / "archive"
            archive.mkdir(parents=True)
            source_migrations = Path(__file__).resolve().parents[1] / "migrations"
            migration_root = release / "runtime_contract" / "migrations"
            shutil.copytree(source_migrations, migration_root)
            runtime = release / "runtime"
            settings = Settings(
                project_root=release,
                archive_root=archive,
                var_root=runtime,
                database_path=runtime / "db" / "platform.sqlite3",
                object_root=runtime / "objects",
                migration_root=migration_root / "platform",
            )
            settings.validate()
            previous = os.environ.pop(subject._READ_ONLY_DATABASE_ROOT_ENV, None)
            try:
                create_app(settings, {"TESTING": True})
                state = root / "state"
                state.mkdir()
                comments = state / "comments.sqlite3"
                workspace = state / "research_workspace.sqlite3"
                initialize_comment_store(comments)
                initialize_research_workspace_database(
                    settings, database_path=workspace
                )
                (state / "viewer_secret.key").write_text("a" * 64, "ascii")
                (state / "viewer_access_password.digest").write_text(
                    derive_password_digest("exact-app-password").hex(), "ascii"
                )

                class _BuildLease(_FakeLease):
                    def __init__(self) -> None:
                        super().__init__()
                        self.record["release"] = {
                            "release_id": "release-r1",
                            "release_path": str(release),
                            "manifest_sha256": "d" * 64,
                        }

                    def _canary_checkpoint(self):  # type: ignore[no-untyped-def]
                        self.checkpoints += 1
                        return self.record.copy(), root, object()

                class _BuildClosure:
                    release_path = release
                    manifest_sha256 = "d" * 64
                    manifest_document = {
                        "application": {"source_kind": "legacy_broadcast"}
                    }

                    @staticmethod
                    def checkpoint() -> None:
                        return None

                class _BuildRunner(_FakeRunner):
                    @classmethod
                    def load_exact_d(cls) -> "_BuildRunner":
                        return cls()

                lease = _BuildLease()
                closure = _BuildClosure()
                before_sidecars = sorted(
                    path.relative_to(runtime).as_posix()
                    for path in runtime.rglob("*")
                    if path.name.endswith(("-wal", "-shm", "-journal"))
                )
                with patch.multiple(
                    subject,
                    LockedWindowsWriterLease=_BuildLease,
                    ExactRuntimeCanaryRunner=_BuildRunner,
                    _LockedExactRuntimeImportClosure=_BuildClosure,
                ):
                    app, checkpoint, guards = subject._build_application(
                        lease, closure  # type: ignore[arg-type]
                    )
                try:
                    checkpoint.checkpoint()
                    headers = self._headers()
                    headers["X-Quant-Hub-Endpoint-Challenge"] = self.challenge
                    response = app.test_client().get(
                        "/deploymentz",
                        headers=headers,
                        environ_base={"REMOTE_ADDR": "127.0.0.1"},
                    )
                    self.assertEqual(200, response.status_code)
                finally:
                    guards.close()
                after_sidecars = sorted(
                    path.relative_to(runtime).as_posix()
                    for path in runtime.rglob("*")
                    if path.name.endswith(("-wal", "-shm", "-journal"))
                )
                self.assertEqual(before_sidecars, after_sidecars)
            finally:
                if previous is None:
                    os.environ.pop(subject._READ_ONLY_DATABASE_ROOT_ENV, None)
                else:
                    os.environ[subject._READ_ONLY_DATABASE_ROOT_ENV] = previous

    def test_runtime_state_drift_escapes_flask_error_handling(self) -> None:
        class _DriftedState:
            @staticmethod
            def checkpoint() -> None:
                raise subject.ExactRuntimeServerError("identity drifted")

        app = Flask("exact-state-checkpoint")

        @app.before_request
        def checkpoint_state() -> None:
            subject._checkpoint_state(_DriftedState())  # type: ignore[arg-type]

        @app.get("/")
        def index() -> str:
            return "unreachable"

        with self.assertRaises(subject._FatalExactRuntime):
            app.test_client().get("/")

    def test_product_surface_is_fixed_and_has_no_dynamic_loader(self) -> None:
        self.assertEqual(
            ["lease", "closure"],
            list(inspect.signature(subject.serve_exact_runtime).parameters),
        )
        source = Path(subject.__file__).read_text("utf-8")
        self.assertNotIn("test_only", source.casefold())
        tree = ast.parse(source)
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertNotIn("importlib", imports)
        self.assertNotIn("sys", imports)
        calls = {
            node.func.id
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertTrue({"exec", "eval", "compile"}.isdisjoint(calls))
        make_server_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "make_server"
        ]
        self.assertEqual(1, len(make_server_calls))
        handler_keywords = [
            keyword.value
            for keyword in make_server_calls[0].keywords
            if keyword.arg == "request_handler"
        ]
        self.assertEqual(1, len(handler_keywords))
        self.assertIsInstance(handler_keywords[0], ast.Name)
        self.assertEqual(
            "_ExactRuntimeRequestHandler",
            handler_keywords[0].id,  # type: ignore[union-attr]
        )


if __name__ == "__main__":
    unittest.main()
