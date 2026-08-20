from __future__ import annotations

import unittest

from flask import Flask, request

from quant_hub.web.security import (
    WriteSecurityError,
    compile_trusted_origins,
    csrf_token,
    normalized_origin,
    require_write_security,
)


class WebSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.app = Flask(__name__)
        self.app.secret_key = "test-only"
        self.trusted = compile_trusted_origins(("http://127.0.0.1:5055",))

    def test_origin_parser_rejects_browser_differentials(self) -> None:
        self.assertEqual(
            ("http", "127.0.0.1", 5055),
            normalized_origin("HTTP://127.0.0.1:5055"),
        )
        for invalid in (
            "http://127.1:5055",
            "http://user@127.0.0.1:5055",
            "http://127.0.0.1:5055/path",
            "http://127.0.0.1:5055\\evil",
        ):
            with self.subTest(invalid=invalid):
                self.assertIsNone(normalized_origin(invalid))

    def test_csrf_token_replaces_missing_or_malformed_session_material(self) -> None:
        with self.app.test_request_context("/"):
            from flask import session

            session["csrf_token"] = ""
            replacement = csrf_token()
            self.assertEqual(43, len(replacement))
            self.assertNotEqual("", replacement)
            self.assertEqual(replacement, csrf_token())

    def test_write_requires_origin_csrf_and_idempotency(self) -> None:
        with self.app.test_request_context("/"):
            token = csrf_token()
        headers = {
            "Origin": "http://127.0.0.1:5055",
            "X-CSRF-Token": token,
            "Idempotency-Key": "comment-create-0001",
        }
        with self.app.test_request_context("/", method="POST", headers=headers):
            # Test request contexts have separate sessions, so freeze the same token.
            from flask import session

            session["csrf_token"] = token
            self.assertEqual(
                "comment-create-0001",
                require_write_security(request, self.trusted),
            )
        bad = {**headers, "Origin": "http://evil.example"}
        with self.app.test_request_context("/", method="POST", headers=bad):
            from flask import session

            session["csrf_token"] = token
            with self.assertRaises(WriteSecurityError) as caught:
                require_write_security(request, self.trusted)
            self.assertEqual("origin_rejected", caught.exception.code)

        # 没有先建立 session 时，缺失 token 的两个空值绝不能互相“匹配”。
        no_session_headers = {
            "Origin": headers["Origin"],
            "Idempotency-Key": headers["Idempotency-Key"],
        }
        with self.app.test_request_context(
            "/", method="POST", headers=no_session_headers
        ):
            with self.assertRaises(WriteSecurityError) as caught:
                require_write_security(request, self.trusted)
            self.assertEqual("csrf_rejected", caught.exception.code)
            self.assertEqual(403, caught.exception.status)

        security_cases = (
            (
                "missing csrf",
                {
                    "Origin": headers["Origin"],
                    "Idempotency-Key": headers["Idempotency-Key"],
                },
                "csrf_rejected",
                403,
            ),
            (
                "wrong csrf",
                {**headers, "X-CSRF-Token": "A" * 43},
                "csrf_rejected",
                403,
            ),
            (
                "missing idempotency key",
                {
                    "Origin": headers["Origin"],
                    "X-CSRF-Token": headers["X-CSRF-Token"],
                },
                "invalid_idempotency_key",
                428,
            ),
            (
                "malformed idempotency key",
                {**headers, "Idempotency-Key": "bad key!"},
                "invalid_idempotency_key",
                400,
            ),
        )
        for label, case_headers, expected_code, expected_status in security_cases:
            with self.subTest(case=label):
                with self.app.test_request_context(
                    "/", method="POST", headers=case_headers
                ):
                    from flask import session

                    session["csrf_token"] = token
                    with self.assertRaises(WriteSecurityError) as caught:
                        require_write_security(request, self.trusted)
                    self.assertEqual(expected_code, caught.exception.code)
                    self.assertEqual(expected_status, caught.exception.status)


if __name__ == "__main__":
    unittest.main()
