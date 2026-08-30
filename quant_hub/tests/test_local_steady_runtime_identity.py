from __future__ import annotations

import copy
import inspect
import pickle
import unittest

from quant_hub.ops.local_release_identity import identity_sha256
from quant_hub.ops.local_steady_runtime_identity import (
    ExactSteadyRuntimeIdentity,
    ExactSteadyRuntimeIdentityError,
    _ARGUMENT_FIELDS,
    _ARGUMENT_FLAGS,
    _parse_exact_steady_argv,
)
from quant_hub.ops.windows_service import (
    WindowsServiceError,
    parse_service_start_authorization,
)


def _values() -> dict[str, str]:
    return {
        "authority_kind": "steady_active",
        "runtime_state_kind": "steady_current",
        "boot_nonce": "0" * 48,
        "active_release_sha256": "1" * 64,
        "binding_sha256": "2" * 64,
        "retention_aggregate_sha256": "3" * 64,
        "state_identity_sha256": "4" * 64,
        "release_id": "release-steady-1",
        "manifest_sha256": "5" * 64,
        "tooling_sha256": "6" * 64,
        "receipt_lineage_aggregate_sha256": "7" * 64,
        "legacy_c_live_fence_aggregate_sha256": "8" * 64,
    }


def _runtime_arguments() -> tuple[str, ...]:
    values = _values()
    return tuple(
        item
        for flag, field in zip(_ARGUMENT_FLAGS, _ARGUMENT_FIELDS, strict=True)
        for item in (flag, values[field])
    )


class ExactSteadyRuntimeIdentityTests(unittest.TestCase):
    def test_exact_arguments_reconstruct_fixed_plan_and_authorization(self) -> None:
        parsed = _parse_exact_steady_argv(_runtime_arguments())
        identity = ExactSteadyRuntimeIdentity(**parsed)
        self.assertEqual(("steady-exact-runtime", *_runtime_arguments()), identity.service_start_arguments)
        self.assertEqual(_runtime_arguments(), identity.child_argv[-len(_runtime_arguments()):])
        self.assertEqual(identity.scm_identity_sha256, identity_sha256(identity.scm_plan_document))
        self.assertEqual(
            identity.authorization_sha256,
            identity_sha256(identity.authorization_document),
        )
        self.assertEqual(
            identity.scm_identity_sha256,
            identity.authorization_document["scm_identity_sha256"],
        )
        serialized = str(identity.scm_plan_document) + str(identity.authorization_document)
        for forbidden in ("attempt_id", "deployment_nonce", "operation", "role", "start_nonce"):
            self.assertNotIn(forbidden, serialized)

    def test_service_parser_accepts_only_exact_steady_shape(self) -> None:
        parsed = parse_service_start_authorization(
            ("service-host", "steady-exact-runtime", *_runtime_arguments())
        )
        self.assertIs(type(parsed), ExactSteadyRuntimeIdentity)
        self.assertEqual(_values()["boot_nonce"], parsed.boot_nonce)
        cases = (
            ("service-host", "steady-exact-runtime", *_runtime_arguments()[:-2]),
            ("service-host", "steady-exact-runtime", *_runtime_arguments(), "--extra", "x"),
            ("service-host", "steady-exact-runtime", "--runtime-state-kind", "steady_current", *_runtime_arguments()[2:]),
            ("service-host", "steady-exact-runtime", *_runtime_arguments()[:1], "candidate", *_runtime_arguments()[2:]),
        )
        for case in cases:
            with self.subTest(case=case), self.assertRaises(WindowsServiceError):
                parse_service_start_authorization(case)

    def test_invalid_fields_and_role_confusion_are_rejected(self) -> None:
        cases = []
        for field, value in (
            ("authority_kind", "transient_candidate"),
            ("runtime_state_kind", "transient_attempt"),
            ("boot_nonce", "attempt-1"),
            ("active_release_sha256", "not-a-hash"),
            ("release_id", "bad/release"),
        ):
            candidate = _values()
            candidate[field] = value
            cases.append(candidate)
        for candidate in cases:
            with self.subTest(candidate=candidate), self.assertRaises(
                ExactSteadyRuntimeIdentityError
            ):
                ExactSteadyRuntimeIdentity(**candidate)
        with self.assertRaises(ExactSteadyRuntimeIdentityError):
            _parse_exact_steady_argv(list(_runtime_arguments()))

    def test_identity_is_exact_immutable_and_non_serializable(self) -> None:
        identity = ExactSteadyRuntimeIdentity(**_values())
        with self.assertRaises(TypeError):
            identity._boot_nonce = "f" * 48  # type: ignore[misc]
        with self.assertRaises(TypeError):
            pickle.dumps(identity)
        with self.assertRaises(TypeError):
            copy.copy(identity)
        with self.assertRaises(TypeError):
            class Derived(ExactSteadyRuntimeIdentity):
                pass
        self.assertEqual(
            [],
            [
                name
                for name in inspect.signature(parse_service_start_authorization).parameters
                if name in {"root", "path", "environment", "callback", "api"}
            ],
        )


if __name__ == "__main__":
    unittest.main()
