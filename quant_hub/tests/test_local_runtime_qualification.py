from __future__ import annotations

import hashlib
import inspect
import pickle
import unittest
from unittest import mock

from quant_hub.ops import local_runtime_qualification as qualification
from quant_hub.ops.local_exact_runtime_canary_evidence import (
    EXACT_RUNTIME_CANARY_REQUEST_SCOPE,
    EXACT_RUNTIME_CANARY_REQUEST_SCHEMA,
    ExactRuntimeCanaryRequest,
    build_exact_runtime_canary_request,
)
from quant_hub.ops.local_exact_runtime_canary_input import (
    LockedExactRuntimeCanaryInput,
)
from quant_hub.ops.local_exact_runtime_canary_live_observer import (
    ExactRuntimeCanaryLiveObservationEvidence,
    LockedExactRuntimeCanaryObservation,
)
from quant_hub.ops.local_exact_runtime_controller_tooling_observer import (
    ExactRuntimeControllerToolingObservationEvidence,
    LockedExactRuntimeControllerToolingObservation,
)
from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256
from quant_hub.ops.local_runtime_qualification_evidence import (
    LocalRuntimeQualificationAggregateEvidence,
)


def _hash(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _request() -> ExactRuntimeCanaryRequest:
    attempt = "attempt-formal-1"
    nonce = "deployment-nonce-1"
    role = "candidate"
    payload = {
        "schema_version": EXACT_RUNTIME_CANARY_REQUEST_SCHEMA,
        "scope": EXACT_RUNTIME_CANARY_REQUEST_SCOPE,
        "attempt_id": attempt,
        "nonce": nonce,
        "operation": "activation",
        "role": role,
        "start_nonce": "start-nonce-1",
        "authorization_sha256": _hash("authorization"),
        "scm_identity_sha256": _hash("scm-identity"),
        "state_identity_sha256": _hash("state-identity"),
        "release": {
            "release_id": "release-formal-1",
            "release_path": (
                r"D:\quant\quant_platform\releases\release-formal-1"
            ),
            "manifest_sha256": _hash("release-manifest"),
        },
        "databases": [
            {
                "database_name": name,
                "relative_path": (
                    f"tmp/deployment-attempts/{attempt}-{nonce}/runtime-canary/"
                    f"{role}/state/{filename}"
                ),
                "source_seal_sha256": _hash(name + "-source"),
                "isolated_copy_evidence_sha256": _hash(name + "-copy"),
                "compatibility_evidence_sha256": _hash(name + "-compatibility"),
                "initial_consistent_bytes": 4096 * index,
                "initial_consistent_sha256": _hash(name + "-initial"),
            }
            for index, (name, filename) in enumerate(
                (
                    ("comments", "comments.sqlite3"),
                    ("research_workspace", "research_workspace.sqlite3"),
                ),
                start=1,
            )
        ],
    }
    return ExactRuntimeCanaryRequest.from_document(
        build_exact_runtime_canary_request(payload)
    )


def _tooling_document() -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "qrh-exact-runtime-controller-tooling-observation/v1",
        "scope": "controller_tooling_live_observed_not_qualified",
        "tooling_sha256": _hash("tooling"),
        "manifest_sha256": _hash("tooling-manifest"),
        "package_inventory_sha256": _hash("package-inventory"),
        "python_sha256": _hash("python"),
        "service_host_sha256": _hash("service-host"),
        "checkpoint_generation": 7,
        "result": "live_observed_not_formally_qualified",
    }
    document["evidence_sha256"] = hashlib.sha256(
        canonical_bytes(document)
    ).hexdigest()
    return document


def _live_document(tooling_stable_sha256: str) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "qrh-exact-runtime-canary-live-observation/v1",
        "scope": "exact_runtime_canary_live_observed_not_qualified",
        "request_sha256": _request().request_sha256,
        "result_evidence_sha256": _hash("canary-result"),
        "challenge_nonce": "ab" * 24,
        "scm_stable_sha256": _hash("scm-before-after"),
        "endpoint_stable_sha256": _hash("endpoint-before-after"),
        "writer_stable_sha256": _hash("writer-before-after"),
        "controller_tooling_stable_sha256": tooling_stable_sha256,
        "production_state_source_seals": [
            {"database_name": name, "seal_sha256": _hash(name + "-source-seal")}
            for name in ("comments", "research_workspace")
        ],
        "databases": [
            {
                "database_name": name,
                "final_consistent_bytes": 8192 * index,
                "final_consistent_sha256": _hash(name + "-final"),
                "final_schema_sha256": _hash(name + "-schema"),
                "final_business_summary_sha256": _hash(name + "-business"),
            }
            for index, name in enumerate(
                ("comments", "research_workspace"), start=1
            )
        ],
        "result": "live_observed_not_formally_qualified",
    }
    document["evidence_sha256"] = identity_sha256(document)
    return document


class _ClosureProbe:
    def checkpoint_unchanged(self) -> None:
        return None

    def metadata(self) -> dict[str, object]:
        return {"roles": ["candidate"], "closure": _hash("release-closure")}


class _CompatibilityProbe:
    aggregate_sha256 = _hash("release-compatibility")


class _StateSealProbe:
    def __init__(self, database: str):
        self.seal_sha256 = _hash(database + "-source-seal")


class LocalRuntimeQualificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.request = _request()
        self.tooling_document = _tooling_document()
        tooling_stable = identity_sha256(
            {
                field: self.tooling_document[field]
                for field in qualification._TOOLING_STABLE_FIELDS  # noqa: SLF001
            }
        )
        self.live_document = _live_document(tooling_stable)
        self.canary = object.__new__(LockedExactRuntimeCanaryInput)
        self.tooling = object.__new__(
            LockedExactRuntimeControllerToolingObservation
        )
        self.live = object.__new__(LockedExactRuntimeCanaryObservation)
        object.__setattr__(self.canary, "_closures", _ClosureProbe())
        object.__setattr__(self.canary, "_live_observation", self.live)
        object.__setattr__(
            self.canary,
            "_controller_tooling_observation",
            self.tooling,
        )
        object.__setattr__(self.live, "_canary", self.canary)
        object.__setattr__(self.live, "_tooling", self.tooling)
        object.__setattr__(self.live, "_state", "live")
        object.__setattr__(self.live, "_qualification", None)

    def patches(self, *, live_side_effect=None, state_side_effect=None):
        live_evidence = ExactRuntimeCanaryLiveObservationEvidence(
            canonical_bytes(self.live_document)
        )
        tooling_evidence = ExactRuntimeControllerToolingObservationEvidence(
            canonical_bytes(self.tooling_document)
        )
        live_patch = mock.patch.object(
            LockedExactRuntimeCanaryObservation,
            "build_evidence",
            return_value=live_evidence,
            side_effect=live_side_effect,
        )
        return (
            mock.patch.object(LockedExactRuntimeCanaryInput, "checkpoint_live"),
            mock.patch.object(
                LockedExactRuntimeCanaryInput,
                "request",
                new_callable=mock.PropertyMock,
                return_value=self.request,
            ),
            live_patch,
            mock.patch.object(
                LockedExactRuntimeControllerToolingObservation,
                "build_evidence",
                return_value=tooling_evidence,
            ),
            mock.patch.object(
                qualification,
                "build_exact_release_compatibility_evidence",
                return_value=_CompatibilityProbe(),
            ),
            mock.patch.object(
                qualification,
                "_live_production_state_order_sha256",
                return_value=_hash("production-state-order"),
                side_effect=state_side_effect,
            ),
            mock.patch.object(
                LockedExactRuntimeCanaryInput,
                "source_seal",
                side_effect=lambda _owner, database: _StateSealProbe(database),
                autospec=True,
            ),
        )

    def test_product_surface_is_noarg_exact_and_nonserializable(self) -> None:
        self.assertEqual(
            [],
            list(
                inspect.signature(
                    qualification.ProductionLocalRuntimeQualificationProducer.load_exact_d
                ).parameters
            ),
        )
        self.assertEqual(
            ["self", "observation"],
            list(
                inspect.signature(
                    qualification.ProductionLocalRuntimeQualificationProducer.qualify
                ).parameters
            ),
        )
        product = qualification.ProductionLocalRuntimeQualificationProducer.load_exact_d()
        with self.assertRaises(TypeError):
            pickle.dumps(product)
        with self.assertRaises(qualification.LocalRuntimeQualificationError):
            product.qualify(object())  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            type(
                "ForgedQualification",
                (qualification.LockedLocalRuntimeQualification,),
                {},
            )

    def test_live_rebuild_forms_stable_persistent_non_authority_aggregate(self) -> None:
        product = qualification.ProductionLocalRuntimeQualificationProducer.load_exact_d()
        patches = self.patches()
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6],
        ):
            locked = product.qualify(self.live)
            first = locked.qualification_sha256
            evidence = locked.build_evidence()
        self.assertIs(locked, self.live._qualification)  # noqa: SLF001
        self.assertEqual(first, evidence.aggregate_sha256)
        self.assertEqual(
            "observation_evidence_only_not_authority",
            evidence.as_dict()["scope"],
        )
        self.assertEqual(
            _hash("production-state-order"),
            evidence.as_dict()["production_state_before_order_sha256"],
        )
        self.assertEqual(
            evidence.as_dict()["production_state_before_order_sha256"],
            evidence.as_dict()["production_state_after_order_sha256"],
        )
        self.assertEqual(
            identity_sha256(self.live_document["databases"]),
            evidence.as_dict()["canary_database_order_sha256"],
        )
        self.assertIsInstance(
            evidence, LocalRuntimeQualificationAggregateEvidence
        )
        with self.assertRaises(TypeError):
            pickle.dumps(locked)
        with self.assertRaises(qualification.LocalRuntimeQualificationError):
            product.qualify(evidence)  # type: ignore[arg-type]

    def test_rebuild_window_drift_revokes_qualification(self) -> None:
        stable = ExactRuntimeCanaryLiveObservationEvidence(
            canonical_bytes(self.live_document)
        )
        changed_document = dict(self.live_document)
        changed_document["writer_stable_sha256"] = _hash("writer-drift")
        changed_document["evidence_sha256"] = identity_sha256(
            {
                key: value
                for key, value in changed_document.items()
                if key != "evidence_sha256"
            }
        )
        changed = ExactRuntimeCanaryLiveObservationEvidence(
            canonical_bytes(changed_document)
        )
        product = qualification.ProductionLocalRuntimeQualificationProducer.load_exact_d()
        patches = self.patches(
            live_side_effect=[stable, stable, stable, stable, stable, changed]
        )
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6],
        ):
            locked = product.qualify(self.live)
            with self.assertRaisesRegex(
                qualification.LocalRuntimeQualificationError,
                "重建窗口",
            ):
                _ = locked.qualification_sha256

    def test_production_state_after_is_fresh_source_checkpoint_not_canary_copy(self) -> None:
        product = qualification.ProductionLocalRuntimeQualificationProducer.load_exact_d()
        patches = self.patches(
            state_side_effect=[
                _hash("production-state-before"),
                _hash("production-state-after"),
            ]
        )
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6], self.assertRaisesRegex(
            qualification.LocalRuntimeQualificationError,
            "production state",
            ),
        ):
            product.qualify(self.live)

    def test_close_revokes_business_use_without_closing_upstream(self) -> None:
        product = qualification.ProductionLocalRuntimeQualificationProducer.load_exact_d()
        patches = self.patches()
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6],
        ):
            locked = product.qualify(self.live)
        locked.close()
        locked.close()
        self.assertIs(self.live, locked._observation)  # noqa: SLF001
        self.assertIsNone(self.live._qualification)  # noqa: SLF001
        with self.assertRaises(qualification.LocalRuntimeQualificationError):
            _ = locked.scope

    def test_live_observation_auto_closes_formal_before_tooling(self) -> None:
        product = qualification.ProductionLocalRuntimeQualificationProducer.load_exact_d()
        patches = self.patches()
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6],
        ):
            locked = product.qualify(self.live)
        events: list[str] = []
        original_formal_close = (
            qualification.LockedLocalRuntimeQualification._close_from_observation
        )

        def close_formal(owner, observation) -> None:
            events.append("formal")
            original_formal_close(owner, observation)

        def close_tooling(owner) -> None:
            del owner
            events.append("tooling")

        def release_live(owner, observation) -> None:
            del owner, observation
            events.append("live_release")

        with (
            mock.patch.object(
                qualification.LockedLocalRuntimeQualification,
                "_close_from_observation",
                autospec=True,
                side_effect=close_formal,
            ),
            mock.patch.object(
                LockedExactRuntimeControllerToolingObservation,
                "close",
                autospec=True,
                side_effect=close_tooling,
            ),
            mock.patch.object(
                LockedExactRuntimeCanaryInput,
                "_release_live_observation",
                autospec=True,
                side_effect=release_live,
            ),
        ):
            self.live._close_from_canary(self.canary)  # noqa: SLF001
        self.assertEqual(["formal", "tooling", "live_release"], events)
        self.assertEqual("closed", locked._state)  # noqa: SLF001
        self.assertIsNone(self.live._qualification)  # noqa: SLF001
        self.assertEqual("closed", self.live._state)  # noqa: SLF001

    def test_publish_failure_after_registration_releases_formal_dependent(self) -> None:
        product = qualification.ProductionLocalRuntimeQualificationProducer.load_exact_d()
        patches = self.patches()
        with (
            patches[0], patches[1], patches[2], patches[3], patches[4],
            patches[5], patches[6],
        ):
            aggregate = qualification._rebuild_aggregate(self.live)  # noqa: SLF001
        with mock.patch.object(
            qualification,
            "_rebuild_aggregate",
            side_effect=[
                aggregate,
                qualification.LocalRuntimeQualificationError(
                    "fixture post-registration rebuild drift"
                ),
            ],
        ), self.assertRaisesRegex(
            qualification.LocalRuntimeQualificationError,
            "post-registration",
        ):
            product.qualify(self.live)
        self.assertIsNone(self.live._qualification)  # noqa: SLF001


if __name__ == "__main__":
    unittest.main()
