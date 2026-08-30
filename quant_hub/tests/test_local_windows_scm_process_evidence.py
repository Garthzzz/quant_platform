from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import json
from typing import Iterator, cast
import unittest
from unittest.mock import patch

from quant_hub.ops import local_release_identity as identity
from quant_hub.ops.local_deployment_persistence import (
    LockedExactScmProcessObservationInput,
)
from quant_hub.ops.local_windows_scm_process_evidence import (
    WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
    WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    WindowsScmProcessEvidenceError,
    WindowsScmProcessObservationEvidence,
    validate_windows_scm_process_observation,
)
from tests.test_local_deployment_persistence import (
    PersistenceFixture,
    advance_one,
    history_to,
    journal,
    release,
    seal,
)


class WindowsScmProcessObservationEvidenceTests(PersistenceFixture):
    def setUp(self) -> None:
        super().setUp()
        self.r_minus_1 = release(
            "release-r-minus-1",
            self.payloads["release-r-minus-1"],
            "8",
            include_migrations=True,
        )
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r1 = release(
            "release-r1",
            self.payloads["release-r1"],
            "a",
            include_migrations=True,
        )
        for document in (self.r_minus_1, self.r0, self.r1):
            self.materialize(document)

    def install_scenario(
        self, *, operation: str, role: str, suffix: str
    ) -> tuple[list[dict[str, object]], str, str]:
        attempt = f"scm-observation-{operation}-{role}-{suffix}"
        nonce = f"nonce-scm-observation-{operation}-{role}-{suffix}"
        if operation == "bootstrap_first_pair":
            first = journal(
                None,
                self.r0,
                operation=operation,
                attempt=attempt,
                nonce=nonce,
            )
        else:
            first = journal(
                self.r0,
                self.r1,
                original_prior=self.r_minus_1,
                operation=operation,
                attempt=attempt,
                nonce=nonce,
            )
        history = history_to(first, "candidate_start_authorized")
        self.append_history(history)
        return history, attempt, nonce

    @contextmanager
    def bound_scenario(
        self, *, operation: str, role: str, suffix: str
    ) -> Iterator[
        tuple[
            LockedExactScmProcessObservationInput,
            list[dict[str, object]],
        ]
    ]:
        history, attempt, nonce = self.install_scenario(
            operation=operation, role=role, suffix=suffix
        )
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, attempt, nonce
            )
            closures = self.persistence.lock_exact_release_closures(
                lock, workspace
            )
            authorization = (
                self.persistence.lock_exact_transient_start_authorization(
                    lock, workspace, role
                )
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            try:
                yield inputs, history
            finally:
                closures.close()
                workspace.close()

    @contextmanager
    def bound_input(
        self, *, suffix: str
    ) -> Iterator[
        tuple[
            LockedExactScmProcessObservationInput,
            list[dict[str, object]],
        ]
    ]:
        with self.bound_scenario(
            operation="activation", role="candidate", suffix=suffix
        ) as result:
            yield result

    @staticmethod
    def reseal(document: dict[str, object]) -> None:
        raw_service = document["service"]
        raw_host = document["host"]
        raw_child = document["child"]
        raw_topology = document["direct_child_topology"]
        if not all(
            type(value) is dict
            for value in (raw_service, raw_host, raw_child, raw_topology)
        ):
            raise AssertionError("fixture observation material 类型漂移")
        service = cast(dict[str, object], raw_service)
        host = cast(dict[str, object], raw_host)
        child = cast(dict[str, object], raw_child)
        topology = cast(dict[str, object], raw_topology)
        seal(service, "service_identity_sha256")
        seal(host, "process_identity_sha256")
        seal(child, "process_identity_sha256")
        seal(topology, "topology_identity_sha256")
        document["observation_aggregate_sha256"] = identity.identity_sha256(
            [
                {
                    "name": "service",
                    "sha256": service["service_identity_sha256"],
                },
                {
                    "name": "host",
                    "sha256": host["process_identity_sha256"],
                },
                {
                    "name": "child",
                    "sha256": child["process_identity_sha256"],
                },
                {
                    "name": "direct_child_topology",
                    "sha256": topology["topology_identity_sha256"],
                },
            ]
        )
        seal(document, "evidence_sha256")

    @classmethod
    def document(
        cls, inputs: LockedExactScmProcessObservationInput
    ) -> dict[str, object]:
        host_pid = 4100
        volume_identity = "1" * 64
        service: dict[str, object] = {
            "service_name": inputs.service_name,
            "service_type": 16,
            "start_type": 2,
            "error_control": 1,
            "binary_path_argv": [inputs.service_executable],
            "service_start_name": "LocalSystem",
            "python_class": inputs.python_class,
            "status": {
                "current_state": 4,
                "controls_accepted": 1,
                "win32_exit_code": 0,
                "service_specific_exit_code": 0,
                "checkpoint": 0,
                "wait_hint_ms": 0,
                "process_id": host_pid,
                "service_flags": 0,
            },
        }
        host: dict[str, object] = {
            "pid": host_pid,
            "parent_pid": 720,
            "creation_time_100ns": 1_400_000,
            "executable_final_path": inputs.service_executable,
            "volume_identity_sha256": volume_identity,
            "file_identity_sha256": "2" * 64,
            "argv": [inputs.service_executable],
        }
        child: dict[str, object] = {
            "pid": 4101,
            "parent_pid": host_pid,
            "creation_time_100ns": 1_400_100,
            "executable_final_path": inputs.child_executable,
            "volume_identity_sha256": volume_identity,
            "file_identity_sha256": "3" * 64,
            "argv": list(inputs.child_argv),
        }
        evidence: dict[str, object] = {
            "schema_version": WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
            "evidence_scope": WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
            "attempt_id": inputs.attempt_id,
            "nonce": inputs.nonce,
            "operation": inputs.operation,
            "authorization_phase": (
                "prior_start_authorized"
                if inputs.role == "prior"
                else "candidate_start_authorized"
            ),
            "role": inputs.role,
            "start_nonce": inputs.start_nonce,
            "authorization_sha256": inputs.authorization_sha256,
            "scm_identity_sha256": inputs.scm_identity_sha256,
            "state_identity_sha256": inputs.state_identity_sha256,
            "release": dict(inputs.release_ref),
            "service": service,
            "host": host,
            "child": child,
            "direct_child_topology": {
                "host_pid": host_pid,
                "direct_child_pids": [child["pid"]],
            },
            "result": "identity_observed_not_writer_qualified",
        }
        cls.reseal(evidence)
        return evidence

    def test_valid_document_is_exact_bound_but_explicitly_not_qualified(
        self,
    ) -> None:
        with self.bound_input(suffix="valid") as (inputs, _history):
            document = self.document(inputs)
            validated = validate_windows_scm_process_observation(
                document, inputs
            )
            evidence = WindowsScmProcessObservationEvidence.from_document(
                document, inputs
            )
            self.assertEqual(document, validated)
            self.assertEqual(document, evidence.as_dict())
            self.assertEqual(
                identity.canonical_bytes(document), evidence.canonical_bytes()
            )
            self.assertEqual(document["evidence_sha256"], evidence.evidence_sha256)
            validated["attempt_id"] = "mutated"
            self.assertNotEqual("mutated", evidence.as_dict()["attempt_id"])
            self.assertEqual(
                "identity_observed_not_writer_qualified",
                evidence.as_dict()["result"],
            )
            for name in (
                "qualified",
                "writer_lease",
                "handle",
                "process_handle",
                "service_handle",
                "authorization",
            ):
                self.assertFalse(hasattr(evidence, name), name)
            self.assertEqual(
                document,
                json.loads(evidence.canonical_bytes().decode("utf-8")),
            )

    def assert_role_binding(self, operation: str, role: str) -> None:
        with self.bound_scenario(
            operation=operation,
            role=role,
            suffix="role-binding",
        ) as (inputs, _history):
            document = self.document(inputs)
            validated = validate_windows_scm_process_observation(
                document, inputs
            )
            self.assertEqual(operation, validated["operation"])
            self.assertEqual(role, validated["role"])
            self.assertEqual(inputs.release_ref, validated["release"])

    def test_activation_prior_role_binding(self) -> None:
        self.assert_role_binding("activation", "prior")

    def test_activation_candidate_role_binding(self) -> None:
        self.assert_role_binding("activation", "candidate")

    def test_rollback_prior_role_binding(self) -> None:
        self.assert_role_binding("rollback", "prior")

    def test_rollback_candidate_role_binding(self) -> None:
        self.assert_role_binding("rollback", "candidate")

    def test_bootstrap_baseline_role_binding(self) -> None:
        self.assert_role_binding("bootstrap_first_pair", "baseline")

    def test_fully_resigned_semantic_alias_and_topology_mutations_fail(
        self,
    ) -> None:
        with self.bound_input(suffix="semantic") as (inputs, _history):
            valid = self.document(inputs)

            def service(document: dict[str, object]) -> dict[str, object]:
                return document["service"]  # type: ignore[return-value]

            def status(document: dict[str, object]) -> dict[str, object]:
                return service(document)["status"]  # type: ignore[return-value]

            def host(document: dict[str, object]) -> dict[str, object]:
                return document["host"]  # type: ignore[return-value]

            def child(document: dict[str, object]) -> dict[str, object]:
                return document["child"]  # type: ignore[return-value]

            def topology(document: dict[str, object]) -> dict[str, object]:
                return document["direct_child_topology"]  # type: ignore[return-value]

            mutations = {
                "attempt relabel": lambda d: d.__setitem__(
                    "attempt_id", "scm-observation-other"
                ),
                "operation relabel": lambda d: d.__setitem__(
                    "operation", "rollback"
                ),
                "authorization phase": lambda d: d.__setitem__(
                    "authorization_phase", "prior_start_authorized"
                ),
                "release case alias": lambda d: d["release"].__setitem__(  # type: ignore[union-attr]
                    "release_path",
                    str(d["release"]["release_path"]).replace(  # type: ignore[index]
                        "quant_platform", "Quant_Platform"
                    ),
                ),
                "release NFKC alias": lambda d: d["release"].__setitem__(  # type: ignore[union-attr]
                    "release_id", "release－r1"
                ),
                "service name": lambda d: service(d).__setitem__(
                    "service_name", "QuantResearchHubAlias"
                ),
                "service type bool": lambda d: service(d).__setitem__(
                    "service_type", True
                ),
                "service start type bool": lambda d: service(d).__setitem__(
                    "start_type", True
                ),
                "service error control bool": lambda d: service(d).__setitem__(
                    "error_control", True
                ),
                "service executable case": lambda d: service(d).__setitem__(
                    "binary_path_argv",
                    [str(inputs.service_executable).replace("tooling", "Tooling")],
                ),
                "service stopped": lambda d: status(d).__setitem__(
                    "current_state", 1
                ),
                "service current state bool": lambda d: status(d).__setitem__(
                    "current_state", True
                ),
                "controls accepted bool": lambda d: status(d).__setitem__(
                    "controls_accepted", True
                ),
                "win32 exit bool": lambda d: status(d).__setitem__(
                    "win32_exit_code", False
                ),
                "service exit bool": lambda d: status(d).__setitem__(
                    "service_specific_exit_code", False
                ),
                "checkpoint bool": lambda d: status(d).__setitem__(
                    "checkpoint", False
                ),
                "wait hint bool": lambda d: status(d).__setitem__(
                    "wait_hint_ms", False
                ),
                "process ID bool": lambda d: status(d).__setitem__(
                    "process_id", True
                ),
                "service flags bool": lambda d: status(d).__setitem__(
                    "service_flags", False
                ),
                "service flags": lambda d: status(d).__setitem__(
                    "service_flags", 1
                ),
                "status host PID mismatch": lambda d: status(d).__setitem__(
                    "process_id", 9999
                ),
                "host self parent": lambda d: host(d).__setitem__(
                    "parent_pid", host(d)["pid"]
                ),
                "host executable case": lambda d: host(d).__setitem__(
                    "executable_final_path",
                    str(inputs.service_executable).replace("tooling", "Tooling"),
                ),
                "host argv": lambda d: host(d).__setitem__(
                    "argv", [inputs.service_executable, "--injected"]
                ),
                "child parent": lambda d: child(d).__setitem__(
                    "parent_pid", 8888
                ),
                "extra direct child": lambda d: topology(d).__setitem__(
                    "direct_child_pids", [child(d)["pid"], 4102]
                ),
                "foreign topology host": lambda d: topology(d).__setitem__(
                    "host_pid", 9999
                ),
                "child same PID": lambda d: child(d).__setitem__(
                    "pid", host(d)["pid"]
                ),
                "child predates host": lambda d: child(d).__setitem__(
                    "creation_time_100ns", 1
                ),
                "child executable case": lambda d: child(d).__setitem__(
                    "executable_final_path",
                    str(inputs.child_executable).replace("tooling", "Tooling"),
                ),
                "child argv reordered": lambda d: child(d).__setitem__(
                    "argv", list(reversed(child(d)["argv"]))
                ),
                "child foreign volume": lambda d: child(d).__setitem__(
                    "volume_identity_sha256", "4" * 64
                ),
                "same executable file identity": lambda d: child(d).__setitem__(
                    "file_identity_sha256", host(d)["file_identity_sha256"]
                ),
                "zero file identity": lambda d: child(d).__setitem__(
                    "file_identity_sha256", "0" * 64
                ),
                "qualification result": lambda d: d.__setitem__(
                    "result", "writer_qualified"
                ),
            }
            for label, mutate in mutations.items():
                candidate = deepcopy(valid)
                mutate(candidate)
                self.reseal(candidate)
                with self.subTest(label=label), self.assertRaises(
                    WindowsScmProcessEvidenceError
                ):
                    validate_windows_scm_process_observation(candidate, inputs)

    def test_closed_schema_nested_and_aggregate_hashes_fail_closed(self) -> None:
        with self.bound_input(suffix="closed") as (inputs, _history):
            valid = self.document(inputs)
            missing = deepcopy(valid)
            missing.pop("result")
            extra = deepcopy(valid)
            extra["writer_qualified"] = True
            wrong_scope = deepcopy(valid)
            wrong_scope["evidence_scope"] = "deployment_qualification"
            seal(wrong_scope, "evidence_sha256")
            nested = deepcopy(valid)
            nested["host"]["file_identity_sha256"] = "4" * 64  # type: ignore[index]
            seal(nested, "evidence_sha256")
            aggregate = deepcopy(valid)
            aggregate["observation_aggregate_sha256"] = "5" * 64
            seal(aggregate, "evidence_sha256")
            self_hash = deepcopy(valid)
            self_hash["evidence_sha256"] = "6" * 64
            for label, candidate in (
                ("missing", missing),
                ("extra", extra),
                ("scope", wrong_scope),
                ("nested", nested),
                ("aggregate", aggregate),
                ("self", self_hash),
            ):
                with self.subTest(label=label), self.assertRaises(
                    WindowsScmProcessEvidenceError
                ):
                    validate_windows_scm_process_observation(candidate, inputs)

    def test_fake_uninitialized_and_revoked_live_input_are_rejected(self) -> None:
        with self.bound_input(suffix="fake") as (inputs, history):
            document = self.document(inputs)
            for fake in (
                {},
                object(),
                object.__new__(LockedExactScmProcessObservationInput),
            ):
                with self.subTest(fake=type(fake)), self.assertRaises(
                    WindowsScmProcessEvidenceError
                ):
                    validate_windows_scm_process_observation(
                        document, fake  # type: ignore[arg-type]
                    )
            advanced = advance_one(history[-1])
            with patch.object(
                self.persistence.journals,
                "replay",
                return_value=(*history, advanced),
            ), self.assertRaisesRegex(
                WindowsScmProcessEvidenceError, "撤销|live"
            ):
                validate_windows_scm_process_observation(document, inputs)

        with self.assertRaisesRegex(
            WindowsScmProcessEvidenceError, "撤销|live"
        ):
            validate_windows_scm_process_observation(document, inputs)


if __name__ == "__main__":
    unittest.main()
