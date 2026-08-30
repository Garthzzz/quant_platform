from __future__ import annotations

import copy
import unittest

from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256
from quant_hub.ops.local_windows_endpoint_evidence import (
    EXACT_RUNTIME_ENDPOINT_SCHEMA,
    WINDOWS_ENDPOINT_OBSERVATION_SCHEMA,
    WINDOWS_ENDPOINT_OBSERVATION_SCOPE,
    WindowsEndpointEvidenceError,
    WindowsEndpointObservationEvidence,
    validate_windows_endpoint_observation,
)
from quant_hub.ops.local_windows_scm_process_evidence import (
    WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
    WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
    WindowsScmProcessObservationEvidence,
)


def _with_self_hash(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = identity_sha256(value)
    return value


def _scm_evidence(
    *,
    host_pid: int = 4100,
    host_creation_time: int = 100_000,
    child_pid: int = 4200,
    child_creation_time: int = 100_100,
) -> WindowsScmProcessObservationEvidence:
    release = {
        "release_id": "release-r1",
        "release_path": "D:\\quant\\quant_platform\\releases\\release-r1",
        "manifest_sha256": "a" * 64,
    }
    service = {
        "service_name": "QuantResearchHub",
        "status": {"process_id": host_pid},
    }
    host = {"pid": host_pid, "creation_time_100ns": host_creation_time}
    child = {"pid": child_pid, "creation_time_100ns": child_creation_time}
    document: dict[str, object] = {
        "schema_version": WINDOWS_SCM_PROCESS_OBSERVATION_SCHEMA,
        "evidence_scope": WINDOWS_SCM_PROCESS_OBSERVATION_SCOPE,
        "attempt_id": "attempt-1",
        "nonce": "deployment-nonce-1",
        "operation": "activation",
        "authorization_phase": "candidate_start_authorized",
        "role": "candidate",
        "start_nonce": "start-nonce-1",
        "authorization_sha256": "b" * 64,
        "scm_identity_sha256": "c" * 64,
        "state_identity_sha256": "d" * 64,
        "release": release,
        "service": service,
        "host": host,
        "child": child,
        "direct_child_topology": {},
        "observation_aggregate_sha256": "e" * 64,
        "result": "identity_observed_not_writer_qualified",
    }
    _with_self_hash(document, "evidence_sha256")
    return WindowsScmProcessObservationEvidence(canonical_bytes(document))


def _listener(*, owning_pid: int = 4200) -> dict[str, object]:
    return _with_self_hash(
        {
            "address_family": "AF_INET",
            "local_address": "0.0.0.0",
            "local_port": 8765,
            "state": "LISTEN",
            "owning_pid": owning_pid,
        },
        "listener_identity_sha256",
    )


def _response(
    *,
    host_pid: int = 4100,
    host_creation_time: int = 100_000,
    child_pid: int = 4200,
    child_creation_time: int = 100_100,
) -> dict[str, object]:
    return _with_self_hash(
        {
            "schema_version": EXACT_RUNTIME_ENDPOINT_SCHEMA,
            "status": "identity_claim_only",
            "probe_challenge": "1" * 48,
            "attempt_id": "attempt-1",
            "nonce": "deployment-nonce-1",
            "operation": "activation",
            "role": "candidate",
            "start_nonce": "start-nonce-1",
            "authorization_sha256": "b" * 64,
            "scm_identity_sha256": "c" * 64,
            "state_identity_sha256": "d" * 64,
            "release": {
                "release_id": "release-r1",
                "release_path": "D:\\quant\\quant_platform\\releases\\release-r1",
                "manifest_sha256": "a" * 64,
            },
            "service": {
                "service_name": "QuantResearchHub",
                "host_pid": host_pid,
                "host_creation_time_100ns": host_creation_time,
            },
            "child": {
                "child_pid": child_pid,
                "child_creation_time_100ns": child_creation_time,
            },
            "listener": {"local_address": "0.0.0.0", "local_port": 8765},
            "writer_lease": {
                "lease_id": "lease-attempt-1-candidate",
                "lease_nonce": "lease-nonce-1",
                "lease_epoch": 7,
                "lease_record_sha256": "f" * 64,
                "authority": "claim_not_independently_observed",
            },
        },
        "endpoint_claim_sha256",
    )


def _evidence(
    *,
    host_pid: int = 4100,
    host_creation_time: int = 100_000,
    child_pid: int = 4200,
    child_creation_time: int = 100_100,
) -> dict[str, object]:
    scm = _scm_evidence(
        host_pid=host_pid,
        host_creation_time=host_creation_time,
        child_pid=child_pid,
        child_creation_time=child_creation_time,
    ).as_dict()
    listener_before = _listener(owning_pid=child_pid)
    listener_after = copy.deepcopy(listener_before)
    response = _response(
        host_pid=host_pid,
        host_creation_time=host_creation_time,
        child_pid=child_pid,
        child_creation_time=child_creation_time,
    )
    probe = _with_self_hash(
        {
            "scheme": "http",
            "host": "127.0.0.1",
            "port": 8765,
            "path": "/deploymentz",
            "method": "GET",
            "challenge": "1" * 48,
            "status_code": 200,
            "content_type": "application/json",
            "content_length": len(canonical_bytes(response)),
            "body_sha256": identity_sha256(response),
            "response": response,
        },
        "probe_identity_sha256",
    )
    document: dict[str, object] = {
        "schema_version": WINDOWS_ENDPOINT_OBSERVATION_SCHEMA,
        "evidence_scope": WINDOWS_ENDPOINT_OBSERVATION_SCOPE,
        "scm_process_evidence_sha256": scm["evidence_sha256"],
        "attempt_id": "attempt-1",
        "nonce": "deployment-nonce-1",
        "operation": "activation",
        "role": "candidate",
        "start_nonce": "start-nonce-1",
        "state_identity_sha256": "d" * 64,
        "release": copy.deepcopy(scm["release"]),
        "listener_before": listener_before,
        "probe": probe,
        "listener_after": listener_after,
        "observation_aggregate_sha256": identity_sha256(
            [
                {"name": "scm_process", "sha256": scm["evidence_sha256"]},
                {"name": "listener_before", "sha256": listener_before["listener_identity_sha256"]},
                {"name": "probe", "sha256": probe["probe_identity_sha256"]},
                {"name": "listener_after", "sha256": listener_after["listener_identity_sha256"]},
            ]
        ),
        "result": "endpoint_observed_not_writer_qualified",
    }
    return _with_self_hash(document, "evidence_sha256")


def _rehash(document: dict[str, object]) -> None:
    probe = document["probe"]
    assert isinstance(probe, dict)
    response = probe["response"]
    assert isinstance(response, dict)
    response.pop("endpoint_claim_sha256", None)
    _with_self_hash(response, "endpoint_claim_sha256")
    probe["content_length"] = len(canonical_bytes(response))
    probe["body_sha256"] = identity_sha256(response)
    probe.pop("probe_identity_sha256", None)
    _with_self_hash(probe, "probe_identity_sha256")
    document["observation_aggregate_sha256"] = identity_sha256(
        [
            {"name": "scm_process", "sha256": document["scm_process_evidence_sha256"]},
            {
                "name": "listener_before",
                "sha256": document["listener_before"]["listener_identity_sha256"],  # type: ignore[index]
            },
            {"name": "probe", "sha256": probe["probe_identity_sha256"]},
            {
                "name": "listener_after",
                "sha256": document["listener_after"]["listener_identity_sha256"],  # type: ignore[index]
            },
        ]
    )
    document.pop("evidence_sha256", None)
    _with_self_hash(document, "evidence_sha256")


def _rehash_probe_and_document(document: dict[str, object]) -> None:
    probe = document["probe"]
    assert isinstance(probe, dict)
    probe.pop("probe_identity_sha256", None)
    _with_self_hash(probe, "probe_identity_sha256")
    document["observation_aggregate_sha256"] = identity_sha256(
        [
            {"name": "scm_process", "sha256": document["scm_process_evidence_sha256"]},
            {
                "name": "listener_before",
                "sha256": document["listener_before"]["listener_identity_sha256"],  # type: ignore[index]
            },
            {"name": "probe", "sha256": probe["probe_identity_sha256"]},
            {
                "name": "listener_after",
                "sha256": document["listener_after"]["listener_identity_sha256"],  # type: ignore[index]
            },
        ]
    )
    document.pop("evidence_sha256", None)
    _with_self_hash(document, "evidence_sha256")


class WindowsEndpointEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scm = _scm_evidence()

    def test_valid_closed_observation_is_typed_but_never_writer_qualified(self) -> None:
        typed = WindowsEndpointObservationEvidence.from_document(_evidence(), self.scm)
        self.assertEqual(WINDOWS_ENDPOINT_OBSERVATION_SCOPE, typed.as_dict()["evidence_scope"])
        self.assertEqual("endpoint_observed_not_writer_qualified", typed.as_dict()["result"])
        material = typed.as_dict()
        material.pop("evidence_sha256")
        self.assertEqual(identity_sha256(material), typed.evidence_sha256)
        self.assertEqual(canonical_bytes(typed.as_dict()), typed.canonical_bytes())

    def test_mapping_or_subclass_cannot_replace_typed_scm_evidence(self) -> None:
        with self.assertRaisesRegex(WindowsEndpointEvidenceError, "typed SCM"):
            validate_windows_endpoint_observation(_evidence(), self.scm.as_dict())  # type: ignore[arg-type]

        class Derived(WindowsScmProcessObservationEvidence):
            pass

        derived = Derived(self.scm.canonical_bytes())
        with self.assertRaisesRegex(WindowsEndpointEvidenceError, "typed SCM"):
            validate_windows_endpoint_observation(_evidence(), derived)

    def test_closed_schema_rejects_added_field_even_with_new_hash(self) -> None:
        document = _evidence()
        document["qualified"] = True
        document.pop("evidence_sha256")
        _with_self_hash(document, "evidence_sha256")
        with self.assertRaisesRegex(WindowsEndpointEvidenceError, "schema 不闭合"):
            validate_windows_endpoint_observation(document, self.scm)

    def test_endpoint_self_report_cannot_replace_observed_child(self) -> None:
        document = _evidence()
        response = document["probe"]["response"]  # type: ignore[index]
        response["child"]["child_pid"] = 9999  # type: ignore[index]
        _rehash(document)
        with self.assertRaisesRegex(WindowsEndpointEvidenceError, "process/listener identity"):
            validate_windows_endpoint_observation(document, self.scm)

    def test_listener_owner_must_be_observed_child(self) -> None:
        document = _evidence()
        before = document["listener_before"]
        assert isinstance(before, dict)
        before["owning_pid"] = 9999
        before.pop("listener_identity_sha256")
        _with_self_hash(before, "listener_identity_sha256")
        _rehash(document)
        with self.assertRaisesRegex(WindowsEndpointEvidenceError, "child 独占"):
            validate_windows_endpoint_observation(document, self.scm)

    def test_endpoint_cannot_self_grant_writer_lease(self) -> None:
        document = _evidence()
        lease = document["probe"]["response"]["writer_lease"]  # type: ignore[index]
        lease["authority"] = "writer_qualified"  # type: ignore[index]
        _rehash(document)
        with self.assertRaisesRegex(WindowsEndpointEvidenceError, "不得自授"):
            validate_windows_endpoint_observation(document, self.scm)

    def test_fully_resigned_bool_aliases_cannot_replace_exact_integer_identity(self) -> None:
        cases = (
            ("listener_before", "owning_pid", {"child_pid": 1}),
            ("listener_after", "owning_pid", {"child_pid": 1}),
            ("service", "host_pid", {"host_pid": 1}),
            ("service", "host_creation_time_100ns", {"host_creation_time": 1}),
            ("child", "child_pid", {"child_pid": 1}),
            ("child", "child_creation_time_100ns", {"child_creation_time": 1}),
        )
        for section, field, identity in cases:
            with self.subTest(section=section, field=field):
                scm = _scm_evidence(**identity)
                document = _evidence(**identity)
                if section.startswith("listener_"):
                    listener = document[section]
                    assert isinstance(listener, dict)
                    listener[field] = True
                    listener.pop("listener_identity_sha256")
                    _with_self_hash(listener, "listener_identity_sha256")
                else:
                    response = document["probe"]["response"]  # type: ignore[index]
                    response[section][field] = True  # type: ignore[index]
                _rehash(document)
                with self.assertRaisesRegex(
                    WindowsEndpointEvidenceError,
                    "正整数",
                ):
                    validate_windows_endpoint_observation(document, scm)

                valid = WindowsEndpointObservationEvidence.from_document(
                    _evidence(**identity),
                    scm,
                )
                self.assertEqual(
                    "endpoint_observed_not_writer_qualified",
                    valid.as_dict()["result"],
                )

    def test_all_other_endpoint_numeric_fields_reject_bool(self) -> None:
        mutations = (
            ("listener_before", "local_port"),
            ("listener_after", "local_port"),
            ("response_listener", "local_port"),
            ("writer_lease", "lease_epoch"),
            ("probe", "port"),
            ("probe", "status_code"),
            ("probe", "content_length"),
        )
        for section, field in mutations:
            with self.subTest(section=section, field=field):
                document = _evidence()
                probe = document["probe"]
                assert isinstance(probe, dict)
                if section in {"listener_before", "listener_after"}:
                    container = document[section]
                    assert isinstance(container, dict)
                    container[field] = True
                    container.pop("listener_identity_sha256")
                    _with_self_hash(container, "listener_identity_sha256")
                elif section == "response_listener":
                    probe["response"]["listener"][field] = True  # type: ignore[index]
                elif section == "writer_lease":
                    probe["response"]["writer_lease"][field] = True  # type: ignore[index]
                else:
                    _rehash(document)
                    probe = document["probe"]
                    assert isinstance(probe, dict)
                    probe[field] = True
                    _rehash_probe_and_document(document)
                if section not in {"probe"}:
                    _rehash(document)
                with self.assertRaises(WindowsEndpointEvidenceError):
                    validate_windows_endpoint_observation(document, self.scm)

    def test_noncanonical_body_length_or_hash_is_rejected(self) -> None:
        for field, value, message in (
            ("content_length", 1, "content_length"),
            ("body_sha256", "9" * 64, "body SHA-256"),
        ):
            with self.subTest(field=field):
                document = _evidence()
                probe = document["probe"]
                assert isinstance(probe, dict)
                probe[field] = value
                probe.pop("probe_identity_sha256")
                _with_self_hash(probe, "probe_identity_sha256")
                document.pop("evidence_sha256")
                _with_self_hash(document, "evidence_sha256")
                with self.assertRaisesRegex(WindowsEndpointEvidenceError, message):
                    validate_windows_endpoint_observation(document, self.scm)

    def test_challenge_and_upstream_hash_are_exact_bound(self) -> None:
        cases = (("challenge", "2" * 48, "challenge"),)
        for field, value, message in cases:
            with self.subTest(field=field):
                document = _evidence()
                probe = document["probe"]
                assert isinstance(probe, dict)
                probe[field] = value
                probe.pop("probe_identity_sha256")
                _with_self_hash(probe, "probe_identity_sha256")
                document.pop("evidence_sha256")
                _with_self_hash(document, "evidence_sha256")
                with self.assertRaisesRegex(WindowsEndpointEvidenceError, message):
                    validate_windows_endpoint_observation(document, self.scm)

        document = _evidence()
        document["scm_process_evidence_sha256"] = "8" * 64
        document.pop("evidence_sha256")
        _with_self_hash(document, "evidence_sha256")
        with self.assertRaisesRegex(WindowsEndpointEvidenceError, "upstream"):
            validate_windows_endpoint_observation(document, self.scm)


if __name__ == "__main__":
    unittest.main()
