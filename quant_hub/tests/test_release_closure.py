from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.ops import release_closure as closure
from quant_hub.ops.local_release_identity import (
    ACTIVE_RELEASE_SCHEMA,
    LOCAL_PRIOR_BINDING_SCHEMA,
    LOCAL_STATE_IDENTITY_SCHEMA,
    RELEASE_MANIFEST_SCHEMA,
    canonical_bytes,
    identity_sha256,
)


def _seal(value: dict[str, object], field: str) -> dict[str, object]:
    value[field] = identity_sha256(value)
    return value


def _release(release_id: str, character: str) -> dict[str, object]:
    inventory = {
        "schema_version": "qrh-release-file-inventory/v2",
        "files": [{"path": "app/package.json", "bytes": 64, "sha256": character * 64}],
    }
    return {
        "schema_version": RELEASE_MANIFEST_SCHEMA,
        "release_id": release_id,
        "built_at": "2026-08-30T22:00:00Z",
        "application": {
            "source_kind": "git",
            "commit_sha": character * 40,
            "tracked_tree_sha256": character * 64,
            "build_tool_version": "closure-tests/v1",
            "provenance": {"builder": "managed-test", "labels": []},
        },
        "content": {
            "snapshot_id": f"ksnap-{release_id}",
            "source_inventory_sha256": "1" * 64,
            "ir_sha256": "2" * 64,
            "knowledge_sha256": "3" * 64,
            "search_sha256": "4" * 64,
            "page_projection_sha256": "5" * 64,
            "mcp_sha256": "6" * 64,
            "active_membership_sha256": "7" * 64,
            "knowledge_enrichment": {"status": "not_applicable"},
            "presentation": {"language": "zh-CN"},
        },
        "resources": {"inventory_sha256": identity_sha256(inventory)},
        "state": {
            "compatibility": {
                "comments": {"read": [1, 2], "write": [1, 2]},
                "research_workspace": {"read": [1, 2, 3], "write": [1, 2, 3]},
                "rollback_policy": "expand_only_no_down_migration",
            }
        },
        "inventory": inventory,
    }


def _release_ref(value: dict[str, object]) -> dict[str, object]:
    release_id = str(value["release_id"])
    return {
        "release_id": release_id,
        "release_path": rf"D:\quant\quant_platform\releases\{release_id}",
        "manifest_sha256": identity_sha256(value),
    }


_ACTIVE_MANIFEST = _release("release-r1", "a")
_PRIOR_MANIFEST = _release("release-r0", "b")
_ACTIVE_REF = _release_ref(_ACTIVE_MANIFEST)
_PRIOR_REF = _release_ref(_PRIOR_MANIFEST)
_STATE_IDENTITY = _seal(
    {
        "schema_version": LOCAL_STATE_IDENTITY_SCHEMA,
        "authority_id": "production-d-state",
        "state_path": r"D:\quant\quant_platform\state",
        "schema_versions": {"comments": 2, "research_workspace": 3},
    },
    "identity_sha256",
)
_PAIR = {"active": _ACTIVE_REF, "prior": _PRIOR_REF}
_ACTIVE_POINTER = {"schema_version": ACTIVE_RELEASE_SCHEMA, "release": _ACTIVE_REF}
_PRIOR_BINDING = _seal(
    {
        "schema_version": LOCAL_PRIOR_BINDING_SCHEMA,
        "binding_id": "binding-release-r1-release-r0",
        "recorded_at": "2026-08-30T22:10:00Z",
        "authority": "retention_evidence_only",
        "active": _ACTIVE_REF,
        "prior": _PRIOR_REF,
        "state_identity": _STATE_IDENTITY,
        "result": {
            "status": "bound",
            "pair_sha256": identity_sha256(_PAIR),
            "retained_release_count": 2,
            "state_policy": "expand_only_no_down_migration",
        },
    },
    "binding_sha256",
)
_SUBJECT = {
    "active_release": {
        "release_id": "release-r1",
        "manifest_sha256": _ACTIVE_REF["manifest_sha256"],
        "snapshot_id": "ksnap-release-r1",
    },
    "prior_release": {
        "release_id": "release-r0",
        "manifest_sha256": _PRIOR_REF["manifest_sha256"],
        "snapshot_id": "ksnap-release-r0",
    },
    "state_identity_sha256": _STATE_IDENTITY["identity_sha256"],
}


def _utc(minute: int) -> str:
    return f"2026-08-31T00:{minute:02d}:00.000000Z"


def _write_canonical(path: Path, value: object) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_bytes(value)
    path.write_bytes(raw)
    return raw


class ReleaseClosureTests(unittest.TestCase):
    def setUp(self) -> None:
        workspace = Path(__file__).resolve().parents[2]
        self._temporary = tempfile.TemporaryDirectory(dir=workspace)
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name)

    def _ref(
        self,
        relative: str,
        artifact_id: str,
        value: object,
        schema: str,
        *,
        observed_at: str = _utc(0),
    ) -> dict[str, object]:
        raw = _write_canonical(self.root / relative, value)
        return {
            "artifact_id": artifact_id,
            "relative_path": relative,
            "artifact_kind": "canonical_json",
            "schema_version": schema,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "observed_at": observed_at,
        }

    def _subject_refs(self) -> list[dict[str, object]]:
        refs = [
            self._ref(
                "subject/active-manifest.json",
                "subject-active-manifest",
                _ACTIVE_MANIFEST,
                RELEASE_MANIFEST_SCHEMA,
            ),
            self._ref(
                "subject/active-pointer.json",
                "subject-active-pointer",
                _ACTIVE_POINTER,
                ACTIVE_RELEASE_SCHEMA,
            ),
            self._ref(
                "subject/prior-binding.json",
                "subject-prior-binding",
                _PRIOR_BINDING,
                LOCAL_PRIOR_BINDING_SCHEMA,
            ),
            self._ref(
                "subject/prior-manifest.json",
                "subject-prior-manifest",
                _PRIOR_MANIFEST,
                RELEASE_MANIFEST_SCHEMA,
            ),
        ]
        return sorted(refs, key=lambda item: (item["artifact_id"], item["relative_path"]))

    def _managed_observation(
        self, role: str = "full_replay_and_comment_lifecycle"
    ) -> tuple[str, dict[str, object]]:
        subject_refs = self._subject_refs()
        support = self._ref(
            f"inputs/{role}.json",
            f"input-{role}",
            {
                "schema_version": "qrh-test-bottom-machine-report/v1",
                "raw_machine_output": "not-authoritative-by-itself",
            },
            "qrh-test-bottom-machine-report/v1",
        )
        support_refs = [support]
        input_refs = sorted(
            [*subject_refs, *support_refs],
            key=lambda item: (item["artifact_id"], item["relative_path"]),
        )
        result_relative = f"results/{role}.json"
        authority = closure._MANAGED_AUTHORITIES[role]  # noqa: SLF001
        observer_name = closure._MANAGED_OBSERVER_NAMES[authority]  # noqa: SLF001
        payload: dict[str, object] = {"claimed": "pass"}
        result: dict[str, object] = {
            "schema_version": closure._MANAGED_RESULT_SCHEMAS[role],  # noqa: SLF001
            "result_id": f"result-{role}",
            "gate_role": role,
            "authority": authority,
            "observer": {"name": observer_name, "version": "1.0.0"},
            "execution": {
                "dispatch_id": f"dispatch-{role}",
                "command": [observer_name, role],
                "cwd": closure.EXACT_VM_PROJECT_ROOT,
                "executable_sha256": "9" * 64,
                "input_artifact_aggregate_sha256": hashlib.sha256(
                    canonical_bytes(input_refs)
                ).hexdigest(),
                "payload_sha256": hashlib.sha256(canonical_bytes(payload)).hexdigest(),
                "output_relative_path": result_relative,
                "started_at": _utc(1),
                "finished_at": _utc(2),
                "exit_code": 0,
            },
            "payload": payload,
        }
        result["result_sha256"] = hashlib.sha256(canonical_bytes(result)).hexdigest()
        result_ref = self._ref(
            result_relative,
            f"managed-result-{role}",
            result,
            str(result["schema_version"]),
            observed_at=_utc(2),
        )
        observation: dict[str, object] = {
            "schema_version": closure.GATE_OBSERVATION_SCHEMA,
            "observation_id": f"observation-{role}",
            "gate_role": role,
            "sealed_at": _utc(3),
            "result_artifact": result_ref,
            "subject_artifacts": subject_refs,
            "support_artifacts": support_refs,
        }
        observation["observation_sha256"] = hashlib.sha256(
            canonical_bytes(observation)
        ).hexdigest()
        relative = f"observations/{role}.json"
        _write_canonical(self.root / relative, observation)
        return relative, observation

    def test_subject_is_recomputed_from_actual_pointer_binding_and_manifests(self) -> None:
        refs = self._subject_refs()
        self.assertEqual(_SUBJECT, closure._subject_from_artifacts(self.root, refs))  # noqa: SLF001

        active_path = self.root / "subject/active-pointer.json"
        changed = json.loads(active_path.read_text(encoding="utf-8"))
        changed["release"]["release_id"] = "release-forged"
        _write_canonical(active_path, changed)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "active pointer|identity"):
            closure._subject_from_artifacts(self.root, refs)  # noqa: SLF001

    def test_old_self_report_and_dummy_primary_artifact_never_qualify(self) -> None:
        old = {
            "schema_version": "qrh-closure-gate-observation/v1",
            "observation_id": "old-self-report",
            "gate_role": "failure_and_incremental_matrix",
            "subject": _SUBJECT,
            "observed_at": _utc(3),
            "observer": {"name": "self", "version": "1", "independent": True},
            "facts": {"matrix_cases_total": 1, "matrix_cases_passed": 1, "silent_failures": 0},
            "artifacts": [],
        }
        old["observation_sha256"] = hashlib.sha256(canonical_bytes(old)).hexdigest()
        _write_canonical(self.root / "observations/old.json", old)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "schema 不闭合|不受支持"):
            closure.produce_gate_evidence_from_observation(self.root, "observations/old.json")

        relative, observation = self._managed_observation()
        result_ref = observation["result_artifact"]
        assert isinstance(result_ref, dict)
        result_path = self.root / str(result_ref["relative_path"])
        result = json.loads(result_path.read_text(encoding="utf-8"))
        result["schema_version"] = "qrh-dummy-pass/v1"
        result.pop("result_sha256")
        result["result_sha256"] = hashlib.sha256(canonical_bytes(result)).hexdigest()
        raw = _write_canonical(result_path, result)
        result_ref["schema_version"] = "qrh-dummy-pass/v1"
        result_ref["sha256"] = hashlib.sha256(raw).hexdigest()
        result_ref["size_bytes"] = len(raw)
        observation.pop("observation_sha256")
        observation["observation_sha256"] = hashlib.sha256(
            canonical_bytes(observation)
        ).hexdigest()
        _write_canonical(self.root / relative, observation)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "primary managed result schema"):
            closure.produce_gate_evidence_from_observation(self.root, relative)

    def test_managed_wrapper_is_explicitly_non_qualifying_without_real_adapter(self) -> None:
        for role, required in (
            (
                "full_replay_and_comment_lifecycle",
                "browser-sqlite-comment-replay-receipt",
            ),
            (
                "identity_graph_negative_fixtures",
                "identity-graph-fixture-report",
            ),
        ):
            with self.subTest(role=role):
                relative, _ = self._managed_observation(role)
                with self.assertRaisesRegex(
                    closure.ReleaseClosureError,
                    f"non-qualifying.*{required}",
                ):
                    closure.produce_gate_evidence_from_observation(self.root, relative)

    def test_cli_fails_closed_without_writing_gate_or_certificate(self) -> None:
        (self.root / "gates").mkdir()
        for index, role in enumerate(
            (
                "full_replay_and_comment_lifecycle",
                "identity_graph_negative_fixtures",
            )
        ):
            with self.subTest(role=role):
                relative, _ = self._managed_observation(role)
                output_relative = f"gates/should-not-exist-{index}.json"
                output = self.root / output_relative
                stdout = io.StringIO()
                stderr = io.StringIO()
                # The product CLI accepts only D:\quant\quant_platform.  Keep that
                # boundary covered separately, and isolate it here so this test reaches
                # the managed-adapter fail-closed branch on hosted checkout paths too.
                with (
                    patch.object(closure, "_cli_evidence_root", return_value=self.root),
                    redirect_stdout(stdout),
                    redirect_stderr(stderr),
                ):
                    code = closure.main(
                        [
                            "derive-gate",
                            "--evidence-root",
                            str(self.root),
                            "--observation",
                            relative,
                            "--output",
                            output_relative,
                        ]
                    )
                self.assertEqual(2, code)
                self.assertEqual("", stdout.getvalue())
                self.assertIn("non-qualifying", stderr.getvalue())
                self.assertFalse(output.exists())

    def test_cli_rejects_evidence_root_outside_exact_d_project(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = closure.main(
                    [
                        "verify-gate",
                        "--evidence-root",
                        outside,
                        "--gate",
                        "gate.json",
                    ]
                )
        self.assertEqual(2, code)
        self.assertIn("exact D project root", stderr.getvalue())

    def test_stage5_rejects_non_authoritative_real_mcp_replay(self) -> None:
        campaign = self.root / "campaigns/real-mcp"
        receipt = {
            "schema_version": "qrh-mcp-acceptance-campaign-receipt/v3-dispatch-replay",
            "fixture": "custody-only",
        }
        raw = _write_canonical(campaign / "campaign-receipt.json", receipt)
        report = {
            "schema_version": "qrh-mcp-real-acceptance-verification/v1",
            "status": "PASS",
            "authority": "REAL_CODEX_EVIDENCE_REPLAY_NON_AUTHORITATIVE",
            "run_id": "real-codex-test",
            "case_count": 2,
            "preregistration_sha256": "8" * 64,
            "campaign_receipt": str((campaign / "campaign-receipt.json").resolve()),
            "campaign_receipt_sha256": hashlib.sha256(raw).hexdigest(),
        }
        with patch(
            "quant_hub.knowledge_mcp.acceptance_cli.validate_real_acceptance_evidence_root",
            return_value=report,
        ) as verifier:
            with self.assertRaisesRegex(closure.ReleaseClosureError, "authoritative"):
                closure._validate_real_mcp_acceptance_evidence_root(  # noqa: SLF001
                    self.root, "campaigns/real-mcp"
                )
        verifier.assert_called_once_with(campaign.resolve())

    def test_tracked_schemas_align_with_runtime_v2_contract(self) -> None:
        relative, observation = self._managed_observation()
        self.assertTrue((self.root / relative).is_file())
        config_root = Path(__file__).resolve().parents[2] / "config"
        expected = {
            "release_closure_gate_observation.schema.json": closure.GATE_OBSERVATION_SCHEMA,
            "release_closure_gate_evidence.schema.json": closure.GATE_EVIDENCE_SCHEMA,
            "stage5_release_certificate.schema.json": closure.STAGE5_CERTIFICATE_SCHEMA,
            "visibility_closure_receipt.schema.json": closure.VISIBILITY_CLOSURE_SCHEMA,
        }
        for name, schema_version in expected.items():
            schema = json.loads((config_root / name).read_text(encoding="utf-8"))
            self.assertEqual(schema_version, schema["properties"]["schema_version"]["const"])
        observation_schema = json.loads(
            (config_root / "release_closure_gate_observation.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(set(observation_schema["required"]), set(observation))
        self.assertFalse(observation_schema["additionalProperties"])
        observation_roles = {
            item["if"]["properties"]["gate_role"]["const"]: item["then"]
            ["properties"]["result_artifact"]["properties"]["schema_version"]["const"]
            for item in observation_schema["allOf"]
        }
        self.assertEqual(closure._PRIMARY_RESULT_SCHEMAS, observation_roles)  # noqa: SLF001

        evidence_schema = json.loads(
            (config_root / "release_closure_gate_evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        evidence_roles = {
            item["if"]["properties"]["gate_role"]["const"]: item["then"]
            ["properties"]["assertions"]["$ref"].rsplit("/", 1)[-1]
            for item in evidence_schema["allOf"]
        }
        self.assertEqual(
            set((*closure.STAGE5_GATE_ROLES, *closure.STAGE6_GATE_ROLES)),
            set(evidence_roles),
        )
        runtime_assertions = {
            **closure._STAGE5_ASSERTIONS,  # noqa: SLF001
            **closure._STAGE6_ASSERTIONS,  # noqa: SLF001
        }
        for role, expected in runtime_assertions.items():
            assertion_schema = evidence_schema["$defs"][evidence_roles[role]]
            self.assertFalse(assertion_schema["additionalProperties"])
            self.assertEqual(set(expected), set(assertion_schema["required"]))
            valid: dict[str, object] = {}
            for field, wanted in expected.items():
                if not callable(wanted):
                    valid[field] = wanted
                elif field == "visibility_changed_at":
                    valid[field] = _utc(4)
                elif field == "candidate_release_id":
                    valid[field] = "release-candidate"
                elif field == "commit_sha":
                    valid[field] = "d" * 40
                else:
                    valid[field] = "e" * 64
            self.assertTrue(self._schema_assertions_accept(assertion_schema, valid))
            invalid = dict(valid)
            invalid["unexpected"] = True
            self.assertFalse(self._schema_assertions_accept(assertion_schema, invalid))
            wrong_value = dict(valid)
            first_field = next(iter(assertion_schema["required"]))
            first_contract = assertion_schema["properties"][first_field]
            wrong_value[first_field] = (
                "__invalid__"
                if isinstance(first_contract, dict) and "const" not in first_contract
                else "__wrong_const__"
            )
            self.assertFalse(
                self._schema_assertions_accept(assertion_schema, wrong_value)
            )

        stage5_schema = json.loads(
            (config_root / "stage5_release_certificate.schema.json").read_text(
                encoding="utf-8"
            )
        )
        stage5_roles = tuple(
            item["properties"]["gate_role"]["const"]
            for item in stage5_schema["properties"]["evidence"]["prefixItems"]
        )
        visibility_schema = json.loads(
            (config_root / "visibility_closure_receipt.schema.json").read_text(
                encoding="utf-8"
            )
        )
        visibility_roles = tuple(
            item["properties"]["gate_role"]["const"]
            for item in visibility_schema["properties"]["evidence"]["prefixItems"]
        )
        self.assertEqual(closure.STAGE5_GATE_ROLES, stage5_roles)
        self.assertEqual(closure.STAGE6_GATE_ROLES, visibility_roles)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "non-qualifying"):
            closure.produce_gate_evidence_from_observation(self.root, relative)

    @staticmethod
    def _schema_assertions_accept(
        schema: dict[str, object], instance: dict[str, object]
    ) -> bool:
        required = schema["required"]
        properties = schema["properties"]
        assert isinstance(required, list) and isinstance(properties, dict)
        if set(instance) != set(required):
            return False
        for field, value in instance.items():
            contract = properties[field]
            assert isinstance(contract, dict)
            if "const" in contract and value != contract["const"]:
                return False
            if "pattern" in contract and (
                not isinstance(value, str)
                or re.fullmatch(str(contract["pattern"]), value) is None
            ):
                return False
            if contract.get("type") == "string" and not isinstance(value, str):
                return False
            if "$ref" in contract:
                target = str(contract["$ref"])
                if target.endswith("/sha256") and (
                    not isinstance(value, str)
                    or re.fullmatch(r"(?!0{64}$)[0-9a-f]{64}", value) is None
                ):
                    return False
                if target.endswith("/id") and (
                    not isinstance(value, str)
                    or re.fullmatch(r"(?!.*\.\.)[A-Za-z0-9][A-Za-z0-9._-]{0,179}", value)
                    is None
                ):
                    return False
        return True


if __name__ == "__main__":
    unittest.main()
