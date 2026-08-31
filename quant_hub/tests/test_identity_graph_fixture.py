from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from quant_hub.ops import identity_graph_fixture as fixture
from quant_hub.ops import release_closure as closure
from quant_hub.ops.local_release_identity import canonical_bytes, identity_sha256


def _write(path: Path, value: object) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = canonical_bytes(value)
    path.write_bytes(raw)
    return raw


def _later(value: str) -> str:
    parsed = datetime.fromisoformat(value[:-1] + "+00:00") + timedelta(seconds=1)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


class IdentityGraphFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        workspace = Path(__file__).resolve().parents[2]
        self._temporary = tempfile.TemporaryDirectory(dir=workspace)
        self.addCleanup(self._temporary.cleanup)
        self.root = Path(self._temporary.name).resolve()
        positive = fixture.fixed_corpus_document()["fixtures"][0]["input"]
        self.subject_paths = [
            "subject/active.json",
            "subject/binding.json",
            "subject/manifest-active.json",
            "subject/manifest-prior.json",
        ]
        _write(self.root / self.subject_paths[0], positive["active_release"])
        _write(self.root / self.subject_paths[1], positive["local_prior_binding"])
        _write(
            self.root / self.subject_paths[2], positive["release_manifests"][1]
        )
        _write(
            self.root / self.subject_paths[3], positive["release_manifests"][0]
        )
        (self.root / "inputs").mkdir()
        (self.root / "results").mkdir()
        (self.root / "observations").mkdir()
        (self.root / "gates").mkdir()

    @staticmethod
    def _ref(
        root: Path,
        relative: str,
        artifact_id: str,
        schema: str,
        observed_at: str,
    ) -> dict[str, object]:
        raw = (root / relative).read_bytes()
        return {
            "artifact_id": artifact_id,
            "relative_path": relative,
            "artifact_kind": "canonical_json",
            "schema_version": schema,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "observed_at": observed_at,
        }

    def _produce(self) -> dict[str, object]:
        return dict(
            fixture.write_fixed_d_report(
                evidence_root=self.root,
                subject_paths=self.subject_paths,
                corpus_output="inputs/identity-corpus.json",
                report_output="results/identity-report.json",
            )
        )

    def _observation(self, report: dict[str, object]) -> str:
        observed_at = str(report["produced_at"])
        schemas = []
        for relative in self.subject_paths:
            document = json.loads((self.root / relative).read_text(encoding="utf-8"))
            schemas.append(str(document["schema_version"]))
        subject_refs = sorted(
            [
                self._ref(
                    self.root,
                    relative,
                    f"subject-{index}",
                    schemas[index],
                    observed_at,
                )
                for index, relative in enumerate(self.subject_paths)
            ],
            key=lambda item: (item["artifact_id"], item["relative_path"]),
        )
        support_refs = [
            self._ref(
                self.root,
                "inputs/identity-corpus.json",
                "identity-corpus",
                fixture.CORPUS_SCHEMA,
                observed_at,
            )
        ]
        result_ref = self._ref(
            self.root,
            "results/identity-report.json",
            "identity-report",
            fixture.REPORT_SCHEMA,
            observed_at,
        )
        observation: dict[str, object] = {
            "schema_version": closure.GATE_OBSERVATION_SCHEMA,
            "observation_id": "observation-identity-graph",
            "gate_role": fixture.GATE_ROLE,
            "sealed_at": _later(observed_at),
            "result_artifact": result_ref,
            "subject_artifacts": subject_refs,
            "support_artifacts": support_refs,
        }
        observation["observation_sha256"] = identity_sha256(observation)
        relative = "observations/identity.json"
        _write(self.root / relative, observation)
        return relative

    def test_real_producer_and_release_closure_adapter_replay_every_fixture(self) -> None:
        report = self._produce()
        self.assertEqual(fixture.REPORT_SCHEMA, report["schema_version"])
        self.assertEqual(fixture.REPORT_AUTHORITY_SCOPE, report["authority_scope"])
        self.assertEqual(10, len(report["fixtures"]))
        self.assertEqual(
            {"accept", "reject"},
            {item["observed_result"] for item in report["fixtures"]},
        )
        relative = self._observation(report)
        evidence = closure.produce_gate_evidence_from_observation(
            self.root, relative
        )
        self.assertEqual(fixture.GATE_ROLE, evidence["gate_role"])
        self.assertEqual(
            {
                "schema_graph_hash_result": "pass",
                "negative_fixtures_rejected": True,
            },
            evidence["assertions"],
        )
        self.assertEqual(False, evidence["producer"]["independent"])

    def test_corpus_byte_drift_is_rejected_even_when_artifact_ref_is_resigned(self) -> None:
        report = self._produce()
        relative = self._observation(report)
        corpus_path = self.root / "inputs/identity-corpus.json"
        corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
        corpus["corpus_id"] = "local-release-identity-v1-drifted"
        corpus["corpus_payload_sha256"] = identity_sha256(
            {key: value for key, value in corpus.items() if key != "corpus_payload_sha256"}
        )
        corpus_raw = _write(corpus_path, corpus)
        observation_path = self.root / relative
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
        support = observation["support_artifacts"][0]
        support["sha256"] = hashlib.sha256(corpus_raw).hexdigest()
        support["size_bytes"] = len(corpus_raw)
        observation["observation_sha256"] = identity_sha256(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )
        _write(observation_path, observation)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "corpus bytes/hash"):
            closure.produce_gate_evidence_from_observation(self.root, relative)

    def test_reversed_outcome_is_rejected_after_report_is_fully_resigned(self) -> None:
        report = self._produce()
        report["fixtures"][0]["observed_result"] = "reject"
        report["fixtures"][0]["observed_graph_sha256"] = None
        report["fixtures"][0]["error_kind"] = "ForgedError"
        report["report_sha256"] = identity_sha256(
            {key: value for key, value in report.items() if key != "report_sha256"}
        )
        report_raw = _write(self.root / "results/identity-report.json", report)
        relative = self._observation(report)
        observation_path = self.root / relative
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
        observation["result_artifact"]["sha256"] = hashlib.sha256(report_raw).hexdigest()
        observation["result_artifact"]["size_bytes"] = len(report_raw)
        observation["observation_sha256"] = identity_sha256(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )
        _write(observation_path, observation)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "现场 linter"):
            closure.produce_gate_evidence_from_observation(self.root, relative)

    def test_create_only_duplicate_and_path_escape_fail_closed(self) -> None:
        self._produce()
        with self.assertRaisesRegex(fixture.IdentityGraphFixtureError, "已存在"):
            self._produce()
        with self.assertRaisesRegex(closure.ReleaseClosureError, "relative path"):
            fixture.write_fixed_d_report(
                evidence_root=self.root,
                subject_paths=self.subject_paths,
                corpus_output="../escaped-corpus.json",
                report_output="results/new-report.json",
            )
        self.assertFalse((self.root.parent / "escaped-corpus.json").exists())

    def test_reparse_output_parent_is_rejected(self) -> None:
        target = self.root / "ordinary-target"
        target.mkdir()
        link = self.root / "linked-output"
        try:
            os.symlink(target, link, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"symlink creation unavailable: {error}")
        with self.assertRaisesRegex(closure.ReleaseClosureError, "symlink/reparse"):
            fixture.write_fixed_d_report(
                evidence_root=self.root,
                subject_paths=self.subject_paths,
                corpus_output="linked-output/corpus.json",
                report_output="linked-output/report.json",
            )

    def test_cli_success_and_managed_identity_wrapper_stays_exit_two(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            patch.object(closure, "_cli_evidence_root", return_value=self.root),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = fixture.main(
                [
                    "--evidence-root",
                    str(self.root),
                    *sum((["--subject", value] for value in self.subject_paths), []),
                    "--corpus-output",
                    "inputs/identity-corpus.json",
                    "--report-output",
                    "results/identity-report.json",
                ]
            )
        self.assertEqual(0, code)
        self.assertEqual("", stderr.getvalue())
        self.assertEqual(fixture.REPORT_SCHEMA, json.loads(stdout.getvalue())["schema_version"])

    def test_report_schema_is_closed(self) -> None:
        report = self._produce()
        relative = self._observation(report)
        report["claimed_authoritative"] = True
        report["report_sha256"] = identity_sha256(
            {key: value for key, value in report.items() if key != "report_sha256"}
        )
        report_raw = _write(self.root / "results/identity-report.json", report)
        observation_path = self.root / relative
        observation = json.loads(observation_path.read_text(encoding="utf-8"))
        observation["result_artifact"]["sha256"] = hashlib.sha256(report_raw).hexdigest()
        observation["result_artifact"]["size_bytes"] = len(report_raw)
        observation["observation_sha256"] = identity_sha256(
            {key: value for key, value in observation.items() if key != "observation_sha256"}
        )
        _write(observation_path, observation)
        with self.assertRaisesRegex(closure.ReleaseClosureError, "schema 不闭合"):
            closure.produce_gate_evidence_from_observation(self.root, relative)


if __name__ == "__main__":
    unittest.main()
