from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from quant_hub.knowledge import ReferenceCompiler
from quant_hub.knowledge.semantic import (
    OUTPUT_SCHEMA_VERSION,
    ModelIdentityContract,
    ProviderIdentityEvidence,
    ProviderResponse,
    SemanticCompiler,
    SemanticJobStore,
)
from quant_hub.knowledge.semantic_cli import (
    SemanticCLIError,
    _execute_one_parent,
    _identity_contract,
    _overall_deadline_seconds,
    _provider,
    main,
)


def _contract() -> ModelIdentityContract:
    evidence = ProviderIdentityEvidence(
        requested_alias="deepseek-v4-pro",
        provider_revision="DeepSeek-V4-Pro-0813",
        evidence_url="https://api-docs.deepseek.example/models",
        evidence_sha256=hashlib.sha256(b"official evidence fixture").hexdigest(),
        observed_at="2026-08-21T00:00:00Z",
        confirmed=True,
    )
    return ModelIdentityContract.create(
        evidence,
        allowed_returned_models=("deepseek-v4-pro",),
        allowed_system_fingerprints=("fp-0813",),
    )


class _Provider:
    def generate(self, envelope):
        columns = envelope.source_data["span_columns"]
        span = next(
            dict(zip(columns, row, strict=True))
            for row in envelope.source_data["spans"]
            if "Rank IC" in dict(zip(columns, row, strict=True))["text"]
        )
        evidence = {"span_id": span["span_id"], "quote": span["text"].strip()}
        items = [
            {
                "kind": "summary",
                "text": "A faithful structured summary.",
                "evidence": [evidence],
                "applicability": {"market": ["fixture-market"]},
                "relation": None,
                "inference": True,
                "confidence": 0.8,
            },
            {
                "kind": "limitation",
                "text": "A candidate for rejection.",
                "evidence": [evidence],
                "applicability": {},
                "relation": None,
                "inference": True,
                "confidence": 0.7,
            },
            {
                "kind": "method",
                "text": "A relation candidate.",
                "evidence": [evidence],
                "applicability": {},
                "relation": {"type": "requires", "target_id": "kitm_missing"},
                "inference": True,
                "confidence": 0.6,
            },
        ]
        return ProviderResponse(
            response_id="resp-cli-fixture",
            created_at="2026-08-21T00:01:00Z",
            model="deepseek-v4-pro",
            system_fingerprint="fp-0813",
            output={"schema_version": OUTPUT_SCHEMA_VERSION, "items": items},
        )


class SemanticCLITests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "protected-workspace"
        self.workspace.mkdir()
        self.sources = self.root / "sources"
        self.sources.mkdir()
        self.source_text = (
            "# Factor research\n\n"
            "Use Rank IC with rolling validation for factor selection.\n"
        )
        (self.sources / "factor.md").write_text(self.source_text, encoding="utf-8")
        report = ReferenceCompiler().compile(self.sources)
        assert report.candidate_snapshot is not None
        self.snapshot = report.candidate_snapshot
        self.release = self.root / "release-fixture"
        self.identity = self.root / "identity-fixture.json"
        self.identity.write_text(
            json.dumps({
                "schema_version": "qrh-deepseek-provider-identity-evidence/v1",
                "requested_alias": "deepseek-v4-pro",
                "official_evidence": {
                    "url": "https://api-docs.deepseek.example/models",
                    "observed_at": "2026-08-21T00:00:00Z",
                    "http_status": 200,
                    "response_bytes": 100,
                    "response_sha256": hashlib.sha256(b"official").hexdigest(),
                    "confirmed_mapping": (
                        "deepseek-v4-pro -> DeepSeek-V4-Pro-0813"
                    ),
                },
                "api_probe": {
                    "source_kind": "synthetic_non_sensitive_identity_probe",
                    "response_id": "response-fixture",
                    "response_created_at": "2026-08-21T00:00:00Z",
                    "returned_model": "deepseek-v4-pro",
                    "system_fingerprint": "fp-0813",
                    "output_schema": "qrh-knowledge-candidate-output/v1",
                    "item_count": 0,
                },
                "secret_handling": {
                    "credential_source": "fixture protected store",
                    "credential_logged": False,
                    "authorization_header_logged": False,
                    "credential_in_git_or_manifest": False,
                },
                "verdict": (
                    "identity_contract_may_pin_this_revision_model_fingerprint_pair"
                ),
            }),
            encoding="utf-8",
        )

    def _call(self, *arguments: str) -> tuple[int, dict[str, object]]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(["--workspace-root", str(self.workspace), *arguments])
        rows = output.getvalue().splitlines()
        self.assertEqual(1, len(rows))
        return code, json.loads(rows[0])

    def _patched(self):
        return (
            patch(
                "quant_hub.knowledge.semantic_cli._snapshot",
                return_value=self.snapshot,
            ),
            patch(
                "quant_hub.knowledge.semantic_cli._identity_contract",
                return_value=_contract(),
            ),
        )

    def test_plan_status_list_execute_review_accept_reject_and_targeted(self) -> None:
        snapshot_patch, identity_patch = self._patched()
        with snapshot_patch, identity_patch:
            code, planned = self._call(
                "plan",
                "--release-root", str(self.release),
                "--identity-evidence", str(self.identity),
            )
            self.assertEqual(0, code)
            self.assertEqual(1, len(planned["jobs"]))
            job_key = planned["jobs"][0]["job_key"]
            self.assertFalse(planned["source_text_included"])

            code, status = self._call("status")
            self.assertEqual(0, code)
            self.assertEqual({"queued": 1}, status["job_counts"])
            self.assertNotIn(self.source_text, json.dumps(status))

            with patch(
                "quant_hub.knowledge.semantic_cli._provider", return_value=_Provider()
            ):
                code, executed = self._call(
                    "execute-one",
                    "--release-root", str(self.release),
                    "--identity-evidence", str(self.identity),
                    "--job-key", job_key,
                    "--credential-source", "env",
                    "--_child-execution",
                )
            self.assertEqual(0, code)
            self.assertEqual("succeeded", executed["status"])
            self.assertEqual(180.0, executed["timeout_seconds"])
            self.assertNotIn(self.source_text, json.dumps(executed))

            code, candidates = self._call("list", "--kind", "candidates")
            self.assertEqual(0, code)
            self.assertEqual(3, len(candidates["rows"]))
            self.assertNotIn("A faithful structured summary", json.dumps(candidates))

            store = SemanticJobStore(self.workspace / "semantic_jobs.sqlite3")
            rows = store.candidates()
            accepted_candidate = next(row for row in rows if row.kind == "summary")
            rejected_candidate = next(row for row in rows if row.kind == "limitation")
            relation_candidate = next(row for row in rows if row.relation is not None)

            code, review = self._call(
                "review", "--candidate-id", accepted_candidate.candidate_id
            )
            self.assertEqual(0, code)
            self.assertFalse(review["candidate"]["includes_source_text"])
            self.assertIsInstance(review["candidate"]["text"], dict)
            self.assertNotIn(self.source_text, json.dumps(review))
            self.assertNotIn("fixture-market", json.dumps(review))

            code, accepted = self._call(
                "accept",
                "--release-root", str(self.release),
                "--candidate-id", accepted_candidate.candidate_id,
                "--actor", "reviewer-fixture",
                "--reason", "evidence checked in protected review UI",
            )
            self.assertEqual(0, code)
            self.assertEqual("human_reviewed", accepted["fact_status"])

            code, rejected = self._call(
                "reject",
                "--candidate-id", rejected_candidate.candidate_id,
                "--actor", "reviewer-fixture",
                "--reason", "candidate overstates the exact source",
            )
            self.assertEqual(0, code)
            self.assertEqual("rejected", rejected["fact_status"])

            code, failed_relation = self._call(
                "accept",
                "--release-root", str(self.release),
                "--candidate-id", relation_candidate.candidate_id,
                "--actor", "reviewer-fixture",
                "--reason", "relation target check",
            )
            self.assertEqual(2, code)
            self.assertEqual("error", failed_relation["status"])
            self.assertNotIn("kitm_missing", json.dumps(failed_relation))

            version_id = next(iter(self.snapshot.active_membership.values()))
            code, targeted = self._call(
                "targeted",
                "--release-root", str(self.release),
                "--identity-evidence", str(self.identity),
                "--version-id", version_id,
                "--reason", "prompt v2 adjudicated recompile",
            )
            self.assertEqual(0, code)
            self.assertEqual(1, len(targeted["jobs"]))

        audit = (self.workspace / "semantic_cli_audit.jsonl").read_text("utf-8")
        self.assertNotIn(self.source_text, audit)
        self.assertNotIn("evidence checked in protected review UI", audit)
        self.assertNotIn("candidate overstates the exact source", audit)
        self.assertNotIn("DEEPSEEK_API_KEY", audit)
        self.assertIn('"command":"execute-one"', audit)
        self.assertIn('"timeout_seconds":180.0', audit)

    def test_execute_provider_timeout_is_bounded_and_passed_through(self) -> None:
        def arguments(timeout_seconds: float) -> SimpleNamespace:
            return SimpleNamespace(
                credential_source="env",
                env_variable="QRH_TEST_DEEPSEEK_API_KEY",
                keyring_service=None,
                keyring_username=None,
                timeout_seconds=timeout_seconds,
            )

        default_provider = _provider(arguments(180.0))
        self.assertIn("timeout_seconds=180.0", repr(default_provider))
        self.assertIn("credential=<protected>", repr(default_provider))
        self.assertNotIn("QRH_TEST_DEEPSEEK_API_KEY", repr(default_provider))
        self.assertIn("timeout_seconds=10.0", repr(_provider(arguments(10.0))))
        self.assertIn("timeout_seconds=600.0", repr(_provider(arguments(600.0))))

        for invalid in (9.99, 600.01, float("nan"), float("inf")):
            with self.subTest(timeout_seconds=invalid):
                with self.assertRaises(SemanticCLIError):
                    _provider(arguments(invalid))

    def test_overall_deadline_is_part_aware_and_caps_multi_part_jobs(self) -> None:
        self.assertEqual(360, _overall_deadline_seconds(1))
        self.assertEqual(1080, _overall_deadline_seconds(3))
        self.assertEqual(1800, _overall_deadline_seconds(5))
        self.assertEqual(1800, _overall_deadline_seconds(100))
        with self.assertRaises(SemanticCLIError):
            _overall_deadline_seconds(0)

    def test_parent_terminates_fake_trickle_child_at_overall_deadline(self) -> None:
        store = SemanticJobStore(self.workspace / "semantic_jobs.sqlite3")
        compiler = SemanticCompiler(store, _contract())
        job = compiler.plan(self.snapshot).jobs[0]
        arguments = SimpleNamespace(
            job_key=job.job_key,
            workspace_root=self.workspace,
            release_root=self.release,
            identity_evidence=self.identity,
            credential_source="env",
            env_variable="QRH_TEST_DEEPSEEK_API_KEY",
            keyring_service=None,
            keyring_username=None,
            timeout_seconds=180.0,
        )

        def fake_trickle(*_args, **kwargs):
            store.set_job_status(job.job_key, "running")
            raise subprocess.TimeoutExpired(
                cmd="protected-child", timeout=kwargs["timeout"]
            )

        with patch(
            "quant_hub.knowledge.semantic_cli.subprocess.run",
            side_effect=fake_trickle,
        ) as process:
            value = _execute_one_parent(arguments, self.workspace, store)
        self.assertEqual("failed_retryable", value["status"])
        self.assertEqual("wall_clock_timeout", value["error_code"])
        self.assertEqual(360, value["overall_deadline_seconds"])
        self.assertEqual(
            "failed_retryable", store.job(job.job_key).status
        )
        self.assertEqual(
            (), store.items_for_versions((job.document_version_id,))
        )
        self.assertEqual(360, process.call_args.kwargs["timeout"])

    def test_parent_reconciles_nonzero_child_without_leaving_running_job(self) -> None:
        store = SemanticJobStore(self.workspace / "semantic_jobs.sqlite3")
        job = SemanticCompiler(store, _contract()).plan(self.snapshot).jobs[0]
        arguments = SimpleNamespace(
            job_key=job.job_key,
            workspace_root=self.workspace,
            release_root=self.release,
            identity_evidence=self.identity,
            credential_source="env",
            env_variable="QRH_TEST_DEEPSEEK_API_KEY",
            keyring_service=None,
            keyring_username=None,
            timeout_seconds=180.0,
        )

        def failed_child(*_args, **_kwargs):
            store.set_job_status(job.job_key, "running")
            return subprocess.CompletedProcess("protected-child", 2, "", "")

        with patch(
            "quant_hub.knowledge.semantic_cli.subprocess.run",
            side_effect=failed_child,
        ):
            with self.assertRaises(SemanticCLIError):
                _execute_one_parent(arguments, self.workspace, store)
        self.assertEqual("failed_retryable", store.job(job.job_key).status)
        self.assertEqual("worker_failed", store.job(job.job_key).error_code)

    def test_parent_disqualifies_success_with_invalid_child_output(self) -> None:
        store = SemanticJobStore(self.workspace / "semantic_jobs.sqlite3")
        compiler = SemanticCompiler(store, _contract())
        job = compiler.plan(self.snapshot).jobs[0]
        arguments = SimpleNamespace(
            job_key=job.job_key,
            workspace_root=self.workspace,
            release_root=self.release,
            identity_evidence=self.identity,
            credential_source="env",
            env_variable="QRH_TEST_DEEPSEEK_API_KEY",
            keyring_service=None,
            keyring_username=None,
            timeout_seconds=180.0,
        )
        generation = None

        def invalid_output(*_args, **_kwargs):
            nonlocal generation
            generation = compiler.execute(self.snapshot, job.job_key, _Provider())
            return subprocess.CompletedProcess(
                "protected-child", 0, "not-json", ""
            )

        with patch(
            "quant_hub.knowledge.semantic_cli.subprocess.run",
            side_effect=invalid_output,
        ):
            with self.assertRaises(SemanticCLIError):
                _execute_one_parent(arguments, self.workspace, store)
        assert generation is not None
        self.assertEqual("succeeded", store.job(job.job_key).status)
        self.assertIn(
            generation.generation_id, store.disqualified_generation_ids()
        )

    def test_exact_candidate_and_nonempty_actor_reason_are_fail_closed(self) -> None:
        # A read-only command does not initialize an absent database.
        code, missing = self._call("status")
        self.assertEqual(2, code)
        self.assertEqual("error", missing["status"])
        self.assertFalse((self.workspace / "semantic_jobs.sqlite3").exists())

        snapshot_patch, identity_patch = self._patched()
        with snapshot_patch, identity_patch:
            self._call(
                "plan",
                "--release-root", str(self.release),
                "--identity-evidence", str(self.identity),
            )
        code, value = self._call(
            "reject",
            "--candidate-id", "kcand_exact_missing",
            "--actor", "",
            "--reason", "",
        )
        self.assertEqual(2, code)
        self.assertEqual("error", value["status"])
        self.assertNotIn("kcand_exact_missing", json.dumps(value))

    def test_identity_evidence_parser_pins_official_revision_and_probe_pair(self) -> None:
        contract = _identity_contract(self.identity)
        self.assertEqual("DeepSeek-V4-Pro-0813", contract.expected_provider_revision)
        self.assertEqual(("deepseek-v4-pro",), contract.allowed_returned_models)
        self.assertEqual(("fp-0813",), contract.allowed_system_fingerprints)


if __name__ == "__main__":
    unittest.main()
