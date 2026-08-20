from __future__ import annotations

import json
from pathlib import Path
import subprocess

from quant_hub.paper_lab.database import paper_lab_connection
from quant_hub.paper_lab.executor import PaperLabCodexExecutor
from quant_hub.paper_lab.service import PaperLabService
from tests.helpers import SettingsTestCase


class PaperLabExecutorTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        drop = self.settings.paper_lab_drop_root
        drop.mkdir(parents=True, exist_ok=True)
        (drop / "1_executor.pdf").write_bytes(b"%PDF-1.4\nexecutor\n%%EOF")
        self.service = PaperLabService(self.settings)
        self.registration = self.service.register_all()[0]
        self.run = self.service.queue_reading(self.registration.paper_id)
        root = self.settings.paper_lab_asset_root.parent / "tasks"
        root.mkdir(parents=True, exist_ok=True)
        self.task_path = root / f"{self.run.run_id}.json"
        self.task_path.write_text(
            json.dumps({
                "schema_version": "paper-lab-codex-task/v1",
                "run_id": self.run.run_id,
                "paper_id": self.registration.paper_id,
                "paper_version_id": self.registration.paper_version_id,
                "workflow_version": "paper-reading/v1",
                "required_phases": ["problem", "method", "experiment", "synthesis"],
                "execution_contract": {"execute": "mock"},
                "status": "queued",
                "attempt": 1,
            }),
            encoding="utf-8",
        )
        with paper_lab_connection(self.settings) as connection:
            row = connection.execute(
                "SELECT content_sha256 FROM lab_paper_version WHERE paper_version_id=?",
                (self.registration.paper_version_id,),
            ).fetchone()
        self.content_sha256 = row["content_sha256"]

    def output_for(self, phase: str, *, run_id: str | None = None) -> dict[str, object]:
        return {
            "schema_version": "paper-reading-phase-output/v1",
            "run_id": run_id or self.run.run_id,
            "phase_key": phase,
            "result_kind": phase,
            "payload": {
                "summary": f"{phase} summary",
                "claims": [f"{phase} claim"],
                "limitations": [],
            },
            "evidence_locators": [{
                "paper_version_id": self.registration.paper_version_id,
                "content_sha256": self.content_sha256,
                "page": 1,
                "locator": "pdf-page:1",
                "excerpt": f"{phase} evidence",
            }],
        }

    @staticmethod
    def phase_and_output(command: list[str]) -> tuple[str, Path]:
        output = Path(command[command.index("-o") + 1])
        return output.name.split(".", 1)[0], output

    def test_dry_run_builds_read_only_commands_without_claim_or_cli(self) -> None:
        executor = PaperLabCodexExecutor(
            self.settings,
            runner=lambda *_args, **_kwargs: self.fail("runner must not execute"),
            which=lambda _name: self.fail("CLI lookup must not execute in dry-run"),
        )
        report = executor.execute(self.task_path, dry_run=True)
        self.assertEqual(report.status, "DRY_RUN")
        self.assertEqual(len(report.commands), 4)
        for command in report.commands:
            self.assertEqual(command[:4], ("codex", "exec", "--sandbox", "read-only"))
            self.assertIn("--skip-git-repo-check", command)
            self.assertIn("--output-schema", command)
            self.assertIn("-o", command)
        with paper_lab_connection(self.settings) as connection:
            status = connection.execute(
                "SELECT status FROM reading_run WHERE run_id=?", (self.run.run_id,)
            ).fetchone()[0]
        self.assertEqual(status, "queued")

    def test_missing_cli_fails_before_claim(self) -> None:
        executor = PaperLabCodexExecutor(
            self.settings,
            runner=lambda *_args, **_kwargs: self.fail("runner must not execute"),
            which=lambda _name: None,
        )
        report = executor.execute(self.task_path)
        self.assertEqual(report.status, "CLI_MISSING")
        with paper_lab_connection(self.settings) as connection:
            status = connection.execute(
                "SELECT status FROM reading_run WHERE run_id=?", (self.run.run_id,)
            ).fetchone()[0]
        self.assertEqual(status, "queued")

    def test_valid_structured_outputs_submit_four_phases_but_do_not_publish(self) -> None:
        calls: list[list[str]] = []

        def runner(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["capture_output"], True)
            phase, output = self.phase_and_output(command)
            output.write_text(json.dumps(self.output_for(phase)), encoding="utf-8")
            calls.append(command)
            return subprocess.CompletedProcess(command, 0, stdout="final", stderr="progress")

        report = PaperLabCodexExecutor(
            self.settings, runner=runner, which=lambda _name: "codex-mock",
        ).execute(self.task_path)
        self.assertEqual(report.status, "PASS")
        self.assertEqual(report.completed_phases, ("problem", "method", "experiment", "synthesis"))
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(call[:4] == ["codex-mock", "exec", "--sandbox", "read-only"] for call in calls))
        with paper_lab_connection(self.settings) as connection:
            status = connection.execute(
                "SELECT status FROM reading_run WHERE run_id=?", (self.run.run_id,)
            ).fetchone()[0]
            results = connection.execute(
                "SELECT count(*) FROM reading_result WHERE run_id=?", (self.run.run_id,)
            ).fetchone()[0]
        self.assertEqual(status, "awaiting_review")
        self.assertEqual(results, 4)
        replay = PaperLabCodexExecutor(
            self.settings,
            runner=lambda *_args, **_kwargs: self.fail("completed task must not rerun Codex"),
            which=lambda _name: self.fail("completed task must not resolve Codex"),
        ).execute(self.task_path)
        self.assertEqual(replay.status, "PASS")
        self.assertEqual(replay.commands, ())

    def test_timeout_is_retried_then_succeeds(self) -> None:
        calls = 0

        def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise subprocess.TimeoutExpired(command, 1)
            phase, output = self.phase_and_output(command)
            output.write_text(json.dumps(self.output_for(phase)), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        report = PaperLabCodexExecutor(
            self.settings, runner=runner, which=lambda _name: "codex-mock",
        ).execute(self.task_path, timeout_seconds=1, max_attempts=2)
        self.assertEqual(report.status, "PASS")
        self.assertEqual(report.attempts[0].outcome, "timeout")
        self.assertEqual(len(report.attempts), 5)

    def test_nonzero_exit_exhausts_retry_and_marks_run_failed(self) -> None:
        def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(command, 7, stdout="", stderr="failure")

        report = PaperLabCodexExecutor(
            self.settings, runner=runner, which=lambda _name: "codex-mock",
        ).execute(self.task_path, max_attempts=2)
        self.assertEqual(report.status, "FAILED")
        self.assertEqual(report.error_code, "codex_nonzero_exit")
        self.assertEqual(len(report.attempts), 2)
        with paper_lab_connection(self.settings) as connection:
            status, code = connection.execute(
                "SELECT status,error_code FROM reading_run WHERE run_id=?", (self.run.run_id,)
            ).fetchone()
        self.assertEqual((status, code), ("failed", "codex_nonzero_exit"))

    def test_invalid_output_exhausts_retry_and_never_submits(self) -> None:
        def runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            _phase, output = self.phase_and_output(command)
            output.write_text("{}", encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="{}", stderr="")

        report = PaperLabCodexExecutor(
            self.settings, runner=runner, which=lambda _name: "codex-mock",
        ).execute(self.task_path, max_attempts=2)
        self.assertEqual(report.status, "FAILED")
        self.assertEqual(report.error_code, "codex_invalid_output")
        with paper_lab_connection(self.settings) as connection:
            results = connection.execute(
                "SELECT count(*) FROM reading_result WHERE run_id=?", (self.run.run_id,)
            ).fetchone()[0]
        self.assertEqual(results, 0)

    def test_resume_inherits_verified_predecessor_and_starts_at_failed_phase(self) -> None:
        first_calls: list[str] = []

        def first_runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            phase, output = self.phase_and_output(command)
            first_calls.append(phase)
            if phase == "method":
                return subprocess.CompletedProcess(command, 9, stdout="", stderr="failed")
            output.write_text(json.dumps(self.output_for(phase)), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        failed = PaperLabCodexExecutor(
            self.settings,
            runner=first_runner,
            which=lambda _name: "codex-mock",
        ).execute(self.task_path, max_attempts=1)
        self.assertEqual(failed.status, "FAILED")
        self.assertEqual(failed.completed_phases, ("problem",))
        self.assertEqual(first_calls, ["problem", "method"])

        resumed = self.service.queue_reading(self.registration.paper_id, resume=True)
        self.assertEqual(resumed.attempt, 2)
        resumed_task = self.task_path.with_name(f"{resumed.run_id}.json")
        resumed_task.write_text(
            json.dumps({
                "schema_version": "paper-lab-codex-task/v1",
                "run_id": resumed.run_id,
                "paper_id": self.registration.paper_id,
                "paper_version_id": self.registration.paper_version_id,
                "workflow_version": "paper-reading/v1",
                "required_phases": ["problem", "method", "experiment", "synthesis"],
                "execution_contract": {"execute": "mock"},
                "status": "queued",
                "attempt": 2,
            }),
            encoding="utf-8",
        )
        dry = PaperLabCodexExecutor(self.settings).execute(resumed_task, dry_run=True)
        self.assertEqual(
            [Path(command[command.index("-o") + 1]).name.split(".", 1)[0] for command in dry.commands],
            ["method", "experiment", "synthesis"],
        )
        self.assertEqual(dry.completed_phases, ("problem",))

        with paper_lab_connection(self.settings) as connection:
            source = connection.execute(
                "SELECT result_id,artifact_sha256 FROM reading_result WHERE run_id=?",
                (self.run.run_id,),
            ).fetchone()
            inherited = connection.execute(
                "SELECT result_id,artifact_sha256 FROM reading_result WHERE run_id=?",
                (resumed.run_id,),
            ).fetchone()
            run_row = connection.execute(
                """
                SELECT resume_from_phase_key,input_revision_sha256
                FROM reading_run WHERE run_id=?
                """,
                (resumed.run_id,),
            ).fetchone()
            lineage = json.loads(connection.execute(
                """
                SELECT payload_json FROM paper_lab_event
                WHERE aggregate_id=? AND event_type='reading_phase_inherited'
                """,
                (resumed.run_id,),
            ).fetchone()[0])
        self.assertNotEqual(source["result_id"], inherited["result_id"])
        self.assertEqual(source["artifact_sha256"], inherited["artifact_sha256"])
        self.assertEqual(run_row["resume_from_phase_key"], "method")
        self.assertEqual(run_row["input_revision_sha256"], self.content_sha256)
        self.assertEqual(lineage["source_result_id"], source["result_id"])
        self.assertEqual(lineage["target_result_id"], inherited["result_id"])
        self.assertEqual(lineage["artifact_sha256"], source["artifact_sha256"])

        second_calls: list[str] = []

        def second_runner(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            phase, output = self.phase_and_output(command)
            second_calls.append(phase)
            output.write_text(
                json.dumps(self.output_for(phase, run_id=resumed.run_id)),
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        recovered = PaperLabCodexExecutor(
            self.settings,
            runner=second_runner,
            which=lambda _name: "codex-mock",
        ).execute(resumed_task, max_attempts=1)
        self.assertEqual(recovered.status, "PASS")
        self.assertEqual(
            recovered.completed_phases,
            ("problem", "method", "experiment", "synthesis"),
        )
        self.assertEqual(second_calls, ["method", "experiment", "synthesis"])
        with paper_lab_connection(self.settings) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT status FROM reading_run WHERE run_id=?", (resumed.run_id,)
                ).fetchone()[0],
                "awaiting_review",
            )
