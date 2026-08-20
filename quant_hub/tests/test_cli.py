from __future__ import annotations

import json

from typer.testing import CliRunner

from quant_hub.cli import app
from tests.helpers import SettingsTestCase


class CliTests(SettingsTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.source = self.archive / "命令行.md"
        self.source.write_text("# CLI\n\n只读导入。\n", encoding="utf-8")
        self.runner = CliRunner()

    def _common(self) -> list[str]:
        return [
            "--project-root",
            str(self.project),
            "--archive-root",
            str(self.archive),
            "--var-root",
            str(self.var),
        ]

    def test_init_and_snapshot_commands_emit_machine_json(self) -> None:
        initialized = self.runner.invoke(app, ["init", *self._common()])
        self.assertEqual(0, initialized.exit_code, initialized.output)
        init_payload = json.loads(initialized.stdout)
        self.assertEqual("qrh-cli-envelope/v1", init_payload["schema_version"])
        self.assertEqual("PASS", init_payload["status"])
        self.assertEqual([1, 2, 3, 4, 5, 6], init_payload["applied_migrations"])

        first = self.runner.invoke(app, ["archive-snapshot", "命令行.md", *self._common()])
        second = self.runner.invoke(app, ["archive-snapshot", "命令行.md", *self._common()])
        self.assertEqual(0, first.exit_code, first.output)
        self.assertEqual(0, second.exit_code, second.output)
        first_payload = json.loads(first.stdout)
        second_payload = json.loads(second.stdout)
        self.assertTrue(first_payload["run_created"])
        self.assertFalse(second_payload["run_created"])
        self.assertEqual(first_payload["run_id"], second_payload["run_id"])

        shown = self.runner.invoke(app, ["run-show", first_payload["run_id"], *self._common()])
        self.assertEqual(0, shown.exit_code, shown.output)
        shown_payload = json.loads(shown.stdout)
        self.assertEqual("succeeded", shown_payload["run"]["run_status"])
        self.assertEqual(1, len(shown_payload["steps"]))
        self.assertEqual(1, len(shown_payload["outbox_events"]))

        missing = self.runner.invoke(app, ["run-show", "run_" + "0" * 32, *self._common()])
        self.assertEqual(4, missing.exit_code)
        missing_payload = json.loads(missing.stdout)
        self.assertEqual("NOT_FOUND", missing_payload["status"])

    def test_snapshot_failure_uses_versioned_json_without_traceback(self) -> None:
        missing = self.runner.invoke(
            app,
            ["archive-snapshot", "missing.md", *self._common()],
        )
        self.assertEqual(5, missing.exit_code)
        payload = json.loads(missing.stdout)
        self.assertEqual("qrh-cli-envelope/v1", payload["schema_version"])
        self.assertEqual("ERROR", payload["status"])
        self.assertEqual("SourceBoundaryError", payload["error_type"])
        self.assertNotIn("Traceback", missing.output)

    def test_paper_lab_formal_commands_are_reachable_and_machine_readable(self) -> None:
        help_result = self.runner.invoke(app, ["paper-lab", "--help"])
        self.assertEqual(0, help_result.exit_code, help_result.output)
        for command in ("scan", "legacy-import", "components", "run", "publish", "query", "viewer"):
            self.assertIn(command, help_result.output)

        scan = self.runner.invoke(app, ["paper-lab", "scan", *self._common()])
        self.assertEqual(0, scan.exit_code, scan.output)
        scan_payload = json.loads(scan.stdout)
        self.assertEqual("PASS", scan_payload["status"])
        self.assertEqual("qrh-cli-envelope/v1", scan_payload["schema_version"])

        dry_run = self.runner.invoke(
            app, ["paper-lab", "run", "--dry-run", *self._common()]
        )
        self.assertEqual(0, dry_run.exit_code, dry_run.output)
        dry_payload = json.loads(dry_run.stdout)
        self.assertEqual("PASS", dry_payload["status"])
        self.assertTrue(dry_payload["dry_run"])

        query = self.runner.invoke(app, ["paper-lab", "query", *self._common()])
        self.assertEqual(0, query.exit_code, query.output)
        self.assertIn("No results.", query.stdout)
