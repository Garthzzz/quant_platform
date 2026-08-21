from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from quant_hub.ops.deployment import CandidateValidationError, DeploymentFailed
from quant_hub.ops.release_identity import manifest_sha256
from quant_hub.ops.vm_deploy_cli import (
    VMDeployCLIError,
    WindowsServiceRuntime,
    apply_publish,
    verify_runtime_environment,
)
from quant_hub.ops.vm_boundary import declared_production_vm_write_set
from quant_hub.runtime_seal import read_json

from tests.test_deployment_controller import (
    DeploymentFixture,
    write_partial,
)


CANDIDATE_HASH = "9" * 64
ENVIRONMENT = {
    "PYTHONDONTWRITEBYTECODE": "1",
    "TEMP": r"D:\quant\quant_platform\tmp\deployment-cli",
    "TMP": r"D:\quant\quant_platform\tmp\deployment-cli",
}


class Hooks:
    def __init__(
        self,
        *,
        health: bool = True,
        candidate_health: bool = True,
        candidate_browser: bool = True,
        candidate_api: bool = True,
        candidate_resource: bool = True,
    ) -> None:
        self.health = health
        self.candidate_health = candidate_health
        self.candidate_browser = candidate_browser
        self.candidate_api = candidate_api
        self.candidate_resource = candidate_resource
        self.started: list[str] = []
        self.stopped: list[str] = []

    def state_compatibility_probe(self, _release) -> bool:
        return True

    def candidate_probe(self, _path: Path, identity):
        return {
            "schema_version": "qrh-candidate-probe-evidence/v1",
            "release_id": identity["release_id"],
            "manifest_sha256": identity["manifest_sha256"],
            "snapshot_id": identity["snapshot_id"],
            "transport": "loopback_isolated",
            "writer_authority": "candidate-checkpoint-isolated",
            "health": self.candidate_health,
            "browser": self.candidate_browser,
            "api": self.candidate_api,
            "resource": self.candidate_resource,
            "state_isolated": True,
            "active_unchanged": True,
            "cleaned": True,
        }

    def start_release(self, path: Path, _active) -> bool:
        self.started.append(path.name)
        return True

    def stop_release(self, path: Path) -> None:
        self.stopped.append(path.name)

    def post_activation_probe(self, _path: Path, _active):
        return {
            "health": self.health,
            "critical_functions": True,
            "writer_fence": True,
        }


class VMDeployCLITests(unittest.TestCase):
    def test_real_start_callback_passes_exact_candidate_and_prior_journal_authorization(self) -> None:
        prior = self.fixture.finalize("release-prior", commit_character="a")
        candidate = self.fixture.finalize("release-next", commit_character="b")
        self.fixture.seed_prior(prior)
        protection = self.fixture.protect(
            prior, candidate, attempt_id="runtime-start-auth"
        )
        runtime = WindowsServiceRuntime(
            root=self.fixture.root, service_name="QuantResearchHub",
            base_url="http://127.0.0.1:8765", listen_host="0.0.0.0", port=8765,
            critical_paths=("/login",), writer_authority="D-active",
            service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
            application_source_relative_path="runtime_contract/code/src",
            archive_root_relative_path="reference/archive", var_root_relative_path="runtime",
            migration_root_relative_path="runtime_contract/migrations/platform",
            access_password_digest_path="state/viewer_access_password.digest",
            session_key_path="state/viewer_secret.key", comment_database_path="state/comments.sqlite3",
            workspace_database_path="state/research_workspace.sqlite3",
        )
        starts = []

        def service(_runtime, action, *, allow_failure=False, start_authorization=None):
            if action == "start":
                starts.append(start_authorization)
            return True

        with mock.patch.object(WindowsServiceRuntime, "_service", autospec=True, side_effect=service), mock.patch.object(
            WindowsServiceRuntime, "_get", autospec=True, return_value=(0, b"")
        ), mock.patch.object(
            WindowsServiceRuntime, "_deployment_identity", autospec=True,
            return_value=(True, True),
        ):
            with self.assertRaises(DeploymentFailed):
                self.fixture.controller.activate(
                    candidate_release_id="release-next",
                    deployment_attempt_id="runtime-start-auth",
                    recovery_protection_receipt_id=str(protection["receipt_id"]),
                    start_release=runtime.start_release,
                    stop_release=runtime.stop_release,
                    post_activation_probe=lambda _path, _active: {
                        "health": False, "critical_functions": True, "writer_fence": True,
                    },
                )
        self.assertEqual(
            ["candidate", "prior_recovery"],
            [authorization[0] for authorization in starts],
        )
        self.assertTrue(all(auth[1] == "runtime-start-auth" for auth in starts))
        self.assertTrue(all(len(auth[2]) == 48 for auth in starts))

    def setUp(self) -> None:
        self.fixture = DeploymentFixture()
        self.addCleanup(self.fixture.close)
        self.verify_root = lambda _path: self.fixture.root

    def apply(self, **arguments):
        return apply_publish(
            vm_root=Path(r"D:\quant\quant_platform"),
            publish_candidate_sha256=CANDIDATE_HASH,
            hooks=arguments.pop("hooks", Hooks()),
            root_verifier=self.verify_root,
            environment=ENVIRONMENT,
            **arguments,
        )

    def test_candidate_only_finalizes_and_writes_event_without_receipt_or_active_change(self) -> None:
        release = write_partial(
            self.fixture.controller,
            "release-candidate",
            {"app/main.py": b"candidate\n"},
            commit_character="c",
        )
        result = self.apply(
            release_id="release-candidate",
            release_manifest_sha256=manifest_sha256(release),
            deployment_mode="candidate_only",
        )
        self.assertEqual("candidate_validated", result["status"])
        self.assertEqual("candidate_validation_event", result["evidence_type"])
        self.assertFalse(self.fixture.controller.layout.active.exists())
        self.assertEqual([], list(self.fixture.controller.layout.audit_receipts.glob("*.json")))
        event = read_json(
            self.fixture.controller.layout.audit_events / f"{result['evidence_id']}.json"
        )
        self.assertEqual("evidence_only", event["authority"])
        self.assertEqual("candidate_validation_completed", event["kind"])
        self.assertFalse(event["fields"]["receipt_created"])
        self.assertTrue(event["fields"]["probe_evidence"]["cleaned"])
        self.assertEqual(
            "loopback_isolated",
            event["fields"]["probe_evidence"]["transport"],
        )

    def test_candidate_only_rejects_failed_isolated_runtime_probe(self) -> None:
        release = write_partial(
            self.fixture.controller,
            "release-candidate-bad-runtime",
            {"app/main.py": b"candidate\n"},
            commit_character="c",
        )
        for hooks in (
            Hooks(candidate_health=False),
            Hooks(candidate_browser=False),
            Hooks(candidate_api=False),
            Hooks(candidate_resource=False),
        ):
            with self.subTest(hooks=hooks), self.assertRaisesRegex(
                CandidateValidationError, "isolated candidate probe"
            ):
                self.apply(
                    release_id="release-candidate-bad-runtime",
                    release_manifest_sha256=manifest_sha256(release),
                    deployment_mode="candidate_only",
                    hooks=hooks,
                )
        self.assertFalse(self.fixture.controller.layout.active.exists())
        self.assertEqual([], list(self.fixture.controller.layout.audit_receipts.glob("*.json")))
        self.assertEqual([], list(
            self.fixture.controller.layout.audit_events.glob(
                "candidate_validation_completed-*.json"
            )
        ))

    def test_activation_requires_real_protection_and_returns_activation_receipt(self) -> None:
        prior = self.fixture.finalize("release-prior", commit_character="a")
        candidate = self.fixture.finalize("release-next", commit_character="b")
        self.fixture.seed_prior(prior)
        protection = self.fixture.protect(
            prior, candidate, attempt_id="publish-activate"
        )
        hooks = Hooks()
        result = self.apply(
            release_id="release-next",
            release_manifest_sha256=manifest_sha256(candidate),
            deployment_mode="activate",
            deployment_attempt_id="publish-activate",
            recovery_protection_receipt_id=str(protection["receipt_id"]),
            hooks=hooks,
        )
        self.assertEqual("activated", result["status"])
        self.assertEqual("activation_receipt", result["evidence_type"])
        receipt = read_json(
            self.fixture.controller.layout.audit_receipts / f"{result['evidence_id']}.json"
        )
        self.assertEqual("activation", receipt["receipt_type"])
        active, _ = self.fixture.controller.read_active()
        self.assertEqual("release-next", active["release_id"])

    def test_failed_probe_only_creates_failure_receipt_and_rolls_back(self) -> None:
        prior = self.fixture.finalize("release-prior", commit_character="a")
        candidate = self.fixture.finalize("release-next", commit_character="b")
        self.fixture.seed_prior(prior)
        protection = self.fixture.protect(prior, candidate, attempt_id="publish-fail")
        with self.assertRaises(DeploymentFailed) as caught:
            self.apply(
                release_id="release-next",
                release_manifest_sha256=manifest_sha256(candidate),
                deployment_mode="activate",
                deployment_attempt_id="publish-fail",
                recovery_protection_receipt_id=str(protection["receipt_id"]),
                hooks=Hooks(health=False),
            )
        failure = read_json(
            self.fixture.controller.layout.audit_receipts
            / f"{caught.exception.result.receipt_id}.json"
        )
        self.assertEqual("failure", failure["receipt_type"])
        receipts = [
            read_json(path)["receipt_type"]
            for path in self.fixture.controller.layout.audit_receipts.glob("*.json")
        ]
        self.assertEqual({"recovery_protection", "failure"}, set(receipts))
        active, _ = self.fixture.controller.read_active()
        self.assertEqual("release-prior", active["release_id"])

    def test_wrong_expected_manifest_fails_before_switch_or_terminal_receipt(self) -> None:
        prior = self.fixture.finalize("release-prior", commit_character="a")
        candidate = self.fixture.finalize("release-next", commit_character="b")
        self.fixture.seed_prior(prior)
        self.fixture.protect(prior, candidate, attempt_id="publish-wrong-hash")
        with self.assertRaisesRegex(CandidateValidationError, "manifest hash differs"):
            self.apply(
                release_id="release-next",
                release_manifest_sha256="8" * 64,
                deployment_mode="activate",
                deployment_attempt_id="publish-wrong-hash",
                recovery_protection_receipt_id="protection-publish-wrong-hash",
            )
        active, _ = self.fixture.controller.read_active()
        self.assertEqual("release-prior", active["release_id"])
        receipts = [
            read_json(path)["receipt_type"]
            for path in self.fixture.controller.layout.audit_receipts.glob("*.json")
        ]
        self.assertEqual(["recovery_protection"], receipts)

    def test_candidate_only_rejects_activation_authorization(self) -> None:
        release = self.fixture.finalize("release-candidate", commit_character="c")
        with self.assertRaisesRegex(VMDeployCLIError, "cannot carry"):
            self.apply(
                release_id="release-candidate",
                release_manifest_sha256=manifest_sha256(release),
                deployment_mode="candidate_only",
                deployment_attempt_id="attempt-not-allowed",
                recovery_protection_receipt_id="protection-not-allowed",
            )

    def test_runtime_environment_rejects_c_temp_or_bytecode(self) -> None:
        with self.assertRaises(VMDeployCLIError):
            verify_runtime_environment(
                Path(r"D:\quant\quant_platform"),
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "TEMP": r"C:\Temp",
                    "TMP": r"D:\quant\quant_platform\tmp",
                },
            )
        with self.assertRaisesRegex(VMDeployCLIError, "PYTHONPYCACHEPREFIX"):
            verify_runtime_environment(
                Path(r"D:\quant\quant_platform"),
                {
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "TEMP": r"D:\quant\quant_platform\tmp\deploy",
                    "TMP": r"D:\quant\quant_platform\tmp\deploy",
                    "PYTHONPYCACHEPREFIX": r"C:\Temp\pycache",
                },
            )

    def test_runtime_config_requires_the_exact_closed_production_write_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            control = root / "control"
            control.mkdir()
            value = {
                "schema_version": "qrh-vm-deploy-runtime/v1",
                "service_name": "QuantResearchHub",
                "base_url": "http://127.0.0.1:8765",
                "listen_host": "0.0.0.0",
                "port": 8765,
                "critical_paths": [
                    "/login", "/api/v1/research", "/api/v1/dashboard"
                ],
                "writer_authority": "D-active",
                "service_entry_relative_path": "tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
                "application_source_relative_path": "runtime_contract/code/src",
                "archive_root_relative_path": "reference/archive",
                "var_root_relative_path": "runtime",
                "migration_root_relative_path": "runtime_contract/migrations/platform",
                "access_password_digest_path": "state/viewer_access_password.digest",
                "session_key_path": "state/viewer_secret.key",
                "comment_database_path": "state/comments.sqlite3",
                "workspace_database_path": "state/research_workspace.sqlite3",
                "write_paths": list(declared_production_vm_write_set().values()),
            }
            path = control / "deployment_runtime.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            runtime = WindowsServiceRuntime.load(root)
            self.assertEqual(set(value["write_paths"]), {str(item) for item in runtime.write_paths})

            for replacement in (
                r"C:\temp",
                r"D:\quant",
                r"D:\quant\quant_platform_sibling\logs",
                r"D:\quant\quant_platform\reference",
            ):
                invalid = json.loads(json.dumps(value))
                invalid["write_paths"][-1] = replacement
                path.write_text(json.dumps(invalid), encoding="utf-8")
                with self.subTest(replacement=replacement), self.assertRaises(
                    VMDeployCLIError
                ):
                    WindowsServiceRuntime.load(root)

            invalid = json.loads(json.dumps(value))
            invalid["writer_authority"] = "C-legacy"
            path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaisesRegex(VMDeployCLIError, "writer authority"):
                WindowsServiceRuntime.load(root)

    def test_v39_state_compatibility_real_shape_and_closed_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            state = root / "state"
            state.mkdir()
            for name, version in (
                ("comments.sqlite3", 2),
                ("research_workspace.sqlite3", 3),
            ):
                with closing(sqlite3.connect(state / name)) as connection:
                    connection.execute(f"PRAGMA user_version={version}")
                    connection.commit()
            runtime = WindowsServiceRuntime(
                root=root,
                service_name="QuantResearchHub",
                base_url="http://127.0.0.1:8765",
                listen_host="0.0.0.0",
                port=8765,
                critical_paths=("/",),
                writer_authority="D-active",
                service_entry_relative_path="tooling/python/Lib/site-packages/quant_hub/ops/service_entry.py",
                application_source_relative_path="runtime_contract/code/src",
                archive_root_relative_path="reference/archive",
                var_root_relative_path="runtime",
                migration_root_relative_path="runtime_contract/migrations/platform",
                access_password_digest_path="state/viewer_access_password.digest",
                session_key_path="state/viewer_secret.key",
                comment_database_path="state/comments.sqlite3",
                workspace_database_path="state/research_workspace.sqlite3",
            )
            real_v39_shape = {
                "state": {
                    "compatibility": {
                        "comments": {"read": [1, 2], "write": [1, 2]},
                        "research_workspace": {
                            "read": [1, 2, 3],
                            "write": [1, 2, 3],
                        },
                        "rollback_policy": "expand_only_no_down_migration",
                    }
                }
            }
            self.assertTrue(runtime.state_compatibility_probe(real_v39_shape))
            self.assertFalse(any(state.glob("*.sqlite3-wal")))
            self.assertFalse(any(state.glob("*.sqlite3-shm")))

            wrong_policy = json.loads(json.dumps(real_v39_shape))
            wrong_policy["state"]["compatibility"]["rollback_policy"] = "down_migrate"
            self.assertFalse(runtime.state_compatibility_probe(wrong_policy))
            unknown = json.loads(json.dumps(real_v39_shape))
            unknown["state"]["compatibility"]["workspace"] = unknown["state"][
                "compatibility"
            ]["research_workspace"]
            self.assertFalse(runtime.state_compatibility_probe(unknown))
            missing = json.loads(json.dumps(real_v39_shape))
            del missing["state"]["compatibility"]["research_workspace"]
            self.assertFalse(runtime.state_compatibility_probe(missing))

    def test_online_copy_allows_normal_wal_writer_progress(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "comments.sqlite3"
            destination = root / "candidate.sqlite3"
            with closing(sqlite3.connect(source)) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("CREATE TABLE comment (id INTEGER PRIMARY KEY, body TEXT)")
                connection.execute("INSERT INTO comment(body) VALUES ('before')")
                connection.commit()
                before = WindowsServiceRuntime._sqlite_source_identity(source)
                self.assertIn("-wal", {row[0] for row in before})
                with mock.patch.object(
                    WindowsServiceRuntime,
                    "_sqlite_source_identity",
                    return_value=before,
                ) as identity:
                    WindowsServiceRuntime._online_copy(source, destination)
                # A live WAL source is protected by SQLite's snapshot backup,
                # not by requiring all production bytes to stop changing.
                identity.assert_called_once_with(source)
            with closing(sqlite3.connect(destination)) as copied:
                self.assertEqual(
                    [("before",)], copied.execute("SELECT body FROM comment").fetchall()
                )
        with self.assertRaises(VMDeployCLIError):
            verify_runtime_environment(
                Path(r"D:\quant\quant_platform"),
                {
                    "PYTHONDONTWRITEBYTECODE": "0",
                    "TEMP": r"D:\quant\quant_platform\tmp",
                    "TMP": r"D:\quant\quant_platform\tmp",
                },
            )


if __name__ == "__main__":
    unittest.main()
