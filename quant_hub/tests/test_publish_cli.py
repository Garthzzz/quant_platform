from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

from quant_hub.ops.publish import (
    CIResult,
    FrozenSources,
    GateResult,
    GitSnapshot,
    PublishActions,
    PublishCoordinator,
    PublishError,
    PublishFailed,
    PublishPipeline,
    PublishQueue,
    PublishRequest,
    PushResult,
    TransferResult,
    VMDeployResult,
    dry_run_plan,
    main,
)


SHA_A = "1" * 40
SHA_B = "2" * 40
SHA_C = "3" * 40
DIGEST = "a" * 64


class FakeActions:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.push_count = 0
        self.ci_sha = SHA_A
        self.started = threading.Event()
        self.release = threading.Event()
        self.block_first = False

    def bundle(self) -> PublishActions:
        return PublishActions(
            inspect_git=self.inspect,
            public_guard=self.public,
            local_test_gate=self.tests,
            freeze_sources=self.freeze,
            push_once=self.push,
            wait_exact_ci=self.ci,
            transport_candidate=self.transport,
            deploy_candidate=self.deploy,
        )

    def inspect(self, sha: str) -> GitSnapshot:
        self.calls.append(("inspect", sha))
        if self.block_first and sha == SHA_A:
            self.started.set()
            self.release.wait(timeout=5)
        return GitSnapshot(sha, "main", DIGEST, True)

    def public(self, snapshot: GitSnapshot) -> GateResult:
        self.calls.append(("public", snapshot.commit_sha))
        return GateResult("public-pass", snapshot.commit_sha, "pass")

    def tests(self, snapshot: GitSnapshot) -> GateResult:
        self.calls.append(("tests", snapshot.commit_sha))
        return GateResult("tests-pass", snapshot.commit_sha, "pass")

    def freeze(self, snapshot: GitSnapshot) -> FrozenSources:
        self.calls.append(("freeze", snapshot.commit_sha))
        return FrozenSources(
            "freeze-1", snapshot.commit_sha, "b" * 64, "release-1", "c" * 64
        )

    def push(self, sha: str) -> PushResult:
        self.calls.append(("push", sha))
        self.push_count += 1
        return PushResult(sha, "pushed")

    def ci(self, sha: str) -> CIResult:
        self.calls.append(("ci", sha))
        return CIResult(self.ci_sha if sha == SHA_A else sha, "success", "ci-1")

    def transport(self, candidate):
        self.calls.append(("transport", str(candidate["commit_sha"])))
        return TransferResult(str(candidate["candidate_manifest_sha256"]), "verified")

    def deploy(self, candidate):
        self.calls.append(("deploy", str(candidate["commit_sha"])))
        return VMDeployResult(
            str(candidate["candidate_manifest_sha256"]),
            "activated",
            "activation-1",
            "activation",
        )


class PublishPipelineTests(unittest.TestCase):
    def test_happy_path_is_fixed_order_and_pushes_exactly_once(self) -> None:
        fake = FakeActions()
        result = PublishPipeline(fake.bundle()).execute(
            PublishRequest("request-a", SHA_A, "2026-08-21T00:00:00Z")
        )
        self.assertEqual("activated", result.status)
        self.assertEqual(1, fake.push_count)
        self.assertEqual(
            ["inspect", "public", "tests", "freeze", "inspect", "push", "ci", "transport", "deploy"],
            [name for name, _ in fake.calls],
        )
        self.assertTrue(all(sha == SHA_A for _, sha in fake.calls))
        self.assertEqual(64, len(result.candidate_manifest_sha256))
        self.assertEqual("activate", result.deployment_mode)

    def test_default_publish_rejects_candidate_only_result(self) -> None:
        fake = FakeActions()

        def candidate_only(candidate):
            return VMDeployResult(
                str(candidate["candidate_manifest_sha256"]),
                "candidate_validated",
                "candidate-validation-1",
                "candidate_validation",
            )

        actions = fake.bundle()
        actions = PublishActions(**{**actions.__dict__, "deploy_candidate": candidate_only})
        with self.assertRaisesRegex(PublishError, "exact candidate identity"):
            PublishPipeline(actions).execute(
                PublishRequest("request-a", SHA_A, "2026-08-21T00:00:00Z")
            )

    def test_explicit_candidate_only_accepts_validation_but_not_activation(self) -> None:
        fake = FakeActions()

        def candidate_only(candidate):
            self.assertEqual("candidate_only", candidate["deployment_mode"])
            return VMDeployResult(
                str(candidate["candidate_manifest_sha256"]),
                "candidate_validated",
                "candidate-validation-1",
                "candidate_validation",
            )

        actions = fake.bundle()
        actions = PublishActions(**{**actions.__dict__, "deploy_candidate": candidate_only})
        result = PublishPipeline(actions).execute(
            PublishRequest(
                "request-a", SHA_A, "2026-08-21T00:00:00Z", "candidate_only"
            )
        )
        self.assertEqual("candidate_validated", result.status)
        self.assertEqual("candidate_only", result.deployment_mode)

    def test_exact_sha_ci_mismatch_stops_before_transport(self) -> None:
        fake = FakeActions()
        fake.ci_sha = SHA_B
        with self.assertRaisesRegex(PublishError, "another commit|exact commit"):
            PublishPipeline(fake.bundle()).execute(
                PublishRequest("request-a", SHA_A, "2026-08-21T00:00:00Z")
            )
        self.assertEqual(1, fake.push_count)
        self.assertNotIn("transport", [name for name, _ in fake.calls])
        self.assertNotIn("deploy", [name for name, _ in fake.calls])

    def test_failed_public_guard_performs_no_external_action(self) -> None:
        fake = FakeActions()

        def blocked(snapshot: GitSnapshot) -> GateResult:
            return GateResult("public-blocked", snapshot.commit_sha, "blocked")

        actions = fake.bundle()
        actions = PublishActions(**{**actions.__dict__, "public_guard": blocked})
        with self.assertRaisesRegex(PublishError, "public_guard did not pass"):
            PublishPipeline(actions).execute(
                PublishRequest("request-a", SHA_A, "2026-08-21T00:00:00Z")
            )
        self.assertEqual(0, fake.push_count)

    def test_transport_callback_cannot_mutate_frozen_candidate(self) -> None:
        fake = FakeActions()

        def mutating_transport(candidate):
            digest = str(candidate["candidate_manifest_sha256"])
            candidate["unexpected"] = "drift"
            return TransferResult(digest, "verified")

        actions = fake.bundle()
        actions = PublishActions(**{**actions.__dict__, "transport_candidate": mutating_transport})
        with self.assertRaisesRegex(PublishError, "schema is not closed"):
            PublishPipeline(actions).execute(
                PublishRequest("request-a", SHA_A, "2026-08-21T00:00:00Z")
            )
        self.assertNotIn("deploy", [name for name, _ in fake.calls])

    def test_tracked_tree_is_rechecked_before_push(self) -> None:
        fake = FakeActions()
        inspections = 0

        def drifting_inspect(sha: str) -> GitSnapshot:
            nonlocal inspections
            inspections += 1
            return GitSnapshot(sha, "main", DIGEST, inspections == 1)

        actions = fake.bundle()
        actions = PublishActions(**{**actions.__dict__, "inspect_git": drifting_inspect})
        with self.assertRaisesRegex(PublishError, "changed after local gates"):
            PublishPipeline(actions).execute(
                PublishRequest("request-a", SHA_A, "2026-08-21T00:00:00Z")
            )
        self.assertEqual(0, fake.push_count)


class PublishQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_running_is_not_cancelled_and_only_latest_pending_runs(self) -> None:
        fake = FakeActions()
        fake.block_first = True
        queue = PublishQueue(self.root / "publish-state")
        coordinator = PublishCoordinator(queue, PublishPipeline(fake.bundle()))
        first = PublishRequest("request-a", SHA_A, "2026-08-21T00:00:00Z")
        second = PublishRequest("request-b", SHA_B, "2026-08-21T00:00:01Z")
        third = PublishRequest("request-c", SHA_C, "2026-08-21T00:00:02Z")

        with ThreadPoolExecutor(max_workers=2) as pool:
            running = pool.submit(coordinator.submit_and_drain, first)
            self.assertTrue(fake.started.wait(timeout=3))
            self.assertEqual("pending", coordinator.submit_and_drain(second)["status"])
            self.assertEqual("pending", coordinator.submit_and_drain(third)["status"])
            self.assertEqual("superseded", queue.request(second.request_id)["status"])
            self.assertEqual(third.request_id, queue.request(second.request_id)["superseded_by"])
            self.assertEqual("running", queue.request(first.request_id)["status"])
            fake.release.set()
            self.assertEqual("succeeded", running.result(timeout=5)["status"])

        executed = [sha for name, sha in fake.calls if name == "inspect"]
        self.assertEqual([SHA_A, SHA_A, SHA_C, SHA_C], executed)
        self.assertEqual("succeeded", queue.request(third.request_id)["status"])
        events = [
            json.loads(path.read_text(encoding="utf-8"))
            for path in (self.root / "publish-state" / "audit").glob("*.json")
        ]
        replacement = [row for row in events if row["kind"] == "pending_superseded"]
        self.assertEqual(1, len(replacement))
        self.assertEqual("request-b", replacement[0]["fields"]["request_id"])

    def test_failure_is_terminal_and_no_error_message_or_secret_is_audited(self) -> None:
        fake = FakeActions()

        def dangerous(_: str) -> PushResult:
            raise RuntimeError("Bearer should-not-be-recorded")

        actions = fake.bundle()
        actions = PublishActions(**{**actions.__dict__, "push_once": dangerous})
        queue = PublishQueue(self.root / "publish-state")
        coordinator = PublishCoordinator(queue, PublishPipeline(actions))
        request = PublishRequest("request-a", SHA_A, "2026-08-21T00:00:00Z")
        with self.assertRaises(PublishFailed):
            coordinator.submit_and_drain(request)
        record = queue.request(request.request_id)
        self.assertEqual("failed", record["status"])
        self.assertEqual("push_once:RuntimeError", record["error"])
        self.assertNotIn(
            "should-not-be-recorded",
            "".join(path.read_text(encoding="utf-8") for path in self.root.rglob("*.json")),
        )


class PublishDryRunTests(unittest.TestCase):
    def test_dry_run_is_cwd_independent_and_executes_no_external_actions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary).resolve()
            subprocess.run(["git", "init", "-b", "main"], cwd=repository, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repository, check=True)
            subprocess.run(["git", "config", "user.name", "test"], cwd=repository, check=True)
            (repository / "tracked.txt").write_text("exact\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repository, check=True)
            subprocess.run(["git", "commit", "-m", "fixture"], cwd=repository, check=True, capture_output=True)
            old = Path.cwd()
            try:
                os.chdir(repository.parent)
                plan = dry_run_plan(repository)
            finally:
                os.chdir(old)
            self.assertEqual("validated", plan["status"])
            self.assertFalse(plan["external_actions_executed"])
            self.assertEqual(str(repository), plan["project_root"])
            self.assertEqual(7, len(plan["steps"]))

    def test_standalone_cli_refuses_non_dry_run(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            main(["--project-root", str(Path.cwd())])
        self.assertEqual(2, caught.exception.code)


if __name__ == "__main__":
    unittest.main()
