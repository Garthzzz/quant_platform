from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from quant_hub.ops.deployment import (
    ActiveAuthorityCorrupt,
    CandidateValidationError,
    DeploymentController,
    DeploymentError,
    DeploymentFailed,
    DeploymentLocked,
    PendingActivationRecoveryRequired,
)
from quant_hub.ops.release_identity import manifest_sha256
from quant_hub.runtime_seal import read_json


ROOT = Path(__file__).resolve().parents[2]
H = {name: str(index) * 64 for index, name in enumerate(("tree", "source", "ir", "knowledge", "search", "state", "tools", "runbook", "operational"), start=1)}
H["operational"] = "a" * 64


def iso_before(seconds: int = 5) -> str:
    return (
        datetime.now(timezone.utc) - timedelta(seconds=seconds)
    ).isoformat().replace("+00:00", "Z")


def release_manifest(
    release_id: str, payloads: dict[str, bytes], *, commit_character: str
) -> dict[str, object]:
    files = [
        {
            "path": path,
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }
        for path, payload in sorted(payloads.items())
    ]
    inventory = {
        "schema_version": "qrh-release-file-inventory/v1",
        "files": files,
    }
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": release_id,
        "built_at": iso_before(30),
        "application": {
            "commit_sha": commit_character * 40,
            "tracked_tree_sha256": H["tree"],
            "build_tool_version": "deployment-tests/v1",
        },
        "content": {
            "snapshot_id": f"snapshot-{release_id}",
            "source_inventory_sha256": H["source"],
            "ir_sha256": H["ir"],
            "knowledge_sha256": H["knowledge"],
            "search_sha256": H["search"],
            "knowledge_enrichment": {"status": "not_applicable"},
        },
        "resources": {"inventory_sha256": manifest_sha256(inventory)},
        "state": {
            "compatibility": {
                "comments": {"read": [1], "write": [1]},
                "workspace": {"read": [1], "write": [1]},
            }
        },
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
        "inventory": inventory,
    }


def write_partial(
    controller: DeploymentController,
    release_id: str,
    payloads: dict[str, bytes],
    *,
    commit_character: str,
) -> dict[str, object]:
    partial = controller.partial_path(release_id)
    partial.mkdir(parents=True)
    for relative, payload in payloads.items():
        target = partial / Path(relative)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    release = release_manifest(
        release_id, payloads, commit_character=commit_character
    )
    (partial / "release_manifest.json").write_text(
        json.dumps(release, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return release


def checkpoint(
    checkpoint_id: str, captured_release: dict[str, object]
) -> dict[str, object]:
    return {
        "schema_version": "qrh-checkpoint-manifest/v1",
        "checkpoint_id": checkpoint_id,
        "captured_at": iso_before(15),
        "captured_under_active_release": {
            "release_id": captured_release["release_id"],
            "manifest_sha256": manifest_sha256(captured_release),
        },
        "state": {
            "authority_id": "state-d-authority",
            "inventory_sha256": H["state"],
            "database_count": 2,
        },
        "verification": {
            "integrity": True,
            "foreign_keys": True,
            "restorable": True,
        },
    }


def recovery_manifest(
    bundle_id: str,
    candidate_release: dict[str, object],
    state_checkpoint: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "qrh-recovery-manifest/v1",
        "bundle_id": bundle_id,
        "created_at": iso_before(10),
        "release": {
            "release_id": candidate_release["release_id"],
            "manifest_sha256": manifest_sha256(candidate_release),
        },
        "checkpoint": {
            "checkpoint_id": state_checkpoint["checkpoint_id"],
            "manifest_sha256": manifest_sha256(state_checkpoint),
        },
        "closure": {
            "inventory_sha256": candidate_release["resources"]["inventory_sha256"],
            "file_count": len(candidate_release["inventory"]["files"]),
            "total_bytes": sum(
                item["bytes"] for item in candidate_release["inventory"]["files"]
            ),
        },
        "compatibility": {"verdict": "compatible", "state_schema": 1},
        "restore": {
            "protocol_version": "qrh-restore/v1",
            "tool_inventory_sha256": H["tools"],
            "runbook_sha256": H["runbook"],
            "operational_bootstrap_sha256": H["operational"],
        },
        "no_secret_attestation": {
            "verdict": "pass",
            "scanner_version": "deployment-tests/v1",
        },
    }


def protection_receipt(
    attempt_id: str,
    candidate_release: dict[str, object],
    recovery: dict[str, object],
    state_checkpoint: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "qrh-recovery-protection-receipt/v1",
        "receipt_type": "recovery_protection",
        "receipt_id": f"protection-{attempt_id}",
        "deployment_attempt_id": attempt_id,
        "recorded_at": iso_before(2),
        "authority": "evidence_only",
        "release_manifest_sha256": manifest_sha256(candidate_release),
        "recovery_manifest_sha256": manifest_sha256(recovery),
        "checkpoint_manifest_sha256": manifest_sha256(state_checkpoint),
        "verdict": "protected",
        "pre_activation_verification": {
            "closure": True,
            "compatibility": True,
            "failure_domain": True,
            "no_secret": True,
            "active_pointer_switched": False,
        },
    }


class DeploymentFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.root = Path(self.temporary.name) / "D-root"
        self.controller = DeploymentController(self.root)

    def close(self) -> None:
        self.temporary.cleanup()

    def finalize(
        self, release_id: str, *, commit_character: str
    ) -> dict[str, object]:
        payloads = {
            "app/main.py": f"print('{release_id}')\n".encode(),
            "content/snapshot.json": json.dumps({"release": release_id}).encode(),
        }
        release = write_partial(
            self.controller,
            release_id,
            payloads,
            commit_character=commit_character,
        )
        self.controller.finalize_candidate(
            release_id, state_compatibility_probe=lambda _: True
        )
        return release

    def seed_prior(self, release: dict[str, object]) -> None:
        self.controller.replay_prior(
            prior_release_id=str(release["release_id"]),
            expected_manifest_sha256=manifest_sha256(release),
            start_release=lambda _path, _active: True,
            probe_release=lambda _path, _active: True,
        )

    def protect(
        self,
        prior: dict[str, object],
        candidate: dict[str, object],
        *,
        attempt_id: str,
    ) -> dict[str, object]:
        state_checkpoint = checkpoint(f"checkpoint-{attempt_id}", prior)
        recovery = recovery_manifest(
            f"bundle-{attempt_id}", candidate, state_checkpoint
        )
        receipt = protection_receipt(
            attempt_id, candidate, recovery, state_checkpoint
        )
        self.controller.record_recovery_protection(
            receipt=receipt,
            recovery_manifest=recovery,
            checkpoint_manifest=state_checkpoint,
            external_protection_probe=lambda _receipt, _rm, _checkpoint: True,
        )
        return receipt


class DeploymentControllerTests(unittest.TestCase):
    def test_pending_activation_crash_cuts_recover_prior_with_one_failure(self) -> None:
        for cut in ("before_pointer", "candidate_start", "post_probe", "receipt_append"):
            with self.subTest(cut=cut):
                fixture = DeploymentFixture()
                self.addCleanup(fixture.close)
                prior = fixture.finalize("release-r0", commit_character="a")
                candidate = fixture.finalize("release-r1", commit_character="b")
                fixture.seed_prior(prior)
                protection = fixture.protect(
                    prior, candidate, attempt_id=f"crash-{cut}"
                )
                original_write = fixture.controller._write_active
                original_append = fixture.controller._append_receipt

                def write(active):
                    if cut == "before_pointer" and active["release_id"] == "release-r1":
                        raise SystemExit("crash-before-pointer")
                    original_write(active)

                def start(path, _active):
                    if cut == "candidate_start" and path.name == "release-r1":
                        raise SystemExit("crash-candidate-start")
                    return True

                def probe(_path, _active):
                    if cut == "post_probe":
                        raise SystemExit("crash-post-probe")
                    return {
                        "health": True,
                        "critical_functions": True,
                        "writer_fence": True,
                    }

                def append(receipt):
                    if cut == "receipt_append" and receipt["receipt_type"] == "activation":
                        raise SystemExit("crash-receipt-append")
                    original_append(receipt)

                with mock.patch.object(fixture.controller, "_write_active", side_effect=write), mock.patch.object(
                    fixture.controller, "_append_receipt", side_effect=append
                ), self.assertRaises(SystemExit):
                    fixture.controller.activate(
                        candidate_release_id="release-r1",
                        deployment_attempt_id=f"crash-{cut}",
                        recovery_protection_receipt_id=str(protection["receipt_id"]),
                        start_release=start,
                        stop_release=lambda _path: None,
                        post_activation_probe=probe,
                    )
                self.assertTrue(fixture.controller.layout.pending_activation.is_file())
                with self.assertRaises(PendingActivationRecoveryRequired):
                    fixture.controller.read_active()
                restarted = DeploymentController(fixture.root)
                result = restarted.recover_pending_activation(
                    start_release=lambda _path, _active: True,
                    stop_release=lambda _path: None,
                )
                self.assertEqual("failed", result.status)
                self.assertFalse(restarted.layout.pending_activation.exists())
                active, _ = restarted.read_active()
                self.assertEqual("release-r0", active["release_id"])
                terminal = [
                    read_json(path)["receipt_type"]
                    for path in restarted.layout.audit_receipts.glob("*.json")
                    if read_json(path)["receipt_type"] in {"activation", "failure"}
                ]
                self.assertEqual(["failure"], terminal)

    def test_committed_activation_crash_only_cleans_journal_on_replay(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        protection = fixture.protect(prior, candidate, attempt_id="crash-cleanup")
        with mock.patch.object(
            fixture.controller,
            "_remove_pending_activation",
            side_effect=SystemExit("crash-after-activation-receipt"),
        ), self.assertRaises(SystemExit):
            fixture.controller.activate(
                candidate_release_id="release-r1",
                deployment_attempt_id="crash-cleanup",
                recovery_protection_receipt_id=str(protection["receipt_id"]),
                start_release=lambda _path, _active: True,
                stop_release=lambda _path: None,
                post_activation_probe=lambda _path, _active: {
                    "health": True, "critical_functions": True, "writer_fence": True,
                },
            )
        restarted = DeploymentController(fixture.root)
        result = restarted.recover_pending_activation(
            start_release=lambda _path, _active: self.fail("must not restart committed activation"),
            stop_release=lambda _path: self.fail("must not stop committed activation"),
        )
        self.assertEqual("activated", result.status)
        active, _ = restarted.read_active()
        self.assertEqual("release-r1", active["release_id"])
        terminal = [
            read_json(path)["receipt_type"]
            for path in restarted.layout.audit_receipts.glob("*.json")
            if read_json(path)["receipt_type"] in {"activation", "failure"}
        ]
        self.assertEqual(["activation"], terminal)

    def test_failure_receipt_cleanup_crash_reuses_same_receipt(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        protection = fixture.protect(prior, candidate, attempt_id="failure-cleanup")
        original_remove = fixture.controller._remove_pending_activation
        crashed = False

        def remove(journal):
            nonlocal crashed
            failure_exists = fixture.controller._receipt_path(
                str(journal["failure_receipt_id"])
            ).exists()
            if failure_exists and not crashed:
                crashed = True
                raise SystemExit("crash-after-failure-receipt")
            original_remove(journal)

        with mock.patch.object(
            fixture.controller, "_remove_pending_activation", side_effect=remove
        ), self.assertRaises(SystemExit):
            fixture.controller.activate(
                candidate_release_id="release-r1",
                deployment_attempt_id="failure-cleanup",
                recovery_protection_receipt_id=str(protection["receipt_id"]),
                start_release=lambda _path, _active: True,
                stop_release=lambda _path: None,
                post_activation_probe=lambda _path, _active: {
                    "health": False, "critical_functions": True, "writer_fence": True,
                },
            )
        restarted = DeploymentController(fixture.root)
        before = {
            path.name for path in restarted.layout.audit_receipts.glob("failure-*.json")
        }
        result = restarted.recover_pending_activation(
            start_release=lambda _path, _active: True,
            stop_release=lambda _path: None,
        )
        after = {
            path.name for path in restarted.layout.audit_receipts.glob("failure-*.json")
        }
        self.assertEqual(before, after)
        self.assertEqual({f"{result.receipt_id}.json"}, after)

    def test_pending_service_start_is_exact_role_attempt_phase_and_nonce(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        protection = fixture.protect(prior, candidate, attempt_id="service-auth")
        observed_roles = []

        def start(_path, active):
            with self.assertRaises(PendingActivationRecoveryRequired):
                fixture.controller.authorize_service_start(
                    active=active, authorization=None
                )
            authorization = fixture.controller.pending_service_start_authorization(active)
            fixture.controller.authorize_service_start(
                active=active, authorization=authorization
            )
            observed_roles.append(authorization[0] if authorization else None)
            return True

        with self.assertRaises(DeploymentFailed):
            fixture.controller.activate(
                candidate_release_id="release-r1",
                deployment_attempt_id="service-auth",
                recovery_protection_receipt_id=str(protection["receipt_id"]),
                start_release=start,
                stop_release=lambda _path: None,
                post_activation_probe=lambda _path, _active: {
                    "health": False, "critical_functions": True, "writer_fence": True,
                },
            )
        self.assertEqual(["candidate", "prior_recovery"], observed_roles)

    def test_failed_prior_restart_keeps_recovery_journal_for_replay(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        protection = fixture.protect(prior, candidate, attempt_id="retry-prior")

        def start(path, _active):
            return path.name == "release-r1"

        with self.assertRaises(DeploymentFailed) as caught:
            fixture.controller.activate(
                candidate_release_id="release-r1",
                deployment_attempt_id="retry-prior",
                recovery_protection_receipt_id=str(protection["receipt_id"]),
                start_release=start,
                stop_release=lambda _path: None,
                post_activation_probe=lambda _path, _active: {
                    "health": False, "critical_functions": True, "writer_fence": True,
                },
            )
        self.assertFalse(caught.exception.result.rollback_succeeded)
        self.assertTrue(fixture.controller.layout.pending_activation.is_file())
        with self.assertRaises(PendingActivationRecoveryRequired):
            fixture.controller.read_active()

        restarted = DeploymentController(fixture.root)
        result = restarted.recover_pending_activation(
            start_release=lambda _path, _active: True,
            stop_release=lambda _path: None,
        )
        self.assertEqual("failed", result.status)
        self.assertFalse(restarted.layout.pending_activation.exists())
        active, _ = restarted.read_active()
        self.assertEqual("release-r0", active["release_id"])

    def test_partial_finalizes_only_after_inventory_and_state_pass(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        release = write_partial(
            fixture.controller,
            "release-r0",
            {"app/main.py": b"print('r0')\n"},
            commit_character="a",
        )
        observed: list[str] = []
        final, digest = fixture.controller.finalize_candidate(
            "release-r0",
            state_compatibility_probe=lambda value: observed.append(
                str(value["release_id"])
            )
            is None,
        )
        self.assertEqual(["release-r0"], observed)
        self.assertEqual(manifest_sha256(release), digest)
        self.assertTrue(final.is_dir())
        self.assertFalse(fixture.controller.partial_path("release-r0").exists())
        self.assertTrue(fixture.controller.layout.state.is_dir())
        self.assertFalse(
            fixture.controller.layout.state.is_relative_to(
                fixture.controller.layout.releases
            )
        )

    def test_inventory_mismatch_and_probe_mutation_leave_partial_unfinalized(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        write_partial(
            fixture.controller,
            "release-bad-hash",
            {"app/main.py": b"original\n"},
            commit_character="b",
        )
        (fixture.controller.partial_path("release-bad-hash") / "app/main.py").write_bytes(
            b"tampered\n"
        )
        with self.assertRaisesRegex(CandidateValidationError, "inventory mismatch"):
            fixture.controller.finalize_candidate(
                "release-bad-hash", state_compatibility_probe=lambda _: True
            )
        self.assertTrue(fixture.controller.partial_path("release-bad-hash").is_dir())

        write_partial(
            fixture.controller,
            "release-probe-drift",
            {"app/main.py": b"stable\n"},
            commit_character="c",
        )

        def mutating_probe(_release: dict[str, object]) -> bool:
            target = fixture.controller.partial_path("release-probe-drift") / "app/main.py"
            target.write_bytes(b"changed-during-probe\n")
            return True

        with self.assertRaisesRegex(CandidateValidationError, "inventory mismatch"):
            fixture.controller.finalize_candidate(
                "release-probe-drift", state_compatibility_probe=mutating_probe
            )
        self.assertTrue(fixture.controller.partial_path("release-probe-drift").is_dir())

    def test_finalized_payload_tamper_is_rejected_on_every_deployment_read(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        release = fixture.finalize("release-r0", commit_character="a")
        (fixture.controller.release_path("release-r0") / "app/main.py").write_bytes(
            b"tampered-after-finalize\n"
        )
        with self.assertRaisesRegex(CandidateValidationError, "inventory mismatch"):
            fixture.controller.replay_prior(
                prior_release_id="release-r0",
                expected_manifest_sha256=manifest_sha256(release),
                start_release=lambda _path, _active: True,
                probe_release=lambda _path, _active: True,
            )

    def test_state_incompatibility_and_global_lock_fail_closed(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        write_partial(
            fixture.controller,
            "release-incompatible",
            {"app/main.py": b"payload\n"},
            commit_character="d",
        )
        with self.assertRaisesRegex(CandidateValidationError, "not compatible"):
            fixture.controller.finalize_candidate(
                "release-incompatible", state_compatibility_probe=lambda _: False
            )
        with fixture.controller.locked():
            with self.assertRaises(DeploymentLocked):
                fixture.controller.finalize_candidate(
                    "release-incompatible", state_compatibility_probe=lambda _: True
                )

    def test_success_activation_requires_existing_protection_then_writes_activation(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        protection = fixture.protect(
            prior, candidate, attempt_id="deploy-success"
        )
        starts: list[str] = []
        result = fixture.controller.activate(
            candidate_release_id="release-r1",
            deployment_attempt_id="deploy-success",
            recovery_protection_receipt_id=str(protection["receipt_id"]),
            start_release=lambda path, _active: starts.append(path.name) is None,
            stop_release=lambda _path: None,
            post_activation_probe=lambda _path, _active: {
                "health": True,
                "critical_functions": True,
                "writer_fence": True,
            },
        )
        self.assertEqual("activated", result.status)
        self.assertEqual(["release-r1"], starts)
        active, _ = fixture.controller.read_active()
        self.assertEqual("release-r1", active["release_id"])
        self.assertEqual(
            {"schema_version", "release_id", "release_path", "manifest_sha256"},
            set(active),
        )
        receipts = [read_json(path) for path in fixture.controller.layout.audit_receipts.glob("*.json")]
        self.assertEqual({"recovery_protection", "activation"}, {r["receipt_type"] for r in receipts})
        self.assertNotIn("failure", {r["receipt_type"] for r in receipts})
        activation_events = [
            read_json(path)
            for path in fixture.controller.layout.audit_events.glob("*.json")
            if read_json(path)["kind"] == "activation_receipt_authorized"
        ]
        self.assertEqual(1, len(activation_events))
        self.assertEqual(
            "release-r0", activation_events[0]["fields"]["prior_release_id"]
        )

    def test_post_activation_failure_restores_explicit_prior_and_only_writes_failure(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        protection = fixture.protect(prior, candidate, attempt_id="deploy-fail")
        starts: list[str] = []
        stops: list[str] = []
        with self.assertRaises(DeploymentFailed) as caught:
            fixture.controller.activate(
                candidate_release_id="release-r1",
                deployment_attempt_id="deploy-fail",
                recovery_protection_receipt_id=str(protection["receipt_id"]),
                start_release=lambda path, _active: starts.append(path.name) is None,
                stop_release=lambda path: stops.append(path.name),
                post_activation_probe=lambda _path, _active: {
                    "health": False,
                    "critical_functions": True,
                    "writer_fence": True,
                },
            )
        self.assertTrue(caught.exception.result.rollback_attempted)
        self.assertTrue(caught.exception.result.rollback_succeeded)
        self.assertEqual(["release-r1", "release-r0"], starts)
        self.assertEqual(["release-r1"], stops)
        active, _ = fixture.controller.read_active()
        self.assertEqual("release-r0", active["release_id"])
        receipts = [read_json(path) for path in fixture.controller.layout.audit_receipts.glob("*.json")]
        self.assertEqual({"recovery_protection", "failure"}, {r["receipt_type"] for r in receipts})

    def test_missing_protection_fails_before_switch_and_writes_no_activation(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        starts: list[str] = []
        with self.assertRaises(DeploymentFailed) as caught:
            fixture.controller.activate(
                candidate_release_id="release-r1",
                deployment_attempt_id="deploy-missing-protection",
                recovery_protection_receipt_id="missing-protection",
                start_release=lambda path, _active: starts.append(path.name) is None,
                stop_release=lambda _path: None,
                post_activation_probe=lambda _path, _active: {
                    "health": True,
                    "critical_functions": True,
                    "writer_fence": True,
                },
            )
        self.assertFalse(caught.exception.result.rollback_attempted)
        self.assertFalse(caught.exception.result.rollback_succeeded)
        self.assertEqual([], starts)
        active, _ = fixture.controller.read_active()
        self.assertEqual("release-r0", active["release_id"])
        receipts = [read_json(path) for path in fixture.controller.layout.audit_receipts.glob("*.json")]
        self.assertEqual(["failure"], [r["receipt_type"] for r in receipts])

    def test_candidate_start_failure_rolls_back_prior(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        protection = fixture.protect(prior, candidate, attempt_id="deploy-start-fail")
        starts: list[str] = []

        def start(path: Path, _active: dict[str, object]) -> bool:
            starts.append(path.name)
            return path.name == "release-r0"

        with self.assertRaises(DeploymentFailed) as caught:
            fixture.controller.activate(
                candidate_release_id="release-r1",
                deployment_attempt_id="deploy-start-fail",
                recovery_protection_receipt_id=str(protection["receipt_id"]),
                start_release=start,
                stop_release=lambda _path: None,
                post_activation_probe=lambda _path, _active: {
                    "health": True,
                    "critical_functions": True,
                    "writer_fence": True,
                },
            )
        self.assertTrue(caught.exception.result.rollback_succeeded)
        self.assertEqual(["release-r1", "release-r0"], starts)

    def test_pointer_switch_failure_restores_prior_and_records_only_failure(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        protection = fixture.protect(
            prior, candidate, attempt_id="deploy-pointer-fail"
        )
        original_write = fixture.controller._write_active
        failed_once = False

        def fail_candidate_once(value: dict[str, object]) -> None:
            nonlocal failed_once
            if value["release_id"] == "release-r1" and not failed_once:
                failed_once = True
                raise OSError("synthetic atomic replace failure")
            original_write(value)

        with mock.patch.object(
            fixture.controller, "_write_active", side_effect=fail_candidate_once
        ):
            with self.assertRaises(DeploymentFailed) as caught:
                fixture.controller.activate(
                    candidate_release_id="release-r1",
                    deployment_attempt_id="deploy-pointer-fail",
                    recovery_protection_receipt_id=str(protection["receipt_id"]),
                    start_release=lambda _path, _active: True,
                    stop_release=lambda _path: None,
                    post_activation_probe=lambda _path, _active: {
                        "health": True,
                        "critical_functions": True,
                        "writer_fence": True,
                    },
                )
        self.assertTrue(caught.exception.result.rollback_succeeded)
        failure = read_json(
            fixture.controller._receipt_path(caught.exception.result.receipt_id)
        )
        self.assertEqual("pointer_switch", failure["failed_phase"])
        active, _ = fixture.controller.read_active()
        self.assertEqual("release-r0", active["release_id"])

    def test_activation_receipt_persist_failure_rolls_back_and_only_failure_remains(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        protection = fixture.protect(
            prior, candidate, attempt_id="deploy-receipt-fail"
        )
        original_append = fixture.controller._append_receipt

        def fail_activation_only(receipt: dict[str, object]) -> None:
            if receipt["receipt_type"] == "activation":
                raise DeploymentError("synthetic activation receipt persistence failure")
            original_append(receipt)

        with mock.patch.object(
            fixture.controller, "_append_receipt", side_effect=fail_activation_only
        ):
            with self.assertRaises(DeploymentFailed) as caught:
                fixture.controller.activate(
                    candidate_release_id="release-r1",
                    deployment_attempt_id="deploy-receipt-fail",
                    recovery_protection_receipt_id=str(protection["receipt_id"]),
                    start_release=lambda _path, _active: True,
                    stop_release=lambda _path: None,
                    post_activation_probe=lambda _path, _active: {
                        "health": True,
                        "critical_functions": True,
                        "writer_fence": True,
                    },
                )
        self.assertEqual("activation_receipt", read_json(
            fixture.controller._receipt_path(caught.exception.result.receipt_id)
        )["failed_phase"])
        active, _ = fixture.controller.read_active()
        self.assertEqual("release-r0", active["release_id"])
        receipts = [
            read_json(path)
            for path in fixture.controller.layout.audit_receipts.glob("*.json")
        ]
        self.assertEqual(
            {"recovery_protection", "failure"},
            {receipt["receipt_type"] for receipt in receipts},
        )

    def test_corrupt_active_never_infers_from_receipts_and_only_explicit_replay_recovers(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        fixture.controller.layout.active.write_text("{broken", encoding="utf-8")
        with self.assertRaises(ActiveAuthorityCorrupt):
            fixture.controller.read_active()
        starts: list[str] = []
        with self.assertRaises(ActiveAuthorityCorrupt):
            fixture.controller.activate(
                candidate_release_id="release-r1",
                deployment_attempt_id="deploy-corrupt-active",
                recovery_protection_receipt_id="missing-protection",
                start_release=lambda path, _active: starts.append(path.name) is None,
                stop_release=lambda _path: None,
                post_activation_probe=lambda _path, _active: {
                    "health": True,
                    "critical_functions": True,
                    "writer_fence": True,
                },
            )
        self.assertEqual([], starts)
        fixture.controller.replay_prior(
            prior_release_id="release-r0",
            expected_manifest_sha256=manifest_sha256(prior),
            start_release=lambda _path, _active: True,
            probe_release=lambda _path, _active: True,
        )
        active, _ = fixture.controller.read_active()
        self.assertEqual("release-r0", active["release_id"])

    def test_receipts_and_audit_are_append_only_evidence(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        state_checkpoint = checkpoint("checkpoint-append", prior)
        recovery = recovery_manifest("bundle-append", candidate, state_checkpoint)
        receipt = protection_receipt(
            "deploy-append", candidate, recovery, state_checkpoint
        )
        fixture.controller.record_recovery_protection(
            receipt=receipt,
            recovery_manifest=recovery,
            checkpoint_manifest=state_checkpoint,
            external_protection_probe=lambda _receipt, _rm, _checkpoint: True,
        )
        active_before = fixture.controller.layout.active.read_bytes()
        with self.assertRaises(DeploymentError):
            fixture.controller.record_recovery_protection(
                receipt=receipt,
                recovery_manifest=recovery,
                checkpoint_manifest=state_checkpoint,
                external_protection_probe=lambda _receipt, _rm, _checkpoint: True,
            )
        self.assertEqual(active_before, fixture.controller.layout.active.read_bytes())
        for evidence in (
            *fixture.controller.layout.audit_receipts.glob("*.json"),
            *fixture.controller.layout.audit_events.glob("*.json"),
        ):
            self.assertNotEqual(evidence, fixture.controller.layout.active)

    def test_recovery_protection_probe_cannot_switch_active_or_write_receipt(self) -> None:
        fixture = DeploymentFixture()
        self.addCleanup(fixture.close)
        prior = fixture.finalize("release-r0", commit_character="a")
        candidate = fixture.finalize("release-r1", commit_character="b")
        fixture.seed_prior(prior)
        state_checkpoint = checkpoint("checkpoint-drift", prior)
        recovery = recovery_manifest("bundle-drift", candidate, state_checkpoint)
        receipt = protection_receipt(
            "deploy-drift", candidate, recovery, state_checkpoint
        )

        def drifting_probe(_receipt, _recovery, _checkpoint) -> bool:
            path = fixture.controller.release_path("release-r1")
            fixture.controller._write_active(
                fixture.controller._active_value(
                    "release-r1", path, manifest_sha256(candidate)
                )
            )
            return True

        with self.assertRaisesRegex(DeploymentError, "active authority changed"):
            fixture.controller.record_recovery_protection(
                receipt=receipt,
                recovery_manifest=recovery,
                checkpoint_manifest=state_checkpoint,
                external_protection_probe=drifting_probe,
            )
        active, _ = fixture.controller.read_active()
        self.assertEqual("release-r0", active["release_id"])
        self.assertFalse(
            fixture.controller._receipt_path(str(receipt["receipt_id"])).exists()
        )


if __name__ == "__main__":
    unittest.main()
