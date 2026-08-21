from __future__ import annotations

from copy import deepcopy
import unittest

from quant_hub.ops.release_identity import (
    IdentityContractError,
    authorize_receipt_append,
    lint_identity_graph,
    lint_state_only_transition,
    manifest_sha256,
    validate_receipt,
    validate_checkpoint_manifest,
    validate_release_manifest,
)


H = {
    name: (str(index) * 64)
    for index, name in enumerate(
        ("tree", "source", "ir", "knowledge", "search", "resources", "state", "tools", "runbook", "operational"),
        start=1,
    )
}
H["operational"] = "a" * 64


def release(release_id: str, *, commit: str) -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": release_id,
        "built_at": "2026-08-21T08:00:00+08:00",
        "application": {
            "commit_sha": commit,
            "tracked_tree_sha256": H["tree"],
            "build_tool_version": "tests/v1",
        },
        "content": {
            "snapshot_id": f"snapshot-{release_id}",
            "source_inventory_sha256": H["source"],
            "ir_sha256": H["ir"],
            "knowledge_sha256": H["knowledge"],
            "search_sha256": H["search"],
            "knowledge_enrichment": {"status": "not_applicable"},
        },
        "resources": {"inventory_sha256": H["resources"]},
        "state": {
            "compatibility": {
                "comments": {"read": [1, 2], "write": [1, 2]},
                "workspace": {"read": [1, 2], "write": [1, 2]},
            }
        },
        "recovery": {
            "compatibility": {
                "checkpoint_manifest_schemas": ["qrh-checkpoint-manifest/v1"],
                "restore_protocol_versions": ["qrh-restore/v1"],
            }
        },
    }


def active(r: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "qrh-active-release/v1",
        "release_id": r["release_id"],
        "release_path": f"D:\\quant\\quant_platform\\releases\\{r['release_id']}",
        "manifest_sha256": manifest_sha256(r),
    }


def checkpoint(checkpoint_id: str, captured_release: dict[str, object], *, hour: int) -> dict[str, object]:
    return {
        "schema_version": "qrh-checkpoint-manifest/v1",
        "checkpoint_id": checkpoint_id,
        "captured_at": f"2026-08-21T{hour:02d}:00:00+08:00",
        "captured_under_active_release": {
            "release_id": captured_release["release_id"],
            "manifest_sha256": manifest_sha256(captured_release),
        },
        "state": {
            "authority_id": "state-d-authority",
            "inventory_sha256": H["state"],
            "database_count": 2,
        },
        "verification": {"integrity": True, "foreign_keys": True, "restorable": True},
    }


def recovery_manifest(
    bundle_id: str, candidate: dict[str, object], state_checkpoint: dict[str, object]
) -> dict[str, object]:
    return {
        "schema_version": "qrh-recovery-manifest/v1",
        "bundle_id": bundle_id,
        "created_at": "2026-08-21T10:00:00+08:00",
        "release": {
            "release_id": candidate["release_id"],
            "manifest_sha256": manifest_sha256(candidate),
        },
        "checkpoint": {
            "checkpoint_id": state_checkpoint["checkpoint_id"],
            "manifest_sha256": manifest_sha256(state_checkpoint),
        },
        "closure": {"inventory_sha256": H["resources"], "file_count": 12, "total_bytes": 4096},
        "compatibility": {"verdict": "compatible", "state_schema": 2},
        "restore": {
            "protocol_version": "qrh-restore/v1",
            "tool_inventory_sha256": H["tools"],
            "runbook_sha256": H["runbook"],
            "operational_bootstrap_sha256": H["operational"],
        },
        "no_secret_attestation": {"verdict": "pass", "scanner_version": "tests/v1"},
    }


def receipt_triple(
    candidate: dict[str, object],
    rm: dict[str, object],
    state_checkpoint: dict[str, object],
) -> dict[str, str]:
    return {
        "release_manifest_sha256": manifest_sha256(candidate),
        "recovery_manifest_sha256": manifest_sha256(rm),
        "checkpoint_manifest_sha256": manifest_sha256(state_checkpoint),
    }


def protection_receipt(
    candidate: dict[str, object], rm: dict[str, object], state_checkpoint: dict[str, object]
) -> dict[str, object]:
    return {
        "schema_version": "qrh-recovery-protection-receipt/v1",
        "receipt_type": "recovery_protection",
        "receipt_id": "receipt-protection-1",
        "deployment_attempt_id": "deploy-attempt-1",
        "recorded_at": "2026-08-21T10:01:00+08:00",
        "authority": "evidence_only",
        **receipt_triple(candidate, rm, state_checkpoint),
        "verdict": "protected",
        "pre_activation_verification": {
            "closure": True,
            "compatibility": True,
            "failure_domain": True,
            "no_secret": True,
            "active_pointer_switched": False,
        },
    }


def activation_receipt(
    candidate: dict[str, object], rm: dict[str, object], state_checkpoint: dict[str, object]
) -> dict[str, object]:
    return {
        "schema_version": "qrh-activation-receipt/v1",
        "receipt_type": "activation",
        "receipt_id": "receipt-activation-1",
        "deployment_attempt_id": "deploy-attempt-1",
        "recorded_at": "2026-08-21T10:05:00+08:00",
        "authority": "evidence_only",
        **receipt_triple(candidate, rm, state_checkpoint),
        "verdict": "activated",
        "switch": {"active_pointer_switched": True, "candidate_started": True},
        "post_activation_verification": {
            "health": True,
            "critical_functions": True,
            "writer_fence": True,
        },
    }


def checkpoint_receipt(
    candidate: dict[str, object], rm: dict[str, object], state_checkpoint: dict[str, object]
) -> dict[str, object]:
    return {
        "schema_version": "qrh-checkpoint-receipt/v1",
        "receipt_type": "checkpoint",
        "receipt_id": f"receipt-{state_checkpoint['checkpoint_id']}",
        "backup_attempt_id": f"backup-{state_checkpoint['checkpoint_id']}",
        "recorded_at": "2026-08-21T12:01:00+08:00",
        "authority": "evidence_only",
        **receipt_triple(candidate, rm, state_checkpoint),
        "operation": "state_only_backup",
        "verdict": "checkpoint_verified",
        "state_only_verification": {
            "integrity": True,
            "closure": True,
            "release_unchanged": True,
            "active_unchanged": True,
        },
    }


class ReleaseIdentityContractTests(unittest.TestCase):
    def test_legacy_broadcast_requires_explicit_non_git_provenance(self) -> None:
        legacy = release("release-v39", commit="a" * 40)
        legacy["application"].update(
            {
                "source_kind": "legacy_broadcast",
                "commit_sha": "0" * 40,
                "source_archive_sha256": "9" * 64,
                "legacy_deployment_id": "quant-hub-v39-test",
            }
        )
        validate_release_manifest(legacy)
        bad = deepcopy(legacy)
        bad["application"]["source_archive_sha256"] = "not-a-hash"
        with self.assertRaises(IdentityContractError):
            validate_release_manifest(bad)
        false_git = deepcopy(legacy)
        false_git["application"]["source_kind"] = "git"
        with self.assertRaises(IdentityContractError):
            validate_release_manifest(false_git)

    def setUp(self) -> None:
        self.r0 = release("release-v39", commit="a" * 40)
        self.r1 = release("release-r1", commit="b" * 40)
        self.c0 = checkpoint("checkpoint-c0", self.r0, hour=9)
        # Candidate R1 is allowed to bind a compatible checkpoint captured under R0.
        self.rm1 = recovery_manifest("bundle-r1-c0", self.r1, self.c0)
        self.protection = protection_receipt(self.r1, self.rm1, self.c0)
        self.activation = activation_receipt(self.r1, self.rm1, self.c0)

    def test_valid_graph_has_only_forward_dependency_directions(self) -> None:
        recovery = {
            "schema_version": "qrh-recovery-receipt/v1",
            "receipt_type": "recovery",
            "receipt_id": "receipt-recovery-1",
            "recovery_attempt_id": "restore-attempt-1",
            "recorded_at": "2026-08-21T11:00:00+08:00",
            "authority": "evidence_only",
            **receipt_triple(self.r1, self.rm1, self.c0),
            "verdict": "recovered",
            "restore_verification": {
                "closure": True,
                "state_restored": True,
                "service_started": True,
                "post_restore": True,
            },
        }
        report = lint_identity_graph(
            active_release=active(self.r1),
            release_manifests=[self.r0, self.r1],
            checkpoint_manifests=[self.c0],
            recovery_manifests=[self.rm1],
            receipts=[self.protection, self.activation, recovery],
        )
        sources = {edge[0].split(":", 1)[0] for edge in report.edges}
        self.assertEqual({"active", "C", "RM", "receipt"}, sources)
        self.assertFalse(any(edge[0].startswith("R:") for edge in report.edges))
        self.assertEqual(manifest_sha256(self.r1), report.active_manifest_sha256)

    def test_release_rejects_concrete_recovery_or_checkpoint_identity(self) -> None:
        for field in (
            "release_manifest_sha256",
            "recovery_manifest_sha256",
            "checkpoint_id",
            "checkpoint_captured_at",
            "bundle_id",
        ):
            with self.subTest(field=field):
                candidate = deepcopy(self.r1)
                candidate["validation"] = {field: H["state"]}
                with self.assertRaisesRegex(IdentityContractError, "dynamic recovery"):
                    validate_release_manifest(candidate)

    def test_release_allows_compatibility_schema_without_dynamic_checkpoint(self) -> None:
        validate_release_manifest(self.r1)

    def test_checkpoint_allows_real_table_named_receipt_without_identity_edge(self) -> None:
        value = deepcopy(self.c0)
        value["state"]["databases"] = [
            {
                "logical_name": "workspace",
                "relative_path": "state/workspace.sqlite3",
                "logical_counts": {"command_receipt": 5},
            }
        ]
        validate_checkpoint_manifest(value)

        back_reference = deepcopy(value)
        back_reference["state"]["recovery_manifest_sha256"] = H["state"]
        with self.assertRaisesRegex(IdentityContractError, "forbidden back-reference"):
            validate_checkpoint_manifest(back_reference)

    def test_activation_append_requires_real_post_switch_active_and_all_gates(self) -> None:
        with self.assertRaisesRegex(IdentityContractError, "observed post-switch"):
            authorize_receipt_append(self.activation)
        with self.assertRaisesRegex(IdentityContractError, "does not match observed"):
            authorize_receipt_append(
                self.activation,
                observed_active_release=active(self.r0),
                existing_receipts=[self.protection],
            )
        with self.assertRaisesRegex(IdentityContractError, "prior recovery protection"):
            authorize_receipt_append(
                self.activation, observed_active_release=active(self.r1)
            )
        authorized = authorize_receipt_append(
            self.activation,
            observed_active_release=active(self.r1),
            existing_receipts=[self.protection],
        )
        self.assertEqual("activation", authorized["receipt_type"])

        failed_health = deepcopy(self.activation)
        failed_health["post_activation_verification"]["health"] = False
        with self.assertRaisesRegex(IdentityContractError, "failed"):
            validate_receipt(failed_health)

    def test_pre_activation_receipt_cannot_claim_switch(self) -> None:
        invalid = deepcopy(self.protection)
        invalid["pre_activation_verification"]["active_pointer_switched"] = True
        with self.assertRaisesRegex(IdentityContractError, "before active switch"):
            validate_receipt(invalid)

    def test_failure_and_activation_are_mutually_exclusive_per_attempt(self) -> None:
        failure = {
            "schema_version": "qrh-failure-receipt/v1",
            "receipt_type": "failure",
            "receipt_id": "receipt-failure-1",
            "deployment_attempt_id": "deploy-attempt-1",
            "recorded_at": "2026-08-21T10:04:00+08:00",
            "authority": "evidence_only",
            "candidate_manifest_sha256": manifest_sha256(self.r1),
            "prior_manifest_sha256": manifest_sha256(self.r0),
            "verdict": "failed",
            "failed_phase": "post_activation_health",
            "error_code": "health_failed",
            "rollback": {"attempted": True, "succeeded": True},
        }
        validate_receipt(failure)
        with self.assertRaisesRegex(IdentityContractError, "terminal"):
            authorize_receipt_append(
                self.activation,
                observed_active_release=active(self.r1),
                existing_receipts=[self.protection, failure],
            )
        with self.assertRaisesRegex(IdentityContractError, "multiple terminal"):
            lint_identity_graph(
                active_release=active(self.r1),
                release_manifests=[self.r0, self.r1],
                checkpoint_manifests=[self.c0],
                recovery_manifests=[self.rm1],
                receipts=[self.protection, self.activation, failure],
            )

    def test_receipt_cannot_be_an_active_authority(self) -> None:
        invalid = deepcopy(self.activation)
        invalid["current_manifest_sha256"] = manifest_sha256(self.r1)
        with self.assertRaisesRegex(IdentityContractError, "active authority"):
            validate_receipt(invalid)

    def test_graph_rejects_activation_without_prior_protection(self) -> None:
        with self.assertRaisesRegex(IdentityContractError, "lacks prior recovery protection"):
            lint_identity_graph(
                active_release=active(self.r1),
                release_manifests=[self.r0, self.r1],
                checkpoint_manifests=[self.c0],
                recovery_manifests=[self.rm1],
                receipts=[self.activation],
            )

    def test_graph_rejects_back_reference_and_dangling_hash(self) -> None:
        circular = deepcopy(self.r1)
        circular["recovery_manifest_sha256"] = manifest_sha256(self.rm1)
        with self.assertRaisesRegex(IdentityContractError, "dynamic recovery"):
            lint_identity_graph(
                active_release=active(self.r1),
                release_manifests=[self.r0, circular],
                checkpoint_manifests=[self.c0],
                recovery_manifests=[self.rm1],
            )

        dangling = deepcopy(self.rm1)
        dangling["checkpoint"]["manifest_sha256"] = "f" * 64
        with self.assertRaisesRegex(IdentityContractError, "does not resolve"):
            lint_identity_graph(
                active_release=active(self.r1),
                release_manifests=[self.r0, self.r1],
                checkpoint_manifests=[self.c0],
                recovery_manifests=[dangling],
            )

    def test_state_only_checkpoint_changes_do_not_change_release_or_active(self) -> None:
        c1 = checkpoint("checkpoint-c1", self.r1, hour=11)
        c2 = checkpoint("checkpoint-c2", self.r1, hour=12)
        self.assertNotEqual(manifest_sha256(c1), manifest_sha256(c2))
        rm_c1 = recovery_manifest("bundle-r1-c1", self.r1, c1)
        rm_c2 = recovery_manifest("bundle-r1-c2", self.r1, c2)
        receipt_c1 = checkpoint_receipt(self.r1, rm_c1, c1)
        receipt_c2 = checkpoint_receipt(self.r1, rm_c2, c2)
        authorize_receipt_append(
            receipt_c1, observed_active_release=active(self.r1)
        )
        report = lint_identity_graph(
            active_release=active(self.r1),
            release_manifests=[self.r1],
            checkpoint_manifests=[c1, c2],
            recovery_manifests=[rm_c1, rm_c2],
            receipts=[receipt_c1, receipt_c2],
        )
        self.assertEqual(manifest_sha256(self.r1), report.active_manifest_sha256)
        self.assertEqual(2, report.checkpoint_count)
        lint_state_only_transition(
            release_before=self.r1,
            release_after=deepcopy(self.r1),
            active_before=active(self.r1),
            active_after=deepcopy(active(self.r1)),
        )
        mutated = deepcopy(self.r1)
        mutated["content"]["snapshot_id"] = "snapshot-illegal-daily-drift"
        with self.assertRaisesRegex(IdentityContractError, "modified release identity"):
            lint_state_only_transition(
                release_before=self.r1,
                release_after=mutated,
                active_before=active(self.r1),
                active_after=active(self.r1),
            )
        drifted_active = active(self.r1)
        drifted_active["release_path"] = (
            "D:\\quant\\quant_platform\\releases\\release-r1-drift"
        )
        drifted_active["release_id"] = "release-r1-drift"
        with self.assertRaisesRegex(IdentityContractError, "modified active authority"):
            lint_state_only_transition(
                release_before=self.r1,
                release_after=deepcopy(self.r1),
                active_before=active(self.r1),
                active_after=drifted_active,
            )

    def test_checkpoint_receipt_cannot_claim_pre_activation_protection(self) -> None:
        c1 = checkpoint("checkpoint-c1", self.r1, hour=11)
        rm_c1 = recovery_manifest("bundle-r1-c1", self.r1, c1)
        invalid = checkpoint_receipt(self.r1, rm_c1, c1)
        invalid["verdict"] = "protected"
        invalid["pre_activation_verification"] = {
            "active_pointer_switched": False
        }
        with self.assertRaises(IdentityContractError):
            validate_receipt(invalid)


if __name__ == "__main__":
    unittest.main()
