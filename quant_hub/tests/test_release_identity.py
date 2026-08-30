from __future__ import annotations

import copy
import unittest

from quant_hub.ops.release_identity import (
    IdentityContractError,
    authorize_receipt_append,
    canonical_manifest_bytes,
    lint_identity_graph,
    manifest_sha256,
    validate_active_release,
    validate_receipt,
    validate_release_manifest,
)


def release(release_id: str, marker: str) -> dict[str, object]:
    return {
        "schema_version": "qrh-release-manifest/v1",
        "release_id": release_id,
        "built_at": "2026-08-29T08:00:00+08:00",
        "application": {
            "commit_sha": marker * 40,
            "tracked_tree_sha256": marker * 64,
            "build_tool_version": "identity-tests/v1",
        },
        "content": {
            "snapshot_id": f"snapshot-{release_id}",
            "source_inventory_sha256": "1" * 64,
            "ir_sha256": "2" * 64,
            "knowledge_sha256": "3" * 64,
            "search_sha256": "4" * 64,
            "knowledge_enrichment": {"status": "ready"},
        },
        "resources": {"inventory_sha256": "5" * 64},
        "state": {"compatibility": {"comments": {"read": [1], "write": [1]}}},
        "inventory": {"schema_version": "qrh-release-file-inventory/v1", "files": []},
    }


def active(value: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "qrh-active-release/v1",
        "release_id": value["release_id"],
        "release_path": rf"D:\quant\quant_platform\releases\{value['release_id']}",
        "manifest_sha256": manifest_sha256(value),
    }


def activation(candidate: dict[str, object], prior: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "qrh-local-activation-receipt/v1",
        "receipt_type": "activation",
        "receipt_id": "activation-attempt-1",
        "deployment_attempt_id": "attempt-1",
        "recorded_at": "2026-08-29T08:01:00+08:00",
        "authority": "evidence_only",
        "release_manifest_sha256": manifest_sha256(candidate),
        "prior_manifest_sha256": manifest_sha256(prior),
        "verdict": "activated",
        "switch": {"active_pointer_switched": True, "candidate_started": True},
        "post_activation_verification": {
            "health": True,
            "critical_functions": True,
            "writer_fence": True,
        },
    }


class ReleaseIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.r0 = release("release-r0", "a")
        self.r1 = release("release-r1", "b")

    def test_release_and_active_are_exact_and_canonical(self) -> None:
        self.assertEqual(self.r1, validate_release_manifest(self.r1))
        self.assertEqual(active(self.r1), validate_active_release(active(self.r1)))
        self.assertEqual(canonical_manifest_bytes(self.r1), canonical_manifest_bytes(copy.deepcopy(self.r1)))

    def test_release_rejects_unknown_top_level_contract(self) -> None:
        invalid = copy.deepcopy(self.r1)
        invalid["retired_contract"] = {}
        with self.assertRaisesRegex(IdentityContractError, "forbidden fields"):
            validate_release_manifest(invalid)

    def test_active_path_must_end_in_release_id(self) -> None:
        invalid = active(self.r1)
        invalid["release_path"] = r"D:\quant\quant_platform\releases\different"
        with self.assertRaisesRegex(IdentityContractError, "end in release_id"):
            validate_active_release(invalid)

    def test_local_activation_binds_candidate_and_single_prior(self) -> None:
        receipt = activation(self.r1, self.r0)
        self.assertEqual(receipt, validate_receipt(receipt))
        self.assertEqual(
            receipt,
            authorize_receipt_append(receipt, observed_active_release=active(self.r1)),
        )
        report = lint_identity_graph(
            release_manifests=[self.r0, self.r1],
            active_release=active(self.r1),
            receipts=[receipt],
        )
        self.assertEqual(2, report.release_count)
        self.assertEqual(1, report.receipt_count)

    def test_activation_requires_observed_candidate_authority(self) -> None:
        with self.assertRaisesRegex(IdentityContractError, "observed"):
            authorize_receipt_append(activation(self.r1, self.r0))
        with self.assertRaisesRegex(IdentityContractError, "does not match"):
            authorize_receipt_append(
                activation(self.r1, self.r0), observed_active_release=active(self.r0)
            )

    def test_one_attempt_has_one_terminal_receipt(self) -> None:
        receipt = activation(self.r1, self.r0)
        with self.assertRaisesRegex(IdentityContractError, "terminal"):
            authorize_receipt_append(
                receipt,
                observed_active_release=active(self.r1),
                existing_receipts=[receipt],
            )
        with self.assertRaisesRegex(IdentityContractError, "duplicated"):
            lint_identity_graph(
                release_manifests=[self.r0, self.r1],
                active_release=active(self.r1),
                receipts=[receipt, copy.deepcopy(receipt)],
            )

    def test_receipt_never_defines_active_authority(self) -> None:
        invalid = activation(self.r1, self.r0)
        invalid["active_pointer"] = active(self.r1)
        with self.assertRaisesRegex(IdentityContractError, "active authority"):
            validate_receipt(invalid)


if __name__ == "__main__":
    unittest.main()
