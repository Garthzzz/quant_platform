from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from quant_hub.ops.failure_domain import (
    FACTS_SCHEMA,
    PROBE_SCHEMA,
    FailureDomainError,
    attest_failure_domain,
    build_independence_probe,
    canonical_bytes,
    collect_host_facts,
)
from quant_hub.ops.recovery_bundle import RecoveryVerification


def facts(role: str, machine: str, volume: str) -> dict[str, object]:
    payload: dict[str, object] = {
        "schema_version": FACTS_SCHEMA,
        "role": role,
        "host_name": machine,
        "machine_identity": machine,
        "canonical_path": "D:\\quant\\quant_platform" if role == "production" else "E:\\recovery",
        "path_kind": "local",
        "reparse_or_symlink": False,
        "volume_identity": volume,
        "storage_backend": "local-ntfs:" + volume,
        "storage_authority": machine + "|" + volume,
        "tool_version": "tests/v1",
    }
    payload["facts_sha256"] = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    return payload


def probe() -> dict[str, object]:
    return {
        "schema_version": PROBE_SCHEMA,
        "production_root_available": False,
        "recovery_bundle_readable": True,
        "closure_verified": True,
        "empty_root_precondition": True,
        "bundle_id": "bundle-v39",
        "release_id": "release-v39",
        "release_manifest_sha256": "c" * 64,
        "bundle_inventory_sha256": "a" * 64,
        "materialization_event_id": "cold-materialization-bundle-v39",
        "materialization_event_sha256": "d" * 64,
        "probe_tool_sha256": "b" * 64,
    }


class FailureDomainTests(unittest.TestCase):
    def test_independent_hosts_and_storage_pass(self) -> None:
        result = attest_failure_domain(
            production_facts=facts("production", "vm-240", "volume-d"),
            recovery_facts=facts("recovery", "developer", "volume-r"),
            independence_probe=probe(),
            observed_at="2026-08-21T06:00:00+08:00",
        )
        self.assertEqual("independent_failure_domain", result.payload["verdict"])
        self.assertEqual(64, len(result.sha256))

    def test_other_drive_on_same_host_is_rejected(self) -> None:
        with self.assertRaisesRegex(FailureDomainError, "production host"):
            attest_failure_domain(
                production_facts=facts("production", "vm-240", "volume-d"),
                recovery_facts=facts("recovery", "vm-240", "volume-e"),
                independence_probe=probe(),
                observed_at="2026-08-21T06:00:00+08:00",
            )

    def test_reparse_and_unisolated_probe_are_rejected(self) -> None:
        recovery = facts("recovery", "developer", "volume-r")
        recovery["reparse_or_symlink"] = True
        recovery.pop("facts_sha256")
        recovery["facts_sha256"] = hashlib.sha256(canonical_bytes(recovery)).hexdigest()
        with self.assertRaisesRegex(FailureDomainError, "reparse"):
            attest_failure_domain(
                production_facts=facts("production", "vm-240", "volume-d"),
                recovery_facts=recovery,
                independence_probe=probe(),
                observed_at="2026-08-21T06:00:00+08:00",
            )
        unisolated = deepcopy(probe())
        unisolated["production_root_available"] = True
        with self.assertRaisesRegex(FailureDomainError, "did not isolate"):
            attest_failure_domain(
                production_facts=facts("production", "vm-240", "volume-d"),
                recovery_facts=facts("recovery", "developer", "volume-r"),
                independence_probe=unisolated,
                observed_at="2026-08-21T06:00:00+08:00",
            )

    def test_collect_local_facts_is_hashed_and_non_secret(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            result = collect_host_facts(
                Path(temporary), role="recovery", tool_version="tests/v1"
            )
        self.assertEqual(FACTS_SCHEMA, result["schema_version"])
        self.assertEqual(64, len(str(result["facts_sha256"])))
        self.assertNotIn("credential", str(result).casefold())

    def test_probe_is_derived_from_verified_bundle_and_empty_d_event(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            recovery = Path(temporary) / "recovery"
            bundle = recovery / "cold-recovery-bundle-v39"
            bundle.mkdir(parents=True)
            inventory = bundle / "closure_inventory.json"
            inventory.write_bytes(b'{"closed":true}\n')
            event = recovery / "materialization.json"
            event_value = {
                "schema_version": "qrh-recovery-materialization-event/v1",
                "event_id": "cold-materialization-bundle-v39",
                "kind": "cold_recovery_materialized",
                "authority": "evidence_only",
                "fields": {
                    "bundle_id": "bundle-v39",
                    "release_id": "release-v39",
                    "manifest_sha256": "c" * 64,
                    "empty_root_precondition": True,
                    "import_cleaned": True,
                    "runtime_tmp_cleaned": True,
                },
            }
            event.write_text(json.dumps(event_value), encoding="utf-8")
            tool = recovery / "failure_domain_cli.py"
            tool.write_text("# reviewed probe tool\n", encoding="utf-8")
            report = RecoveryVerification(
                valid=True,
                bundle_id="bundle-v39",
                release_id="release-v39",
                release_manifest_sha256="c" * 64,
                checkpoint_id="checkpoint-v39",
                checkpoint_manifest_sha256="e" * 64,
                recovery_manifest_sha256="f" * 64,
                errors=(),
            )
            with patch(
                "quant_hub.ops.recovery_bundle.verify_recovery_bundle",
                return_value=report,
            ):
                result = build_independence_probe(
                    recovery_root=recovery,
                    bundle_root=bundle,
                    materialization_event_path=event,
                    probe_tool_path=tool,
                )
            self.assertFalse(result["production_root_available"])
            self.assertTrue(result["empty_root_precondition"])
            self.assertEqual("bundle-v39", result["bundle_id"])
            self.assertEqual(
                hashlib.sha256(event.read_bytes()).hexdigest(),
                result["materialization_event_sha256"],
            )

            event_value["fields"]["release_id"] = "another-release"
            event.write_text(json.dumps(event_value), encoding="utf-8")
            with patch(
                "quant_hub.ops.recovery_bundle.verify_recovery_bundle",
                return_value=report,
            ), self.assertRaisesRegex(FailureDomainError, "does not bind"):
                build_independence_probe(
                    recovery_root=recovery,
                    bundle_root=bundle,
                    materialization_event_path=event,
                    probe_tool_path=tool,
                )


if __name__ == "__main__":
    unittest.main()
