from __future__ import annotations

from copy import deepcopy
import hashlib
import tempfile
import unittest
from pathlib import Path

from quant_hub.ops.failure_domain import (
    FACTS_SCHEMA,
    PROBE_SCHEMA,
    FailureDomainError,
    attest_failure_domain,
    canonical_bytes,
    collect_host_facts,
)


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
        "bundle_inventory_sha256": "a" * 64,
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


if __name__ == "__main__":
    unittest.main()
