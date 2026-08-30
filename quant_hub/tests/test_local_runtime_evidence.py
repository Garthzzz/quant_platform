from __future__ import annotations

from copy import deepcopy
import hashlib
import unittest

from quant_hub.ops.local_release_identity import identity_sha256
from quant_hub.ops.local_runtime_evidence import (
    DEPLOYMENT_CANARY_EVIDENCE_SCHEMA,
    ISOLATED_SQLITE_COPY_EVIDENCE_SCHEMA,
    STATE_DATABASE_SEAL_SCHEMA,
    DeploymentCanaryEvidence,
    IsolatedSqliteCopyEvidence,
    LocalRuntimeEvidenceError,
    SqliteCompatibilityManifest,
    StateDatabaseSeal,
    build_deployment_canary_evidence,
    build_isolated_sqlite_copy_evidence,
    build_sqlite_compatibility_manifest,
    build_state_database_seal,
    validate_state_database_seal,
)


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


WORKSPACE_MIGRATIONS = [
    {
        "version": 1,
        "name": "research_workspace",
        "up_sha256": "23342bf329cf9164987ed636f37858c2802ed9c3e2a36c045c967c927af6df4b",
        "down_sha256": "991a1c21dca347bd8d8615abaf50b365871079bc24aa6667d38c28c403601ecd",
    },
    {
        "version": 2,
        "name": "project_semantics",
        "up_sha256": "e72a07ea4adfca987ceffaf58b30bfa36958e3e816b977c09f943f08de6fe0a5",
        "down_sha256": "686e2f587de39485de4c8c41e8a4fc0fe7c150a8aad07b63a3521356b8c7c4c2",
    },
    {
        "version": 3,
        "name": "project_creation_command",
        "up_sha256": "bc77fd306e193466a4af48fa2c16086a69167e1a07bfefed17f400d1d420c387",
        "down_sha256": "b0e4c172b41fe914076a10768af1e74c3e970c2529624a55a2c52491be8c14f1",
    },
]

BUSINESS_TABLES = {
    "comments": (
        "actor",
        "command_receipt",
        "comment",
        "comment_event",
        "comment_target",
        "legacy_import_run",
        "outbox_event",
        "progress_command_receipt",
        "progress_topic",
        "progress_topic_event",
    ),
    "research_workspace": (
        "actor",
        "research_workspace_command_receipt",
        "research_workspace_comment",
        "research_workspace_comment_event",
        "research_workspace_event",
        "research_workspace_node",
        "research_workspace_observation",
        "research_workspace_sync_run",
    ),
}


def compatibility(database: str = "comments") -> dict[str, object]:
    version = 2 if database == "comments" else 3
    return build_sqlite_compatibility_manifest(
        operation="activate_successor",
        database_name=database,
        logical_schema_version=version,
        candidate_release_id="release-r1",
        candidate_release_manifest_sha256=digest("r1"),
        candidate_read_versions=[version],
        candidate_write_versions=[version],
        prior_release_id="release-r0",
        prior_release_manifest_sha256=digest("r0"),
        prior_read_versions=[version],
        prior_write_versions=[version],
        schema_contract_sha256=digest(f"contract-{database}"),
    )


def business_summary(database: str) -> dict[str, object]:
    metrics = [{"metric": "rows_total", "value": 0}]
    table_digests = [
        {"table": name, "row_count": 0, "rows_sha256": digest(f"rows-{name}")}
        for name in BUSINESS_TABLES[database]
    ]
    logical = identity_sha256(table_digests)
    material = {
        "metrics": metrics,
        "table_digests": table_digests,
        "logical_content_sha256": logical,
    }
    return {**material, "summary_sha256": identity_sha256(material)}


def observation(label: str) -> dict[str, object]:
    return {
        "identity_scheme": "windows_file_id",
        "bytes": 4096,
        "mtime_ns": 1,
        "bytes_sha256": digest(f"bytes-{label}"),
        "volume_identity_sha256": digest("volume"),
        "file_identity_sha256": digest(f"file-{label}"),
    }


def state_seal(database: str = "comments") -> dict[str, object]:
    filename = "comments.sqlite3" if database == "comments" else "research_workspace.sqlite3"
    path = rf"D:\quant\quant_platform\state\{filename}"
    logical = (
        {"logical_version": 2, "comment_store_schema": [1, 2], "comment_target_schema": [3]}
        if database == "comments"
        else {"logical_version": 3, "comment_store_schema": [], "comment_target_schema": []}
    )
    main = observation("main")
    return build_state_database_seal(
        {
            "schema_version": STATE_DATABASE_SEAL_SCHEMA,
            "attempt_id": "attempt-b3",
            "nonce": "nonce-b3",
            "operation": "activate_successor",
            "database_name": database,
            "qualification_scope": "diagnostic_only_unresolved_release_closure",
            "runtime_scope": "production_exact_d",
            "canonical_path": path,
            "state_identity_sha256": digest("state"),
            "open_mode": "main_only_immutable",
            "raw_user_version": 0,
            "logical_schema": logical,
            "migration_ledger": [] if database == "comments" else deepcopy(WORKSPACE_MIGRATIONS),
            "sqlite_schema_sha256": digest("schema"),
            "integrity_check": "ok",
            "quick_check": "ok",
            "foreign_key_violation_count": 0,
            "business_summary": business_summary(database),
            "file_set": [
                {
                    "role": "main",
                    "canonical_path": path,
                    "presence": "present",
                    "before": main,
                    "after": deepcopy(main),
                },
                {
                    "role": "wal",
                    "canonical_path": path + "-wal",
                    "presence": "absent",
                    "before": None,
                    "after": None,
                },
                {
                    "role": "shm",
                    "canonical_path": path + "-shm",
                    "presence": "absent",
                    "before": None,
                    "after": None,
                },
            ],
            "compatibility_manifest_sha256": compatibility(database)["manifest_sha256"],
            "result": "read_only_observation",
        }
    )


class LocalRuntimeEvidenceTests(unittest.TestCase):
    def test_bootstrap_compatibility_has_an_exact_absent_prior(self) -> None:
        document = build_sqlite_compatibility_manifest(
            operation="bootstrap_first_pair",
            database_name="comments",
            logical_schema_version=2,
            candidate_release_id="release-r0",
            candidate_release_manifest_sha256=digest("r0"),
            candidate_read_versions=[2],
            candidate_write_versions=[2],
            prior_release_id=None,
            prior_release_manifest_sha256=None,
            prior_read_versions=None,
            prior_write_versions=None,
            schema_contract_sha256=digest("contract-comments"),
        )
        self.assertEqual({"status": "absent"}, document["prior_compatibility"])
        self.assertEqual(
            document,
            SqliteCompatibilityManifest.from_document(document).as_dict(),
        )
        forged = deepcopy(document)
        forged["prior_compatibility"] = deepcopy(
            forged["candidate_compatibility"]
        )
        forged["manifest_sha256"] = identity_sha256(
            {
                key: value
                for key, value in forged.items()
                if key != "manifest_sha256"
            }
        )
        with self.assertRaises(LocalRuntimeEvidenceError):
            SqliteCompatibilityManifest.from_document(forged)

    def test_compatibility_is_closed_pair_aggregate_and_canonical(self) -> None:
        document = compatibility()
        typed = SqliteCompatibilityManifest.from_document(document)
        self.assertEqual(document["manifest_sha256"], typed.manifest_sha256)
        self.assertEqual(document, typed.as_dict())

        for mutation in (
            lambda item: item.update({"unknown": "x"}),
            lambda item: item.pop("operation"),
            lambda item: item["candidate_compatibility"].update(
                {"release_id": item["prior_compatibility"]["release_id"]}
            ),
            lambda item: item["candidate_compatibility"].update({"read_versions": [1]}),
        ):
            changed = deepcopy(document)
            mutation(changed)
            changed["manifest_sha256"] = identity_sha256(
                {key: value for key, value in changed.items() if key != "manifest_sha256"}
            )
            with self.assertRaises(LocalRuntimeEvidenceError):
                SqliteCompatibilityManifest.from_document(changed)

    def test_state_seal_binds_attempt_operation_exact_d_and_table_rows(self) -> None:
        document = state_seal()
        typed = StateDatabaseSeal.from_document(document)
        self.assertEqual(document["seal_sha256"], typed.seal_sha256)
        self.assertEqual(document, typed.as_dict())

        mutations = (
            lambda item: item.update({"unknown": 1}),
            lambda item: item.pop("attempt_id"),
            lambda item: item.update({"qualification_scope": "formal"}),
            lambda item: item.update({"raw_user_version": True}),
            lambda item: item.update({"canonical_path": r"C:\state\comments.sqlite3"}),
            lambda item: item["file_set"][0].update(
                {"canonical_path": r"D:\quant\sibling\comments.sqlite3"}
            ),
            lambda item: item["business_summary"]["table_digests"].pop(),
            lambda item: item.update({"integrity_check": "not ok"}),
        )
        for mutation in mutations:
            changed = deepcopy(document)
            mutation(changed)
            changed["seal_sha256"] = identity_sha256(
                {key: value for key, value in changed.items() if key != "seal_sha256"}
            )
            with self.assertRaises(LocalRuntimeEvidenceError):
                validate_state_database_seal(changed)

    def test_workspace_is_v3_and_migration_hashes_are_exact(self) -> None:
        document = state_seal("research_workspace")
        self.assertEqual(3, document["logical_schema"]["logical_version"])
        self.assertEqual(0, document["raw_user_version"])
        self.assertEqual(WORKSPACE_MIGRATIONS, document["migration_ledger"])

        for changed_version in (2, 4):
            changed = deepcopy(document)
            changed["logical_schema"]["logical_version"] = changed_version
            changed["seal_sha256"] = identity_sha256(
                {key: value for key, value in changed.items() if key != "seal_sha256"}
            )
            with self.assertRaises(LocalRuntimeEvidenceError):
                validate_state_database_seal(changed)
        changed = deepcopy(document)
        changed["migration_ledger"][1]["up_sha256"] = digest("drifted")
        changed["seal_sha256"] = identity_sha256(
            {key: value for key, value in changed.items() if key != "seal_sha256"}
        )
        with self.assertRaises(LocalRuntimeEvidenceError):
            validate_state_database_seal(changed)

    def test_copy_and_controller_canary_are_closed_diagnostic_evidence(self) -> None:
        copy_document = build_isolated_sqlite_copy_evidence(
            {
                "schema_version": ISOLATED_SQLITE_COPY_EVIDENCE_SCHEMA,
                "attempt_id": "attempt-b3",
                "nonce": "nonce-b3",
                "operation": "activate_successor",
                "database_name": "comments",
                "state_identity_sha256": digest("state"),
                "compatibility_manifest_sha256": compatibility()["manifest_sha256"],
                "source_seal_sha256": state_seal()["seal_sha256"],
                "sqlite_main_bytes": 4096,
                "sqlite_main_sha256": digest("copy"),
                "destination_members": ["main"],
                "destination_integrity_check": "ok",
                "destination_quick_check": "ok",
                "destination_foreign_key_violation_count": 0,
                "destination_schema_sha256": digest("schema"),
                "destination_business_summary_sha256": digest("business"),
                "result": "isolated_copy_verified",
            }
        )
        copy_typed = IsolatedSqliteCopyEvidence.from_document(copy_document)
        challenge = {
            "initial_revision": 0,
            "applied_from_revision": 0,
            "applied_to_revision": 1,
            "applied_rowcount": 1,
            "stale_from_revision": 0,
            "stale_to_revision": 2,
            "stale_rowcount": 0,
            "readback_revision": 1,
            "append_only_event_count": 1,
            "event_update_outcome": "rejected_by_trigger",
            "event_delete_outcome": "rejected_by_trigger",
        }
        canary_document = build_deployment_canary_evidence(
            {
                "schema_version": DEPLOYMENT_CANARY_EVIDENCE_SCHEMA,
                "attempt_id": "attempt-b3",
                "nonce": "nonce-b3",
                "operation": "activate_successor",
                "database_name": "comments",
                "state_identity_sha256": digest("state"),
                "compatibility_manifest_sha256": compatibility()["manifest_sha256"],
                "execution_lane": "controller_sql_fixture",
                "qualification_scope": "diagnostic_only_not_exact_release",
                "copy_evidence_sha256": copy_typed.evidence_sha256,
                "challenge": challenge,
                "business_probe": {
                    "family": "archive_comments",
                    "create_rowcount": 1,
                    "idempotent_replay_rowcount": 0,
                    "edit_rowcount": 1,
                    "soft_delete_rowcount": 1,
                    "final_revision": 3,
                    "event_count": 3,
                    "receipt_count": 3,
                    "deleted_row_count": 1,
                    "before_summary_sha256": digest("before"),
                    "after_summary_sha256": digest("after"),
                },
                "final_main_bytes": 8192,
                "final_main_sha256": digest("final"),
                "final_schema_sha256": digest("final-schema"),
                "final_business_summary_sha256": digest("after"),
                "result": "controller_fixture_verified",
            }
        )
        typed = DeploymentCanaryEvidence.from_document(canary_document)
        self.assertEqual(canary_document, typed.as_dict())

        for field, value in (
            ("execution_lane", "exact_release"),
            ("qualification_scope", True),
        ):
            changed = deepcopy(canary_document)
            changed[field] = value
            changed["evidence_sha256"] = identity_sha256(
                {key: child for key, child in changed.items() if key != "evidence_sha256"}
            )
            with self.assertRaises(LocalRuntimeEvidenceError):
                DeploymentCanaryEvidence.from_document(changed)


if __name__ == "__main__":
    unittest.main()
