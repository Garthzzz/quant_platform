from __future__ import annotations

from copy import deepcopy
import inspect
import json
import pickle
import unittest

from quant_hub.ops import local_release_identity as identity
from quant_hub.ops.local_deployment_persistence import (
    DeploymentJournalError,
    LocalDeploymentPersistence,
    LockedExactReleaseClosures,
)
from quant_hub.ops.local_exact_release_compatibility import (
    DATABASE_ORDER,
    EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCHEMA,
    EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCOPE,
    ExactReleaseCompatibilityError,
    LockedExactReleaseCompatibilityEvidenceSet,
    WORKSPACE_MIGRATIONS,
    WORKSPACE_RUNTIME_MIGRATIONS,
    build_exact_release_compatibility_evidence,
    plan_exact_release_compatibility,
    validate_exact_release_compatibility_evidence,
    validate_exact_release_compatibility_evidence_set,
)
from tests.test_local_deployment_persistence import (
    EXACT_MIGRATIONS,
    PersistenceFixture,
    advance_one,
    digest,
    journal,
    migration_bytes,
    release,
    seal,
    state_identity,
    validate_deployment_journal,
)


class ExactReleaseCompatibilityTests(PersistenceFixture):
    def exact_release(
        self, release_id: str, character: str
    ) -> dict[str, object]:
        return release(
            release_id,
            self.payloads[release_id],
            character,
            include_migrations=True,
        )

    def plan(
        self,
        *,
        operation: str,
        attempt: str,
        nonce: str,
        candidate: dict[str, object],
        prior: dict[str, object] | None,
    ):
        return plan_exact_release_compatibility(
            operation=operation,
            attempt_id=attempt,
            nonce=nonce,
            state_identity_sha256=state_identity()["identity_sha256"],
            candidate_manifest=candidate,
            prior_manifest=prior,
        )

    @staticmethod
    def bind_plan(first: dict[str, object], aggregate: str) -> None:
        first["state_plan"]["compatibility_sha256"] = aggregate
        seal(first, "journal_sha256")

    @staticmethod
    def reseal_document(document: dict[str, object]) -> None:
        document.pop("evidence_sha256", None)
        document["evidence_sha256"] = identity.identity_sha256(document)

    @classmethod
    def reseal_material(
        cls, document: dict[str, object], role: str
    ) -> None:
        material = document["release_qualification"][role]
        material.pop("material_sha256", None)
        material["material_sha256"] = identity.identity_sha256(material)
        cls.reseal_document(document)

    def install_scenario(
        self, operation: str, *, suffix: str
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object] | None,
        object,
    ]:
        attempt = f"attempt-{suffix}"
        nonce = f"nonce-{suffix}"
        if operation == "bootstrap_first_pair":
            candidate = self.exact_release("release-r0", "9")
            prior = None
            first = journal(
                None,
                candidate,
                operation=operation,
                attempt=attempt,
                nonce=nonce,
            )
            physical = (candidate,)
        elif operation == "activation":
            prior = self.exact_release("release-r0", "9")
            candidate = self.exact_release("release-r1", "a")
            first = journal(
                prior,
                candidate,
                attempt=attempt,
                nonce=nonce,
            )
            physical = (candidate, prior)
        else:
            original_active = self.exact_release("release-r0", "9")
            candidate = self.exact_release("release-r-minus-1", "8")
            prior = original_active
            first = journal(
                original_active,
                self.exact_release("release-r1", "a"),
                original_prior=candidate,
                operation="rollback",
                attempt=attempt,
                nonce=nonce,
            )
            physical = (candidate, prior)
        for manifest in physical:
            self.materialize(manifest)
        planned = self.plan(
            operation=operation,
            attempt=attempt,
            nonce=nonce,
            candidate=candidate,
            prior=prior,
        )
        self.bind_plan(first, planned.aggregate_sha256)
        self.append_history([first])
        return first, candidate, prior, planned

    def installed_evidence_documents(
        self, operation: str, *, suffix: str
    ) -> tuple[tuple[dict[str, object], ...], str, object]:
        first, _candidate, _prior, planned = self.install_scenario(
            operation, suffix=suffix
        )
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, str(first["attempt"]), str(first["nonce"])
            )
            closures = self.persistence.lock_exact_release_closures(
                lock, workspace
            )
            evidence = build_exact_release_compatibility_evidence(closures)
            documents = evidence.documents
            aggregate = evidence.aggregate_sha256
            closures.close()
            workspace.close()
        return documents, aggregate, planned

    def test_activation_rollback_and_bootstrap_plan_match_live_evidence(self) -> None:
        for operation in ("activation", "rollback", "bootstrap_first_pair"):
            with self.subTest(operation=operation):
                first, _candidate, _prior, planned = self.install_scenario(
                    operation, suffix=operation
                )
                self.assertEqual("plan_only", planned.scope)
                self.assertFalse(hasattr(planned, "documents"))
                with self.persistence.global_lock() as lock:
                    workspace = self.persistence.bind_attempt_workspace(
                        lock, str(first["attempt"]), str(first["nonce"])
                    )
                    closures = self.persistence.lock_exact_release_closures(
                        lock, workspace
                    )
                    evidence = build_exact_release_compatibility_evidence(
                        closures
                    )
                    self.assertIsInstance(
                        evidence, LockedExactReleaseCompatibilityEvidenceSet
                    )
                    self.assertEqual(
                        EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCOPE,
                        evidence.scope,
                    )
                    self.assertEqual(planned.aggregate_sha256, evidence.aggregate_sha256)
                    documents, aggregate = (
                        validate_exact_release_compatibility_evidence_set(
                            evidence.documents
                        )
                    )
                    self.assertEqual(DATABASE_ORDER, tuple(
                        document["database_name"] for document in documents
                    ))
                    self.assertEqual(planned.aggregate_sha256, aggregate)
                    self.assertEqual(
                        "bootstrap_baseline"
                        if operation == "bootstrap_first_pair"
                        else "release_pair",
                        documents[0]["release_qualification"]["kind"],
                    )
                    self.assertEqual(
                        EXACT_RELEASE_COMPATIBILITY_EVIDENCE_SCHEMA,
                        evidence.document("comments")["schema_version"],
                    )
                    closures.close()
                    workspace.close()

    def test_sealed_runtime_migration_layout_is_accepted_without_mixing(self) -> None:
        candidate = self.exact_release("release-r1", "a")
        for record in candidate["inventory"]["files"]:
            if record["path"] in WORKSPACE_MIGRATIONS:
                index = WORKSPACE_MIGRATIONS.index(record["path"])
                record["path"] = WORKSPACE_RUNTIME_MIGRATIONS[index]
                raw = migration_bytes("release-r1", record["path"])
                record["bytes"] = len(raw)
                record["sha256"] = digest(raw)
        candidate["inventory"]["files"].sort(key=lambda item: item["path"])
        candidate["resources"]["inventory_sha256"] = identity.identity_sha256(
            candidate["inventory"]
        )

        planned = self.plan(
            operation="bootstrap_first_pair",
            attempt="runtime-layout",
            nonce="runtime-layout-nonce",
            candidate=candidate,
            prior=None,
        )
        self.assertRegex(planned.aggregate_sha256, r"^[0-9a-f]{64}$")
        first = journal(
            None,
            candidate,
            operation="bootstrap_first_pair",
            attempt="runtime-layout",
            nonce="runtime-layout-nonce",
        )
        self.bind_plan(first, planned.aggregate_sha256)
        self.materialize(candidate)
        self.append_history([first])
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "runtime-layout", "runtime-layout-nonce"
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            self.assertEqual(
                list(WORKSPACE_MIGRATIONS),
                [
                    item["relative_path"]
                    for item in closures.metadata()["roles"]["candidate"][
                        "migrations"
                    ]
                ],
            )
            self.assertEqual(
                migration_bytes("release-r1", WORKSPACE_RUNTIME_MIGRATIONS[0]),
                closures.read_migration("candidate", WORKSPACE_MIGRATIONS[0]),
            )
            evidence = build_exact_release_compatibility_evidence(closures)
            self.assertEqual(planned.aggregate_sha256, evidence.aggregate_sha256)
            closures.close()
            workspace.close()

        mixed = deepcopy(candidate)
        mixed["inventory"]["files"].append(
            {
                "path": WORKSPACE_MIGRATIONS[0],
                "bytes": 1,
                "sha256": "1" * 64,
            }
        )
        mixed["inventory"]["files"].sort(key=lambda item: item["path"])
        mixed["resources"]["inventory_sha256"] = identity.identity_sha256(
            mixed["inventory"]
        )
        with self.assertRaisesRegex(
            ExactReleaseCompatibilityError, "migration set is not exact"
        ):
            self.plan(
                operation="bootstrap_first_pair",
                attempt="mixed-layout",
                nonce="mixed-layout-nonce",
                candidate=mixed,
                prior=None,
            )

    def test_plan_aggregate_is_exactly_the_journal_and_database_seal_value(self) -> None:
        first, _candidate, _prior, planned = self.install_scenario(
            "activation", suffix="three-lane"
        )
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, str(first["attempt"]), str(first["nonce"])
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            evidence = build_exact_release_compatibility_evidence(closures)
            documents = evidence.documents
            closures.close()
            workspace.close()
        state_applied = advance_one(advance_one(first))
        by_name = {
            document["database_name"]: document["evidence_sha256"]
            for document in documents
        }
        state_applied["database_seals"] = [
            {
                "name": name,
                "seal_sha256": str(index + 1) * 64,
                "compatibility_manifest_sha256": by_name[name],
            }
            for index, name in enumerate(DATABASE_ORDER)
        ]
        state_applied["evidence_hashes"]["state_compatibility_sha256"] = (
            planned.aggregate_sha256
        )
        seal(state_applied, "journal_sha256")
        validate_deployment_journal(state_applied)

        for mutation in ("evidence", "plan", "seal", "reorder", "missing", "extra"):
            changed = deepcopy(state_applied)
            if mutation == "evidence":
                changed["evidence_hashes"]["state_compatibility_sha256"] = "d" * 64
            elif mutation == "plan":
                changed["state_plan"]["compatibility_sha256"] = "e" * 64
            elif mutation == "seal":
                changed["database_seals"][0]["compatibility_manifest_sha256"] = "f" * 64
            elif mutation == "reorder":
                changed["database_seals"].reverse()
            elif mutation == "missing":
                changed["database_seals"].pop()
            else:
                changed["database_seals"].append(
                    {
                        "name": "third_database",
                        "seal_sha256": "7" * 64,
                        "compatibility_manifest_sha256": "8" * 64,
                    }
                )
            seal(changed, "journal_sha256")
            with self.subTest(mutation=mutation), self.assertRaises(
                DeploymentJournalError
            ):
                validate_deployment_journal(changed)

    def test_plan_manifest_must_match_the_pinned_live_closure(self) -> None:
        candidate = self.exact_release("release-r1", "a")
        prior = self.exact_release("release-r0", "9")
        other = self.exact_release("release-r2", "b")
        for manifest in (candidate, prior):
            self.materialize(manifest)
        planned_for_other = self.plan(
            operation="activation",
            attempt="attempt-plan-drift",
            nonce="nonce-plan-drift",
            candidate=other,
            prior=prior,
        )
        first = journal(
            prior,
            candidate,
            attempt="attempt-plan-drift",
            nonce="nonce-plan-drift",
        )
        self.bind_plan(first, planned_for_other.aggregate_sha256)
        self.append_history([first])
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "attempt-plan-drift", "nonce-plan-drift"
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            with self.assertRaisesRegex(
                ExactReleaseCompatibilityError, "planned aggregate"
            ):
                build_exact_release_compatibility_evidence(closures)
            closures.close()
            workspace.close()

    def test_relabelled_release_core_and_incomplete_manifest_are_rejected(self) -> None:
        prior = self.exact_release("release-r0", "9")
        relabelled = deepcopy(prior)
        relabelled["release_id"] = "release-r1"
        relabelled["built_at"] = "2026-08-26T10:09:00+08:00"
        relabelled["application"]["provenance"] = {
            "builder": "relabelled-copy",
            "labels": ["copy"],
        }
        with self.assertRaisesRegex(
            ExactReleaseCompatibilityError, "sealed cores"
        ):
            self.plan(
                operation="activation",
                attempt="attempt-core-copy",
                nonce="nonce-core-copy",
                candidate=relabelled,
                prior=prior,
            )
        for malformed in (
            {"release_id": "release-r1"},
            {**deepcopy(prior), "schema_version": "qrh-release-manifest/v1"},
            {**deepcopy(prior), "unexpected_field": "forbidden"},
        ):
            with self.subTest(keys=tuple(malformed)), self.assertRaises(
                ExactReleaseCompatibilityError
            ):
                plan_exact_release_compatibility(
                    operation="bootstrap_first_pair",
                    attempt_id="attempt-malformed",
                    nonce="nonce-malformed",
                    state_identity_sha256=state_identity()["identity_sha256"],
                    candidate_manifest=malformed,
                    prior_manifest=None,
                )

    def test_migration_comments_and_bootstrap_union_mutations_fail_closed(self) -> None:
        documents, _aggregate, _planned = self.installed_evidence_documents(
            "activation", suffix="mutations"
        )
        workspace = deepcopy(documents[1])
        workspace["release_qualification"]["candidate"]["migration_files"][0][
            "bytes"
        ] += 1
        with self.assertRaises(ExactReleaseCompatibilityError):
            validate_exact_release_compatibility_evidence(workspace)

        renamed = deepcopy(documents[1])
        renamed["release_qualification"]["candidate"]["migration_files"][0][
            "path"
        ] = "migrations/research_workspace/0001_wrong.down.sql"
        self.reseal_material(renamed, "candidate")
        with self.assertRaisesRegex(ExactReleaseCompatibilityError, "fixed enum"):
            validate_exact_release_compatibility_evidence(renamed)

        comments = deepcopy(documents[0])
        comments["release_qualification"]["candidate"]["migration_files"] = [
            {
                "path": WORKSPACE_MIGRATIONS[0],
                "bytes": 1,
                "sha256": "1" * 64,
            }
        ]
        self.reseal_material(comments, "candidate")
        with self.assertRaisesRegex(ExactReleaseCompatibilityError, "comments"):
            validate_exact_release_compatibility_evidence(comments)

        fake_prior = deepcopy(documents[0])
        fake_prior["operation"] = "bootstrap_first_pair"
        fake_prior["release_qualification"]["kind"] = "bootstrap_baseline"
        fake_prior["release_qualification"]["prior"] = {
            "status": "present"
        }
        self.reseal_document(fake_prior)
        with self.assertRaisesRegex(ExactReleaseCompatibilityError, "absent"):
            validate_exact_release_compatibility_evidence(fake_prior)

    def test_closed_validator_canonical_hash_path_roles_versions_and_order(self) -> None:
        documents, _aggregate, _planned = self.installed_evidence_documents(
            "activation", suffix="validator"
        )
        for document in documents:
            canonical = identity.canonical_bytes(document)
            self.assertEqual(
                document,
                validate_exact_release_compatibility_evidence(
                    json.loads(canonical.decode("utf-8"))
                ),
            )

        cases: list[tuple[str, dict[str, object]]] = []
        unknown = deepcopy(documents[0])
        unknown["qualified"] = True
        cases.append(("unknown", unknown))
        missing = deepcopy(documents[0])
        missing.pop("logical_schema")
        cases.append(("missing", missing))
        wrong_bool = deepcopy(documents[0])
        wrong_bool["attempt_id"] = True
        self.reseal_document(wrong_bool)
        cases.append(("bool", wrong_bool))
        wrong_scope = deepcopy(documents[0])
        wrong_scope["evidence_scope"] = "deployment_qualification"
        self.reseal_document(wrong_scope)
        cases.append(("scope", wrong_scope))
        wrong_version = deepcopy(documents[0])
        wrong_version["release_qualification"]["candidate"]["write_versions"] = [1]
        self.reseal_material(wrong_version, "candidate")
        cases.append(("version", wrong_version))
        path_alias = deepcopy(documents[0])
        path_alias["release_qualification"]["candidate"]["release"][
            "release_path"
        ] = r"D:\quant\quant_platform\releases\RELEASE-R1"
        self.reseal_material(path_alias, "candidate")
        cases.append(("path", path_alias))
        same_role = deepcopy(documents[0])
        same_role["release_qualification"]["candidate"]["role"] = "prior"
        self.reseal_material(same_role, "candidate")
        cases.append(("role", same_role))
        zero_hash = deepcopy(documents[0])
        zero_hash["schema_contract_sha256"] = "0" * 64
        self.reseal_document(zero_hash)
        cases.append(("zero", zero_hash))
        for label, document in cases:
            with self.subTest(label=label), self.assertRaises(
                ExactReleaseCompatibilityError
            ):
                validate_exact_release_compatibility_evidence(document)

        with self.assertRaisesRegex(ExactReleaseCompatibilityError, "order"):
            validate_exact_release_compatibility_evidence_set(
                tuple(reversed(documents))
            )
        inconsistent = list(deepcopy(documents))
        inconsistent[1]["nonce"] = "nonce-other"
        self.reseal_document(inconsistent[1])
        with self.assertRaisesRegex(ExactReleaseCompatibilityError, "identity"):
            validate_exact_release_compatibility_evidence_set(inconsistent)

        mixed_release = list(deepcopy(documents))
        mixed_candidate = mixed_release[1]["release_qualification"]["candidate"]
        mixed_candidate["release"] = {
            "release_id": "release-r2",
            "release_path": r"D:\quant\quant_platform\releases\release-r2",
            "manifest_sha256": "b" * 64,
        }
        mixed_candidate["inventory_sha256"] = "c" * 64
        mixed_candidate["sealed_core_sha256"] = "d" * 64
        mixed_candidate.pop("material_sha256", None)
        mixed_candidate["material_sha256"] = identity.identity_sha256(
            mixed_candidate
        )
        self.reseal_document(mixed_release[1])
        with self.assertRaisesRegex(ExactReleaseCompatibilityError, "manifest set"):
            validate_exact_release_compatibility_evidence_set(mixed_release)

    def test_exact_capability_only_nonserializable_and_clone_isolated(self) -> None:
        signature = inspect.signature(plan_exact_release_compatibility)
        self.assertEqual(
            {
                "operation",
                "attempt_id",
                "nonce",
                "state_identity_sha256",
                "candidate_manifest",
                "prior_manifest",
            },
            set(signature.parameters),
        )
        self.assertEqual(
            {"closures"},
            set(inspect.signature(build_exact_release_compatibility_evidence).parameters),
        )
        for fake in ({}, object()):
            with self.subTest(fake=type(fake).__name__), self.assertRaisesRegex(
                ExactReleaseCompatibilityError, "exact"
            ):
                build_exact_release_compatibility_evidence(fake)  # type: ignore[arg-type]

        class ClosureSubclass(LockedExactReleaseClosures):
            pass

        forged = object.__new__(ClosureSubclass)
        with self.assertRaisesRegex(ExactReleaseCompatibilityError, "exact"):
            build_exact_release_compatibility_evidence(forged)

        first, _candidate, _prior, planned = self.install_scenario(
            "activation", suffix="capability"
        )
        with self.assertRaisesRegex(ExactReleaseCompatibilityError, "exact"):
            build_exact_release_compatibility_evidence(planned)  # type: ignore[arg-type]
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, str(first["attempt"]), str(first["nonce"])
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            evidence = build_exact_release_compatibility_evidence(closures)
            with self.assertRaises(TypeError):
                pickle.dumps(evidence)
            clone = evidence.document("comments")
            clone["attempt_id"] = "mutated"
            self.assertEqual(
                "attempt-capability",
                evidence.document("comments")["attempt_id"],
            )
            self.assertFalse(hasattr(planned, "documents"))
            closures.close()
            with self.assertRaises(Exception):
                build_exact_release_compatibility_evidence(closures)
            workspace.close()

        with self.assertRaises(ExactReleaseCompatibilityError):
            LockedExactReleaseCompatibilityEvidenceSet(
                documents=evidence.documents,
                aggregate_sha256=planned.aggregate_sha256,
                _construction_token=object(),
            )


if __name__ == "__main__":
    unittest.main()
