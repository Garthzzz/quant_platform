from __future__ import annotations

from copy import deepcopy
from contextlib import closing
import hashlib
import inspect
import json
import os
from pathlib import Path
import pickle
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from quant_hub.ops import local_deployment_persistence as persistence_module
from quant_hub.ops import local_exact_release_compatibility as compatibility_module
from quant_hub.ops import local_exact_runtime_controller_tooling_observer as tooling_observer_module
from quant_hub.ops import local_exact_runtime_tooling as tooling_contract
from quant_hub.ops import local_steady_legacy_c_fence as legacy_c_fence_module
from quant_hub.ops import local_steady_admission_authorization as steady_admission_module
from quant_hub.ops import local_steady_receipt_lineage as receipt_lineage_module
from quant_hub.ops import local_steady_start_authorization as steady_start_module
from quant_hub.ops import local_release_identity as identity
from quant_hub.ops import local_runtime_qualification as qualification_module
from quant_hub.ops.local_deployment_persistence import (
    DEPLOYMENT_ATTEMPT_SCHEMA,
    CompareAndSwapConflict,
    DeploymentJournalError,
    DeploymentLockBusy,
    IncomingCleanupTargetPlan,
    LocalDeploymentPersistence,
    LocalDeploymentPersistenceError,
    LockedExactReleaseClosures,
    LockedExactScmProcessObservationInput,
    LockedExactTransientStartAuthorization,
    LockedVerifiedPhaseCasAuthorization,
    LockedMutableCanarySqliteSet,
    LockedWindowsScmProcessHandleTracking,
    LockedStateSqliteMemoryView,
    LockedStateSqliteSource,
    LockedSteadyBootWorkspace,
    LockedSteadyPairStaticFacts,
    LockedSteadyReleaseClosures,
    LockedNewFile,
    PartialCleanupTargetPlan,
    ReleaseCleanupTargetPlan,
    RetentionPlanningError,
    UnreferencedObjectCleanupTargetPlan,
    UnsafeLocalPath,
    validate_deployment_journal,
    validate_journal_history,
)
from quant_hub.ops.local_exact_runtime_canary_input import (
    LockedExactRuntimeCanaryInput,
)
from quant_hub.ops.local_exact_runtime_canary_live_observer import (
    LockedExactRuntimeCanaryObservation,
)
from quant_hub.ops.local_exact_runtime_tooling_scanner import (
    EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH,
    TestOnlyExactRuntimeToolingAdapter,
)
from quant_hub.ops.local_runtime_qualification import (
    LockedLocalRuntimeQualification,
)
from quant_hub.ops.local_runtime_qualification_evidence import (
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
    LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
    LocalRuntimeQualificationAggregateEvidence,
    build_local_runtime_qualification_evidence,
)


EXACT_MIGRATIONS = (
    "migrations/research_workspace/0001_research_workspace.down.sql",
    "migrations/research_workspace/0001_research_workspace.up.sql",
    "migrations/research_workspace/0002_project_semantics.down.sql",
    "migrations/research_workspace/0002_project_semantics.up.sql",
    "migrations/research_workspace/0003_project_creation_command.down.sql",
    "migrations/research_workspace/0003_project_creation_command.up.sql",
)


ORDINARY_PHASES = (
    "intent_durable", "root_preflight_verified", "state_expand_applied",
    "prior_start_authorized", "prior_verified", "pointer_cas_committed",
    "candidate_start_authorized", "candidate_verified", "binding_cas_committed",
    "terminal_receipt_committed", "cleanup_authorized", "cleanup_planned",
    "cleanup_receipt_committed",
)
BOOTSTRAP_PHASES = (
    "intent_durable", "root_preflight_verified", "state_expand_applied",
    "pointer_cas_committed", "candidate_start_authorized", "candidate_verified",
    "terminal_receipt_committed",
)
EVIDENCE_FIELDS = {
    "root_preflight_sha256", "state_compatibility_sha256",
    "prior_start_authorization_sha256", "prior_runtime_qualification_sha256",
    "pointer_cas_observation_sha256",
    "candidate_start_authorization_sha256", "candidate_runtime_qualification_sha256",
    "binding_cas_observation_sha256", "cleanup_authorization_sha256",
    "controller_verification_sha256",
    "cleanup_receipt_sha256", "write_set_sha256",
    "bootstrap_ingress_closed_sha256", "bootstrap_legacy_c_writer_fence_sha256",
    "failure_original_pointer_observation_sha256",
    "failure_original_binding_observation_sha256",
    "failure_original_service_observation_sha256",
    "failure_original_writer_fence_observation_sha256",
    "failure_state_identity_observation_sha256",
}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def seal(document: dict[str, object], field: str) -> dict[str, object]:
    material = deepcopy(document)
    material.pop(field, None)
    document[field] = identity.identity_sha256(material)
    return document


def observation(document: dict[str, object]) -> dict[str, object]:
    return seal(document, "observation_sha256")


def migration_bytes(release_id: str, relative_path: str) -> bytes:
    return f"-- {release_id}:{relative_path}\nSELECT 1;\n".encode("utf-8")


def release(
    release_id: str,
    payload: bytes,
    character: str,
    *,
    include_migrations: bool = False,
) -> dict[str, object]:
    files = [
        {"path": "app/payload.bin", "bytes": len(payload), "sha256": digest(payload)}
    ]
    if include_migrations:
        for relative_path in EXACT_MIGRATIONS:
            raw = migration_bytes(release_id, relative_path)
            files.append(
                {
                    "path": relative_path,
                    "bytes": len(raw),
                    "sha256": digest(raw),
                }
            )
    inventory = {
        "schema_version": "qrh-release-file-inventory/v2",
        "files": sorted(files, key=lambda item: str(item["path"])),
    }
    return {
        "schema_version": identity.RELEASE_MANIFEST_SCHEMA,
        "release_id": release_id,
        "built_at": "2026-08-26T10:00:00+08:00",
        "application": {
            "source_kind": "git", "commit_sha": character * 40,
            "tracked_tree_sha256": character * 64, "build_tool_version": "b2-tests/v2",
            "provenance": {"builder": "b2-public-test", "labels": []},
        },
        "content": {
            "snapshot_id": f"snapshot-{release_id}",
            "source_inventory_sha256": "1" * 64, "ir_sha256": "2" * 64,
            "knowledge_sha256": "3" * 64, "search_sha256": "4" * 64,
            "page_projection_sha256": "5" * 64, "mcp_sha256": "6" * 64,
            "active_membership_sha256": "7" * 64,
            "knowledge_enrichment": {"status": "not_applicable"},
            "presentation": {"language": "zh-CN"},
        },
        "resources": {"inventory_sha256": identity.identity_sha256(inventory)},
        "state": {"compatibility": {
            "comments": {"read": [1, 2], "write": [1, 2]},
            "research_workspace": {
                "read": [1, 2, 3], "write": [1, 2, 3]
            },
            "rollback_policy": "expand_only_no_down_migration",
        }},
        "inventory": inventory,
    }


def release_ref(document: dict[str, object]) -> dict[str, object]:
    release_id = str(document["release_id"])
    return {
        "release_id": release_id,
        "release_path": f"D:\\quant\\quant_platform\\releases\\{release_id}",
        "manifest_sha256": identity.identity_sha256(document),
    }


def active(document: dict[str, object]) -> dict[str, object]:
    return {"schema_version": identity.ACTIVE_RELEASE_SCHEMA, "release": release_ref(document)}


def state_identity() -> dict[str, object]:
    return seal({
        "schema_version": identity.LOCAL_STATE_IDENTITY_SCHEMA,
        "authority_id": "production-d-state",
        "state_path": r"D:\quant\quant_platform\state",
        "schema_versions": {"comments": 2, "research_workspace": 3},
    }, "identity_sha256")


def pair(active_release: dict[str, object], prior_release: dict[str, object] | None) -> dict[str, object]:
    return {"active": release_ref(active_release), "prior": None if prior_release is None else release_ref(prior_release)}


def binding(active_release: dict[str, object], prior_release: dict[str, object]) -> dict[str, object]:
    result_pair = pair(active_release, prior_release)
    return seal({
        "schema_version": identity.LOCAL_PRIOR_BINDING_SCHEMA,
        "binding_id": f"binding-{active_release['release_id']}-{prior_release['release_id']}",
        "recorded_at": "2026-08-26T10:01:00+08:00", "authority": "retention_evidence_only",
        "active": result_pair["active"], "prior": result_pair["prior"],
        "state_identity": state_identity(),
        "result": {"status": "bound", "pair_sha256": identity.identity_sha256(result_pair),
                   "retained_release_count": 2, "state_policy": "expand_only_no_down_migration"},
    }, "binding_sha256")


def transition_receipt(active_release: dict[str, object], prior_release: dict[str, object], *, attempt: str, rollback: bool = False) -> dict[str, object]:
    result_pair = pair(active_release, prior_release)
    status = "rolled_back" if rollback else "activated"
    return seal({
        "schema_version": identity.ROLLBACK_RECEIPT_SCHEMA if rollback else identity.ACTIVATION_RECEIPT_SCHEMA,
        "receipt_id": f"{'rollback' if rollback else 'activation'}-{attempt}",
        "attempt_id": attempt, "recorded_at": "2026-08-26T10:20:00+08:00",
        "authority": "evidence_only", "operation": "rollback_to_prior" if rollback else "activate_successor",
        "pair": result_pair, "result": {
            "status": status,
            "pair_sha256": identity.identity_sha256(result_pair),
            "controller_verification_sha256": "c" * 64,
        },
    }, "receipt_sha256")


def bootstrap_receipt(r0: dict[str, object], *, attempt: str) -> dict[str, object]:
    result_pair = pair(r0, None)
    final_state = state_identity()
    proof = {"ingress_status": "closed", "legacy_c_writer_status": "fenced",
             "r0_live": release_ref(r0), "writer_fence_sha256": "e" * 64}
    return seal({
        "schema_version": identity.ACTIVATION_RECEIPT_SCHEMA,
        "receipt_id": f"activation-{attempt}", "attempt_id": attempt,
        "recorded_at": "2026-08-26T10:20:00+08:00", "authority": "evidence_only",
        "operation": "bootstrap_first_pair",
        "original": {"active_pointer_status": "absent", "local_prior_binding_status": "absent"},
        "pair": result_pair, "state_identity": final_state, "proof": proof,
        "result": {"status": "bootstrapped", "pair_sha256": identity.identity_sha256(result_pair),
                   "state_identity_sha256": final_state["identity_sha256"],
                   "proof_sha256": identity.identity_sha256(proof)},
    }, "receipt_sha256")


def failure_receipt(
    original_active: dict[str, object] | None,
    candidate: dict[str, object],
    *,
    original_prior: dict[str, object] | None,
    attempt: str,
    operation: str | None = None,
    failed_phase: str = "intent_durable",
) -> dict[str, object]:
    if operation is None:
        operation = (
            "bootstrap_first_pair"
            if original_active is None
            else "activate_successor"
        )
    original = ({"kind": "bootstrap_no_d_pair", "pair": None} if original_active is None
                else {"kind": "release_pair", "pair": pair(original_active, original_prior)})
    candidate_ref = release_ref(candidate)
    original_active_ref = None if original_active is None else release_ref(original_active)
    original_bound_pair = None if original_active is None or original_prior is None else pair(original_active, original_prior)
    original_state = state_identity()
    restoration = {
        "original_active_pointer_observation": observation({
            "status": "absent" if original_active_ref is None else "original_active_restored",
            "observed_release": original_active_ref, "evidence_sha256": "1" * 64,
        }),
        "original_local_prior_binding_observation": observation({
            "status": "absent" if original_bound_pair is None else "original_binding_restored",
            "observed_pair": original_bound_pair, "evidence_sha256": "2" * 64,
        }),
        "original_active_service_live_identity_observation": observation({
            "status": "absent" if original_active_ref is None else "original_active_live",
            "observed_release": original_active_ref, "evidence_sha256": "3" * 64,
        }),
        "original_active_writer_fence_observation": observation({
            "status": "d_writer_absent_or_fenced" if original_active_ref is None else "original_active_writer_fence_restored",
            "observed_release": original_active_ref, "evidence_sha256": "4" * 64,
        }),
        "current_d_state_identity_observation": observation({
            "status": "d_state_not_externally_written" if original_active_ref is None else "current_d_state_identity_unchanged",
            "observed_state_identity": state_identity(), "evidence_sha256": "5" * 64,
        }),
    }
    return seal({
        "schema_version": identity.FAILURE_RECEIPT_SCHEMA,
        "receipt_id": f"failure-{attempt}", "attempt_id": attempt,
        "recorded_at": "2026-08-26T10:21:00+08:00", "authority": "evidence_only",
        "operation": operation,
        "original_pair": original, "candidate": candidate_ref, "failed_phase": failed_phase,
        "original_state_identity": original_state,
        "restoration_evidence": restoration,
        "result": {"status": "failed", "original_pair_sha256": identity.identity_sha256(original),
                   "candidate_manifest_sha256": candidate_ref["manifest_sha256"],
                   "original_state_identity_sha256": original_state["identity_sha256"],
                   "restoration_evidence_sha256": identity.identity_sha256(restoration)},
    }, "receipt_sha256")


def release_cleanup_target(document: dict[str, object]) -> dict[str, object]:
    return {"kind": "release_closure", "release": release_ref(document),
            "closure_sha256": document["resources"]["inventory_sha256"]}


def cleanup_receipt(active_release: dict[str, object], prior_release: dict[str, object],
                    targets: list[dict[str, object]], *, attempt: str) -> dict[str, object]:
    result_pair = pair(active_release, prior_release)
    ordered = sorted(targets, key=lambda item: (
        str(item["kind"]),
        str(item["release"]["release_path"] if item["kind"] == "release_closure" else item["path"]).casefold(),
        identity.identity_sha256(item),
    ))
    return seal({
        "schema_version": identity.CLEANUP_RECEIPT_SCHEMA,
        "receipt_id": f"cleanup-{attempt}", "attempt_id": attempt,
        "recorded_at": "2026-08-26T10:30:00+08:00", "authority": "evidence_only",
        "retained_pair": result_pair, "removed_targets": ordered,
        "result": {"status": "cleaned", "retained_pair_sha256": identity.identity_sha256(result_pair),
                   "removed_targets_sha256": identity.identity_sha256(ordered), "removed_count": len(ordered)},
    }, "receipt_sha256")


def journal(original_active: dict[str, object] | None, candidate: dict[str, object], *,
            original_prior: dict[str, object] | None = None,
            cleanup_targets: list[dict[str, object]] | None = None,
            operation: str = "activation", attempt: str = "attempt-1", nonce: str = "nonce-1") -> dict[str, object]:
    bootstrap = operation == "bootstrap_first_pair"
    original_pair = None if bootstrap else pair(original_active, original_prior)  # type: ignore[arg-type]
    if bootstrap:
        target_pair = pair(candidate, None)
        success = {"activation": f"activation-{attempt}", "rollback": None}
    elif operation == "activation":
        target_pair = pair(candidate, original_active)
        success = {"activation": f"activation-{attempt}", "rollback": None}
    else:
        if original_active is None or original_prior is None:
            raise AssertionError("rollback fixture requires pair")
        candidate = original_prior
        target_pair = pair(original_prior, original_active)
        success = {"activation": None, "rollback": f"rollback-{attempt}"}
    targets = sorted(cleanup_targets or [], key=lambda item: (
        str(item["kind"]),
        str(item["release"]["release_path"] if item["kind"] == "release_closure" else item["path"]).casefold(),
        identity.identity_sha256(item),
    ))
    expected_binding = (
        None
        if bootstrap or original_prior is None
        else binding(original_active, original_prior)  # type: ignore[arg-type]
    )
    desired_binding = (
        None
        if bootstrap
        else binding(candidate, original_active)  # type: ignore[arg-type]
    )
    value: dict[str, object] = {
        "schema_version": DEPLOYMENT_ATTEMPT_SCHEMA, "attempt": attempt, "operation": operation,
        "revision": 0, "phase": "intent_durable", "nonce": nonce,
        "timestamps": {"created_at": "2026-08-26T10:02:00+08:00", "updated_at": "2026-08-26T10:02:00+08:00"},
        "previous_journal_sha256": None, "original_pair": original_pair, "candidate": release_ref(candidate),
        "target_pair": target_pair,
        "pointer_cas": {"expected": None if bootstrap else original_pair["active"], "desired": target_pair["active"]},
        "binding_cas": {
            "expected_binding": expected_binding,
            "desired_binding": desired_binding,
            "expected_binding_sha256": None if expected_binding is None else expected_binding["binding_sha256"],
            "desired_binding_sha256": None if desired_binding is None else desired_binding["binding_sha256"],
        },
        "state_plan": {"state_identity_sha256": state_identity()["identity_sha256"],
                       "expand_plan_sha256": "6" * 64,
                       "compatibility_sha256": identity.identity_sha256([
                           {"name": name, "compatibility_manifest_sha256": "b" * 64}
                           for name in ("comments", "research_workspace")
                       ]),
                       "database_names": ["comments", "research_workspace"]},
        "database_seals": [], "transient_start": [],
        "reserved_receipt_ids": {**success, "failure": f"failure-{attempt}",
                                 "cleanup": None if bootstrap else f"cleanup-{attempt}"},
        "cleanup_targets": targets, "evidence_hashes": {field: None for field in EVIDENCE_FIELDS},
        "terminal_receipt": None,
    }
    return seal(value, "journal_sha256")


def advance_one(previous: dict[str, object], *, receipt: dict[str, object] | None = None,
                cleanup: dict[str, object] | None = None, failure: bool = False) -> dict[str, object]:
    value = deepcopy(previous)
    value["revision"] = int(previous["revision"]) + 1
    value["previous_journal_sha256"] = previous["journal_sha256"]
    value["timestamps"]["updated_at"] = f"2026-08-26T10:{2 + int(value['revision']):02d}:00+08:00"
    if failure:
        value["phase"] = "failure_receipt_committed"
        if receipt is None:
            raise AssertionError("failure receipt required")
        restoration = receipt["restoration_evidence"]
        for field, receipt_field in {
            "failure_original_pointer_observation_sha256": "original_active_pointer_observation",
            "failure_original_binding_observation_sha256": "original_local_prior_binding_observation",
            "failure_original_service_observation_sha256": "original_active_service_live_identity_observation",
            "failure_original_writer_fence_observation_sha256": "original_active_writer_fence_observation",
            "failure_state_identity_observation_sha256": "current_d_state_identity_observation",
        }.items():
            value["evidence_hashes"][field] = restoration[receipt_field]["observation_sha256"]
        value["terminal_receipt"] = {"kind": "failure", "receipt_id": receipt["receipt_id"],
                                     "receipt_sha256": receipt["receipt_sha256"],
                                     "operation": receipt["operation"],
                                     "failed_phase": receipt["failed_phase"]}
        return seal(value, "journal_sha256")
    phases = BOOTSTRAP_PHASES if value["operation"] == "bootstrap_first_pair" else ORDINARY_PHASES
    phase = phases[phases.index(str(previous["phase"])) + 1]
    value["phase"] = phase
    evidence = {
        "root_preflight_verified": ("root_preflight_sha256",),
        "state_expand_applied": ("state_compatibility_sha256",),
        "prior_start_authorized": ("prior_start_authorization_sha256",),
        "prior_verified": ("prior_runtime_qualification_sha256",),
        "pointer_cas_committed": ("pointer_cas_observation_sha256",),
        "candidate_start_authorized": ("candidate_start_authorization_sha256",),
        "candidate_verified": ("candidate_runtime_qualification_sha256",),
        "binding_cas_committed": ("binding_cas_observation_sha256",),
        "cleanup_receipt_committed": ("cleanup_receipt_sha256", "write_set_sha256"),
    }
    for field in evidence.get(phase, ()):
        if field not in {
            "prior_start_authorization_sha256",
            "candidate_start_authorization_sha256",
        }:
            value["evidence_hashes"][field] = "d" * 64
    if phase == "cleanup_receipt_committed":
        if cleanup is None:
            raise AssertionError("cleanup receipt required")
        value["evidence_hashes"]["cleanup_receipt_sha256"] = cleanup["receipt_sha256"]
    if phase == "state_expand_applied":
        value["evidence_hashes"]["state_compatibility_sha256"] = value[
            "state_plan"
        ]["compatibility_sha256"]
        value["database_seals"] = [{"name": name, "seal_sha256": "a" * 64,
                                     "compatibility_manifest_sha256": "b" * 64}
                                    for name in value["state_plan"]["database_names"]]
    if phase == "prior_start_authorized":
        reference = value["original_pair"]["active"] if value["operation"] == "activation" else value["candidate"]
        start = {"role": "prior", "release": reference,
                 "start_nonce": f"prior-{value['nonce']}"}
        start["scm_identity_sha256"] = (
            persistence_module._transient_scm_start_plan_sha256(value, start)
        )
        value["transient_start"].append(start)
        value["evidence_hashes"]["prior_start_authorization_sha256"] = (
            persistence_module._transient_start_authorization_sha256(value, start)
        )
    if phase == "candidate_start_authorized":
        role = "baseline" if value["operation"] == "bootstrap_first_pair" else "candidate"
        start = {"role": role, "release": value["candidate"],
                 "start_nonce": f"{role}-{value['nonce']}"}
        start["scm_identity_sha256"] = (
            persistence_module._transient_scm_start_plan_sha256(value, start)
        )
        value["transient_start"].append(start)
        value["transient_start"] = sorted(value["transient_start"], key=lambda item: (item["role"], item["release"]["release_id"]))
        value["evidence_hashes"]["candidate_start_authorization_sha256"] = (
            persistence_module._transient_start_authorization_sha256(value, start)
        )
    if phase == "terminal_receipt_committed":
        if receipt is None:
            raise AssertionError("success receipt required")
        kind = "rollback" if value["operation"] == "rollback" else "activation"
        value["terminal_receipt"] = {"kind": kind, "receipt_id": receipt["receipt_id"],
                                     "receipt_sha256": receipt["receipt_sha256"]}
        if value["operation"] == "bootstrap_first_pair":
            value["evidence_hashes"]["bootstrap_ingress_closed_sha256"] = "1" * 64
            value["evidence_hashes"]["bootstrap_legacy_c_writer_fence_sha256"] = "2" * 64
        else:
            value["evidence_hashes"]["controller_verification_sha256"] = receipt["result"]["controller_verification_sha256"]
    if phase == "cleanup_authorized":
        value["evidence_hashes"]["cleanup_authorization_sha256"] = identity.identity_sha256(
            {"attempt_id": value["attempt"], "terminal_receipt": value["terminal_receipt"],
             "cleanup_targets": value["cleanup_targets"]})
    return seal(value, "journal_sha256")


def history_to(first: dict[str, object], phase: str, *, receipt: dict[str, object] | None = None,
               cleanup: dict[str, object] | None = None) -> list[dict[str, object]]:
    history = [first]
    phases = BOOTSTRAP_PHASES if first["operation"] == "bootstrap_first_pair" else ORDINARY_PHASES
    while history[-1]["phase"] != phase:
        next_phase = phases[int(history[-1]["revision"]) + 1]
        history.append(advance_one(
            history[-1],
            receipt=receipt if next_phase == "terminal_receipt_committed" else None,
            cleanup=cleanup if next_phase == "cleanup_receipt_committed" else None,
        ))
    return history


class PersistenceFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.persistence = LocalDeploymentPersistence.for_test_only(self.root, allow_posix_test_only=True)
        self.payloads = {"release-r-minus-1": b"old-prior", "release-r0": b"active-r0",
                         "release-r1": b"candidate-r1", "release-r2": b"third-r2"}
        self.r_minus_1 = release("release-r-minus-1", self.payloads["release-r-minus-1"], "8")
        self.r0 = release("release-r0", self.payloads["release-r0"], "9")
        self.r1 = release("release-r1", self.payloads["release-r1"], "a")
        self.r2 = release("release-r2", self.payloads["release-r2"], "b")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def materialize(self, document: dict[str, object]) -> Path:
        release_root = self.persistence.layout.releases / str(document["release_id"])
        for item in document["inventory"]["files"]:
            relative = str(item["path"])
            target = release_root.joinpath(*relative.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            raw = (
                self.payloads[str(document["release_id"])]
                if relative == "app/payload.bin"
                else migration_bytes(str(document["release_id"]), relative)
            )
            target.write_bytes(raw)
        (release_root / "release_manifest.json").write_bytes(identity.canonical_bytes(document))
        return release_root

    def write_pair(self, active_release: dict[str, object], prior_release: dict[str, object]) -> None:
        with self.persistence.global_lock() as lock:
            self.persistence.cas_active_release(lock=lock, expected=None, desired=active(active_release))
            self.persistence.cas_local_prior_binding(lock=lock, expected=None, desired=binding(active_release, prior_release))

    def append_history(self, history: list[dict[str, object]]) -> None:
        with self.persistence.global_lock() as lock:
            for item in history:
                self.persistence.journals.append(item, lock=lock)


class RootLockAndCasTests(PersistenceFixture):
    def test_product_root_has_no_injection_and_posix_is_explicit_test_only(self) -> None:
        self.assertEqual({}, inspect.signature(LocalDeploymentPersistence.production).parameters)
        with self.assertRaises(TypeError):
            LocalDeploymentPersistence(self.root)  # type: ignore[call-arg]
        if os.name != "nt":
            with tempfile.TemporaryDirectory() as temporary, self.assertRaisesRegex(UnsafeLocalPath, "POSIX"):
                LocalDeploymentPersistence.for_test_only(Path(temporary).resolve())

    @unittest.skipUnless(os.name == "nt", "production provenance is Windows-only")
    def test_product_persistence_method_shadow_is_structurally_impossible(self) -> None:
        production_root = Path(r"D:\quant\quant_platform")
        if not production_root.is_dir():
            with self.assertRaises(UnsafeLocalPath):
                LocalDeploymentPersistence.production_read_only()
            self.assertNotIn("__dict__", LocalDeploymentPersistence.__dict__)
            return
        persistence = LocalDeploymentPersistence.production_read_only()
        for method_name in (
            "consume_verified_phase_next_cas",
            "bind_attempt_workspace",
            "global_lock",
        ):
            with self.subTest(method_name=method_name), self.assertRaises(AttributeError):
                object.__setattr__(
                    persistence,
                    method_name,
                    lambda *_args, **_kwargs: None,
                )
        with self.assertRaises(AttributeError):
            _ = persistence.__dict__
        LocalDeploymentPersistence._assert_production_provenance(persistence)

    @unittest.skipUnless(os.name == "nt", "production D alias contract is Windows-only")
    def test_test_only_factory_rejects_every_exact_production_root_alias_before_init(self) -> None:
        aliases = (
            Path(r"D:\quant\quant_platform"),
            Path(r"D:\quant\quant_platform\."),
            Path(r"D:\quant\quant_platform\child\.."),
            Path(r"d:/QUANT/quant_PLATFORM"),
        )
        with patch.object(
            LocalDeploymentPersistence,
            "__init__",
            side_effect=AssertionError("layout construction must not run"),
        ):
            for alias in aliases:
                with self.subTest(alias=str(alias)):
                    with self.assertRaisesRegex(
                        UnsafeLocalPath, "production exact D root/alias"
                    ):
                        LocalDeploymentPersistence.for_test_only(alias)

        with tempfile.TemporaryDirectory(dir=self.root) as temporary, patch.object(
            Path,
            "exists",
            return_value=True,
        ), patch(
            "quant_hub.ops.local_deployment_persistence.os.path.samefile",
            return_value=True,
        ), patch.object(
            LocalDeploymentPersistence,
            "__init__",
            side_effect=AssertionError("same-file alias must not construct layout"),
        ):
            with self.assertRaisesRegex(
                UnsafeLocalPath, "production exact D root/alias"
            ):
                LocalDeploymentPersistence.for_test_only(Path(temporary))

    def test_case_and_escape_fail_before_layout_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "Control").mkdir()
            with self.assertRaisesRegex(UnsafeLocalPath, "大小写"):
                LocalDeploymentPersistence.for_test_only(root, allow_posix_test_only=True)
            self.assertFalse((root / "locks").exists())
        with self.assertRaisesRegex(UnsafeLocalPath, "逃逸"):
            self.persistence.assert_write_path(self.root.parent / "outside")

    def test_persistent_lock_file_is_not_occupancy(self) -> None:
        first = self.persistence.global_lock()
        second = self.persistence.global_lock()
        with first:
            self.assertTrue(self.persistence.layout.deployment_lock.exists())
            with self.assertRaises(DeploymentLockBusy):
                second.acquire()
        with second:
            self.assertTrue(second.held)

    def test_owner_kill_releases_cross_process_kernel_lock(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src"
        helper = (
            "from pathlib import Path\nimport sys,time\n"
            "from quant_hub.ops.local_deployment_persistence import LocalDeploymentPersistence\n"
            "p=LocalDeploymentPersistence.for_test_only(Path(sys.argv[1]).resolve(),allow_posix_test_only=True)\n"
            "with p.global_lock():\n print('LOCKED',flush=True)\n time.sleep(300)\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(source_root)
        process = subprocess.Popen(
            [sys.executable, "-c", helper, str(self.root)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=environment,
        )
        try:
            assert process.stdout is not None
            self.assertEqual("LOCKED", process.stdout.readline().strip())
            with self.assertRaises(DeploymentLockBusy):
                self.persistence.global_lock().acquire()
            process.kill()
            process.wait(timeout=15)
            deadline = time.monotonic() + 10
            while True:
                try:
                    acquired = self.persistence.global_lock().acquire()
                except DeploymentLockBusy:
                    if time.monotonic() >= deadline:
                        self.fail("owner kill 后 kernel lock 未释放")
                    time.sleep(0.05)
                else:
                    acquired.release()
                    break
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=15)
            process.communicate(timeout=5)

    def test_active_and_binding_cas_expected_desired_third_value(self) -> None:
        with self.persistence.global_lock() as lock:
            self.assertEqual("swapped", self.persistence.cas_active_release(
                lock=lock, expected=None, desired=active(self.r0)).outcome)
            self.assertEqual("already_desired", self.persistence.cas_active_release(
                lock=lock, expected=None, desired=active(self.r0)).outcome)
            self.persistence.cas_active_release(lock=lock, expected=active(self.r0), desired=active(self.r1))
            with self.assertRaises(CompareAndSwapConflict):
                self.persistence.cas_active_release(lock=lock, expected=active(self.r0), desired=active(self.r2))
            b0 = binding(self.r0, self.r_minus_1)
            b1 = binding(self.r1, self.r0)
            self.persistence.cas_local_prior_binding(lock=lock, expected=None, desired=b0)
            self.persistence.cas_local_prior_binding(lock=lock, expected=b0, desired=b1)
        self.assertEqual(identity.canonical_bytes(active(self.r1)), self.persistence.layout.active_release.read_bytes())

    def test_raw_cas_seams_reject_product_mode_without_writing(self) -> None:
        with self.persistence.global_lock() as lock:
            self.persistence._test_only = False
            try:
                with self.assertRaisesRegex(
                    DeploymentLockBusy, "one-shot authorization"
                ):
                    self.persistence.cas_active_release(
                        lock=lock,
                        expected=None,
                        desired=active(self.r0),
                    )
                with self.assertRaisesRegex(
                    DeploymentLockBusy, "one-shot authorization"
                ):
                    self.persistence.cas_local_prior_binding(
                        lock=lock,
                        expected=None,
                        desired=binding(self.r0, self.r_minus_1),
                    )
            finally:
                self.persistence._test_only = True
        self.assertFalse(self.persistence.layout.active_release.exists())
        self.assertFalse(self.persistence.layout.local_prior_binding.exists())

    def test_steady_boot_workspace_is_distinct_fresh_process_local_owner(self) -> None:
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            self.assertIsInstance(workspace, LockedSteadyBootWorkspace)
            self.assertEqual("steady_boot_workspace_only", workspace.scope)
            first_nonce = workspace.boot_nonce
            self.assertRegex(first_nonce, r"^[0-9a-f]{48}$")
            for transient_name in (
                "attempt_id",
                "nonce",
                "operation",
                "journals",
                "open_new_file",
                "atomic_replace",
                "remove_exact_transient",
                "__dict__",
            ):
                self.assertFalse(hasattr(workspace, transient_name), transient_name)
            with self.assertRaises(TypeError):
                pickle.dumps(workspace)
            with self.assertRaises(TypeError):
                workspace._boot_nonce = "f" * 48
            with self.assertRaises(DeploymentLockBusy):
                self.persistence.bind_steady_boot_workspace(lock)
            with self.assertRaises(DeploymentLockBusy):
                self.persistence.bind_attempt_workspace(
                    lock, "attempt-mixed", "nonce-mixed"
                )
            workspace.close()
            with self.assertRaises(DeploymentLockBusy):
                _ = workspace.scope
            second = self.persistence.bind_steady_boot_workspace(lock)
            self.assertNotEqual(first_nonce, second.boot_nonce)
            second.close()

        with self.assertRaises(TypeError):
            class DerivedSteadyWorkspace(LockedSteadyBootWorkspace):
                pass

    def test_steady_workspace_rejects_pending_journal_before_nonce_generation(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        with self.persistence.global_lock() as lock:
            self.persistence.journals.append(first, lock=lock)
            with patch.object(
                persistence_module.secrets,
                "token_hex",
                wraps=persistence_module.secrets.token_hex,
            ) as nonce_generator:
                with self.assertRaisesRegex(
                    DeploymentJournalError, "active deployment journal"
                ):
                    self.persistence.bind_steady_boot_workspace(lock)
                nonce_generator.assert_not_called()

    def test_steady_workspace_auto_closes_before_kernel_unlock(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_steady_boot_workspace(lock)
        nonce = workspace.boot_nonce
        lock.release()
        self.assertFalse(lock.held)
        self.assertRegex(nonce, r"^[0-9a-f]{48}$")
        with self.assertRaises(DeploymentLockBusy):
            _ = workspace.boot_nonce

        lock.acquire()
        try:
            replay = self.persistence.bind_steady_boot_workspace(lock)
            self.assertNotEqual(nonce, replay.boot_nonce)
        finally:
            lock.release()

    def test_steady_admission_authorization_replacement_is_destination_first(
        self,
    ) -> None:
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            lifetime = object()
            prepare = object.__new__(
                steady_admission_module.LockedSteadyAdmissionPrepareAuthorization
            )
            for name, value in {
                "_workspace": workspace,
                "_lifetime": lifetime,
                "_state": "live",
                "_sealed": True,
            }.items():
                object.__setattr__(prepare, name, value)
            workspace._register_steady_admission_authorization(prepare)
            self.assertEqual(
                {prepare}, workspace._steady_admission_authorizations
            )
            object.__setattr__(prepare, "_state", "prepared")
            commit = object.__new__(
                steady_admission_module.LockedSteadyAdmissionCommitAuthorization
            )
            for name, value in {
                "_workspace": workspace,
                "_lifetime": lifetime,
                "_state": "live",
                "_sealed": True,
            }.items():
                object.__setattr__(commit, name, value)
            workspace._replace_steady_admission_authorization(prepare, commit)
            self.assertEqual("consumed", prepare._state)
            self.assertEqual(
                {commit}, workspace._steady_admission_authorizations
            )
            object.__setattr__(commit, "_state", "consumed")
            workspace._release_steady_admission_authorization(commit)
            workspace.close()

    def test_pointer_case_and_symlink_reparse_fail_closed(self) -> None:
        wrong_case = self.persistence.layout.control / "Active_release.json"
        wrong_case.write_bytes(identity.canonical_bytes(active(self.r0)))
        with self.assertRaisesRegex(UnsafeLocalPath, "大小写"):
            self.persistence.read_active_release()
        wrong_case.unlink()
        with tempfile.TemporaryDirectory() as external_text:
            external = Path(external_text) / "active.json"
            external.write_bytes(identity.canonical_bytes(active(self.r0)))
            try:
                self.persistence.layout.active_release.symlink_to(external)
            except OSError as error:
                self.skipTest(f"当前主机不能创建 symlink/reparse fixture: {error}")
            with self.assertRaisesRegex(UnsafeLocalPath, "symlink|reparse"):
                self.persistence.read_active_release()

    @unittest.skipUnless(os.name == "nt", "真实 no-share-delete 竞态只在 Windows 产品语义执行")
    def test_lock_owner_holds_exact_root_rename_guard(self) -> None:
        destination = self.root.parent / f"{self.root.name}-held"
        with self.persistence.global_lock():
            with self.assertRaises(OSError):
                self.root.rename(destination)
        self.assertTrue(self.root.is_dir())

    @unittest.skipUnless(os.name == "nt", "真实 no-share-delete 竞态只在 Windows 产品语义执行")
    def test_control_parent_swap_after_preflight_cannot_escape_first_write(self) -> None:
        with tempfile.TemporaryDirectory() as external_text:
            external = Path(external_text).resolve()
            moved = self.root / "control-held"
            switched = False
            real_replace = os.replace

            def attack(source: object, destination: object, *args: object, **kwargs: object) -> None:
                nonlocal switched
                try:
                    self.persistence.layout.control.rename(moved)
                    self.persistence.layout.control.symlink_to(external, target_is_directory=True)
                    switched = True
                except OSError:
                    switched = False
                real_replace(source, destination, *args, **kwargs)

            with self.persistence.global_lock() as lock, patch.object(persistence_module.os, "replace", side_effect=attack):
                self.persistence.cas_active_release(lock=lock, expected=None, desired=active(self.r0))
            self.assertFalse(switched)
            self.assertFalse((external / "active_release.json").exists())

    @unittest.skipUnless(os.name == "nt", "真实 no-share-delete 竞态只在 Windows 产品语义执行")
    def test_journal_parent_swap_after_preflight_cannot_escape_first_write(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        with tempfile.TemporaryDirectory() as external_text:
            external = Path(external_text).resolve()
            moved = self.persistence.layout.audit / "deployment_attempts-held"
            switched = False
            real_replace = os.replace

            def attack(source: object, destination: object, *args: object, **kwargs: object) -> None:
                nonlocal switched
                try:
                    self.persistence.layout.journals.rename(moved)
                    self.persistence.layout.journals.symlink_to(external, target_is_directory=True)
                    switched = True
                except OSError:
                    switched = False
                real_replace(source, destination, *args, **kwargs)

            with self.persistence.global_lock() as lock, patch.object(persistence_module.os, "replace", side_effect=attack):
                self.persistence.journals.append(first, lock=lock)
            self.assertFalse(switched)
            self.assertEqual([], list(external.iterdir()))

    @unittest.skipUnless(os.name == "nt", "真实 no-share-delete 竞态只在 Windows 产品语义执行")
    def test_temporary_parent_swap_at_first_temp_write_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as external_text:
            external = Path(external_text).resolve()
            moved = self.root / "tmp-held"
            switched = False
            bound_type = persistence_module._BoundDirectory
            real_open = bound_type.open_file

            def attack(bound: object, name: str, flags: int, mode: int = 0o600) -> int:
                nonlocal switched
                if bound.path == self.persistence.layout.temporary and name.endswith(".tmp"):
                    try:
                        self.persistence.layout.temporary.rename(moved)
                        self.persistence.layout.temporary.symlink_to(
                            external, target_is_directory=True
                        )
                        switched = True
                    except OSError:
                        switched = False
                return real_open(bound, name, flags, mode)

            with self.persistence.global_lock() as lock, patch.object(
                bound_type, "open_file", new=attack
            ):
                self.persistence.cas_active_release(
                    lock=lock, expected=None, desired=active(self.r0)
                )
            self.assertFalse(switched)
            self.assertEqual([], list(external.iterdir()))


class AttemptWorkspaceSeamTests(PersistenceFixture):
    def workspace_path(
        self,
        attempt: str = "attempt-seam",
        nonce: str = "nonce-seam",
    ) -> Path:
        return (
            self.persistence.layout.temporary
            / "deployment-attempts"
            / f"{attempt}-{nonce}"
        )

    def cross_process_lock_probe(self) -> str:
        source_root = Path(__file__).resolve().parents[1] / "src"
        helper = (
            "from pathlib import Path\nimport sys\n"
            "from quant_hub.ops.local_deployment_persistence import "
            "DeploymentLockBusy,LocalDeploymentPersistence\n"
            "p=LocalDeploymentPersistence.for_test_only("
            "Path(sys.argv[1]).resolve(),allow_posix_test_only=True)\n"
            "try:\n"
            " with p.global_lock(): print('ACQUIRED')\n"
            "except DeploymentLockBusy: print('BUSY')\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(source_root)
        return subprocess.check_output(
            [sys.executable, "-c", helper, str(self.root)],
            text=True,
            env=environment,
            timeout=15,
        ).strip()

    def test_lock_authority_owner_thread_and_release_are_all_required(self) -> None:
        other = LocalDeploymentPersistence.for_test_only(
            self.root, allow_posix_test_only=True
        )
        lock = self.persistence.global_lock()
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.assert_global_lock(lock)
        workspace = None
        with lock:
            self.persistence.assert_global_lock(lock)
            with self.assertRaises(DeploymentLockBusy):
                other.assert_global_lock(lock)
            failures: list[type[BaseException] | None] = []

            def wrong_thread() -> None:
                try:
                    self.persistence.assert_global_lock(lock)
                except BaseException as error:  # noqa: BLE001 - exact public boundary
                    failures.append(type(error))
                else:
                    failures.append(None)

            thread = threading.Thread(target=wrong_thread)
            thread.start()
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
            self.assertEqual([DeploymentLockBusy], failures)
            workspace = self.persistence.bind_attempt_workspace(
                lock, "attempt-owner", "nonce-owner"
            )
            workspace.create_exact_directory("state")
        assert workspace is not None
        with self.assertRaises(UnsafeLocalPath):
            workspace.preflight("state", expected_kind="directory")
        workspace.close()

    def test_locked_new_file_and_workspace_cannot_escape_owner_or_lock_epoch(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-lifecycle", "nonce-lifecycle"
        )
        workspace.create_exact_directory("state")
        opened_file = workspace.open_new_file("state/proof.bin")
        self.assertIsInstance(opened_file, LockedNewFile)
        for leaked_name in (
            "fileno",
            "descriptor",
            "_descriptor",
            "path",
            "write",
            "__dict__",
        ):
            self.assertFalse(hasattr(opened_file, leaked_name), leaked_name)
        with self.assertRaises(TypeError):
            os.write(opened_file, b"raw-fd-bypass")  # type: ignore[arg-type]
        self.assertFalse(hasattr(lock, "acquisition_epoch"))
        self.assertFalse(hasattr(workspace, "acquisition_epoch"))
        with self.assertRaises(TypeError):
            pickle.dumps(lock._acquisition_epoch)  # noqa: SLF001 - invariant audit
        with self.assertRaises(UnsafeLocalPath):
            LockedNewFile(
                workspace=workspace,
                _construction_token=object(),
            )

        failures: list[tuple[str, type[BaseException] | None]] = []

        def wrong_thread() -> None:
            try:
                opened_file.write_all(b"wrong-thread")
            except BaseException as error:  # noqa: BLE001 - exact seam audit
                failures.append(("write", type(error)))
            else:
                failures.append(("write", None))
            try:
                opened_file.fsync()
            except BaseException as error:  # noqa: BLE001 - exact seam audit
                failures.append(("fsync", type(error)))
            else:
                failures.append(("fsync", None))
            try:
                opened_file.close()
            except BaseException as error:  # noqa: BLE001 - exact seam audit
                failures.append(("file-close", type(error)))
            else:
                failures.append(("file-close", None))
            try:
                workspace.close()
            except BaseException as error:  # noqa: BLE001 - exact seam audit
                failures.append(("workspace-close", type(error)))
            else:
                failures.append(("workspace-close", None))
            try:
                lock.release()
            except BaseException as error:  # noqa: BLE001 - exact seam audit
                failures.append(("release", type(error)))
            else:
                failures.append(("release", None))

        thread = threading.Thread(target=wrong_thread)
        thread.start()
        thread.join(timeout=10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(
            [
                ("write", DeploymentLockBusy),
                ("fsync", DeploymentLockBusy),
                ("file-close", DeploymentLockBusy),
                ("workspace-close", DeploymentLockBusy),
                ("release", DeploymentLockBusy),
            ],
            failures,
        )
        self.assertTrue(lock.held)
        self.persistence.assert_global_lock(lock)
        self.assertEqual(len(b"owner"), opened_file.write_all(b"owner"))
        opened_file.fsync()

        lock.release()
        self.assertFalse(lock.held)
        with self.assertRaises(UnsafeLocalPath):
            opened_file.write_all(b"after-release")
        with self.assertRaises(UnsafeLocalPath):
            opened_file.write_all(b"")
        with self.assertRaises(UnsafeLocalPath):
            opened_file.fsync()
        with self.assertRaises(UnsafeLocalPath):
            workspace.atomic_replace("state/proof.bin", b"after-release")

        lock.acquire()
        try:
            with self.assertRaises(UnsafeLocalPath):
                workspace.atomic_replace("state/proof.bin", b"revived")
            with self.assertRaises(UnsafeLocalPath):
                opened_file.write_all(b"revived")
            with self.persistence.bind_attempt_workspace(
                lock, "attempt-lifecycle", "nonce-lifecycle"
            ) as replayed:
                self.assertIsNotNone(
                    replayed.preflight(
                        "state/proof.bin",
                        expected_kind="file",
                        allow_absent=False,
                    )
                )
                replayed.atomic_replace("state/proof.bin", b"new-epoch")
        finally:
            lock.release()
        self.assertEqual(
            b"new-epoch",
            self.workspace_path(
                "attempt-lifecycle", "nonce-lifecycle"
            ).joinpath("state", "proof.bin").read_bytes(),
        )

    def test_explicit_workspace_close_closes_children_and_unregisters(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-explicit", "nonce-explicit"
        )
        workspace.create_exact_directory("state")
        with workspace.open_new_file("state/comments.sqlite3") as main_file:
            main_file.write_all(b"sqlite-main")
            main_file.fsync()
        pinned = workspace.pin_sqlite_set("state/comments.sqlite3")
        pending_file = workspace.open_new_file("state/pending.bin")
        pending_file.write_all(b"pending")
        workspace.close()
        with self.assertRaises(UnsafeLocalPath):
            pinned.read_bytes("main")
        self.assertEqual((), pinned.members)
        with self.assertRaises(UnsafeLocalPath):
            pending_file.write_all(b"after-close")
        with self.persistence.bind_attempt_workspace(
            lock, "attempt-followup", "nonce-followup"
        ) as followup:
            followup.create_exact_directory("state")
        lock.release()

    def test_release_closes_multiple_workspaces_open_files_pins_and_guards(self) -> None:
        lock = self.persistence.global_lock().acquire()
        first = self.persistence.bind_attempt_workspace(
            lock, "attempt-multi-a", "nonce-multi-a"
        )
        second = self.persistence.bind_attempt_workspace(
            lock, "attempt-multi-b", "nonce-multi-b"
        )
        first.create_exact_directory("state")
        second.create_exact_directory("state")
        with first.open_new_file("state/comments.sqlite3") as main_file:
            main_file.write_all(b"sqlite-main")
            main_file.fsync()
        pinned = first.pin_sqlite_set("state/comments.sqlite3")
        pending_file = second.open_new_file("state/pending.bin")
        pending_file.write_all(b"before-release")
        pending_file.fsync()

        lock.release()
        self.assertFalse(lock.held)
        for workspace in (first, second):
            with self.assertRaises(UnsafeLocalPath):
                workspace.preflight("state", expected_kind="directory")
        with self.assertRaises(UnsafeLocalPath):
            pinned.read_bytes("main")
        with self.assertRaises(UnsafeLocalPath):
            pending_file.write_all(b"after-release")

        parent = self.persistence.layout.temporary / "deployment-attempts"
        moved = self.persistence.layout.temporary / "deployment-attempts-closed"
        parent.rename(moved)
        moved.rename(parent)

        lock.acquire()
        try:
            with self.persistence.bind_attempt_workspace(
                lock, "attempt-multi-b", "nonce-multi-b"
            ) as replayed:
                self.assertIsNotNone(
                    replayed.preflight(
                        "state/pending.bin",
                        expected_kind="file",
                        allow_absent=False,
                    )
                )
        finally:
            lock.release()

    def test_wrong_pid_release_is_rejected_without_mutating_lock_or_dependents(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-pid", "nonce-pid"
        )
        workspace.create_exact_directory("state")
        opened_file = workspace.open_new_file("state/proof.bin")
        actual_pid = os.getpid()
        with patch.object(
            persistence_module.os, "getpid", return_value=actual_pid + 1
        ):
            with self.assertRaises(DeploymentLockBusy):
                lock.release()
        self.assertTrue(lock.held)
        self.persistence.assert_global_lock(lock)
        opened_file.write_all(b"owner-still-live")
        opened_file.fsync()
        lock.release()
        with self.assertRaises(UnsafeLocalPath):
            opened_file.write_all(b"after-owner-release")

    def test_dependent_close_failure_keeps_kernel_lock_until_retry(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-close-failure", "nonce-close-failure"
        )
        workspace.create_exact_directory("state")
        opened_file = workspace.open_new_file("state/proof.bin")
        opened_file.write_all(b"before-failure")
        real_close = LockedNewFile._close_from_workspace  # noqa: SLF001
        failed_once = False

        def injected_failure(
            target: LockedNewFile,
            *,
            _close_token: object,
        ) -> None:
            nonlocal failed_once
            if not failed_once:
                failed_once = True
                raise OSError("injected dependent close failure")
            real_close(target, _close_token=_close_token)

        with patch.object(
            LockedNewFile,
            "_close_from_workspace",
            new=injected_failure,
        ):
            with self.assertRaises(LocalDeploymentPersistenceError):
                lock.release()
        self.assertTrue(lock.held)
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.global_lock().acquire()
        with self.assertRaises(UnsafeLocalPath):
            opened_file.write_all(b"while-close-failed")

        lock.release()
        self.assertFalse(lock.held)
        with self.assertRaises(UnsafeLocalPath):
            opened_file.write_all(b"after-retry")

    def test_file_descriptor_close_failure_retains_exact_identity_until_retry(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-file-retry", "nonce-file-retry"
        )
        opened_file = workspace.open_new_file("pending.bin")
        opened_file.write_all(b"pending")
        descriptor = workspace._open_files[opened_file]  # noqa: SLF001 - invariant audit
        real_close = persistence_module.os.close
        failed_once = False

        def fail_before_close(target: int) -> None:
            nonlocal failed_once
            if target == descriptor and not failed_once:
                failed_once = True
                raise OSError("injected fd remains live")
            real_close(target)

        with patch.object(persistence_module.os, "close", new=fail_before_close):
            with self.assertRaises(UnsafeLocalPath):
                opened_file.close()
        self.assertTrue(lock.held)
        self.assertEqual("live", lock._release_phase)  # noqa: SLF001
        self.assertEqual("closing", workspace._state)  # noqa: SLF001
        self.assertEqual(workspace._open_files.get(opened_file), descriptor)  # noqa: SLF001
        self.assertFalse(opened_file._closed)  # noqa: SLF001
        self.assertEqual(
            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino),
            (opened_file._initial.st_dev, opened_file._initial.st_ino),  # noqa: SLF001
        )
        for action in (
            lambda: opened_file.write_all(b"forbidden"),
            opened_file.fsync,
            lambda: workspace.open_new_file("third.bin"),
        ):
            with self.assertRaises(UnsafeLocalPath):
                action()

        wrong_thread_errors: list[type[BaseException] | None] = []

        def wrong_thread_retry() -> None:
            try:
                lock.release()
            except BaseException as error:  # noqa: BLE001 - owner boundary audit
                wrong_thread_errors.append(type(error))
            else:
                wrong_thread_errors.append(None)

        thread = threading.Thread(target=wrong_thread_retry)
        thread.start()
        thread.join(timeout=10)
        self.assertEqual([DeploymentLockBusy], wrong_thread_errors)
        self.assertEqual(descriptor, workspace._open_files[opened_file])  # noqa: SLF001

        lock.release()
        self.assertFalse(lock.held)
        self.assertTrue(opened_file._closed)  # noqa: SLF001
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_file_close_error_after_actual_close_is_mechanically_proven(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-file-proof", "nonce-file-proof"
        )
        opened_file = workspace.open_new_file("proof.bin")
        descriptor = workspace._open_files[opened_file]  # noqa: SLF001
        real_close = persistence_module.os.close
        reported_once = False

        def close_then_report_error(target: int) -> None:
            nonlocal reported_once
            if target == descriptor and not reported_once:
                reported_once = True
                real_close(target)
                raise OSError("close succeeded but wrapper reported failure")
            real_close(target)

        with patch.object(
            persistence_module.os, "close", new=close_then_report_error
        ):
            lock.release()
        self.assertFalse(lock.held)
        self.assertTrue(opened_file._closed)  # noqa: SLF001
        self.assertNotIn(opened_file, workspace._open_files)  # noqa: SLF001
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_sqlite_pin_partial_close_retains_only_failed_member_for_retry(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-pin-retry", "nonce-pin-retry"
        )
        for name, raw in (
            ("comments.sqlite3", b"main"),
            ("comments.sqlite3-wal", b"wal"),
            ("comments.sqlite3-shm", b"shm"),
        ):
            with workspace.open_new_file(name) as opened_file:
                opened_file.write_all(raw)
                opened_file.fsync()
        pinned = workspace.pin_sqlite_set("comments.sqlite3")
        descriptors = {
            member.label: member.descriptor for member in pinned._members  # noqa: SLF001
        }
        failed_descriptor = descriptors["wal"]
        assert failed_descriptor is not None
        real_close = persistence_module.os.close
        failed_once = False

        def fail_wal_once(target: int) -> None:
            nonlocal failed_once
            if target == failed_descriptor and not failed_once:
                failed_once = True
                raise OSError("injected WAL close failure")
            real_close(target)

        with patch.object(persistence_module.os, "close", new=fail_wal_once):
            with self.assertRaises(UnsafeLocalPath):
                pinned.close()
        self.assertTrue(lock.held)
        self.assertEqual("live", lock._release_phase)  # noqa: SLF001
        self.assertEqual("closing", workspace._state)  # noqa: SLF001
        self.assertFalse(pinned._closed)  # noqa: SLF001
        self.assertIn(pinned, workspace._pins)  # noqa: SLF001
        self.assertEqual(("wal",), pinned.members)
        for member in pinned._members:  # noqa: SLF001
            if member.label == "wal":
                self.assertEqual(failed_descriptor, member.descriptor)
            else:
                self.assertIsNone(member.descriptor)
        self.assertIsNotNone(os.fstat(failed_descriptor))

        lock.release()
        self.assertFalse(lock.held)
        self.assertTrue(pinned._closed)  # noqa: SLF001
        self.assertNotIn(pinned, workspace._pins)  # noqa: SLF001
        for descriptor in descriptors.values():
            assert descriptor is not None
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_final_lock_descriptor_close_failure_is_retryable_without_double_unlock(self) -> None:
        lock = self.persistence.global_lock().acquire()
        descriptor = lock._descriptor  # noqa: SLF001 - release phase invariant audit
        assert descriptor is not None
        identity_before = os.fstat(descriptor)
        real_close = persistence_module.os.close
        failed_once = False

        def fail_lock_once(target: int) -> None:
            nonlocal failed_once
            if target == descriptor and not failed_once:
                failed_once = True
                raise OSError("injected lock descriptor close failure")
            real_close(target)

        with patch.object(persistence_module.os, "close", new=fail_lock_once):
            with self.assertRaises(LocalDeploymentPersistenceError):
                lock.release()
        self.assertTrue(lock.held)
        self.assertEqual("closing", lock._release_phase)  # noqa: SLF001
        self.assertEqual(
            (identity_before.st_dev, identity_before.st_ino),
            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino),
        )
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.assert_global_lock(lock)
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.global_lock().acquire()

        errors: list[type[BaseException] | None] = []

        def wrong_thread_retry() -> None:
            try:
                lock.release()
            except BaseException as error:  # noqa: BLE001
                errors.append(type(error))
            else:
                errors.append(None)

        thread = threading.Thread(target=wrong_thread_retry)
        thread.start()
        thread.join(timeout=10)
        self.assertEqual([DeploymentLockBusy], errors)
        self.assertEqual(descriptor, lock._descriptor)  # noqa: SLF001

        lock.release()
        self.assertFalse(lock.held)
        self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_lock_close_error_after_actual_close_finishes_release(self) -> None:
        lock = self.persistence.global_lock().acquire()
        descriptor = lock._descriptor  # noqa: SLF001
        assert descriptor is not None
        real_close = persistence_module.os.close
        reported_once = False

        def close_then_report_error(target: int) -> None:
            nonlocal reported_once
            if target == descriptor and not reported_once:
                reported_once = True
                real_close(target)
                raise OSError("lock fd was closed")
            real_close(target)

        with patch.object(
            persistence_module.os, "close", new=close_then_report_error
        ):
            lock.release()
        self.assertFalse(lock.held)
        self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    @unittest.skipUnless(os.name == "nt", "Windows acquire cleanup 只在真实 handle 语义执行")
    def test_windows_context_acquire_temp_guard_one_shot_close_returns_idle(self) -> None:
        lock = self.persistence.global_lock()
        bound_type = persistence_module._BoundDirectory
        real_open = bound_type._open_windows_directory
        real_close = bound_type._close_windows_handle
        temporary_exact_handles: list[int] = []
        failed_once = False

        def capture_open(path: Path, *, protect_rename: bool) -> int:
            handle = real_open(path, protect_rename=protect_rename)
            if path == self.persistence.layout.locks and not protect_rename:
                temporary_exact_handles.append(handle)
            return handle

        def fail_once(target: int) -> None:
            nonlocal failed_once
            if target in temporary_exact_handles and not failed_once:
                failed_once = True
                raise OSError("injected final temporary guard close failure")
            real_close(target)

        with patch.object(
            bound_type,
            "_open_windows_directory",
            side_effect=capture_open,
        ), patch.object(
            bound_type,
            "_close_windows_handle",
            side_effect=fail_once,
        ):
            with self.assertRaises(LocalDeploymentPersistenceError):
                with lock:
                    self.fail("failed acquire 不得进入 context body")

        self.assertTrue(failed_once)
        self.assertEqual(1, len(temporary_exact_handles))
        failed_handle = temporary_exact_handles[0]
        self.assertFalse(lock.held)
        self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
        self.assertIsNone(lock._descriptor)  # noqa: SLF001
        self.assertIsNone(lock._acquire_parent)  # noqa: SLF001
        self.assertIsNone(lock._bound_root)  # noqa: SLF001
        self.assertIsNone(lock._bound_parent)  # noqa: SLF001
        self.assertFalse(lock._process_reservation)  # noqa: SLF001
        with self.assertRaises(UnsafeLocalPath):
            bound_type._windows_final_path(failed_handle)
        with self.persistence.global_lock() as contender:
            self.assertTrue(contender.held)

    @unittest.skipUnless(os.name == "nt", "Windows acquire cleanup 只在真实 handle 语义执行")
    def test_windows_acquire_temp_guard_persistent_close_is_tracked_and_retryable(self) -> None:
        lock = self.persistence.global_lock()
        bound_type = persistence_module._BoundDirectory
        real_open = bound_type._open_windows_directory
        real_close = bound_type._close_windows_handle
        temporary_exact_handles: list[int] = []

        def capture_open(path: Path, *, protect_rename: bool) -> int:
            handle = real_open(path, protect_rename=protect_rename)
            if path == self.persistence.layout.locks and not protect_rename:
                temporary_exact_handles.append(handle)
            return handle

        def fail_persistently(target: int) -> None:
            if target in temporary_exact_handles:
                raise OSError("persistent final temporary guard close failure")
            real_close(target)

        with patch.object(
            bound_type,
            "_open_windows_directory",
            side_effect=capture_open,
        ), patch.object(
            bound_type,
            "_close_windows_handle",
            side_effect=fail_persistently,
        ):
            with self.assertRaises(LocalDeploymentPersistenceError):
                lock.acquire()

        self.assertEqual(1, len(temporary_exact_handles))
        failed_handle = temporary_exact_handles[0]
        descriptor = lock._descriptor  # noqa: SLF001
        assert descriptor is not None
        self.assertTrue(lock.held)
        self.assertEqual("acquire_failed", lock._release_phase)  # noqa: SLF001
        self.assertTrue(lock._kernel_lock_acquired)  # noqa: SLF001
        self.assertIsNone(lock._acquisition_epoch)  # noqa: SLF001
        self.assertTrue(lock._process_reservation)  # noqa: SLF001
        acquire_parent = lock._acquire_parent  # noqa: SLF001
        assert acquire_parent is not None
        self.assertEqual([failed_handle], acquire_parent._windows_handles)  # noqa: SLF001
        self.assertIsNotNone(os.fstat(descriptor))
        self.assertEqual(
            str(self.persistence.layout.locks),
            bound_type._windows_final_path(failed_handle),
        )
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.global_lock().acquire()

        wrong_thread_errors: list[type[BaseException] | None] = []

        def wrong_thread_retry() -> None:
            try:
                lock.release()
            except BaseException as error:  # noqa: BLE001 - pre-live owner audit
                wrong_thread_errors.append(type(error))
            else:
                wrong_thread_errors.append(None)

        thread = threading.Thread(target=wrong_thread_retry)
        thread.start()
        thread.join(timeout=10)
        self.assertEqual([DeploymentLockBusy], wrong_thread_errors)
        self.assertEqual(descriptor, lock._descriptor)  # noqa: SLF001
        self.assertIn(failed_handle, acquire_parent._windows_handles)  # noqa: SLF001

        lock.release()
        self.assertFalse(lock.held)
        self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.assertRaises(UnsafeLocalPath):
            bound_type._windows_final_path(failed_handle)
        with self.persistence.global_lock() as contender:
            self.assertTrue(contender.held)

    def test_pre_kernel_fstat_failure_and_unclosed_fd_remain_retryable(self) -> None:
        lock = self.persistence.global_lock()
        real_fstat = persistence_module.os.fstat
        real_close = persistence_module.os.close
        captured_descriptor: list[int] = []

        def fail_first_lock_identity(descriptor: int) -> os.stat_result:
            if (
                lock._descriptor == descriptor  # noqa: SLF001
                and not captured_descriptor
            ):
                captured_descriptor.append(descriptor)
                raise OSError("injected first lock descriptor identity failure")
            return real_fstat(descriptor)

        def retain_unknown_descriptor(descriptor: int) -> None:
            if captured_descriptor and descriptor == captured_descriptor[0]:
                raise OSError("persistent unknown-identity descriptor close failure")
            real_close(descriptor)

        with patch.object(
            persistence_module.os,
            "fstat",
            new=fail_first_lock_identity,
        ), patch.object(
            persistence_module.os,
            "close",
            new=retain_unknown_descriptor,
        ):
            with self.assertRaises(OSError):
                lock.acquire()

        self.assertEqual(1, len(captured_descriptor))
        descriptor = captured_descriptor[0]
        self.assertTrue(lock.held)
        self.assertEqual("acquire_failed", lock._release_phase)  # noqa: SLF001
        self.assertEqual(descriptor, lock._descriptor)  # noqa: SLF001
        provisional = lock._descriptor_identity  # noqa: SLF001
        assert provisional is not None
        expected = os.stat(self.persistence.layout.deployment_lock)
        self.assertEqual(
            (expected.st_dev, expected.st_ino),
            (provisional.st_dev, provisional.st_ino),
        )
        self.assertFalse(lock._kernel_lock_acquired)  # noqa: SLF001
        self.assertIsNone(lock._acquisition_epoch)  # noqa: SLF001
        self.assertIsNotNone(lock._descriptor_instance_guard)  # noqa: SLF001
        self.assertTrue(lock._descriptor_instance_guard_required)  # noqa: SLF001
        self.assertIsNotNone(real_fstat(descriptor))
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.global_lock().acquire()

        lock.release()
        self.assertFalse(lock.held)
        self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
        with self.assertRaises(OSError):
            real_fstat(descriptor)

    def test_pre_kernel_identity_acquisition_failure_never_calls_ambiguous_close(self) -> None:
        lock = self.persistence.global_lock()
        real_fstat = persistence_module.os.fstat
        real_close = persistence_module.os.close
        captured_descriptor: list[int] = []
        close_attempts: list[int] = []

        def persistently_fail_lock_identity(descriptor: int) -> os.stat_result:
            if lock._descriptor == descriptor:  # noqa: SLF001
                if not captured_descriptor:
                    captured_descriptor.append(descriptor)
                raise OSError("persistent opened-descriptor identity failure")
            return real_fstat(descriptor)

        def observe_close(descriptor: int) -> None:
            if captured_descriptor and descriptor == captured_descriptor[0]:
                close_attempts.append(descriptor)
            real_close(descriptor)

        with patch.object(
            persistence_module.os,
            "fstat",
            new=persistently_fail_lock_identity,
        ), patch.object(
            persistence_module.os,
            "close",
            new=observe_close,
        ):
            with self.assertRaises(OSError):
                lock.acquire()

        self.assertEqual(1, len(captured_descriptor))
        descriptor = captured_descriptor[0]
        self.assertEqual([], close_attempts)
        self.assertTrue(lock.held)
        self.assertEqual("acquire_failed", lock._release_phase)  # noqa: SLF001
        self.assertEqual(descriptor, lock._descriptor)  # noqa: SLF001
        self.assertIsNone(lock._descriptor_identity)  # noqa: SLF001
        self.assertIsNotNone(lock._descriptor_instance_guard)  # noqa: SLF001
        self.assertTrue(lock._descriptor_instance_guard_required)  # noqa: SLF001
        expected = lock._descriptor_expected_identity  # noqa: SLF001
        assert expected is not None
        path_identity = os.stat(self.persistence.layout.deployment_lock)
        self.assertEqual(
            (path_identity.st_dev, path_identity.st_ino),
            (expected.st_dev, expected.st_ino),
        )
        self.assertIsNotNone(real_fstat(descriptor))
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.global_lock().acquire()

        # 故障解除后 owner 先取得 actual identity，再且仅再关闭原 descriptor。
        lock.release()
        self.assertFalse(lock.held)
        self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
        with self.assertRaises(OSError):
            real_fstat(descriptor)

    def test_pre_kernel_fstat_failure_and_different_inode_fd_reuse_does_not_close_replacement(self) -> None:
        lock = self.persistence.global_lock()
        replacement_path = self.persistence.layout.locks / "replacement.bin"
        replacement_path.write_bytes(b"replacement-stays-open")
        expected = os.stat(self.persistence.layout.deployment_lock)
        replacement_identity = os.stat(replacement_path)
        self.assertNotEqual(
            (expected.st_dev, expected.st_ino),
            (replacement_identity.st_dev, replacement_identity.st_ino),
        )
        real_fstat = persistence_module.os.fstat
        real_close = persistence_module.os.close
        captured_descriptor: list[int] = []
        replacement_descriptors: list[int] = []

        def fail_first_lock_identity(descriptor: int) -> os.stat_result:
            if lock._descriptor == descriptor and not captured_descriptor:  # noqa: SLF001
                captured_descriptor.append(descriptor)
                raise OSError("injected lock fstat failure before exact verification")
            return real_fstat(descriptor)

        def close_reuse_different_inode_then_raise(descriptor: int) -> None:
            if (
                captured_descriptor
                and descriptor == captured_descriptor[0]
                and not replacement_descriptors
            ):
                real_close(descriptor)
                replacement_descriptor = os.open(replacement_path, os.O_RDWR)
                if replacement_descriptor != descriptor:
                    real_close(replacement_descriptor)
                    raise AssertionError("fixture 未取得同号 replacement fd")
                replacement_descriptors.append(replacement_descriptor)
                raise OSError("old fd closed and number reused by different inode")
            real_close(descriptor)

        with patch.object(
            persistence_module.os,
            "fstat",
            new=fail_first_lock_identity,
        ), patch.object(
            persistence_module.os,
            "close",
            new=close_reuse_different_inode_then_raise,
        ):
            with self.assertRaises(OSError):
                lock.acquire()

        self.assertEqual(1, len(replacement_descriptors))
        descriptor = replacement_descriptors[0]
        try:
            self.assertFalse(lock.held)
            self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
            self.assertIsNone(lock._descriptor)  # noqa: SLF001
            self.assertIsNone(lock._descriptor_instance_guard)  # noqa: SLF001
            self.assertFalse(lock._descriptor_instance_guard_required)  # noqa: SLF001
            observed = real_fstat(descriptor)
            self.assertEqual(
                (replacement_identity.st_dev, replacement_identity.st_ino),
                (observed.st_dev, observed.st_ino),
            )
            os.lseek(descriptor, 0, os.SEEK_END)
            self.assertEqual(1, os.write(descriptor, b"!"))
            lock.release()
            self.assertIsNotNone(real_fstat(descriptor))
            with self.persistence.global_lock() as contender:
                self.assertTrue(contender.held)
            self.assertIsNotNone(real_fstat(descriptor))
        finally:
            real_close(descriptor)

    @unittest.skipUnless(os.name == "nt", "same-file open-instance oracle 只在 Windows 产品 API 执行")
    def test_pre_kernel_same_path_same_inode_reopen_never_closes_replacement(self) -> None:
        lock = self.persistence.global_lock()
        real_fstat = persistence_module.os.fstat
        real_close = persistence_module.os.close
        captured_descriptor: list[int] = []
        reopened_descriptors: list[int] = []
        instance_relations: list[str] = []

        def fail_first_lock_identity(descriptor: int) -> os.stat_result:
            if lock._descriptor == descriptor and not captured_descriptor:  # noqa: SLF001
                captured_descriptor.append(descriptor)
                raise OSError("injected lock fstat failure")
            return real_fstat(descriptor)

        def close_reopen_same_inode_then_raise(descriptor: int) -> None:
            if (
                captured_descriptor
                and descriptor == captured_descriptor[0]
                and not reopened_descriptors
            ):
                guard = lock._descriptor_instance_guard  # noqa: SLF001
                assert guard is not None
                instance_relations.append(
                    lock._windows_descriptor_instance_relation(  # noqa: SLF001
                        descriptor, guard
                    )
                )
                real_close(descriptor)
                reopened = os.open(
                    self.persistence.layout.deployment_lock,
                    os.O_RDWR | getattr(os, "O_CLOEXEC", 0),
                )
                if reopened != descriptor:
                    real_close(reopened)
                    raise AssertionError("fixture 未取得同号 same-inode fd")
                reopened_descriptors.append(reopened)
                instance_relations.append(
                    lock._windows_descriptor_instance_relation(  # noqa: SLF001
                        reopened, guard
                    )
                )
                raise OSError("old fd closed and same inode reopened")
            real_close(descriptor)

        with patch.object(
            persistence_module.os,
            "fstat",
            new=fail_first_lock_identity,
        ), patch.object(
            persistence_module.os,
            "close",
            new=close_reopen_same_inode_then_raise,
        ):
            with self.assertRaises(OSError):
                lock.acquire()

        self.assertEqual(1, len(reopened_descriptors))
        descriptor = reopened_descriptors[0]
        try:
            self.assertEqual(["same", "different"], instance_relations)
            self.assertFalse(lock.held)
            self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
            self.assertIsNone(lock._descriptor)  # noqa: SLF001
            self.assertIsNone(lock._descriptor_instance_guard)  # noqa: SLF001
            self.assertFalse(lock._descriptor_instance_guard_required)  # noqa: SLF001
            expected = os.stat(self.persistence.layout.deployment_lock)
            observed = real_fstat(descriptor)
            self.assertEqual(
                (expected.st_dev, expected.st_ino),
                (observed.st_dev, observed.st_ino),
            )
            os.lseek(descriptor, 0, os.SEEK_END)
            self.assertEqual(1, os.write(descriptor, b"!"))
            lock.release()
            self.assertIsNotNone(real_fstat(descriptor))
            with self.persistence.global_lock() as contender:
                self.assertTrue(contender.held)
            self.assertIsNotNone(real_fstat(descriptor))
        finally:
            real_close(descriptor)

    @unittest.skipUnless(os.name == "nt", "Windows open-instance guard 使用真实 kernel API")
    def test_windows_compare_object_handles_distinguishes_reopen_and_guard_close_source(self) -> None:
        hardlink_path = self.persistence.layout.locks / "deployment-lock-hardlink"
        try:
            os.link(self.persistence.layout.deployment_lock, hardlink_path)
        except OSError as error:
            self.skipTest(f"当前 Windows volume 不支持 hardlink fixture: {error}")
        # lock 文件有 hardlink 时产品 acquire 会按合同拒绝；先移除，live 后再建立。
        hardlink_path.unlink()
        captured_guard: int | None = None
        with self.persistence.global_lock() as lock:
            descriptor = lock._descriptor  # noqa: SLF001
            captured_guard = lock._descriptor_instance_guard  # noqa: SLF001
            assert descriptor is not None and captured_guard is not None
            self.assertEqual(
                "same",
                lock._windows_descriptor_instance_relation(  # noqa: SLF001
                    descriptor, captured_guard
                ),
            )
            reopened = os.open(lock.path, os.O_RDWR)
            try:
                self.assertEqual(
                    "different",
                    lock._windows_descriptor_instance_relation(  # noqa: SLF001
                        reopened, captured_guard
                    ),
                )
            finally:
                os.close(reopened)
            os.link(lock.path, hardlink_path)
            hardlink_descriptor = os.open(hardlink_path, os.O_RDWR)
            try:
                self.assertEqual(
                    "different",
                    lock._windows_descriptor_instance_relation(  # noqa: SLF001
                        hardlink_descriptor, captured_guard
                    ),
                )
            finally:
                os.close(hardlink_descriptor)
                hardlink_path.unlink()
        assert captured_guard is not None
        with self.assertRaises(OSError):
            persistence_module._BoundDirectory._windows_kernel_identity(  # noqa: SLF001
                captured_guard
            )

    @unittest.skipUnless(os.name == "nt", "hardlink open-instance oracle 只在 Windows 产品 API 执行")
    def test_pre_kernel_hardlink_same_inode_reopen_never_closes_replacement(self) -> None:
        lock = self.persistence.global_lock()
        hardlink_path = self.persistence.layout.locks / "deployment-lock-alias"
        try:
            os.link(lock.path, hardlink_path)
        except OSError as error:
            self.skipTest(f"当前 Windows volume 不支持 hardlink fixture: {error}")
        real_close = persistence_module.os.close
        replacement_descriptors: list[int] = []
        instance_relations: list[str] = []

        def close_reopen_hardlink_then_raise(descriptor: int) -> None:
            if lock._descriptor == descriptor and not replacement_descriptors:  # noqa: SLF001
                guard = lock._descriptor_instance_guard  # noqa: SLF001
                assert guard is not None
                instance_relations.append(
                    lock._windows_descriptor_instance_relation(  # noqa: SLF001
                        descriptor, guard
                    )
                )
                real_close(descriptor)
                reopened = os.open(hardlink_path, os.O_RDWR)
                if reopened != descriptor:
                    real_close(reopened)
                    raise AssertionError("fixture 未取得同号 hardlink fd")
                replacement_descriptors.append(reopened)
                instance_relations.append(
                    lock._windows_descriptor_instance_relation(  # noqa: SLF001
                        reopened, guard
                    )
                )
                raise OSError("old fd closed and hardlink reopened")
            real_close(descriptor)

        try:
            with patch.object(
                persistence_module.os,
                "close",
                new=close_reopen_hardlink_then_raise,
            ):
                with self.assertRaises(UnsafeLocalPath):
                    lock.acquire()
            self.assertEqual(["same", "different"], instance_relations)
            self.assertEqual(1, len(replacement_descriptors))
            replacement = replacement_descriptors[0]
            self.assertFalse(lock.held)
            self.assertIsNone(lock._descriptor_instance_guard)  # noqa: SLF001
            self.assertFalse(lock._descriptor_instance_guard_required)  # noqa: SLF001
            self.assertIsNotNone(os.fstat(replacement))
            os.lseek(replacement, 0, os.SEEK_END)
            self.assertEqual(1, os.write(replacement, b"!"))
            lock.release()
            self.assertIsNotNone(os.fstat(replacement))
        finally:
            for replacement in replacement_descriptors:
                real_close(replacement)
            hardlink_path.unlink(missing_ok=True)
        with self.persistence.global_lock() as contender:
            self.assertTrue(contender.held)

    @unittest.skipUnless(os.name == "nt", "Windows guard acquisition fault 只在产品 API 执行")
    def test_windows_guard_acquisition_failure_never_closes_unguarded_descriptor(self) -> None:
        lock = self.persistence.global_lock()
        lock_type = persistence_module.CrashReleasedFileLock
        real_close = persistence_module.os.close
        descriptor_close_attempts: list[int] = []
        duplicate_calls = 0

        def fail_persistently(descriptor: int) -> int:
            nonlocal duplicate_calls
            duplicate_calls += 1
            raise OSError("injected DuplicateHandle acquisition failure")

        def observe_close(descriptor: int) -> None:
            if lock._descriptor == descriptor:  # noqa: SLF001
                descriptor_close_attempts.append(descriptor)
            real_close(descriptor)

        with patch.object(
            lock_type,
            "_duplicate_windows_descriptor_instance",
            side_effect=fail_persistently,
        ), patch.object(persistence_module.os, "close", new=observe_close):
            with self.assertRaises(OSError):
                lock.acquire()

        self.assertGreaterEqual(duplicate_calls, 2)
        descriptor = lock._descriptor  # noqa: SLF001
        assert descriptor is not None
        self.assertEqual([], descriptor_close_attempts)
        self.assertTrue(lock._descriptor_instance_guard_required)  # noqa: SLF001
        self.assertIsNone(lock._descriptor_instance_guard)  # noqa: SLF001
        self.assertEqual("acquire_failed", lock._release_phase)  # noqa: SLF001
        self.assertIsNotNone(os.fstat(descriptor))
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.global_lock().acquire()

        wrong_thread: list[type[BaseException] | None] = []

        def wrong_owner_retry() -> None:
            try:
                lock.release()
            except BaseException as error:  # noqa: BLE001 - owner invariant
                wrong_thread.append(type(error))
            else:
                wrong_thread.append(None)

        thread = threading.Thread(target=wrong_owner_retry)
        thread.start()
        thread.join(timeout=10)
        self.assertEqual([DeploymentLockBusy], wrong_thread)

        lock.release()
        self.assertFalse(lock.held)
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.persistence.global_lock() as contender:
            self.assertTrue(contender.held)

    @unittest.skipUnless(os.name == "nt", "Windows guard acquisition fault 只在产品 API 执行")
    def test_windows_one_shot_guard_acquisition_failure_cleans_to_idle(self) -> None:
        lock = self.persistence.global_lock()
        lock_type = persistence_module.CrashReleasedFileLock
        real_duplicate = lock_type._duplicate_windows_descriptor_instance
        captured_descriptors: list[int] = []

        def fail_once_then_duplicate(descriptor: int) -> None:
            captured_descriptors.append(descriptor)
            if len(captured_descriptors) == 1:
                raise OSError("one-shot DuplicateHandle failure")
            real_duplicate(lock, descriptor)

        with patch.object(
            lock_type,
            "_duplicate_windows_descriptor_instance",
            side_effect=fail_once_then_duplicate,
        ):
            with self.assertRaises(OSError):
                lock.acquire()
        self.assertGreaterEqual(len(captured_descriptors), 2)
        descriptor = captured_descriptors[0]
        self.assertFalse(lock.held)
        self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
        self.assertIsNone(lock._descriptor_instance_guard)  # noqa: SLF001
        self.assertFalse(lock._descriptor_instance_guard_required)  # noqa: SLF001
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        with self.persistence.global_lock() as contender:
            self.assertTrue(contender.held)

    @unittest.skipUnless(os.name == "nt", "Windows syscall output commit 只在产品 API 执行")
    def test_windows_duplicate_output_is_registered_before_all_wrapper_errors(self) -> None:
        lock_type = persistence_module.CrashReleasedFileLock
        real_raw = lock_type._windows_duplicate_handle_call
        real_state_owner = lock_type._duplicate_windows_descriptor_instance
        for cut in ("raw_raise_after_output", "false_with_output", "outer_raise_after_commit"):
            with self.subTest(cut=cut):
                lock = self.persistence.global_lock()
                output_handles: list[int] = []

                def raw_raise_after_output(
                    raw_handle: int,
                    output_handle: object,
                ) -> bool:
                    status = real_raw(raw_handle, output_handle)
                    output = getattr(output_handle, "value")
                    assert output is not None
                    output_handles.append(int(output))
                    raise OSError("raw wrapper raised after DuplicateHandle output")

                def false_with_output(
                    raw_handle: int,
                    output_handle: object,
                ) -> bool:
                    self.assertTrue(real_raw(raw_handle, output_handle))
                    output = getattr(output_handle, "value")
                    assert output is not None
                    output_handles.append(int(output))
                    return False

                def outer_raise_after_commit(descriptor: int) -> None:
                    real_state_owner(lock, descriptor)
                    output = lock._descriptor_instance_guard  # noqa: SLF001
                    assert output is not None
                    output_handles.append(output)
                    raise OSError("outer wrapper raised after tracking commit")

                if cut == "outer_raise_after_commit":
                    patcher = patch.object(
                        lock_type,
                        "_duplicate_windows_descriptor_instance",
                        side_effect=outer_raise_after_commit,
                    )
                else:
                    patcher = patch.object(
                        lock_type,
                        "_windows_duplicate_handle_call",
                        side_effect=(
                            raw_raise_after_output
                            if cut == "raw_raise_after_output"
                            else false_with_output
                        ),
                    )
                with patcher:
                    with self.assertRaises(OSError):
                        lock.acquire()
                self.assertEqual(1, len(output_handles))
                self.assertFalse(lock.held)
                self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
                self.assertIsNone(lock._descriptor_instance_guard)  # noqa: SLF001
                self.assertFalse(lock._descriptor_instance_guard_required)  # noqa: SLF001
                self.assertIsNone(lock._retired_guard_close_audit_sha256)  # noqa: SLF001
                for output in output_handles:
                    with self.assertRaises(OSError):
                        persistence_module._BoundDirectory._windows_kernel_identity(  # noqa: SLF001
                            output
                        )
                with self.persistence.global_lock() as contender:
                    self.assertTrue(contender.held)

    @unittest.skipUnless(os.name == "nt", "Windows tracking monotonic commit 只在产品 API 执行")
    def test_windows_outer_close_wrapper_cannot_reverse_committed_guard_close(self) -> None:
        lock = self.persistence.global_lock().acquire()
        lock_type = persistence_module.CrashReleasedFileLock
        bound_type = persistence_module._BoundDirectory
        real_state_owner = lock_type._close_windows_descriptor_instance_guard
        original_guard = lock._descriptor_instance_guard  # noqa: SLF001
        assert original_guard is not None
        replacement_handles: list[int] = []

        def outer_raise_after_commit() -> None:
            real_state_owner(lock)
            opened: list[int] = []
            replacement: int | None = None
            for _ in range(2048):
                handle = bound_type._open_windows_directory(  # noqa: SLF001
                    self.persistence.layout.incoming,
                    protect_rename=False,
                )
                opened.append(handle)
                if handle == original_guard:
                    replacement = handle
                    break
            for handle in opened:
                if handle != replacement:
                    bound_type._close_windows_handle(handle)  # noqa: SLF001
            if replacement is None:
                raise AssertionError("fixture 未取得同号 outer-wrapper replacement handle")
            replacement_handles.append(replacement)
            raise OSError("outer wrapper raised after state owner committed close")

        try:
            with patch.object(
                lock_type,
                "_close_windows_descriptor_instance_guard",
                side_effect=outer_raise_after_commit,
            ):
                lock.release()
            self.assertFalse(lock.held)
            self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
            self.assertIsNone(lock._descriptor_instance_guard)  # noqa: SLF001
            self.assertFalse(lock._descriptor_instance_guard_required)  # noqa: SLF001
            self.assertFalse(lock._kernel_lock_acquired)  # noqa: SLF001
            self.assertEqual("ACQUIRED", self.cross_process_lock_probe())
            self.assertEqual(1, len(replacement_handles))
            replacement = replacement_handles[0]
            self.assertEqual(
                str(self.persistence.layout.incoming),
                bound_type._windows_final_path(replacement),  # noqa: SLF001
            )
            lock.release()
            self.assertEqual(
                str(self.persistence.layout.incoming),
                bound_type._windows_final_path(replacement),  # noqa: SLF001
            )
        finally:
            for replacement in replacement_handles:
                bound_type._close_windows_handle(replacement)  # noqa: SLF001

    @unittest.skipUnless(os.name == "nt", "Windows owner-crash-only 只在产品 API 执行")
    def test_windows_raw_close_unknown_is_owner_crash_only_until_process_exit(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src"
        helper = (
            "import json,sys,threading,time\n"
            "from pathlib import Path\n"
            "from quant_hub.ops import local_deployment_persistence as m\n"
            "p=m.LocalDeploymentPersistence.for_test_only(Path(sys.argv[1]).resolve(),allow_posix_test_only=True)\n"
            "mode=sys.argv[2]\n"
            "lock=p.global_lock().acquire()\n"
            "real=m.CrashReleasedFileLock._windows_duplicate_close_source_call\n"
            "replacement=[]\n"
            "def injected(handle):\n"
            " if mode == 'post':\n"
            "  real(handle)\n"
            "  opened=[]\n"
            "  for _ in range(2048):\n"
            "   h=m._BoundDirectory._open_windows_directory(p.layout.incoming,protect_rename=False); opened.append(h)\n"
            "   if h == handle: replacement.append(h); break\n"
            "  for h in opened:\n"
            "   if not replacement or h != replacement[0]: m._BoundDirectory._close_windows_handle(h)\n"
            "  if not replacement: raise AssertionError('same-number replacement unavailable')\n"
            " raise OSError('raw close-source outcome unknown')\n"
            "m.CrashReleasedFileLock._windows_duplicate_close_source_call=staticmethod(injected)\n"
            "try: lock.release()\n"
            "except BaseException as e: release_error=type(e).__name__\n"
            "else: release_error='NONE'\n"
            "wrong=[]\n"
            "def wrong_owner():\n"
            " try: lock.release()\n"
            " except BaseException as e: wrong.append(type(e).__name__)\n"
            " else: wrong.append('NONE')\n"
            "t=threading.Thread(target=wrong_owner); t.start(); t.join()\n"
            "try: lock.release()\n"
            "except BaseException as e: owner_retry=type(e).__name__\n"
            "else: owner_retry='NONE'\n"
            "replacement_live=(not replacement) or (m._BoundDirectory._windows_final_path(replacement[0])==str(p.layout.incoming))\n"
            "print(json.dumps({'phase':lock._release_phase,'held':lock.held,'kernel':lock._kernel_lock_acquired,'guard':lock._descriptor_instance_guard,'retired_len':len(lock._retired_guard_close_audit_sha256 or ''),'release_error':release_error,'wrong':wrong,'owner_retry':owner_retry,'replacement_live':replacement_live}),flush=True)\n"
            "time.sleep(300)\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(source_root)
        for mode, expected_probe in (("pre", "BUSY"), ("post", "ACQUIRED")):
            with self.subTest(mode=mode):
                process = subprocess.Popen(
                    [sys.executable, "-c", helper, str(self.root), mode],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                )
                try:
                    assert process.stdout is not None
                    state = json.loads(process.stdout.readline())
                    self.assertEqual("owner_crash_only", state["phase"])
                    self.assertTrue(state["held"])
                    self.assertIsNone(state["kernel"])
                    self.assertIsNone(state["guard"])
                    self.assertEqual(64, state["retired_len"])
                    self.assertEqual("LocalDeploymentPersistenceError", state["release_error"])
                    self.assertEqual(["DeploymentLockBusy"], state["wrong"])
                    self.assertEqual("LocalDeploymentPersistenceError", state["owner_retry"])
                    self.assertTrue(state["replacement_live"])
                    self.assertEqual(expected_probe, self.cross_process_lock_probe())
                    process.kill()
                    process.wait(timeout=15)
                    self.assertEqual("ACQUIRED", self.cross_process_lock_probe())
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=15)
                    process.communicate(timeout=5)

    @unittest.skipUnless(os.name == "nt", "Windows CompareObjectHandles fail-closed 只在产品 API 执行")
    def test_windows_compare_api_error_is_not_treated_as_replacement_proof(self) -> None:
        lock = self.persistence.global_lock().acquire()
        lock_type = persistence_module.CrashReleasedFileLock
        descriptor = lock._descriptor  # noqa: SLF001
        guard = lock._descriptor_instance_guard  # noqa: SLF001
        assert descriptor is not None and guard is not None

        def reject_non_not_same_error(
            current_descriptor: int,
            instance_guard: int,
        ) -> str:
            self.assertEqual(descriptor, current_descriptor)
            self.assertEqual(guard, instance_guard)
            raise LocalDeploymentPersistenceError(
                "CompareObjectHandles 无法证明 descriptor open instance: 87"
            )

        with patch.object(
            lock_type,
            "_windows_descriptor_instance_relation",
            side_effect=reject_non_not_same_error,
        ):
            with self.assertRaisesRegex(
                LocalDeploymentPersistenceError,
                "无法证明",
            ):
                lock.release()
        self.assertTrue(lock.held)
        self.assertEqual("closing", lock._release_phase)  # noqa: SLF001
        self.assertEqual(descriptor, lock._descriptor)  # noqa: SLF001
        self.assertEqual(guard, lock._descriptor_instance_guard)  # noqa: SLF001
        self.assertTrue(lock._kernel_lock_acquired)  # noqa: SLF001
        self.assertEqual("BUSY", self.cross_process_lock_probe())
        lock.release()
        self.assertFalse(lock.held)
        self.assertEqual("ACQUIRED", self.cross_process_lock_probe())

    @unittest.skipUnless(os.name == "nt", "Windows guard/byte-lock 生命周期只在产品 API 执行")
    def test_windows_duplicate_guard_keeps_kernel_lock_until_close_source(self) -> None:
        lock = self.persistence.global_lock().acquire()
        lock_type = persistence_module.CrashReleasedFileLock
        real_close = persistence_module.os.close
        original_descriptor = lock._descriptor  # noqa: SLF001
        assert original_descriptor is not None
        replacement_descriptors: list[int] = []

        def close_reopen_then_raise(descriptor: int) -> None:
            if descriptor == original_descriptor and not replacement_descriptors:
                real_close(descriptor)
                reopened = os.open(lock.path, os.O_RDWR)
                if reopened != descriptor:
                    real_close(reopened)
                    raise AssertionError("fixture 未取得同号 live replacement fd")
                replacement_descriptors.append(reopened)
                raise OSError("old live fd closed and same path reopened")
            real_close(descriptor)

        def fail_before_close_source() -> None:
            raise OSError("injected failure before DUPLICATE_CLOSE_SOURCE syscall")

        try:
            with patch.object(
                persistence_module.os,
                "close",
                new=close_reopen_then_raise,
            ), patch.object(
                lock_type,
                "_close_windows_descriptor_instance_guard",
                side_effect=fail_before_close_source,
            ):
                with self.assertRaises(OSError):
                    lock.release()
            replacement = replacement_descriptors[0]
            self.assertEqual("closing", lock._release_phase)  # noqa: SLF001
            self.assertIsNone(lock._descriptor)  # noqa: SLF001
            self.assertIsNotNone(lock._descriptor_instance_guard)  # noqa: SLF001
            self.assertTrue(lock._kernel_lock_acquired)  # noqa: SLF001
            self.assertEqual("BUSY", self.cross_process_lock_probe())
            self.assertIsNotNone(os.fstat(replacement))

            lock.release()
            self.assertFalse(lock.held)
            self.assertEqual("ACQUIRED", self.cross_process_lock_probe())
            self.assertIsNotNone(os.fstat(replacement))
            os.lseek(replacement, 0, os.SEEK_END)
            self.assertEqual(1, os.write(replacement, b"!"))
        finally:
            for replacement in replacement_descriptors:
                real_close(replacement)
            if lock.held:
                lock.release()

    @unittest.skipIf(os.name == "nt", "POSIX test-only fail-closed 分支")
    def test_posix_same_file_ambiguous_close_never_retries_replacement_number(self) -> None:
        lock = self.persistence.global_lock()
        real_fstat = persistence_module.os.fstat
        real_close = persistence_module.os.close
        captured: list[int] = []
        replacement_descriptors: list[int] = []

        def fail_first_identity(descriptor: int) -> os.stat_result:
            if lock._descriptor == descriptor and not captured:  # noqa: SLF001
                captured.append(descriptor)
                raise OSError("injected identity failure")
            return real_fstat(descriptor)

        def close_reopen_then_raise(descriptor: int) -> None:
            if captured and descriptor == captured[0] and not replacement_descriptors:
                real_close(descriptor)
                reopened = os.open(lock.path, os.O_RDWR)
                if reopened != descriptor:
                    real_close(reopened)
                    raise AssertionError("fixture 未取得同号 POSIX replacement fd")
                replacement_descriptors.append(reopened)
                raise OSError("same-file reopen is ambiguous on POSIX")
            real_close(descriptor)

        with patch.object(
            persistence_module.os, "fstat", new=fail_first_identity
        ), patch.object(
            persistence_module.os, "close", new=close_reopen_then_raise
        ):
            with self.assertRaises(OSError):
                lock.acquire()
        replacement = replacement_descriptors[0]
        self.assertTrue(lock.held)
        self.assertTrue(lock._descriptor_close_ambiguous)  # noqa: SLF001
        with self.assertRaisesRegex(LocalDeploymentPersistenceError, "fail-closed"):
            lock.release()
        self.assertIsNotNone(real_fstat(replacement))
        real_close(replacement)
        lock.release()
        self.assertFalse(lock.held)

    def test_acquire_rejects_opened_descriptor_identity_drift(self) -> None:
        lock = self.persistence.global_lock()
        alternate_path = self.persistence.layout.locks / "alternate.lock"
        alternate_path.write_bytes(b"not-the-deployment-lock")
        expected = os.stat(self.persistence.layout.deployment_lock)
        alternate = os.stat(alternate_path)
        self.assertNotEqual(
            (expected.st_dev, expected.st_ino),
            (alternate.st_dev, alternate.st_ino),
        )
        bound_type = persistence_module._BoundDirectory
        real_open = bound_type.open_file

        def redirect_lock_open(
            bound: object,
            name: str,
            flags: int,
            mode: int = 0o600,
        ) -> int:
            if bound is lock._acquire_parent and name == lock.path.name:  # noqa: SLF001
                return real_open(bound, alternate_path.name, flags, mode)
            return real_open(bound, name, flags, mode)

        with patch.object(bound_type, "open_file", new=redirect_lock_open):
            with self.assertRaises(UnsafeLocalPath):
                lock.acquire()
        self.assertFalse(lock.held)
        self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
        self.assertIsNone(lock._descriptor)  # noqa: SLF001
        with self.persistence.global_lock() as contender:
            self.assertTrue(contender.held)

    @unittest.skipUnless(os.name == "nt", "Windows pre-kernel partial enter 只在真实 handle 语义执行")
    def test_windows_pre_kernel_partial_guard_failure_without_descriptor_retries(self) -> None:
        lock = self.persistence.global_lock()
        bound_type = persistence_module._BoundDirectory
        real_open = bound_type._open_windows_directory
        real_close = bound_type._close_windows_handle
        partial_handles: list[int] = []

        def fail_during_temp_enter(path: Path, *, protect_rename: bool) -> int:
            if path == self.root and not protect_rename:
                raise OSError("injected pre-kernel partial guard enter failure")
            handle = real_open(path, protect_rename=protect_rename)
            if not protect_rename:
                partial_handles.append(handle)
            return handle

        def retain_first_handle(target: int) -> None:
            if partial_handles and target == partial_handles[0]:
                raise OSError("persistent partial guard close failure")
            real_close(target)

        with patch.object(
            bound_type,
            "_open_windows_directory",
            side_effect=fail_during_temp_enter,
        ), patch.object(
            bound_type,
            "_close_windows_handle",
            side_effect=retain_first_handle,
        ):
            with self.assertRaises(LocalDeploymentPersistenceError):
                lock.acquire()

        self.assertTrue(partial_handles)
        retained_handle = partial_handles[0]
        self.assertTrue(lock.held)
        self.assertEqual("acquire_failed", lock._release_phase)  # noqa: SLF001
        self.assertIsNone(lock._descriptor)  # noqa: SLF001
        self.assertFalse(lock._kernel_lock_acquired)  # noqa: SLF001
        self.assertIsNone(lock._acquisition_epoch)  # noqa: SLF001
        self.assertTrue(lock._process_reservation)  # noqa: SLF001
        acquire_parent = lock._acquire_parent  # noqa: SLF001
        assert acquire_parent is not None
        self.assertEqual([retained_handle], acquire_parent._windows_handles)  # noqa: SLF001
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.global_lock().acquire()

        lock.release()
        self.assertFalse(lock.held)
        self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
        with self.assertRaises(UnsafeLocalPath):
            bound_type._windows_final_path(retained_handle)

    @unittest.skipUnless(os.name == "nt", "Windows post-kernel partial enter 只在真实 handle 语义执行")
    def test_windows_partial_root_and_locks_guard_enter_failures_cleanup_kernel_lock(self) -> None:
        bound_type = persistence_module._BoundDirectory
        real_open = bound_type._open_windows_directory
        for stage, failed_path in (
            ("root", self.root),
            ("locks", self.persistence.layout.locks),
        ):
            with self.subTest(stage=stage):
                lock = self.persistence.global_lock()

                def fail_exact_long_guard(
                    path: Path,
                    *,
                    protect_rename: bool,
                ) -> int:
                    if path == failed_path and protect_rename:
                        raise OSError(f"injected {stage} guard enter failure")
                    return real_open(path, protect_rename=protect_rename)

                with patch.object(
                    bound_type,
                    "_open_windows_directory",
                    side_effect=fail_exact_long_guard,
                ):
                    with self.assertRaises(OSError):
                        lock.acquire()
                self.assertFalse(lock.held)
                self.assertEqual("idle", lock._release_phase)  # noqa: SLF001
                self.assertIsNone(lock._descriptor)  # noqa: SLF001
                self.assertFalse(lock._kernel_lock_acquired)  # noqa: SLF001
                self.assertIsNone(lock._acquisition_epoch)  # noqa: SLF001
                with self.persistence.global_lock() as contender:
                    self.assertTrue(contender.held)

    @unittest.skipIf(os.name == "nt", "POSIX dir-fd 仅由 test-only adapter 覆盖")
    def test_posix_workspace_guard_close_failure_retains_dirfd_until_retry(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-posix-guard", "nonce-posix-guard"
        )
        guard = workspace._guards[-1]  # noqa: SLF001 - dir-fd invariant audit
        descriptor = guard._descriptor  # noqa: SLF001
        assert descriptor is not None
        identity_before = os.fstat(descriptor)
        real_close = persistence_module.os.close
        failed_once = False

        def fail_before_close(target: int) -> None:
            nonlocal failed_once
            if target == descriptor and not failed_once:
                failed_once = True
                raise OSError("injected POSIX directory fd close failure")
            real_close(target)

        with patch.object(persistence_module.os, "close", new=fail_before_close):
            with self.assertRaises(LocalDeploymentPersistenceError):
                lock.release()
        self.assertTrue(lock.held)
        self.assertEqual(descriptor, guard._descriptor)  # noqa: SLF001
        self.assertEqual(
            (identity_before.st_dev, identity_before.st_ino),
            (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino),
        )
        lock.release()
        self.assertFalse(lock.held)
        self.assertTrue(guard._fully_closed())  # noqa: SLF001

    @unittest.skipUnless(os.name == "nt", "Windows handle close-retry 只在真实产品语义执行")
    def test_windows_workspace_guard_close_failure_keeps_tracking_until_retry(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-win-guard", "nonce-win-guard"
        )
        workspace.create_exact_directory("state")
        guard = workspace._guards[-1]  # noqa: SLF001 - exact handle invariant audit
        handle = guard._windows_handles[-1]  # noqa: SLF001
        expected_path = guard._windows_handle_identities[handle]  # noqa: SLF001
        real_close = persistence_module._BoundDirectory._close_windows_handle
        failed_once = False

        def fail_before_close(target: int) -> None:
            nonlocal failed_once
            if target == handle and not failed_once:
                failed_once = True
                raise OSError("injected Windows directory handle close failure")
            real_close(target)

        with patch.object(
            persistence_module._BoundDirectory,
            "_close_windows_handle",
            side_effect=fail_before_close,
        ):
            with self.assertRaises(LocalDeploymentPersistenceError):
                lock.release()
        self.assertTrue(lock.held)
        self.assertEqual("closing", workspace._state)  # noqa: SLF001
        self.assertIn(workspace, lock._dependent_workspaces)  # noqa: SLF001
        self.assertIn(handle, guard._windows_handles)  # noqa: SLF001
        self.assertEqual(
            expected_path,
            guard._windows_handle_identities[handle],  # noqa: SLF001
        )
        self.assertEqual([handle], guard._windows_handles)  # noqa: SLF001

        lock.release()
        self.assertFalse(lock.held)
        self.assertTrue(guard._fully_closed())  # noqa: SLF001
        self.assertNotIn(workspace, lock._dependent_workspaces)  # noqa: SLF001
        with self.assertRaises(UnsafeLocalPath):
            persistence_module._BoundDirectory._windows_final_path(handle)

    @unittest.skipUnless(os.name == "nt", "Windows shared guard close-retry 只在真实产品语义执行")
    def test_windows_shared_guard_failure_and_actual_close_proof_are_distinct(self) -> None:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-shared-guard", "nonce-shared-guard"
        )
        workspace.close()
        shared_path, guard = next(
            iter(lock._shared_directory_guards.items())  # noqa: SLF001
        )
        handle = guard._windows_handles[-1]  # noqa: SLF001
        real_close = persistence_module._BoundDirectory._close_windows_handle
        failed_once = False

        def fail_before_close(target: int) -> None:
            nonlocal failed_once
            if target == handle and not failed_once:
                failed_once = True
                raise OSError("injected shared guard close failure")
            real_close(target)

        with patch.object(
            persistence_module._BoundDirectory,
            "_close_windows_handle",
            side_effect=fail_before_close,
        ):
            with self.assertRaises(LocalDeploymentPersistenceError):
                lock.release()
        self.assertTrue(lock.held)
        self.assertIs(guard, lock._shared_directory_guards[shared_path])  # noqa: SLF001
        self.assertIn(handle, guard._windows_handles)  # noqa: SLF001
        self.assertEqual([handle], guard._windows_handles)  # noqa: SLF001
        lock.release()
        self.assertFalse(lock.held)
        with self.assertRaises(UnsafeLocalPath):
            persistence_module._BoundDirectory._windows_final_path(handle)

        proof_lock = self.persistence.global_lock().acquire()
        proof_workspace = self.persistence.bind_attempt_workspace(
            proof_lock, "attempt-shared-proof", "nonce-shared-proof"
        )
        proof_workspace.close()
        _, proof_guard = next(
            iter(proof_lock._shared_directory_guards.items())  # noqa: SLF001
        )
        proof_handle = proof_guard._windows_handles[-1]  # noqa: SLF001
        reported_once = False

        def close_then_report_error(target: int) -> None:
            nonlocal reported_once
            if target == proof_handle and not reported_once:
                reported_once = True
                real_close(target)
                raise OSError("shared handle closed before reported error")
            real_close(target)

        with patch.object(
            persistence_module._BoundDirectory,
            "_close_windows_handle",
            side_effect=close_then_report_error,
        ):
            proof_lock.release()
        self.assertFalse(proof_lock.held)
        self.assertTrue(proof_guard._fully_closed())  # noqa: SLF001
        with self.assertRaises(UnsafeLocalPath):
            persistence_module._BoundDirectory._windows_final_path(proof_handle)

    @unittest.skipUnless(os.name == "nt", "Windows root/locks guard retry 只在真实产品语义执行")
    def test_windows_locks_guard_close_failure_precedes_kernel_unlock(self) -> None:
        lock = self.persistence.global_lock().acquire()
        guard = lock._bound_parent  # noqa: SLF001 - locks guard invariant audit
        assert guard is not None
        handle = guard._windows_handles[-1]  # noqa: SLF001
        descriptor = lock._descriptor  # noqa: SLF001
        assert descriptor is not None
        real_close = persistence_module._BoundDirectory._close_windows_handle
        failed_once = False

        def fail_before_close(target: int) -> None:
            nonlocal failed_once
            if target == handle and not failed_once:
                failed_once = True
                raise OSError("injected locks guard close failure")
            real_close(target)

        with patch.object(
            persistence_module._BoundDirectory,
            "_close_windows_handle",
            side_effect=fail_before_close,
        ):
            with self.assertRaises(LocalDeploymentPersistenceError):
                lock.release()
        self.assertTrue(lock.held)
        self.assertEqual(descriptor, lock._descriptor)  # noqa: SLF001
        self.assertIs(guard, lock._bound_parent)  # noqa: SLF001
        self.assertIn(handle, guard._windows_handles)  # noqa: SLF001
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.global_lock().acquire()

        lock.release()
        self.assertFalse(lock.held)
        self.assertTrue(guard._fully_closed())  # noqa: SLF001
        with self.assertRaises(UnsafeLocalPath):
            persistence_module._BoundDirectory._windows_final_path(handle)

    def test_closed_relative_workspace_operations_and_sqlite_pin(self) -> None:
        with self.persistence.global_lock() as lock:
            with self.persistence.bind_attempt_workspace(
                lock, "attempt-seam", "nonce-seam"
            ) as workspace:
                self.assertEqual("attempt-seam", workspace.attempt_id)
                self.assertEqual("nonce-seam", workspace.nonce)
                self.assertFalse(hasattr(workspace, "path"))
                self.assertFalse(hasattr(workspace, "authority_token"))
                workspace.create_exact_directory("state/candidate")
                self.assertIsNotNone(
                    workspace.preflight(
                        "state/candidate",
                        expected_kind="directory",
                        allow_absent=False,
                    )
                )
                opened_file = workspace.open_new_file(
                    "state/candidate/comments.sqlite3"
                )
                self.assertIsInstance(opened_file, LockedNewFile)
                self.assertEqual(
                    len(b"SQLite seam bytes"),
                    opened_file.write_all(b"SQLite seam bytes"),
                )
                opened_file.fsync()
                opened_file.close()
                with self.assertRaisesRegex(UnsafeLocalPath, "已存在"):
                    workspace.open_new_file("state/candidate/comments.sqlite3")
                self.assertEqual(
                    digest(b"replacement"),
                    workspace.atomic_replace(
                        "state/candidate/comments.sqlite3", b"replacement"
                    ),
                )
                with workspace.pin_sqlite_set(
                    "state/candidate/comments.sqlite3"
                ) as pinned:
                    self.assertEqual(("main",), pinned.members)
                    self.assertEqual(b"replacement", pinned.read_bytes("main"))
                    pinned.assert_unchanged()
                    with self.assertRaisesRegex(UnsafeLocalPath, "仍被 pin"):
                        workspace.remove_exact_transient(
                            "state/candidate/comments.sqlite3"
                        )
                self.assertTrue(
                    workspace.remove_exact_transient(
                        "state/candidate/comments.sqlite3"
                    )
                )
                self.assertFalse(
                    workspace.remove_exact_transient(
                        "state/candidate/comments.sqlite3"
                    )
                )
                self.assertTrue(
                    workspace.remove_exact_transient("state/candidate")
                )
                self.assertTrue(workspace.remove_exact_transient("state"))

    def test_relative_escape_case_collision_and_unsafe_ids_fail_closed(self) -> None:
        with self.persistence.global_lock() as lock:
            for attempt, nonce in (
                ("CON", "nonce"),
                ("attempt", "NUL"),
                ("attempt.", "nonce"),
                ("a" * 100, "b" * 100),
            ):
                with self.assertRaises(UnsafeLocalPath):
                    self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            with self.persistence.bind_attempt_workspace(
                lock, "attempt-path", "nonce-path"
            ) as workspace:
                for relative in (
                    "../outside",
                    "/absolute",
                    "state\\escape",
                    "state/../../outside",
                    "state/.",
                    "Ｃase",
                ):
                    with self.assertRaises(UnsafeLocalPath, msg=relative):
                        workspace.create_exact_directory(relative)
                workspace.create_exact_directory("state")
                with self.assertRaisesRegex(UnsafeLocalPath, "大小写"):
                    workspace.create_exact_directory("State")
                with self.assertRaisesRegex(UnsafeLocalPath, "保留"):
                    workspace.atomic_replace("workspace_binding.json", b"{}")

    def test_hardlink_reparse_and_new_sidecar_are_rejected(self) -> None:
        with self.persistence.global_lock() as lock:
            with self.persistence.bind_attempt_workspace(
                lock, "attempt-files", "nonce-files"
            ) as workspace:
                workspace.create_exact_directory("state")
                source = self.root / "hardlink-source.sqlite3"
                source.write_bytes(b"hardlink")
                hardlink = self.workspace_path("attempt-files", "nonce-files") / "state" / "comments.sqlite3"
                try:
                    os.link(source, hardlink)
                except OSError as error:
                    self.skipTest(f"当前主机不能创建 hardlink fixture: {error}")
                with self.assertRaisesRegex(UnsafeLocalPath, "hardlink"):
                    workspace.pin_sqlite_set("state/comments.sqlite3")
                hardlink.unlink()
                source.unlink()

                with workspace.open_new_file("state/comments.sqlite3") as opened_file:
                    opened_file.write_all(b"main")
                    opened_file.fsync()
                with workspace.pin_sqlite_set("state/comments.sqlite3") as pinned:
                    (self.workspace_path("attempt-files", "nonce-files") / "state" / "comments.sqlite3-wal").write_bytes(b"wal")
                    with self.assertRaisesRegex(UnsafeLocalPath, "absent sidecar"):
                        pinned.assert_unchanged()
                workspace.remove_exact_transient("state/comments.sqlite3-wal")

                external = self.root / "external.sqlite3"
                external.write_bytes(b"external")
                link = self.workspace_path("attempt-files", "nonce-files") / "state" / "linked.sqlite3"
                try:
                    link.symlink_to(external)
                except OSError:
                    pass
                else:
                    with self.assertRaisesRegex(UnsafeLocalPath, "symlink|reparse"):
                        workspace.preflight("state/linked.sqlite3")

    def test_owner_crash_releases_lock_and_exact_workspace_rebinds(self) -> None:
        source_root = Path(__file__).resolve().parents[1] / "src"
        helper = (
            "from pathlib import Path\nimport os,sys,time\n"
            "from quant_hub.ops.local_deployment_persistence import LocalDeploymentPersistence\n"
            "p=LocalDeploymentPersistence.for_test_only(Path(sys.argv[1]).resolve(),allow_posix_test_only=True)\n"
            "with p.global_lock() as lock:\n"
            " w=p.bind_attempt_workspace(lock,'attempt-crash','nonce-crash')\n"
            " w.create_exact_directory('state')\n"
            " with w.open_new_file('state/owner.bin') as d:\n"
            "  d.write_all(b'owner');d.fsync()\n"
            " print('BOUND',flush=True)\n time.sleep(300)\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(source_root)
        process = subprocess.Popen(
            [sys.executable, "-c", helper, str(self.root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        try:
            assert process.stdout is not None
            self.assertEqual("BOUND", process.stdout.readline().strip())
            with self.assertRaises(DeploymentLockBusy):
                self.persistence.global_lock().acquire()
            process.kill()
            process.wait(timeout=15)
            deadline = time.monotonic() + 10
            while True:
                try:
                    lock = self.persistence.global_lock().acquire()
                except DeploymentLockBusy:
                    if time.monotonic() >= deadline:
                        self.fail("workspace owner crash 后 global lock 未释放")
                    time.sleep(0.05)
                else:
                    break
            try:
                with self.persistence.bind_attempt_workspace(
                    lock, "attempt-crash", "nonce-crash"
                ) as workspace:
                    self.assertIsNotNone(
                        workspace.preflight(
                            "state/owner.bin",
                            expected_kind="file",
                            allow_absent=False,
                        )
                    )
                    workspace.atomic_replace("state/owner.bin", b"replayed")
            finally:
                lock.release()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=15)
            process.communicate(timeout=5)

    def test_canonical_evidence_is_exclusive_idempotent_and_third_value_safe(self) -> None:
        raw = identity.canonical_bytes(
            {
                "schema_version": "qrh-test-attempt-evidence/v1",
                "attempt_id": "attempt-evidence",
                "observation": "exact",
            }
        )
        with self.persistence.global_lock() as lock:
            first = self.persistence.commit_attempt_evidence(
                lock, "attempt-evidence", "root-preflight", raw
            )
            replay = self.persistence.commit_attempt_evidence(
                lock, "attempt-evidence", "root-preflight", raw
            )
            self.assertEqual(first, replay)
            self.assertEqual(digest(raw), first.sha256)
            with self.assertRaises(CompareAndSwapConflict):
                self.persistence.commit_attempt_evidence(
                    lock,
                    "attempt-evidence",
                    "root-preflight",
                    identity.canonical_bytes(
                        {"schema_version": "qrh-test-attempt-evidence/v1", "observation": "third"}
                    ),
                )
            with self.assertRaisesRegex(
                LocalDeploymentPersistenceError, "canonical"
            ):
                self.persistence.commit_attempt_evidence(
                    lock,
                    "attempt-evidence",
                    "noncanonical",
                    b'{"schema_version": "qrh-test/v1"}',
                )
        self.assertEqual({}, self.persistence.journals.histories())

    @unittest.skipUnless(os.name == "nt", "真实 no-share-delete 竞态只在 Windows 产品语义执行")
    def test_workspace_parent_chain_cannot_be_renamed_while_bound(self) -> None:
        moved = self.root / "attempt-parent-held"
        with self.persistence.global_lock() as lock:
            with self.persistence.bind_attempt_workspace(
                lock, "attempt-race", "nonce-race"
            ) as workspace:
                parent = self.persistence.layout.temporary / "deployment-attempts"
                with self.assertRaises(OSError):
                    parent.rename(moved)
                workspace.create_exact_directory("state")
                workspace.atomic_replace("state/proof.bin", b"inside")


class StateSqliteSourceSeamTests(PersistenceFixture):
    def database_path(self, database: str = "comments") -> Path:
        filename = (
            "comments.sqlite3"
            if database == "comments"
            else "research_workspace.sqlite3"
        )
        return self.persistence.layout.state / filename

    def create_main_database(self, database: str = "comments") -> Path:
        path = self.database_path(database)
        with closing(sqlite3.connect(path, isolation_level=None)) as connection:
            connection.execute(
                "CREATE TABLE source_probe(id INTEGER PRIMARY KEY,value TEXT NOT NULL) STRICT"
            )
            connection.execute("INSERT INTO source_probe VALUES(1,'stable')")
        return path

    def create_wal_triplet(self, database: str = "comments") -> Path:
        target = self.database_path(database)
        staging = self.persistence.layout.temporary / f"{database}-wal-source.sqlite3"
        with closing(sqlite3.connect(staging, isolation_level=None)) as writer:
            self.assertEqual(
                "wal",
                str(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0]).casefold(),
            )
            writer.execute("PRAGMA wal_autocheckpoint=0")
            writer.execute(
                "CREATE TABLE source_probe(id INTEGER PRIMARY KEY,value TEXT NOT NULL) STRICT"
            )
            writer.execute("INSERT INTO source_probe VALUES(1,'from-wal')")
            for suffix in ("", "-wal", "-shm"):
                shutil.copyfile(Path(str(staging) + suffix), Path(str(target) + suffix))
        # 只读打开一次，预建可复用 WAL read-mark；source pin 自身不得修改 SHM。
        uri = "file:" + str(target).replace("\\", "/") + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, isolation_level=None)) as reader:
            self.assertEqual("from-wal", reader.execute(
                "SELECT value FROM source_probe WHERE id=1"
            ).fetchone()[0])
        return target

    def bind_source(
        self,
        *,
        database: str = "comments",
        attempt: str = "attempt-source",
        nonce: str = "nonce-source",
    ) -> tuple[object, object, LockedStateSqliteSource]:
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, attempt, nonce
        )
        source = self.persistence.lock_state_sqlite_source(
            lock, workspace, database
        )
        return lock, workspace, source

    def cross_process_lock_probe(self) -> str:
        helper = (
            "import os,sys\n"
            "fd=os.open(sys.argv[1],os.O_RDWR)\n"
            "try:\n"
            " try:\n"
            "  if os.name=='nt':\n"
            "   import msvcrt; os.lseek(fd,0,0); msvcrt.locking(fd,msvcrt.LK_NBLCK,1)\n"
            "  else:\n"
            "   import fcntl; fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n"
            " except (OSError,BlockingIOError): print('BUSY')\n"
            " else: print('ACQUIRED')\n"
            "finally: os.close(fd)\n"
        )
        environment = dict(os.environ)
        return subprocess.check_output(
            [
                sys.executable,
                "-c",
                helper,
                str(self.persistence.layout.deployment_lock),
            ],
            text=True,
            env=environment,
            timeout=15,
        ).strip()

    def test_signature_database_enum_and_epoch_authority_have_no_injection_surface(self) -> None:
        parameters = inspect.signature(
            LocalDeploymentPersistence.lock_state_sqlite_source
        ).parameters
        self.assertEqual(["self", "lock", "workspace", "database"], list(parameters))
        self.create_main_database()
        lock = self.persistence.global_lock()
        with self.assertRaises(DeploymentLockBusy):
            self.persistence.lock_state_sqlite_source(lock, object(), "comments")  # type: ignore[arg-type]
        with lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "attempt-authority", "nonce-authority"
            )
            for invalid in ("workspace", "comments.sqlite3", "COMMENTS", None):
                with self.subTest(database=invalid), self.assertRaises(UnsafeLocalPath):
                    self.persistence.lock_state_sqlite_source(
                        lock, workspace, invalid  # type: ignore[arg-type]
                    )
            for keyword in ("root", "path", "uri", "environment", "hook", "runtime"):
                with self.subTest(keyword=keyword), self.assertRaises(TypeError):
                    self.persistence.lock_state_sqlite_source(
                        lock,
                        workspace,
                        "comments",
                        **{keyword: self.root},  # type: ignore[arg-type]
                    )
            source = self.persistence.lock_state_sqlite_source(
                lock, workspace, "comments"
            )
        self.assertEqual("closed", source._state)  # noqa: SLF001
        lock.acquire()
        try:
            with self.assertRaises(UnsafeLocalPath):
                source.backup_to_memory()
            with self.assertRaises(UnsafeLocalPath):
                self.persistence.lock_state_sqlite_source(
                    lock, workspace, "comments"
                )
        finally:
            lock.release()

        with tempfile.TemporaryDirectory() as other_text:
            other = LocalDeploymentPersistence.for_test_only(
                Path(other_text).resolve(), allow_posix_test_only=True
            )
            other_lock = other.global_lock().acquire()
            try:
                other_workspace = other.bind_attempt_workspace(
                    other_lock, "attempt-other", "nonce-other"
                )
                with self.assertRaises(DeploymentLockBusy):
                    self.persistence.lock_state_sqlite_source(
                        other_lock, other_workspace, "comments"
                    )
            finally:
                other_lock.release()

    def test_main_only_backup_returns_tracked_pathless_raw_memory_view(self) -> None:
        self.create_main_database()
        lock, workspace, source = self.bind_source()
        try:
            self.assertEqual("main_only_immutable", source.mode)
            self.assertEqual(("main",), source.members)
            self.assertEqual("diagnostic_source_pin_only", source.scope)
            public = {name for name in dir(source) if not name.startswith("_")}
            self.assertFalse(any(token in name.casefold() for name in public for token in (
                "path", "root", "uri", "fd", "handle", "qualified", "formal"
            )))
            with self.assertRaises(TypeError):
                pickle.dumps(source)
            view = source.backup_to_memory()
            self.assertIsInstance(view, LockedStateSqliteMemoryView)
            self.assertFalse(hasattr(view, "connection"))
            self.assertEqual(view.before, view.after)
            self.assertNotIn(str(self.root), repr(view.before))
            self.assertEqual(("main",), view.members)
            self.assertEqual("diagnostic_source_pin_only", view.scope)
            with self.assertRaises(TypeError):
                pickle.dumps(view)
            if os.name == "nt":
                with self.assertRaises(sqlite3.OperationalError):
                    with closing(sqlite3.connect(self.database_path())) as writer:
                        writer.execute(
                            "UPDATE source_probe SET value='drift' WHERE id=1"
                        )
                moved = self.persistence.layout.state / "comments-moved.sqlite3"
                with self.assertRaises(OSError):
                    self.database_path().rename(moved)
            self.assertEqual(
                [(0, "main", "")],
                list(view.query("PRAGMA database_list")),
            )
            self.assertTrue(view.query("PRAGMA table_info(source_probe)"))
            for mutating_or_open_pragma in (
                "PRAGMA foreign_keys(ON)",
                "PRAGMA user_version(123)",
                "PRAGMA schema_version(123)",
                "PRAGMA database_list(ignored)",
            ):
                with self.subTest(pragma=mutating_or_open_pragma), self.assertRaises(
                    UnsafeLocalPath
                ):
                    view.query(mutating_or_open_pragma)
            self.assertEqual(((0,),), view.query("PRAGMA foreign_keys"))
            self.assertEqual(((0,),), view.query("PRAGMA user_version"))
            before_rows = list(view.query(
                "SELECT id,value FROM source_probe ORDER BY id"
            ))
            with self.assertRaises(UnsafeLocalPath):
                view.query("ATTACH DATABASE 'C:/escape.sqlite3' AS escaped")
            view.vacuum()
            after_rows = list(view.query(
                "SELECT id,value FROM source_probe ORDER BY id"
            ))
            self.assertEqual(before_rows, after_rows)
            raw = view.serialize()
            with closing(sqlite3.connect(":memory:")) as verifier:
                verifier.deserialize(raw)
                self.assertEqual(before_rows, list(verifier.execute(
                    "SELECT id,value FROM source_probe ORDER BY id"
                )))
            view.close()
            source.close()
            workspace.close()
        finally:
            if lock.held:
                lock.release()

    @unittest.skipUnless(os.name == "nt", "WAL source guard 使用真实 Windows share mode")
    def test_wal_triplet_backup_is_exact_and_does_not_change_members(self) -> None:
        path = self.create_wal_triplet()
        members = [path, Path(str(path) + "-wal"), Path(str(path) + "-shm")]
        before = [(member.stat(), member.read_bytes()) for member in members]
        lock, workspace, source = self.bind_source(attempt="attempt-wal-source")
        try:
            self.assertEqual("wal_triplet_read_only", source.mode)
            self.assertEqual(("main", "wal", "shm"), source.members)
            with source.backup_to_memory() as view:
                self.assertEqual("from-wal", view.query(
                    "SELECT value FROM source_probe WHERE id=1"
                )[0][0])
                self.assertEqual(view.before, view.after)
            source.close()
            workspace.close()
        finally:
            if lock.held:
                lock.release()
        after = [(member.stat(), member.read_bytes()) for member in members]
        for (before_stat, before_raw), (after_stat, after_raw) in zip(
            before, after, strict=True
        ):
            self.assertEqual(before_raw, after_raw)
            self.assertEqual(
                (before_stat.st_ino, before_stat.st_size, before_stat.st_mtime_ns),
                (after_stat.st_ino, after_stat.st_size, after_stat.st_mtime_ns),
            )

    def test_sidecar_third_values_hardlink_and_post_pin_drift_fail_closed(self) -> None:
        path = self.create_main_database()
        wal = Path(str(path) + "-wal")
        wal.write_bytes(b"orphan")
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "attempt-orphan", "nonce-orphan"
            )
            with self.assertRaisesRegex(UnsafeLocalPath, "WAL/SHM"):
                self.persistence.lock_state_sqlite_source(
                    lock, workspace, "comments"
                )
        wal.unlink()

        alias = self.persistence.layout.state / "comments-hardlink.sqlite3"
        try:
            os.link(path, alias)
        except OSError as error:
            self.skipTest(f"当前 volume 不支持 hardlink fixture: {error}")
        try:
            with self.persistence.global_lock() as lock:
                workspace = self.persistence.bind_attempt_workspace(
                    lock, "attempt-hardlink", "nonce-hardlink"
                )
                with self.assertRaises(UnsafeLocalPath):
                    self.persistence.lock_state_sqlite_source(
                        lock, workspace, "comments"
                    )
        finally:
            alias.unlink(missing_ok=True)

        lock, workspace, source = self.bind_source(attempt="attempt-drift")
        try:
            Path(str(path) + "-wal").write_bytes(b"new-sidecar")
            with self.assertRaisesRegex(UnsafeLocalPath, "sidecar|第三值"):
                source.backup_to_memory()
        finally:
            Path(str(path) + "-wal").unlink(missing_ok=True)
            if workspace._state == "live":  # noqa: SLF001
                source.close()
                workspace.close()
            if lock.held:
                lock.release()

    @unittest.skipUnless(os.name == "nt", "writer fence 使用真实 Windows share mode")
    def test_unfenced_writer_is_rejected_without_source_or_workspace_leak(self) -> None:
        path = self.database_path()
        with closing(sqlite3.connect(path, isolation_level=None)) as writer:
            writer.execute(
                "CREATE TABLE source_probe(id INTEGER PRIMARY KEY,value TEXT NOT NULL) STRICT"
            )
            writer.execute("INSERT INTO source_probe VALUES(1,'writer-live')")
            writer.execute("PRAGMA journal_mode=WAL")
            lock = self.persistence.global_lock().acquire()
            workspace = self.persistence.bind_attempt_workspace(
                lock, "attempt-writer", "nonce-writer"
            )
            with self.assertRaisesRegex(UnsafeLocalPath, "no-share-write/delete"):
                self.persistence.lock_state_sqlite_source(
                    lock, workspace, "comments"
                )
            self.assertEqual("live", workspace._state)  # noqa: SLF001
            self.assertEqual(set(), workspace._state_sources)  # noqa: SLF001
            workspace.close()
            lock.release()

    def test_explicit_workspace_and_lock_release_close_views_and_sources(self) -> None:
        self.create_main_database()
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-lifecycle-source", "nonce-lifecycle-source"
        )
        source = self.persistence.lock_state_sqlite_source(
            lock, workspace, "comments"
        )
        view = source.backup_to_memory()
        workspace.close()
        self.assertEqual("closed", source._state)  # noqa: SLF001
        with self.assertRaises(UnsafeLocalPath):
            view.query("SELECT 1")

        replay = self.persistence.bind_attempt_workspace(
            lock, "attempt-lifecycle-source-2", "nonce-lifecycle-source-2"
        )
        second = self.persistence.lock_state_sqlite_source(
            lock, replay, "comments"
        )
        second_view = second.backup_to_memory()
        lock.release()
        self.assertFalse(lock.held)
        self.assertEqual("closed", second._state)  # noqa: SLF001
        with self.assertRaises(UnsafeLocalPath):
            second_view.query("SELECT 1")

    @unittest.skipUnless(os.name == "nt", "close retry 使用真实 Windows source guard")
    def test_source_close_fault_keeps_workspace_and_kernel_lock_until_owner_retry(self) -> None:
        self.create_main_database()
        lock, workspace, source = self.bind_source(attempt="attempt-close-source")
        source_type = persistence_module.LockedStateSqliteSource
        real_close = source_type._close_windows_member
        calls = 0

        def fail_once(
            current: LockedStateSqliteSource,
            member: object,
        ) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected before source close syscall")
            real_close(current, member)  # type: ignore[arg-type]

        with patch.object(source_type, "_close_windows_member", new=fail_once):
            with self.assertRaises(LocalDeploymentPersistenceError):
                workspace.close()
        self.assertEqual("closing", workspace._state)  # noqa: SLF001
        self.assertIn(source, workspace._state_sources)  # noqa: SLF001
        self.assertTrue(lock.held)
        self.assertEqual("BUSY", self.cross_process_lock_probe())
        workspace.close()
        self.assertEqual("closed", source._state)  # noqa: SLF001
        lock.release()
        self.assertEqual("ACQUIRED", self.cross_process_lock_probe())

    @unittest.skipUnless(os.name == "nt", "owner-crash-only 使用真实 Windows CLOSE_SOURCE")
    def test_source_raw_close_unknown_retires_numbers_until_owner_process_exit(self) -> None:
        self.create_main_database()
        source_root = Path(__file__).resolve().parents[1] / "src"
        helper = (
            "import json,sys,time\n"
            "from pathlib import Path\n"
            "from quant_hub.ops import local_deployment_persistence as m\n"
            "p=m.LocalDeploymentPersistence.for_test_only(Path(sys.argv[1]).resolve(),allow_posix_test_only=True)\n"
            "mode=sys.argv[2]\n"
            "lock=p.global_lock().acquire()\n"
            "workspace=p.bind_attempt_workspace(lock,'attempt-crash-source','nonce-crash-source')\n"
            "source=p.lock_state_sqlite_source(lock,workspace,'comments')\n"
            "real=m.CrashReleasedFileLock._windows_duplicate_close_source_call\n"
            "replacement=[]\n"
            "def injected(handle):\n"
            " if mode=='post':\n"
            "  real(handle)\n"
            "  opened=[]\n"
            "  for _ in range(2048):\n"
            "   h=m._BoundDirectory._open_windows_directory(p.layout.incoming,protect_rename=False); opened.append(h)\n"
            "   if h==handle: replacement.append(h); break\n"
            "  for h in opened:\n"
            "   if not replacement or h!=replacement[0]: m._BoundDirectory._close_windows_handle(h)\n"
            "  if not replacement: raise AssertionError('same-number source replacement unavailable')\n"
            " raise OSError('source raw close outcome unknown')\n"
            "m.CrashReleasedFileLock._windows_duplicate_close_source_call=staticmethod(injected)\n"
            "try: source.close()\n"
            "except BaseException as e: close_error=type(e).__name__\n"
            "else: close_error='NONE'\n"
            "try: source.close()\n"
            "except BaseException as e: retry_error=type(e).__name__\n"
            "else: retry_error='NONE'\n"
            "replacement_live=(not replacement) or (m._BoundDirectory._windows_final_path(replacement[0])==str(p.layout.incoming))\n"
            "print(json.dumps({'phase':lock._release_phase,'held':lock.held,'kernel':lock._kernel_lock_acquired,'source_state':source._state,'member_handles':[x.windows_handle for x in source._members],'retired_len':len(lock._retired_guard_close_audit_sha256 or ''),'close_error':close_error,'retry_error':retry_error,'replacement_live':replacement_live}),flush=True)\n"
            "time.sleep(300)\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(source_root)
        for mode in ("pre", "post"):
            with self.subTest(mode=mode):
                process = subprocess.Popen(
                    [sys.executable, "-c", helper, str(self.root), mode],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                )
                try:
                    assert process.stdout is not None
                    line = process.stdout.readline()
                    if not line:
                        assert process.stderr is not None
                        self.fail(process.stderr.read())
                    state = json.loads(line)
                    self.assertEqual("owner_crash_only", state["phase"])
                    self.assertTrue(state["held"])
                    self.assertIsNone(state["kernel"])
                    self.assertEqual("owner_crash_only", state["source_state"])
                    self.assertTrue(all(value is None for value in state["member_handles"]))
                    self.assertEqual(64, state["retired_len"])
                    self.assertEqual(
                        "LocalDeploymentPersistenceError", state["close_error"]
                    )
                    self.assertNotEqual("NONE", state["retry_error"])
                    self.assertTrue(state["replacement_live"])
                    self.assertEqual("BUSY", self.cross_process_lock_probe())
                    process.kill()
                    process.wait(timeout=15)
                    self.assertEqual("ACQUIRED", self.cross_process_lock_probe())
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=15)
                    process.communicate(timeout=5)


class ExactReleaseClosureSeamTests(PersistenceFixture):
    def exact_release(
        self, release_id: str, character: str
    ) -> dict[str, object]:
        return release(
            release_id,
            self.payloads[release_id],
            character,
            include_migrations=True,
        )

    def install_activation_intent(self) -> None:
        self.r0 = self.exact_release("release-r0", "9")
        self.r1 = self.exact_release("release-r1", "a")
        for document in (self.r0, self.r1):
            self.materialize(document)
        self.append_history(
            [journal(self.r0, self.r1, nonce="nonce-closure")]
        )

    def cross_process_lock_probe(self) -> str:
        helper = (
            "import os,sys\n"
            "fd=os.open(sys.argv[1],os.O_RDWR)\n"
            "try:\n"
            " try:\n"
            "  import msvcrt; os.lseek(fd,0,0); msvcrt.locking(fd,msvcrt.LK_NBLCK,1)\n"
            " except (OSError,BlockingIOError): print('BUSY')\n"
            " else: print('ACQUIRED')\n"
            "finally: os.close(fd)\n"
        )
        return subprocess.check_output(
            [
                sys.executable,
                "-c",
                helper,
                str(self.persistence.layout.deployment_lock),
            ],
            text=True,
            timeout=15,
        ).strip()

    def test_bootstrap_activation_and_rollback_roles_come_from_target_pair(self) -> None:
        scenarios = ("bootstrap_first_pair", "activation", "rollback")
        for operation in scenarios:
            with self.subTest(operation=operation):
                if operation == "bootstrap_first_pair":
                    self.r0 = self.exact_release("release-r0", "9")
                    self.materialize(self.r0)
                    first = journal(
                        None,
                        self.r0,
                        operation=operation,
                        attempt="attempt-bootstrap",
                        nonce="nonce-bootstrap",
                    )
                    expected = ("candidate",)
                    candidate_id, prior_id = "release-r0", None
                elif operation == "activation":
                    self.r0 = self.exact_release("release-r0", "9")
                    self.r1 = self.exact_release("release-r1", "a")
                    for document in (self.r0, self.r1):
                        self.materialize(document)
                    first = journal(
                        self.r0,
                        self.r1,
                        attempt="attempt-activation",
                        nonce="nonce-activation",
                    )
                    expected = ("candidate", "prior")
                    candidate_id, prior_id = "release-r1", "release-r0"
                else:
                    self.r_minus_1 = self.exact_release(
                        "release-r-minus-1", "8"
                    )
                    self.r0 = self.exact_release("release-r0", "9")
                    for document in (self.r_minus_1, self.r0):
                        self.materialize(document)
                    first = journal(
                        self.r0,
                        self.r1,
                        original_prior=self.r_minus_1,
                        operation=operation,
                        attempt="attempt-rollback",
                        nonce="nonce-rollback",
                    )
                    expected = ("candidate", "prior")
                    candidate_id, prior_id = "release-r-minus-1", "release-r0"
                self.append_history([first])
                with self.persistence.global_lock() as lock:
                    workspace = self.persistence.bind_attempt_workspace(
                        lock, str(first["attempt"]), str(first["nonce"])
                    )
                    closures = self.persistence.lock_exact_release_closures(
                        lock, workspace
                    )
                    self.assertIsInstance(closures, LockedExactReleaseClosures)
                    self.assertEqual(expected, closures.roles)
                    roles = closures.metadata()["roles"]
                    self.assertEqual(candidate_id, roles["candidate"]["release_id"])
                    self.assertEqual(
                        prior_id,
                        None
                        if roles["prior"] is None
                        else roles["prior"]["release_id"],
                    )
                    self.assertEqual(
                        migration_bytes(candidate_id, EXACT_MIGRATIONS[0]),
                        closures.read_migration("candidate", EXACT_MIGRATIONS[0]),
                    )
                    closures.close()
                    workspace.close()

    def test_signature_latest_nonce_authority_and_closed_attempt(self) -> None:
        self.assertEqual(
            {"self", "lock", "workspace"},
            set(
                inspect.signature(
                    LocalDeploymentPersistence.lock_exact_release_closures
                ).parameters
            ),
        )
        self.install_activation_intent()
        with self.persistence.global_lock() as lock:
            wrong_nonce = self.persistence.bind_attempt_workspace(
                lock, "attempt-1", "different-nonce"
            )
            with self.assertRaisesRegex(DeploymentJournalError, "nonce"):
                self.persistence.lock_exact_release_closures(lock, wrong_nonce)
            wrong_nonce.close()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "attempt-1", "nonce-closure"
            )
            for injected in (
                {"database": "comments"},
                {"path": self.root},
                {"root": self.root},
                {"release_id": "release-r1"},
            ):
                with self.subTest(injected=tuple(injected)), self.assertRaises(TypeError):
                    self.persistence.lock_exact_release_closures(  # type: ignore[call-arg]
                        lock, workspace, **injected
                    )
            workspace.close()
        with self.assertRaises((UnsafeLocalPath, DeploymentLockBusy)):
            self.persistence.lock_exact_release_closures(lock, workspace)

        foreign = LocalDeploymentPersistence.for_test_only(
            self.root, allow_posix_test_only=True
        )
        with self.persistence.global_lock() as held:
            current = self.persistence.bind_attempt_workspace(
                held, "attempt-1", "nonce-closure"
            )
            with self.assertRaises(DeploymentLockBusy):
                foreign.lock_exact_release_closures(held, current)
            current.close()

        bootstrap = self.exact_release("release-r2", "b")
        self.materialize(bootstrap)
        first = journal(
            None,
            bootstrap,
            operation="bootstrap_first_pair",
            attempt="closed-bootstrap",
            nonce="nonce-closed",
        )
        terminal = bootstrap_receipt(bootstrap, attempt="closed-bootstrap")
        self.append_history(history_to(first, "terminal_receipt_committed", receipt=terminal))
        with self.persistence.global_lock() as held:
            closed_workspace = self.persistence.bind_attempt_workspace(
                held, "closed-bootstrap", "nonce-closed"
            )
            with self.assertRaisesRegex(DeploymentJournalError, "closed"):
                self.persistence.lock_exact_release_closures(
                    held, closed_workspace
                )
            closed_workspace.close()

    def test_public_surface_is_pathless_cloned_and_non_serializable(self) -> None:
        self.install_activation_intent()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "attempt-1", "nonce-closure"
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            self.assertEqual("exact_release_closure_input_only", closures.scope)
            expected_plan = identity.identity_sha256(
                [
                    {
                        "name": name,
                        "compatibility_manifest_sha256": "b" * 64,
                    }
                    for name in ("comments", "research_workspace")
                ]
            )
            self.assertEqual(
                expected_plan, closures.planned_compatibility_sha256
            )
            self.assertEqual(
                expected_plan,
                closures.metadata()["planned_compatibility_sha256"],
            )
            with self.assertRaises(TypeError):
                pickle.dumps(closures)
            rendered = json.dumps(closures.metadata(), ensure_ascii=False).casefold()
            for forbidden in (
                "canonical_path",
                "release_path",
                "handle",
                "descriptor",
                str(self.root).casefold(),
                "qualified",
            ):
                self.assertNotIn(forbidden, rendered)
            manifest = closures.read_manifest("candidate")
            manifest["release_id"] = "mutated-clone"
            self.assertEqual(
                "release-r1",
                closures.read_manifest("candidate")["release_id"],
            )
            with self.assertRaisesRegex(UnsafeLocalPath, "固定"):
                closures.read_migration("candidate", "app/payload.bin")
            self.assertFalse(hasattr(closures, "__dict__"))
            closures.close()
            workspace.close()

    def test_migration_subtree_missing_extra_and_renamed_are_rejected(self) -> None:
        for mutation in ("missing", "extra", "renamed"):
            with self.subTest(mutation=mutation):
                for release_id in ("release-r0", "release-r1"):
                    shutil.rmtree(
                        self.persistence.layout.releases / release_id,
                        ignore_errors=True,
                    )
                self.r0 = self.exact_release("release-r0", "9")
                self.r1 = self.exact_release("release-r1", "a")
                if mutation == "renamed":
                    record = next(
                        item
                        for item in self.r1["inventory"]["files"]
                        if item["path"] == EXACT_MIGRATIONS[0]
                    )
                    record["path"] = "migrations/research_workspace/0001_wrong.down.sql"
                    raw = migration_bytes("release-r1", str(record["path"]))
                    record["bytes"], record["sha256"] = len(raw), digest(raw)
                    self.r1["inventory"]["files"] = sorted(
                        self.r1["inventory"]["files"],
                        key=lambda item: str(item["path"]),
                    )
                    self.r1["resources"]["inventory_sha256"] = (
                        identity.identity_sha256(self.r1["inventory"])
                    )
                for document in (self.r0, self.r1):
                    self.materialize(document)
                root = self.persistence.layout.releases / "release-r1"
                if mutation == "missing":
                    root.joinpath(*EXACT_MIGRATIONS[0].split("/")).unlink()
                elif mutation == "extra":
                    (root / "migrations" / "research_workspace" / "extra.sql").write_text(
                        "SELECT 1;", encoding="utf-8"
                    )
                attempt = f"attempt-{mutation}"
                first = journal(
                    self.r0,
                    self.r1,
                    attempt=attempt,
                    nonce=f"nonce-{mutation}",
                )
                self.append_history([first])
                with self.persistence.global_lock() as lock:
                    workspace = self.persistence.bind_attempt_workspace(
                        lock, attempt, f"nonce-{mutation}"
                    )
                    with self.assertRaises(
                        (RetentionPlanningError, UnsafeLocalPath)
                    ):
                        self.persistence.lock_exact_release_closures(lock, workspace)
                    workspace.close()

    def test_legacy_manifest_schema_and_unknown_field_are_rejected(self) -> None:
        for variant in ("v1", "unknown_field"):
            with self.subTest(variant=variant):
                for release_id in ("release-r0", "release-r1"):
                    shutil.rmtree(
                        self.persistence.layout.releases / release_id,
                        ignore_errors=True,
                    )
                self.r0 = self.exact_release("release-r0", "9")
                self.r1 = self.exact_release("release-r1", "a")
                if variant == "v1":
                    self.r1["schema_version"] = "qrh-release-manifest/v1"
                else:
                    self.r1["unexpected_field"] = "forbidden"
                for document in (self.r0, self.r1):
                    self.materialize(document)
                attempt = f"attempt-legacy-{variant}"
                first = journal(
                    self.r0,
                    self.r1,
                    attempt=attempt,
                    nonce=f"nonce-legacy-{variant}",
                )
                self.append_history([first])
                with self.persistence.global_lock() as lock:
                    workspace = self.persistence.bind_attempt_workspace(
                        lock, attempt, f"nonce-legacy-{variant}"
                    )
                    with self.assertRaises(
                        (
                            RetentionPlanningError,
                            LocalDeploymentPersistenceError,
                            identity.LocalReleaseIdentityError,
                        )
                    ):
                        self.persistence.lock_exact_release_closures(lock, workspace)
                    workspace.close()

        shutil.rmtree(
            self.persistence.layout.releases / "release-r0", ignore_errors=True
        )
        shutil.rmtree(
            self.persistence.layout.releases / "release-r1", ignore_errors=True
        )
        self.r0 = self.exact_release("release-r0", "9")
        self.r1 = self.exact_release("release-r1", "a")
        for document in (self.r0, self.r1):
            self.materialize(document)
        migration = self.persistence.layout.releases.joinpath(
            "release-r1", *EXACT_MIGRATIONS[0].split("/")
        )
        shadow = self.persistence.layout.temporary / "migration-hardlink-shadow"
        os.link(migration, shadow)
        first = journal(
            self.r0,
            self.r1,
            attempt="attempt-hardlink",
            nonce="nonce-hardlink",
        )
        self.append_history([first])
        try:
            with self.persistence.global_lock() as lock:
                workspace = self.persistence.bind_attempt_workspace(
                    lock, "attempt-hardlink", "nonce-hardlink"
                )
                with self.assertRaises(RetentionPlanningError):
                    self.persistence.lock_exact_release_closures(lock, workspace)
                workspace.close()
        finally:
            shadow.unlink(missing_ok=True)

        if os.name != "nt":
            migration.unlink()
            migration.symlink_to(self.persistence.layout.releases / "release-r0" / "app" / "payload.bin")
            reparse = journal(
                self.r0,
                self.r1,
                attempt="attempt-reparse",
                nonce="nonce-reparse",
            )
            self.append_history([reparse])
            with self.persistence.global_lock() as lock:
                workspace = self.persistence.bind_attempt_workspace(
                    lock, "attempt-reparse", "nonce-reparse"
                )
                with self.assertRaises(UnsafeLocalPath):
                    self.persistence.lock_exact_release_closures(lock, workspace)
                workspace.close()

    def test_manifest_inventory_and_relabelled_core_fail_closed(self) -> None:
        for variant in (
            "manifest_hash",
            "manifest_id",
            "inventory_bytes",
            "core_copy",
        ):
            with self.subTest(variant=variant):
                for release_id in ("release-r0", "release-r1"):
                    shutil.rmtree(
                        self.persistence.layout.releases / release_id,
                        ignore_errors=True,
                    )
                self.r0 = self.exact_release("release-r0", "9")
                if variant == "core_copy":
                    self.payloads["release-r1"] = self.payloads["release-r0"]
                    self.r1 = deepcopy(self.r0)
                    self.r1["release_id"] = "release-r1"
                    self.r1["built_at"] = "2026-08-26T10:01:00+08:00"
                    self.r1["application"]["provenance"] = {
                        "builder": "copy",
                        "labels": ["copy"],
                    }
                else:
                    self.r1 = self.exact_release("release-r1", "a")
                for document in (self.r0, self.r1):
                    self.materialize(document)
                if variant == "core_copy":
                    release_root = self.persistence.layout.releases / "release-r1"
                    for relative in EXACT_MIGRATIONS:
                        release_root.joinpath(*relative.split("/")).write_bytes(
                            migration_bytes("release-r0", relative)
                        )
                attempt = f"attempt-{variant}"
                first = journal(
                    self.r0,
                    self.r1,
                    attempt=attempt,
                    nonce=f"nonce-{variant}",
                )
                if variant == "manifest_hash":
                    changed = deepcopy(self.r1)
                    changed["built_at"] = "2026-08-26T10:02:00+08:00"
                    (self.persistence.layout.releases / "release-r1" / "release_manifest.json").write_bytes(
                        identity.canonical_bytes(changed)
                    )
                elif variant == "manifest_id":
                    changed = deepcopy(self.r1)
                    changed["release_id"] = "release-other"
                    (self.persistence.layout.releases / "release-r1" / "release_manifest.json").write_bytes(
                        identity.canonical_bytes(changed)
                    )
                elif variant == "inventory_bytes":
                    (self.persistence.layout.releases / "release-r1" / "app" / "payload.bin").write_bytes(b"drift")
                self.append_history([first])
                with self.persistence.global_lock() as lock:
                    workspace = self.persistence.bind_attempt_workspace(
                        lock, attempt, f"nonce-{variant}"
                    )
                    with self.assertRaises(RetentionPlanningError):
                        self.persistence.lock_exact_release_closures(lock, workspace)
                    workspace.close()

        wrong_path = journal(
            self.r0,
            self.r1,
            attempt="attempt-wrong-path",
            nonce="nonce-wrong-path",
        )
        wrong_path["candidate"]["release_path"] = r"C:\forbidden\release-r1"
        seal(wrong_path, "journal_sha256")
        with self.assertRaises(DeploymentJournalError):
            validate_deployment_journal(wrong_path)

    def test_nonmigration_drift_keeps_lock_until_repair_and_retry(self) -> None:
        self.install_activation_intent()
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-1", "nonce-closure"
        )
        closures = self.persistence.lock_exact_release_closures(lock, workspace)
        contender = self.persistence.global_lock()
        transient = (
            self.persistence.layout.releases
            / "release-r1"
            / "app"
            / "unmanifested-transient.bin"
        )
        try:
            transient.write_bytes(b"temporary-drift")
            with self.assertRaises(RetentionPlanningError):
                closures.checkpoint_unchanged()
            self.assertEqual("revoked", closures._state)  # noqa: SLF001
            with self.assertRaises(DeploymentLockBusy):
                contender.acquire()
            transient.unlink()
            workspace.close()
            lock.release()
            with contender:
                self.assertTrue(contender.held)
        finally:
            transient.unlink(missing_ok=True)
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    @unittest.skipUnless(
        os.name == "nt",
        "递归 namespace add-delete ABA monitor 只验证 Windows 产品语义",
    )
    def test_release_namespace_create_delete_aba_revokes_live_closure(self) -> None:
        self.install_activation_intent()
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-1", "nonce-closure"
        )
        closures = self.persistence.lock_exact_release_closures(lock, workspace)
        transient = (
            self.persistence.layout.releases
            / "release-r1"
            / "app"
            / "unmanifested-aba.bin"
        )
        try:
            transient.write_bytes(b"create-delete-aba")
            transient.unlink()
            with self.assertRaises(RetentionPlanningError):
                closures.checkpoint_unchanged()
            self.assertEqual("revoked", closures._state)  # noqa: SLF001
            with self.assertRaises(UnsafeLocalPath):
                closures.checkpoint_unchanged()
            workspace.close()
            lock.release()
        finally:
            transient.unlink(missing_ok=True)
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def test_partial_known_close_fault_keeps_tracking_and_owner_can_retry(self) -> None:
        self.install_activation_intent()
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-1", "nonce-closure"
        )
        closures = self.persistence.lock_exact_release_closures(lock, workspace)
        close_name = (
            "_close_windows_member" if os.name == "nt" else "_close_posix_member"
        )
        real_close = getattr(LockedExactReleaseClosures, close_name)
        calls = 0

        def fail_first(current: LockedExactReleaseClosures, member: object) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise OSError("injected before exact-release member close")
            real_close(current, member)

        with patch.object(LockedExactReleaseClosures, close_name, new=fail_first):
            with self.assertRaises(LocalDeploymentPersistenceError):
                workspace.close()
        self.assertEqual("closing", workspace._state)  # noqa: SLF001
        self.assertIn(closures, workspace._exact_release_closures)  # noqa: SLF001
        contender = self.persistence.global_lock()
        with self.assertRaises(DeploymentLockBusy):
            contender.acquire()

        workspace.close()
        self.assertEqual("closed", closures._state)  # noqa: SLF001
        lock.release()
        with contender:
            self.assertTrue(contender.held)

    @unittest.skipUnless(os.name == "nt", "Windows no-share-write/delete guard")
    def test_windows_migration_write_rename_blocked_and_lock_auto_closes(self) -> None:
        self.install_activation_intent()
        target = self.persistence.layout.releases.joinpath(
            "release-r1", *EXACT_MIGRATIONS[0].split("/")
        )
        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock, "attempt-1", "nonce-closure"
        )
        self.persistence.lock_exact_release_closures(lock, workspace)
        with self.assertRaises(PermissionError):
            target.write_bytes(b"blocked")
        with self.assertRaises(PermissionError):
            target.rename(target.with_suffix(".renamed"))
        manifest = self.persistence.layout.releases / "release-r1" / "release_manifest.json"
        with self.assertRaises(PermissionError):
            manifest.write_bytes(b"blocked")
        payload = self.persistence.layout.releases / "release-r1" / "app" / "payload.bin"
        with self.assertRaises(PermissionError):
            payload.write_bytes(b"transient-tamper")
        with self.assertRaises(PermissionError):
            payload.rename(payload.with_suffix(".renamed"))
        lock.release()
        target.write_bytes(migration_bytes("release-r1", EXACT_MIGRATIONS[0]))

    @unittest.skipUnless(os.name == "nt", "真实 Windows raw close outcome")
    def test_windows_raw_close_unknown_retires_closure_until_process_exit(self) -> None:
        self.install_activation_intent()
        source_root = Path(__file__).resolve().parents[1] / "src"
        helper = (
            "import json,sys,time\n"
            "from pathlib import Path\n"
            "from quant_hub.ops import local_deployment_persistence as m\n"
            "p=m.LocalDeploymentPersistence.for_test_only(Path(sys.argv[1]).resolve(),allow_posix_test_only=True)\n"
            "mode=sys.argv[2]\n"
            "lock=p.global_lock().acquire()\n"
            "workspace=p.bind_attempt_workspace(lock,'attempt-1','nonce-closure')\n"
            "closures=p.lock_exact_release_closures(lock,workspace)\n"
            "real=m.CrashReleasedFileLock._windows_duplicate_close_source_call\n"
            "replacement=[]\n"
            "def injected(handle):\n"
            " if mode=='post':\n"
            "  real(handle)\n"
            "  opened=[]\n"
            "  for _ in range(2048):\n"
            "   h=m._BoundDirectory._open_windows_directory(p.layout.incoming,protect_rename=False); opened.append(h)\n"
            "   if h==handle: replacement.append(h); break\n"
            "  for h in opened:\n"
            "   if not replacement or h!=replacement[0]: m._BoundDirectory._close_windows_handle(h)\n"
            "  if not replacement: raise AssertionError('same-number closure replacement unavailable')\n"
            " raise OSError('closure raw close outcome unknown')\n"
            "m.CrashReleasedFileLock._windows_duplicate_close_source_call=staticmethod(injected)\n"
            "try: closures.close()\n"
            "except BaseException as e: close_error=type(e).__name__\n"
            "else: close_error='NONE'\n"
            "replacement_live=(not replacement) or (m._BoundDirectory._windows_final_path(replacement[0])==str(p.layout.incoming))\n"
            "print(json.dumps({'phase':lock._release_phase,'held':lock.held,'kernel':lock._kernel_lock_acquired,'closure_state':closures._state,'handles':[x.windows_handle for r in closures._roles for x in r.members],'retired_len':len(lock._retired_guard_close_audit_sha256 or ''),'close_error':close_error,'replacement_live':replacement_live}),flush=True)\n"
            "time.sleep(300)\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(source_root)
        for mode in ("pre", "post"):
            with self.subTest(mode=mode):
                process = subprocess.Popen(
                    [sys.executable, "-c", helper, str(self.root), mode],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=environment,
                )
                try:
                    assert process.stdout is not None
                    line = process.stdout.readline()
                    if not line:
                        assert process.stderr is not None
                        self.fail(process.stderr.read())
                    state = json.loads(line)
                    self.assertEqual("owner_crash_only", state["phase"])
                    self.assertTrue(state["held"])
                    self.assertIsNone(state["kernel"])
                    self.assertEqual("owner_crash_only", state["closure_state"])
                    self.assertTrue(all(value is None for value in state["handles"]))
                    self.assertEqual(64, state["retired_len"])
                    self.assertEqual(
                        "LocalDeploymentPersistenceError", state["close_error"]
                    )
                    self.assertTrue(state["replacement_live"])
                    self.assertEqual("BUSY", self.cross_process_lock_probe())
                    process.kill()
                    process.wait(timeout=15)
                    self.assertEqual("ACQUIRED", self.cross_process_lock_probe())
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=15)
                    process.communicate(timeout=5)

    @unittest.skipUnless(os.name == "nt", "真实 Windows namespace monitor close outcome")
    def test_windows_namespace_monitor_close_unknown_is_owner_crash_only(self) -> None:
        self.install_activation_intent()
        source_root = Path(__file__).resolve().parents[1] / "src"
        helper = (
            "import json,sys,time\n"
            "from pathlib import Path\n"
            "from quant_hub.ops import local_deployment_persistence as m\n"
            "from quant_hub.ops import local_exact_runtime_tooling_scanner as s\n"
            "p=m.LocalDeploymentPersistence.for_test_only(Path(sys.argv[1]).resolve(),allow_posix_test_only=True)\n"
            "lock=p.global_lock().acquire()\n"
            "workspace=p.bind_attempt_workspace(lock,'attempt-1','nonce-closure')\n"
            "closures=p.lock_exact_release_closures(lock,workspace)\n"
            "real=s._WindowsNamespaceChangeMonitor.close\n"
            "def injected(current):\n"
            " real(current)\n"
            " raise OSError('namespace monitor close outcome unknown')\n"
            "s._WindowsNamespaceChangeMonitor.close=injected\n"
            "try: closures.checkpoint_unchanged()\n"
            "except BaseException as e: checkpoint_error=type(e).__name__\n"
            "else: checkpoint_error='NONE'\n"
            "print(json.dumps({'phase':lock._release_phase,'held':lock.held,'kernel':lock._kernel_lock_acquired,'closure_state':closures._state,'monitors':[r.namespace_monitor is None for r in closures._roles],'checkpoint_error':checkpoint_error}),flush=True)\n"
            "time.sleep(300)\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(source_root)
        process = subprocess.Popen(
            [sys.executable, "-c", helper, str(self.root)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        try:
            assert process.stdout is not None
            line = process.stdout.readline()
            if not line:
                assert process.stderr is not None
                self.fail(process.stderr.read())
            state = json.loads(line)
            self.assertEqual("owner_crash_only", state["phase"])
            self.assertTrue(state["held"])
            self.assertIsNone(state["kernel"])
            self.assertEqual("owner_crash_only", state["closure_state"])
            self.assertTrue(all(state["monitors"]))
            self.assertEqual(
                "LocalDeploymentPersistenceError",
                state["checkpoint_error"],
            )
            self.assertEqual("BUSY", self.cross_process_lock_probe())
            process.kill()
            process.wait(timeout=15)
            self.assertEqual("ACQUIRED", self.cross_process_lock_probe())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=15)
            process.communicate(timeout=5)


class ExactTransientStartAuthorizationSeamTests(PersistenceFixture):
    def workspace_path(self, attempt: str, nonce: str) -> Path:
        return (
            self.persistence.layout.temporary
            / "deployment-attempts"
            / f"{attempt}-{nonce}"
        )

    def _first(
        self,
        *,
        operation: str,
        attempt: str,
        nonce: str,
    ) -> dict[str, object]:
        if operation == "bootstrap_first_pair":
            return journal(
                None,
                self.r0,
                operation=operation,
                attempt=attempt,
                nonce=nonce,
            )
        return journal(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            operation=operation,
            attempt=attempt,
            nonce=nonce,
        )

    def test_activation_rollback_bootstrap_are_exact_and_hash_bound(self) -> None:
        cases = (
            (
                "activation",
                "transient-activation",
                "nonce-transient-activation",
                {"prior": self.r0, "candidate": self.r1},
            ),
            (
                "rollback",
                "transient-rollback",
                "nonce-transient-rollback",
                {"prior": self.r_minus_1, "candidate": self.r_minus_1},
            ),
            (
                "bootstrap_first_pair",
                "transient-bootstrap",
                "nonce-transient-bootstrap",
                {"baseline": self.r0},
            ),
        )
        for operation, attempt, nonce, expected_roles in cases:
            first = self._first(
                operation=operation,
                attempt=attempt,
                nonce=nonce,
            )
            latest = history_to(first, "candidate_start_authorized")[-1]
            self.append_history(history_to(first, "candidate_start_authorized"))
            with self.persistence.global_lock() as lock:
                workspace = self.persistence.bind_attempt_workspace(
                    lock, attempt, nonce
                )
                for role, expected_release in expected_roles.items():
                    with self.subTest(operation=operation, role=role):
                        authorization = (
                            self.persistence.lock_exact_transient_start_authorization(
                                lock, workspace, role
                            )
                        )
                        self.assertIs(
                            type(authorization),
                            LockedExactTransientStartAuthorization,
                        )
                        self.assertEqual(
                            "exact_transient_start_authorization_input_only",
                            authorization.scope,
                        )
                        self.assertEqual(operation, authorization.operation)
                        self.assertEqual(
                            "candidate_start_authorized", authorization.phase
                        )
                        self.assertEqual(attempt, authorization.attempt_id)
                        self.assertEqual(nonce, authorization.nonce)
                        self.assertEqual(role, authorization.role)
                        self.assertEqual(
                            f"{role}-{nonce}", authorization.start_nonce
                        )
                        start = next(
                            item
                            for item in latest["transient_start"]
                            if item["role"] == role
                        )
                        self.assertEqual(
                            persistence_module._transient_scm_start_plan_sha256(
                                latest, start
                            ),
                            authorization.scm_identity_sha256,
                        )
                        self.assertEqual(
                            state_identity()["identity_sha256"],
                            authorization.state_identity_sha256,
                        )
                        self.assertEqual(
                            release_ref(expected_release), authorization.release_ref
                        )
                        evidence_field = (
                            "prior_start_authorization_sha256"
                            if role == "prior"
                            else "candidate_start_authorization_sha256"
                        )
                        self.assertEqual(
                            latest["evidence_hashes"][evidence_field],
                            authorization.authorization_sha256,
                        )
                workspace.close()

    def test_signature_rejects_injection_bad_role_and_phase_before_record(self) -> None:
        self.assertEqual(
            {"self", "lock", "workspace", "role"},
            set(
                inspect.signature(
                    LocalDeploymentPersistence.lock_exact_transient_start_authorization
                ).parameters
            ),
        )
        first = self._first(
            operation="activation",
            attempt="transient-prephase",
            nonce="nonce-transient-prephase",
        )
        self.append_history([first])
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "transient-prephase", "nonce-transient-prephase"
            )
            for role in (True, "Candidate", "candidate ", "unknown", None):
                with self.subTest(role=role), self.assertRaises(
                    DeploymentJournalError
                ):
                    self.persistence.lock_exact_transient_start_authorization(
                        lock, workspace, role  # type: ignore[arg-type]
                    )
            for role in ("prior", "candidate", "baseline"):
                with self.subTest(missing_role=role), self.assertRaisesRegex(
                    DeploymentJournalError, "唯一"
                ):
                    self.persistence.lock_exact_transient_start_authorization(
                        lock, workspace, role
                    )
            for injected in (
                {"attempt": "other"},
                {"nonce": "other"},
                {"release": release_ref(self.r1)},
                {"path": self.root},
                {"root": self.root},
                {"scm_identity_sha256": "a" * 64},
                {"runtime": object()},
                {"hook": object()},
                {"env": {}},
            ):
                with self.subTest(injected=tuple(injected)), self.assertRaises(
                    TypeError
                ):
                    self.persistence.lock_exact_transient_start_authorization(  # type: ignore[call-arg]
                        lock, workspace, "candidate", **injected
                    )
            wrong_nonce = self.persistence.bind_attempt_workspace(
                lock, "transient-prephase", "different-transient-nonce"
            )
            with self.assertRaisesRegex(DeploymentJournalError, "attempt/nonce"):
                self.persistence.lock_exact_transient_start_authorization(
                    lock, wrong_nonce, "candidate"
                )
            wrong_nonce.close()
            workspace.close()

    def test_journal_authorization_hash_binds_closed_material(self) -> None:
        first = self._first(
            operation="activation",
            attempt="transient-material",
            nonce="nonce-transient-material",
        )
        prior = history_to(first, "prior_start_authorized")[-1]
        validated = validate_deployment_journal(prior)
        start = validated["transient_start"][0]
        material = persistence_module._transient_start_authorization_material(
            validated, start
        )
        self.assertEqual(
            {
                "schema_version",
                "scope",
                "attempt",
                "nonce",
                "operation",
                "authorization_phase",
                "role",
                "release",
                "start_nonce",
                "scm_identity_sha256",
                "state_identity_sha256",
            },
            set(material),
        )
        self.assertEqual("prior_start_authorized", material["authorization_phase"])
        self.assertEqual(
            identity.identity_sha256(material),
            validated["evidence_hashes"]["prior_start_authorization_sha256"],
        )

        for mutate in (
            lambda value: value["evidence_hashes"].__setitem__(
                "prior_start_authorization_sha256", "e" * 64
            ),
            lambda value: value["transient_start"][0].__setitem__(
                "start_nonce", "changed-start-nonce"
            ),
            lambda value: value["transient_start"][0].__setitem__(
                "scm_identity_sha256", "e" * 64
            ),
            lambda value: value["state_plan"].__setitem__(
                "state_identity_sha256", "e" * 64
            ),
        ):
            forged = deepcopy(prior)
            mutate(forged)
            seal(forged, "journal_sha256")
            with self.subTest(mutate=mutate), self.assertRaisesRegex(
                DeploymentJournalError, "authorization"
            ):
                validate_deployment_journal(forged)

    def _legacy_pythonservice_failure_histories(
        self,
        *,
        attempt: str,
        nonce: str,
    ) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
        first = self._first(
            operation="activation",
            attempt=attempt,
            nonce=nonce,
        )
        history = history_to(first, "candidate_start_authorized")
        receipt = failure_receipt(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            attempt=attempt,
            failed_phase="candidate_start_authorized",
        )
        history.append(
            advance_one(
                history[-1],
                receipt=receipt,
                failure=True,
            )
        )
        legacy_history: list[dict[str, object]] = []
        for raw in history:
            journal = deepcopy(raw)
            journal["previous_journal_sha256"] = (
                None
                if not legacy_history
                else legacy_history[-1]["journal_sha256"]
            )
            for start in journal["transient_start"]:
                start["scm_identity_sha256"] = (
                    persistence_module._legacy_transient_scm_start_plan_sha256(
                        journal, start
                    )
                )
                field = (
                    persistence_module._transient_start_authorization_evidence_field(
                        start["role"]
                    )
                )
                journal["evidence_hashes"][field] = (
                    persistence_module._transient_start_authorization_sha256(
                        journal, start
                    )
                )
            seal(journal, "journal_sha256")
            legacy_history.append(journal)
        return history, legacy_history

    def test_store_replays_only_failure_closed_legacy_pythonservice_history(self) -> None:
        _current_history, legacy_history = (
            self._legacy_pythonservice_failure_histories(
                attempt="transient-legacy-pythonservice",
                nonce="nonce-transient-legacy-pythonservice",
            )
        )

        with self.assertRaisesRegex(
            DeploymentJournalError,
            "SCM start plan hash",
        ):
            validate_journal_history(legacy_history)
        with self.assertRaisesRegex(
            DeploymentJournalError,
            "failure-closed",
        ):
            validate_journal_history(
                legacy_history[:-1],
                _allow_legacy_scm_plan=True,
            )

        for journal in legacy_history:
            target = self.persistence.layout.journals / (
                f"{journal['attempt']}.r{int(journal['revision']):020d}.json"
            )
            target.write_bytes(identity.canonical_bytes(journal))
        self.assertEqual(
            tuple(legacy_history),
            self.persistence.journals.replay(
                "transient-legacy-pythonservice"
            ),
        )

    def test_failure_closed_mixed_scm_generations_are_rejected(self) -> None:
        current_history, _legacy_history = (
            self._legacy_pythonservice_failure_histories(
                attempt="transient-mixed-pythonservice",
                nonce="nonce-transient-mixed-pythonservice",
            )
        )
        mixed_history: list[dict[str, object]] = []
        for raw in current_history:
            journal = deepcopy(raw)
            journal["previous_journal_sha256"] = (
                None
                if not mixed_history
                else mixed_history[-1]["journal_sha256"]
            )
            for start in journal["transient_start"]:
                if start["role"] == "prior":
                    start["scm_identity_sha256"] = (
                        persistence_module._legacy_transient_scm_start_plan_sha256(
                            journal, start
                        )
                    )
                else:
                    start["scm_identity_sha256"] = (
                        persistence_module._transient_scm_start_plan_sha256(
                            journal, start
                        )
                    )
                field = (
                    persistence_module._transient_start_authorization_evidence_field(
                        start["role"]
                    )
                )
                journal["evidence_hashes"][field] = (
                    persistence_module._transient_start_authorization_sha256(
                        journal, start
                    )
                )
            seal(journal, "journal_sha256")
            mixed_history.append(journal)

        with self.assertRaisesRegex(DeploymentJournalError, "failure-closed"):
            validate_journal_history(
                mixed_history,
                _allow_legacy_scm_plan=True,
            )
        for journal in mixed_history:
            target = self.persistence.layout.journals / (
                f"{journal['attempt']}.r{int(journal['revision']):020d}.json"
            )
            target.write_bytes(identity.canonical_bytes(journal))
        with self.assertRaisesRegex(DeploymentJournalError, "failure-closed"):
            self.persistence.journals.replay("transient-mixed-pythonservice")

    def test_legacy_failure_history_rejects_same_and_next_revision_append(self) -> None:
        current_history, legacy_history = (
            self._legacy_pythonservice_failure_histories(
                attempt="transient-legacy-no-append",
                nonce="nonce-transient-legacy-no-append",
            )
        )
        for journal in legacy_history:
            target = self.persistence.layout.journals / (
                f"{journal['attempt']}.r{int(journal['revision']):020d}.json"
            )
            target.write_bytes(identity.canonical_bytes(journal))

        same_revision = current_history[-1]
        validate_deployment_journal(same_revision)
        next_revision = history_to(
            current_history[0], "binding_cas_committed"
        )[-1]
        next_revision["previous_journal_sha256"] = legacy_history[-1][
            "journal_sha256"
        ]
        seal(next_revision, "journal_sha256")
        validate_deployment_journal(next_revision)

        with self.persistence.global_lock() as lock:
            with self.assertRaisesRegex(DeploymentJournalError, "第三值"):
                self.persistence.journals.append(same_revision, lock=lock)
            with self.assertRaisesRegex(
                DeploymentJournalError,
                "SCM start plan hash",
            ):
                self.persistence.journals.append(next_revision, lock=lock)

    def test_multiple_role_records_are_rejected_by_journal_and_facade(self) -> None:
        first = self._first(
            operation="activation",
            attempt="transient-duplicate",
            nonce="nonce-transient-duplicate",
        )
        prior = history_to(first, "prior_start_authorized")[-1]
        duplicate = deepcopy(prior)
        duplicate_start = {
            "role": "prior",
            "release": release_ref(self.r_minus_1),
            "start_nonce": "duplicate-prior-nonce",
        }
        duplicate_start["scm_identity_sha256"] = (
            persistence_module._transient_scm_start_plan_sha256(
                duplicate, duplicate_start
            )
        )
        duplicate["transient_start"].insert(0, duplicate_start)
        seal(duplicate, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "每个 role"):
            validate_deployment_journal(duplicate)

        self.append_history(history_to(first, "prior_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "transient-duplicate", "nonce-transient-duplicate"
            )
            with patch.object(
                self.persistence.journals,
                "replay",
                return_value=(duplicate,),
            ), self.assertRaisesRegex(DeploymentJournalError, "唯一"):
                self.persistence.lock_exact_transient_start_authorization(
                    lock, workspace, "prior"
                )
            workspace.close()

    def test_rollback_start_nonce_collision_is_rejected_after_resigning(self) -> None:
        first = self._first(
            operation="rollback",
            attempt="transient-rollback-nonce-collision",
            nonce="nonce-transient-rollback-nonce-collision",
        )
        history = history_to(first, "candidate_start_authorized")
        forged = deepcopy(history[-1])
        prior = next(
            item for item in forged["transient_start"] if item["role"] == "prior"
        )
        candidate = next(
            item
            for item in forged["transient_start"]
            if item["role"] == "candidate"
        )
        candidate["start_nonce"] = prior["start_nonce"]
        candidate["scm_identity_sha256"] = (
            persistence_module._transient_scm_start_plan_sha256(forged, candidate)
        )
        forged["evidence_hashes"]["candidate_start_authorization_sha256"] = (
            persistence_module._transient_start_authorization_sha256(
                forged, candidate
            )
        )
        seal(forged, "journal_sha256")

        with self.assertRaisesRegex(DeploymentJournalError, "start_nonce"):
            validate_deployment_journal(forged)
        with self.assertRaisesRegex(DeploymentJournalError, "start_nonce"):
            validate_journal_history((*history[:-1], forged))

    def test_foreign_closed_stale_and_terminal_authority_are_rejected(self) -> None:
        first = self._first(
            operation="activation",
            attempt="transient-lifecycle",
            nonce="nonce-transient-lifecycle",
        )
        history = history_to(first, "candidate_start_authorized")
        self.append_history(history)
        foreign = LocalDeploymentPersistence.for_test_only(
            self.root, allow_posix_test_only=True
        )
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "transient-lifecycle", "nonce-transient-lifecycle"
            )
            with self.assertRaises(DeploymentLockBusy):
                foreign.lock_exact_transient_start_authorization(
                    lock, workspace, "candidate"
                )
            authorization = (
                self.persistence.lock_exact_transient_start_authorization(
                    lock, workspace, "candidate"
                )
            )
            workspace.close()
            with self.assertRaises((UnsafeLocalPath, DeploymentLockBusy)):
                self.persistence.lock_exact_transient_start_authorization(
                    lock, workspace, "candidate"
                )
        with self.persistence.global_lock():
            with self.assertRaises((UnsafeLocalPath, DeploymentLockBusy)):
                _ = authorization.role

        terminal_first = self._first(
            operation="activation",
            attempt="transient-terminal",
            nonce="nonce-transient-terminal",
        )
        terminal_receipt = transition_receipt(
            self.r1, self.r0, attempt="transient-terminal"
        )
        terminal_history = history_to(
            terminal_first,
            "terminal_receipt_committed",
            receipt=terminal_receipt,
        )
        self.append_history(terminal_history)
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "transient-terminal", "nonce-transient-terminal"
            )
            with self.assertRaisesRegex(DeploymentJournalError, "terminal"):
                self.persistence.lock_exact_transient_start_authorization(
                    lock, workspace, "candidate"
                )
            workspace.close()

    def test_every_property_replays_and_journal_advance_or_record_drift_revokes(self) -> None:
        first = self._first(
            operation="activation",
            attempt="transient-replay",
            nonce="nonce-transient-replay",
        )
        history = history_to(first, "candidate_start_authorized")
        self.append_history(history)
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "transient-replay", "nonce-transient-replay"
            )
            authorization = (
                self.persistence.lock_exact_transient_start_authorization(
                    lock, workspace, "candidate"
                )
            )
            public_reads = (
                lambda: authorization.scope,
                lambda: authorization.operation,
                lambda: authorization.phase,
                lambda: authorization.attempt_id,
                lambda: authorization.nonce,
                lambda: authorization.role,
                lambda: authorization.start_nonce,
                lambda: authorization.scm_identity_sha256,
                lambda: authorization.state_identity_sha256,
                lambda: authorization.authorization_sha256,
                lambda: authorization.release_ref,
            )
            real_replay = self.persistence.journals.replay
            with patch.object(
                self.persistence.journals,
                "replay",
                wraps=real_replay,
            ) as replay:
                for read in public_reads:
                    read()
                self.assertEqual(len(public_reads), replay.call_count)

            forged = deepcopy(history[-1])
            next(
                item
                for item in forged["transient_start"]
                if item["role"] == "candidate"
            )["start_nonce"] = "record-drift"
            with patch.object(
                self.persistence.journals,
                "replay",
                return_value=(forged,),
            ), self.assertRaisesRegex(DeploymentJournalError, "material|漂移"):
                _ = authorization.release_ref

            advanced = advance_one(history[-1])
            with patch.object(
                self.persistence.journals,
                "replay",
                return_value=(*history, advanced),
            ):
                for read in public_reads:
                    with self.subTest(read=read), self.assertRaisesRegex(
                        DeploymentJournalError, "撤销"
                    ):
                        read()
            terminal_history = history_to(
                first,
                "terminal_receipt_committed",
                receipt=transition_receipt(
                    self.r1, self.r0, attempt="transient-replay"
                ),
            )
            with patch.object(
                self.persistence.journals,
                "replay",
                return_value=terminal_history,
            ), self.assertRaisesRegex(DeploymentJournalError, "terminal"):
                _ = authorization.authorization_sha256
            workspace.close()

    def test_capability_is_nonserializable_clone_isolated_and_has_no_document_surface(self) -> None:
        first = self._first(
            operation="bootstrap_first_pair",
            attempt="transient-surface",
            nonce="nonce-transient-surface",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "transient-surface", "nonce-transient-surface"
            )
            authorization = (
                self.persistence.lock_exact_transient_start_authorization(
                    lock, workspace, "baseline"
                )
            )
            with self.assertRaises(TypeError):
                pickle.dumps(authorization)
            with self.assertRaises(TypeError):
                class ForgedAuthorization(  # type: ignore[misc]
                    LockedExactTransientStartAuthorization
                ):
                    pass
            with self.assertRaises(TypeError):
                vars(authorization)
            for name in (
                "as_dict",
                "document",
                "path",
                "root",
                "raw_token",
                "handle",
                "fd",
                "connection",
            ):
                self.assertFalse(hasattr(authorization, name), name)
            first_clone = authorization.release_ref
            first_clone["release_id"] = "mutated"
            self.assertEqual("release-r0", authorization.release_ref["release_id"])
            self.assertNotIn("release-r0", repr(authorization))
            workspace.close()

    @staticmethod
    def _canonical_sqlite_main_bytes(database: str) -> bytes:
        connection = sqlite3.connect(":memory:", isolation_level=None)
        try:
            connection.execute(
                "CREATE TABLE canary_probe(id INTEGER PRIMARY KEY,value TEXT NOT NULL) STRICT"
            )
            connection.execute(
                "INSERT INTO canary_probe VALUES(1,?)", (database,)
            )
            connection.execute("VACUUM")
            raw = connection.serialize()
        finally:
            connection.close()
        assert raw[:16] == b"SQLite format 3\x00"
        assert raw[18:20] == b"\x01\x01"
        return raw

    def test_mutable_canary_creator_is_pretracked_and_supports_two_live_mains(self) -> None:
        attempt = "mutable-canary-live"
        nonce = "nonce-mutable-canary-live"
        first = self._first(operation="activation", attempt=attempt, nonce=nonce)
        self.append_history(history_to(first, "candidate_start_authorized"))
        self.assertEqual(
            {"self", "lock", "workspace", "authorization"},
            set(
                inspect.signature(
                    LocalDeploymentPersistence.prepare_runtime_canary_layout
                ).parameters
            ),
        )
        self.assertEqual(
            {"self", "lock", "workspace", "database", "canonical_main_bytes"},
            set(
                inspect.signature(
                    LocalDeploymentPersistence.create_mutable_canary_sqlite
                ).parameters
            ),
        )
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            self.persistence.prepare_runtime_canary_layout(
                lock, workspace, authorization
            )
            comments_raw = self._canonical_sqlite_main_bytes("comments")
            workspace_raw = self._canonical_sqlite_main_bytes("research_workspace")
            capture_name = (
                "_capture_windows_creator"
                if os.name == "nt"
                else "_capture_posix_creator"
            )
            real_capture = getattr(LockedMutableCanarySqliteSet, capture_name)
            observed_pretracking: list[bool] = []

            def capture(resource: LockedMutableCanarySqliteSet) -> None:
                observed_pretracking.append(
                    resource in resource._workspace._mutable_canary_sqlite_sets  # noqa: SLF001
                    and resource._state == "acquiring"  # noqa: SLF001
                    and resource._windows_handle is None  # noqa: SLF001
                    and resource._posix_descriptor is None  # noqa: SLF001
                )
                real_capture(resource)

            with patch.object(
                LockedMutableCanarySqliteSet, capture_name, new=capture
            ):
                comments = self.persistence.create_mutable_canary_sqlite(
                    lock, workspace, "comments", comments_raw
                )
                research_workspace = self.persistence.create_mutable_canary_sqlite(
                    lock, workspace, "research_workspace", workspace_raw
                )
            self.assertEqual([True, True], observed_pretracking)
            self.assertIs(type(comments), LockedMutableCanarySqliteSet)
            self.assertEqual(
                "mutable_canary_sqlite_open_instance_only", comments.scope
            )
            self.assertEqual("comments", comments.database)
            self.assertEqual(("main",), comments.members)
            self.assertEqual(hashlib.sha256(comments_raw).hexdigest(), comments.initial_main_sha256)
            self.assertEqual(comments_raw, comments.read_main_bytes())
            self.assertEqual(("main",), research_workspace.members)
            for name in (
                "path", "root", "handle", "fd", "descriptor", "as_dict",
                "document", "from_document", "from_mapping",
            ):
                self.assertFalse(hasattr(comments, name), name)
            with self.assertRaises(TypeError):
                pickle.dumps(comments)
            with self.assertRaises(TypeError):
                class ForgedMutableCanary(  # type: ignore[misc]
                    LockedMutableCanarySqliteSet
                ):
                    pass

            comments_path = self.workspace_path(attempt, nonce) / (
                "runtime-canary/candidate/state/comments.sqlite3"
            )
            with closing(sqlite3.connect(comments_path, isolation_level=None)) as writer:
                writer.execute("UPDATE canary_probe SET value='changed' WHERE id=1")
            comments.checkpoint_closed()
            self.assertNotEqual(comments_raw, comments.read_main_bytes())
            research_workspace.checkpoint_closed()

            with self.assertRaises(DeploymentLockBusy):
                self.persistence.create_mutable_canary_sqlite(
                    lock, workspace, "comments", comments_raw
                )
            research_workspace.close()
            comments.close()
            self.assertFalse(workspace._mutable_canary_sqlite_sets)  # noqa: SLF001
            workspace.close()

    def test_mutable_canary_rejects_injection_third_values_and_replacement(self) -> None:
        attempt = "mutable-canary-negative"
        nonce = "nonce-mutable-canary-negative"
        first = self._first(operation="activation", attempt=attempt, nonce=nonce)
        self.append_history(history_to(first, "candidate_start_authorized"))
        raw = self._canonical_sqlite_main_bytes("comments")
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            for fake in ({}, object(), object.__new__(LockedExactTransientStartAuthorization)):
                with self.subTest(fake=type(fake)), self.assertRaises(DeploymentLockBusy):
                    self.persistence.prepare_runtime_canary_layout(
                        lock, workspace, fake  # type: ignore[arg-type]
                    )
            self.persistence.prepare_runtime_canary_layout(
                lock, workspace, authorization
            )
            with self.assertRaisesRegex(DeploymentLockBusy, "已绑定"):
                self.persistence.prepare_runtime_canary_layout(
                    lock, workspace, authorization
                )
            for database, payload in (
                (True, raw),
                ("Comments", raw),
                ("comments", b"not-sqlite"),
                ("comments", bytearray(raw)),
            ):
                with self.subTest(database=database, payload=type(payload)), self.assertRaises(
                    (UnsafeLocalPath, TypeError)
                ):
                    self.persistence.create_mutable_canary_sqlite(
                        lock,
                        workspace,
                        database,  # type: ignore[arg-type]
                        payload,  # type: ignore[arg-type]
                    )
            for injected in (
                {"path": self.root}, {"root": self.root}, {"role": "candidate"},
                {"handle": 1}, {"runtime": object()}, {"hook": object()},
            ):
                with self.subTest(injected=tuple(injected)), self.assertRaises(TypeError):
                    self.persistence.create_mutable_canary_sqlite(  # type: ignore[call-arg]
                        lock, workspace, "comments", raw, **injected
                    )
            mutable = self.persistence.create_mutable_canary_sqlite(
                lock, workspace, "comments", raw
            )
            state = self.workspace_path(attempt, nonce) / (
                "runtime-canary/candidate/state"
            )
            (state / "comments.sqlite3-wal").write_bytes(b"third")
            with self.assertRaisesRegex(UnsafeLocalPath, "成员集合"):
                mutable.checkpoint_closed()
            (state / "comments.sqlite3-wal").unlink()
            original = state / "comments.sqlite3"
            moved = state / "original-held.sqlite3"
            try:
                original.rename(moved)
            except OSError:
                # Windows产品 handle 明确不共享delete，rename本身即机械拒绝。
                mutable.checkpoint_closed()
            else:
                original.write_bytes(raw)
                moved.unlink()
                with self.assertRaisesRegex(UnsafeLocalPath, "替换"):
                    mutable.checkpoint_closed()
            mutable.close()
            workspace.close()

    def test_mutable_canary_existing_main_fails_without_losing_tracking(self) -> None:
        attempt = "mutable-canary-existing"
        nonce = "nonce-mutable-canary-existing"
        first = self._first(operation="activation", attempt=attempt, nonce=nonce)
        self.append_history(history_to(first, "candidate_start_authorized"))
        raw = self._canonical_sqlite_main_bytes("comments")
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            self.persistence.prepare_runtime_canary_layout(
                lock, workspace, authorization
            )
            state = self.workspace_path(attempt, nonce) / (
                "runtime-canary/candidate/state"
            )
            (state / "comments.sqlite3").write_bytes(raw)
            with self.assertRaisesRegex(UnsafeLocalPath, "CREATE_NEW"):
                self.persistence.create_mutable_canary_sqlite(
                    lock, workspace, "comments", raw
                )
            self.assertFalse(workspace._mutable_canary_sqlite_sets)  # noqa: SLF001
            workspace.close()

    def test_mutable_canary_is_closed_before_lock_release_completes(self) -> None:
        attempt = "mutable-canary-lock-release"
        nonce = "nonce-mutable-canary-lock-release"
        first = self._first(operation="activation", attempt=attempt, nonce=nonce)
        self.append_history(history_to(first, "candidate_start_authorized"))
        raw = self._canonical_sqlite_main_bytes("comments")
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            self.persistence.prepare_runtime_canary_layout(
                lock, workspace, authorization
            )
            mutable = self.persistence.create_mutable_canary_sqlite(
                lock, workspace, "comments", raw
            )
            main = self.workspace_path(attempt, nonce) / (
                "runtime-canary/candidate/state/comments.sqlite3"
            )
            held = main.with_name("comments-held.sqlite3")
            if os.name == "nt":
                with self.assertRaises(OSError):
                    main.rename(held)
        self.assertEqual("closed", mutable._state)  # noqa: SLF001
        self.assertEqual("closed", workspace._state)  # noqa: SLF001
        main.rename(held)
        held.rename(main)


class ExactScmProcessObservationInputSeamTests(PersistenceFixture):
    def setUp(self) -> None:
        super().setUp()
        self.r_minus_1 = release(
            "release-r-minus-1",
            self.payloads["release-r-minus-1"],
            "8",
            include_migrations=True,
        )
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r1 = release(
            "release-r1",
            self.payloads["release-r1"],
            "a",
            include_migrations=True,
        )
        for document in (self.r_minus_1, self.r0, self.r1):
            self.materialize(document)

    def _first(
        self, *, operation: str, attempt: str, nonce: str
    ) -> dict[str, object]:
        if operation == "bootstrap_first_pair":
            return journal(
                None,
                self.r0,
                operation=operation,
                attempt=attempt,
                nonce=nonce,
            )
        return journal(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            operation=operation,
            attempt=attempt,
            nonce=nonce,
        )

    def test_activation_rollback_bootstrap_join_exact_release_and_plan(self) -> None:
        cases = (
            ("activation", "scm-join-activation", "nonce-scm-activation", "prior", "prior"),
            ("activation", "scm-join-candidate", "nonce-scm-candidate", "candidate", "candidate"),
            ("rollback", "scm-join-rollback-prior", "nonce-scm-rollback-prior", "prior", "candidate"),
            ("rollback", "scm-join-rollback-candidate", "nonce-scm-rollback-candidate", "candidate", "candidate"),
            ("bootstrap_first_pair", "scm-join-bootstrap", "nonce-scm-bootstrap", "baseline", "candidate"),
        )
        for operation, attempt, nonce, role, closure_role in cases:
            with self.subTest(operation=operation, role=role):
                first = self._first(
                    operation=operation, attempt=attempt, nonce=nonce
                )
                history = history_to(first, "candidate_start_authorized")
                self.append_history(history)
                latest = history[-1]
                with self.persistence.global_lock() as lock:
                    workspace = self.persistence.bind_attempt_workspace(
                        lock, attempt, nonce
                    )
                    closures = self.persistence.lock_exact_release_closures(
                        lock, workspace
                    )
                    authorization = (
                        self.persistence.lock_exact_transient_start_authorization(
                            lock, workspace, role
                        )
                    )
                    bound = self.persistence.bind_exact_scm_process_observation_input(
                        lock, workspace, authorization, closures
                    )
                    self.assertIs(type(bound), LockedExactScmProcessObservationInput)
                    self.assertEqual(
                        "exact_scm_process_observation_input_only", bound.scope
                    )
                    self.assertEqual((attempt, nonce, operation, role), (
                        bound.attempt_id, bound.nonce, bound.operation, bound.role
                    ))
                    self.assertEqual(closure_role, bound.closure_role)
                    self.assertEqual(authorization.release_ref, bound.release_ref)
                    start = next(
                        item
                        for item in latest["transient_start"]
                        if item["role"] == role
                    )
                    plan = persistence_module._transient_scm_start_plan_material(
                        latest, start
                    )
                    self.assertEqual(
                        {
                            "schema_version", "scope", "attempt", "nonce",
                            "operation", "role", "start_nonce",
                            "state_identity_sha256", "release", "service", "child",
                        },
                        set(plan),
                    )
                    self.assertNotIn("authorization_sha256", plan)
                    self.assertEqual(
                        persistence_module._transient_scm_start_plan_sha256(
                            latest, start
                        ),
                        bound.scm_identity_sha256,
                    )
                    self.assertEqual(
                        authorization.authorization_sha256,
                        bound.authorization_sha256,
                    )
                    self.assertEqual("QuantResearchHub", bound.service_name)
                    self.assertEqual(
                        ("exact-runtime", *bound.child_argv[9:]),
                        bound.service_start_arguments,
                    )
                    self.assertEqual(
                        r"D:\quant\quant_platform\tooling\python\python.exe",
                        bound.child_executable,
                    )
                    argv = bound.child_argv
                    self.assertEqual(bound.child_executable, argv[0])
                    for flag, expected in (
                        ("--deployment-attempt", attempt),
                        ("--deployment-nonce", nonce),
                        ("--deployment-operation", operation),
                        ("--deployment-role", role),
                        ("--start-nonce", bound.start_nonce),
                        ("--release-id", bound.release_ref["release_id"]),
                        ("--manifest-sha256", bound.release_ref["manifest_sha256"]),
                        ("--state-identity-sha256", bound.state_identity_sha256),
                    ):
                        index = argv.index(flag)
                        self.assertEqual(expected, argv[index + 1])
                    clone = bound.release_ref
                    clone["release_id"] = "mutated"
                    self.assertNotEqual("mutated", bound.release_ref["release_id"])
                    closures.close()
                    workspace.close()

    def test_factory_is_closed_and_rejects_fake_or_foreign_capabilities(self) -> None:
        self.assertEqual(
            {"self", "lock", "workspace", "authorization", "closures"},
            set(
                inspect.signature(
                    LocalDeploymentPersistence.bind_exact_scm_process_observation_input
                ).parameters
            ),
        )
        first = self._first(
            operation="activation",
            attempt="scm-join-closed",
            nonce="nonce-scm-join-closed",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        second = self._first(
            operation="activation",
            attempt="scm-join-foreign",
            nonce="nonce-scm-join-foreign",
        )
        self.append_history(history_to(second, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "scm-join-closed", "nonce-scm-join-closed"
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            foreign_workspace = self.persistence.bind_attempt_workspace(
                lock, "scm-join-foreign", "nonce-scm-join-foreign"
            )
            foreign_closures = self.persistence.lock_exact_release_closures(
                lock, foreign_workspace
            )
            foreign_authorization = (
                self.persistence.lock_exact_transient_start_authorization(
                    lock, foreign_workspace, "candidate"
                )
            )
            for fake_authorization, fake_closures in (
                ({}, closures),
                (authorization, {}),
                (object.__new__(LockedExactTransientStartAuthorization), closures),
                (authorization, object.__new__(LockedExactReleaseClosures)),
            ):
                with self.subTest(
                    fake_authorization=type(fake_authorization),
                    fake_closures=type(fake_closures),
                ), self.assertRaises(DeploymentLockBusy):
                    self.persistence.bind_exact_scm_process_observation_input(
                        lock,
                        workspace,
                        fake_authorization,  # type: ignore[arg-type]
                        fake_closures,  # type: ignore[arg-type]
                    )
            for mixed_authorization, mixed_closures in (
                (foreign_authorization, closures),
                (authorization, foreign_closures),
            ):
                with self.assertRaises(DeploymentLockBusy):
                    self.persistence.bind_exact_scm_process_observation_input(
                        lock,
                        workspace,
                        mixed_authorization,
                        mixed_closures,
                    )
            for injected in (
                {"root": self.root},
                {"path": self.root},
                {"service_name": "other"},
                {"pid": os.getpid()},
                {"argv": []},
                {"runtime": object()},
                {"hook": object()},
                {"env": {}},
            ):
                with self.subTest(injected=tuple(injected)), self.assertRaises(
                    TypeError
                ):
                    self.persistence.bind_exact_scm_process_observation_input(  # type: ignore[call-arg]
                        lock, workspace, authorization, closures, **injected
                    )
            foreign_closures.close()
            foreign_workspace.close()
            closures.close()
            workspace.close()

    def test_arbitrary_scm_hash_is_rejected_even_after_resigning(self) -> None:
        first = self._first(
            operation="activation",
            attempt="scm-plan-forged",
            nonce="nonce-scm-plan-forged",
        )
        history = history_to(first, "candidate_start_authorized")
        forged = deepcopy(history[-1])
        candidate = next(
            item
            for item in forged["transient_start"]
            if item["role"] == "candidate"
        )
        candidate["scm_identity_sha256"] = "e" * 64
        forged["evidence_hashes"]["candidate_start_authorization_sha256"] = (
            persistence_module._transient_start_authorization_sha256(
                forged, candidate
            )
        )
        seal(forged, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "SCM start plan"):
            validate_deployment_journal(forged)
        with self.assertRaisesRegex(DeploymentJournalError, "SCM start plan"):
            validate_journal_history((*history[:-1], forged))

    def test_bound_input_is_nonserializable_surface_closed_and_live_only(self) -> None:
        first = self._first(
            operation="activation",
            attempt="scm-join-lifecycle",
            nonce="nonce-scm-join-lifecycle",
        )
        history = history_to(first, "candidate_start_authorized")
        self.append_history(history)
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock, "scm-join-lifecycle", "nonce-scm-join-lifecycle"
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            bound = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            with self.assertRaises(TypeError):
                pickle.dumps(bound)
            with self.assertRaises(TypeError):
                vars(bound)
            with self.assertRaises(TypeError):
                class ForgedInput(  # type: ignore[misc]
                    LockedExactScmProcessObservationInput
                ):
                    pass
            for name in (
                "as_dict", "document", "path", "root", "raw_token",
                "handle", "fd", "connection", "writer_lease", "qualified",
            ):
                self.assertFalse(hasattr(bound, name), name)
            advanced = advance_one(history[-1])
            with patch.object(
                self.persistence.journals,
                "replay",
                return_value=(*history, advanced),
            ):
                for read in (
                    lambda: bound.scope,
                    lambda: bound.scm_identity_sha256,
                    lambda: bound.child_argv,
                    lambda: bound.release_ref,
                ):
                    with self.subTest(read=read), self.assertRaisesRegex(
                        DeploymentJournalError, "撤销"
                    ):
                        read()
            closures.close()
            workspace.close()

    @staticmethod
    def _populate_handle_tracking(
        tracking: LockedWindowsScmProcessHandleTracking,
        *,
        before_call: object | None = None,
    ) -> list[tuple[str, str, int]]:
        captured: list[tuple[str, str, int]] = []
        for index, (label, family) in enumerate(
            persistence_module._WINDOWS_SCM_PROCESS_HANDLE_SLOT_FAMILIES,
            start=101,
        ):
            def returned(
                value: int = index,
                current_label: str = label,
                current_family: str = family,
            ) -> int:
                if callable(before_call):
                    before_call(current_label, current_family)
                return value

            if (
                label
                in persistence_module._WINDOWS_SCM_PROCESS_REUSABLE_SNAPSHOT_SLOTS
            ):
                with patch.object(
                    persistence_module.CrashReleasedFileLock,
                    "_windows_duplicate_close_source_call",
                    return_value=True,
                ):
                    tracking._capture_reusable_snapshot_handle(
                        label, returned
                    )
                    tracking._release_reusable_snapshot_handle(label)
            else:
                tracking._capture_returned_handle(label, family, returned)
                captured.append((label, family, index))
        tracking._seal_acquisition()
        return captured

    def test_handle_tracking_is_registered_before_first_call_and_surface_closed(
        self,
    ) -> None:
        self.assertEqual(
            {"self", "lock", "workspace", "inputs"},
            set(
                inspect.signature(
                    LocalDeploymentPersistence.prepare_windows_scm_process_handle_tracking
                ).parameters
            ),
        )
        first = self._first(
            operation="activation",
            attempt="handle-tracking-registered",
            nonce="nonce-handle-tracking-registered",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "handle-tracking-registered",
                "nonce-handle-tracking-registered",
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            tracking = self.persistence.prepare_windows_scm_process_handle_tracking(
                lock, workspace, inputs
            )
            with self.assertRaisesRegex(DeploymentLockBusy, "只允许一个"):
                self.persistence.prepare_windows_scm_process_handle_tracking(
                    lock, workspace, inputs
                )
            with self.assertRaises(UnsafeLocalPath):
                tracking._seal_acquisition()
            with self.assertRaises(UnsafeLocalPath):
                tracking._capture_returned_handle(
                    "scm_manager", "kernel", lambda: 999
                )
            with self.assertRaisesRegex(UnsafeLocalPath, "固定枚举"):
                tracking._capture_returned_handle_for_states(
                    "scm_manager",
                    "scm",
                    lambda: 999,
                    (),
                    states={"live"},
                    prepared_phases={"prepared"},
                )
            with self.assertRaises(UnsafeLocalPath):
                _ = tracking.scope

            def before_call(_label: str, _family: str) -> None:
                self.assertIn(
                    tracking, workspace._windows_scm_process_handle_tracking
                )

            captured = self._populate_handle_tracking(
                tracking, before_call=before_call
            )
            with self.assertRaises(UnsafeLocalPath):
                tracking._capture_returned_handle(
                    "scm_manager", "scm", lambda: 999
                )
            self.assertEqual(
                "windows_scm_process_handle_tracking_only", tracking.scope
            )
            with self.assertRaises(TypeError):
                pickle.dumps(tracking)
            with self.assertRaises(TypeError):
                vars(tracking)
            with self.assertRaises(TypeError):
                class ForgedTracking(  # type: ignore[misc]
                    LockedWindowsScmProcessHandleTracking
                ):
                    pass
            for name in (
                "as_dict",
                "document",
                "handle",
                "handles",
                "raw_handle",
                "writer_lease",
                "qualified",
                "evidence",
            ):
                self.assertFalse(hasattr(tracking, name), name)
            closed: list[tuple[str, int]] = []

            def close_scm(handle: int) -> None:
                closed.append(("scm", handle))

            def close_registry(handle: int) -> None:
                closed.append(("registry", handle))

            def close_kernel(handle: int) -> bool:
                closed.append(("kernel", handle))
                return True

            with patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_windows_close_scm_handle_call",
                side_effect=close_scm,
            ), patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_windows_close_registry_handle_call",
                side_effect=close_registry,
            ), patch.object(
                persistence_module.CrashReleasedFileLock,
                "_windows_duplicate_close_source_call",
                side_effect=close_kernel,
            ):
                tracking.close()
            self.assertEqual(
                [(family, value) for _label, family, value in reversed(captured)],
                closed,
            )
            self.assertNotIn(
                tracking, workspace._windows_scm_process_handle_tracking
            )
            closures.close()
            workspace.close()

    def test_live_snapshot_slot_is_closed_before_reuse_and_invalid_is_retryable(
        self,
    ) -> None:
        first = self._first(
            operation="activation",
            attempt="handle-tracking-snapshot-reuse",
            nonce="nonce-handle-tracking-snapshot-reuse",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "handle-tracking-snapshot-reuse",
                "nonce-handle-tracking-snapshot-reuse",
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            tracking = self.persistence.prepare_windows_scm_process_handle_tracking(
                lock, workspace, inputs
            )
            self._populate_handle_tracking(tracking)
            closed: list[int] = []

            def close_snapshot(slot: object) -> None:
                closed.append(slot.value)  # type: ignore[attr-defined]
                slot.value = None  # type: ignore[attr-defined]
                slot.phase = "closed"  # type: ignore[attr-defined]

            with self.assertRaisesRegex(
                LocalDeploymentPersistenceError, "未返回有效"
            ):
                tracking._capture_reusable_snapshot_handle(
                    "snapshot_after", lambda: 0
                )
            slot = tracking._slot("snapshot_after", "kernel")
            self.assertEqual(
                ("reusable_prepared", None), (slot.phase, slot.value)
            )
            with patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_close_slot_owned",
                side_effect=close_snapshot,
            ):
                for value in (210, 211):
                    tracking._capture_reusable_snapshot_handle(
                        "snapshot_after", lambda current=value: current
                    )
                    self.assertEqual(
                        value,
                        tracking._borrow_handle("snapshot_after", "kernel"),
                    )
                    tracking._release_reusable_snapshot_handle(
                        "snapshot_after"
                    )
            self.assertEqual([210, 211], closed)
            self.assertEqual(
                ("reusable_prepared", None), (slot.phase, slot.value)
            )
            with patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_close_slot_owned",
                side_effect=lambda item: (
                    setattr(item, "value", None),
                    setattr(item, "phase", "closed"),
                ),
            ):
                tracking.close()
            closures.close()
            workspace.close()

    def test_known_absent_handle_can_close_partial_tracking_and_keep_workspace_live(
        self,
    ) -> None:
        first = self._first(
            operation="activation",
            attempt="handle-tracking-known-absent",
            nonce="nonce-handle-tracking-known-absent",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "handle-tracking-known-absent",
                "nonce-handle-tracking-known-absent",
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            tracking = self.persistence.prepare_windows_scm_process_handle_tracking(
                lock, workspace, inputs
            )
            tracking._capture_returned_handle(
                "scm_manager", "scm", lambda: 101
            )
            with self.assertRaisesRegex(
                LocalDeploymentPersistenceError, "未返回有效"
            ):
                tracking._capture_returned_handle(
                    "scm_service", "scm", lambda: 0
                )
            with patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_windows_close_scm_handle_call",
                return_value=None,
            ):
                tracking.close()
            workspace._assert_live()
            self.assertEqual(set(), workspace._windows_scm_process_handle_tracking)
            closures.close()
            workspace.close()

    @unittest.skipUnless(
        os.name == "nt", "pointer-width INVALID_HANDLE_VALUE 只在 Windows 验证"
    )
    def test_pointer_width_invalid_executable_and_snapshot_never_reach_close(
        self,
    ) -> None:
        import ctypes

        invalid = ctypes.c_void_p(-1).value
        self.assertIs(type(invalid), int)
        self.assertNotEqual(-1, invalid)
        for target in ("host_executable", "snapshot_before"):
            with self.subTest(target=target):
                attempt = f"handle-tracking-invalid-{target}"
                nonce = f"nonce-handle-tracking-invalid-{target}"
                first = self._first(
                    operation="activation", attempt=attempt, nonce=nonce
                )
                self.append_history(
                    history_to(first, "candidate_start_authorized")
                )
                with self.persistence.global_lock() as lock:
                    workspace = self.persistence.bind_attempt_workspace(
                        lock, attempt, nonce
                    )
                    closures = self.persistence.lock_exact_release_closures(
                        lock, workspace
                    )
                    authorization = (
                        self.persistence.lock_exact_transient_start_authorization(
                            lock, workspace, "candidate"
                        )
                    )
                    inputs = (
                        self.persistence.bind_exact_scm_process_observation_input(
                            lock, workspace, authorization, closures
                        )
                    )
                    tracking = (
                        self.persistence.prepare_windows_scm_process_handle_tracking(
                            lock, workspace, inputs
                        )
                    )
                    tracking._capture_returned_handle(
                        "scm_manager", "scm", lambda: 101
                    )
                    with self.assertRaisesRegex(
                        LocalDeploymentPersistenceError, "未返回有效"
                    ):
                        tracking._capture_returned_handle(
                            target, "kernel", lambda: invalid
                        )
                    target_slot = tracking._slot(target, "kernel")
                    self.assertEqual(
                        ("failed_without_handle", None),
                        (target_slot.phase, target_slot.value),
                    )
                    kernel_close: list[int] = []
                    with patch.object(
                        LockedWindowsScmProcessHandleTracking,
                        "_windows_close_scm_handle_call",
                        return_value=None,
                    ), patch.object(
                        persistence_module.CrashReleasedFileLock,
                        "_windows_duplicate_close_source_call",
                        side_effect=lambda handle: kernel_close.append(handle),
                    ):
                        tracking.close()
                    self.assertEqual([], kernel_close)
                    workspace._assert_live()
                    closures.close()
                    workspace.close()

    @unittest.skipUnless(
        os.name == "nt", "超位宽 HANDLE 整数域只在 Windows 验证"
    )
    def test_out_of_range_handle_retires_authority_until_owner_exit(
        self,
    ) -> None:
        import ctypes

        attempt = "handle-tracking-pointer-overflow"
        nonce = "nonce-handle-tracking-pointer-overflow"
        first = self._first(
            operation="activation", attempt=attempt, nonce=nonce
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        pointer_bits = ctypes.sizeof(ctypes.c_void_p) * 8
        overflow_values = (
            1 << pointer_bits,
            (1 << pointer_bits) + 1,
            (1 << (pointer_bits + 1)) - 1,
        )
        source_root = Path(__file__).resolve().parents[1] / "src"
        helper = (
            "import os,sys\n"
            "from pathlib import Path\n"
            "from unittest.mock import patch\n"
            "from quant_hub.ops.local_deployment_persistence import "
            "CrashReleasedFileLock,LocalDeploymentPersistence,"
            "LocalDeploymentPersistenceError\n"
            "p=LocalDeploymentPersistence.for_test_only(Path(sys.argv[1]).resolve(),"
            "allow_posix_test_only=True)\n"
            "lock=p.global_lock();lock.acquire()\n"
            "w=p.bind_attempt_workspace(lock,sys.argv[2],sys.argv[3])\n"
            "c=p.lock_exact_release_closures(lock,w)\n"
            "a=p.lock_exact_transient_start_authorization(lock,w,'candidate')\n"
            "i=p.bind_exact_scm_process_observation_input(lock,w,a,c)\n"
            "t=p.prepare_windows_scm_process_handle_tracking(lock,w,i)\n"
            "closed=[]\n"
            "with patch.object(CrashReleasedFileLock,"
            "'_windows_duplicate_close_source_call',"
            "side_effect=lambda handle:closed.append(handle)):\n"
            " try:t._capture_returned_handle(sys.argv[4],'kernel',"
            "lambda:int(sys.argv[5]))\n"
            " except LocalDeploymentPersistenceError:\n"
            "  slot=t._slot(sys.argv[4],'kernel')\n"
            "  print(t._state,lock._release_phase,"
            "all(item.value is None for item in t._slots),"
            "slot.phase,slot.value is None,len(closed),"
            "t in w._windows_scm_process_handle_tracking,flush=True)\n"
            "  if sys.argv[6]=='wait':sys.stdin.readline()\n"
            "  os._exit(0)\n"
            "os._exit(2)\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(source_root)
        probe_helper = (
            "import msvcrt,os,sys\n"
            "fd=os.open(sys.argv[1],os.O_RDWR)\n"
            "try:\n"
            " try:\n"
            "  os.lseek(fd,0,0);msvcrt.locking(fd,msvcrt.LK_NBLCK,1)\n"
            " except (OSError,BlockingIOError):print('BUSY')\n"
            " else:print('ACQUIRED')\n"
            "finally:os.close(fd)\n"
        )

        def probe_lock() -> str:
            return subprocess.check_output(
                [
                    sys.executable,
                    "-c",
                    probe_helper,
                    str(self.persistence.layout.deployment_lock),
                ],
                text=True,
                env=environment,
                timeout=15,
            ).strip()

        expected = "owner_crash_only owner_crash_only True retired True 0 True"
        interactive_case = True
        for target in (
            "host_executable",
            "child_executable",
            "snapshot_before",
            "snapshot_after",
        ):
            for value in overflow_values:
                with self.subTest(target=target, value=value):
                    command = [
                        sys.executable,
                        "-c",
                        helper,
                        str(self.root),
                        attempt,
                        nonce,
                        target,
                        str(value),
                        "wait" if interactive_case else "exit",
                    ]
                    if interactive_case:
                        process = subprocess.Popen(
                            command,
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                            env=environment,
                        )
                        assert process.stdout is not None
                        self.assertEqual(expected, process.stdout.readline().strip())
                        self.assertEqual("BUSY", probe_lock())
                        stdout, stderr = process.communicate("\n", timeout=60)
                        self.assertEqual(0, process.returncode, stderr)
                        self.assertEqual("", stdout.strip())
                        interactive_case = False
                    else:
                        result = subprocess.run(
                            command,
                            capture_output=True,
                            text=True,
                            env=environment,
                            timeout=60,
                            check=False,
                        )
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual(expected, result.stdout.strip())
                    self.assertEqual("ACQUIRED", probe_lock())

    def test_close_post_return_exception_cannot_restore_numeric_authority(
        self,
    ) -> None:
        first = self._first(
            operation="activation",
            attempt="handle-tracking-post-return",
            nonce="nonce-handle-tracking-post-return",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "handle-tracking-post-return",
                "nonce-handle-tracking-post-return",
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            tracking = self.persistence.prepare_windows_scm_process_handle_tracking(
                lock, workspace, inputs
            )
            self._populate_handle_tracking(tracking)
            original = tracking._close_slot_owned
            raised = False

            def close_then_raise(slot: object) -> None:
                nonlocal raised
                original(slot)  # type: ignore[arg-type]
                if not raised:
                    raised = True
                    raise RuntimeError("outer wrapper after state-owner commit")

            with patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_windows_close_scm_handle_call",
                return_value=None,
            ), patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_windows_close_registry_handle_call",
                return_value=None,
            ), patch.object(
                persistence_module.CrashReleasedFileLock,
                "_windows_duplicate_close_source_call",
                return_value=True,
            ), patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_close_slot_owned",
                side_effect=close_then_raise,
            ):
                tracking.close()
            self.assertTrue(raised)
            self.assertEqual("closed", tracking._state)
            self.assertTrue(all(slot.value is None for slot in tracking._slots))
            closures.close()
            workspace.close()

    def test_registry_out_handle_is_tracked_before_wrapper_exception_escapes(
        self,
    ) -> None:
        import ctypes
        from ctypes import wintypes

        first = self._first(
            operation="activation",
            attempt="handle-tracking-output-finally",
            nonce="nonce-handle-tracking-output-finally",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "handle-tracking-output-finally",
                "nonce-handle-tracking-output-finally",
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            tracking = self.persistence.prepare_windows_scm_process_handle_tracking(
                lock, workspace, inputs
            )
            tracking._capture_returned_handle(
                "scm_manager", "scm", lambda: 101
            )
            tracking._capture_returned_handle(
                "scm_service", "scm", lambda: 102
            )

            def output_then_raise(output: object) -> int:
                pointer = ctypes.cast(output, ctypes.POINTER(wintypes.HANDLE))
                pointer.contents.value = 103
                raise RuntimeError("wrapper after out parameter commit")

            with self.assertRaisesRegex(
                LocalDeploymentPersistenceError, "已登记"
            ):
                tracking._capture_registry_output_handle(
                    "python_class_registry", output_then_raise
                )
            registry = tracking._slot("python_class_registry", "registry")
            self.assertEqual(("returned", 103), (registry.phase, registry.value))
            self.assertIn(
                tracking, workspace._windows_scm_process_handle_tracking
            )
            with patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_windows_close_scm_handle_call",
                return_value=None,
            ), patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_windows_close_registry_handle_call",
                return_value=None,
            ):
                tracking.close()
            workspace._assert_live()
            closures.close()
            workspace.close()

    def test_workspace_auto_closes_tracking_before_release_closures(self) -> None:
        first = self._first(
            operation="activation",
            attempt="handle-tracking-auto-order",
            nonce="nonce-handle-tracking-auto-order",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "handle-tracking-auto-order",
                "nonce-handle-tracking-auto-order",
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            tracking = self.persistence.prepare_windows_scm_process_handle_tracking(
                lock, workspace, inputs
            )
            self._populate_handle_tracking(tracking)
            events: list[str] = []
            tracking_close = tracking._close_from_workspace
            closures_close = closures._close_from_workspace

            def close_tracking(**kwargs: object) -> None:
                events.append("tracking")
                tracking_close(**kwargs)

            def close_closures(**kwargs: object) -> None:
                events.append("closures")
                closures_close(**kwargs)

            def close_tracking_slot(slot: object) -> None:
                slot.value = None  # type: ignore[attr-defined]
                slot.phase = "closed"  # type: ignore[attr-defined]

            with patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_close_slot_owned",
                side_effect=close_tracking_slot,
            ), patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_close_from_workspace",
                side_effect=close_tracking,
            ), patch.object(
                LockedExactReleaseClosures,
                "_close_from_workspace",
                side_effect=close_closures,
            ):
                workspace.close()
            self.assertEqual(["tracking", "closures"], events)
            self.assertEqual("closed", tracking._state)
            self.assertEqual("closed", closures._state)

    @unittest.skipUnless(
        os.name == "nt", "真实 kernel handle close 只在 Windows 产品语义执行"
    )
    def test_tracking_closes_real_kernel_handles_with_round7_seam(self) -> None:
        import ctypes
        from ctypes import wintypes

        first = self._first(
            operation="activation",
            attempt="handle-tracking-real-kernel",
            nonce="nonce-handle-tracking-real-kernel",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateEventW.argtypes = (
            wintypes.LPVOID,
            wintypes.BOOL,
            wintypes.BOOL,
            wintypes.LPCWSTR,
        )
        kernel32.CreateEventW.restype = wintypes.HANDLE
        kernel32.GetHandleInformation.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        )
        kernel32.GetHandleInformation.restype = wintypes.BOOL
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "handle-tracking-real-kernel",
                "nonce-handle-tracking-real-kernel",
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            tracking = self.persistence.prepare_windows_scm_process_handle_tracking(
                lock, workspace, inputs
            )
            kernel_handles: list[int] = []
            for index, (label, family) in enumerate(
                persistence_module._WINDOWS_SCM_PROCESS_HANDLE_SLOT_FAMILIES,
                start=201,
            ):
                if family == "kernel":
                    if (
                        label
                        in persistence_module._WINDOWS_SCM_PROCESS_REUSABLE_SNAPSHOT_SLOTS
                    ):
                        tracking._capture_reusable_snapshot_handle(
                            label,
                            kernel32.CreateEventW,
                            None,
                            False,
                            False,
                            None,
                        )
                        kernel_handles.append(
                            tracking._borrow_handle(label, family)
                        )
                        tracking._release_reusable_snapshot_handle(label)
                    else:
                        tracking._capture_returned_handle(
                            label,
                            family,
                            kernel32.CreateEventW,
                            None,
                            False,
                            False,
                            None,
                        )
                        kernel_handles.append(
                            tracking._borrow_handle(label, family)
                        )
                else:
                    tracking._capture_returned_handle(
                        label, family, lambda value=index: value
                    )
            tracking._seal_acquisition()
            with patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_windows_close_scm_handle_call",
                return_value=None,
            ), patch.object(
                LockedWindowsScmProcessHandleTracking,
                "_windows_close_registry_handle_call",
                return_value=None,
            ):
                tracking.close()
            flags = wintypes.DWORD()
            for handle in kernel_handles:
                with self.subTest(handle=handle):
                    ctypes.set_last_error(0)
                    self.assertFalse(
                        kernel32.GetHandleInformation(handle, ctypes.byref(flags))
                    )
                    self.assertEqual(6, ctypes.get_last_error())
            closures.close()
            workspace.close()

    def test_prepare_rejects_fake_closed_and_injected_inputs(self) -> None:
        first = self._first(
            operation="activation",
            attempt="handle-tracking-closed",
            nonce="nonce-handle-tracking-closed",
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                "handle-tracking-closed",
                "nonce-handle-tracking-closed",
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            inputs = self.persistence.bind_exact_scm_process_observation_input(
                lock, workspace, authorization, closures
            )
            for fake in (
                {},
                object(),
                object.__new__(LockedExactScmProcessObservationInput),
            ):
                with self.subTest(fake=type(fake)), self.assertRaises(
                    DeploymentLockBusy
                ):
                    self.persistence.prepare_windows_scm_process_handle_tracking(
                        lock, workspace, fake  # type: ignore[arg-type]
                    )
            for injected in (
                {"service_name": "other"},
                {"pid": 1},
                {"path": self.root},
                {"api": object()},
                {"hook": object()},
                {"runtime": object()},
            ):
                with self.subTest(injected=tuple(injected)), self.assertRaises(
                    TypeError
                ):
                    self.persistence.prepare_windows_scm_process_handle_tracking(  # type: ignore[call-arg]
                        lock, workspace, inputs, **injected
                    )
            closures.close()
            with self.assertRaises(UnsafeLocalPath):
                self.persistence.prepare_windows_scm_process_handle_tracking(
                    lock, workspace, inputs
                )
            workspace.close()

    def test_unknown_close_outcome_retires_all_until_owner_process_exit(
        self,
    ) -> None:
        attempt = "handle-tracking-owner-crash"
        nonce = "nonce-handle-tracking-owner-crash"
        first = self._first(
            operation="activation", attempt=attempt, nonce=nonce
        )
        self.append_history(history_to(first, "candidate_start_authorized"))
        source_root = Path(__file__).resolve().parents[1] / "src"
        helper = (
            "import os,sys\n"
            "from pathlib import Path\n"
            "from unittest.mock import patch\n"
            "from quant_hub.ops.local_deployment_persistence import "
            "LocalDeploymentPersistence,LockedWindowsScmProcessHandleTracking,"
            "LocalDeploymentPersistenceError\n"
            "p=LocalDeploymentPersistence.for_test_only(Path(sys.argv[1]).resolve(),"
            "allow_posix_test_only=True)\n"
            "lock=p.global_lock();lock.acquire()\n"
            "w=p.bind_attempt_workspace(lock,sys.argv[2],sys.argv[3])\n"
            "c=p.lock_exact_release_closures(lock,w)\n"
            "a=p.lock_exact_transient_start_authorization(lock,w,'candidate')\n"
            "i=p.bind_exact_scm_process_observation_input(lock,w,a,c)\n"
            "t=p.prepare_windows_scm_process_handle_tracking(lock,w,i)\n"
            "slots=(('scm_manager','scm'),('scm_service','scm'),"
            "('python_class_registry','registry'),('host_process','kernel'),"
            "('host_executable','kernel'),('snapshot_before','kernel'),"
            "('child_process','kernel'),('child_executable','kernel'),"
            "('snapshot_after','kernel'))\n"
            "for n,(label,family) in enumerate(slots,101):\n"
            " if label.startswith('snapshot'):\n"
            "  with patch.object(LockedWindowsScmProcessHandleTracking,"
            "'_close_slot_owned',side_effect=lambda s:(setattr(s,'value',None),"
            "setattr(s,'phase','closed'))):\n"
            "   t._capture_reusable_snapshot_handle(label,lambda v=n:v)\n"
            "   t._release_reusable_snapshot_handle(label)\n"
            " else:t._capture_returned_handle(label,family,lambda v=n:v)\n"
            "t._seal_acquisition()\n"
            "if sys.argv[4]=='reusable':\n"
            " t._capture_reusable_snapshot_handle('snapshot_after',lambda:210)\n"
            "with patch.object(LockedWindowsScmProcessHandleTracking,"
            "'_close_slot_owned',side_effect=OSError('unknown')):\n"
            " try:\n"
            "  if sys.argv[4]=='reusable':\n"
            "   t._release_reusable_snapshot_handle('snapshot_after')\n"
            "  else:t.close()\n"
            " except LocalDeploymentPersistenceError:\n"
            "  print(t._state,lock._release_phase,"
            "all(s.value is None for s in t._slots),t in w._windows_scm_process_handle_tracking,flush=True)\n"
            "  os._exit(0)\n"
            "os._exit(2)\n"
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(source_root)
        for mode in ("final", "reusable"):
            with self.subTest(mode=mode):
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        helper,
                        str(self.root),
                        attempt,
                        nonce,
                        mode,
                    ],
                    capture_output=True,
                    text=True,
                    env=environment,
                    timeout=60,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual(
                    "owner_crash_only owner_crash_only True True",
                    result.stdout.strip(),
                )
                with self.persistence.global_lock():
                    pass


class JournalContractTests(PersistenceFixture):
    def test_revision_zero_is_intent_and_schema_rejects_boolean_qualification(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        validate_deployment_journal(first)
        candidate = deepcopy(first)
        candidate["started"] = True
        seal(candidate, "journal_sha256")
        with self.assertRaises(DeploymentJournalError):
            validate_deployment_journal(candidate)
        boolean_inside_closed_field = deepcopy(first)
        boolean_inside_closed_field["timestamps"]["updated_at"] = True
        seal(boolean_inside_closed_field, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "自报布尔"):
            validate_deployment_journal(boolean_inside_closed_field)
        wrong = deepcopy(first)
        wrong["phase"] = "root_preflight_verified"
        wrong["evidence_hashes"]["root_preflight_sha256"] = "a" * 64
        seal(wrong, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "revision 0"):
            validate_journal_history([wrong])

    def test_phase_must_not_skip_repeat_or_prefill_future_evidence(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        root = advance_one(first)
        validate_journal_history([first, root])
        repeated = deepcopy(root)
        repeated["revision"] = 2
        repeated["previous_journal_sha256"] = root["journal_sha256"]
        seal(repeated, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "逐阶段"):
            validate_journal_history([first, root, repeated])
        jumped = history_to(first, "state_expand_applied")[-1]
        with self.assertRaisesRegex(DeploymentJournalError, "revision|previous"):
            validate_journal_history([first, jumped])
        prefilled = deepcopy(first)
        prefilled["evidence_hashes"]["candidate_runtime_qualification_sha256"] = "a" * 64
        seal(prefilled, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "预填"):
            validate_deployment_journal(prefilled)

    def test_state_plan_and_database_seals_fail_closed(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        state = history_to(first, "state_expand_applied")[-1]
        validate_deployment_journal(state)
        missing = deepcopy(state)
        missing["database_seals"].pop()
        seal(missing, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "database_seals"):
            validate_deployment_journal(missing)
        extra = deepcopy(first)
        extra["state_plan"]["database_names"] = []
        seal(extra, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "非空"):
            validate_deployment_journal(extra)
        zero = deepcopy(first)
        zero["state_plan"]["expand_plan_sha256"] = "0" * 64
        seal(zero, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "SHA-256"):
            validate_deployment_journal(zero)

    def test_state_compatibility_evidence_plan_and_seals_are_exactly_bound(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        state = history_to(first, "state_expand_applied")[-1]
        validate_deployment_journal(state)

        arbitrary_evidence = deepcopy(state)
        arbitrary_evidence["evidence_hashes"][
            "state_compatibility_sha256"
        ] = "e" * 64
        seal(arbitrary_evidence, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "exact"):
            validate_deployment_journal(arbitrary_evidence)

        changed_plan = deepcopy(state)
        changed_plan["state_plan"]["compatibility_sha256"] = "e" * 64
        seal(changed_plan, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "exact|aggregate"):
            validate_deployment_journal(changed_plan)

        changed_seal = deepcopy(state)
        changed_seal["database_seals"][0][
            "compatibility_manifest_sha256"
        ] = "e" * 64
        seal(changed_seal, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "aggregate"):
            validate_deployment_journal(changed_seal)

        reordered = deepcopy(state)
        reordered["database_seals"].reverse()
        seal(reordered, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "排序"):
            validate_deployment_journal(reordered)

        extra = deepcopy(state)
        extra["database_seals"].append(
            {
                "name": "third",
                "seal_sha256": "a" * 64,
                "compatibility_manifest_sha256": "b" * 64,
            }
        )
        extra["database_seals"] = sorted(
            extra["database_seals"], key=lambda item: str(item["name"])
        )
        seal(extra, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "aggregate|database_seals"):
            validate_deployment_journal(extra)

        failed_receipt = failure_receipt(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            attempt="attempt-1",
            failed_phase="state_expand_applied",
        )
        failed = advance_one(state, receipt=failed_receipt, failure=True)
        validate_deployment_journal(failed)
        forged_failure = deepcopy(failed)
        forged_failure["evidence_hashes"][
            "state_compatibility_sha256"
        ] = "e" * 64
        seal(forged_failure, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "exact"):
            validate_deployment_journal(forged_failure)

    def test_prior_and_candidate_start_authorization_are_exact(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        prior = history_to(first, "prior_start_authorized")[-1]
        validate_deployment_journal(prior)
        forged = deepcopy(prior)
        forged["transient_start"][0]["release"] = release_ref(self.r_minus_1)
        seal(forged, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "transient_start"):
            validate_deployment_journal(forged)

    def test_failure_terminal_requires_sealed_restoration_closure(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        receipt = failure_receipt(self.r0, self.r1, original_prior=self.r_minus_1, attempt="attempt-1")
        failed = advance_one(first, receipt=receipt, failure=True)
        validate_journal_history([first, failed])
        forged = deepcopy(failed)
        forged["evidence_hashes"]["failure_original_writer_fence_observation_sha256"] = None
        seal(forged, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "恢复闭包"):
            validate_deployment_journal(forged)

    def test_failure_terminal_binds_last_nonterminal_phase_for_every_operation(self) -> None:
        cases = (
            (
                "activation",
                journal(self.r0, self.r1, original_prior=self.r_minus_1),
                failure_receipt(
                    self.r0,
                    self.r1,
                    original_prior=self.r_minus_1,
                    attempt="attempt-1",
                    failed_phase="candidate_verified",
                ),
            ),
            (
                "bootstrap_first_pair",
                journal(
                    None,
                    self.r0,
                    operation="bootstrap_first_pair",
                    attempt="bootstrap-phase",
                    nonce="bootstrap-phase-nonce",
                ),
                failure_receipt(
                    None,
                    self.r0,
                    original_prior=None,
                    attempt="bootstrap-phase",
                    failed_phase="candidate_verified",
                ),
            ),
            (
                "rollback",
                journal(
                    self.r0,
                    self.r1,
                    original_prior=self.r_minus_1,
                    operation="rollback",
                    attempt="rollback-phase",
                    nonce="rollback-phase-nonce",
                ),
                failure_receipt(
                    self.r0,
                    self.r_minus_1,
                    original_prior=self.r_minus_1,
                    attempt="rollback-phase",
                    operation="rollback_to_prior",
                    failed_phase="candidate_verified",
                ),
            ),
        )
        for operation, first, receipt in cases:
            with self.subTest(operation=operation):
                history = history_to(first, "candidate_verified")
                failed = advance_one(history[-1], receipt=receipt, failure=True)
                validate_deployment_journal(failed)
                validate_journal_history([*history, failed])

                wrong_phase = deepcopy(failed)
                wrong_phase["terminal_receipt"][
                    "failed_phase"
                ] = "root_preflight_verified"
                seal(wrong_phase, "journal_sha256")
                with self.assertRaisesRegex(
                    DeploymentJournalError, "last legal non-terminal"
                ):
                    validate_deployment_journal(wrong_phase)

        rollback_wrong_operation = deepcopy(failed)
        rollback_wrong_operation["terminal_receipt"][
            "operation"
        ] = "activate_successor"
        seal(rollback_wrong_operation, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "operation"):
            validate_deployment_journal(rollback_wrong_operation)

    def test_failure_cannot_follow_a_success_terminal(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        terminal = transition_receipt(self.r1, self.r0, attempt="attempt-1")
        successful = history_to(
            first, "terminal_receipt_committed", receipt=terminal
        )[-1]
        failure = failure_receipt(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            attempt="attempt-1",
            failed_phase="terminal_receipt_committed",
        )
        impossible = advance_one(successful, receipt=failure, failure=True)
        with self.assertRaisesRegex(
            DeploymentJournalError, "legal non-terminal"
        ):
            validate_deployment_journal(impossible)

    def test_bootstrap_failure_preserves_absent_pointer_binding_service_writer(self) -> None:
        first = journal(
            None, self.r0, operation="bootstrap_first_pair",
            attempt="bootstrap-failure", nonce="bootstrap-failure-nonce",
        )
        receipt = failure_receipt(
            None, self.r0, original_prior=None, attempt="bootstrap-failure",
        )
        identity.validate_failure_receipt(receipt)
        failed = advance_one(first, receipt=receipt, failure=True)
        validate_journal_history([first, failed])
        evidence = receipt["restoration_evidence"]
        self.assertEqual("absent", evidence["original_active_pointer_observation"]["status"])
        self.assertEqual("d_writer_absent_or_fenced",
                         evidence["original_active_writer_fence_observation"]["status"])

    def test_windows_unsafe_attempt_nonce_and_filename_are_rejected(self) -> None:
        for identifier_value, field in (("CON", "attempt"), ("NUL.txt", "nonce"),
                                        ("COM1", "attempt"), ("LPT1.log", "nonce"), ("bad.", "attempt")):
            with self.subTest(value=identifier_value):
                candidate = journal(self.r0, self.r1, original_prior=self.r_minus_1)
                candidate[field] = identifier_value
                seal(candidate, "journal_sha256")
                with self.assertRaisesRegex(DeploymentJournalError, "稳定标识"):
                    validate_deployment_journal(candidate)
        unsafe_target = {
            "kind": "incoming",
            "path": r"D:\quant\quant_platform\incoming\CON\payload.bin",
            "payload_sha256": "a" * 64,
            "closure_sha256": "b" * 64,
        }
        candidate = journal(
            self.r0, self.r1, original_prior=self.r_minus_1,
            cleanup_targets=[unsafe_target],
        )
        with self.assertRaisesRegex(DeploymentJournalError, "Windows 不安全"):
            validate_deployment_journal(candidate)
        duplicate_a = {
            "kind": "incoming", "path": r"D:\quant\quant_platform\incoming\A.pkg",
            "payload_sha256": "a" * 64, "closure_sha256": "b" * 64,
        }
        duplicate_b = {
            "kind": "incoming", "path": r"D:\quant\quant_platform\incoming\a.pkg",
            "payload_sha256": "c" * 64, "closure_sha256": "d" * 64,
        }
        duplicate = journal(
            self.r0, self.r1, original_prior=self.r_minus_1,
            cleanup_targets=[duplicate_a, duplicate_b],
        )
        with self.assertRaisesRegex(DeploymentJournalError, "physical duplicate"):
            validate_deployment_journal(duplicate)
        wrong_root_case = deepcopy(duplicate_a)
        wrong_root_case["path"] = r"d:\quant\quant_platform\incoming\a.pkg"
        wrong_case = journal(
            self.r0, self.r1, original_prior=self.r_minus_1,
            cleanup_targets=[wrong_root_case],
        )
        with self.assertRaisesRegex(DeploymentJournalError, "canonical"):
            validate_deployment_journal(wrong_case)
        oversized = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        oversized["revision"] = 10**20
        seal(oversized, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "filename"):
            validate_deployment_journal(oversized)

    def test_bootstrap_absent_to_r0_has_no_binding_ingress_or_cleanup(self) -> None:
        first = journal(None, self.r0, operation="bootstrap_first_pair",
                        attempt="bootstrap-r0", nonce="bootstrap-nonce")
        receipt = bootstrap_receipt(self.r0, attempt="bootstrap-r0")
        history = history_to(first, "terminal_receipt_committed", receipt=receipt)
        validate_journal_history(history)
        self.assertIsNone(history[-1]["target_pair"]["prior"])
        forged = deepcopy(first)
        forged["cleanup_targets"] = [release_cleanup_target(self.r1)]
        seal(forged, "journal_sha256")
        with self.assertRaisesRegex(DeploymentJournalError, "bootstrap"):
            validate_deployment_journal(forged)

    def test_rollback_sequence_swaps_only_exact_active_prior(self) -> None:
        first = journal(
            self.r0, self.r1, original_prior=self.r_minus_1,
            operation="rollback", attempt="rollback-attempt", nonce="rollback-nonce",
        )
        receipt = transition_receipt(
            self.r_minus_1, self.r0, attempt="rollback-attempt", rollback=True,
        )
        history = history_to(first, "terminal_receipt_committed", receipt=receipt)
        validate_journal_history(history)
        self.assertEqual(pair(self.r_minus_1, self.r0), history[-1]["target_pair"])

    def test_store_replay_revision_chain_and_global_nonce(self) -> None:
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        root = advance_one(first)
        self.append_history([first, root])
        self.assertEqual((first, root), self.persistence.journals.replay("attempt-1"))
        reopened = LocalDeploymentPersistence.for_test_only(
            self.root, allow_posix_test_only=True
        )
        self.assertEqual((first, root), reopened.journals.replay("attempt-1"))
        conflicting = journal(self.r0, self.r2, original_prior=self.r_minus_1,
                              attempt="attempt-2", nonce="nonce-1")
        with self.persistence.global_lock() as lock, self.assertRaisesRegex(DeploymentJournalError, "nonce"):
            self.persistence.journals.append(conflicting, lock=lock)


class RetentionContractTests(PersistenceFixture):
    def materialize_exact_tooling(
        self,
    ) -> tooling_observer_module._TestOnlyExactRuntimeControllerToolingObserverAdapter:
        for _field, logical_name, relative in tooling_contract._BINARY_PATHS:
            path = self.root.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((logical_name + "-binary\n").encode("utf-8"))
        package = self.root.joinpath(
            *tooling_contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH.split("/")
        )
        for logical_name, relative in tooling_contract._KEY_FILES:
            path = package.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((logical_name + "\n").encode("utf-8"))
        (package / "app.py").write_bytes(b"application\n")
        tooling = TestOnlyExactRuntimeToolingAdapter.for_test_only(self.root)
        manifest = tooling.build_claim()
        manifest_path = self.root.joinpath(
            *EXACT_RUNTIME_TOOLING_MANIFEST_RELATIVE_PATH.split("/")
        )
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_bytes(manifest.canonical_bytes())
        return (
            tooling_observer_module._TestOnlyExactRuntimeControllerToolingObserverAdapter.for_test_only(
                self.root
            )
        )

    def materialize_steady_receipt_lineage(
        self,
        *,
        active_release: dict[str, object],
        prior_release: dict[str, object],
    ) -> tuple[dict[str, object], dict[str, object]]:
        bootstrap = bootstrap_receipt(
            prior_release, attempt="bootstrap-lineage"
        )
        bootstrap_intent = journal(
            None,
            prior_release,
            operation="bootstrap_first_pair",
            attempt="bootstrap-lineage",
            nonce="bootstrap-lineage-nonce",
        )
        activation_terminal = transition_receipt(
            active_release,
            prior_release,
            attempt="activation-lineage",
        )
        activation_intent = journal(
            prior_release,
            active_release,
            original_prior=None,
            attempt="activation-lineage",
            nonce="activation-lineage-nonce",
        )
        cleanup_terminal = cleanup_receipt(
            active_release,
            prior_release,
            [],
            attempt="activation-lineage",
        )
        self.append_history(
            history_to(
                bootstrap_intent,
                "terminal_receipt_committed",
                receipt=bootstrap,
            )
        )
        self.append_history(
            history_to(
                activation_intent,
                "cleanup_receipt_committed",
                receipt=activation_terminal,
                cleanup=cleanup_terminal,
            )
        )
        for receipt in (bootstrap, activation_terminal, cleanup_terminal):
            path = (
                self.persistence.layout.receipts
                / f"{receipt['receipt_id']}.json"
            )
            path.write_bytes(identity.canonical_bytes(receipt))
        return bootstrap, activation_terminal

    def test_steady_state_is_exact_active_plus_one_prior(self) -> None:
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        with self.persistence.global_lock() as lock:
            plan = self.persistence.plan_retention(lock=lock)
        self.assertEqual("release-r0", plan.active.release_id)
        assert plan.prior is not None
        self.assertEqual("release-r-minus-1", plan.prior.release_id)
        self.assertEqual((), plan.cleanup_targets)

    def test_steady_pair_static_facts_are_exact_tagged_and_not_authority(self) -> None:
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            facts = self.persistence.lock_steady_pair_static_facts(
                lock, workspace
            )
            self.assertIsInstance(facts, LockedSteadyPairStaticFacts)
            self.assertEqual(
                "steady_pair_static_facts_not_start_authorization",
                facts.scope,
            )
            self.assertEqual("steady_active", facts.authority_kind)
            self.assertEqual("steady_current", facts.runtime_state_kind)
            self.assertEqual(workspace.boot_nonce, facts.boot_nonce)
            self.assertRegex(facts.active_release_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(facts.binding_sha256, r"^[0-9a-f]{64}$")
            self.assertRegex(
                facts.retention_aggregate_sha256, r"^[0-9a-f]{64}$"
            )
            self.assertEqual(
                binding(self.r0, self.r_minus_1)["state_identity"][
                    "identity_sha256"
                ],
                facts.state_identity_sha256,
            )
            self.assertEqual(release_ref(self.r0), facts.release_ref)
            self.assertEqual(
                release_ref(self.r_minus_1), facts.prior_release_ref
            )
            for forbidden in (
                "start",
                "authorize",
                "observe",
                "admit",
                "journal",
                "attempt_id",
                "__dict__",
            ):
                self.assertFalse(hasattr(facts, forbidden), forbidden)
            with self.assertRaises(TypeError):
                pickle.dumps(facts)
            with self.assertRaises(TypeError):
                facts._material_raw = b"{}"
            workspace.close()
            with self.assertRaises(DeploymentLockBusy):
                _ = facts.scope

        with self.assertRaises(TypeError):
            class DerivedSteadyFacts(LockedSteadyPairStaticFacts):
                pass

    def test_steady_release_closures_bind_exact_active_prior_without_transient_api(
        self,
    ) -> None:
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r_minus_1 = release(
            "release-r-minus-1",
            self.payloads["release-r-minus-1"],
            "8",
            include_migrations=True,
        )
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            facts = self.persistence.lock_steady_pair_static_facts(
                lock, workspace
            )
            closures = self.persistence.lock_steady_release_closures(
                lock, workspace, facts
            )
            self.assertIsInstance(closures, LockedSteadyReleaseClosures)
            self.assertEqual(
                "steady_active_prior_release_closures_not_start_authorization",
                closures.scope,
            )
            self.assertEqual("steady_active", closures.authority_kind)
            self.assertEqual("steady_current", closures.runtime_state_kind)
            self.assertEqual(workspace.boot_nonce, closures.boot_nonce)
            self.assertEqual(("active", "prior"), closures.roles)
            metadata = closures.metadata()
            self.assertEqual(
                {"active", "prior"}, set(metadata["roles"])
            )
            self.assertEqual(
                self.r0, closures.read_manifest("active")
            )
            self.assertEqual(
                self.r_minus_1, closures.read_manifest("prior")
            )
            self.assertEqual(
                migration_bytes("release-r0", EXACT_MIGRATIONS[0]),
                closures.read_migration("active", EXACT_MIGRATIONS[0]),
            )
            closures.checkpoint_unchanged()
            for forbidden in (
                "attempt_id",
                "nonce",
                "operation",
                "journal",
                "start",
                "authorize",
                "observe",
                "admit",
                "__dict__",
            ):
                self.assertFalse(hasattr(closures, forbidden), forbidden)
            with self.assertRaises(TypeError):
                pickle.dumps(closures)
            with self.assertRaises(TypeError):
                closures._engine = None
            with self.assertRaises(DeploymentLockBusy):
                self.persistence.lock_steady_release_closures(
                    lock, workspace, facts
                )
        with self.assertRaises((DeploymentLockBusy, UnsafeLocalPath)):
            _ = closures.scope
        self.assertEqual("closed", closures._engine._state)

        with self.assertRaises(TypeError):
            class DerivedSteadyClosures(LockedSteadyReleaseClosures):
                pass

    def test_steady_release_closure_namespace_drift_revokes_capability(self) -> None:
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r_minus_1 = release(
            "release-r-minus-1",
            self.payloads["release-r-minus-1"],
            "8",
            include_migrations=True,
        )
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            facts = self.persistence.lock_steady_pair_static_facts(
                lock, workspace
            )
            closures = self.persistence.lock_steady_release_closures(
                lock, workspace, facts
            )
            extra = (
                self.persistence.layout.releases
                / "release-r0"
                / "unsealed-third-file.bin"
            )
            extra.write_bytes(b"third")
            with self.assertRaises(RetentionPlanningError):
                closures.checkpoint_unchanged()

    @unittest.skipUnless(os.name == "nt", "真实 Windows tooling closure 测试")
    def test_steady_tooling_observation_is_tagged_and_workspace_owned(self) -> None:
        adapter = self.materialize_exact_tooling()
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r_minus_1 = release(
            "release-r-minus-1",
            self.payloads["release-r-minus-1"],
            "8",
            include_migrations=True,
        )
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            facts = self.persistence.lock_steady_pair_static_facts(
                lock, workspace
            )
            closures = self.persistence.lock_steady_release_closures(
                lock, workspace, facts
            )
            live = adapter.observe_steady_test_only(
                workspace, facts, closures
            )
            self.assertIsInstance(
                live,
                tooling_observer_module.LockedSteadyExactRuntimeControllerToolingObservation,
            )
            evidence = live.build_evidence().as_dict()
            self.assertEqual(
                "qrh-exact-runtime-controller-tooling-observation/v2",
                evidence["schema_version"],
            )
            self.assertEqual(
                "steady_controller_tooling_live_observed_not_qualified",
                evidence["scope"],
            )
            self.assertEqual("steady_active", evidence["authority_kind"])
            self.assertEqual("steady_current", evidence["runtime_state_kind"])
            self.assertEqual(workspace.boot_nonce, evidence["boot_nonce"])
            self.assertEqual(facts.release_ref, evidence["release"])
            self.assertEqual(
                facts.retention_aggregate_sha256,
                evidence["retention_aggregate_sha256"],
            )
            self.assertRegex(
                str(evidence["tooling_sha256"]), r"^[0-9a-f]{64}$"
            )
            for forbidden in (
                "attempt_id",
                "nonce",
                "operation",
                "journal",
                "start",
                "authorize",
                "admit",
                "__dict__",
            ):
                self.assertFalse(hasattr(live, forbidden), forbidden)
            with self.assertRaises(TypeError):
                pickle.dumps(live)
            with self.assertRaises(TypeError):
                live._core = None
            with self.assertRaises(DeploymentLockBusy):
                adapter.observe_steady_test_only(
                    workspace, facts, closures
                )
        self.assertEqual("closed", live._state)
        with self.assertRaises(
            (
                DeploymentLockBusy,
                tooling_observer_module.ExactRuntimeControllerToolingObserverError,
            )
        ):
            live.build_evidence()

        with self.assertRaises(TypeError):
            class DerivedSteadyTooling(
                tooling_observer_module.LockedSteadyExactRuntimeControllerToolingObservation
            ):
                pass

    @unittest.skipUnless(os.name == "nt", "真实 Windows tooling closure 测试")
    def test_steady_tooling_add_delete_aba_revokes_and_closes(self) -> None:
        adapter = self.materialize_exact_tooling()
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r_minus_1 = release(
            "release-r-minus-1",
            self.payloads["release-r-minus-1"],
            "8",
            include_migrations=True,
        )
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            facts = self.persistence.lock_steady_pair_static_facts(
                lock, workspace
            )
            closures = self.persistence.lock_steady_release_closures(
                lock, workspace, facts
            )
            live = adapter.observe_steady_test_only(
                workspace, facts, closures
            )
            package = self.root.joinpath(
                *tooling_contract.EXACT_RUNTIME_PACKAGE_RELATIVE_PATH.split("/")
            )
            added = package / "steady-aba.py"
            added.write_bytes(b"temporary\n")
            added.unlink()
            with self.assertRaisesRegex(
                tooling_observer_module.ExactRuntimeControllerToolingObserverError,
                "checkpoint",
            ):
                live.build_evidence()

    @unittest.skipUnless(os.name == "nt", "真实 Windows tooling closure 前缀测试")
    def test_steady_receipt_lineage_pins_journal_bound_inventory_and_detects_aba(
        self,
    ) -> None:
        tooling_adapter = self.materialize_exact_tooling()
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r_minus_1 = release(
            "release-r-minus-1",
            self.payloads["release-r-minus-1"],
            "8",
            include_migrations=True,
        )
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        bootstrap, activation_terminal = self.materialize_steady_receipt_lineage(
            active_release=self.r0,
            prior_release=self.r_minus_1,
        )
        adapter = (
            receipt_lineage_module._TestOnlySteadyReceiptLineageObserverAdapter.for_test_only()
        )
        current_path = (
            self.persistence.layout.receipts
            / f"{activation_terminal['receipt_id']}.json"
        )
        current_raw = current_path.read_bytes()
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            facts = self.persistence.lock_steady_pair_static_facts(
                lock, workspace
            )
            closures = self.persistence.lock_steady_release_closures(
                lock, workspace, facts
            )
            tooling = tooling_adapter.observe_steady_test_only(
                workspace, facts, closures
            )

            current_path.unlink()
            with self.assertRaisesRegex(
                receipt_lineage_module.SteadyReceiptLineageError,
                "terminal receipt 缺失",
            ):
                adapter.observe_test_only(
                    workspace, facts, closures, tooling
                )
            current_path.write_bytes(current_raw)

            unreserved = deepcopy(bootstrap)
            unreserved["receipt_id"] = "activation-unreserved"
            unreserved["receipt_sha256"] = identity.identity_sha256(
                {
                    key: value
                    for key, value in unreserved.items()
                    if key != "receipt_sha256"
                }
            )
            unreserved_path = (
                self.persistence.layout.receipts
                / "activation-unreserved.json"
            )
            unreserved_path.write_bytes(identity.canonical_bytes(unreserved))
            with self.assertRaisesRegex(
                receipt_lineage_module.SteadyReceiptLineageError,
                "未被 durable journal 预留",
            ):
                adapter.observe_test_only(
                    workspace, facts, closures, tooling
                )
            unreserved_path.unlink()

            lineage = adapter.observe_test_only(
                workspace, facts, closures, tooling
            )
            evidence = lineage.build_evidence().as_dict()
            self.assertEqual(
                "steady_receipt_lineage_live_observed_not_start_authorization",
                evidence["scope"],
            )
            with self.assertRaises(OSError):
                current_path.write_bytes(current_raw + b"\n")
            aba = self.persistence.layout.receipts / "receipt-aba.json"
            aba.write_bytes(b"{}")
            aba.unlink()
            with self.assertRaises(
                receipt_lineage_module.SteadyReceiptLineageError
            ):
                lineage.build_evidence()

    @unittest.skipUnless(os.name == "nt", "真实 Windows tooling closure 前缀测试")
    def test_steady_legacy_c_prelaunch_fence_is_live_tagged_and_fail_closed(
        self,
    ) -> None:
        tooling_adapter = self.materialize_exact_tooling()
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r_minus_1 = release(
            "release-r-minus-1",
            self.payloads["release-r-minus-1"],
            "8",
            include_migrations=True,
        )
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        bootstrap, _activation_terminal = self.materialize_steady_receipt_lineage(
            active_release=self.r0,
            prior_release=self.r_minus_1,
        )
        absent = {
            "services": [
                {
                    "name": "LegacyQuantFixture",
                    "state": "Stopped",
                    "start_mode": "Disabled",
                    "path_name": r'"C:\quant_platform\legacy.exe" -I',
                }
            ],
            "processes": [],
            "listeners": [],
        }
        adapter = (
            legacy_c_fence_module._TestOnlySteadyLegacyCPrelaunchObserverAdapter.for_test_only(
                absent
            )
        )
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            facts = self.persistence.lock_steady_pair_static_facts(
                lock, workspace
            )
            closures = self.persistence.lock_steady_release_closures(
                lock, workspace, facts
            )
            tooling = tooling_adapter.observe_steady_test_only(
                workspace, facts, closures
            )
            lineage = (
                receipt_lineage_module._TestOnlySteadyReceiptLineageObserverAdapter.for_test_only().observe_test_only(
                    workspace, facts, closures, tooling
                )
            )
            lineage_evidence = lineage.build_evidence().as_dict()
            self.assertEqual(
                bootstrap["receipt_sha256"],
                lineage_evidence["bootstrap_receipt_sha256"],
            )
            self.assertEqual(1, lineage_evidence["current_pair_terminal_count"])
            self.assertEqual(
                3, lineage_evidence["receipt_inventory_count"]
            )
            self.assertRegex(
                str(
                    lineage_evidence[
                        "current_pair_terminal_aggregate_sha256"
                    ]
                ),
                r"^[0-9a-f]{64}$",
            )
            fence = adapter.observe_test_only(
                workspace, facts, closures, tooling, lineage
            )
            self.assertIsInstance(
                fence,
                legacy_c_fence_module.LockedSteadyLegacyCPrelaunchFence,
            )
            evidence = fence.build_evidence().as_dict()
            self.assertEqual(
                "qrh-steady-legacy-c-prelaunch-live-fence/v1",
                evidence["schema_version"],
            )
            self.assertEqual(
                "steady_legacy_c_prelaunch_live_fence_not_start_authorization",
                evidence["scope"],
            )
            self.assertEqual("steady_active", evidence["authority_kind"])
            self.assertEqual("steady_current", evidence["runtime_state_kind"])
            self.assertEqual(workspace.boot_nonce, evidence["boot_nonce"])
            self.assertRegex(
                str(evidence["legacy_c_live_fence_aggregate_sha256"]),
                r"^[0-9a-f]{64}$",
            )
            self.assertEqual(
                bootstrap["receipt_sha256"],
                evidence["bootstrap_receipt_sha256"],
            )
            self.assertEqual(
                lineage_evidence[
                    "current_pair_terminal_aggregate_sha256"
                ],
                evidence["current_pair_terminal_aggregate_sha256"],
            )
            legacy = evidence["legacy_c_live_fence"]
            self.assertEqual(0, legacy["legacy_process_count"])
            self.assertEqual([], legacy["listener_pids"])
            self.assertNotIn(
                "path_name", legacy["legacy_services"][0]
            )
            for forbidden in (
                "attempt_id",
                "nonce",
                "operation",
                "journal",
                "start",
                "authorize",
                "admit",
                "__dict__",
            ):
                self.assertFalse(hasattr(fence, forbidden), forbidden)
            with self.assertRaises(TypeError):
                pickle.dumps(fence)
            with self.assertRaises(TypeError):
                fence._backend = object()

            authorization = (
                steady_start_module._TestOnlyExactSteadyStartAuthorizerAdapter.for_test_only().authorize_test_only(
                    workspace,
                    facts,
                    closures,
                    tooling,
                    lineage,
                    fence,
                )
            )
            scm_input = (
                steady_start_module._TestOnlyExactSteadyStartAuthorizerAdapter.for_test_only().bind_scm_process_observation_input_test_only(
                    workspace,
                    authorization,
                    closures,
                )
            )
            self.assertIsInstance(
                authorization,
                steady_start_module.LockedExactSteadyStartAuthorization,
            )
            self.assertEqual(
                "exact_steady_start_authorization_input_only",
                authorization.scope,
            )
            self.assertEqual("steady_active", authorization.authority_kind)
            self.assertEqual("steady_current", authorization.runtime_state_kind)
            self.assertEqual(workspace.boot_nonce, authorization.boot_nonce)
            self.assertEqual(facts.release_ref, authorization.release_ref)
            self.assertEqual("QuantResearchHub", authorization.service_name)
            self.assertRegex(
                authorization.scm_identity_sha256, r"^[0-9a-f]{64}$"
            )
            self.assertRegex(
                authorization.authorization_sha256, r"^[0-9a-f]{64}$"
            )
            self.assertEqual(
                "steady-exact-runtime",
                authorization.service_start_arguments[0],
            )
            self.assertIn("--authority-kind", authorization.child_argv)
            self.assertIn("steady_active", authorization.child_argv)
            self.assertNotIn("--deployment-attempt", authorization.child_argv)
            self.assertNotIn("--deployment-nonce", authorization.child_argv)
            self.assertIsInstance(
                scm_input,
                steady_start_module.LockedExactSteadyScmProcessObservationInput,
            )
            self.assertEqual(
                "exact_steady_scm_process_observation_input_only",
                scm_input.scope,
            )
            self.assertEqual("steady_active", scm_input.authority_kind)
            self.assertEqual("steady_current", scm_input.runtime_state_kind)
            self.assertEqual(workspace.boot_nonce, scm_input.boot_nonce)
            self.assertEqual(
                authorization.authorization_sha256,
                scm_input.authorization_sha256,
            )
            self.assertEqual(
                authorization.scm_identity_sha256,
                scm_input.scm_identity_sha256,
            )
            self.assertEqual(authorization.release_ref, scm_input.release_ref)
            self.assertEqual(
                authorization.child_argv, scm_input.child_argv
            )
            for forbidden in (
                "attempt_id",
                "nonce",
                "operation",
                "role",
                "journal",
                "observe",
                "admit",
                "__dict__",
            ):
                self.assertFalse(hasattr(scm_input, forbidden), forbidden)
            with self.assertRaises(TypeError):
                pickle.dumps(scm_input)
            with self.assertRaises(TypeError):
                scm_input._plan_raw = b"{}"
            for forbidden in (
                "attempt_id",
                "nonce",
                "operation",
                "journal",
                "observe",
                "admit",
                "as_dict",
                "document",
                "__dict__",
            ):
                self.assertFalse(hasattr(authorization, forbidden), forbidden)
            with self.assertRaises(TypeError):
                pickle.dumps(authorization)
            with self.assertRaises(TypeError):
                authorization._plan_raw = b"{}"
            with self.assertRaises(DeploymentLockBusy):
                steady_start_module._TestOnlyExactSteadyStartAuthorizerAdapter.for_test_only().authorize_test_only(
                    workspace,
                    facts,
                    closures,
                    tooling,
                    lineage,
                    fence,
                )

            bad_process = deepcopy(absent)
            bad_process["processes"] = [
                {
                    "pid": 417,
                    "executable_path": r"C:\quant_platform\python.exe",
                    "command_line": r"C:\quant_platform\python.exe -I C:\quant_platform\tools\viewer\server.py",
                }
            ]
            adapter.replace(bad_process)
            with self.assertRaisesRegex(
                legacy_c_fence_module.SteadyLegacyCFenceError,
                "live process",
            ):
                fence.build_evidence()
            with self.assertRaisesRegex(
                legacy_c_fence_module.SteadyLegacyCFenceError,
                "live process",
            ):
                _ = authorization.scope
            with self.assertRaisesRegex(
                legacy_c_fence_module.SteadyLegacyCFenceError,
                "live process",
            ):
                _ = scm_input.scope
            adapter.replace(absent)
            self.assertEqual(
                "steady_legacy_c_prelaunch_live_fence_not_start_authorization",
                fence.scope,
            )
            self.assertEqual(
                "exact_steady_start_authorization_input_only",
                authorization.scope,
            )
            self.assertEqual(
                "exact_steady_scm_process_observation_input_only",
                scm_input.scope,
            )
        self.assertEqual("closed", fence._state)
        self.assertEqual("closed", authorization._state)

        with self.assertRaises(TypeError):
            class DerivedLegacyCFence(
                legacy_c_fence_module.LockedSteadyLegacyCPrelaunchFence
            ):
                pass

        with self.assertRaises(TypeError):
            class DerivedSteadyAuthorization(
                steady_start_module.LockedExactSteadyStartAuthorization
            ):
                pass

        with self.assertRaises(TypeError):
            class DerivedSteadyScmInput(
                steady_start_module.LockedExactSteadyScmProcessObservationInput
            ):
                pass

        self.assertEqual(
            [],
            list(
                inspect.signature(
                    legacy_c_fence_module.ProductionSteadyLegacyCPrelaunchObserver.load_exact_d
                ).parameters
            ),
        )

    def test_steady_pair_static_facts_reject_third_release_and_live_drift(self) -> None:
        for document in (self.r_minus_1, self.r0, self.r1):
            self.materialize(document)
        self.write_pair(self.r0, self.r_minus_1)
        with self.persistence.global_lock() as lock:
            workspace = self.persistence.bind_steady_boot_workspace(lock)
            with self.assertRaisesRegex(RetentionPlanningError, "steady inventory"):
                self.persistence.lock_steady_pair_static_facts(lock, workspace)
            shutil.rmtree(self.persistence.layout.releases / "release-r1")
            facts = self.persistence.lock_steady_pair_static_facts(
                lock, workspace
            )
            self.persistence.cas_active_release(
                lock=lock,
                expected=active(self.r0),
                desired=active(self.r_minus_1),
            )
            with self.assertRaisesRegex(
                RetentionPlanningError, "不一致|漂移"
            ):
                _ = facts.binding_sha256

    def test_live_pair_state_compatibility_is_revalidated_from_manifests(self) -> None:
        incompatible = deepcopy(self.r0)
        incompatible["state"]["compatibility"]["comments"] = {
            "read": [1], "write": [1],
        }
        self.r0 = incompatible
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        with self.persistence.global_lock() as lock, self.assertRaisesRegex(RetentionPlanningError, "graph"):
            self.persistence.plan_retention(lock=lock)

    def test_terminal_third_retained_release_is_blocked(self) -> None:
        for document in (self.r_minus_1, self.r0, self.r1):
            self.materialize(document)
        self.write_pair(self.r0, self.r_minus_1)
        with self.persistence.global_lock() as lock, self.assertRaisesRegex(RetentionPlanningError, "第三"):
            self.persistence.plan_retention(lock=lock)

    def test_multiple_active_attempts_are_blocked(self) -> None:
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        second = journal(
            self.r0, self.r2, original_prior=self.r_minus_1,
            attempt="attempt-2", nonce="nonce-2",
        )
        self.append_history([first])
        self.append_history([second])
        with self.persistence.global_lock() as lock, self.assertRaisesRegex(RetentionPlanningError, "多个"):
            self.persistence.plan_retention(lock=lock)

    def test_candidate_is_only_transient_before_pointer_commit(self) -> None:
        for document in (self.r_minus_1, self.r0, self.r1):
            self.materialize(document)
        self.write_pair(self.r0, self.r_minus_1)
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1,
                        cleanup_targets=[release_cleanup_target(self.r_minus_1)])
        self.append_history(history_to(first, "prior_verified"))
        with self.persistence.global_lock() as lock:
            plan = self.persistence.plan_retention(lock=lock)
        assert plan.transient is not None
        self.assertEqual("release-r1", plan.transient.release_id)
        self.assertEqual((), plan.cleanup_targets)

    def test_pointer_to_binding_window_protects_new_active_rollback_target_and_old_prior(self) -> None:
        for document in (self.r_minus_1, self.r0, self.r1):
            self.materialize(document)
        self.write_pair(self.r0, self.r_minus_1)
        first = journal(
            self.r0, self.r1, original_prior=self.r_minus_1,
            cleanup_targets=[release_cleanup_target(self.r_minus_1)],
        )
        self.append_history(history_to(first, "candidate_verified"))
        with self.persistence.global_lock() as lock:
            self.persistence.cas_active_release(
                lock=lock, expected=active(self.r0), desired=active(self.r1)
            )
            plan = self.persistence.plan_retention(lock=lock)
        self.assertEqual("release-r1", plan.active.release_id)
        assert plan.prior is not None and plan.transient is not None
        self.assertEqual("release-r0", plan.prior.release_id)
        self.assertEqual("release-r-minus-1", plan.transient.release_id)
        self.assertEqual((), plan.cleanup_targets)

    def post_activation_setup(self, phase: str) -> dict[str, object]:
        for document in (self.r_minus_1, self.r0, self.r1):
            self.materialize(document)
        self.write_pair(self.r1, self.r0)
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1,
                        cleanup_targets=[release_cleanup_target(self.r_minus_1)])
        receipt = transition_receipt(self.r1, self.r0, attempt="attempt-1")
        self.append_history(history_to(first, phase, receipt=receipt))
        return receipt

    def test_binding_cas_committed_returns_empty_without_receipt(self) -> None:
        self.post_activation_setup("binding_cas_committed")
        with self.persistence.global_lock() as lock:
            plan = self.persistence.plan_retention(lock=lock)
        self.assertEqual((), plan.cleanup_targets)

    def test_terminal_receipt_committed_still_returns_empty(self) -> None:
        receipt = self.post_activation_setup("terminal_receipt_committed")
        with self.persistence.global_lock() as lock:
            plan = self.persistence.plan_retention(lock=lock, receipts=[receipt])
        self.assertEqual((), plan.cleanup_targets)

    def test_cleanup_authorized_requires_exact_success_receipt(self) -> None:
        receipt = self.post_activation_setup("cleanup_authorized")
        with self.persistence.global_lock() as lock, self.assertRaisesRegex(RetentionPlanningError, "terminal receipt"):
            self.persistence.plan_retention(lock=lock)
        forged = deepcopy(receipt)
        forged["receipt_id"] = "activation-other"
        seal(forged, "receipt_sha256")
        with self.persistence.global_lock() as lock, self.assertRaises(RetentionPlanningError):
            self.persistence.plan_retention(lock=lock, receipts=[forged])
        with self.persistence.global_lock() as lock:
            plan = self.persistence.plan_retention(lock=lock, receipts=[receipt])
        self.assertEqual(1, len(plan.cleanup_targets))
        self.assertIsInstance(plan.cleanup_targets[0], ReleaseCleanupTargetPlan)

    def test_historical_receipt_is_validated_without_current_pair_equivalence(self) -> None:
        receipt = self.post_activation_setup("cleanup_authorized")
        old = transition_receipt(self.r0, self.r_minus_1, attempt="historical-attempt")
        with self.persistence.global_lock() as lock:
            plan = self.persistence.plan_retention(lock=lock, receipts=[old, receipt])
        self.assertEqual(1, len(plan.cleanup_targets))

    def test_cleanup_union_plans_four_exact_types_and_never_deletes(self) -> None:
        incoming_payload, partial_payload, object_payload = b"incoming", b"partial", b"object"
        incoming_path = self.persistence.layout.incoming / "candidate.pkg"
        partial_path = self.persistence.layout.incoming / "candidate.partial"
        object_path = self.root / "objects" / digest(object_payload)
        object_path.parent.mkdir()
        incoming_path.write_bytes(incoming_payload)
        partial_path.write_bytes(partial_payload)
        object_path.write_bytes(object_payload)

        def path_target(kind: str, logical_path: str, payload: bytes) -> dict[str, object]:
            hash_field = "object_sha256" if kind == "unreferenced_object" else "payload_sha256"
            core = {"kind": kind, "path": logical_path, hash_field: digest(payload)}
            return {**core, "closure_sha256": identity.identity_sha256({**core, "bytes": len(payload)})}

        targets = [
            release_cleanup_target(self.r_minus_1),
            path_target("incoming", r"D:\quant\quant_platform\incoming\candidate.pkg", incoming_payload),
            path_target("partial", r"D:\quant\quant_platform\incoming\candidate.partial", partial_payload),
            path_target("unreferenced_object", rf"D:\quant\quant_platform\objects\{digest(object_payload)}", object_payload),
        ]
        for document in (self.r_minus_1, self.r0, self.r1):
            self.materialize(document)
        self.write_pair(self.r1, self.r0)
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1, cleanup_targets=targets)
        receipt = transition_receipt(self.r1, self.r0, attempt="attempt-1")
        self.append_history(history_to(first, "cleanup_authorized", receipt=receipt))
        with self.persistence.global_lock() as lock:
            plan = self.persistence.plan_retention(lock=lock, receipts=[receipt])
        self.assertEqual(
            {ReleaseCleanupTargetPlan, IncomingCleanupTargetPlan,
             PartialCleanupTargetPlan, UnreferencedObjectCleanupTargetPlan},
            {type(item) for item in plan.cleanup_targets},
        )
        self.assertTrue(all(path.exists() for path in (incoming_path, partial_path, object_path)))

    def test_cleanup_closure_drift_blocks_and_never_deletes(self) -> None:
        receipt = self.post_activation_setup("cleanup_authorized")
        payload_path = self.persistence.layout.releases / "release-r-minus-1" / "app" / "payload.bin"
        payload_path.write_bytes(b"drift")
        with self.persistence.global_lock() as lock, self.assertRaises(RetentionPlanningError):
            self.persistence.plan_retention(lock=lock, receipts=[receipt])
        self.assertTrue(payload_path.exists())

    def test_cleanup_terminal_binds_same_attempt_terminal_pair_and_targets(self) -> None:
        for document in (self.r0, self.r1):
            self.materialize(document)
        self.write_pair(self.r1, self.r0)
        targets = [release_cleanup_target(self.r_minus_1)]
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1, cleanup_targets=targets)
        terminal = transition_receipt(self.r1, self.r0, attempt="attempt-1")
        cleaned = cleanup_receipt(self.r1, self.r0, targets, attempt="attempt-1")
        self.append_history(history_to(
            first, "cleanup_receipt_committed", receipt=terminal, cleanup=cleaned
        ))
        with self.persistence.global_lock() as lock:
            plan = self.persistence.plan_retention(lock=lock, receipts=[terminal, cleaned])
        self.assertEqual((), plan.cleanup_targets)

        other_terminal = transition_receipt(self.r0, self.r_minus_1, attempt="other-attempt")
        with self.persistence.global_lock() as lock, self.assertRaisesRegex(RetentionPlanningError, "same attempt|同 attempt"):
            self.persistence.plan_retention(lock=lock, receipts=[other_terminal, cleaned])

    def test_failure_receipt_observations_bind_journal_and_restore_original_pair(self) -> None:
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        failed_receipt = failure_receipt(
            self.r0, self.r1, original_prior=self.r_minus_1, attempt="attempt-1"
        )
        failed = advance_one(first, receipt=failed_receipt, failure=True)
        self.append_history([first, failed])
        with self.persistence.global_lock() as lock:
            plan = self.persistence.plan_retention(lock=lock, receipts=[failed_receipt])
        assert plan.prior is not None
        self.assertEqual(("release-r0", "release-r-minus-1"),
                         (plan.active.release_id, plan.prior.release_id))

    def test_retention_rejects_receipt_failed_phase_different_from_journal(self) -> None:
        self.materialize(self.r0)
        self.materialize(self.r_minus_1)
        self.write_pair(self.r0, self.r_minus_1)
        first = journal(self.r0, self.r1, original_prior=self.r_minus_1)
        history = history_to(first, "candidate_verified")
        wrong_receipt = failure_receipt(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            attempt="attempt-1",
            failed_phase="root_preflight_verified",
        )
        failed = advance_one(history[-1], receipt=wrong_receipt, failure=True)
        failed["terminal_receipt"]["failed_phase"] = "candidate_verified"
        seal(failed, "journal_sha256")
        validate_journal_history([*history, failed])
        self.append_history([*history, failed])
        with self.persistence.global_lock() as lock, self.assertRaisesRegex(
            RetentionPlanningError, "operation/failed_phase"
        ):
            self.persistence.plan_retention(
                lock=lock, receipts=[wrong_receipt]
            )

    def test_bootstrap_result_allows_only_r0_without_binding_or_cleanup(self) -> None:
        self.materialize(self.r0)
        first = journal(None, self.r0, operation="bootstrap_first_pair",
                        attempt="bootstrap-r0", nonce="bootstrap-nonce")
        receipt = bootstrap_receipt(self.r0, attempt="bootstrap-r0")
        self.append_history(history_to(first, "terminal_receipt_committed", receipt=receipt))
        with self.persistence.global_lock() as lock:
            self.persistence.cas_active_release(lock=lock, expected=None, desired=active(self.r0))
            plan = self.persistence.plan_retention(lock=lock, receipts=[receipt])
        self.assertIsNone(plan.prior)
        self.assertEqual((), plan.cleanup_targets)

    def test_first_r0_to_r1_before_binding_is_exact_and_cannot_cleanup(self) -> None:
        self.materialize(self.r0)
        self.materialize(self.r1)
        bootstrap = journal(
            None, self.r0, operation="bootstrap_first_pair",
            attempt="bootstrap-r0", nonce="bootstrap-nonce",
        )
        bootstrap_done = bootstrap_receipt(self.r0, attempt="bootstrap-r0")
        first_activation = journal(
            self.r0, self.r1, original_prior=None,
            attempt="first-r0-r1", nonce="first-r0-r1-nonce",
        )
        self.append_history(history_to(
            bootstrap, "terminal_receipt_committed", receipt=bootstrap_done
        ))
        with self.persistence.global_lock() as lock:
            self.persistence.cas_active_release(
                lock=lock, expected=None, desired=active(self.r0)
            )
        self.append_history(history_to(first_activation, "candidate_verified"))
        with self.persistence.global_lock() as lock:
            self.persistence.cas_active_release(
                lock=lock, expected=active(self.r0), desired=active(self.r1)
            )
            plan = self.persistence.plan_retention(
                lock=lock, receipts=[bootstrap_done]
            )
        self.assertEqual("release-r1", plan.active.release_id)
        self.assertIsNone(plan.prior)
        assert plan.transient is not None
        self.assertEqual("release-r0", plan.transient.release_id)
        self.assertEqual((), plan.cleanup_targets)


class RuntimeQualificationConsumeTests(PersistenceFixture):
    def setUp(self) -> None:
        super().setUp()
        for database, filename in (
            ("comments", "comments.sqlite3"),
            ("research_workspace", "research_workspace.sqlite3"),
        ):
            path = self.persistence.layout.state / filename
            with closing(sqlite3.connect(path, isolation_level=None)) as connection:
                connection.execute(
                    "CREATE TABLE state_fixture (database_name TEXT PRIMARY KEY)"
                )
                connection.execute(
                    "INSERT INTO state_fixture(database_name) VALUES (?)",
                    (database,),
                )

    def _set_candidate_current(self, lock) -> None:
        if self.persistence.read_active_release() is None:
            self.persistence.cas_active_release(
                lock=lock,
                expected=None,
                desired=active(self.r1),
            )
        if self.persistence.read_local_prior_binding() is None:
            self.persistence.cas_local_prior_binding(
                lock=lock,
                expected=None,
                desired=binding(self.r0, self.r_minus_1),
            )

    def _closure_metadata(
        self,
        authorization: LockedExactTransientStartAuthorization,
    ) -> dict[str, object]:
        attempt_id = authorization._workspace.attempt_id  # noqa: SLF001
        latest = self.persistence.journals.replay(attempt_id)[-1]
        role = authorization._role  # noqa: SLF001
        closure_role = "prior" if role == "prior" else "candidate"
        release = json.loads(
            authorization._release_ref_raw.decode("utf-8")  # noqa: SLF001
        )
        return {
            "operation": authorization._operation,  # noqa: SLF001
            "attempt_id": attempt_id,
            "nonce": authorization._workspace.nonce,  # noqa: SLF001
            "state_identity_sha256": authorization._state_identity_sha256,  # noqa: SLF001
            "planned_compatibility_sha256": latest["state_plan"][
                "compatibility_sha256"
            ],
            "roles": {
                closure_role: {
                    "release_id": release["release_id"],
                    "manifest_sha256": release["manifest_sha256"],
                }
            },
        }

    def _aggregate(
        self,
        authorization: LockedExactTransientStartAuthorization,
        production_state_order_sha256: str,
        *,
        closure_metadata: dict[str, object] | None = None,
        release_compatibility_sha256: str | None = None,
    ) -> LocalRuntimeQualificationAggregateEvidence:
        latest = self.persistence.journals.replay(authorization.attempt_id)[-1]
        if closure_metadata is None:
            closure_metadata = self._closure_metadata(authorization)
        payload: dict[str, object] = {
            "schema_version": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCHEMA,
            "scope": LOCAL_RUNTIME_QUALIFICATION_EVIDENCE_SCOPE,
            "attempt_id": authorization.attempt_id,
            "nonce": authorization.nonce,
            "operation": authorization.operation,
            "role": authorization.role,
            "start_nonce": authorization.start_nonce,
            "state_identity_sha256": authorization.state_identity_sha256,
            "authorization_sha256": authorization.authorization_sha256,
        }
        for index, field in enumerate(
            (
                "release_compatibility_sha256",
                "release_closure_sha256",
                "production_state_before_order_sha256",
                "production_state_after_order_sha256",
                "scm_before_after_sha256",
                "endpoint_before_after_sha256",
                "writer_before_after_sha256",
                "canary_request_sha256",
                "canary_result_sha256",
                "canary_database_order_sha256",
                "runtime_tooling_manifest_sha256",
                "controller_tooling_observation_sha256",
            ),
            start=1,
        ):
            payload[field] = hashlib.sha256(
                f"{authorization.role}:{index}:{field}".encode("utf-8")
            ).hexdigest()
        payload["release_compatibility_sha256"] = (
            latest["state_plan"]["compatibility_sha256"]
            if release_compatibility_sha256 is None
            else release_compatibility_sha256
        )
        payload["release_closure_sha256"] = identity.identity_sha256(
            closure_metadata
        )
        payload["production_state_before_order_sha256"] = (
            production_state_order_sha256
        )
        payload["production_state_after_order_sha256"] = (
            production_state_order_sha256
        )
        return LocalRuntimeQualificationAggregateEvidence.from_document(
            build_local_runtime_qualification_evidence(payload)
        )

    @staticmethod
    def _locked_qualification(
        persistence: LocalDeploymentPersistence,
        lock,
        workspace,
        authorization: LockedExactTransientStartAuthorization,
        aggregate: LocalRuntimeQualificationAggregateEvidence,
        state_sources: dict[str, LockedStateSqliteSource],
        closures: LockedExactReleaseClosures | None = None,
    ) -> tuple[
        LockedLocalRuntimeQualification,
        LockedExactRuntimeCanaryObservation,
    ]:
        canary = object.__new__(LockedExactRuntimeCanaryInput)
        live = object.__new__(LockedExactRuntimeCanaryObservation)
        locked = object.__new__(LockedLocalRuntimeQualification)
        object.__setattr__(canary, "_persistence", persistence)
        object.__setattr__(canary, "_lock", lock)
        object.__setattr__(canary, "_workspace", workspace)
        object.__setattr__(canary, "_authorization", authorization)
        object.__setattr__(canary, "_sources", state_sources)
        if closures is None:
            closures = object.__new__(LockedExactReleaseClosures)
            object.__setattr__(closures, "_persistence", persistence)
            object.__setattr__(closures, "_lock", lock)
            object.__setattr__(closures, "_workspace", workspace)
            object.__setattr__(closures, "_state", "live")
        object.__setattr__(canary, "_closures", closures)
        object.__setattr__(canary, "_live_observation", live)
        object.__setattr__(live, "_canary", canary)
        object.__setattr__(live, "_state", "live")
        object.__setattr__(live, "_qualification", locked)
        object.__setattr__(locked, "_observation", live)
        object.__setattr__(locked, "_aggregate_raw", aggregate.canonical_bytes())
        object.__setattr__(locked, "_state", "live")
        object.__setattr__(locked, "_sealed", True)
        return locked, live

    def _qualification_fixture(
        self,
        lock,
        workspace,
        authorization: LockedExactTransientStartAuthorization,
    ) -> tuple[
        LocalRuntimeQualificationAggregateEvidence,
        LockedLocalRuntimeQualification,
        LockedExactRuntimeCanaryObservation,
    ]:
        state_sources = {
            database: self.persistence.lock_state_sqlite_source(
                lock, workspace, database
            )
            for database in ("comments", "research_workspace")
        }
        state_sha256 = persistence_module._locked_production_state_order_sha256(
            state_sources,
            persistence=self.persistence,
            workspace=workspace,
        )
        aggregate = self._aggregate(authorization, state_sha256)
        locked, live = self._locked_qualification(
            self.persistence,
            lock,
            workspace,
            authorization,
            aggregate,
            state_sources,
        )
        return aggregate, locked, live

    def _verified_release_patches(
        self,
        authorization: LockedExactTransientStartAuthorization,
    ):
        latest = self.persistence.journals.replay(
            authorization._workspace.attempt_id  # noqa: SLF001
        )[-1]
        compatibility = type(
            "CompatibilityProbe",
            (),
            {
                "aggregate_sha256": latest["state_plan"][
                    "compatibility_sha256"
                ]
            },
        )()
        return (
            patch.object(
                LockedExactReleaseClosures,
                "metadata",
                return_value=self._closure_metadata(authorization),
            ),
            patch.object(
                compatibility_module,
                "build_exact_release_compatibility_evidence",
                return_value=compatibility,
            ),
            patch.object(
                LockedExactReleaseClosures,
                "checkpoint_unchanged",
                return_value=None,
            ),
        )

    def test_one_shot_consume_advances_all_exact_roles_and_revokes_start(self) -> None:
        cases = (
            (
                "bootstrap_first_pair",
                "baseline",
                "candidate_start_authorized",
                "candidate_verified",
                "bootstrap_terminal_receipt",
            ),
            (
                "activation",
                "prior",
                "prior_start_authorized",
                "prior_verified",
                "active_pointer_cas",
            ),
            (
                "activation",
                "candidate",
                "candidate_start_authorized",
                "candidate_verified",
                "local_prior_binding_cas",
            ),
        )
        for index, (operation, role, start_phase, verified_phase, next_action) in enumerate(
            cases, start=1
        ):
            attempt = f"qualification-{role}-{index}"
            nonce = f"qualification-nonce-{role}-{index}"
            first = (
                journal(
                    None,
                    self.r0,
                    operation=operation,
                    attempt=attempt,
                    nonce=nonce,
                )
                if operation == "bootstrap_first_pair"
                else journal(
                    self.r0,
                    self.r1,
                    original_prior=self.r_minus_1,
                    operation=operation,
                    attempt=attempt,
                    nonce=nonce,
                )
            )
            history = history_to(first, start_phase)
            self.append_history(history)
            with self.subTest(role=role), self.persistence.global_lock() as lock:
                if role == "baseline":
                    self.persistence.cas_active_release(
                        lock=lock,
                        expected=None,
                        desired=active(self.r0),
                    )
                elif role == "prior":
                    self.persistence.cas_local_prior_binding(
                        lock=lock,
                        expected=None,
                        desired=binding(self.r0, self.r_minus_1),
                    )
                else:
                    self.persistence.cas_active_release(
                        lock=lock,
                        expected=active(self.r0),
                        desired=active(self.r1),
                    )
                workspace = self.persistence.bind_attempt_workspace(
                    lock, attempt, nonce
                )
                authorization = (
                    self.persistence.lock_exact_transient_start_authorization(
                        lock, workspace, role
                    )
                )
                authorized_release = authorization.release_ref
                aggregate, locked, live = self._qualification_fixture(
                    lock, workspace, authorization
                )
                release_patches = self._verified_release_patches(authorization)
                with patch.object(
                    qualification_module,
                    "_rebuild_aggregate",
                    return_value=aggregate,
                ), release_patches[0], release_patches[1], release_patches[2]:
                    verified = (
                        self.persistence.consume_runtime_qualification_and_advance(
                            lock,
                            workspace,
                            locked,
                            int(history[-1]["revision"]),
                        )
                    )
                release_patches = self._verified_release_patches(authorization)
                with release_patches[0], release_patches[1], release_patches[2]:
                    self.assertIs(type(verified), LockedVerifiedPhaseCasAuthorization)
                    self.assertEqual(verified_phase, verified.phase)
                    self.assertEqual(role, verified.role)
                    self.assertEqual(next_action, verified.next_action)
                    self.assertEqual(
                        aggregate.aggregate_sha256,
                        verified.qualification_sha256,
                    )
                    if role == "baseline":
                        with self.assertRaisesRegex(
                            DeploymentJournalError,
                            "baseline",
                        ):
                            self.persistence.consume_verified_phase_next_cas(
                                lock,
                                workspace,
                                verified,
                            )
                with self.assertRaises(TypeError):
                    pickle.dumps(verified)
                with self.assertRaises(TypeError):
                    verified._role = "candidate"  # type: ignore[misc]  # noqa: SLF001
                self.assertEqual("consumed", locked._state)  # noqa: SLF001
                self.assertIsNone(live._qualification)  # noqa: SLF001
                latest = self.persistence.journals.replay(attempt)[-1]
                evidence_field = (
                    "prior_runtime_qualification_sha256"
                    if role == "prior"
                    else "candidate_runtime_qualification_sha256"
                )
                self.assertEqual(verified_phase, latest["phase"])
                self.assertEqual(
                    aggregate.aggregate_sha256,
                    latest["evidence_hashes"][evidence_field],
                )
                target = (
                    self.persistence.layout.journals
                    / f"{attempt}.evidence"
                    / f"runtime-qualification-{role}.json"
                )
                self.assertEqual(aggregate.canonical_bytes(), target.read_bytes())
                with self.assertRaises(DeploymentJournalError):
                    _ = authorization.role
                with self.assertRaises(
                    (DeploymentLockBusy, qualification_module.LocalRuntimeQualificationError)
                ):
                    self.persistence.consume_runtime_qualification_and_advance(
                        lock,
                        workspace,
                        locked,
                        int(history[-1]["revision"]),
                    )
                closures = object.__new__(LockedExactReleaseClosures)
                object.__setattr__(closures, "_persistence", self.persistence)
                object.__setattr__(closures, "_lock", lock)
                object.__setattr__(closures, "_workspace", workspace)
                object.__setattr__(closures, "_state", "live")
                closure_role = "prior" if role == "prior" else "candidate"
                closure_metadata = {
                    "operation": operation,
                    "attempt_id": attempt,
                    "nonce": nonce,
                    "state_identity_sha256": latest["state_plan"][
                        "state_identity_sha256"
                    ],
                    "planned_compatibility_sha256": latest["state_plan"][
                        "compatibility_sha256"
                    ],
                    "roles": {
                        closure_role: {
                            "release_id": authorized_release["release_id"],
                            "manifest_sha256": authorized_release[
                                "manifest_sha256"
                            ],
                        }
                    },
                }
                compatibility = type(
                    "CompatibilityProbe",
                    (),
                    {
                        "aggregate_sha256": latest["state_plan"][
                            "compatibility_sha256"
                        ]
                    },
                )()
                with patch.object(
                    LockedExactReleaseClosures,
                    "metadata",
                    return_value=closure_metadata,
                ), patch.object(
                    compatibility_module,
                    "build_exact_release_compatibility_evidence",
                    return_value=compatibility,
                ), patch.object(
                    LockedExactReleaseClosures,
                    "checkpoint_unchanged",
                    return_value=None,
                ):
                    replayed = self.persistence.lock_verified_phase_cas_authorization(
                        lock,
                        workspace,
                        role,
                        closures,
                    )
                    self.assertEqual(next_action, replayed.next_action)
                drifted_compatibility = type(
                    "DriftedCompatibilityProbe",
                    (),
                    {"aggregate_sha256": hashlib.sha256(b"drift").hexdigest()},
                )()
                with patch.object(
                    LockedExactReleaseClosures,
                    "metadata",
                    return_value=closure_metadata,
                ), patch.object(
                    compatibility_module,
                    "build_exact_release_compatibility_evidence",
                    return_value=drifted_compatibility,
                ), patch.object(
                    LockedExactReleaseClosures,
                    "checkpoint_unchanged",
                    return_value=None,
                ), self.assertRaises(DeploymentJournalError):
                    _ = replayed.scope
                object.__setattr__(closures, "_state", "closed")
                with self.assertRaises(DeploymentLockBusy):
                    _ = replayed.next_action
                for forbidden in ("canary", "build_evidence", "consume", "qualify"):
                    self.assertNotIn(forbidden, dir(replayed))
                with self.assertRaises(DeploymentLockBusy):
                    self.persistence.lock_verified_phase_cas_authorization(
                        lock,
                        workspace,
                        role,
                        aggregate,  # type: ignore[arg-type]
                    )
                workspace.close()

    def test_bootstrap_terminal_consumes_live_baseline_qualification_once(self) -> None:
        attempt = "qualification-bootstrap-terminal"
        nonce = "qualification-bootstrap-terminal-nonce"
        first = journal(
            None,
            self.r0,
            operation="bootstrap_first_pair",
            attempt=attempt,
            nonce=nonce,
        )
        history = history_to(first, "candidate_start_authorized")
        self.append_history(history)
        with self.persistence.global_lock() as lock:
            self.persistence.cas_active_release(
                lock=lock, expected=None, desired=active(self.r0)
            )
            workspace = self.persistence.bind_attempt_workspace(
                lock, attempt, nonce
            )
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "baseline"
            )
            aggregate, locked, _live = self._qualification_fixture(
                lock, workspace, authorization
            )
            release_patches = self._verified_release_patches(authorization)
            with patch.object(
                qualification_module,
                "_rebuild_aggregate",
                return_value=aggregate,
            ), release_patches[0], release_patches[1], release_patches[2]:
                verified = self.persistence.consume_runtime_qualification_and_advance(
                    lock,
                    workspace,
                    locked,
                    int(history[-1]["revision"]),
                )
            release_patches = self._verified_release_patches(authorization)
            with release_patches[0], release_patches[1], release_patches[2]:
                terminal = self.persistence.consume_bootstrap_terminal(
                    lock=lock,
                    workspace=workspace,
                    authorization=verified,
                    state_identity=state_identity(),
                    ingress_closed_sha256="d" * 64,
                    legacy_c_writer_fence_sha256="e" * 64,
                )
            self.assertEqual("terminal_receipt_committed", terminal["phase"])
            self.assertEqual("activation", terminal["terminal_receipt"]["kind"])
            self.assertIsNone(self.persistence.read_local_prior_binding())
            receipts = [record.value for record in self.persistence.read_local_receipts()]
            self.assertEqual(1, len(receipts))
            self.assertEqual("bootstrap_first_pair", receipts[0]["operation"])
            self.assertEqual(
                {"active": release_ref(self.r0), "prior": None},
                receipts[0]["pair"],
            )
            self.assertEqual("consumed", verified._state)  # noqa: SLF001
            for source in verified._state_sources:  # noqa: SLF001
                source.close()
            object.__setattr__(verified._closures, "_state", "closed")  # noqa: SLF001
            workspace.close()

    def test_verified_replay_requires_fresh_exact_production_state_observation(self) -> None:
        attempt = "qualification-replay-state"
        nonce = "qualification-replay-state-nonce"
        first = journal(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            attempt=attempt,
            nonce=nonce,
        )
        history = history_to(first, "candidate_start_authorized")
        self.append_history(history)
        with self.persistence.global_lock() as lock:
            self._set_candidate_current(lock)
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            authorized_release = authorization.release_ref
            aggregate, locked, _live = self._qualification_fixture(
                lock, workspace, authorization
            )
            release_patches = self._verified_release_patches(authorization)
            with patch.object(
                qualification_module,
                "_rebuild_aggregate",
                return_value=aggregate,
            ), release_patches[0], release_patches[1], release_patches[2]:
                verified = self.persistence.consume_runtime_qualification_and_advance(
                    lock,
                    workspace,
                    locked,
                    int(history[-1]["revision"]),
                )
            for source in verified._state_sources:  # noqa: SLF001
                source.close()
            release_patches = self._verified_release_patches(authorization)
            with release_patches[0], release_patches[1], release_patches[2], self.assertRaises(
                UnsafeLocalPath
            ):
                _ = verified.scope
            with closing(
                sqlite3.connect(
                    self.persistence.layout.state / "comments.sqlite3",
                    isolation_level=None,
                )
            ) as connection:
                connection.execute(
                    "INSERT INTO state_fixture(database_name) VALUES ('drift')"
                )

            latest = self.persistence.journals.replay(attempt)[-1]
            closure_metadata = {
                "operation": "activation",
                "attempt_id": attempt,
                "nonce": nonce,
                "state_identity_sha256": latest["state_plan"][
                    "state_identity_sha256"
                ],
                "planned_compatibility_sha256": latest["state_plan"][
                    "compatibility_sha256"
                ],
                "roles": {
                    "candidate": {
                        "release_id": authorized_release["release_id"],
                        "manifest_sha256": authorized_release[
                            "manifest_sha256"
                        ],
                    }
                },
            }
            closures = object.__new__(LockedExactReleaseClosures)
            object.__setattr__(closures, "_persistence", self.persistence)
            object.__setattr__(closures, "_lock", lock)
            object.__setattr__(closures, "_workspace", workspace)
            object.__setattr__(closures, "_state", "live")
            compatibility = type(
                "CompatibilityProbe",
                (),
                {
                    "aggregate_sha256": latest["state_plan"][
                        "compatibility_sha256"
                    ]
                },
            )()
            with patch.object(
                LockedExactReleaseClosures,
                "metadata",
                return_value=closure_metadata,
            ), patch.object(
                compatibility_module,
                "build_exact_release_compatibility_evidence",
                return_value=compatibility,
            ), patch.object(
                LockedExactReleaseClosures,
                "checkpoint_unchanged",
                return_value=None,
            ), self.assertRaisesRegex(
                DeploymentJournalError,
                "production state seal",
            ):
                self.persistence.lock_verified_phase_cas_authorization(
                    lock, workspace, "candidate", closures
                )
            self.assertFalse(workspace._state_sources)  # noqa: SLF001
            workspace.close()

    def _real_verified_authority_fixture(
        self,
        suffix: str,
        *,
        role: str = "candidate",
    ):
        if role not in {"prior", "candidate"}:
            raise AssertionError("real verified fixture role must be prior/candidate")
        self.r0 = release(
            "release-r0",
            self.payloads["release-r0"],
            "9",
            include_migrations=True,
        )
        self.r1 = release(
            "release-r1",
            self.payloads["release-r1"],
            "a",
            include_migrations=True,
        )
        self.materialize(self.r0)
        candidate_root = self.materialize(self.r1)
        attempt = f"qualification-real-closure-{suffix}"
        nonce = f"qualification-real-closure-nonce-{suffix}"
        first = journal(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            attempt=attempt,
            nonce=nonce,
        )
        compatibility_documents = tuple(
            compatibility_module._build_document(  # noqa: SLF001
                operation="activation",
                attempt_id=attempt,
                nonce=nonce,
                state_identity_sha256=first["state_plan"][
                    "state_identity_sha256"
                ],
                database_name=database_name,
                candidate=self.r1,
                prior=self.r0,
            )
            for database_name in ("comments", "research_workspace")
        )
        _, planned_compatibility_sha256 = (
            compatibility_module.validate_exact_release_compatibility_evidence_set(
                compatibility_documents
            )
        )
        first["state_plan"]["compatibility_sha256"] = (
            planned_compatibility_sha256
        )
        first.pop("journal_sha256")
        first = seal(first, "journal_sha256")
        history = [first]
        start_phase = f"{role}_start_authorized"
        while history[-1]["phase"] != start_phase:
            next_revision = advance_one(history[-1])
            if next_revision["database_seals"]:
                next_revision["database_seals"] = [
                    {
                        "name": document["database_name"],
                        "seal_sha256": "a" * 64,
                        "compatibility_manifest_sha256": document[
                            "evidence_sha256"
                        ],
                    }
                    for document in compatibility_documents
                ]
                next_revision.pop("journal_sha256")
                next_revision = seal(next_revision, "journal_sha256")
            history.append(next_revision)
        self.append_history(history)
        lock = self.persistence.global_lock().acquire()
        workspace = None
        try:
            if role == "candidate":
                self._set_candidate_current(lock)
            else:
                if self.persistence.read_active_release() is None:
                    self.persistence.cas_active_release(
                        lock=lock,
                        expected=None,
                        desired=active(self.r0),
                    )
                if self.persistence.read_local_prior_binding() is None:
                    self.persistence.cas_local_prior_binding(
                        lock=lock,
                        expected=None,
                        desired=binding(self.r0, self.r_minus_1),
                    )
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, role
            )
            closures = self.persistence.lock_exact_release_closures(lock, workspace)
            compatibility = (
                compatibility_module.build_exact_release_compatibility_evidence(
                    closures
                )
            )
            closure_metadata = json.loads(
                identity.canonical_bytes(closures.metadata()).decode("utf-8")
            )
            state_sources = {
                database: self.persistence.lock_state_sqlite_source(
                    lock, workspace, database
                )
                for database in ("comments", "research_workspace")
            }
            state_sha256 = (
                persistence_module._locked_production_state_order_sha256(
                    state_sources,
                    persistence=self.persistence,
                    workspace=workspace,
                )
            )
            aggregate = self._aggregate(
                authorization,
                state_sha256,
                closure_metadata=closure_metadata,
                release_compatibility_sha256=compatibility.aggregate_sha256,
            )
            locked, _live = self._locked_qualification(
                self.persistence,
                lock,
                workspace,
                authorization,
                aggregate,
                state_sources,
                closures,
            )
            with patch.object(
                qualification_module,
                "_rebuild_aggregate",
                return_value=aggregate,
            ):
                verified = self.persistence.consume_runtime_qualification_and_advance(
                    lock,
                    workspace,
                    locked,
                    int(history[-1]["revision"]),
                )
            return lock, workspace, closures, verified, candidate_root
        except BaseException:
            if workspace is not None and workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()
            raise

    def test_candidate_verified_authorization_is_only_real_binding_cas_seam(
        self,
    ) -> None:
        lock, workspace, _closures, verified, _candidate_root = (
            self._real_verified_authority_fixture(
                "candidate-next-cas",
                role="candidate",
            )
        )
        try:
            latest_before = self.persistence.journals.replay(
                workspace.attempt_id
            )[-1]
            self.assertEqual("candidate_verified", latest_before["phase"])
            before_binding = self.persistence.read_local_prior_binding()
            object.__setattr__(verified, "_next_action", "active_pointer_cas")
            with self.assertRaisesRegex(
                DeploymentJournalError,
                "role/phase/action",
            ):
                self.persistence.consume_verified_phase_next_cas(
                    lock,
                    workspace,
                    verified,
                )
            after_wrong_action = self.persistence.read_local_prior_binding()
            self.assertEqual(
                None if before_binding is None else before_binding.raw,
                None if after_wrong_action is None else after_wrong_action.raw,
            )
            object.__setattr__(
                verified,
                "_next_action",
                "local_prior_binding_cas",
            )
            with tempfile.TemporaryDirectory() as foreign_text:
                foreign = LocalDeploymentPersistence.for_test_only(
                    Path(foreign_text).resolve(),
                    allow_posix_test_only=True,
                )
                foreign_lock = foreign.global_lock().acquire()
                foreign_workspace = foreign.bind_attempt_workspace(
                    foreign_lock,
                    "foreign-verified-cas",
                    "foreign-verified-cas-nonce",
                )
                try:
                    with self.assertRaises(DeploymentLockBusy):
                        foreign.consume_verified_phase_next_cas(
                            foreign_lock,
                            foreign_workspace,
                            verified,
                        )
                    foreign_workspace.close()
                    foreign_lock.release()
                finally:
                    if foreign_workspace._state != "closed":  # noqa: SLF001
                        foreign_workspace.close()
                    if foreign_lock.held:
                        foreign_lock.release()
            result = self.persistence.consume_verified_phase_next_cas(
                lock,
                workspace,
                verified,
            )
            self.assertEqual("swapped", result.outcome)
            current = self.persistence.read_local_prior_binding()
            self.assertIsNotNone(current)
            assert current is not None
            self.assertEqual(
                latest_before["binding_cas"]["desired_binding"],
                current.value,
            )
            latest_after = self.persistence.journals.replay(
                workspace.attempt_id
            )[-1]
            self.assertEqual("binding_cas_committed", latest_after["phase"])
            self.assertIsNotNone(
                latest_after["evidence_hashes"][
                    "binding_cas_observation_sha256"
                ]
            )
            self.assertEqual("consumed", verified._state)  # noqa: SLF001
            with self.assertRaises(DeploymentLockBusy):
                self.persistence.consume_verified_phase_next_cas(
                    lock,
                    workspace,
                    verified,
                )
            with self.assertRaises(DeploymentLockBusy):
                _ = verified.next_action
            workspace.close()
            lock.release()
        finally:
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def test_prior_verified_authorization_is_only_real_pointer_cas_seam(
        self,
    ) -> None:
        lock, workspace, _closures, verified, _candidate_root = (
            self._real_verified_authority_fixture(
                "prior-next-cas",
                role="prior",
            )
        )
        try:
            latest_before = self.persistence.journals.replay(
                workspace.attempt_id
            )[-1]
            self.assertEqual("prior_verified", latest_before["phase"])
            result = self.persistence.consume_verified_phase_next_cas(
                lock,
                workspace,
                verified,
            )
            self.assertEqual("swapped", result.outcome)
            current = self.persistence.read_active_release()
            self.assertIsNotNone(current)
            assert current is not None
            self.assertEqual(
                latest_before["pointer_cas"]["desired"],
                current.value["release"],
            )
            latest_after = self.persistence.journals.replay(
                workspace.attempt_id
            )[-1]
            self.assertEqual("pointer_cas_committed", latest_after["phase"])
            self.assertIsNotNone(
                latest_after["evidence_hashes"][
                    "pointer_cas_observation_sha256"
                ]
            )
            self.assertEqual("consumed", verified._state)  # noqa: SLF001
            workspace.close()
            lock.release()
        finally:
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def test_verified_next_cas_rejects_fake_and_uninitialized_authority(
        self,
    ) -> None:
        attempt = "qualification-cas-fake"
        nonce = "qualification-cas-fake-nonce"
        first = journal(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            attempt=attempt,
            nonce=nonce,
        )
        self.append_history(history_to(first, "candidate_verified"))
        with self.persistence.global_lock() as lock:
            self.persistence.cas_active_release(
                lock=lock,
                expected=None,
                desired=active(self.r1),
            )
            self.persistence.cas_local_prior_binding(
                lock=lock,
                expected=None,
                desired=binding(self.r0, self.r_minus_1),
            )
            workspace = self.persistence.bind_attempt_workspace(
                lock,
                attempt,
                nonce,
            )
            for forged in (
                object(),
                {"scope": "verified_phase_next_cas_authorization"},
                object.__new__(LockedVerifiedPhaseCasAuthorization),
            ):
                with self.subTest(forged=type(forged).__name__), self.assertRaises(
                    DeploymentLockBusy
                ):
                    self.persistence.consume_verified_phase_next_cas(
                        lock,
                        workspace,
                        forged,
                    )
            workspace.close()

    def test_verified_next_cas_prewrite_failure_keeps_expected_and_live(
        self,
    ) -> None:
        lock, workspace, _closures, verified, _candidate_root = (
            self._real_verified_authority_fixture(
                "cas-prewrite",
                role="candidate",
            )
        )
        before = self.persistence.read_local_prior_binding()
        try:
            with patch.object(
                persistence_module._CanonicalCasAuthority,
                "compare_and_swap",
                side_effect=OSError("fixture CAS prewrite failure"),
            ), self.assertRaisesRegex(OSError, "prewrite"):
                self.persistence.consume_verified_phase_next_cas(
                    lock,
                    workspace,
                    verified,
                )
            after = self.persistence.read_local_prior_binding()
            self.assertEqual(
                None if before is None else before.raw,
                None if after is None else after.raw,
            )
            self.assertEqual("live", verified._state)  # noqa: SLF001
            workspace.close()
            lock.release()
        finally:
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def test_verified_next_cas_postwrite_return_failure_is_replayed(
        self,
    ) -> None:
        lock, workspace, _closures, verified, _candidate_root = (
            self._real_verified_authority_fixture(
                "cas-postwrite",
                role="candidate",
            )
        )
        original = persistence_module._CanonicalCasAuthority.compare_and_swap

        def fail_after_cas(authority, **kwargs):
            original(authority, **kwargs)
            raise OSError("fixture CAS postwrite return failure")

        try:
            with patch.object(
                persistence_module._CanonicalCasAuthority,
                "compare_and_swap",
                new=fail_after_cas,
            ):
                result = self.persistence.consume_verified_phase_next_cas(
                    lock,
                    workspace,
                    verified,
                )
            self.assertEqual("already_desired", result.outcome)
            self.assertEqual(
                "binding_cas_committed",
                self.persistence.journals.replay(workspace.attempt_id)[-1][
                    "phase"
                ],
            )
            self.assertEqual("consumed", verified._state)  # noqa: SLF001
            workspace.close()
            lock.release()
        finally:
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def test_verified_next_cas_evidence_and_journal_postwrite_are_replayed(
        self,
    ) -> None:
        for cut in ("evidence", "journal"):
            with self.subTest(cut=cut):
                fixture = RuntimeQualificationConsumeTests(
                    methodName="test_candidate_verified_authorization_is_only_real_binding_cas_seam"
                )
                fixture.setUp()
                try:
                    lock, workspace, _closures, verified, _candidate_root = (
                        fixture._real_verified_authority_fixture(
                            f"{cut}-postwrite",
                            role="candidate",
                        )
                    )
                    try:
                        if cut == "evidence":
                            original_commit = (
                                LocalDeploymentPersistence._commit_attempt_evidence
                            )

                            def fail_after_evidence(instance, *args, **kwargs):
                                original_commit(instance, *args, **kwargs)
                                raise OSError(
                                    "fixture evidence postwrite return failure"
                                )

                            context = patch.object(
                                LocalDeploymentPersistence,
                                "_commit_attempt_evidence",
                                fail_after_evidence,
                            )
                        else:
                            original_append = fixture.persistence.journals.append

                            def fail_after_journal(value, *, lock):
                                original_append(value, lock=lock)
                                raise OSError(
                                    "fixture journal postwrite return failure"
                                )

                            context = patch.object(
                                fixture.persistence.journals,
                                "append",
                                side_effect=fail_after_journal,
                            )
                        with context:
                            result = (
                                fixture.persistence.consume_verified_phase_next_cas(
                                    lock,
                                    workspace,
                                    verified,
                                )
                            )
                        self.assertIn(
                            result.outcome,
                            {"swapped", "already_desired"},
                        )
                        self.assertEqual(
                            "binding_cas_committed",
                            fixture.persistence.journals.replay(
                                workspace.attempt_id
                            )[-1]["phase"],
                        )
                        workspace.close()
                        lock.release()
                    finally:
                        if workspace._state != "closed":  # noqa: SLF001
                            workspace.close()
                        if lock.held:
                            lock.release()
                finally:
                    fixture.tearDown()

    @unittest.skipUnless(
        os.name == "nt",
        "verified CAS owner-crash replay 只验证 Windows 产品语义",
    )
    def test_verified_next_cas_crash_after_cas_before_journal_replays(
        self,
    ) -> None:
        attempt = "qualification-real-closure-crash-replay"
        nonce = "qualification-real-closure-nonce-crash-replay"
        code = r'''
import os
from pathlib import Path
import sys
from unittest.mock import patch

from quant_hub.ops.local_deployment_persistence import LocalDeploymentPersistence
from tests.test_local_deployment_persistence import (
    RuntimeQualificationConsumeTests,
    release,
)

case = RuntimeQualificationConsumeTests(
    methodName="test_candidate_verified_authorization_is_only_real_binding_cas_seam"
)
case.root = Path(sys.argv[1]).resolve()
case.persistence = LocalDeploymentPersistence.for_test_only(
    case.root,
    allow_posix_test_only=True,
)
case.payloads = {
    "release-r-minus-1": b"old-prior",
    "release-r0": b"active-r0",
    "release-r1": b"candidate-r1",
    "release-r2": b"third-r2",
}
case.r_minus_1 = release("release-r-minus-1", b"old-prior", "8")
case.r0 = release("release-r0", b"active-r0", "9")
case.r1 = release("release-r1", b"candidate-r1", "a")
case.r2 = release("release-r2", b"third-r2", "b")
lock, workspace, closures, verified, candidate_root = (
    case._real_verified_authority_fixture(
        "crash-replay",
        role="candidate",
    )
)
del closures, candidate_root
try:
    def fail_before_evidence(_instance, *_args, **_kwargs):
        raise OSError("fixture evidence prewrite crash cut")

    with patch.object(
        LocalDeploymentPersistence,
        "_commit_attempt_evidence",
        fail_before_evidence,
    ):
        case.persistence.consume_verified_phase_next_cas(
            lock,
            workspace,
            verified,
        )
except BaseException:
    current = case.persistence.read_local_prior_binding()
    latest = case.persistence.journals.replay(workspace.attempt_id)[-1]
    print(
        verified._state,
        lock._release_phase,
        latest["phase"],
        None if current is None else current.value["binding_sha256"],
        flush=True,
    )
    os._exit(0)
os._exit(9)
'''
        completed = subprocess.run(
            [sys.executable, "-c", code, str(self.root)],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn(
            "owner_crash_only owner_crash_only candidate_verified",
            completed.stdout,
        )

        lock = self.persistence.global_lock().acquire()
        workspace = self.persistence.bind_attempt_workspace(
            lock,
            attempt,
            nonce,
        )
        try:
            closures = self.persistence.lock_exact_release_closures(
                lock,
                workspace,
            )
            verified = self.persistence.lock_verified_phase_cas_authorization(
                lock,
                workspace,
                "candidate",
                closures,
            )
            self.assertEqual("local_prior_binding_cas", verified.next_action)
            result = self.persistence.consume_verified_phase_next_cas(
                lock,
                workspace,
                verified,
            )
            self.assertEqual("already_desired", result.outcome)
            self.assertEqual(
                "binding_cas_committed",
                self.persistence.journals.replay(attempt)[-1]["phase"],
            )
            workspace.close()
            lock.release()
        finally:
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def test_verified_authority_retains_real_release_closure_until_use(self) -> None:
        lock, workspace, closures, verified, candidate_root = (
            self._real_verified_authority_fixture("close")
        )
        try:
            self.assertEqual(
                "verified_phase_next_cas_authorization",
                verified.scope,
            )
            closures.close()
            (candidate_root / "app" / "payload.bin").write_bytes(
                b"drift-after-closure-close"
            )
            before = self.persistence.read_local_prior_binding()
            with self.assertRaises(DeploymentLockBusy):
                self.persistence.consume_verified_phase_next_cas(
                    lock,
                    workspace,
                    verified,
                )
            after = self.persistence.read_local_prior_binding()
            self.assertEqual(
                None if before is None else before.raw,
                None if after is None else after.raw,
            )
            with self.assertRaises(DeploymentLockBusy):
                _ = verified.next_action
            workspace.close()
            lock.release()
        finally:
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def _assert_all_verified_properties_reject(
        self,
        verified: LockedVerifiedPhaseCasAuthorization,
    ) -> None:
        properties = (
            "scope",
            "phase",
            "role",
            "next_action",
            "qualification_sha256",
        )
        for name in properties:
            with self.subTest(property=name), self.assertRaises(
                (
                    DeploymentLockBusy,
                    LocalDeploymentPersistenceError,
                    RetentionPlanningError,
                    UnsafeLocalPath,
                )
            ):
                getattr(verified, name)

    @unittest.skipUnless(
        os.name == "nt",
        "verified release namespace monitor 只验证 Windows 产品语义",
    )
    def test_verified_authority_rejects_late_unmanifested_file(self) -> None:
        lock, workspace, closures, verified, candidate_root = (
            self._real_verified_authority_fixture("late-file")
        )
        late = candidate_root / "app" / "unmanifested-late.py"
        try:
            before = self.persistence.read_local_prior_binding()
            late.write_bytes(b"late-unmanifested-member")
            with self.assertRaises(
                (
                    DeploymentLockBusy,
                    LocalDeploymentPersistenceError,
                    RetentionPlanningError,
                    UnsafeLocalPath,
                )
            ):
                self.persistence.consume_verified_phase_next_cas(
                    lock,
                    workspace,
                    verified,
                )
            after = self.persistence.read_local_prior_binding()
            self.assertEqual(
                None if before is None else before.raw,
                None if after is None else after.raw,
            )
            self._assert_all_verified_properties_reject(verified)
            self.assertEqual("revoked", closures._state)  # noqa: SLF001
            self.assertEqual("revoked", verified._state)  # noqa: SLF001
            late.unlink()
            workspace.close()
            lock.release()
        finally:
            late.unlink(missing_ok=True)
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    @unittest.skipUnless(
        os.name == "nt",
        "verified release namespace ABA monitor 只验证 Windows 产品语义",
    )
    def test_verified_authority_rejects_nested_create_delete_aba(self) -> None:
        lock, workspace, closures, verified, candidate_root = (
            self._real_verified_authority_fixture("nested-aba")
        )
        late_directory = candidate_root / "app" / "late-package"
        late = late_directory / "member.py"
        try:
            before = self.persistence.read_local_prior_binding()
            late_directory.mkdir()
            late.write_bytes(b"nested-create-delete-aba")
            late.unlink()
            late_directory.rmdir()
            with self.assertRaises(
                (
                    DeploymentLockBusy,
                    LocalDeploymentPersistenceError,
                    RetentionPlanningError,
                    UnsafeLocalPath,
                )
            ):
                self.persistence.consume_verified_phase_next_cas(
                    lock,
                    workspace,
                    verified,
                )
            after = self.persistence.read_local_prior_binding()
            self.assertEqual(
                None if before is None else before.raw,
                None if after is None else after.raw,
            )
            self._assert_all_verified_properties_reject(verified)
            self.assertEqual("revoked", closures._state)  # noqa: SLF001
            self.assertEqual("revoked", verified._state)  # noqa: SLF001
            workspace.close()
            lock.release()
        finally:
            late.unlink(missing_ok=True)
            if late_directory.exists():
                late_directory.rmdir()
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    @unittest.skipUnless(
        os.name == "nt",
        "verified migration namespace monitor 只验证 Windows 产品语义",
    )
    def test_verified_authority_rejects_late_migration_member(self) -> None:
        lock, workspace, closures, verified, candidate_root = (
            self._real_verified_authority_fixture("late-migration")
        )
        late = (
            candidate_root
            / "migrations"
            / "research_workspace"
            / "9999_unmanifested.up.sql"
        )
        try:
            before = self.persistence.read_local_prior_binding()
            late.write_bytes(b"SELECT 1;")
            with self.assertRaises(
                (
                    DeploymentLockBusy,
                    LocalDeploymentPersistenceError,
                    RetentionPlanningError,
                    UnsafeLocalPath,
                )
            ):
                self.persistence.consume_verified_phase_next_cas(
                    lock,
                    workspace,
                    verified,
                )
            after = self.persistence.read_local_prior_binding()
            self.assertEqual(
                None if before is None else before.raw,
                None if after is None else after.raw,
            )
            self._assert_all_verified_properties_reject(verified)
            self.assertEqual("revoked", closures._state)  # noqa: SLF001
            self.assertEqual("revoked", verified._state)  # noqa: SLF001
            late.unlink()
            workspace.close()
            lock.release()
        finally:
            late.unlink(missing_ok=True)
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    @unittest.skipUnless(
        os.name == "nt",
        "verified release NFKC alias 只验证 Windows 产品语义",
    )
    def test_verified_next_cas_rejects_nfkc_alias_before_write(self) -> None:
        lock, workspace, closures, verified, candidate_root = (
            self._real_verified_authority_fixture("nfkc-next-cas")
        )
        alias = candidate_root / "app" / "ｐａｙｌｏａｄ.bin"
        before = self.persistence.read_local_prior_binding()
        try:
            alias.write_bytes(b"nfkc-alias")
            with self.assertRaises(
                (
                    DeploymentLockBusy,
                    LocalDeploymentPersistenceError,
                    RetentionPlanningError,
                    UnsafeLocalPath,
                )
            ):
                self.persistence.consume_verified_phase_next_cas(
                    lock,
                    workspace,
                    verified,
                )
            after = self.persistence.read_local_prior_binding()
            self.assertEqual(
                None if before is None else before.raw,
                None if after is None else after.raw,
            )
            self.assertEqual("revoked", closures._state)  # noqa: SLF001
            self.assertEqual("revoked", verified._state)  # noqa: SLF001
            alias.unlink()
            workspace.close()
            lock.release()
        finally:
            alias.unlink(missing_ok=True)
            if workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def test_existing_identical_aggregate_cannot_restore_or_replay_authority(self) -> None:
        attempt = "qualification-existing"
        nonce = "qualification-existing-nonce"
        first = journal(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            attempt=attempt,
            nonce=nonce,
        )
        history = history_to(first, "candidate_start_authorized")
        self.append_history(history)
        with self.persistence.global_lock() as lock:
            self._set_candidate_current(lock)
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            aggregate, locked, _live = self._qualification_fixture(
                lock, workspace, authorization
            )
            self.persistence.commit_attempt_evidence(
                lock,
                attempt,
                "runtime-qualification-candidate",
                aggregate.canonical_bytes(),
            )
            with patch.object(
                qualification_module,
                "_rebuild_aggregate",
                return_value=aggregate,
            ), self.assertRaisesRegex(CompareAndSwapConflict, "absent"):
                self.persistence.consume_runtime_qualification_and_advance(
                    lock,
                    workspace,
                    locked,
                    int(history[-1]["revision"]),
                )
            self.assertEqual(
                "candidate_start_authorized",
                self.persistence.journals.replay(attempt)[-1]["phase"],
            )
            self.assertEqual("live", locked._state)  # noqa: SLF001
            locked.close()
            workspace.close()

    def test_persistent_evidence_and_wrong_revision_are_not_consumable(self) -> None:
        attempt = "qualification-forgery"
        nonce = "qualification-forgery-nonce"
        first = journal(
            self.r0,
            self.r1,
            original_prior=self.r_minus_1,
            attempt=attempt,
            nonce=nonce,
        )
        history = history_to(first, "candidate_start_authorized")
        self.append_history(history)
        with self.persistence.global_lock() as lock:
            self._set_candidate_current(lock)
            workspace = self.persistence.bind_attempt_workspace(lock, attempt, nonce)
            authorization = self.persistence.lock_exact_transient_start_authorization(
                lock, workspace, "candidate"
            )
            aggregate, locked, _live = self._qualification_fixture(
                lock, workspace, authorization
            )
            for forged in (aggregate, aggregate.as_dict(), object()):
                with self.subTest(forged=type(forged).__name__), self.assertRaises(
                    DeploymentLockBusy
                ):
                    self.persistence.consume_runtime_qualification_and_advance(
                        lock,
                        workspace,
                        forged,
                        int(history[-1]["revision"]),
                    )
            with patch.object(
                qualification_module,
                "_rebuild_aggregate",
                return_value=aggregate,
            ), self.assertRaises(DeploymentJournalError):
                self.persistence.consume_runtime_qualification_and_advance(
                    lock,
                    workspace,
                    locked,
                    int(history[-1]["revision"]) - 1,
                )
            locked.close()
            workspace.close()

    def test_journal_append_prewrite_failure_is_ambiguous_but_postwrite_is_recovered(
        self,
    ) -> None:
        for postwrite in (False, True):
            attempt = f"qualification-append-{'post' if postwrite else 'pre'}"
            nonce = f"qualification-append-nonce-{'post' if postwrite else 'pre'}"
            first = journal(
                self.r0,
                self.r1,
                original_prior=self.r_minus_1,
                attempt=attempt,
                nonce=nonce,
            )
            history = history_to(first, "candidate_start_authorized")
            self.append_history(history)
            with self.subTest(postwrite=postwrite), self.persistence.global_lock() as lock:
                self._set_candidate_current(lock)
                workspace = self.persistence.bind_attempt_workspace(
                    lock, attempt, nonce
                )
                authorization = (
                    self.persistence.lock_exact_transient_start_authorization(
                        lock, workspace, "candidate"
                    )
                )
                aggregate, locked, _live = self._qualification_fixture(
                    lock, workspace, authorization
                )
                original_append = self.persistence.journals.append

                def fail_append(value, *, lock):
                    if postwrite:
                        original_append(value, lock=lock)
                    raise DeploymentJournalError("fixture append return failure")

                rebuild = patch.object(
                    qualification_module,
                    "_rebuild_aggregate",
                    return_value=aggregate,
                )
                append_failure = patch.object(
                    self.persistence.journals,
                    "append",
                    side_effect=fail_append,
                )
                if postwrite:
                    release_patches = self._verified_release_patches(
                        authorization
                    )
                    with (
                        rebuild,
                        append_failure,
                        release_patches[0],
                        release_patches[1],
                        release_patches[2],
                    ):
                        verified = (
                            self.persistence.consume_runtime_qualification_and_advance(
                                lock,
                                workspace,
                                locked,
                                int(history[-1]["revision"]),
                            )
                        )
                        self.assertEqual("candidate_verified", verified.phase)
                    self.assertEqual("consumed", locked._state)  # noqa: SLF001
                else:
                    with rebuild, append_failure, self.assertRaisesRegex(
                        DeploymentJournalError,
                        "durable latest",
                    ):
                        self.persistence.consume_runtime_qualification_and_advance(
                            lock,
                            workspace,
                            locked,
                            int(history[-1]["revision"]),
                        )
                    self.assertEqual(
                        "candidate_start_authorized",
                        self.persistence.journals.replay(attempt)[-1]["phase"],
                    )
                    self.assertEqual("live", locked._state)  # noqa: SLF001
                    with rebuild, self.assertRaises(CompareAndSwapConflict):
                        self.persistence.consume_runtime_qualification_and_advance(
                            lock,
                            workspace,
                            locked,
                            int(history[-1]["revision"]),
                        )
                    locked.close()
                workspace.close()

    def test_reserved_schema_and_case_alias_artifacts_fail_before_publish(self) -> None:
        for evidence_id in (
            "Runtime-qualification-candidate",
            "runtime-qualification-copy",
        ):
            attempt = f"qualification-alias-{evidence_id.split('-')[-1].lower()}"
            nonce = f"qualification-alias-nonce-{evidence_id.split('-')[-1].lower()}"
            first = journal(
                self.r0,
                self.r1,
                original_prior=self.r_minus_1,
                attempt=attempt,
                nonce=nonce,
            )
            history = history_to(first, "candidate_start_authorized")
            self.append_history(history)
            with self.subTest(evidence_id=evidence_id), self.persistence.global_lock() as lock:
                self._set_candidate_current(lock)
                workspace = self.persistence.bind_attempt_workspace(
                    lock, attempt, nonce
                )
                authorization = (
                    self.persistence.lock_exact_transient_start_authorization(
                        lock, workspace, "candidate"
                    )
                )
                aggregate, locked, _live = self._qualification_fixture(
                    lock, workspace, authorization
                )
                self.persistence.commit_attempt_evidence(
                    lock,
                    attempt,
                    evidence_id,
                    aggregate.canonical_bytes(),
                )
                with patch.object(
                    qualification_module,
                    "_rebuild_aggregate",
                    return_value=aggregate,
                ), self.assertRaises(CompareAndSwapConflict):
                    self.persistence.consume_runtime_qualification_and_advance(
                        lock,
                        workspace,
                        locked,
                        int(history[-1]["revision"]),
                    )
                self.assertEqual(
                    "candidate_start_authorized",
                    self.persistence.journals.replay(attempt)[-1]["phase"],
                )
                locked.close()
                workspace.close()


if __name__ == "__main__":
    unittest.main()
