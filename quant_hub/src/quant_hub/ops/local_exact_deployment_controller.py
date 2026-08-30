"""Production v4 successor activation orchestrator for the exact VM D root."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
import secrets
from typing import Mapping

from . import local_release_identity as identity
from .local_deployment_persistence import (
    CrashReleasedFileLock,
    DEPLOYMENT_ATTEMPT_SCHEMA,
    DeploymentJournalError,
    LocalDeploymentPersistence,
    LockedAttemptWorkspace,
    LockedVerifiedPhaseCasAuthorization,
    PRODUCTION_VM_ROOT_TEXT,
    validate_deployment_journal,
)
from .local_deployment_runtime import ProductionWindowsDeploymentRuntime
from .local_exact_release_compatibility import (
    DATABASE_ORDER,
    _build_document as _build_compatibility_document,
    plan_exact_release_compatibility,
    validate_exact_release_compatibility_evidence_set,
)
from .local_exact_runtime_canary_input import (
    ProductionExactRuntimeCanaryInputProducer,
)
from .local_exact_runtime_canary_live_observer import (
    ProductionExactRuntimeCanaryLiveObserver,
)
from .local_runtime_qualification import (
    ProductionLocalRuntimeQualificationProducer,
)
from .local_windows_endpoint_observer import ProductionWindowsEndpointObserver
from .local_windows_scm_process_observer import (
    ProductionWindowsScmProcessObserver,
)
from .local_windows_writer_lease_holder import ExactRuntimeLeaseIdentity
from .local_windows_writer_lease_observer import (
    ProductionWindowsWriterLeaseObserver,
)


_EVIDENCE_FIELDS = (
    "root_preflight_sha256",
    "state_compatibility_sha256",
    "prior_start_authorization_sha256",
    "prior_runtime_qualification_sha256",
    "pointer_cas_observation_sha256",
    "candidate_start_authorization_sha256",
    "candidate_runtime_qualification_sha256",
    "binding_cas_observation_sha256",
    "cleanup_authorization_sha256",
    "controller_verification_sha256",
    "cleanup_receipt_sha256",
    "write_set_sha256",
    "bootstrap_ingress_closed_sha256",
    "bootstrap_legacy_c_writer_fence_sha256",
    "failure_original_pointer_observation_sha256",
    "failure_original_binding_observation_sha256",
    "failure_original_service_observation_sha256",
    "failure_original_writer_fence_observation_sha256",
    "failure_state_identity_observation_sha256",
)

_CONTROLLER_TOKEN = object()
_TEST_CONTROLLER_TOKEN = object()
_LIVE_PRODUCTION_CONTROLLERS: dict[int, "ProductionExactDeploymentController"] = {}
_LIVE_TEST_CONTROLLERS: dict[int, "ProductionExactDeploymentController"] = {}


class ExactDeploymentControllerError(RuntimeError):
    """The production v4 activation state machine failed closed."""


def _now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _clone(value: object) -> dict[str, object]:
    cloned = json.loads(identity.canonical_bytes(value).decode("utf-8"))
    if type(cloned) is not dict:
        raise ExactDeploymentControllerError("controller material is not an object")
    return cloned


def _seal(value: dict[str, object], field: str) -> Mapping[str, object]:
    value.pop(field, None)
    value[field] = identity.identity_sha256(value)
    return value


def _release_ref(manifest: Mapping[str, object]) -> Mapping[str, object]:
    release_id = str(manifest["release_id"])
    document = identity.validate_active_release(
        {
            "schema_version": identity.ACTIVE_RELEASE_SCHEMA,
            "release": {
                "release_id": release_id,
                "release_path": (
                    f"D:\\quant\\quant_platform\\releases\\{release_id}"
                ),
                "manifest_sha256": identity.identity_sha256(manifest),
            },
        }
    )
    return document["release"]


def _pair(
    active: Mapping[str, object], prior: Mapping[str, object] | None
) -> Mapping[str, object]:
    return {"active": active, "prior": prior}


def _binding(
    *,
    attempt: str,
    active: Mapping[str, object],
    prior: Mapping[str, object],
    state_identity: Mapping[str, object],
) -> Mapping[str, object]:
    pair = _pair(active, prior)
    document: dict[str, object] = {
        "schema_version": identity.LOCAL_PRIOR_BINDING_SCHEMA,
        "binding_id": f"binding-{attempt}",
        "recorded_at": _now(),
        "authority": "retention_evidence_only",
        "active": active,
        "prior": prior,
        "state_identity": state_identity,
        "result": {
            "status": "bound",
            "pair_sha256": identity.identity_sha256(pair),
            "retained_release_count": 2,
            "state_policy": "expand_only_no_down_migration",
        },
    }
    return identity.validate_local_prior_binding(
        _seal(document, "binding_sha256")
    )


def _next_revision(
    latest: Mapping[str, object],
    *,
    phase: str,
) -> dict[str, object]:
    value = _clone(latest)
    value["revision"] = int(latest["revision"]) + 1
    value["phase"] = phase
    value["previous_journal_sha256"] = latest["journal_sha256"]
    value["timestamps"]["updated_at"] = _now()  # type: ignore[index]
    return value


class ProductionExactDeploymentController:
    """No-root-injection product controller for ordinary active/prior activation."""

    __slots__ = ("_persistence", "_service", "_sealed", "_provenance")

    def __init_subclass__(cls, **kwargs: object) -> None:
        del cls, kwargs
        raise TypeError("production exact deployment controller 不允许派生")

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise TypeError("production exact deployment controller 不可替换")
        object.__setattr__(self, name, value)

    def __init__(self, *, token: object) -> None:
        if token is not _CONTROLLER_TOKEN:
            raise TypeError("production exact deployment controller provenance 无效")
        from .vm_deploy_cli import WindowsServiceRuntime

        self._persistence = LocalDeploymentPersistence.production()
        self._service = WindowsServiceRuntime.load(Path(PRODUCTION_VM_ROOT_TEXT))
        self._provenance = _CONTROLLER_TOKEN
        object.__setattr__(self, "_sealed", True)
        _LIVE_PRODUCTION_CONTROLLERS[id(self)] = self

    @classmethod
    def load_exact_d(cls) -> "ProductionExactDeploymentController":
        return cls(token=_CONTROLLER_TOKEN)

    @classmethod
    def for_test_only(
        cls,
        *,
        persistence: LocalDeploymentPersistence,
        service: object,
    ) -> "ProductionExactDeploymentController":
        """Create an isolated controller that can never bind production D."""

        if (
            type(persistence) is not LocalDeploymentPersistence
            or not persistence._test_only  # noqa: SLF001
            or str(persistence.layout.root) == PRODUCTION_VM_ROOT_TEXT
        ):
            raise TypeError("test-only controller requires isolated persistence")
        value = object.__new__(cls)
        object.__setattr__(value, "_persistence", persistence)
        object.__setattr__(value, "_service", service)
        object.__setattr__(value, "_provenance", _TEST_CONTROLLER_TOKEN)
        object.__setattr__(value, "_sealed", True)
        _LIVE_TEST_CONTROLLERS[id(value)] = value
        return value

    def _assert_live_provenance(self) -> None:
        """Prove construction provenance before any persistence/service use."""

        if _LIVE_TEST_CONTROLLERS.get(id(self)) is self:
            if (
                getattr(self, "_provenance", None) is not _TEST_CONTROLLER_TOKEN
                or type(self._persistence) is not LocalDeploymentPersistence
                or not self._persistence._test_only  # noqa: SLF001
                or str(self._persistence.layout.root) == PRODUCTION_VM_ROOT_TEXT
            ):
                raise ExactDeploymentControllerError(
                    "test-only controller provenance differs"
                )
            return
        if _LIVE_PRODUCTION_CONTROLLERS.get(id(self)) is not self:
            raise ExactDeploymentControllerError(
                "production controller is not a live factory instance"
            )
        from .vm_deploy_cli import WindowsServiceRuntime

        # Invoke class-owned provenance checks so an instance-level helper
        # shadow can never replace the verifier itself.
        LocalDeploymentPersistence._assert_production_provenance(
            self._persistence
        )
        WindowsServiceRuntime._assert_production_provenance(self._service)

        if (
            getattr(self, "_provenance", None) is not _CONTROLLER_TOKEN
            or type(self._persistence) is not LocalDeploymentPersistence
            or self._persistence._test_only  # noqa: SLF001
            or str(self._persistence.layout.root) != PRODUCTION_VM_ROOT_TEXT
            or type(self._service) is not WindowsServiceRuntime
            or str(self._service.root) != PRODUCTION_VM_ROOT_TEXT
            or self._service.allow_test_root
        ):
            raise ExactDeploymentControllerError(
                "production controller dependency provenance differs"
            )

    def _manifest(self, release_id: str) -> Mapping[str, object]:
        matches = [
            entry
            for entry in self._persistence.release_inventory()
            if entry.release_id == release_id
        ]
        if len(matches) != 1:
            raise ExactDeploymentControllerError(
                "candidate release is not one exact v2 closure"
            )
        return self._persistence._manifest_for_entry(matches[0])  # noqa: SLF001

    def _initial_ordinary_journal(
        self,
        *,
        lock: CrashReleasedFileLock,
        attempt: str,
        nonce: str,
        candidate_manifest: Mapping[str, object],
    ) -> tuple[Mapping[str, object], tuple[Mapping[str, object], ...]]:
        active_record = self._persistence.read_active_release()
        binding_record = self._persistence.read_local_prior_binding()
        if active_record is None:
            raise ExactDeploymentControllerError(
                "ordinary activation requires an existing exact active pointer"
            )
        receipt_records = self._persistence.read_local_receipts()
        receipt_values = tuple(record.value for record in receipt_records)
        retention = self._persistence.plan_retention(
            lock=lock,
            receipts=receipt_values,
        )
        if retention.transient is not None or retention.cleanup_targets:
            raise ExactDeploymentControllerError(
                "ordinary activation requires a closed stable retention state"
            )
        if binding_record is None:
            bootstraps = [
                value
                for value in receipt_values
                if value.get("schema_version") == identity.ACTIVATION_RECEIPT_SCHEMA
                and value.get("operation") == "bootstrap_first_pair"
                and value.get("pair")
                == _pair(active_record.value["release"], None)
            ]
            if len(bootstraps) != 1:
                raise ExactDeploymentControllerError(
                    "binding-absent activation requires one exact bootstrap receipt"
                )
            bootstrap = bootstraps[0]
            original_pair = _pair(active_record.value["release"], None)
            state_identity = identity.validate_state_identity(
                bootstrap["state_identity"]
            )
            expected_binding = None
        else:
            binding = binding_record.value
            original_pair = _pair(binding["active"], binding["prior"])
            if active_record.value["release"] != original_pair["active"]:
                raise ExactDeploymentControllerError(
                    "active pointer/binding pair drifted"
                )
            state_identity = identity.validate_state_identity(
                binding["state_identity"]
            )
            expected_binding = binding
        candidate_ref = _release_ref(candidate_manifest)
        if candidate_ref in (original_pair["active"], original_pair["prior"]):
            raise ExactDeploymentControllerError("candidate is already retained")
        current_manifest = self._manifest(
            str(original_pair["active"]["release_id"])  # type: ignore[index]
        )
        plan = plan_exact_release_compatibility(
            operation="activation",
            attempt_id=attempt,
            nonce=nonce,
            state_identity_sha256=str(state_identity["identity_sha256"]),
            candidate_manifest=candidate_manifest,
            prior_manifest=current_manifest,
        )
        compatibility_documents = tuple(
            _build_compatibility_document(
                operation="activation",
                attempt_id=attempt,
                nonce=nonce,
                state_identity_sha256=str(state_identity["identity_sha256"]),
                database_name=database,
                candidate=candidate_manifest,
                prior=current_manifest,
            )
            for database in DATABASE_ORDER
        )
        _, observed_aggregate = validate_exact_release_compatibility_evidence_set(
            compatibility_documents
        )
        if observed_aggregate != plan.aggregate_sha256:
            raise ExactDeploymentControllerError("compatibility plan drifted")
        desired_binding = _binding(
            attempt=attempt,
            active=candidate_ref,
            prior=original_pair["active"],  # type: ignore[arg-type]
            state_identity=state_identity,
        )
        cleanup_targets: list[Mapping[str, object]] = []
        if original_pair["prior"] is not None:
            original_prior_manifest = self._manifest(
                str(original_pair["prior"]["release_id"])  # type: ignore[index]
            )
            cleanup_targets.append(
                {
                    "kind": "release_closure",
                    "release": original_pair["prior"],
                    "closure_sha256": original_prior_manifest["resources"][
                        "inventory_sha256"
                    ],
                }
            )
        created = _now()
        journal: dict[str, object] = {
            "schema_version": DEPLOYMENT_ATTEMPT_SCHEMA,
            "attempt": attempt,
            "operation": "activation",
            "revision": 0,
            "phase": "intent_durable",
            "nonce": nonce,
            "timestamps": {"created_at": created, "updated_at": created},
            "previous_journal_sha256": None,
            "original_pair": original_pair,
            "candidate": candidate_ref,
            "target_pair": _pair(candidate_ref, original_pair["active"]),
            "pointer_cas": {
                "expected": original_pair["active"],
                "desired": candidate_ref,
            },
            "binding_cas": {
                "expected_binding": expected_binding,
                "desired_binding": desired_binding,
                "expected_binding_sha256": (
                    None
                    if expected_binding is None
                    else expected_binding["binding_sha256"]
                ),
                "desired_binding_sha256": desired_binding["binding_sha256"],
            },
            "state_plan": {
                "state_identity_sha256": state_identity["identity_sha256"],
                "expand_plan_sha256": identity.identity_sha256(
                    {
                        "policy": "expand_only_no_down_migration",
                        "databases": list(DATABASE_ORDER),
                        "target": candidate_ref,
                    }
                ),
                "compatibility_sha256": plan.aggregate_sha256,
                "database_names": list(DATABASE_ORDER),
            },
            "database_seals": [],
            "transient_start": [],
            "reserved_receipt_ids": {
                "activation": f"activation-{attempt}",
                "rollback": None,
                "failure": f"failure-{attempt}",
                "cleanup": f"cleanup-{attempt}",
            },
            "cleanup_targets": cleanup_targets,
            "evidence_hashes": {field: None for field in _EVIDENCE_FIELDS},
            "terminal_receipt": None,
        }
        return validate_deployment_journal(
            _seal(journal, "journal_sha256")
        ), compatibility_documents

    def _initial_rollback_journal(
        self,
        *,
        lock: CrashReleasedFileLock,
        attempt: str,
        nonce: str,
    ) -> tuple[
        Mapping[str, object],
        tuple[Mapping[str, object], ...],
        Mapping[str, object],
    ]:
        """Derive an ordinary rollback only from the retained active/prior pair."""

        active_record = self._persistence.read_active_release()
        binding_record = self._persistence.read_local_prior_binding()
        if active_record is None or binding_record is None:
            raise ExactDeploymentControllerError(
                "ordinary rollback requires one exact active/prior binding"
            )
        binding = binding_record.value
        original_pair = _pair(binding["active"], binding["prior"])
        if (
            binding["prior"] is None
            or active_record.value["release"] != binding["active"]
        ):
            raise ExactDeploymentControllerError(
                "ordinary rollback requires a non-null prior and aligned active pointer"
            )
        receipts = tuple(
            record.value for record in self._persistence.read_local_receipts()
        )
        retention = self._persistence.plan_retention(
            lock=lock,
            receipts=receipts,
        )
        if retention.transient is not None or retention.cleanup_targets:
            raise ExactDeploymentControllerError(
                "ordinary rollback requires a closed stable retention state"
            )
        state_identity = identity.validate_state_identity(
            binding["state_identity"]
        )
        candidate_manifest = self._manifest(
            str(binding["prior"]["release_id"])
        )
        candidate_ref = _release_ref(candidate_manifest)
        if candidate_ref != binding["prior"]:
            raise ExactDeploymentControllerError(
                "retained prior manifest differs from the binding"
            )
        current_manifest = self._manifest(str(binding["active"]["release_id"]))
        plan = plan_exact_release_compatibility(
            operation="rollback",
            attempt_id=attempt,
            nonce=nonce,
            state_identity_sha256=str(state_identity["identity_sha256"]),
            candidate_manifest=candidate_manifest,
            prior_manifest=current_manifest,
        )
        compatibility_documents = tuple(
            _build_compatibility_document(
                operation="rollback",
                attempt_id=attempt,
                nonce=nonce,
                state_identity_sha256=str(state_identity["identity_sha256"]),
                database_name=database,
                candidate=candidate_manifest,
                prior=current_manifest,
            )
            for database in DATABASE_ORDER
        )
        _, observed_aggregate = validate_exact_release_compatibility_evidence_set(
            compatibility_documents
        )
        if observed_aggregate != plan.aggregate_sha256:
            raise ExactDeploymentControllerError(
                "rollback compatibility plan drifted"
            )
        target_pair = _pair(candidate_ref, binding["active"])
        desired_binding = _binding(
            attempt=attempt,
            active=candidate_ref,
            prior=binding["active"],
            state_identity=state_identity,
        )
        created = _now()
        journal: dict[str, object] = {
            "schema_version": DEPLOYMENT_ATTEMPT_SCHEMA,
            "attempt": attempt,
            "operation": "rollback",
            "revision": 0,
            "phase": "intent_durable",
            "nonce": nonce,
            "timestamps": {"created_at": created, "updated_at": created},
            "previous_journal_sha256": None,
            "original_pair": original_pair,
            "candidate": candidate_ref,
            "target_pair": target_pair,
            "pointer_cas": {
                "expected": binding["active"],
                "desired": candidate_ref,
            },
            "binding_cas": {
                "expected_binding": binding,
                "desired_binding": desired_binding,
                "expected_binding_sha256": binding["binding_sha256"],
                "desired_binding_sha256": desired_binding["binding_sha256"],
            },
            "state_plan": {
                "state_identity_sha256": state_identity["identity_sha256"],
                "expand_plan_sha256": identity.identity_sha256(
                    {
                        "policy": "expand_only_no_down_migration",
                        "databases": list(DATABASE_ORDER),
                        "target": candidate_ref,
                    }
                ),
                "compatibility_sha256": plan.aggregate_sha256,
                "database_names": list(DATABASE_ORDER),
            },
            "database_seals": [],
            "transient_start": [],
            "reserved_receipt_ids": {
                "activation": None,
                "rollback": f"rollback-{attempt}",
                "failure": f"failure-{attempt}",
                "cleanup": f"cleanup-{attempt}",
            },
            "cleanup_targets": [],
            "evidence_hashes": {field: None for field in _EVIDENCE_FIELDS},
            "terminal_receipt": None,
        }
        return (
            validate_deployment_journal(_seal(journal, "journal_sha256")),
            compatibility_documents,
            candidate_manifest,
        )

    @staticmethod
    def _production_state_identity() -> Mapping[str, object]:
        value: dict[str, object] = {
            "schema_version": identity.LOCAL_STATE_IDENTITY_SCHEMA,
            "authority_id": "production-d-state",
            "state_path": r"D:\quant\quant_platform\state",
            "schema_versions": {
                "comments": 2,
                "research_workspace": 3,
            },
        }
        return identity.validate_state_identity(
            _seal(value, "identity_sha256")
        )

    def _initial_bootstrap_journal(
        self,
        *,
        lock: CrashReleasedFileLock,
        attempt: str,
        nonce: str,
        candidate_manifest: Mapping[str, object],
    ) -> tuple[Mapping[str, object], tuple[Mapping[str, object], ...]]:
        if (
            self._persistence.read_active_release() is not None
            or self._persistence.read_local_prior_binding() is not None
        ):
            raise ExactDeploymentControllerError(
                "bootstrap requires absent active pointer and prior binding"
            )
        successful = [
            record.value
            for record in self._persistence.read_local_receipts()
            if record.value.get("schema_version")
            in {identity.ACTIVATION_RECEIPT_SCHEMA, identity.ROLLBACK_RECEIPT_SCHEMA}
        ]
        if successful:
            raise ExactDeploymentControllerError(
                "bootstrap cannot replace an existing successful local lineage"
            )
        state = self._production_state_identity()
        candidate_ref = _release_ref(candidate_manifest)
        plan = plan_exact_release_compatibility(
            operation="bootstrap_first_pair",
            attempt_id=attempt,
            nonce=nonce,
            state_identity_sha256=str(state["identity_sha256"]),
            candidate_manifest=candidate_manifest,
            prior_manifest=None,
        )
        compatibility_documents = tuple(
            _build_compatibility_document(
                operation="bootstrap_first_pair",
                attempt_id=attempt,
                nonce=nonce,
                state_identity_sha256=str(state["identity_sha256"]),
                database_name=database,
                candidate=candidate_manifest,
                prior=None,
            )
            for database in DATABASE_ORDER
        )
        _, observed = validate_exact_release_compatibility_evidence_set(
            compatibility_documents
        )
        if observed != plan.aggregate_sha256:
            raise ExactDeploymentControllerError(
                "bootstrap compatibility plan drifted"
            )
        created = _now()
        journal: dict[str, object] = {
            "schema_version": DEPLOYMENT_ATTEMPT_SCHEMA,
            "attempt": attempt,
            "operation": "bootstrap_first_pair",
            "revision": 0,
            "phase": "intent_durable",
            "nonce": nonce,
            "timestamps": {"created_at": created, "updated_at": created},
            "previous_journal_sha256": None,
            "original_pair": None,
            "candidate": candidate_ref,
            "target_pair": _pair(candidate_ref, None),
            "pointer_cas": {"expected": None, "desired": candidate_ref},
            "binding_cas": {
                "expected_binding": None,
                "desired_binding": None,
                "expected_binding_sha256": None,
                "desired_binding_sha256": None,
            },
            "state_plan": {
                "state_identity_sha256": state["identity_sha256"],
                "expand_plan_sha256": identity.identity_sha256(
                    {
                        "policy": "expand_only_no_down_migration",
                        "databases": list(DATABASE_ORDER),
                        "target": candidate_ref,
                    }
                ),
                "compatibility_sha256": plan.aggregate_sha256,
                "database_names": list(DATABASE_ORDER),
            },
            "database_seals": [],
            "transient_start": [],
            "reserved_receipt_ids": {
                "activation": f"activation-{attempt}",
                "rollback": None,
                "failure": f"failure-{attempt}",
                "cleanup": None,
            },
            "cleanup_targets": [],
            "evidence_hashes": {field: None for field in _EVIDENCE_FIELDS},
            "terminal_receipt": None,
        }
        return validate_deployment_journal(
            _seal(journal, "journal_sha256")
        ), compatibility_documents

    def _append_preflight_and_state(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        latest: Mapping[str, object],
        compatibility_documents: tuple[Mapping[str, object], ...],
        candidate_manifest: Mapping[str, object],
    ) -> Mapping[str, object]:
        if latest["phase"] == "intent_durable":
            root = _next_revision(latest, phase="root_preflight_verified")
            root["evidence_hashes"]["root_preflight_sha256"] = identity.identity_sha256(  # type: ignore[index]
                {
                    "attempt": workspace.attempt_id,
                    "nonce": workspace.nonce,
                    "active": latest["pointer_cas"]["expected"],  # type: ignore[index]
                    "candidate": latest["candidate"],
                    "release_count": len(self._persistence.release_inventory()),
                }
            )
            latest = self._persistence.journals.append(
                _seal(root, "journal_sha256"), lock=lock
            )
        if latest["phase"] != "root_preflight_verified":
            raise DeploymentJournalError(
                "state compatibility requires intent/root-preflight latest"
            )
        operation = str(latest["operation"])
        current_manifest = (
            None
            if operation == "bootstrap_first_pair"
            else self._manifest(
                str(latest["original_pair"]["active"]["release_id"])  # type: ignore[index]
            )
        )
        runtime_operation = {
            "activation": "activate_successor",
            "rollback": "rollback_to_prior",
            "bootstrap_first_pair": "bootstrap_first_pair",
        }[operation]
        runtime = ProductionWindowsDeploymentRuntime.load_exact_d()
        seals: list[Mapping[str, object]] = []
        for document in compatibility_documents:
            database = str(document["database_name"])
            candidate_versions = candidate_manifest["state"]["compatibility"][database]  # type: ignore[index]
            prior_versions = (
                None
                if current_manifest is None
                else current_manifest["state"]["compatibility"][database]  # type: ignore[index]
            )
            compatibility = runtime.compatibility_manifest(
                operation=runtime_operation,
                database_name=database,
                candidate_release_id=str(candidate_manifest["release_id"]),
                candidate_release_manifest_sha256=identity.identity_sha256(
                    candidate_manifest
                ),
                candidate_read_versions=list(candidate_versions["read"]),
                candidate_write_versions=list(candidate_versions["write"]),
                prior_release_id=(
                    None
                    if current_manifest is None
                    else str(current_manifest["release_id"])
                ),
                prior_release_manifest_sha256=(
                    None
                    if current_manifest is None
                    else identity.identity_sha256(current_manifest)
                ),
                prior_read_versions=(
                    None
                    if prior_versions is None
                    else list(prior_versions["read"])
                ),
                prior_write_versions=(
                    None
                    if prior_versions is None
                    else list(prior_versions["write"])
                ),
            )
            seal = runtime.seal_database(
                attempt_id=workspace.attempt_id,
                nonce=workspace.nonce,
                operation=runtime_operation,
                database_name=database,
                state_identity_sha256=str(
                    latest["state_plan"]["state_identity_sha256"]  # type: ignore[index]
                ),
                compatibility_manifest=compatibility,
            )
            seals.append(
                {
                    "name": database,
                    "seal_sha256": seal.seal_sha256,
                    "compatibility_manifest_sha256": document["evidence_sha256"],
                }
            )
        state = _next_revision(latest, phase="state_expand_applied")
        state["database_seals"] = seals
        state["evidence_hashes"]["state_compatibility_sha256"] = state[  # type: ignore[index]
            "state_plan"
        ]["compatibility_sha256"]
        return self._persistence.journals.append(
            _seal(state, "journal_sha256"), lock=lock
        )

    def _compatibility_documents_from_journal(
        self,
        latest: Mapping[str, object],
        candidate_manifest: Mapping[str, object],
    ) -> tuple[Mapping[str, object], ...]:
        """Rebuild the exact immutable compatibility inputs for fresh replay."""

        operation = str(latest["operation"])
        current_manifest = (
            None
            if operation == "bootstrap_first_pair"
            else self._manifest(
                str(latest["original_pair"]["active"]["release_id"])  # type: ignore[index]
            )
        )
        documents = tuple(
            _build_compatibility_document(
                operation=operation,
                attempt_id=str(latest["attempt"]),
                nonce=str(latest["nonce"]),
                state_identity_sha256=str(
                    latest["state_plan"]["state_identity_sha256"]  # type: ignore[index]
                ),
                database_name=database,
                candidate=candidate_manifest,
                prior=current_manifest,
            )
            for database in DATABASE_ORDER
        )
        _, observed = validate_exact_release_compatibility_evidence_set(
            documents
        )
        if observed != latest["state_plan"]["compatibility_sha256"]:  # type: ignore[index]
            raise ExactDeploymentControllerError(
                "fresh replay compatibility material drifted"
            )
        return documents

    def _append_start_authorization(
        self,
        *,
        lock: CrashReleasedFileLock,
        latest: Mapping[str, object],
        role: str,
    ) -> Mapping[str, object]:
        phase = (
            "prior_start_authorized"
            if role == "prior"
            else "candidate_start_authorized"
        )
        reference = latest["candidate"]
        if role == "prior" and latest["operation"] == "activation":
            reference = latest["original_pair"]["active"]  # type: ignore[index]
        lease = ExactRuntimeLeaseIdentity(
            attempt_id=str(latest["attempt"]),
            nonce=str(latest["nonce"]),
            operation=str(latest["operation"]),
            role=role,
            start_nonce=secrets.token_hex(24),
            release_id=str(reference["release_id"]),
            manifest_sha256=str(reference["manifest_sha256"]),
            state_identity_sha256=str(
                latest["state_plan"]["state_identity_sha256"]  # type: ignore[index]
            ),
        )
        value = _next_revision(latest, phase=phase)
        starts = list(value["transient_start"])
        starts.append(
            {
                "role": role,
                "release": reference,
                "start_nonce": lease.start_nonce,
                "scm_identity_sha256": lease.scm_identity_sha256,
            }
        )
        value["transient_start"] = sorted(
            starts, key=lambda item: (str(item["role"]), str(item["release"]["release_id"]))
        )
        field = (
            "prior_start_authorization_sha256"
            if role == "prior"
            else "candidate_start_authorization_sha256"
        )
        value["evidence_hashes"][field] = lease.authorization_sha256  # type: ignore[index]
        return self._persistence.journals.append(
            _seal(value, "journal_sha256"), lock=lock
        )

    def _qualify_and_stop(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        role: str,
    ) -> LockedVerifiedPhaseCasAuthorization:
        authorization = self._persistence.lock_exact_transient_start_authorization(
            lock, workspace, role
        )
        closures = self._persistence.lock_exact_release_closures(lock, workspace)
        canary = ProductionExactRuntimeCanaryInputProducer.load_exact_d().produce(
            self._persistence, lock, workspace, authorization, closures
        )
        scm_input = self._persistence.bind_exact_scm_process_observation_input(
            lock, workspace, authorization, closures
        )
        started = False
        try:
            if self._service.start_exact_transient(authorization) is not True:
                raise ExactDeploymentControllerError(
                    "SCM rejected exact transient start"
                )
            started = True
            scm = ProductionWindowsScmProcessObserver.load_exact_d().observe(
                self._persistence, lock, workspace, scm_input
            )
            endpoint = ProductionWindowsEndpointObserver.load_exact_d().observe(scm)
            writer = ProductionWindowsWriterLeaseObserver.load_exact_d().observe(
                scm, endpoint
            )
            observation = (
                ProductionExactRuntimeCanaryLiveObserver.load_exact_d().observe(
                    canary, scm, endpoint, writer
                )
            )
            qualification = (
                ProductionLocalRuntimeQualificationProducer.load_exact_d().qualify(
                    observation
                )
            )
            revision = int(
                self._persistence.journals.replay(workspace.attempt_id)[-1][
                    "revision"
                ]
            )
            return self._persistence.consume_runtime_qualification_and_advance(
                lock, workspace, qualification, revision
            )
        finally:
            if started:
                self._service.stop_exact_transient()

    @staticmethod
    def _release_verified_resources(
        authorization: LockedVerifiedPhaseCasAuthorization,
    ) -> None:
        for source in authorization._state_sources:  # noqa: SLF001
            source.close()
        authorization._closures.close()  # noqa: SLF001

    def _finish_success(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
    ) -> Mapping[str, object]:
        latest = self._persistence.journals.replay(workspace.attempt_id)[-1]
        if latest["phase"] == "binding_cas_committed":
            verification = identity.identity_sha256(
                {
                    "attempt": latest["attempt"],
                    "target_pair": latest["target_pair"],
                    "prior_qualification": latest["evidence_hashes"][
                        "prior_runtime_qualification_sha256"
                    ],
                    "candidate_qualification": latest["evidence_hashes"][
                        "candidate_runtime_qualification_sha256"
                    ],
                    "pointer_cas": latest["evidence_hashes"][
                        "pointer_cas_observation_sha256"
                    ],
                    "binding_cas": latest["evidence_hashes"][
                        "binding_cas_observation_sha256"
                    ],
                }
            )
            rollback = latest["operation"] == "rollback"
            receipt: dict[str, object] = {
                "schema_version": (
                    identity.ROLLBACK_RECEIPT_SCHEMA
                    if rollback
                    else identity.ACTIVATION_RECEIPT_SCHEMA
                ),
                "receipt_id": latest["reserved_receipt_ids"][
                    "rollback" if rollback else "activation"
                ],
                "attempt_id": latest["attempt"],
                # The source revision is durable before receipt creation, so a
                # commit-success/journal-append-crash replay regenerates exact
                # canonical bytes rather than a new timestamp/hash.
                "recorded_at": latest["timestamps"]["updated_at"],
                "authority": "evidence_only",
                "operation": (
                    "rollback_to_prior" if rollback else "activate_successor"
                ),
                "pair": latest["target_pair"],
                "result": {
                    "status": "rolled_back" if rollback else "activated",
                    "pair_sha256": identity.identity_sha256(latest["target_pair"]),
                    "controller_verification_sha256": verification,
                },
            }
            receipt = dict(_seal(receipt, "receipt_sha256"))
            validated = (
                identity.validate_rollback_receipt(receipt)
                if rollback
                else identity.validate_activation_receipt(receipt)
            )
            self._persistence.commit_local_receipt(
                lock=lock, receipt=validated
            )
            terminal = _next_revision(
                latest, phase="terminal_receipt_committed"
            )
            terminal["evidence_hashes"][
                "controller_verification_sha256"
            ] = verification  # type: ignore[index]
            terminal["terminal_receipt"] = {
                "kind": "rollback" if rollback else "activation",
                "receipt_id": validated["receipt_id"],
                "receipt_sha256": validated["receipt_sha256"],
            }
            latest = self._persistence.journals.append(
                _seal(terminal, "journal_sha256"), lock=lock
            )
        if latest["phase"] == "terminal_receipt_committed":
            cleanup_authorized = _next_revision(
                latest, phase="cleanup_authorized"
            )
            cleanup_authorized["evidence_hashes"][
                "cleanup_authorization_sha256"
            ] = identity.identity_sha256(
                {
                    "attempt_id": latest["attempt"],
                    "terminal_receipt": latest["terminal_receipt"],
                    "cleanup_targets": latest["cleanup_targets"],
                }
            )
            latest = self._persistence.journals.append(
                _seal(cleanup_authorized, "journal_sha256"), lock=lock
            )
        if latest["phase"] == "cleanup_authorized":
            planned = _next_revision(latest, phase="cleanup_planned")
            latest = self._persistence.journals.append(
                _seal(planned, "journal_sha256"), lock=lock
            )
        if latest["phase"] == "cleanup_receipt_committed":
            return latest
        if latest["phase"] != "cleanup_planned":
            raise DeploymentJournalError(
                "success replay requires binding/terminal/cleanup phase"
            )
        receipt_values = tuple(
            record.value for record in self._persistence.read_local_receipts()
        )
        removed_targets = list(
            self._persistence.execute_retention_cleanup(
                lock=lock,
                receipts=receipt_values,
            )
        )
        if removed_targets != latest["cleanup_targets"]:
            raise ExactDeploymentControllerError(
                "executed cleanup targets differ from the durable journal"
            )
        cleanup: dict[str, object] = {
            "schema_version": identity.CLEANUP_RECEIPT_SCHEMA,
            "receipt_id": latest["reserved_receipt_ids"]["cleanup"],
            "attempt_id": latest["attempt"],
            "recorded_at": latest["timestamps"]["updated_at"],
            "authority": "evidence_only",
            "retained_pair": latest["target_pair"],
            "removed_targets": removed_targets,
            "result": {
                "status": "cleaned",
                "retained_pair_sha256": identity.identity_sha256(
                    latest["target_pair"]
                ),
                "removed_targets_sha256": identity.identity_sha256(
                    removed_targets
                ),
                "removed_count": len(removed_targets),
            },
        }
        cleanup = dict(_seal(cleanup, "receipt_sha256"))
        validated_cleanup = identity.validate_cleanup_receipt(cleanup)
        self._persistence.commit_local_receipt(
            lock=lock, receipt=validated_cleanup
        )
        closed = _next_revision(latest, phase="cleanup_receipt_committed")
        closed["evidence_hashes"]["cleanup_receipt_sha256"] = validated_cleanup[  # type: ignore[index]
            "receipt_sha256"
        ]
        closed["evidence_hashes"]["write_set_sha256"] = identity.identity_sha256(  # type: ignore[index]
            removed_targets
        )
        return self._persistence.journals.append(
            _seal(closed, "journal_sha256"), lock=lock
        )

    def _resume_verified_cas(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        role: str,
    ) -> None:
        """Replay a durable verified revision without reviving qualification."""

        closures = self._persistence.lock_exact_release_closures(
            lock, workspace
        )
        authorization: LockedVerifiedPhaseCasAuthorization | None = None
        try:
            authorization = (
                self._persistence.lock_verified_phase_cas_authorization(
                    lock, workspace, role, closures
                )
            )
            self._persistence.consume_verified_phase_next_cas(
                lock, workspace, authorization
            )
        finally:
            if authorization is not None:
                self._release_verified_resources(authorization)
            else:
                closures.close()

    def _ensure_steady(self, release: Mapping[str, object]) -> None:
        ensure = getattr(self._service, "ensure_steady_exact", None)
        if callable(ensure):
            if ensure(release) is not True:
                raise ExactDeploymentControllerError(
                    "exact steady service did not recover"
                )
            return
        if self._service.start_steady_exact() is not True:
            raise ExactDeploymentControllerError(
                "exact steady service did not start"
            )

    def _observe_bootstrap_boundary(self) -> Mapping[str, object]:
        observe = getattr(self._service, "observe_bootstrap_boundary", None)
        if not callable(observe):
            raise ExactDeploymentControllerError(
                "bootstrap service lacks a fixed boundary observer"
            )
        evidence = observe()
        if not isinstance(evidence, Mapping) or set(evidence) != {
            "schema_version",
            "ingress",
            "legacy_c_writer",
            "ingress_closed_sha256",
            "legacy_c_writer_fence_sha256",
            "evidence_sha256",
        }:
            raise ExactDeploymentControllerError(
                "bootstrap boundary evidence schema is not closed"
            )
        ingress = evidence["ingress"]
        legacy = evidence["legacy_c_writer"]
        unsigned = dict(evidence)
        claimed = unsigned.pop("evidence_sha256")
        if (
            evidence["schema_version"]
            != "qrh-bootstrap-boundary-observation/v1"
            or not isinstance(ingress, Mapping)
            or set(ingress)
            != {"scm_state", "listen_host", "port", "listener_pids"}
            or ingress["scm_state"] != "STOPPED"
            or ingress["listen_host"] != "0.0.0.0"
            or ingress["port"] != 8765
            or ingress["listener_pids"] != []
            or not isinstance(legacy, Mapping)
            or set(legacy) != {"legacy_roots", "process_pids", "status"}
            or legacy["legacy_roots"]
            != [r"C:\quant_platform", r"C:\quant_platform_data"]
            or legacy["process_pids"] != []
            or legacy["status"] != "fenced"
            or evidence["ingress_closed_sha256"]
            != identity.identity_sha256(ingress)
            or evidence["legacy_c_writer_fence_sha256"]
            != identity.identity_sha256(legacy)
            or claimed != identity.identity_sha256(unsigned)
        ):
            raise ExactDeploymentControllerError(
                "bootstrap boundary is not closed/fenced"
            )
        return evidence

    @staticmethod
    def _assert_request_matches_journal(
        latest: Mapping[str, object],
        *,
        release_id: str,
        expected_manifest_sha256: str,
    ) -> None:
        if (
            latest["operation"] != "activation"
            or latest["candidate"]["release_id"] != release_id  # type: ignore[index]
            or latest["candidate"]["manifest_sha256"]  # type: ignore[index]
            != expected_manifest_sha256
        ):
            raise ExactDeploymentControllerError(
                "requested candidate differs from durable attempt"
            )

    @staticmethod
    def _assert_rollback_journal(latest: Mapping[str, object]) -> None:
        if latest["operation"] != "rollback":
            raise ExactDeploymentControllerError(
                "requested rollback differs from durable attempt"
            )

    def _original_state_identity(
        self, latest: Mapping[str, object]
    ) -> Mapping[str, object]:
        if latest["operation"] == "bootstrap_first_pair":
            state = self._production_state_identity()
            if (
                state["identity_sha256"]
                != latest["state_plan"]["state_identity_sha256"]  # type: ignore[index]
            ):
                raise ExactDeploymentControllerError(
                    "bootstrap failure state identity differs from durable journal"
                )
            return state
        expected_binding = latest["binding_cas"]["expected_binding"]  # type: ignore[index]
        if expected_binding is not None:
            state = identity.validate_state_identity(
                expected_binding["state_identity"]
            )
        else:
            bootstraps = [
                record.value
                for record in self._persistence.read_local_receipts()
                if record.value.get("schema_version")
                == identity.ACTIVATION_RECEIPT_SCHEMA
                and record.value.get("operation") == "bootstrap_first_pair"
                and record.value.get("pair")
                == _pair(latest["original_pair"]["active"], None)  # type: ignore[index]
            ]
            if len(bootstraps) != 1:
                raise ExactDeploymentControllerError(
                    "failure restore cannot resolve the bootstrap state identity"
                )
            state = identity.validate_state_identity(
                bootstraps[0]["state_identity"]
            )
        if (
            state["identity_sha256"]
            != latest["state_plan"]["state_identity_sha256"]  # type: ignore[index]
        ):
            raise ExactDeploymentControllerError(
                "failure restore state identity differs from durable journal"
            )
        return state

    @staticmethod
    def _failure_observation(
        *,
        status: str,
        evidence_sha256: str,
        **details: object,
    ) -> Mapping[str, object]:
        observation: dict[str, object] = {
            "status": status,
            "evidence_sha256": evidence_sha256,
            **details,
        }
        return _seal(observation, "observation_sha256")

    def _commit_failure_terminal(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        restoration: Mapping[str, object],
        steady: Mapping[str, object],
    ) -> Mapping[str, object]:
        latest = self._persistence.journals.replay(workspace.attempt_id)[-1]
        if latest["phase"] in {
            "failure_receipt_committed",
            "terminal_receipt_committed",
            "cleanup_authorized",
            "cleanup_planned",
            "cleanup_receipt_committed",
        }:
            raise DeploymentJournalError(
                "failure terminal cannot replace an existing terminal"
            )
        if latest["operation"] == "bootstrap_first_pair":
            return self._commit_bootstrap_failure_terminal(
                lock=lock,
                workspace=workspace,
                restoration=restoration,
                boundary=steady,
            )
        original_active = latest["original_pair"]["active"]  # type: ignore[index]
        if set(steady) != {
            "schema_version",
            "scm_state",
            "release",
            "snapshot_id",
            "writer_authority",
            "endpoint_response_sha256",
            "evidence_sha256",
        }:
            raise ExactDeploymentControllerError(
                "failure recovery steady observation schema is not closed"
            )
        steady_unsigned = dict(steady)
        steady_hash = steady_unsigned.pop("evidence_sha256")
        if (
            steady["schema_version"]
            != "qrh-exact-steady-observation/v1"
            or steady["scm_state"] != "RUNNING"
            or steady["release"] != original_active
            or steady["writer_authority"] != "D-active"
            or identity.identity_sha256(steady_unsigned) != steady_hash
        ):
            raise ExactDeploymentControllerError(
                "failure recovery steady observation is not exact/live"
            )
        original_binding = latest["binding_cas"]["expected_binding"]  # type: ignore[index]
        original_pair = {
            "kind": "release_pair",
            "pair": latest["original_pair"],
        }
        state = self._original_state_identity(latest)
        writer_evidence_sha256 = identity.identity_sha256(
            {
                "steady_evidence_sha256": steady["evidence_sha256"],
                "writer_authority": steady["writer_authority"],
                "release": original_active,
            }
        )
        evidence = {
            "original_active_pointer_observation": self._failure_observation(
                status="original_active_restored",
                evidence_sha256=str(restoration["active_raw_sha256"]),
                observed_release=original_active,
            ),
            "original_local_prior_binding_observation": self._failure_observation(
                status=(
                    "absent"
                    if original_binding is None
                    else "original_binding_restored"
                ),
                evidence_sha256=str(restoration["binding_raw_sha256"]),
                observed_pair=(
                    None
                    if original_binding is None
                    else {
                        "active": original_binding["active"],
                        "prior": original_binding["prior"],
                    }
                ),
            ),
            "original_active_service_live_identity_observation": self._failure_observation(
                status="original_active_live",
                evidence_sha256=str(steady["evidence_sha256"]),
                observed_release=original_active,
            ),
            "original_active_writer_fence_observation": self._failure_observation(
                status="original_active_writer_fence_restored",
                evidence_sha256=writer_evidence_sha256,
                observed_release=original_active,
            ),
            "current_d_state_identity_observation": self._failure_observation(
                status="current_d_state_identity_unchanged",
                evidence_sha256=str(restoration["state_order_sha256"]),
                observed_state_identity=state,
            ),
        }
        receipt_id = str(latest["reserved_receipt_ids"]["failure"])  # type: ignore[index]
        existing = [
            record.value
            for record in self._persistence.read_local_receipts()
            if record.value.get("receipt_id") == receipt_id
        ]
        if len(existing) > 1:
            raise DeploymentJournalError(
                "failure receipt namespace contains duplicate reserved ID"
            )
        receipt_operation = (
            "rollback_to_prior"
            if latest["operation"] == "rollback"
            else "activate_successor"
        )
        if existing:
            receipt = identity.validate_failure_receipt(existing[0])
            if (
                receipt["attempt_id"] != latest["attempt"]
                or receipt["operation"] != receipt_operation
                or receipt["failed_phase"] != latest["phase"]
                or receipt["original_pair"] != original_pair
                or receipt["candidate"] != latest["candidate"]
                or receipt["original_state_identity"] != state
            ):
                raise DeploymentJournalError(
                    "existing failure receipt differs from durable attempt"
                )
        else:
            receipt_body: dict[str, object] = {
                "schema_version": identity.FAILURE_RECEIPT_SCHEMA,
                "receipt_id": receipt_id,
                "attempt_id": latest["attempt"],
                "recorded_at": latest["timestamps"]["updated_at"],
                "authority": "evidence_only",
                "operation": receipt_operation,
                "original_pair": original_pair,
                "original_state_identity": state,
                "candidate": latest["candidate"],
                "failed_phase": latest["phase"],
                "restoration_evidence": evidence,
                "result": {
                    "status": "failed",
                    "original_pair_sha256": identity.identity_sha256(
                        original_pair
                    ),
                    "original_state_identity_sha256": state[
                        "identity_sha256"
                    ],
                    "candidate_manifest_sha256": latest["candidate"][  # type: ignore[index]
                        "manifest_sha256"
                    ],
                    "restoration_evidence_sha256": identity.identity_sha256(
                        evidence
                    ),
                },
            }
            receipt = identity.validate_failure_receipt(
                _seal(receipt_body, "receipt_sha256")
            )
            self._persistence.commit_local_receipt(
                lock=lock, receipt=receipt
            )
        terminal = _next_revision(
            latest, phase="failure_receipt_committed"
        )
        terminal["timestamps"]["updated_at"] = latest["timestamps"][
            "updated_at"
        ]
        terminal["terminal_receipt"] = {
            "kind": "failure",
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
            "operation": receipt["operation"],
            "failed_phase": receipt["failed_phase"],
        }
        receipt_evidence = receipt["restoration_evidence"]
        for journal_field, receipt_field in {
            "failure_original_pointer_observation_sha256": "original_active_pointer_observation",
            "failure_original_binding_observation_sha256": "original_local_prior_binding_observation",
            "failure_original_service_observation_sha256": "original_active_service_live_identity_observation",
            "failure_original_writer_fence_observation_sha256": "original_active_writer_fence_observation",
            "failure_state_identity_observation_sha256": "current_d_state_identity_observation",
        }.items():
            terminal["evidence_hashes"][journal_field] = receipt_evidence[  # type: ignore[index]
                receipt_field
            ]["observation_sha256"]
        return self._persistence.journals.append(
            _seal(terminal, "journal_sha256"), lock=lock
        )

    def _commit_bootstrap_failure_terminal(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        restoration: Mapping[str, object],
        boundary: Mapping[str, object],
    ) -> Mapping[str, object]:
        latest = self._persistence.journals.replay(workspace.attempt_id)[-1]
        if (
            latest["operation"] != "bootstrap_first_pair"
            or latest["phase"] in {
                "failure_receipt_committed",
                "terminal_receipt_committed",
            }
            or restoration.get("active") is not None
            or restoration.get("binding") is not None
        ):
            raise DeploymentJournalError(
                "bootstrap failure terminal lacks restored absent controls"
            )
        # Revalidate the exact fixed observer shape without accepting booleans
        # or caller-authored status shortcuts.
        if not isinstance(boundary, Mapping) or set(boundary) != {
            "schema_version",
            "ingress",
            "legacy_c_writer",
            "ingress_closed_sha256",
            "legacy_c_writer_fence_sha256",
            "evidence_sha256",
        }:
            raise ExactDeploymentControllerError(
                "bootstrap failure boundary evidence is not closed"
            )
        unsigned_boundary = dict(boundary)
        boundary_hash = unsigned_boundary.pop("evidence_sha256")
        if (
            boundary["schema_version"]
            != "qrh-bootstrap-boundary-observation/v1"
            or boundary_hash != identity.identity_sha256(unsigned_boundary)
        ):
            raise ExactDeploymentControllerError(
                "bootstrap failure boundary evidence hash differs"
            )
        state = self._original_state_identity(latest)
        original_pair = {"kind": "bootstrap_no_d_pair", "pair": None}
        evidence = {
            "original_active_pointer_observation": self._failure_observation(
                status="absent",
                evidence_sha256=str(restoration["active_raw_sha256"]),
                observed_release=None,
            ),
            "original_local_prior_binding_observation": self._failure_observation(
                status="absent",
                evidence_sha256=str(restoration["binding_raw_sha256"]),
                observed_pair=None,
            ),
            "original_active_service_live_identity_observation": self._failure_observation(
                status="absent",
                evidence_sha256=str(boundary["ingress_closed_sha256"]),
                observed_release=None,
            ),
            "original_active_writer_fence_observation": self._failure_observation(
                status="d_writer_absent_or_fenced",
                evidence_sha256=str(boundary["evidence_sha256"]),
                observed_release=None,
            ),
            "current_d_state_identity_observation": self._failure_observation(
                status="d_state_not_externally_written",
                evidence_sha256=str(restoration["state_order_sha256"]),
                observed_state_identity=state,
            ),
        }
        receipt_body: dict[str, object] = {
            "schema_version": identity.FAILURE_RECEIPT_SCHEMA,
            "receipt_id": latest["reserved_receipt_ids"]["failure"],
            "attempt_id": latest["attempt"],
            "recorded_at": latest["timestamps"]["updated_at"],
            "authority": "evidence_only",
            "operation": "bootstrap_first_pair",
            "original_pair": original_pair,
            "original_state_identity": state,
            "candidate": latest["candidate"],
            "failed_phase": latest["phase"],
            "restoration_evidence": evidence,
            "result": {
                "status": "failed",
                "original_pair_sha256": identity.identity_sha256(original_pair),
                "candidate_manifest_sha256": latest["candidate"]["manifest_sha256"],
                "original_state_identity_sha256": state["identity_sha256"],
                "restoration_evidence_sha256": identity.identity_sha256(evidence),
            },
        }
        receipt = identity.validate_failure_receipt(
            _seal(receipt_body, "receipt_sha256")
        )
        self._persistence.commit_local_receipt(lock=lock, receipt=receipt)
        terminal = _next_revision(latest, phase="failure_receipt_committed")
        terminal["timestamps"]["updated_at"] = latest["timestamps"][
            "updated_at"
        ]
        terminal["terminal_receipt"] = {
            "kind": "failure",
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
            "operation": receipt["operation"],
            "failed_phase": receipt["failed_phase"],
        }
        for journal_field, receipt_field in {
            "failure_original_pointer_observation_sha256": "original_active_pointer_observation",
            "failure_original_binding_observation_sha256": "original_local_prior_binding_observation",
            "failure_original_service_observation_sha256": "original_active_service_live_identity_observation",
            "failure_original_writer_fence_observation_sha256": "original_active_writer_fence_observation",
            "failure_state_identity_observation_sha256": "current_d_state_identity_observation",
        }.items():
            terminal["evidence_hashes"][journal_field] = evidence[receipt_field][  # type: ignore[index]
                "observation_sha256"
            ]
        return self._persistence.journals.append(
            _seal(terminal, "journal_sha256"), lock=lock
        )

    def _is_first_post_bootstrap_activation(
        self, latest: Mapping[str, object]
    ) -> bool:
        if (
            latest["operation"] != "activation"
            or latest["original_pair"]["prior"] is not None  # type: ignore[index]
            or latest["binding_cas"]["expected_binding"] is not None  # type: ignore[index]
        ):
            return False
        expected_pair = latest["original_pair"]
        bootstraps = [
            record.value
            for record in self._persistence.read_local_receipts()
            if record.value.get("schema_version")
            == identity.ACTIVATION_RECEIPT_SCHEMA
            and record.value.get("operation") == "bootstrap_first_pair"
            and record.value.get("pair") == expected_pair
        ]
        if len(bootstraps) != 1:
            raise DeploymentJournalError(
                "first post-bootstrap activation lacks one exact R0 receipt"
            )
        return True

    def _commit_pre_ingress_activation_failure_terminal(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace,
        restoration: Mapping[str, object],
        boundary: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Close failed R0->R1 without ever authorizing single-R0 ingress."""

        latest = self._persistence.journals.replay(workspace.attempt_id)[-1]
        if not self._is_first_post_bootstrap_activation(latest):
            raise DeploymentJournalError(
                "pre-ingress failure terminal requires first R0 to R1 activation"
            )
        original_active = latest["original_pair"]["active"]  # type: ignore[index]
        if (
            restoration.get("active", {}).get("release") != original_active
            or restoration.get("binding") is not None
            or not isinstance(boundary, Mapping)
            or set(boundary)
            != {
                "schema_version",
                "ingress",
                "legacy_c_writer",
                "ingress_closed_sha256",
                "legacy_c_writer_fence_sha256",
                "evidence_sha256",
            }
        ):
            raise ExactDeploymentControllerError(
                "pre-ingress failure did not restore exact R0/null boundary"
            )
        unsigned_boundary = dict(boundary)
        boundary_hash = unsigned_boundary.pop("evidence_sha256")
        if (
            boundary["schema_version"]
            != "qrh-bootstrap-boundary-observation/v1"
            or boundary_hash != identity.identity_sha256(unsigned_boundary)
        ):
            raise ExactDeploymentControllerError(
                "pre-ingress failure boundary hash differs"
            )
        state = self._original_state_identity(latest)
        original_pair = {
            "kind": "release_pair",
            "pair": latest["original_pair"],
        }
        evidence = {
            "original_active_pointer_observation": self._failure_observation(
                status="original_active_restored",
                evidence_sha256=str(restoration["active_raw_sha256"]),
                observed_release=original_active,
            ),
            "original_local_prior_binding_observation": self._failure_observation(
                status="absent",
                evidence_sha256=str(restoration["binding_raw_sha256"]),
                observed_pair=None,
            ),
            "original_active_service_live_identity_observation": self._failure_observation(
                status="bootstrap_r0_ingress_closed",
                evidence_sha256=str(boundary["ingress_closed_sha256"]),
                observed_release=original_active,
            ),
            "original_active_writer_fence_observation": self._failure_observation(
                status="bootstrap_r0_writer_fenced",
                evidence_sha256=str(boundary["evidence_sha256"]),
                observed_release=original_active,
            ),
            "current_d_state_identity_observation": self._failure_observation(
                status="current_d_state_identity_unchanged",
                evidence_sha256=str(restoration["state_order_sha256"]),
                observed_state_identity=state,
            ),
        }
        receipt_id = str(latest["reserved_receipt_ids"]["failure"])  # type: ignore[index]
        existing = [
            record.value
            for record in self._persistence.read_local_receipts()
            if record.value.get("receipt_id") == receipt_id
        ]
        if len(existing) > 1:
            raise DeploymentJournalError(
                "pre-ingress failure receipt namespace contains duplicates"
            )
        if existing:
            receipt = identity.validate_failure_receipt(existing[0])
            if (
                receipt["attempt_id"] != latest["attempt"]
                or receipt["operation"] != "activate_successor"
                or receipt["failed_phase"] != latest["phase"]
                or receipt["original_pair"] != original_pair
                or receipt["candidate"] != latest["candidate"]
                or receipt["original_state_identity"] != state
                or receipt["restoration_evidence"] != evidence
            ):
                raise DeploymentJournalError(
                    "existing pre-ingress failure receipt differs"
                )
        else:
            receipt_body: dict[str, object] = {
                "schema_version": identity.FAILURE_RECEIPT_SCHEMA,
                "receipt_id": receipt_id,
                "attempt_id": latest["attempt"],
                "recorded_at": latest["timestamps"]["updated_at"],
                "authority": "evidence_only",
                "operation": "activate_successor",
                "original_pair": original_pair,
                "original_state_identity": state,
                "candidate": latest["candidate"],
                "failed_phase": latest["phase"],
                "restoration_evidence": evidence,
                "result": {
                    "status": "failed",
                    "original_pair_sha256": identity.identity_sha256(
                        original_pair
                    ),
                    "original_state_identity_sha256": state[
                        "identity_sha256"
                    ],
                    "candidate_manifest_sha256": latest["candidate"][  # type: ignore[index]
                        "manifest_sha256"
                    ],
                    "restoration_evidence_sha256": identity.identity_sha256(
                        evidence
                    ),
                },
            }
            receipt = identity.validate_failure_receipt(
                _seal(receipt_body, "receipt_sha256")
            )
            self._persistence.commit_local_receipt(lock=lock, receipt=receipt)
        terminal = _next_revision(latest, phase="failure_receipt_committed")
        terminal["timestamps"]["updated_at"] = latest["timestamps"][
            "updated_at"
        ]
        terminal["terminal_receipt"] = {
            "kind": "failure",
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
            "operation": receipt["operation"],
            "failed_phase": receipt["failed_phase"],
        }
        for journal_field, receipt_field in {
            "failure_original_pointer_observation_sha256": "original_active_pointer_observation",
            "failure_original_binding_observation_sha256": "original_local_prior_binding_observation",
            "failure_original_service_observation_sha256": "original_active_service_live_identity_observation",
            "failure_original_writer_fence_observation_sha256": "original_active_writer_fence_observation",
            "failure_state_identity_observation_sha256": "current_d_state_identity_observation",
        }.items():
            terminal["evidence_hashes"][journal_field] = evidence[receipt_field][  # type: ignore[index]
                "observation_sha256"
            ]
        return self._persistence.journals.append(
            _seal(terminal, "journal_sha256"), lock=lock
        )

    def _restore_and_commit_failure(
        self,
        *,
        lock: CrashReleasedFileLock,
        workspace: LockedAttemptWorkspace | None,
        attempt_id: str,
        cause: Exception,
    ) -> None:
        history = self._persistence.journals.histories().get(
            attempt_id.casefold()
        )
        if history is None:
            raise cause
        latest = history[-1]
        if latest["phase"] == "failure_receipt_committed":
            if latest["operation"] != "rollback":
                self._persistence.cleanup_failed_candidate(
                    lock=lock,
                    attempt_id=attempt_id,
                )
            raise ExactDeploymentControllerError(
                "deployment already failed after exact original pair restoration; "
                f"failure_receipt={latest['terminal_receipt']['receipt_id']}"  # type: ignore[index]
            ) from cause
        if latest["phase"] in {
            "terminal_receipt_committed",
            "cleanup_authorized",
            "cleanup_planned",
            "cleanup_receipt_committed",
        }:
            raise cause
        if latest["operation"] == "bootstrap_first_pair":
            selection = workspace
            if selection is None or selection._state == "closed":  # noqa: SLF001
                selection = self._persistence.bind_attempt_workspace(
                    lock, attempt_id, str(history[0]["nonce"])
                )
            try:
                self._persistence.commit_bootstrap_failure_authorization(
                    lock=lock,
                    workspace=selection,
                )
            finally:
                selection.close()
            stop = getattr(self._service, "stop_exact_transient", None)
            if not callable(stop):
                raise ExactDeploymentControllerError(
                    "bootstrap failure recovery lacks exact service stop"
                ) from cause
            stop()
            recovery = self._persistence.bind_attempt_workspace(
                lock, attempt_id, str(history[0]["nonce"])
            )
            try:
                first = self._persistence.restore_original_control_for_failure(
                    lock=lock, workspace=recovery
                )
                failure_authorization = (
                    self._persistence.read_bootstrap_failure_authorization(
                        lock=lock,
                        attempt_id=attempt_id,
                        nonce=str(history[0]["nonce"]),
                    )
                )
                if failure_authorization is None:
                    raise ExactDeploymentControllerError(
                        "bootstrap failure selection disappeared before reverse proof"
                    )
                if (
                    first["state_order_sha256"]
                    != failure_authorization["production_state_order_sha256"]
                ):
                    raise ExactDeploymentControllerError(
                        "bootstrap state drifted across failure selection/reverse CAS"
                    )
            finally:
                recovery.close()
            lock.release()
            boundary = self._observe_bootstrap_boundary()
            lock.acquire()
            recovery = self._persistence.bind_attempt_workspace(
                lock, attempt_id, str(history[0]["nonce"])
            )
            try:
                second = self._persistence.restore_original_control_for_failure(
                    lock=lock, workspace=recovery
                )
                if (
                    second["active_raw_sha256"] != first["active_raw_sha256"]
                    or second["binding_raw_sha256"]
                    != first["binding_raw_sha256"]
                    or second["state_order_sha256"]
                    != first["state_order_sha256"]
                ):
                    raise ExactDeploymentControllerError(
                        "bootstrap failure restoration drifted around boundary observation"
                    )
                terminal = self._commit_bootstrap_failure_terminal(
                    lock=lock,
                    workspace=recovery,
                    restoration=second,
                    boundary=boundary,
                )
            finally:
                recovery.close()
            lock.release()
            lock.acquire()
            self._persistence.cleanup_failed_candidate(
                lock=lock, attempt_id=attempt_id
            )
            raise ExactDeploymentControllerError(
                "bootstrap failed after exact absent-control restoration; "
                f"failure_receipt={terminal['terminal_receipt']['receipt_id']}"  # type: ignore[index]
            ) from cause
        selection = workspace
        if selection is None or selection._state == "closed":  # noqa: SLF001
            selection = self._persistence.bind_attempt_workspace(
                lock,
                attempt_id,
                str(history[0]["nonce"]),
            )
        try:
            self._persistence.commit_failure_selection_authorization(
                lock=lock,
                workspace=selection,
            )
        finally:
            selection.close()
        pre_ingress = self._is_first_post_bootstrap_activation(latest)
        recovery = self._persistence.bind_attempt_workspace(
            lock,
            attempt_id,
            str(history[0]["nonce"]),
        )
        try:
            first = self._persistence.restore_original_control_for_failure(
                lock=lock, workspace=recovery
            )
            if not pre_ingress:
                self._persistence.commit_failure_steady_recovery_authorization(
                    lock=lock,
                    workspace=recovery,
                    restoration=first,
                )
        finally:
            recovery.close()
        if pre_ingress:
            stop = getattr(self._service, "stop_exact_transient", None)
            if not callable(stop):
                raise ExactDeploymentControllerError(
                    "pre-ingress failure recovery lacks exact service stop"
                ) from cause
            stop()
            lock.release()
            boundary = self._observe_bootstrap_boundary()
            lock.acquire()
            recovery = self._persistence.bind_attempt_workspace(
                lock,
                attempt_id,
                str(history[0]["nonce"]),
            )
            try:
                second = self._persistence.restore_original_control_for_failure(
                    lock=lock, workspace=recovery
                )
                if (
                    second["active_raw_sha256"] != first["active_raw_sha256"]
                    or second["binding_raw_sha256"]
                    != first["binding_raw_sha256"]
                    or second["state_order_sha256"]
                    != first["state_order_sha256"]
                ):
                    raise ExactDeploymentControllerError(
                        "pre-ingress R0/null restoration drifted around boundary proof"
                    )
                terminal = self._commit_pre_ingress_activation_failure_terminal(
                    lock=lock,
                    workspace=recovery,
                    restoration=second,
                    boundary=boundary,
                )
            finally:
                recovery.close()
            lock.release()
            lock.acquire()
            self._persistence.cleanup_failed_candidate(
                lock=lock, attempt_id=attempt_id
            )
            raise ExactDeploymentControllerError(
                "first R0 to R1 activation failed with ingress still closed; "
                f"failure_receipt={terminal['terminal_receipt']['receipt_id']}"  # type: ignore[index]
            ) from cause
        lock.release()
        original_active = latest["original_pair"]["active"]  # type: ignore[index]
        self._ensure_steady(original_active)
        observe = getattr(self._service, "observe_steady_exact", None)
        if not callable(observe):
            raise ExactDeploymentControllerError(
                "failure recovery service lacks exact live observation"
            )
        steady = observe(original_active)
        lock.acquire()
        recovery = self._persistence.bind_attempt_workspace(
            lock,
            attempt_id,
            str(history[0]["nonce"]),
        )
        try:
            second = self._persistence.restore_original_control_for_failure(
                lock=lock, workspace=recovery
            )
            if (
                second["active_raw_sha256"] != first["active_raw_sha256"]
                or second["binding_raw_sha256"]
                != first["binding_raw_sha256"]
                or second["state_order_sha256"]
                != first["state_order_sha256"]
            ):
                raise ExactDeploymentControllerError(
                    "failure restoration control/state identity drifted around steady restart"
                )
            terminal = self._commit_failure_terminal(
                lock=lock,
                workspace=recovery,
                restoration=second,
                steady=steady,
            )
        finally:
            recovery.close()
        # Retire every attempt-workspace directory guard before the atomic
        # releases→quarantine rename.  The failure terminal is already durable;
        # a competing controller can only replay the same idempotent cleanup.
        lock.release()
        lock.acquire()
        if latest["operation"] != "rollback":
            self._persistence.cleanup_failed_candidate(
                lock=lock,
                attempt_id=attempt_id,
            )
        raise ExactDeploymentControllerError(
            "deployment failed after exact original pair restoration; "
            f"failure_receipt={terminal['terminal_receipt']['receipt_id']}"  # type: ignore[index]
        ) from cause

    def inspect_closed_bootstrap_baseline(
        self,
        *,
        release_id: str,
        expected_manifest_sha256: str,
    ) -> Mapping[str, object] | None:
        """Read one existing non-ingress R0 so a later handoff can resume."""

        self._assert_live_provenance()
        with self._persistence.global_lock() as lock:
            return self._persistence.inspect_closed_bootstrap_baseline(
                lock=lock,
                release_id=release_id,
                manifest_sha256=expected_manifest_sha256,
            )

    def activate_successor(
        self,
        *,
        release_id: str,
        expected_manifest_sha256: str,
        attempt_id: str,
    ) -> Mapping[str, object]:
        self._assert_live_provenance()
        lock = self._persistence.global_lock()
        workspace: LockedAttemptWorkspace | None = None
        failure_replay_selected = False
        lock.acquire()
        try:
            histories = self._persistence.journals.histories()
            history = histories.get(attempt_id.casefold())
            if history is None:
                nonce = secrets.token_hex(24)
                candidate = self._persistence.inspect_exact_incoming_candidate(
                    lock=lock,
                    release_id=release_id,
                    expected_manifest_sha256=expected_manifest_sha256,
                )
                intent, compatibility = self._initial_ordinary_journal(
                    lock=lock,
                    attempt=attempt_id,
                    nonce=nonce,
                    candidate_manifest=candidate,
                )
                latest = self._persistence.journals.append(intent, lock=lock)
            else:
                latest = history[-1]
                nonce = str(history[0]["nonce"])
                self._assert_request_matches_journal(
                    latest,
                    release_id=release_id,
                    expected_manifest_sha256=expected_manifest_sha256,
                )
                if latest["phase"] == "failure_receipt_committed":
                    self._persistence.cleanup_failed_candidate(
                        lock=lock, attempt_id=attempt_id
                    )
                    raise ExactDeploymentControllerError(
                        "durable attempt already ended in failure; "
                        f"failure_receipt={latest['terminal_receipt']['receipt_id']}"  # type: ignore[index]
                    )
                failure_selection = (
                    self._persistence.read_failure_selection_authorization(
                        lock=lock,
                        attempt_id=attempt_id,
                        nonce=nonce,
                    )
                )
                failure_recovery = (
                    self._persistence.read_failure_steady_recovery_authorization(
                        lock=lock,
                        attempt_id=attempt_id,
                        nonce=nonce,
                    )
                )
                if failure_selection is not None or failure_recovery is not None:
                    # Durable failure selection is a one-way authority boundary.
                    # A fresh controller may only finish original steady recovery,
                    # terminal evidence, and candidate cleanup; it must never
                    # re-enter qualification or either forward CAS.
                    failure_replay_selected = True
                    self._restore_and_commit_failure(
                        lock=lock,
                        workspace=None,
                        attempt_id=attempt_id,
                        cause=ExactDeploymentControllerError(
                            "durable failure recovery replay required"
                        ),
                    )
                if latest["phase"] == "intent_durable" and not (
                    self._persistence.layout.releases / release_id
                ).exists():
                    candidate = (
                        self._persistence.inspect_exact_incoming_candidate(
                            lock=lock,
                            release_id=release_id,
                            expected_manifest_sha256=(
                                expected_manifest_sha256
                            ),
                        )
                    )
                else:
                    candidate = self._manifest(release_id)
                compatibility = self._compatibility_documents_from_journal(
                    history[0], candidate
                )

            self._assert_request_matches_journal(
                latest,
                release_id=release_id,
                expected_manifest_sha256=expected_manifest_sha256,
            )
            if latest["phase"] == "failure_receipt_committed":
                raise ExactDeploymentControllerError(
                    "durable attempt already ended in failure"
                )
            if latest["phase"] == "intent_durable":
                finalized = self._persistence.finalize_exact_incoming_candidate(
                    lock=lock,
                    release_id=release_id,
                    expected_manifest_sha256=expected_manifest_sha256,
                )
                if finalized != candidate:
                    raise ExactDeploymentControllerError(
                        "candidate closure drifted after durable intent"
                    )
            workspace = self._persistence.bind_attempt_workspace(
                lock, attempt_id, nonce
            )
            latest = self._persistence.journals.replay(attempt_id)[-1]
            if latest["phase"] in {
                "intent_durable",
                "root_preflight_verified",
            }:
                latest = self._append_preflight_and_state(
                    lock=lock,
                    workspace=workspace,
                    latest=latest,
                    compatibility_documents=compatibility,
                    candidate_manifest=candidate,
                )
            if latest["phase"] == "state_expand_applied":
                latest = self._append_start_authorization(
                    lock=lock, latest=latest, role="prior"
                )
            if latest["phase"] == "prior_start_authorized":
                prior_verified = self._qualify_and_stop(
                    lock=lock, workspace=workspace, role="prior"
                )
                try:
                    self._persistence.consume_verified_phase_next_cas(
                        lock, workspace, prior_verified
                    )
                finally:
                    self._release_verified_resources(prior_verified)
                latest = self._persistence.journals.replay(attempt_id)[-1]
            elif latest["phase"] == "prior_verified":
                self._resume_verified_cas(
                    lock=lock, workspace=workspace, role="prior"
                )
                latest = self._persistence.journals.replay(attempt_id)[-1]
            if latest["phase"] == "pointer_cas_committed":
                latest = self._append_start_authorization(
                    lock=lock, latest=latest, role="candidate"
                )
            if latest["phase"] == "candidate_start_authorized":
                candidate_verified = self._qualify_and_stop(
                    lock=lock, workspace=workspace, role="candidate"
                )
                try:
                    self._persistence.consume_verified_phase_next_cas(
                        lock, workspace, candidate_verified
                    )
                finally:
                    self._release_verified_resources(candidate_verified)
                latest = self._persistence.journals.replay(attempt_id)[-1]
            elif latest["phase"] == "candidate_verified":
                self._resume_verified_cas(
                    lock=lock, workspace=workspace, role="candidate"
                )
                latest = self._persistence.journals.replay(attempt_id)[-1]
            if latest["phase"] not in {
                "binding_cas_committed",
                "terminal_receipt_committed",
                "cleanup_authorized",
                "cleanup_planned",
                "cleanup_receipt_committed",
            }:
                raise DeploymentJournalError(
                    f"unsupported replay phase: {latest['phase']}"
                )
            closed = self._finish_success(lock=lock, workspace=workspace)
            workspace.close()
            workspace = None
            lock.release()
            self._ensure_steady(closed["target_pair"]["active"])  # type: ignore[index]
            return {
                "schema_version": "qrh-vm-deploy-result/v2",
                "status": "activated",
                "release_id": release_id,
                "release_manifest_sha256": expected_manifest_sha256,
                "attempt_id": attempt_id,
                "terminal_journal_sha256": closed["journal_sha256"],
                "activation_receipt_id": closed["terminal_receipt"]["receipt_id"],  # type: ignore[index]
            }
        except Exception as error:
            if failure_replay_selected:
                raise
            self._restore_and_commit_failure(
                lock=lock,
                workspace=workspace,
                attempt_id=attempt_id,
                cause=error,
            )
        finally:
            if workspace is not None and workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def rollback_to_prior(
        self,
        *,
        attempt_id: str,
    ) -> Mapping[str, object]:
        """Swap only the currently bound active/prior pair on shared D state."""

        self._assert_live_provenance()
        lock = self._persistence.global_lock()
        workspace: LockedAttemptWorkspace | None = None
        failure_replay_selected = False
        lock.acquire()
        try:
            histories = self._persistence.journals.histories()
            history = histories.get(attempt_id.casefold())
            if history is None:
                nonce = secrets.token_hex(24)
                intent, compatibility, candidate = (
                    self._initial_rollback_journal(
                        lock=lock,
                        attempt=attempt_id,
                        nonce=nonce,
                    )
                )
                latest = self._persistence.journals.append(intent, lock=lock)
            else:
                latest = history[-1]
                nonce = str(history[0]["nonce"])
                self._assert_rollback_journal(latest)
                if latest["phase"] == "failure_receipt_committed":
                    raise ExactDeploymentControllerError(
                        "durable rollback attempt already ended in failure; "
                        f"failure_receipt={latest['terminal_receipt']['receipt_id']}"  # type: ignore[index]
                    )
                failure_selection = (
                    self._persistence.read_failure_selection_authorization(
                        lock=lock,
                        attempt_id=attempt_id,
                        nonce=nonce,
                    )
                )
                failure_recovery = (
                    self._persistence.read_failure_steady_recovery_authorization(
                        lock=lock,
                        attempt_id=attempt_id,
                        nonce=nonce,
                    )
                )
                if failure_selection is not None or failure_recovery is not None:
                    failure_replay_selected = True
                    self._restore_and_commit_failure(
                        lock=lock,
                        workspace=None,
                        attempt_id=attempt_id,
                        cause=ExactDeploymentControllerError(
                            "durable rollback failure recovery replay required"
                        ),
                    )
                candidate = self._manifest(
                    str(latest["candidate"]["release_id"])  # type: ignore[index]
                )
                if _release_ref(candidate) != latest["candidate"]:
                    raise ExactDeploymentControllerError(
                        "retained rollback target differs from durable attempt"
                    )
                compatibility = self._compatibility_documents_from_journal(
                    history[0], candidate
                )

            self._assert_rollback_journal(latest)
            if latest["phase"] == "failure_receipt_committed":
                raise ExactDeploymentControllerError(
                    "durable rollback attempt already ended in failure"
                )
            workspace = self._persistence.bind_attempt_workspace(
                lock, attempt_id, nonce
            )
            latest = self._persistence.journals.replay(attempt_id)[-1]
            if latest["phase"] in {
                "intent_durable",
                "root_preflight_verified",
            }:
                latest = self._append_preflight_and_state(
                    lock=lock,
                    workspace=workspace,
                    latest=latest,
                    compatibility_documents=compatibility,
                    candidate_manifest=candidate,
                )
            if latest["phase"] == "state_expand_applied":
                latest = self._append_start_authorization(
                    lock=lock, latest=latest, role="prior"
                )
            if latest["phase"] == "prior_start_authorized":
                prior_verified = self._qualify_and_stop(
                    lock=lock, workspace=workspace, role="prior"
                )
                try:
                    self._persistence.consume_verified_phase_next_cas(
                        lock, workspace, prior_verified
                    )
                finally:
                    self._release_verified_resources(prior_verified)
                latest = self._persistence.journals.replay(attempt_id)[-1]
            elif latest["phase"] == "prior_verified":
                self._resume_verified_cas(
                    lock=lock, workspace=workspace, role="prior"
                )
                latest = self._persistence.journals.replay(attempt_id)[-1]
            if latest["phase"] == "pointer_cas_committed":
                latest = self._append_start_authorization(
                    lock=lock, latest=latest, role="candidate"
                )
            if latest["phase"] == "candidate_start_authorized":
                candidate_verified = self._qualify_and_stop(
                    lock=lock, workspace=workspace, role="candidate"
                )
                try:
                    self._persistence.consume_verified_phase_next_cas(
                        lock, workspace, candidate_verified
                    )
                finally:
                    self._release_verified_resources(candidate_verified)
                latest = self._persistence.journals.replay(attempt_id)[-1]
            elif latest["phase"] == "candidate_verified":
                self._resume_verified_cas(
                    lock=lock, workspace=workspace, role="candidate"
                )
                latest = self._persistence.journals.replay(attempt_id)[-1]
            if latest["phase"] not in {
                "binding_cas_committed",
                "terminal_receipt_committed",
                "cleanup_authorized",
                "cleanup_planned",
                "cleanup_receipt_committed",
            }:
                raise DeploymentJournalError(
                    f"unsupported rollback replay phase: {latest['phase']}"
                )
            closed = self._finish_success(lock=lock, workspace=workspace)
            workspace.close()
            workspace = None
            lock.release()
            target = closed["target_pair"]["active"]  # type: ignore[index]
            self._ensure_steady(target)
            return {
                "schema_version": "qrh-vm-deploy-result/v2",
                "status": "rolled_back",
                "release_id": target["release_id"],
                "release_manifest_sha256": target["manifest_sha256"],
                "attempt_id": attempt_id,
                "terminal_journal_sha256": closed["journal_sha256"],
                "rollback_receipt_id": closed["terminal_receipt"]["receipt_id"],  # type: ignore[index]
            }
        except Exception as error:
            if failure_replay_selected:
                raise
            self._restore_and_commit_failure(
                lock=lock,
                workspace=workspace,
                attempt_id=attempt_id,
                cause=error,
            )
        finally:
            if workspace is not None and workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()

    def bootstrap_first_pair(
        self,
        *,
        release_id: str,
        expected_manifest_sha256: str,
        attempt_id: str,
    ) -> Mapping[str, object]:
        """Build the sole R0/null lineage without opening steady ingress."""

        self._assert_live_provenance()
        lock = self._persistence.global_lock()
        workspace: LockedAttemptWorkspace | None = None
        verified: LockedVerifiedPhaseCasAuthorization | None = None
        failure_replay_selected = False
        lock.acquire()
        try:
            histories = self._persistence.journals.histories()
            history = histories.get(attempt_id.casefold())
            if history is None:
                nonce = secrets.token_hex(24)
                candidate = self._persistence.inspect_exact_incoming_candidate(
                    lock=lock,
                    release_id=release_id,
                    expected_manifest_sha256=expected_manifest_sha256,
                )
                intent, compatibility = self._initial_bootstrap_journal(
                    lock=lock,
                    attempt=attempt_id,
                    nonce=nonce,
                    candidate_manifest=candidate,
                )
                latest = self._persistence.journals.append(intent, lock=lock)
            else:
                latest = history[-1]
                nonce = str(history[0]["nonce"])
                if (
                    latest["operation"] != "bootstrap_first_pair"
                    or latest["candidate"]["release_id"] != release_id
                    or latest["candidate"]["manifest_sha256"]
                    != expected_manifest_sha256
                ):
                    raise ExactDeploymentControllerError(
                        "requested R0 differs from durable bootstrap attempt"
                    )
                if latest["phase"] == "failure_receipt_committed":
                    self._persistence.cleanup_failed_candidate(
                        lock=lock, attempt_id=attempt_id
                    )
                    raise ExactDeploymentControllerError(
                        "durable bootstrap attempt already ended in failure; "
                        f"failure_receipt={latest['terminal_receipt']['receipt_id']}"  # type: ignore[index]
                    )
                failure_authorization = (
                    self._persistence.read_bootstrap_failure_authorization(
                        lock=lock,
                        attempt_id=attempt_id,
                        nonce=nonce,
                    )
                )
                if failure_authorization is not None:
                    failure_replay_selected = True
                    self._restore_and_commit_failure(
                        lock=lock,
                        workspace=None,
                        attempt_id=attempt_id,
                        cause=ExactDeploymentControllerError(
                            "durable bootstrap failure replay required"
                        ),
                    )
                if latest["phase"] == "intent_durable" and not (
                    self._persistence.layout.releases / release_id
                ).exists():
                    candidate = self._persistence.inspect_exact_incoming_candidate(
                        lock=lock,
                        release_id=release_id,
                        expected_manifest_sha256=expected_manifest_sha256,
                    )
                else:
                    candidate = self._manifest(release_id)
                compatibility = self._compatibility_documents_from_journal(
                    history[0], candidate
                )
            if latest["phase"] == "failure_receipt_committed":
                raise ExactDeploymentControllerError(
                    "durable bootstrap attempt already ended in failure"
                )
            if latest["phase"] == "intent_durable":
                finalized = self._persistence.finalize_exact_incoming_candidate(
                    lock=lock,
                    release_id=release_id,
                    expected_manifest_sha256=expected_manifest_sha256,
                )
                if finalized != candidate:
                    raise ExactDeploymentControllerError(
                        "R0 closure drifted after durable bootstrap intent"
                    )
            workspace = self._persistence.bind_attempt_workspace(
                lock, attempt_id, nonce
            )
            latest = self._persistence.journals.replay(attempt_id)[-1]
            if latest["phase"] in {"intent_durable", "root_preflight_verified"}:
                latest = self._append_preflight_and_state(
                    lock=lock,
                    workspace=workspace,
                    latest=latest,
                    compatibility_documents=compatibility,
                    candidate_manifest=candidate,
                )
            if latest["phase"] == "state_expand_applied":
                self._persistence.commit_bootstrap_pointer_cas(
                    lock=lock, workspace=workspace
                )
                latest = self._persistence.journals.replay(attempt_id)[-1]
            if latest["phase"] == "pointer_cas_committed":
                latest = self._append_start_authorization(
                    lock=lock, latest=latest, role="baseline"
                )
            if latest["phase"] == "candidate_start_authorized":
                verified = self._qualify_and_stop(
                    lock=lock, workspace=workspace, role="baseline"
                )
                latest = self._persistence.journals.replay(attempt_id)[-1]
            elif latest["phase"] == "candidate_verified":
                closures = self._persistence.lock_exact_release_closures(
                    lock, workspace
                )
                try:
                    verified = self._persistence.lock_verified_phase_cas_authorization(
                        lock, workspace, "baseline", closures
                    )
                except BaseException:
                    closures.close()
                    raise
            if latest["phase"] == "candidate_verified":
                if verified is None:
                    raise ExactDeploymentControllerError(
                        "bootstrap verified phase lacks its live qualification"
                    )
                boundary = self._observe_bootstrap_boundary()
                try:
                    latest = self._persistence.consume_bootstrap_terminal(
                        lock=lock,
                        workspace=workspace,
                        authorization=verified,
                        state_identity=self._production_state_identity(),
                        ingress_closed_sha256=str(
                            boundary["ingress_closed_sha256"]
                        ),
                        legacy_c_writer_fence_sha256=str(
                            boundary["legacy_c_writer_fence_sha256"]
                        ),
                    )
                finally:
                    self._release_verified_resources(verified)
                    verified = None
            if latest["phase"] != "terminal_receipt_committed":
                raise DeploymentJournalError(
                    f"unsupported bootstrap replay phase: {latest['phase']}"
                )
            workspace.close()
            workspace = None
            lock.release()
            return {
                "schema_version": "qrh-vm-bootstrap-result/v1",
                "status": "bootstrapped",
                "release_id": release_id,
                "release_manifest_sha256": expected_manifest_sha256,
                "attempt_id": attempt_id,
                "terminal_journal_sha256": latest["journal_sha256"],
                "activation_receipt_id": latest["terminal_receipt"]["receipt_id"],
                "ingress_status": "closed",
            }
        except Exception as error:
            if verified is not None:
                self._release_verified_resources(verified)
                verified = None
            if failure_replay_selected:
                raise
            self._restore_and_commit_failure(
                lock=lock,
                workspace=workspace,
                attempt_id=attempt_id,
                cause=error,
            )
        finally:
            if verified is not None:
                self._release_verified_resources(verified)
            if workspace is not None and workspace._state != "closed":  # noqa: SLF001
                workspace.close()
            if lock.held:
                lock.release()


__all__ = [
    "ExactDeploymentControllerError",
    "ProductionExactDeploymentController",
]
