"""Stage 5/6 closure identities and non-destructive recovery plans.

This module deliberately contains no VM, GitHub, Task Scheduler, service, or
filesystem mutation entry point.  Producers only assemble closed canonical
documents from already-created evidence identities; verifiers fail closed on
missing, additional, reordered, or self-asserted evidence.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Callable, Mapping, Protocol, Sequence

from quant_hub.config import ensure_no_reparse_components

from .failure_domain import (
    FailureDomainError,
    verify_host_facts,
    verify_independence_probe,
)
from .release_identity import (
    canonical_manifest_bytes,
    manifest_sha256,
    validate_checkpoint_manifest,
    validate_receipt,
    validate_recovery_manifest,
    validate_release_manifest,
)


STAGE5_CERTIFICATE_SCHEMA = "qrh-stage5-release-certificate/v3"
VISIBILITY_CLOSURE_SCHEMA = "qrh-visibility-closure-receipt/v3"
MEASURED_PRIOR_SCHEMA = "qrh-measured-prior-release/v2"
ACTIVE_D_DRILL_PLAN_SCHEMA = "qrh-active-d-maintenance-drill-plan/v1"
RECOVERY_FINALIZE_PLAN_SCHEMA = "qrh-recovery-finalize-plan/v1"
REPOSITORY_OBSERVATION_SCHEMA = "qrh-repository-public-observation/v1"
D_PRIOR_ROLLBACK_SCHEMA = "qrh-d-prior-rollback-receipt/v1"
VISIBILITY_EVIDENCE_SCHEMA = "qrh-visibility-evidence/v1"

PRODUCTION_TARGET = "10.5.1.240"
PRODUCTION_VM_ROOT = r"D:\quant\quant_platform"
STATE_ONLY_TASK_IDENTITY = r"\QuantResearchHub\StateOnlyBackup"

STAGE5_REQUIRED_GATES = (
    "stage0_4_prerequisites",
    "stage5_6_1_global_replay",
    "stage5_6_2_failure_paths",
    "stage5_6_3_snapshot_identity",
    "stage5_6_4_independent_verifier",
    "stage5_6_5_state_compatibility",
    "stage5_6_6_final_cold_recovery",
    "stage5_6_7_gc_roots",
    "stage5_6_8_quality_report",
    "stage5_6_9_state_only_backup",
    "stage5_6_10_identity_graph",
)
STAGE5_REQUIRED_RUNBOOKS = (
    "cold_recovery",
    "state_only_backup",
    "writer_handoff",
)
RECOVERY_FINALIZE_REQUIRED_EVIDENCE = (
    "materialization_event",
    "closure_verification",
    "state_restore",
    "service_start",
    "web_api",
    "search_mcp",
    "writer_fence",
    "write_set_audit",
    "active_identity",
    "independent_verifier",
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,179}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_REPOSITORY = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})"
)
_LOCATOR = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,239}")
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024

_FIXED_ARTIFACT_LOCATORS = {
    "d_prior_rollback_receipt": "stage5/d_prior/rollback_receipt.json",
    "repository_observation": "stage5/repository_public_observation.json",
    "release_manifest": "stage5/release_manifest.json",
    "measured_prior_binding": "state-only/control/measured_prior_release.json",
    "recovery_manifest": "stage5/final_recovery/recovery_manifest.json",
    "checkpoint_manifest": "stage5/final_recovery/checkpoint_manifest.json",
    "failure_domain_attestation": "stage5/final_recovery/failure_domain_attestation.json",
    "recovery_receipt": "stage5/final_recovery/recovery_receipt.json",
    "task_candidate": "state-only/control/scheduled_task_candidate.json",
    "task_inspection": "state-only/control/scheduled_task_inspection.json",
    "task_authority": "state-only/control/scheduled_task_authority.json",
    "stage5_certificate": "stage5/stage5_release_certificate.json",
    **{kind: f"stage5/gates/{kind}.json" for kind in STAGE5_REQUIRED_GATES},
    **{kind: f"runbooks/{kind}.md" for kind in STAGE5_REQUIRED_RUNBOOKS},
    **{
        kind: f"visibility/{kind}.json"
        for kind in (
            "repository_private_transition", "private_controls", "private_ci",
            "candidate_validation", "no_switch", "visibility_independent_verifier",
        )
    },
}


class EvidenceArtifactResolver(Protocol):
    """Read immutable evidence bytes from one pre-authorized authority."""

    def read_bytes(self, locator: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class DirectoryEvidenceResolver:
    """Read-only resolver confined to one fixed non-reparse evidence root."""

    root: Path

    def read_bytes(self, locator: str) -> bytes:
        safe = _artifact_locator(locator)
        unresolved_root = Path(self.root)
        unresolved_target = unresolved_root.joinpath(*safe.split("/"))
        try:
            ensure_no_reparse_components(unresolved_root)
            ensure_no_reparse_components(unresolved_target)
            root = unresolved_root.resolve(strict=True)
            target = unresolved_target.resolve(strict=True)
        except (OSError, ValueError) as error:
            raise StageClosureError("evidence artifact path is not a strict path") from error
        if target == root or root not in target.parents or not target.is_file():
            raise StageClosureError("evidence artifact escapes its fixed authority root")
        if target.is_symlink():
            raise StageClosureError("evidence artifact cannot be a symlink")
        try:
            # Open the resolved directory entry once, then compare both the open
            # handle and the path before and after the read.  A path-only check
            # accepts a hardlink to a mutable file outside the authority root;
            # resolve-then-read also leaves a replacement race.  Stage evidence
            # is therefore restricted to a regular, single-link, stable file.
            with target.open("rb") as handle:
                before_handle = os.fstat(handle.fileno())
                before_path = target.stat(follow_symlinks=False)
                _require_same_single_link_file(
                    before_handle, before_path, label="evidence artifact before read"
                )
                payload = handle.read(_MAX_ARTIFACT_BYTES + 1)
                after_handle = os.fstat(handle.fileno())
                after_path = target.stat(follow_symlinks=False)
                _require_same_single_link_file(
                    after_handle, after_path, label="evidence artifact after read"
                )
                if _file_observation(before_handle) != _file_observation(after_handle):
                    raise StageClosureError("evidence artifact changed while being read")
                if _file_observation(before_path) != _file_observation(after_path):
                    raise StageClosureError("evidence artifact path identity changed while being read")
                if _file_identity(after_handle) != _file_identity(after_path):
                    raise StageClosureError("evidence artifact path no longer names the opened file")
        except OSError as error:
            raise StageClosureError("evidence artifact is unreadable") from error
        if not 0 < len(payload) <= _MAX_ARTIFACT_BYTES:
            raise StageClosureError("evidence artifact size is outside the contract")
        return payload


class StageClosureError(RuntimeError):
    """A Stage 5/6 evidence identity is incomplete or inconsistent."""


def _file_identity(value: os.stat_result) -> tuple[int, int]:
    return int(value.st_dev), int(value.st_ino)


def _file_observation(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        *_file_identity(value),
        int(value.st_nlink),
        int(value.st_size),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


def _require_same_single_link_file(
    handle_stat: os.stat_result, path_stat: os.stat_result, *, label: str
) -> None:
    if (
        not stat.S_ISREG(handle_stat.st_mode)
        or not stat.S_ISREG(path_stat.st_mode)
        or int(handle_stat.st_nlink) != 1
        or int(path_stat.st_nlink) != 1
        or _file_identity(handle_stat) != _file_identity(path_stat)
    ):
        raise StageClosureError(f"{label} is not one stable single-link regular file")


def _mapping(value: object, fields: set[str], *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != fields:
        raise StageClosureError(f"{label} schema is not closed")
    return value


def _artifact_locator(value: object) -> str:
    if (
        not isinstance(value, str)
        or _LOCATOR.fullmatch(value) is None
        or "\\" in value
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise StageClosureError("evidence artifact locator is not fixed and relative")
    return value


def artifact_ref(*, kind: str, locator: str, raw_bytes: bytes) -> Mapping[str, object]:
    """Build a locator reference; authority bytes remain outside the receipt."""

    if not isinstance(raw_bytes, bytes) or not 0 < len(raw_bytes) <= _MAX_ARTIFACT_BYTES:
        raise StageClosureError("evidence artifact bytes are outside the contract")
    _identifier(kind, label="artifact kind")
    return {
        "kind": kind,
        "locator": _artifact_locator(locator),
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    }


def _artifact_ref(value: object, *, expected_kind: str) -> Mapping[str, object]:
    reference = _mapping(
        value, {"kind", "locator", "sha256"}, label=f"{expected_kind} artifact ref"
    )
    if reference["kind"] != expected_kind:
        raise StageClosureError(f"{expected_kind} artifact kind differs")
    locator = _artifact_locator(reference["locator"])
    expected_locator = _FIXED_ARTIFACT_LOCATORS.get(expected_kind)
    if expected_locator is None or locator != expected_locator:
        raise StageClosureError(f"{expected_kind} artifact locator differs")
    _sha(reference["sha256"], label=f"{expected_kind} artifact hash")
    return reference


def _artifact_bytes(
    value: object, *, expected_kind: str, resolver: EvidenceArtifactResolver
) -> tuple[Mapping[str, object], bytes]:
    reference = _artifact_ref(value, expected_kind=expected_kind)
    try:
        raw = resolver.read_bytes(str(reference["locator"]))
    except StageClosureError:
        raise
    except Exception as error:
        raise StageClosureError(f"{expected_kind} artifact cannot be resolved") from error
    if not isinstance(raw, bytes) or not 0 < len(raw) <= _MAX_ARTIFACT_BYTES:
        raise StageClosureError(f"{expected_kind} artifact bytes are invalid")
    if hashlib.sha256(raw).hexdigest() != reference["sha256"]:
        raise StageClosureError(f"{expected_kind} artifact raw hash differs")
    return reference, raw


def _json_artifact(
    value: object,
    *,
    expected_kind: str,
    resolver: EvidenceArtifactResolver,
    verifier: Callable[[object], Mapping[str, object]],
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    reference, raw = _artifact_bytes(
        value, expected_kind=expected_kind, resolver=resolver
    )
    try:
        document = json.loads(raw.decode("utf-8"))
        if canonical_manifest_bytes(document) != raw:
            raise StageClosureError(f"{expected_kind} artifact is not canonical JSON")
        verified = verifier(document)
    except StageClosureError:
        raise
    except Exception as error:
        raise StageClosureError(f"{expected_kind} artifact failed verification") from error
    if not isinstance(verified, Mapping):
        raise StageClosureError(f"{expected_kind} verifier returned no object")
    return reference, verified


def _text_artifact(
    value: object, *, expected_kind: str, resolver: EvidenceArtifactResolver
) -> Mapping[str, object]:
    reference, raw = _artifact_bytes(
        value, expected_kind=expected_kind, resolver=resolver
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise StageClosureError(f"{expected_kind} runbook is not UTF-8") from error
    if not text or text.startswith("\ufeff") or "\x00" in text:
        raise StageClosureError(f"{expected_kind} runbook bytes are invalid")
    return reference


def _identifier(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None or ".." in value:
        raise StageClosureError(f"{label} is not a stable ID")
    return value


def _sha(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise StageClosureError(f"{label} is not lowercase SHA-256")
    return value


def _commit(value: object) -> str:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise StageClosureError("commit_sha is not a full lowercase Git SHA")
    return value


def _timestamp(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise StageClosureError(f"{label} is not a timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise StageClosureError(f"{label} is not a timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise StageClosureError(f"{label} must be timezone-aware")
    parsed.astimezone(UTC)
    return value


def _moment(value: object, *, label: str) -> datetime:
    return datetime.fromisoformat(_timestamp(value, label=label).replace("Z", "+00:00"))


def _ordered(*moments: datetime, label: str) -> None:
    normalized = [value.astimezone(UTC) for value in moments]
    if normalized != sorted(normalized):
        raise StageClosureError(f"{label} chronology differs")


def _evidence(value: object, *, expected_kind: str) -> Mapping[str, object]:
    evidence = _mapping(
        value,
        {"kind", "evidence_id", "sha256", "observed_at", "verdict"},
        label=f"{expected_kind} evidence",
    )
    if evidence["kind"] != expected_kind or evidence["verdict"] != "pass":
        raise StageClosureError(f"{expected_kind} evidence did not pass")
    _identifier(evidence["evidence_id"], label=f"{expected_kind}.evidence_id")
    _sha(evidence["sha256"], label=f"{expected_kind}.sha256")
    _timestamp(evidence["observed_at"], label=f"{expected_kind}.observed_at")
    return evidence


def _evidence_sequence(
    value: object, *, expected_kinds: Sequence[str], label: str
) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or len(value) != len(expected_kinds):
        raise StageClosureError(f"{label} does not contain the required evidence set")
    result = [
        _evidence(item, expected_kind=kind)
        for item, kind in zip(value, expected_kinds, strict=True)
    ]
    identities = [str(item["evidence_id"]) for item in result]
    if len(set(identities)) != len(identities):
        raise StageClosureError(f"{label} evidence IDs are not unique")
    return result


def _release(value: object, *, label: str, with_snapshot: bool) -> Mapping[str, object]:
    fields = {"release_id", "manifest_sha256"}
    if with_snapshot:
        fields.add("snapshot_id")
    release = _mapping(value, fields, label=label)
    _identifier(release["release_id"], label=f"{label}.release_id")
    _sha(release["manifest_sha256"], label=f"{label}.manifest_sha256")
    if with_snapshot:
        _identifier(release["snapshot_id"], label=f"{label}.snapshot_id")
    return release


def _verify_document_hash(
    document: Mapping[str, object], *, hash_field: str, label: str
) -> str:
    claimed = _sha(document.get(hash_field), label=f"{label}.{hash_field}")
    material = dict(document)
    del material[hash_field]
    if manifest_sha256(material) != claimed:
        raise StageClosureError(f"{label} hash differs")
    canonical_manifest_bytes(document)
    return claimed


def _verify_repository_observation(value: object) -> Mapping[str, object]:
    document = _mapping(
        value,
        {
            "schema_version", "observation_id", "observed_at", "repository_id",
            "full_name", "visibility", "head_sha", "evidence_sha256",
        },
        label="repository observation",
    )
    if document["schema_version"] != REPOSITORY_OBSERVATION_SCHEMA:
        raise StageClosureError("repository observation schema differs")
    for field in ("observation_id", "repository_id"):
        _identifier(document[field], label=f"repository observation {field}")
    if (
        not isinstance(document["full_name"], str)
        or _REPOSITORY.fullmatch(document["full_name"]) is None
        or document["visibility"] != "public"
    ):
        raise StageClosureError("repository observation is not Public")
    _commit(document["head_sha"])
    _timestamp(document["observed_at"], label="repository observed_at")
    _verify_document_hash(document, hash_field="evidence_sha256", label="repository observation")
    return document


def _verify_failure_domain_attestation(value: object) -> Mapping[str, object]:
    document = _mapping(
        value,
        {
            "schema_version", "observed_at", "production_host_facts_sha256",
            "recovery_host_facts_sha256", "production", "recovery",
            "independence_probe", "verdict",
        },
        label="failure-domain attestation",
    )
    if (
        document["schema_version"] != "qrh-recovery-failure-domain-attestation/v1"
        or document["verdict"] != "independent_failure_domain"
    ):
        raise StageClosureError("failure-domain attestation verdict differs")
    try:
        production = verify_host_facts(document["production"], expected_role="production")
        recovery = verify_host_facts(document["recovery"], expected_role="recovery")
        verify_independence_probe(document["independence_probe"])
    except (FailureDomainError, TypeError) as error:
        raise StageClosureError("failure-domain attestation facts failed") from error
    if (
        production["facts_sha256"] != document["production_host_facts_sha256"]
        or recovery["facts_sha256"] != document["recovery_host_facts_sha256"]
        or production["machine_identity"] == recovery["machine_identity"]
        or production["storage_authority"] == recovery["storage_authority"]
        or recovery["reparse_or_symlink"] is not False
        or recovery["path_kind"] != "local"
    ):
        raise StageClosureError("failure-domain attestation is not independent")
    _timestamp(document["observed_at"], label="failure-domain observed_at")
    return document


def verify_failure_domain_attestation(value: object) -> Mapping[str, object]:
    """Public categorical verifier shared by Scheduler and Stage 5."""

    return _verify_failure_domain_attestation(value)


def _verify_rollback_receipt(value: object) -> Mapping[str, object]:
    document = _mapping(
        value,
        {
            "schema_version", "receipt_id", "observed_at", "authority",
            "active_release", "prior_release", "verification", "receipt_sha256",
        },
        label="D-prior rollback receipt",
    )
    if (
        document["schema_version"] != D_PRIOR_ROLLBACK_SCHEMA
        or document["authority"] != "evidence_only"
    ):
        raise StageClosureError("D-prior rollback receipt identity differs")
    _identifier(document["receipt_id"], label="D-prior rollback receipt_id")
    _timestamp(document["observed_at"], label="D-prior rollback observed_at")
    active = _release(document["active_release"], label="rollback active", with_snapshot=False)
    prior = _release(document["prior_release"], label="rollback prior", with_snapshot=False)
    if (
        active["release_id"] == prior["release_id"]
        or active["manifest_sha256"] == prior["manifest_sha256"]
    ):
        raise StageClosureError("D-prior rollback identities are not distinct")
    verification = _mapping(
        document["verification"],
        {"prior_activated", "health", "writer_fence", "active_restored"},
        label="D-prior rollback verification",
    )
    if any(verification[field] is not True for field in verification):
        raise StageClosureError("D-prior rollback verification did not pass")
    _verify_document_hash(document, hash_field="receipt_sha256", label="D-prior rollback receipt")
    return document


# A Stage 5 certificate is a production claim, so a generic ``status=pass``
# envelope is never a gate verifier.  Each future entry must name the concrete
# canonical producer artifact and replay its public verifier.  Until every
# required gate has such an entry the certificate is intentionally unavailable.
_STAGE_GATE_ARTIFACT_VERIFIERS: Mapping[
    str, Callable[[object, EvidenceArtifactResolver], Mapping[str, object]]
] = {}


def _verify_stage_gate(
    value: object, *, expected_kind: str, resolver: EvidenceArtifactResolver
) -> Mapping[str, object]:
    if expected_kind not in STAGE5_REQUIRED_GATES:
        raise StageClosureError("Stage 5 gate kind is unknown")
    verifier = _STAGE_GATE_ARTIFACT_VERIFIERS.get(expected_kind)
    if verifier is None:
        raise StageClosureError(
            f"{expected_kind} has no registered canonical producer/verifier; "
            "generic self-reported gate evidence is forbidden"
        )
    verified = verifier(value, resolver)
    if not isinstance(verified, Mapping):
        raise StageClosureError(f"{expected_kind} concrete verifier returned no object")
    return verified


def build_measured_prior_binding(
    *,
    observed_at: str,
    rollback_receipt_ref: Mapping[str, object],
    resolver: EvidenceArtifactResolver,
) -> Mapping[str, object]:
    reference, rollback = _json_artifact(
        rollback_receipt_ref,
        expected_kind="d_prior_rollback_receipt",
        resolver=resolver,
        verifier=_verify_rollback_receipt,
    )
    body: dict[str, object] = {
        "schema_version": MEASURED_PRIOR_SCHEMA,
        "observed_at": observed_at,
        "authority": "retention_evidence_only",
        "active_release": dict(rollback["active_release"]),
        "prior_release": dict(rollback["prior_release"]),
        "rollback_receipt_ref": dict(reference),
    }
    body["measurement_id"] = "measured-prior-" + manifest_sha256(body)[:32]
    body["binding_sha256"] = manifest_sha256(body)
    return verify_measured_prior_binding(body, resolver=resolver)


def verify_measured_prior_binding(
    value: object, *, resolver: EvidenceArtifactResolver
) -> Mapping[str, object]:
    binding = _mapping(
        value,
        {
            "schema_version", "measurement_id", "observed_at", "authority",
            "active_release", "prior_release", "rollback_receipt_ref", "binding_sha256",
        },
        label="measured prior binding",
    )
    if (
        binding["schema_version"] != MEASURED_PRIOR_SCHEMA
        or binding["authority"] != "retention_evidence_only"
    ):
        raise StageClosureError("measured prior binding identity differs")
    observed = _moment(binding["observed_at"], label="measured prior observed_at")
    active = _release(binding["active_release"], label="active_release", with_snapshot=False)
    prior = _release(binding["prior_release"], label="prior_release", with_snapshot=False)
    if (
        active["release_id"] == prior["release_id"]
        or active["manifest_sha256"] == prior["manifest_sha256"]
    ):
        raise StageClosureError("measured prior must have distinct ID and manifest")
    _, rollback = _json_artifact(
        binding["rollback_receipt_ref"],
        expected_kind="d_prior_rollback_receipt",
        resolver=resolver,
        verifier=_verify_rollback_receipt,
    )
    if rollback["active_release"] != active or rollback["prior_release"] != prior:
        raise StageClosureError("measured prior differs from rollback receipt")
    _ordered(
        _moment(rollback["observed_at"], label="rollback observed_at"),
        observed,
        label="D-prior measurement",
    )
    expected_id_material = dict(binding)
    expected_id_material.pop("measurement_id")
    expected_id_material.pop("binding_sha256")
    expected_id = "measured-prior-" + manifest_sha256(expected_id_material)[:32]
    if binding["measurement_id"] != expected_id:
        raise StageClosureError("measured prior ID is not derived from verified evidence")
    _verify_document_hash(binding, hash_field="binding_sha256", label="measured prior binding")
    return binding


_STAGE_ARTIFACT_KINDS = {
    "repository_observation": "repository_observation",
    "release_manifest": "release_manifest",
    "measured_prior_binding": "measured_prior_binding",
    "recovery_manifest": "recovery_manifest",
    "checkpoint_manifest": "checkpoint_manifest",
    "failure_domain_attestation": "failure_domain_attestation",
    "recovery_receipt": "recovery_receipt",
    "task_candidate": "task_candidate",
    "task_inspection": "task_inspection",
}


def _stage_certificate_material(
    *, artifact_refs: Mapping[str, object], gate_evidence: Sequence[Mapping[str, object]],
    runbook_evidence: Sequence[Mapping[str, object]], issued_at: str,
    resolver: EvidenceArtifactResolver,
) -> dict[str, object]:
    refs = _mapping(artifact_refs, set(_STAGE_ARTIFACT_KINDS), label="Stage 5 artifact refs")
    repo_ref, repo = _json_artifact(refs["repository_observation"], expected_kind="repository_observation", resolver=resolver, verifier=_verify_repository_observation)
    release_ref, release_manifest = _json_artifact(refs["release_manifest"], expected_kind="release_manifest", resolver=resolver, verifier=validate_release_manifest)
    measured_ref, measured = _json_artifact(
        refs["measured_prior_binding"], expected_kind="measured_prior_binding", resolver=resolver,
        verifier=lambda item: verify_measured_prior_binding(item, resolver=resolver),
    )
    recovery_ref, recovery_manifest = _json_artifact(refs["recovery_manifest"], expected_kind="recovery_manifest", resolver=resolver, verifier=validate_recovery_manifest)
    checkpoint_ref, checkpoint = _json_artifact(refs["checkpoint_manifest"], expected_kind="checkpoint_manifest", resolver=resolver, verifier=validate_checkpoint_manifest)
    failure_ref, failure = _json_artifact(refs["failure_domain_attestation"], expected_kind="failure_domain_attestation", resolver=resolver, verifier=_verify_failure_domain_attestation)
    receipt_ref, receipt = _json_artifact(refs["recovery_receipt"], expected_kind="recovery_receipt", resolver=resolver, verifier=validate_receipt)
    from .state_only_backup import validate_task_candidate, validate_task_inspection_artifact
    task_ref, task = _json_artifact(refs["task_candidate"], expected_kind="task_candidate", resolver=resolver, verifier=validate_task_candidate)
    inspection_ref, inspection = _json_artifact(
        refs["task_inspection"], expected_kind="task_inspection", resolver=resolver,
        verifier=lambda item: validate_task_inspection_artifact(item, candidate=task),
    )

    release_hash = str(release_ref["sha256"])
    checkpoint_hash = str(checkpoint_ref["sha256"])
    recovery_hash = str(recovery_ref["sha256"])
    release_id = str(release_manifest["release_id"])
    commit_sha = str(release_manifest["application"]["commit_sha"])
    snapshot_id = str(release_manifest["content"]["snapshot_id"])
    release = {"release_id": release_id, "manifest_sha256": release_hash, "snapshot_id": snapshot_id}
    prior = measured["prior_release"]
    if measured["active_release"] != {"release_id": release_id, "manifest_sha256": release_hash}:
        raise StageClosureError("measured prior does not bind final active release")
    if recovery_manifest["release"] != {"release_id": release_id, "manifest_sha256": release_hash}:
        raise StageClosureError("recovery manifest does not bind final release")
    if recovery_manifest["checkpoint"] != {"checkpoint_id": checkpoint["checkpoint_id"], "manifest_sha256": checkpoint_hash}:
        raise StageClosureError("recovery manifest does not bind final checkpoint")
    if checkpoint["captured_under_active_release"] != {"release_id": release_id, "manifest_sha256": release_hash}:
        raise StageClosureError("final checkpoint was not captured under final release")
    if (
        receipt.get("receipt_type") != "recovery"
        or receipt["release_manifest_sha256"] != release_hash
        or receipt["recovery_manifest_sha256"] != recovery_hash
        or receipt["checkpoint_manifest_sha256"] != checkpoint_hash
    ):
        raise StageClosureError("recovery receipt triple differs")
    if failure["independence_probe"]["release_id"] != release_id or failure["independence_probe"]["release_manifest_sha256"] != release_hash or failure["independence_probe"]["bundle_id"] != recovery_manifest["bundle_id"]:
        raise StageClosureError("failure-domain attestation differs from recovery bundle")
    if inspection["status"] != "exact" or inspection["contract_sha256"] != task["contract_sha256"]:
        raise StageClosureError("state-only task inspection is not exact")
    if task["host_binding"]["failure_domain_attestation_sha256"] != failure_ref["sha256"]:
        raise StageClosureError("state-only task belongs to another attested host")
    expected_task_repository = {
        "repository_id": repo["repository_id"],
        "full_name": repo["full_name"],
        "commit_sha": commit_sha,
        "tracked_tree_sha256": release_manifest["application"]["tracked_tree_sha256"],
    }
    if task["repository_binding"] != expected_task_repository:
        raise StageClosureError("state-only task repository/commit binding differs")
    if task["release_binding"] != release:
        raise StageClosureError("state-only task release binding differs")

    expected_subject = {
        "repository_id": repo["repository_id"], "commit_sha": commit_sha,
        "release_id": release_id, "release_manifest_sha256": release_hash,
        "snapshot_id": snapshot_id,
    }
    if not isinstance(gate_evidence, Sequence) or len(gate_evidence) != len(STAGE5_REQUIRED_GATES):
        raise StageClosureError("Stage 5 gate set differs")
    verified_gates: list[Mapping[str, object]] = []
    gate_times: list[datetime] = []
    for reference, kind in zip(gate_evidence, STAGE5_REQUIRED_GATES, strict=True):
        normalized_ref, gate = _json_artifact(
            reference, expected_kind=kind, resolver=resolver,
            verifier=lambda item, current=kind: _verify_stage_gate(
                item, expected_kind=current, resolver=resolver
            ),
        )
        if gate["subject"] != expected_subject:
            raise StageClosureError(f"{kind} gate subject differs")
        verified_gates.append(normalized_ref)
        gate_times.append(_moment(gate["observed_at"], label=f"{kind} observed_at"))
        if kind == "stage5_6_6_final_cold_recovery" and gate["bindings"] != {
            "failure_domain_attestation_sha256": failure_ref["sha256"],
            "recovery_manifest_sha256": recovery_hash,
            "checkpoint_manifest_sha256": checkpoint_hash,
            "recovery_receipt_sha256": receipt_ref["sha256"],
        }:
            raise StageClosureError("final cold recovery gate bindings differ")
        if kind == "stage5_6_7_gc_roots" and gate["bindings"]["measured_prior_binding_sha256"] != measured_ref["sha256"]:
            raise StageClosureError("GC roots gate does not bind measured prior")
        if kind == "stage5_6_9_state_only_backup" and gate["bindings"] != {
            "task_candidate_sha256": task_ref["sha256"],
            "task_inspection_sha256": inspection_ref["sha256"],
        }:
            raise StageClosureError("state-only task gate bindings differ")
    if gate_times != sorted(gate_times):
        raise StageClosureError("Stage 5 gate DAG is not chronological")
    gate_time = dict(zip(STAGE5_REQUIRED_GATES, gate_times, strict=True))
    _ordered(
        _moment(release_manifest["built_at"], label="release built_at"),
        _moment(checkpoint["captured_at"], label="checkpoint captured_at"),
        _moment(recovery_manifest["created_at"], label="recovery created_at"),
        _moment(receipt["recorded_at"], label="recovery receipt recorded_at"),
        gate_time["stage5_6_6_final_cold_recovery"],
        label="final recovery DAG",
    )
    _ordered(
        _moment(failure["observed_at"], label="failure-domain observed_at"),
        gate_time["stage5_6_6_final_cold_recovery"],
        label="failure-domain DAG",
    )
    _ordered(
        _moment(measured["observed_at"], label="measured prior observed_at"),
        gate_time["stage5_6_7_gc_roots"],
        label="measured-prior DAG",
    )
    _ordered(
        _moment(inspection["observed_at"], label="task inspection observed_at"),
        gate_time["stage5_6_9_state_only_backup"],
        label="Scheduler acceptance DAG",
    )
    _ordered(
        _moment(repo["observed_at"], label="repository observed_at"),
        gate_times[0],
        label="repository observation DAG",
    )
    issued = _moment(issued_at, label="Stage 5 issued_at")
    dependencies = [
        _moment(repo["observed_at"], label="repository observed_at"),
        _moment(release_manifest["built_at"], label="release built_at"),
        _moment(checkpoint["captured_at"], label="checkpoint captured_at"),
        _moment(recovery_manifest["created_at"], label="recovery created_at"),
        _moment(receipt["recorded_at"], label="recovery receipt recorded_at"),
        _moment(failure["observed_at"], label="failure-domain observed_at"),
        _moment(measured["observed_at"], label="measured prior observed_at"),
        _moment(inspection["observed_at"], label="task inspection observed_at"),
        *gate_times,
    ]
    if any(moment.astimezone(UTC) > issued.astimezone(UTC) for moment in dependencies):
        raise StageClosureError("Stage 5 certificate predates verified dependency")
    if not isinstance(runbook_evidence, Sequence) or len(runbook_evidence) != len(STAGE5_REQUIRED_RUNBOOKS):
        raise StageClosureError("Stage 5 runbook set differs")
    runbooks = [
        _text_artifact(reference, expected_kind=kind, resolver=resolver)
        for reference, kind in zip(runbook_evidence, STAGE5_REQUIRED_RUNBOOKS, strict=True)
    ]
    return {
        "schema_version": STAGE5_CERTIFICATE_SCHEMA,
        "issued_at": issued_at,
        "authority": "evidence_only",
        "repository": {
            "repository_id": repo["repository_id"], "full_name": repo["full_name"],
            "visibility": "public", "observation_sha256": repo_ref["sha256"],
        },
        "commit_sha": commit_sha,
        "release": release,
        "d_prior": {
            **dict(prior), "measurement_binding_sha256": measured_ref["sha256"],
            "rollback_receipt_sha256": measured["rollback_receipt_ref"]["sha256"],
        },
        "final_recovery": {
            "bundle_id": recovery_manifest["bundle_id"], "recovery_manifest_sha256": recovery_hash,
            "checkpoint_id": checkpoint["checkpoint_id"], "checkpoint_manifest_sha256": checkpoint_hash,
            "failure_domain_attestation_sha256": failure_ref["sha256"],
            "recovery_receipt_id": receipt["receipt_id"], "recovery_receipt_sha256": receipt_ref["sha256"],
        },
        "state_only_task": {
            "task_identity": task["task_identity"], "contract_sha256": task["contract_sha256"],
            "task_xml_sha256": inspection["task_xml_sha256"], "inspection_sha256": inspection_ref["sha256"],
            "authority_sha256": task["authority_ref"]["sha256"],
            "project_root": task["action"]["project_root"],
            "config_path": task["action"]["arguments"][6],
            "config_sha256": task["action"]["config_sha256"],
            "operational_root": task["action"]["operational_root"],
            "executable_sha256": task["action"]["executable_sha256"],
            "recovery_root": task["host_binding"]["recovery_root"],
            "failure_domain_attestation_path": task["host_binding"]["failure_domain_attestation_path"],
        },
        "artifact_refs": {key: dict(refs[key]) for key in _STAGE_ARTIFACT_KINDS},
        "gate_evidence": [dict(item) for item in verified_gates],
        "runbook_evidence": [dict(item) for item in runbooks],
    }


def build_stage5_release_certificate(
    *, issued_at: str, artifact_refs: Mapping[str, object],
    gate_evidence: Sequence[Mapping[str, object]], runbook_evidence: Sequence[Mapping[str, object]],
    resolver: EvidenceArtifactResolver,
) -> Mapping[str, object]:
    value = _stage_certificate_material(
        artifact_refs=artifact_refs, gate_evidence=gate_evidence,
        runbook_evidence=runbook_evidence, issued_at=issued_at, resolver=resolver,
    )
    value["certificate_id"] = "stage5-" + manifest_sha256(value)[:32]
    value["certificate_sha256"] = manifest_sha256(value)
    return verify_stage5_release_certificate(value, resolver=resolver)


def verify_stage5_release_certificate(
    value: object, *, resolver: EvidenceArtifactResolver
) -> Mapping[str, object]:
    certificate = _mapping(
        value,
        {
            "schema_version", "certificate_id", "issued_at", "authority", "repository",
            "commit_sha", "release", "d_prior", "final_recovery", "state_only_task",
            "artifact_refs", "gate_evidence", "runbook_evidence", "certificate_sha256",
        },
        label="Stage 5 release certificate",
    )
    material = _stage_certificate_material(
        artifact_refs=certificate["artifact_refs"], gate_evidence=certificate["gate_evidence"],
        runbook_evidence=certificate["runbook_evidence"], issued_at=str(certificate["issued_at"]),
        resolver=resolver,
    )
    for key, expected in material.items():
        if certificate[key] != expected:
            raise StageClosureError(f"Stage 5 derived field differs: {key}")
    expected_id = "stage5-" + manifest_sha256(material)[:32]
    if certificate["certificate_id"] != expected_id:
        raise StageClosureError("Stage 5 certificate ID is not derived")
    _verify_document_hash(certificate, hash_field="certificate_sha256", label="Stage 5 certificate")
    return certificate


_VISIBILITY_KINDS = (
    "repository_private_transition", "private_controls", "private_ci",
    "candidate_validation", "no_switch", "visibility_independent_verifier",
)


def _verify_visibility_evidence(value: object, *, expected_kind: str) -> Mapping[str, object]:
    document = _mapping(
        value,
        {
            "schema_version", "evidence_id", "kind", "observed_at", "status",
            "repository", "commit_sha", "release", "payload", "evidence_sha256",
        },
        label=f"{expected_kind} visibility evidence",
    )
    if document["schema_version"] != VISIBILITY_EVIDENCE_SCHEMA or document["kind"] != expected_kind or document["status"] != "pass":
        raise StageClosureError(f"{expected_kind} visibility evidence did not pass")
    _identifier(document["evidence_id"], label=f"{expected_kind} evidence_id")
    _timestamp(document["observed_at"], label=f"{expected_kind} observed_at")
    repository = _mapping(document["repository"], {"repository_id", "full_name"}, label=f"{expected_kind} repository")
    _identifier(repository["repository_id"], label=f"{expected_kind} repository_id")
    if not isinstance(repository["full_name"], str) or _REPOSITORY.fullmatch(repository["full_name"]) is None:
        raise StageClosureError(f"{expected_kind} repository name differs")
    _commit(document["commit_sha"])
    release = _release(document["release"], label=f"{expected_kind} release", with_snapshot=True)
    payload_fields = {
        "repository_private_transition": {"visibility_before", "visibility_after"},
        "private_controls": {"plan_sha256", "actions_sha256", "branch_protection_sha256", "environment_protection_sha256", "publish_permission_sha256", "verdict"},
        "private_ci": {"run_id", "head_sha", "conclusion"},
        "candidate_validation": {"deployment_mode", "event_id", "status"},
        "no_switch": {"active_before", "active_after", "activation_receipt_set_sha256_before", "activation_receipt_set_sha256_after", "writer_authority_sha256_before", "writer_authority_sha256_after"},
        "visibility_independent_verifier": {"verifier_id", "verdict"},
    }[expected_kind]
    payload = _mapping(document["payload"], payload_fields, label=f"{expected_kind} payload")
    if expected_kind == "repository_private_transition" and payload != {"visibility_before": "public", "visibility_after": "private"}:
        raise StageClosureError("repository did not transition Public to Private")
    elif expected_kind == "private_controls":
        if payload["verdict"] != "pass": raise StageClosureError("private controls failed")
        for key in payload:
            if key != "verdict": _sha(payload[key], label=f"private controls {key}")
    elif expected_kind == "private_ci":
        _identifier(payload["run_id"], label="private CI run_id")
        if payload["head_sha"] != document["commit_sha"] or payload["conclusion"] != "success": raise StageClosureError("private CI exact SHA failed")
    elif expected_kind == "candidate_validation":
        _identifier(payload["event_id"], label="candidate event_id")
        if payload["deployment_mode"] != "candidate_only" or payload["status"] != "candidate_validated": raise StageClosureError("candidate validation switched authority")
    elif expected_kind == "no_switch":
        before = _release(payload["active_before"], label="active_before", with_snapshot=True)
        after = _release(payload["active_after"], label="active_after", with_snapshot=True)
        if before != release or after != release: raise StageClosureError("candidate changed active release")
        for left, right in (("activation_receipt_set_sha256_before", "activation_receipt_set_sha256_after"), ("writer_authority_sha256_before", "writer_authority_sha256_after")):
            _sha(payload[left], label=left); _sha(payload[right], label=right)
            if payload[left] != payload[right]: raise StageClosureError("candidate changed authority evidence")
    elif expected_kind == "visibility_independent_verifier":
        _identifier(payload["verifier_id"], label="visibility verifier_id")
        if payload["verdict"] != "pass": raise StageClosureError("visibility independent verifier failed")
    _verify_document_hash(document, hash_field="evidence_sha256", label=f"{expected_kind} evidence")
    return document


def _visibility_material(
    *, stage5_certificate_ref: Mapping[str, object], evidence_refs: Sequence[Mapping[str, object]],
    recorded_at: str, resolver: EvidenceArtifactResolver,
) -> dict[str, object]:
    certificate_ref, certificate = _json_artifact(
        stage5_certificate_ref, expected_kind="stage5_certificate", resolver=resolver,
        verifier=lambda item: verify_stage5_release_certificate(item, resolver=resolver),
    )
    if not isinstance(evidence_refs, Sequence) or len(evidence_refs) != len(_VISIBILITY_KINDS):
        raise StageClosureError("visibility evidence set differs")
    expected_repo = {"repository_id": certificate["repository"]["repository_id"], "full_name": certificate["repository"]["full_name"]}
    verified_refs: list[Mapping[str, object]] = []
    times: list[datetime] = []
    for reference, kind in zip(evidence_refs, _VISIBILITY_KINDS, strict=True):
        normalized_ref, evidence = _json_artifact(reference, expected_kind=kind, resolver=resolver, verifier=lambda item, current=kind: _verify_visibility_evidence(item, expected_kind=current))
        if evidence["repository"] != expected_repo or evidence["commit_sha"] != certificate["commit_sha"] or evidence["release"] != certificate["release"]:
            raise StageClosureError(f"{kind} visibility subject differs from certificate")
        verified_refs.append(normalized_ref)
        times.append(_moment(evidence["observed_at"], label=f"{kind} observed_at"))
    if times != sorted(times):
        raise StageClosureError("visibility evidence DAG is not chronological")
    recorded = _moment(recorded_at, label="visibility recorded_at")
    if _moment(certificate["issued_at"], label="certificate issued_at").astimezone(UTC) > times[0].astimezone(UTC) or any(moment.astimezone(UTC) > recorded.astimezone(UTC) for moment in times):
        raise StageClosureError("visibility closure predates a dependency")
    return {
        "schema_version": VISIBILITY_CLOSURE_SCHEMA,
        "recorded_at": recorded_at,
        "authority": "evidence_only",
        "repository": {**expected_repo, "visibility_before": "public", "visibility_after": "private"},
        "commit_sha": certificate["commit_sha"],
        "release": dict(certificate["release"]),
        "stage5_certificate_ref": dict(certificate_ref),
        "evidence_refs": [dict(item) for item in verified_refs],
    }


def build_visibility_closure_receipt(
    *, recorded_at: str, stage5_certificate_ref: Mapping[str, object],
    evidence_refs: Sequence[Mapping[str, object]], resolver: EvidenceArtifactResolver,
) -> Mapping[str, object]:
    value = _visibility_material(stage5_certificate_ref=stage5_certificate_ref, evidence_refs=evidence_refs, recorded_at=recorded_at, resolver=resolver)
    value["receipt_id"] = "visibility-" + manifest_sha256(value)[:32]
    value["receipt_sha256"] = manifest_sha256(value)
    return verify_visibility_closure_receipt(value, resolver=resolver)


def verify_visibility_closure_receipt(
    value: object, *, resolver: EvidenceArtifactResolver
) -> Mapping[str, object]:
    receipt = _mapping(
        value,
        {"schema_version", "receipt_id", "recorded_at", "authority", "repository", "commit_sha", "release", "stage5_certificate_ref", "evidence_refs", "receipt_sha256"},
        label="visibility closure receipt",
    )
    material = _visibility_material(
        stage5_certificate_ref=receipt["stage5_certificate_ref"], evidence_refs=receipt["evidence_refs"],
        recorded_at=str(receipt["recorded_at"]), resolver=resolver,
    )
    for key, expected in material.items():
        if receipt[key] != expected: raise StageClosureError(f"visibility derived field differs: {key}")
    expected_id = "visibility-" + manifest_sha256(material)[:32]
    if receipt["receipt_id"] != expected_id: raise StageClosureError("visibility receipt ID is not derived")
    _verify_document_hash(receipt, hash_field="receipt_sha256", label="visibility receipt")
    return receipt


def _legacy_build_measured_prior_binding(
    *,
    measurement_id: str,
    observed_at: str,
    active_release: Mapping[str, object],
    prior_release: Mapping[str, object],
    rollback_evidence: Mapping[str, object],
) -> Mapping[str, object]:
    raise StageClosureError("self-reported measured-prior v1 producer is removed")
    value: dict[str, object] = {
        "schema_version": MEASURED_PRIOR_SCHEMA,
        "measurement_id": measurement_id,
        "observed_at": observed_at,
        "authority": "retention_evidence_only",
        "active_release": dict(active_release),
        "prior_release": dict(prior_release),
        "rollback_evidence": dict(rollback_evidence),
    }
    value["binding_sha256"] = manifest_sha256(value)
    return verify_measured_prior_binding(value)


def _legacy_verify_measured_prior_binding(value: object) -> Mapping[str, object]:
    raise StageClosureError("self-reported measured-prior v1 verifier is removed")
    binding = _mapping(
        value,
        {
            "schema_version",
            "measurement_id",
            "observed_at",
            "authority",
            "active_release",
            "prior_release",
            "rollback_evidence",
            "binding_sha256",
        },
        label="measured prior binding",
    )
    if (
        binding["schema_version"] != MEASURED_PRIOR_SCHEMA
        or binding["authority"] != "retention_evidence_only"
    ):
        raise StageClosureError("measured prior binding identity differs")
    _identifier(binding["measurement_id"], label="measurement_id")
    _timestamp(binding["observed_at"], label="observed_at")
    active = _release(binding["active_release"], label="active_release", with_snapshot=False)
    prior = _release(binding["prior_release"], label="prior_release", with_snapshot=False)
    if active == prior:
        raise StageClosureError("measured prior must differ from active release")
    _evidence(binding["rollback_evidence"], expected_kind="d_prior_rollback")
    _verify_document_hash(binding, hash_field="binding_sha256", label="measured prior binding")
    return binding


def _legacy_build_stage5_release_certificate(
    *,
    certificate_id: str,
    issued_at: str,
    repository: Mapping[str, object],
    commit_sha: str,
    release: Mapping[str, object],
    d_prior: Mapping[str, object],
    final_recovery: Mapping[str, object],
    state_only_task: Mapping[str, object],
    gate_evidence: Sequence[Mapping[str, object]],
    runbook_evidence: Sequence[Mapping[str, object]],
) -> Mapping[str, object]:
    raise StageClosureError("self-reported Stage 5 v1 producer is removed")
    value: dict[str, object] = {
        "schema_version": STAGE5_CERTIFICATE_SCHEMA,
        "certificate_id": certificate_id,
        "issued_at": issued_at,
        "authority": "evidence_only",
        "repository": dict(repository),
        "commit_sha": commit_sha,
        "release": dict(release),
        "d_prior": dict(d_prior),
        "final_recovery": dict(final_recovery),
        "state_only_task": dict(state_only_task),
        "gate_evidence": [dict(item) for item in gate_evidence],
        "runbook_evidence": [dict(item) for item in runbook_evidence],
    }
    value["certificate_sha256"] = manifest_sha256(value)
    return verify_stage5_release_certificate(value)


def _legacy_verify_stage5_release_certificate(value: object) -> Mapping[str, object]:
    raise StageClosureError("self-reported Stage 5 v1 verifier is removed")
    certificate = _mapping(
        value,
        {
            "schema_version",
            "certificate_id",
            "issued_at",
            "authority",
            "repository",
            "commit_sha",
            "release",
            "d_prior",
            "final_recovery",
            "state_only_task",
            "gate_evidence",
            "runbook_evidence",
            "certificate_sha256",
        },
        label="Stage 5 release certificate",
    )
    if (
        certificate["schema_version"] != STAGE5_CERTIFICATE_SCHEMA
        or certificate["authority"] != "evidence_only"
    ):
        raise StageClosureError("Stage 5 certificate identity differs")
    _identifier(certificate["certificate_id"], label="certificate_id")
    _timestamp(certificate["issued_at"], label="issued_at")
    _commit(certificate["commit_sha"])
    repository = _mapping(
        certificate["repository"],
        {"full_name", "visibility", "observation_sha256"},
        label="Stage 5 repository",
    )
    if (
        not isinstance(repository["full_name"], str)
        or _REPOSITORY.fullmatch(repository["full_name"]) is None
        or repository["visibility"] != "public"
    ):
        raise StageClosureError("Stage 5 repository must still be Public")
    _sha(repository["observation_sha256"], label="repository.observation_sha256")
    release = _release(certificate["release"], label="release", with_snapshot=True)
    prior = _mapping(
        certificate["d_prior"],
        {
            "release_id",
            "manifest_sha256",
            "measurement_binding_sha256",
            "rollback_evidence_sha256",
        },
        label="D prior",
    )
    _release(
        {"release_id": prior["release_id"], "manifest_sha256": prior["manifest_sha256"]},
        label="D prior",
        with_snapshot=False,
    )
    if prior["manifest_sha256"] == release["manifest_sha256"]:
        raise StageClosureError("D prior must differ from the final active release")
    _sha(prior["measurement_binding_sha256"], label="d_prior.measurement_binding_sha256")
    _sha(prior["rollback_evidence_sha256"], label="d_prior.rollback_evidence_sha256")
    recovery = _mapping(
        certificate["final_recovery"],
        {
            "bundle_id",
            "recovery_manifest_sha256",
            "checkpoint_id",
            "checkpoint_manifest_sha256",
            "failure_domain_attestation_sha256",
            "recovery_receipt_id",
            "recovery_receipt_sha256",
        },
        label="final recovery",
    )
    for field in ("bundle_id", "checkpoint_id", "recovery_receipt_id"):
        _identifier(recovery[field], label=f"final_recovery.{field}")
    for field in (
        "recovery_manifest_sha256",
        "checkpoint_manifest_sha256",
        "failure_domain_attestation_sha256",
        "recovery_receipt_sha256",
    ):
        _sha(recovery[field], label=f"final_recovery.{field}")
    task = _mapping(
        certificate["state_only_task"],
        {
            "task_identity",
            "contract_sha256",
            "task_xml_sha256",
            "acceptance_evidence_sha256",
        },
        label="state-only task",
    )
    if task["task_identity"] != STATE_ONLY_TASK_IDENTITY:
        raise StageClosureError("state-only task identity differs")
    for field in ("contract_sha256", "task_xml_sha256", "acceptance_evidence_sha256"):
        _sha(task[field], label=f"state_only_task.{field}")
    _evidence_sequence(
        certificate["gate_evidence"],
        expected_kinds=STAGE5_REQUIRED_GATES,
        label="Stage 5 gates",
    )
    _evidence_sequence(
        certificate["runbook_evidence"],
        expected_kinds=STAGE5_REQUIRED_RUNBOOKS,
        label="Stage 5 runbooks",
    )
    all_evidence = list(certificate["gate_evidence"]) + list(
        certificate["runbook_evidence"]
    )
    all_ids = [str(item["evidence_id"]) for item in all_evidence]
    if len(set(all_ids)) != len(all_ids):
        raise StageClosureError("Stage 5 evidence IDs are not globally unique")
    _verify_document_hash(
        certificate, hash_field="certificate_sha256", label="Stage 5 certificate"
    )
    return certificate


def _legacy_build_visibility_closure_receipt(
    *,
    receipt_id: str,
    recorded_at: str,
    repository: Mapping[str, object],
    stage5_certificate: Mapping[str, object],
    commit_sha: str,
    private_controls: Mapping[str, object],
    private_ci: Mapping[str, object],
    candidate_validation: Mapping[str, object],
    no_switch_evidence: Mapping[str, object],
    independent_verifier: Mapping[str, object],
) -> Mapping[str, object]:
    raise StageClosureError("self-reported visibility v1 producer is removed")
    value: dict[str, object] = {
        "schema_version": VISIBILITY_CLOSURE_SCHEMA,
        "receipt_id": receipt_id,
        "recorded_at": recorded_at,
        "authority": "evidence_only",
        "repository": dict(repository),
        "stage5_certificate": dict(stage5_certificate),
        "commit_sha": commit_sha,
        "private_controls": dict(private_controls),
        "private_ci": dict(private_ci),
        "candidate_validation": dict(candidate_validation),
        "no_switch_evidence": dict(no_switch_evidence),
        "independent_verifier": dict(independent_verifier),
    }
    value["receipt_sha256"] = manifest_sha256(value)
    return verify_visibility_closure_receipt(value)


def _legacy_verify_visibility_closure_receipt(value: object) -> Mapping[str, object]:
    raise StageClosureError("self-reported visibility v1 verifier is removed")
    receipt = _mapping(
        value,
        {
            "schema_version",
            "receipt_id",
            "recorded_at",
            "authority",
            "repository",
            "stage5_certificate",
            "commit_sha",
            "private_controls",
            "private_ci",
            "candidate_validation",
            "no_switch_evidence",
            "independent_verifier",
            "receipt_sha256",
        },
        label="visibility closure receipt",
    )
    if (
        receipt["schema_version"] != VISIBILITY_CLOSURE_SCHEMA
        or receipt["authority"] != "evidence_only"
    ):
        raise StageClosureError("visibility closure identity differs")
    _identifier(receipt["receipt_id"], label="visibility receipt_id")
    _timestamp(receipt["recorded_at"], label="visibility recorded_at")
    commit_sha = _commit(receipt["commit_sha"])
    repository = _mapping(
        receipt["repository"],
        {
            "repository_id",
            "full_name",
            "visibility_before",
            "visibility_after",
            "transition_evidence_sha256",
        },
        label="visibility repository",
    )
    _identifier(repository["repository_id"], label="repository_id")
    if (
        not isinstance(repository["full_name"], str)
        or _REPOSITORY.fullmatch(repository["full_name"]) is None
        or repository["visibility_before"] != "public"
        or repository["visibility_after"] != "private"
    ):
        raise StageClosureError("repository visibility transition differs")
    _sha(repository["transition_evidence_sha256"], label="transition evidence")
    certificate = _mapping(
        receipt["stage5_certificate"],
        {"certificate_id", "certificate_sha256", "release"},
        label="Stage 5 certificate binding",
    )
    _identifier(certificate["certificate_id"], label="stage5 certificate_id")
    _sha(certificate["certificate_sha256"], label="stage5 certificate hash")
    certified_release = _release(
        certificate["release"], label="certified release", with_snapshot=True
    )
    controls = _mapping(
        receipt["private_controls"],
        {
            "plan_observation_sha256",
            "actions_observation_sha256",
            "branch_protection_observation_sha256",
            "environment_protection_observation_sha256",
            "publish_permission_observation_sha256",
            "verdict",
        },
        label="Private controls",
    )
    if controls["verdict"] != "pass":
        raise StageClosureError("Private control revalidation did not pass")
    for field in controls:
        if field != "verdict":
            _sha(controls[field], label=f"private_controls.{field}")
    ci = _mapping(
        receipt["private_ci"],
        {"run_id", "head_sha", "conclusion", "evidence_sha256"},
        label="Private CI",
    )
    _identifier(ci["run_id"], label="private_ci.run_id")
    if ci["head_sha"] != commit_sha or ci["conclusion"] != "success":
        raise StageClosureError("Private CI does not prove exact-SHA success")
    _sha(ci["evidence_sha256"], label="private_ci.evidence_sha256")
    candidate = _mapping(
        receipt["candidate_validation"],
        {
            "deployment_mode",
            "status",
            "event_id",
            "event_sha256",
            "commit_sha",
            "release_id",
            "manifest_sha256",
            "snapshot_id",
        },
        label="Private candidate validation",
    )
    if (
        candidate["deployment_mode"] != "candidate_only"
        or candidate["status"] != "candidate_validated"
        or candidate["commit_sha"] != commit_sha
        or {
            "release_id": candidate["release_id"],
            "manifest_sha256": candidate["manifest_sha256"],
            "snapshot_id": candidate["snapshot_id"],
        }
        != certified_release
    ):
        raise StageClosureError("Private candidate was not a no-switch exact-SHA validation")
    _identifier(candidate["event_id"], label="candidate.event_id")
    _identifier(candidate["release_id"], label="candidate.release_id")
    _identifier(candidate["snapshot_id"], label="candidate.snapshot_id")
    _sha(candidate["event_sha256"], label="candidate.event_sha256")
    _sha(candidate["manifest_sha256"], label="candidate.manifest_sha256")
    no_switch = _mapping(
        receipt["no_switch_evidence"],
        {
            "active_before",
            "active_after",
            "activation_receipt_set_sha256_before",
            "activation_receipt_set_sha256_after",
            "writer_authority_sha256_before",
            "writer_authority_sha256_after",
            "evidence_sha256",
        },
        label="no-switch evidence",
    )
    before = _release(no_switch["active_before"], label="active_before", with_snapshot=True)
    after = _release(no_switch["active_after"], label="active_after", with_snapshot=True)
    if before != after:
        raise StageClosureError("Private candidate changed active identity")
    if before != certified_release:
        raise StageClosureError("Private candidate did not preserve certified active release")
    for left, right, label in (
        (
            "activation_receipt_set_sha256_before",
            "activation_receipt_set_sha256_after",
            "activation receipt set",
        ),
        ("writer_authority_sha256_before", "writer_authority_sha256_after", "writer authority"),
    ):
        _sha(no_switch[left], label=f"{label} before")
        _sha(no_switch[right], label=f"{label} after")
        if no_switch[left] != no_switch[right]:
            raise StageClosureError(f"Private candidate changed {label}")
    _sha(no_switch["evidence_sha256"], label="no-switch evidence hash")
    _evidence(receipt["independent_verifier"], expected_kind="visibility_independent_verifier")
    _verify_document_hash(receipt, hash_field="receipt_sha256", label="visibility receipt")
    return receipt


def build_active_d_maintenance_plan(
    *,
    plan_id: str,
    created_at: str,
    active_release: Mapping[str, object],
    prior_release: Mapping[str, object],
    cold_bundle: Mapping[str, object],
    final_checkpoint: Mapping[str, object],
    prerequisite_evidence: Sequence[Mapping[str, object]],
) -> Mapping[str, object]:
    """Build an inspect-only plan; no destructive executor exists in v1."""

    value: dict[str, object] = {
        "schema_version": ACTIVE_D_DRILL_PLAN_SCHEMA,
        "plan_id": plan_id,
        "created_at": created_at,
        "authority": "coordination_only",
        "target_address": PRODUCTION_TARGET,
        "vm_root": PRODUCTION_VM_ROOT,
        "mode": "inspect_only",
        "destructive_apply_enabled": False,
        "active_release": dict(active_release),
        "prior_release": dict(prior_release),
        "cold_bundle": dict(cold_bundle),
        "final_checkpoint": dict(final_checkpoint),
        "prerequisite_evidence": [dict(item) for item in prerequisite_evidence],
    }
    value["plan_sha256"] = manifest_sha256(value)
    return verify_active_d_maintenance_plan(value)


def verify_active_d_maintenance_plan(value: object) -> Mapping[str, object]:
    plan = _mapping(
        value,
        {
            "schema_version",
            "plan_id",
            "created_at",
            "authority",
            "target_address",
            "vm_root",
            "mode",
            "destructive_apply_enabled",
            "active_release",
            "prior_release",
            "cold_bundle",
            "final_checkpoint",
            "prerequisite_evidence",
            "plan_sha256",
        },
        label="active-D maintenance plan",
    )
    if (
        plan["schema_version"] != ACTIVE_D_DRILL_PLAN_SCHEMA
        or plan["authority"] != "coordination_only"
        or plan["target_address"] != PRODUCTION_TARGET
        or plan["vm_root"] != PRODUCTION_VM_ROOT
        or plan["mode"] != "inspect_only"
        or plan["destructive_apply_enabled"] is not False
    ):
        raise StageClosureError("active-D plan cannot authorize destructive apply")
    _identifier(plan["plan_id"], label="active-D plan_id")
    _timestamp(plan["created_at"], label="active-D created_at")
    active = _release(plan["active_release"], label="active-D active", with_snapshot=True)
    prior = _release(plan["prior_release"], label="active-D prior", with_snapshot=False)
    if active["manifest_sha256"] == prior["manifest_sha256"]:
        raise StageClosureError("active-D prior must differ from active")
    bundle = _mapping(
        plan["cold_bundle"],
        {"bundle_id", "recovery_manifest_sha256", "closure_inventory_sha256"},
        label="active-D cold bundle",
    )
    _identifier(bundle["bundle_id"], label="active-D bundle_id")
    _sha(bundle["recovery_manifest_sha256"], label="active-D recovery manifest")
    _sha(bundle["closure_inventory_sha256"], label="active-D closure inventory")
    checkpoint = _mapping(
        plan["final_checkpoint"],
        {"checkpoint_id", "checkpoint_manifest_sha256", "captured_release_manifest_sha256"},
        label="active-D final checkpoint",
    )
    _identifier(checkpoint["checkpoint_id"], label="active-D checkpoint_id")
    _sha(checkpoint["checkpoint_manifest_sha256"], label="active-D checkpoint manifest")
    if checkpoint["captured_release_manifest_sha256"] != active["manifest_sha256"]:
        raise StageClosureError("active-D final checkpoint belongs to another release")
    _sha(checkpoint["captured_release_manifest_sha256"], label="captured release manifest")
    _evidence_sequence(
        plan["prerequisite_evidence"],
        expected_kinds=(
            "maintenance_window",
            "traffic_fence",
            "writer_fence",
            "restore_path",
            "root_inventory",
            "independent_verifier",
        ),
        label="active-D prerequisites",
    )
    _verify_document_hash(plan, hash_field="plan_sha256", label="active-D plan")
    return plan


def reject_active_d_destructive_apply(value: object) -> None:
    verify_active_d_maintenance_plan(value)
    raise StageClosureError(
        "active-D destructive apply is intentionally unavailable until a reviewed "
        "nonce-bound maintenance executor and crash replay are implemented"
    )


def build_recovery_finalize_plan(
    *,
    plan_id: str,
    created_at: str,
    release: Mapping[str, object],
    recovery_manifest_sha256: str,
    checkpoint_manifest_sha256: str,
    evidence: Sequence[Mapping[str, object]],
) -> Mapping[str, object]:
    value: dict[str, object] = {
        "schema_version": RECOVERY_FINALIZE_PLAN_SCHEMA,
        "plan_id": plan_id,
        "created_at": created_at,
        "authority": "coordination_only",
        "finalize_enabled": False,
        "release": dict(release),
        "recovery_manifest_sha256": recovery_manifest_sha256,
        "checkpoint_manifest_sha256": checkpoint_manifest_sha256,
        "evidence": [dict(item) for item in evidence],
    }
    value["plan_sha256"] = manifest_sha256(value)
    return verify_recovery_finalize_plan(value)


def verify_recovery_finalize_plan(value: object) -> Mapping[str, object]:
    plan = _mapping(
        value,
        {
            "schema_version",
            "plan_id",
            "created_at",
            "authority",
            "finalize_enabled",
            "release",
            "recovery_manifest_sha256",
            "checkpoint_manifest_sha256",
            "evidence",
            "plan_sha256",
        },
        label="recovery finalize plan",
    )
    if (
        plan["schema_version"] != RECOVERY_FINALIZE_PLAN_SCHEMA
        or plan["authority"] != "coordination_only"
        or plan["finalize_enabled"] is not False
    ):
        raise StageClosureError("recovery finalize plan cannot append a receipt")
    _identifier(plan["plan_id"], label="recovery finalize plan_id")
    _timestamp(plan["created_at"], label="recovery finalize created_at")
    _release(plan["release"], label="recovered release", with_snapshot=True)
    _sha(plan["recovery_manifest_sha256"], label="recovery manifest")
    _sha(plan["checkpoint_manifest_sha256"], label="checkpoint manifest")
    _evidence_sequence(
        plan["evidence"],
        expected_kinds=RECOVERY_FINALIZE_REQUIRED_EVIDENCE,
        label="recovery finalize evidence",
    )
    _verify_document_hash(plan, hash_field="plan_sha256", label="recovery finalize plan")
    return plan


def reject_recovery_receipt_finalize(value: object) -> None:
    verify_recovery_finalize_plan(value)
    raise StageClosureError(
        "Stage 5 recovery receipt finalization is intentionally unavailable until "
        "the fixed verifier consumes and replays every bound evidence artifact"
    )


__all__ = [
    "ACTIVE_D_DRILL_PLAN_SCHEMA",
    "MEASURED_PRIOR_SCHEMA",
    "RECOVERY_FINALIZE_REQUIRED_EVIDENCE",
    "RECOVERY_FINALIZE_PLAN_SCHEMA",
    "STAGE5_CERTIFICATE_SCHEMA",
    "STAGE5_REQUIRED_GATES",
    "STAGE5_REQUIRED_RUNBOOKS",
    "DirectoryEvidenceResolver",
    "EvidenceArtifactResolver",
    "StageClosureError",
    "VISIBILITY_CLOSURE_SCHEMA",
    "build_active_d_maintenance_plan",
    "build_measured_prior_binding",
    "build_recovery_finalize_plan",
    "build_stage5_release_certificate",
    "build_visibility_closure_receipt",
    "artifact_ref",
    "reject_active_d_destructive_apply",
    "reject_recovery_receipt_finalize",
    "verify_active_d_maintenance_plan",
    "verify_measured_prior_binding",
    "verify_recovery_finalize_plan",
    "verify_stage5_release_certificate",
    "verify_visibility_closure_receipt",
    "verify_failure_domain_attestation",
]
