"""Non-interactive, auditable operator CLI for semantic knowledge compilation."""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from typing import Any, Sequence

from quant_hub.config import ensure_no_reparse_components, stat_is_reparse_point
from quant_hub.generic_research import load_generic_catalog_from_release
from quant_hub.knowledge.contracts import BaseSnapshot, canonical_json
from quant_hub.platform.db import utc_now

from .semantic import (
    KnowledgeCandidate,
    ModelIdentityContract,
    ProviderIdentityEvidence,
    RecompileCampaign,
    SemanticCompiler,
    SemanticJobStore,
    extract_source_explicit,
    human_accept,
    reject_candidate,
)
from .semantic_provider import (
    DeepSeekV4ProProvider,
    EnvironmentSecretProvider,
    KeyringSecretProvider,
)


WORKSPACE_DB = "semantic_jobs.sqlite3"
AUDIT_LOG = "semantic_cli_audit.jsonl"
CLI_SCHEMA = "qrh-semantic-operator-cli/v1"


class SemanticCLIError(RuntimeError):
    pass


def _safe_root(path: Path, *, label: str) -> Path:
    try:
        ensure_no_reparse_components(path)
        root = path.resolve(strict=True)
        info = root.lstat()
    except (OSError, ValueError) as error:
        raise SemanticCLIError(f"{label} is unavailable") from error
    if stat_is_reparse_point(info) or not stat.S_ISDIR(info.st_mode):
        raise SemanticCLIError(f"{label} is not a protected directory")
    return root


def _workspace(path: Path, *, require_database: bool) -> tuple[Path, SemanticJobStore]:
    root = _safe_root(path, label="workspace root")
    database = root / WORKSPACE_DB
    if require_database and not database.is_file():
        raise SemanticCLIError("semantic workspace database is unavailable")
    if database.exists():
        ensure_no_reparse_components(database)
        info = database.lstat()
        if (
            stat_is_reparse_point(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            raise SemanticCLIError("semantic workspace database is unsafe")
    return root, SemanticJobStore(database)


def _snapshot(release_root: Path) -> BaseSnapshot:
    # The release loader verifies the immutable manifest, inventory, source
    # object closure, knowledge artifact and shared search artifact before this
    # isolated copy is exposed to the compiler.
    return load_generic_catalog_from_release(
        _safe_root(release_root, label="release root")
    ).base_snapshot


def _identity_contract(path: Path) -> ModelIdentityContract:
    ensure_no_reparse_components(path)
    try:
        resolved = path.resolve(strict=True)
        info = resolved.lstat()
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SemanticCLIError("model identity evidence is unavailable") from error
    if (
        stat_is_reparse_point(info)
        or not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or not isinstance(raw, dict)
        or set(raw)
        != {
            "schema_version",
            "requested_alias",
            "official_evidence",
            "api_probe",
            "secret_handling",
            "verdict",
        }
        or raw["schema_version"]
        != "qrh-deepseek-provider-identity-evidence/v1"
        or raw["requested_alias"] != "deepseek-v4-pro"
        or raw["verdict"]
        != "identity_contract_may_pin_this_revision_model_fingerprint_pair"
    ):
        raise SemanticCLIError("model identity evidence contract is invalid")
    official = raw["official_evidence"]
    probe = raw["api_probe"]
    handling = raw["secret_handling"]
    if (
        not isinstance(official, dict)
        or not isinstance(probe, dict)
        or not isinstance(handling, dict)
        or official.get("http_status") != 200
        or type(official.get("response_bytes")) is not int
        or official["response_bytes"] <= 0
        or probe.get("source_kind") != "synthetic_non_sensitive_identity_probe"
        or not isinstance(probe.get("response_id"), str)
        or not probe["response_id"]
        or handling.get("credential_logged") is not False
        or handling.get("authorization_header_logged") is not False
        or handling.get("credential_in_git_or_manifest") is not False
    ):
        raise SemanticCLIError("model identity evidence fields are invalid")
    mapping = official.get("confirmed_mapping")
    revision = "DeepSeek-V4-Pro-0813"
    if mapping != f"deepseek-v4-pro -> {revision}":
        raise SemanticCLIError("model alias revision is not officially confirmed")
    evidence = ProviderIdentityEvidence(
        requested_alias="deepseek-v4-pro",
        provider_revision=revision,
        evidence_url=str(official.get("url") or ""),
        evidence_sha256=str(official.get("response_sha256") or ""),
        observed_at=str(official.get("observed_at") or ""),
        confirmed=True,
    )
    returned_model = probe.get("returned_model")
    fingerprint = probe.get("system_fingerprint")
    if not isinstance(returned_model, str) or not isinstance(fingerprint, str):
        raise SemanticCLIError("API identity probe fields are invalid")
    return ModelIdentityContract.create(
        evidence,
        allowed_returned_models=(returned_model,),
        allowed_system_fingerprints=(fingerprint,),
    )


def _hash_text(value: str) -> dict[str, object]:
    encoded = value.encode("utf-8")
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def _candidate_projection(
    candidate: KnowledgeCandidate, *, include_text: bool
) -> dict[str, object]:
    evidence = [
        {
            "span_id": binding.span_id,
            "byte_start": binding.byte_start,
            "byte_end": binding.byte_end,
            "quote_sha256": binding.quote_sha256,
            **({"quote": binding.quote} if include_text else {}),
        }
        for binding in candidate.evidence
    ]
    applicability: dict[str, object] = {
        key: (
            list(values)
            if include_text
            else [_hash_text(value) for value in values]
        )
        for key, values in candidate.applicability.items()
    }
    return {
        "candidate_id": candidate.candidate_id,
        "generation_id": candidate.generation_id,
        "document_id": candidate.document_id,
        "document_version_id": candidate.document_version_id,
        "kind": candidate.kind,
        "text": candidate.text if include_text else _hash_text(candidate.text),
        "evidence": evidence,
        "applicability": applicability,
        "relation": candidate.relation,
        "inference": candidate.inference,
        "confidence": candidate.confidence,
        "fact_status": candidate.fact_status,
        "validator_version": candidate.validator_version,
        "rejection_reason": candidate.rejection_reason,
        "includes_source_text": include_text,
    }


def _audit(root: Path, command: str, payload: dict[str, object]) -> None:
    path = root / AUDIT_LOG
    if path.exists():
        ensure_no_reparse_components(path)
        info = path.lstat()
        if (
            stat_is_reparse_point(info)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
        ):
            raise SemanticCLIError("semantic audit log is unsafe")
    row = canonical_json(
        {
            "schema_version": "qrh-semantic-cli-audit/v1",
            "command": command,
            "recorded_at": utc_now(),
            **payload,
        }
    ).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        os.write(descriptor, row)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _add_release(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release-root", type=Path, required=True)


def _add_identity(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--identity-evidence", type=Path, required=True)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qrh-knowledge-compile")
    parser.add_argument("--workspace-root", type=Path, required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    listing = commands.add_parser("list")
    listing.add_argument(
        "--kind", choices=("jobs", "candidates", "generations"), required=True
    )
    listing.add_argument("--status")
    review = commands.add_parser("review")
    review.add_argument("--candidate-id", required=True)
    review.add_argument("--include-text", action="store_true")
    plan = commands.add_parser("plan")
    _add_release(plan)
    _add_identity(plan)
    execute = commands.add_parser("execute-one")
    _add_release(execute)
    _add_identity(execute)
    execute.add_argument("--job-key", required=True)
    execute.add_argument("--credential-source", choices=("keyring", "env"), required=True)
    execute.add_argument("--keyring-service")
    execute.add_argument("--keyring-username")
    execute.add_argument("--env-variable", default="DEEPSEEK_API_KEY")
    execute.add_argument("--timeout-seconds", type=float, default=180.0)
    execute.add_argument("--_child-execution", action="store_true", help=argparse.SUPPRESS)
    accept = commands.add_parser("accept")
    _add_release(accept)
    accept.add_argument("--candidate-id", required=True)
    accept.add_argument("--actor", required=True)
    accept.add_argument("--reason", required=True)
    reject = commands.add_parser("reject")
    reject.add_argument("--candidate-id", required=True)
    reject.add_argument("--actor", required=True)
    reject.add_argument("--reason", required=True)
    targeted = commands.add_parser("targeted")
    _add_release(targeted)
    _add_identity(targeted)
    targeted.add_argument("--version-id", action="append", required=True)
    targeted.add_argument("--reason", required=True)
    return parser


def _provider(arguments: argparse.Namespace) -> DeepSeekV4ProProvider:
    if not 10.0 <= arguments.timeout_seconds <= 600.0:
        raise SemanticCLIError("provider timeout must be between 10 and 600 seconds")
    if arguments.credential_source == "keyring":
        if not arguments.keyring_service or not arguments.keyring_username:
            raise SemanticCLIError(
                "keyring credential source requires service and username"
            )
        secret_provider = KeyringSecretProvider(
            arguments.keyring_service, arguments.keyring_username
        )
    else:
        secret_provider = EnvironmentSecretProvider(arguments.env_variable)
    return DeepSeekV4ProProvider(
        secret_provider, timeout_seconds=arguments.timeout_seconds
    )


def _overall_deadline_seconds(part_count: int) -> int:
    if not isinstance(part_count, int) or part_count < 1:
        raise SemanticCLIError("semantic job part count is invalid")
    return min(1800, 360 * part_count)


def _generation_projection(generation: Any, *, timeout_seconds: float, overall_deadline_seconds: int) -> dict[str, object]:
    return {
        "schema_version": CLI_SCHEMA,
        "command": "execute-one",
        "job_key": generation.job_key,
        "generation_id": generation.generation_id,
        "status": generation.status,
        "error_code": generation.error_code,
        "part_statuses": [row.status for row in generation.part_receipts],
        "part_error_codes": [
            row.error_code for row in generation.part_receipts if row.error_code
        ],
        "returned_model": generation.returned_model,
        "system_fingerprint": generation.system_fingerprint,
        "timeout_seconds": timeout_seconds,
        "overall_deadline_seconds": overall_deadline_seconds,
        "source_text_included": False,
    }


def _latest_generation_for_job(store: SemanticJobStore, job: Any) -> Any | None:
    return next(
        (
            row
            for row in reversed(store.generations_for_version(job.document_version_id))
            if row.job_key == job.job_key
        ),
        None,
    )


def _reconcile_unverifiable_child(
    workspace: Path,
    store: SemanticJobStore,
    job: Any,
    *,
    failure_code: str,
) -> None:
    current = store.job(job.job_key)
    generation = _latest_generation_for_job(store, job)
    if generation is not None and generation.status == "succeeded":
        if generation.generation_id not in store.disqualified_generation_ids():
            store.disqualify_generation(
                generation.generation_id,
                actor="semantic-child-contract-watchdog",
                reason="successful generation has unverifiable child process output",
            )
    elif current.status == "running":
        store.set_job_status(job.job_key, "failed_retryable", "worker_failed")
    _audit(
        workspace,
        "execute-one-child-reconciliation",
        {
            "job_key": job.job_key,
            "generation_id": generation.generation_id if generation else None,
            "job_status": store.job(job.job_key).status,
            "failure_code": failure_code,
            "generation_disqualified": bool(
                generation is not None
                and generation.generation_id in store.disqualified_generation_ids()
            ),
        },
    )


def _execute_one_parent(
    arguments: argparse.Namespace,
    workspace: Path,
    store: SemanticJobStore,
) -> dict[str, object]:
    job = store.job(arguments.job_key)
    deadline = _overall_deadline_seconds(job.part_count)
    command = [
        sys.executable,
        "-B",
        "-m",
        "quant_hub.knowledge.semantic_cli",
        "--workspace-root",
        str(arguments.workspace_root),
        "execute-one",
        "--release-root",
        str(arguments.release_root),
        "--identity-evidence",
        str(arguments.identity_evidence),
        "--job-key",
        arguments.job_key,
        "--credential-source",
        arguments.credential_source,
        "--timeout-seconds",
        str(arguments.timeout_seconds),
        "--_child-execution",
    ]
    if arguments.credential_source == "env":
        command.extend(("--env-variable", arguments.env_variable))
    else:
        if arguments.keyring_service:
            command.extend(("--keyring-service", arguments.keyring_service))
        if arguments.keyring_username:
            command.extend(("--keyring-username", arguments.keyring_username))
    creationflags = (
        getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    )
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=deadline,
            check=False,
            creationflags=creationflags,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
        current = store.job(job.job_key)
        generation = _latest_generation_for_job(store, job)
        if generation is not None and generation.status == "succeeded":
            store.disqualify_generation(
                generation.generation_id,
                actor="semantic-overall-deadline-watchdog",
                reason="generation committed after the immutable overall deadline",
            )
        elif current.status in {"queued", "running"}:
            store.set_job_status(
                job.job_key, "failed_retryable", "wall_clock_timeout"
            )
        _audit(
            workspace,
            "execute-one-deadline",
            {
                "job_key": job.job_key,
                "generation_id": generation.generation_id if generation else None,
                "status": "failed_retryable",
                "error_code": "wall_clock_timeout",
                "overall_deadline_seconds": deadline,
                "elapsed_seconds": round(elapsed, 3),
            },
        )
        return {
            "schema_version": CLI_SCHEMA,
            "command": "execute-one",
            "job_key": job.job_key,
            "generation_id": generation.generation_id if generation else None,
            "status": "failed_retryable",
            "error_code": "wall_clock_timeout",
            "part_statuses": [],
            "part_error_codes": ["wall_clock_timeout"],
            "returned_model": generation.returned_model if generation else "",
            "system_fingerprint": generation.system_fingerprint if generation else "",
            "timeout_seconds": arguments.timeout_seconds,
            "overall_deadline_seconds": deadline,
            "source_text_included": False,
        }
    if completed.returncode != 0:
        _reconcile_unverifiable_child(
            workspace, store, job, failure_code="worker_nonzero_exit"
        )
        raise SemanticCLIError("semantic execution child failed")
    try:
        value = json.loads(completed.stdout.strip())
    except (TypeError, ValueError) as error:
        _reconcile_unverifiable_child(
            workspace, store, job, failure_code="worker_invalid_json"
        )
        raise SemanticCLIError("semantic execution child returned invalid output") from error
    if (
        not isinstance(value, dict)
        or value.get("schema_version") != CLI_SCHEMA
        or value.get("command") != "execute-one"
        or value.get("job_key") != job.job_key
        or value.get("source_text_included") is not False
    ):
        _reconcile_unverifiable_child(
            workspace, store, job, failure_code="worker_output_contract_invalid"
        )
        raise SemanticCLIError("semantic execution child violated output contract")
    value["overall_deadline_seconds"] = deadline
    return value


def _status(store: SemanticJobStore) -> dict[str, object]:
    jobs = store.jobs()
    candidates = store.candidates()
    generations = store.generations()
    return {
        "schema_version": CLI_SCHEMA,
        "command": "status",
        "job_counts": dict(sorted(Counter(job.status for job in jobs).items())),
        "generation_counts": dict(
            sorted(Counter(row.status for row in generations).items())
        ),
        "candidate_counts": dict(
            sorted(Counter(row.fact_status for row in candidates).items())
        ),
        "prompt_versions": sorted({job.prompt_version for job in jobs}),
        "output_schema_versions": sorted({job.output_schema_version for job in jobs}),
        "source_text_included": False,
    }


def _list(store: SemanticJobStore, kind: str, status: str | None) -> dict[str, object]:
    if kind == "jobs":
        rows = [
            {
                "job_key": row.job_key,
                "document_version_id": row.document_version_id,
                "status": row.status,
                "error_code": row.error_code,
                "prompt_version": row.prompt_version,
                "output_schema_version": row.output_schema_version,
                "part_count": row.part_count,
                "partition_manifest_hash": row.partition_manifest_hash,
            }
            for row in store.jobs()
            if status is None or row.status == status
        ]
    elif kind == "candidates":
        rows = [
            {
                "candidate_id": row.candidate_id,
                "generation_id": row.generation_id,
                "document_version_id": row.document_version_id,
                "kind": row.kind,
                "fact_status": row.fact_status,
            }
            for row in store.candidates()
            if status is None or row.fact_status == status
        ]
    else:
        rows = [
            {
                "generation_id": row.generation_id,
                "job_key": row.job_key,
                "document_version_id": row.document_version_id,
                "status": row.status,
                "error_code": row.error_code,
                "returned_model": row.returned_model,
                "system_fingerprint": row.system_fingerprint,
                "partition_manifest_hash": row.partition_manifest_hash,
                "aggregate_hash": row.aggregate_hash,
                "part_error_codes": [
                    part.error_code for part in row.part_receipts if part.error_code
                ],
            }
            for row in store.generations()
            if status is None or row.status == status
        ]
    return {
        "schema_version": CLI_SCHEMA,
        "command": "list",
        "kind": kind,
        "rows": rows,
        "source_text_included": False,
    }


def _execute(arguments: argparse.Namespace) -> dict[str, object]:
    require_database = arguments.command not in {"plan"}
    workspace, store = _workspace(
        arguments.workspace_root, require_database=require_database
    )
    if arguments.command == "status":
        return _status(store)
    if arguments.command == "list":
        return _list(store, arguments.kind, arguments.status)
    if arguments.command == "review":
        candidate = store.candidate(arguments.candidate_id)
        return {
            "schema_version": CLI_SCHEMA,
            "command": "review",
            "candidate": _candidate_projection(
                candidate, include_text=arguments.include_text
            ),
        }
    if arguments.command == "reject":
        if not arguments.actor.strip() or not arguments.reason.strip():
            raise SemanticCLIError("reject requires non-empty actor and reason")
        candidate = store.candidate(arguments.candidate_id)
        rejected = reject_candidate(
            store, candidate, actor=arguments.actor, reason=arguments.reason
        )
        _audit(
            workspace,
            "reject",
            {
                "candidate_id": rejected.candidate_id,
                "actor": arguments.actor,
                "reason_sha256": _hash_text(arguments.reason)["sha256"],
                "fact_status": rejected.fact_status,
            },
        )
        return {
            "schema_version": CLI_SCHEMA,
            "command": "reject",
            "candidate_id": rejected.candidate_id,
            "fact_status": rejected.fact_status,
            "source_text_included": False,
        }

    snapshot = _snapshot(arguments.release_root)
    if arguments.command == "accept":
        if not arguments.actor.strip() or not arguments.reason.strip():
            raise SemanticCLIError("accept requires non-empty actor and reason")
        candidate = store.candidate(arguments.candidate_id)
        if candidate.document_version_id not in snapshot.active_membership.values():
            raise SemanticCLIError("candidate is not attached to the active release base")
        active_versions = tuple(snapshot.active_membership.values())
        valid_targets = frozenset(
            row.knowledge_item_id
            for row in store.items_for_versions(active_versions)
            if row.fact_status
            in {"source_explicit", "machine_verified", "human_reviewed"}
        )
        item = human_accept(
            store,
            candidate,
            actor=arguments.actor,
            reason=arguments.reason,
            valid_relation_targets=valid_targets,
        )
        _audit(
            workspace,
            "accept",
            {
                "candidate_id": candidate.candidate_id,
                "knowledge_item_id": item.knowledge_item_id,
                "actor": arguments.actor,
                "reason_sha256": _hash_text(arguments.reason)["sha256"],
                "relation_target_validated": candidate.relation is not None,
            },
        )
        return {
            "schema_version": CLI_SCHEMA,
            "command": "accept",
            "candidate_id": candidate.candidate_id,
            "knowledge_item_id": item.knowledge_item_id,
            "fact_status": item.fact_status,
            "source_text_included": False,
        }

    contract = _identity_contract(arguments.identity_evidence)
    compiler = SemanticCompiler(store, contract)
    if arguments.command == "plan":
        deterministic_items = extract_source_explicit(snapshot, store)
        plan = compiler.plan(snapshot)
        _audit(
            workspace,
            "plan",
            {
                "snapshot_id": snapshot.snapshot_id,
                "job_keys": [job.job_key for job in plan.jobs],
                "blocked_version_ids": list(plan.blocked_version_ids),
                "targeted_recompile_required_version_ids": list(
                    plan.targeted_recompile_required_version_ids
                ),
                "deterministic_source_item_ids": [
                    item.knowledge_item_id for item in deterministic_items
                ],
            },
        )
        return {
            "schema_version": CLI_SCHEMA,
            "command": "plan",
            "snapshot_id": snapshot.snapshot_id,
            "jobs": [
                {
                    "job_key": job.job_key,
                    "document_version_id": job.document_version_id,
                    "part_count": job.part_count,
                    "partition_manifest_hash": job.partition_manifest_hash,
                }
                for job in plan.jobs
            ],
            "reused_version_ids": list(plan.reused_version_ids),
            "blocked_version_ids": list(plan.blocked_version_ids),
            "targeted_recompile_required_version_ids": list(
                plan.targeted_recompile_required_version_ids
            ),
            "deterministic_source_items_created": len(deterministic_items),
            "source_text_included": False,
        }
    if arguments.command == "targeted":
        if not arguments.reason.strip():
            raise SemanticCLIError("targeted recompile requires a non-empty reason")
        unknown = set(arguments.version_id).difference(snapshot.versions)
        if unknown:
            raise SemanticCLIError("targeted recompile contains an unknown version identity")
        campaign = RecompileCampaign.create(arguments.version_id, arguments.reason)
        plan = compiler.plan(snapshot, campaign=campaign)
        _audit(
            workspace,
            "targeted",
            {
                "campaign_id": campaign.campaign_id,
                "version_ids": list(campaign.selected_version_ids),
                "reason_sha256": _hash_text(arguments.reason)["sha256"],
                "job_keys": [job.job_key for job in plan.jobs],
            },
        )
        return {
            "schema_version": CLI_SCHEMA,
            "command": "targeted",
            "campaign_id": campaign.campaign_id,
            "jobs": [job.job_key for job in plan.jobs],
            "blocked_version_ids": list(plan.blocked_version_ids),
            "targeted_recompile_required_version_ids": list(
                plan.targeted_recompile_required_version_ids
            ),
            "source_text_included": False,
        }
    job = store.job(arguments.job_key)
    if job.document_version_id not in snapshot.versions:
        raise SemanticCLIError("semantic job is not attached to the release base")
    if not arguments._child_execution:
        return _execute_one_parent(arguments, workspace, store)
    generation = compiler.execute(snapshot, job.job_key, _provider(arguments))
    _audit(
        workspace,
        "execute-one",
        {
            "job_key": job.job_key,
            "generation_id": generation.generation_id,
            "status": generation.status,
            "error_code": generation.error_code,
            "partition_manifest_hash": generation.partition_manifest_hash,
            "aggregate_hash": generation.aggregate_hash,
            "timeout_seconds": arguments.timeout_seconds,
        },
    )
    return _generation_projection(
        generation,
        timeout_seconds=arguments.timeout_seconds,
        overall_deadline_seconds=_overall_deadline_seconds(job.part_count),
    )


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        value = _execute(arguments)
    except Exception as error:
        value = {
            "schema_version": CLI_SCHEMA,
            "command": getattr(arguments, "command", None),
            "status": "error",
            "error_type": type(error).__name__,
            "source_text_included": False,
        }
        sys.stdout.write(canonical_json(value) + "\n")
        return 2
    sys.stdout.write(canonical_json(value) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["main"]
