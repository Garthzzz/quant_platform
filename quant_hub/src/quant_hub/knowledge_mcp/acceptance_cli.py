"""CLI for immutable real Codex/MCP acceptance evidence campaigns."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
from typing import Mapping

from quant_hub.knowledge.contracts import canonical_json

from .acceptance_contracts import (
    PUBLIC_SYNTHETIC_ACCEPTANCE_AUTHORITY,
    REAL_ACCEPTANCE_PROMPTS_SCHEMA,
    REAL_CODEX_EVIDENCE_REPLAY_AUTHORITY,
    REAL_CODEX_RUNNER,
    pin_runtime_closure,
    real_dispatch_paths,
    stable_read_file,
)
from .acceptance_runner import (
    acceptance_evidence_inventory,
    expected_acceptance_paths,
    load_real_acceptance_inputs,
    record_real_acceptance_inputs,
    run_real_acceptance_arm,
)
from .evaluation import (
    PreregisteredAcceptanceCase,
    _reject_duplicate_json_keys,
    _write_new_bytes,
    evaluate_preregistered_acceptance,
    validate_acceptance_campaign_receipt_bytes,
    validate_acceptance_preregistration_bytes,
)
from .mirror import AuthorityIdentity


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="qrh-mcp-acceptance")
    commands = parser.add_subparsers(dest="command", required=True)
    preregister = commands.add_parser("preregister")
    preregister.add_argument("--preregistration", type=Path, required=True)
    preregister.add_argument("--launch-config", type=Path, required=True)
    preregister.add_argument("--prompts-manifest", type=Path, required=True)
    preregister.add_argument("--evidence-root", type=Path, required=True)
    run = commands.add_parser("run")
    run.add_argument("--evidence-root", type=Path, required=True)
    verify = commands.add_parser("verify")
    verify.add_argument("--evidence-root", type=Path, required=True)
    return parser


def _load_prompt_inputs(path: Path) -> dict[str, bytes]:
    path = Path(path).resolve(strict=True)
    payload = stable_read_file(path, kind="acceptance prompts manifest", maximum=2 * 1024 * 1024)
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("real acceptance prompts manifest is invalid JSON") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "cases"}
        or value.get("schema_version") != REAL_ACCEPTANCE_PROMPTS_SCHEMA
        or canonical_json(value).encode("utf-8") != payload
        or not isinstance(value.get("cases"), list)
        or not value["cases"]
    ):
        raise ValueError("real acceptance prompts manifest is not closed canonical JSON")
    prompts: dict[str, bytes] = {}
    for row in value["cases"]:
        if (
            not isinstance(row, dict)
            or set(row) != {"case_id", "prompt_path"}
            or not isinstance(row.get("case_id"), str)
            or not row["case_id"]
            or row["case_id"] in prompts
            or not isinstance(row.get("prompt_path"), str)
            or not row["prompt_path"]
        ):
            raise ValueError("real acceptance prompts manifest case is invalid")
        prompt_path = Path(row["prompt_path"])
        if not prompt_path.is_absolute():
            prompt_path = path.parent / prompt_path
        prompts[row["case_id"]] = stable_read_file(
            prompt_path.resolve(strict=True),
            kind=f"acceptance source prompt {row['case_id']}",
            maximum=128 * 1024,
        )
    return prompts


def _load_cases(
    evidence_root: Path,
    *,
    expect_receipt: bool,
) -> tuple[
    bytes,
    Path,
    bytes,
    tuple[PreregisteredAcceptanceCase, ...],
    Path,
]:
    inventory_before = acceptance_evidence_inventory(evidence_root)
    preregistration, ledger_path, config_bytes, prompts = (
        load_real_acceptance_inputs(evidence_root)
    )
    registered = validate_acceptance_preregistration_bytes(preregistration)
    expected = expected_acceptance_paths(
        registered, include_dispatch=True, include_receipt=expect_receipt
    )
    if set(inventory_before) != expected:
        raise ValueError("acceptance evidence inventory is incomplete or contains extras")
    identity = AuthorityIdentity(**registered["authority_identity"])
    dispatch_root = Path(evidence_root) / "dispatch"
    cases: list[PreregisteredAcceptanceCase] = []
    for definition in registered["cases"]:
        case_id = str(definition["case_id"])
        evidence: dict[str, tuple[bytes, bytes, bytes]] = {}
        for arm in ("assisted", "no_mcp"):
            intent_path, trace_path, completion_path = real_dispatch_paths(
                dispatch_root,
                run_id=str(registered["run_id"]),
                case_id=case_id,
                arm=arm,
            )
            evidence[arm] = (
                stable_read_file(intent_path, kind="dispatch intent", maximum=2 * 1024 * 1024),
                stable_read_file(trace_path, kind="dispatch trace", maximum=32 * 1024 * 1024),
                stable_read_file(completion_path, kind="dispatch completion", maximum=2 * 1024 * 1024),
            )
        assisted_intent, assisted_trace, assisted_completion = evidence["assisted"]
        no_mcp_intent, no_mcp_trace, no_mcp_completion = evidence["no_mcp"]
        cases.append(
            PreregisteredAcceptanceCase(
                case_id=case_id,
                prompt_bytes=prompts[case_id],
                assisted_trace_bytes=assisted_trace,
                no_mcp_trace_bytes=no_mcp_trace,
                assisted_dispatch_intent=assisted_intent,
                assisted_dispatch_completion=assisted_completion,
                no_mcp_dispatch_intent=no_mcp_intent,
                no_mcp_dispatch_completion=no_mcp_completion,
                expected_identity=identity if definition["should_call"] else None,
            )
        )
    if inventory_before != acceptance_evidence_inventory(evidence_root):
        raise ValueError("acceptance evidence changed while loading cases")
    return preregistration, ledger_path, config_bytes, tuple(cases), dispatch_root


def _evaluate(evidence_root: Path, *, write_receipt: bool) -> Mapping[str, object]:
    preregistration, ledger, config, cases, dispatch_root = _load_cases(
        evidence_root, expect_receipt=not write_receipt
    )
    launch = json.loads(config)
    pins = pin_runtime_closure(launch)
    try:
        report = evaluate_preregistered_acceptance(
            preregistration,
            cases,
            preregistration_ledger=ledger,
            dispatch_ledger_root=dispatch_root,
            config_bytes=config,
        )
    finally:
        pins.close()
    if report.authority != REAL_CODEX_EVIDENCE_REPLAY_AUTHORITY:
        raise ValueError("real acceptance evidence contains a non-real dispatch")
    receipt_path = Path(evidence_root) / "campaign-receipt.json"
    if write_receipt:
        _write_new_bytes(receipt_path, report.campaign_receipt)
        registered = validate_acceptance_preregistration_bytes(preregistration)
        if set(acceptance_evidence_inventory(evidence_root)) != expected_acceptance_paths(
            registered, include_dispatch=True, include_receipt=True
        ):
            raise ValueError("acceptance campaign receipt did not close exact inventory")
    else:
        validate_acceptance_campaign_receipt_bytes(
            stable_read_file(receipt_path, kind="campaign receipt", maximum=4 * 1024 * 1024),
            preregistration=preregistration,
            cases=cases,
            preregistration_ledger=ledger,
            dispatch_ledger_root=dispatch_root,
            config_bytes=config,
        )
    return {
        "schema_version": "qrh-mcp-real-acceptance-cli-result/v1",
        "status": report.status,
        "case_count": report.case_count,
        "authority": report.authority,
        "campaign_receipt": str(receipt_path.resolve()),
        "campaign_receipt_sha256": hashlib.sha256(report.campaign_receipt).hexdigest(),
        "findings": list(report.findings),
    }


def validate_real_acceptance_evidence_root(
    evidence_root: Path,
) -> Mapping[str, object]:
    """Replay a persisted real-Codex campaign without granting release authority.

    Disk evidence is useful for functional acceptance, but it is not a trusted
    execution attestation.  Stage 5 therefore rejects the returned authority.
    """

    evidence_root = Path(evidence_root)
    inventory_before = acceptance_evidence_inventory(evidence_root)
    preregistration, ledger, config, cases, dispatch_root = _load_cases(
        evidence_root, expect_receipt=True
    )
    receipt_path = evidence_root / "campaign-receipt.json"
    receipt_bytes = stable_read_file(
        receipt_path, kind="campaign receipt", maximum=4 * 1024 * 1024
    )
    pins = pin_runtime_closure(json.loads(config))
    try:
        receipt = validate_acceptance_campaign_receipt_bytes(
            receipt_bytes,
            preregistration=preregistration,
            cases=cases,
            preregistration_ledger=ledger,
            dispatch_ledger_root=dispatch_root,
            config_bytes=config,
        )
    finally:
        pins.close()
    if (
        receipt.get("status") != "PASS"
        or receipt.get("authority")
        != REAL_CODEX_EVIDENCE_REPLAY_AUTHORITY
        or not isinstance(receipt.get("cases"), list)
        or len(receipt["cases"]) != len(cases)
        or any(
            not isinstance(case, dict)
            or not isinstance(case.get("assisted_dispatch"), dict)
            or not isinstance(case.get("no_mcp_dispatch"), dict)
            or case["assisted_dispatch"].get("runner") != REAL_CODEX_RUNNER
            or case["no_mcp_dispatch"].get("runner") != REAL_CODEX_RUNNER
            for case in receipt["cases"]
        )
    ):
        raise ValueError("real acceptance evidence is not a valid non-authoritative replay")
    if inventory_before != acceptance_evidence_inventory(evidence_root):
        raise ValueError("acceptance evidence changed during non-authoritative replay")
    return {
        "schema_version": "qrh-mcp-real-acceptance-verification/v1",
        "status": "PASS",
        "authority": receipt["authority"],
        "run_id": receipt["run_id"],
        "case_count": len(cases),
        "preregistration_sha256": hashlib.sha256(preregistration).hexdigest(),
        "campaign_receipt": str(receipt_path.resolve()),
        "campaign_receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
    }


def _run(evidence_root: Path) -> Mapping[str, object]:
    preregistration, ledger, config, prompts = load_real_acceptance_inputs(
        evidence_root
    )
    registered = validate_acceptance_preregistration_bytes(preregistration)
    dispatch_root = Path(evidence_root) / "dispatch"
    arm_statuses: list[dict[str, str]] = []

    def fail(*, case_id: str, arm: str, status: str, reason: str) -> Mapping[str, object]:
        inventory = acceptance_evidence_inventory(evidence_root)
        receipt = canonical_json(
            {
                "schema_version": "qrh-mcp-real-acceptance-failure/v1",
                "status": "FAIL",
                "authority": PUBLIC_SYNTHETIC_ACCEPTANCE_AUTHORITY,
                "run_id": registered["run_id"],
                "failed_case_id": case_id,
                "failed_arm": arm,
                "failed_status": status,
                "reason": reason,
                "preregistration_sha256": hashlib.sha256(preregistration).hexdigest(),
                "config_sha256": hashlib.sha256(config).hexdigest(),
                "arm_statuses": arm_statuses,
                "inventory_before_receipt": inventory,
            }
        ).encode("utf-8")
        receipt_path = Path(evidence_root) / "campaign-failure.json"
        _write_new_bytes(receipt_path, receipt)
        return {
            "schema_version": "qrh-mcp-real-acceptance-cli-result/v2-provenance",
            "status": "FAIL",
            "authority": PUBLIC_SYNTHETIC_ACCEPTANCE_AUTHORITY,
            "arm_statuses": arm_statuses,
            "reason": reason,
            "failure_receipt": str(receipt_path.resolve()),
            "failure_receipt_sha256": hashlib.sha256(receipt).hexdigest(),
        }

    try:
        campaign_pins = pin_runtime_closure(json.loads(config))
    except Exception as error:
        return fail(
            case_id="__campaign__",
            arm="none",
            status="provenance_error",
            reason=f"campaign runtime closure failed closed:{type(error).__name__}",
        )
    pending_failure: dict[str, str] | None = None
    try:
        for definition in registered["cases"]:
            case_id = str(definition["case_id"])
            for arm in ("assisted", "no_mcp"):
                try:
                    result = run_real_acceptance_arm(
                        preregistration=preregistration,
                        preregistration_ledger=ledger,
                        dispatch_ledger_root=dispatch_root,
                        case_id=case_id,
                        arm=arm,
                        prompt_bytes=prompts[case_id],
                        config_bytes=config,
                    )
                except Exception as error:
                    arm_statuses.append(
                        {
                            "case_id": case_id,
                            "arm": arm,
                            "status": "provenance_error",
                        }
                    )
                    pending_failure = {
                        "case_id": case_id,
                        "arm": arm,
                        "status": "provenance_error",
                        "reason": f"real Codex arm failed closed:{type(error).__name__}",
                    }
                    break
                arm_statuses.append(
                    {"case_id": case_id, "arm": arm, "status": result.status}
                )
                if result.status != "completed":
                    pending_failure = {
                        "case_id": case_id,
                        "arm": arm,
                        "status": result.status,
                        "reason": "real Codex arm did not complete with qualifying provenance and valid raw JSONL",
                    }
                    break
            if pending_failure is not None:
                break
    except Exception as error:
        pending_failure = {
            "case_id": "__campaign__",
            "arm": "none",
            "status": "provenance_error",
            "reason": f"real Codex campaign execution failed closed:{type(error).__name__}",
        }
    try:
        campaign_pins.close()
    except Exception as error:
        pending_failure = {
            "case_id": "__campaign__",
            "arm": "none",
            "status": "provenance_error",
            "reason": f"campaign runtime closure close failed closed:{type(error).__name__}",
        }
    if pending_failure is not None:
        return fail(**pending_failure)
    try:
        value = dict(_evaluate(evidence_root, write_receipt=True))
    except Exception as error:
        return fail(
            case_id="__campaign__",
            arm="none",
            status="evaluation_error",
            reason=f"real Codex campaign evaluation failed closed:{type(error).__name__}",
        )
    value["arm_statuses"] = arm_statuses
    return value


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    exit_code = 0
    try:
        if arguments.command == "preregister":
            preregistration = stable_read_file(
                arguments.preregistration.resolve(strict=True),
                kind="source preregistration",
                maximum=2 * 1024 * 1024,
            )
            config = stable_read_file(
                arguments.launch_config.resolve(strict=True),
                kind="source launch config",
                maximum=2 * 1024 * 1024,
            )
            manifest = record_real_acceptance_inputs(
                preregistration=preregistration,
                config_bytes=config,
                prompts=_load_prompt_inputs(arguments.prompts_manifest),
                evidence_root=arguments.evidence_root,
            )
            value: Mapping[str, object] = {
                "schema_version": "qrh-mcp-real-acceptance-cli-result/v1",
                "status": "preregistered",
                "evidence_root": str(arguments.evidence_root.resolve()),
                "input_manifest_sha256": hashlib.sha256(manifest).hexdigest(),
            }
        elif arguments.command == "run":
            value = _run(arguments.evidence_root)
            exit_code = 0 if value["status"] == "PASS" else 2
        else:
            value = validate_real_acceptance_evidence_root(arguments.evidence_root)
            exit_code = 0 if value["status"] == "PASS" else 2
    except (OSError, TypeError, ValueError) as error:
        value = {
            "schema_version": "qrh-mcp-real-acceptance-cli-error/v1",
            "status": "error",
            "error_type": type(error).__name__,
            "message": str(error),
        }
        exit_code = 2
    sys.stdout.write(canonical_json(dict(value)) + "\n")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
