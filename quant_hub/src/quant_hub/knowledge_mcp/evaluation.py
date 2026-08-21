"""Machine gate for implicit tool choice and MCP/no-MCP research gain traces."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
from typing import Mapping, Sequence

from quant_hub.knowledge.contracts import canonical_json

from .mirror import AuthorityIdentity


QUALITY_DIMENSIONS = (
    "grounded_decision",
    "condition_limitation_recognition",
    "citation_correctness",
)
READ_TOOLS = {
    "search_quant_knowledge",
    "get_quant_knowledge",
    "list_knowledge_updates",
}
CODEX_TRACE_MAX_BYTES = 32 * 1024 * 1024
ACCEPTANCE_PREREGISTRATION_SCHEMA = "qrh-mcp-acceptance-preregistration/v1"


@dataclass(frozen=True, slots=True)
class CodexToolTrace:
    """Sanitized projection of a real ``codex exec --json`` trace.

    Full model output stays in ignored/off-host evidence.  The evaluator only
    needs completed calls for the named server, completion state, and the final
    response; it never copies prompts or unrelated tool payloads into Git.
    """

    events: tuple[ToolTraceEvent, ...]
    raw_events: tuple[ToolTraceEvent, ...]
    failed_calls: tuple[str, ...]
    unrelated_mcp_call_count: int
    unrelated_mcp_calls: tuple[ToolTraceEvent, ...]
    final_response: str
    turn_completed: bool


def load_codex_tool_trace(
    path: Path,
    *,
    server_name: str = "quant_research_knowledge",
    max_bytes: int = CODEX_TRACE_MAX_BYTES,
) -> CodexToolTrace:
    path = Path(path)
    if not server_name or max_bytes < 1:
        raise ValueError("server_name and max_bytes are invalid")
    try:
        size = path.stat().st_size
        if not 0 < size <= max_bytes:
            raise ValueError("Codex trace size is outside the accepted range")
        payload = path.read_bytes()
    except OSError as error:
        raise ValueError("Codex trace is unreadable") from error
    encoding = "utf-16" if payload.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    try:
        lines = payload.decode(encoding, errors="strict").splitlines()
    except UnicodeError as error:
        raise ValueError("Codex trace encoding is invalid") from error
    events: list[ToolTraceEvent] = []
    raw_events: list[ToolTraceEvent] = []
    failed: list[str] = []
    unrelated_events: list[ToolTraceEvent] = []
    final_response = ""
    turn_completed = False
    for ordinal, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"Codex trace line {ordinal} is invalid JSON") from error
        if not isinstance(row, dict):
            raise ValueError(f"Codex trace line {ordinal} is not an object")
        if row.get("type") == "turn.completed":
            turn_completed = True
        item = row.get("item")
        if not isinstance(item, dict) or row.get("type") != "item.completed":
            continue
        if item.get("type") == "agent_message" and isinstance(item.get("text"), str):
            final_response = item["text"]
            continue
        if item.get("type") != "mcp_tool_call":
            continue
        arguments = item.get("arguments")
        safe_arguments = arguments if isinstance(arguments, dict) else {}
        status = str(item.get("status") or "unknown")
        result = item.get("result")
        structured = result.get("structured_content") if isinstance(result, dict) else None
        response = structured if isinstance(structured, dict) else {}
        failed_call = status != "completed" or item.get("error") is not None
        raw_event = ToolTraceEvent(
            tool_name=str(item.get("tool") or ""),
            response=response,
            arguments=safe_arguments,
            ordinal=ordinal,
            status=status,
            failed=failed_call or not isinstance(structured, dict),
            raw=dict(item),
        )
        if item.get("server") != server_name:
            unrelated_events.append(raw_event)
            continue
        raw_events.append(raw_event)
        tool_name = item.get("tool")
        if tool_name not in READ_TOOLS:
            failed.append(f"line_{ordinal}:unknown_or_non_read_tool")
            continue
        if failed_call:
            failed.append(f"line_{ordinal}:{tool_name}:failed")
            continue
        if not isinstance(structured, dict):
            failed.append(f"line_{ordinal}:{tool_name}:missing_structured_content")
            continue
        events.append(raw_event)
    return CodexToolTrace(
        events=tuple(events),
        raw_events=tuple(raw_events),
        failed_calls=tuple(failed),
        unrelated_mcp_call_count=len(unrelated_events),
        unrelated_mcp_calls=tuple(unrelated_events),
        final_response=final_response,
        turn_completed=turn_completed,
    )


def score_response_markers(
    response: str,
    *,
    markers: Mapping[str, Sequence[str]],
) -> dict[str, float]:
    """Deterministic acceptance scorer over pre-registered semantic markers."""

    if not isinstance(response, str) or set(markers) != set(QUALITY_DIMENSIONS):
        raise ValueError("response markers must cover every quality dimension")
    folded = response.casefold()
    scores: dict[str, float] = {}
    for dimension in QUALITY_DIMENSIONS:
        expected = tuple(markers[dimension])
        if not expected or any(not isinstance(value, str) or not value for value in expected):
            raise ValueError("quality marker sets must be non-empty strings")
        scores[dimension] = sum(value.casefold() in folded for value in expected) / len(
            expected
        )
    return scores


@dataclass(frozen=True, slots=True)
class ToolTraceEvent:
    tool_name: str
    response: Mapping[str, object]
    arguments: Mapping[str, object] = field(default_factory=dict)
    ordinal: int = 0
    status: str = "completed"
    failed: bool = False
    raw: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CodexTraceGateReport:
    status: str
    target_call_count: int
    successful_call_count: int
    unrelated_call_count: int
    findings: tuple[str, ...]


def evaluate_codex_trace(
    trace: CodexToolTrace,
    *,
    should_call: bool,
    maximum_target_calls: int,
    required_sequence: Sequence[str] = (),
    expected_identity: AuthorityIdentity | None = None,
) -> CodexTraceGateReport:
    """Fail-closed state-machine gate for one real Codex JSONL trace."""

    if type(should_call) is not bool or type(maximum_target_calls) is not int:
        raise ValueError("trace gate flags are invalid")
    if maximum_target_calls < 0 or (should_call and maximum_target_calls < 1):
        raise ValueError("trace gate call budget is invalid")
    if any(name not in READ_TOOLS for name in required_sequence):
        raise ValueError("trace gate required sequence contains an unknown tool")
    findings: list[str] = []
    raw_events = trace.raw_events
    ordinals = tuple(event.ordinal for event in raw_events)
    if any(value < 1 for value in ordinals) or tuple(sorted(set(ordinals))) != ordinals:
        findings.append("raw_event_order_invalid")
    if len(raw_events) > maximum_target_calls:
        findings.append("target_call_budget_exceeded")
    if trace.failed_calls or any(event.failed for event in raw_events):
        findings.append("failed_target_call")
    if trace.unrelated_mcp_call_count or trace.unrelated_mcp_calls:
        findings.append("unrelated_mcp_call")
    if not trace.turn_completed:
        findings.append("turn_not_completed")
    if should_call:
        required = tuple(required_sequence) or (
            "search_quant_knowledge",
            "get_quant_knowledge",
        )
        observed = tuple(event.tool_name for event in trace.events)
        if not _is_subsequence(required, observed):
            findings.append("required_sequence_missing")
        if expected_identity is None:
            findings.append("expected_identity_missing")
        else:
            expected = expected_identity.to_dict()
            if any(event.response.get("identity") != expected for event in trace.events):
                findings.append("response_identity_mismatch")
    elif raw_events:
        findings.append("meaningless_target_call")

    returned_ids: set[str] = set()
    for event in sorted(raw_events, key=lambda value: value.ordinal):
        if event.failed:
            continue
        if event.tool_name == "search_quant_knowledge":
            results = event.response.get("results")
            if isinstance(results, list):
                returned_ids.update(
                    str(row["object_id"])
                    for row in results
                    if isinstance(row, dict)
                    and isinstance(row.get("object_id"), str)
                    and row["object_id"]
                )
        elif event.tool_name == "get_quant_knowledge":
            object_id = event.arguments.get("object_id")
            if not isinstance(object_id, str) or object_id not in returned_ids:
                findings.append(f"get_without_prior_search_result:line_{event.ordinal}")
    return CodexTraceGateReport(
        status="PASS" if not findings else "FAIL",
        target_call_count=len(raw_events),
        successful_call_count=len(trace.events),
        unrelated_call_count=trace.unrelated_mcp_call_count,
        findings=tuple(findings),
    )


@dataclass(frozen=True, slots=True)
class AcceptanceCaseDefinition:
    case_id: str
    prompt_bytes: bytes
    should_call: bool
    required_sequence: tuple[str, ...] = ()
    maximum_target_calls: int = 0


def _marker_definition_bytes(markers: Mapping[str, Sequence[str]]) -> bytes:
    if not isinstance(markers, Mapping) or set(markers) != set(QUALITY_DIMENSIONS):
        raise ValueError("marker definitions must cover every quality dimension")
    closed: dict[str, list[str]] = {}
    for dimension in QUALITY_DIMENSIONS:
        raw_values = markers[dimension]
        if not isinstance(raw_values, (list, tuple)):
            raise ValueError(
                "marker definitions must be non-empty unique list/tuple strings"
            )
        values = tuple(raw_values)
        if (
            not values
            or any(not isinstance(value, str) or not value for value in values)
            or len(set(values)) != len(values)
        ):
            raise ValueError(
                "marker definitions must be non-empty unique list/tuple strings"
            )
        closed[dimension] = list(values)
    return canonical_json(closed).encode("utf-8")


def build_acceptance_preregistration(
    *,
    suite_id: str,
    cases: Sequence[AcceptanceCaseDefinition],
    marker_definitions: Mapping[str, Sequence[str]],
    minimum_net_gain: float = 0.05,
) -> bytes:
    """Build deterministic future-suite evidence without storing prompt text."""

    if (
        not isinstance(suite_id, str)
        or not suite_id
        or not cases
        or isinstance(minimum_net_gain, bool)
        or not isinstance(minimum_net_gain, (int, float))
        or not 0 <= minimum_net_gain <= 1
    ):
        raise ValueError("acceptance preregistration header is invalid")
    marker_bytes = _marker_definition_bytes(marker_definitions)
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for case in cases:
        if (
            not case.case_id
            or case.case_id in seen
            or not isinstance(case.prompt_bytes, bytes)
            or not case.prompt_bytes
            or type(case.should_call) is not bool
            or type(case.maximum_target_calls) is not int
            or case.maximum_target_calls < (1 if case.should_call else 0)
            or any(name not in READ_TOOLS for name in case.required_sequence)
            or (case.should_call and not case.required_sequence)
            or (
                not case.should_call
                and (case.required_sequence or case.maximum_target_calls != 0)
            )
        ):
            raise ValueError("acceptance preregistration case is invalid")
        seen.add(case.case_id)
        rows.append(
            {
                "case_id": case.case_id,
                "prompt_bytes": len(case.prompt_bytes),
                "prompt_sha256": hashlib.sha256(case.prompt_bytes).hexdigest(),
                "should_call": case.should_call,
                "required_sequence": list(case.required_sequence),
                "maximum_target_calls": case.maximum_target_calls,
            }
        )
    value = {
        "schema_version": ACCEPTANCE_PREREGISTRATION_SCHEMA,
        "suite_id": suite_id,
        "marker_definition_bytes_base64": base64.b64encode(marker_bytes).decode("ascii"),
        "marker_definition_sha256": hashlib.sha256(marker_bytes).hexdigest(),
        "minimum_net_gain_each_dimension": minimum_net_gain,
        "cases": rows,
    }
    return canonical_json(value).encode("utf-8")


def validate_acceptance_preregistration_bytes(payload: bytes) -> Mapping[str, object]:
    """Validate canonical bytes and every closed future-suite binding field."""

    if not isinstance(payload, bytes) or not payload:
        raise ValueError("acceptance preregistration bytes are invalid")
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("acceptance preregistration is invalid UTF-8 JSON") from error
    expected_fields = {
        "schema_version",
        "suite_id",
        "marker_definition_bytes_base64",
        "marker_definition_sha256",
        "minimum_net_gain_each_dimension",
        "cases",
    }
    if (
        not isinstance(value, dict)
        or set(value) != expected_fields
        or value.get("schema_version") != ACCEPTANCE_PREREGISTRATION_SCHEMA
        or canonical_json(value).encode("utf-8") != payload
    ):
        raise ValueError("acceptance preregistration envelope is not closed canonical JSON")
    if not isinstance(value["marker_definition_bytes_base64"], str):
        raise ValueError("acceptance marker definition bytes are invalid")
    try:
        marker_bytes = base64.b64decode(
            value["marker_definition_bytes_base64"], validate=True
        )
        markers = json.loads(marker_bytes.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("acceptance marker definition bytes are invalid") from error
    normalized_marker_bytes = _marker_definition_bytes(markers)
    if normalized_marker_bytes != marker_bytes:
        raise ValueError(
            "acceptance marker definition bytes do not match canonical normalization"
        )
    if hashlib.sha256(marker_bytes).hexdigest() != value["marker_definition_sha256"]:
        raise ValueError("acceptance marker definition hash is invalid")
    gain = value["minimum_net_gain_each_dimension"]
    if (
        isinstance(gain, bool)
        or not isinstance(gain, (int, float))
        or not 0 <= gain <= 1
        or not isinstance(value["suite_id"], str)
        or not value["suite_id"]
        or not isinstance(value["cases"], list)
        or not value["cases"]
    ):
        raise ValueError("acceptance preregistration header values are invalid")
    case_fields = {
        "case_id",
        "prompt_bytes",
        "prompt_sha256",
        "should_call",
        "required_sequence",
        "maximum_target_calls",
    }
    seen: set[str] = set()
    for case in value["cases"]:
        if not isinstance(case, dict) or set(case) != case_fields:
            raise ValueError("acceptance preregistration case fields are not closed")
        case_id = case["case_id"]
        required = case["required_sequence"]
        should_call = case["should_call"]
        maximum = case["maximum_target_calls"]
        if (
            not isinstance(case_id, str)
            or not case_id
            or case_id in seen
            or type(case["prompt_bytes"]) is not int
            or case["prompt_bytes"] < 1
            or not isinstance(case["prompt_sha256"], str)
            or len(case["prompt_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in case["prompt_sha256"])
            or type(should_call) is not bool
            or not isinstance(required, list)
            or any(name not in READ_TOOLS for name in required)
            or type(maximum) is not int
            or maximum < (1 if should_call else 0)
            or (should_call and not required)
            or (not should_call and (required or maximum != 0))
        ):
            raise ValueError("acceptance preregistration case values are invalid")
        seen.add(case_id)
    return value


@dataclass(frozen=True, slots=True)
class ToolChoiceCase:
    case_id: str
    should_call: bool
    events: tuple[ToolTraceEvent, ...]
    required_sequence: tuple[str, ...] = ()
    expected_identity: AuthorityIdentity | None = None
    decision_claims_current: bool = False
    assisted_quality: Mapping[str, float] | None = None
    no_mcp_quality: Mapping[str, float] | None = None


@dataclass(frozen=True, slots=True)
class ToolChoiceReport:
    status: str
    case_count: int
    should_call_accuracy: float
    should_not_call_accuracy: float
    grounded_gain_cases: int
    findings: tuple[str, ...]


def _is_subsequence(required: Sequence[str], observed: Sequence[str]) -> bool:
    position = 0
    for name in observed:
        if position < len(required) and name == required[position]:
            position += 1
    return position == len(required)


def _quality_gain(case: ToolChoiceCase, minimum_net_gain: float) -> bool:
    assisted = case.assisted_quality
    baseline = case.no_mcp_quality
    if assisted is None or baseline is None:
        return False
    if set(assisted) != set(QUALITY_DIMENSIONS) or set(baseline) != set(
        QUALITY_DIMENSIONS
    ):
        return False
    for dimension in QUALITY_DIMENSIONS:
        assisted_value = assisted[dimension]
        baseline_value = baseline[dimension]
        if (
            isinstance(assisted_value, bool)
            or isinstance(baseline_value, bool)
            or not isinstance(assisted_value, (int, float))
            or not isinstance(baseline_value, (int, float))
            or not 0 <= assisted_value <= 1
            or not 0 <= baseline_value <= 1
            or assisted_value - baseline_value < minimum_net_gain
        ):
            return False
    return True


def evaluate_tool_choice(
    cases: Sequence[ToolChoiceCase], *, minimum_net_gain: float = 0.05
) -> ToolChoiceReport:
    if not cases or not 0 <= minimum_net_gain <= 1:
        raise ValueError("cases and minimum_net_gain are invalid")
    findings: list[str] = []
    should_total = should_correct = no_call_total = no_call_correct = gain_cases = 0
    seen: set[str] = set()
    for case in cases:
        if not case.case_id or case.case_id in seen:
            raise ValueError("tool-choice case IDs must be non-empty and unique")
        seen.add(case.case_id)
        observed = tuple(event.tool_name for event in case.events)
        if any(name not in READ_TOOLS for name in observed):
            findings.append(f"{case.case_id}:unknown_or_non_read_tool")
        if case.should_call:
            should_total += 1
            required = case.required_sequence or (
                "search_quant_knowledge",
                "get_quant_knowledge",
            )
            sequence_ok = _is_subsequence(required, observed)
            if sequence_ok:
                should_correct += 1
            else:
                findings.append(f"{case.case_id}:required_sequence_missing")
            if case.expected_identity is None:
                findings.append(f"{case.case_id}:expected_identity_missing")
            else:
                expected = case.expected_identity.to_dict()
                for ordinal, event in enumerate(case.events, 1):
                    if event.response.get("identity") != expected:
                        findings.append(
                            f"{case.case_id}:event_{ordinal}_identity_mismatch"
                        )
            if case.decision_claims_current and any(
                event.response.get("availability") != "fresh" for event in case.events
            ):
                findings.append(f"{case.case_id}:stale_or_unavailable_supported_current")
            if _quality_gain(case, minimum_net_gain):
                gain_cases += 1
            else:
                findings.append(f"{case.case_id}:no_reproducible_quality_gain")
        else:
            no_call_total += 1
            if not observed:
                no_call_correct += 1
            else:
                findings.append(f"{case.case_id}:meaningless_tool_call")
    if should_total == 0 or no_call_total == 0:
        findings.append("suite:positive_and_negative_cases_required")
    return ToolChoiceReport(
        status="PASS" if not findings else "FAIL",
        case_count=len(cases),
        should_call_accuracy=should_correct / should_total if should_total else 0.0,
        should_not_call_accuracy=no_call_correct / no_call_total if no_call_total else 0.0,
        grounded_gain_cases=gain_cases,
        findings=tuple(findings),
    )


__all__ = [
    "ACCEPTANCE_PREREGISTRATION_SCHEMA",
    "AcceptanceCaseDefinition",
    "CODEX_TRACE_MAX_BYTES",
    "CodexTraceGateReport",
    "CodexToolTrace",
    "QUALITY_DIMENSIONS",
    "ToolChoiceCase",
    "ToolChoiceReport",
    "ToolTraceEvent",
    "build_acceptance_preregistration",
    "evaluate_codex_trace",
    "evaluate_tool_choice",
    "load_codex_tool_trace",
    "score_response_markers",
    "validate_acceptance_preregistration_bytes",
]
