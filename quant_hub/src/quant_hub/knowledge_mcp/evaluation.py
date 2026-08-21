"""Machine gate for implicit tool choice and MCP/no-MCP research gain traces."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

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


@dataclass(frozen=True, slots=True)
class ToolTraceEvent:
    tool_name: str
    response: Mapping[str, object]


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
    "QUALITY_DIMENSIONS",
    "ToolChoiceCase",
    "ToolChoiceReport",
    "ToolTraceEvent",
    "evaluate_tool_choice",
]
