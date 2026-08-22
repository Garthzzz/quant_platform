"""Machine gate for implicit tool choice and MCP/no-MCP research gain traces."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Mapping, Sequence
import unicodedata

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
ACCEPTANCE_PREREGISTRATION_SCHEMA = "qrh-mcp-acceptance-preregistration/v2-bound"
ACCEPTANCE_CAMPAIGN_RECEIPT_SCHEMA = "qrh-mcp-acceptance-campaign-receipt/v2-raw-replay"
MAX_TARGET_CALLS_PER_CASE = 6
MAX_TARGET_CALLS_PER_CAMPAIGN = 48
MAX_ACCEPTANCE_CASES = 24
MAX_ACCEPTANCE_PROMPT_BYTES = 64 * 1024
MAX_ACCEPTANCE_CONFIG_BYTES = 1024 * 1024
MAX_ACCEPTANCE_MARKER_BYTES = 64 * 1024
MAX_ACCEPTANCE_CAMPAIGN_TRACE_BYTES = 256 * 1024 * 1024
STRUCTURED_ACCEPTANCE_RESPONSE_SCHEMA = "qrh-mcp-structured-acceptance-response/v1"
ACCEPTANCE_PREREGISTRATION_LEDGER_SCHEMA = "qrh-mcp-preregistration-ledger/v1"
ACCEPTANCE_FAKE_DISPATCH_SCHEMA = "qrh-mcp-fake-dispatch-receipt/v1"


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
    turn_started_at: str | None
    turn_terminal_at: str | None
    turn_terminal: str
    run_id: str | None
    case_id: str | None
    model: str | None
    config_sha256: str | None
    arm: str | None


def load_codex_tool_trace(
    path: Path,
    *,
    server_name: str = "quant_research_knowledge",
    max_bytes: int = CODEX_TRACE_MAX_BYTES,
) -> CodexToolTrace:
    """Load one raw JSONL trace path through the canonical byte parser."""

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
    return load_codex_tool_trace_bytes(
        payload,
        server_name=server_name,
        max_bytes=max_bytes,
    )


def load_codex_tool_trace_bytes(
    payload: bytes,
    *,
    server_name: str = "quant_research_knowledge",
    max_bytes: int = CODEX_TRACE_MAX_BYTES,
) -> CodexToolTrace:
    """Parse immutable raw JSONL bytes; never accept prebuilt trace events."""

    if (
        not server_name
        or max_bytes < 1
        or not isinstance(payload, bytes)
        or not 0 < len(payload) <= max_bytes
    ):
        raise ValueError("Codex trace bytes are outside the accepted range")
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
    agent_message_seen = False
    agent_message_count = 0
    turn_completed = False
    turn_started = False
    turn_terminal = ""
    turn_started_at: str | None = None
    turn_terminal_at: str | None = None
    run_id = case_id = model = config_sha256 = arm = None
    thread_started = False
    active_items: dict[str, Mapping[str, object]] = {}
    closed_items: set[str] = set()
    rows_with_ordinals = [(ordinal, line) for ordinal, line in enumerate(lines, 1) if line.strip()]
    if not rows_with_ordinals:
        raise ValueError("Codex trace has no events")
    for position, (ordinal, line) in enumerate(rows_with_ordinals):
        if not line.strip():
            continue
        try:
            row = json.loads(line, object_pairs_hook=_reject_duplicate_json_keys)
        except (json.JSONDecodeError, ValueError) as error:
            raise ValueError(f"Codex trace line {ordinal} is invalid JSON") from error
        if not isinstance(row, dict):
            raise ValueError(f"Codex trace line {ordinal} is not an object")
        row_type = row.get("type")
        if row_type not in {
            "thread.started", "turn.started", "item.started", "item.completed",
            "item.failed", "turn.completed", "turn.failed",
        }:
            raise ValueError(f"Codex trace line {ordinal} has unknown event type")
        if turn_terminal:
            raise ValueError("Codex turn terminal event must be unique and last")
        if row_type == "thread.started":
            if position != 0 or thread_started or turn_started:
                raise ValueError("Codex thread.started state is invalid")
            thread_started = True
            continue
        if row_type == "turn.started":
            if turn_started or active_items or closed_items:
                raise ValueError("Codex turn.started state is invalid")
            turn_started = True
            turn_started_at = _event_timestamp(row, ordinal)
            binding_fields = ("run_id", "case_id", "model", "config_sha256", "arm")
            bindings = [row.get(name) for name in binding_fields]
            if any(value is not None for value in bindings) and any(
                not isinstance(value, str) or not value for value in bindings
            ):
                raise ValueError("Codex turn.started bindings are incomplete")
            run_id, case_id, model, config_sha256, arm = bindings
            if arm is not None and arm not in {"assisted", "no_mcp"}:
                raise ValueError("Codex turn.started arm is invalid")
            continue
        if not turn_started:
            raise ValueError("Codex trace item/terminal precedes turn.started")
        if row_type in {"turn.completed", "turn.failed"}:
            if active_items:
                raise ValueError("Codex turn closed with unfinished items")
            if position != len(rows_with_ordinals) - 1:
                raise ValueError("Codex turn terminal event must be last")
            turn_terminal = str(row_type)
            turn_completed = row_type == "turn.completed"
            turn_terminal_at = _event_timestamp(row, ordinal)
            continue
        item = row.get("item")
        if not isinstance(item, dict):
            raise ValueError(f"Codex trace line {ordinal} item is invalid")
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise ValueError(f"Codex trace line {ordinal} item ID is invalid")
        if row_type == "item.started":
            if agent_message_seen:
                raise ValueError("Codex final agent message must be the last item")
            if item_id in active_items or item_id in closed_items:
                raise ValueError(f"Codex trace line {ordinal} item start is duplicate")
            if item.get("type") not in {"mcp_tool_call", "agent_message", "reasoning"}:
                raise ValueError(f"Codex trace line {ordinal} item type is unknown")
            if item.get("type") == "mcp_tool_call" and (
                not isinstance(item.get("server"), str)
                or not item["server"]
                or not isinstance(item.get("tool"), str)
                or not item["tool"]
                or not isinstance(item.get("arguments"), dict)
            ):
                raise ValueError(
                    f"Codex trace line {ordinal} tool start identity is incomplete"
                )
            active_items[item_id] = dict(item)
            continue
        if item_id not in active_items or item_id in closed_items:
            raise ValueError(f"Codex trace line {ordinal} item terminal has no open start")
        started_item = active_items.pop(item_id)
        closed_items.add(item_id)
        if item.get("type") != started_item.get("type"):
            raise ValueError(f"Codex trace line {ordinal} item type changed")
        if any(
            name != "status" and item.get(name) != value
            for name, value in started_item.items()
        ):
            identity_kind = (
                "tool identity"
                if item.get("type") == "mcp_tool_call"
                else "item identity"
            )
            raise ValueError(f"Codex trace line {ordinal} {identity_kind} changed")
        if agent_message_seen:
            raise ValueError("Codex final agent message must be the last item")
        if item.get("type") == "mcp_tool_call" and any(
            item.get(name) != started_item.get(name)
            for name in ("server", "tool", "arguments")
        ):
            raise ValueError(f"Codex trace line {ordinal} tool identity changed")
        item_failed = row_type == "item.failed"
        if item.get("type") == "agent_message":
            if item_failed:
                failed.append(f"line_{ordinal}:agent_message:failed")
                continue
            text = item.get("text")
            if not isinstance(text, str) or not text.strip():
                raise ValueError("Codex completed agent message must be non-empty")
            agent_message_count += 1
            if agent_message_count != 1:
                raise ValueError("Codex trace has multiple completed agent messages")
            if active_items:
                raise ValueError("Codex final agent message must be the last open item")
            agent_message_seen = True
            final_response = text
            continue
        if item.get("type") == "reasoning":
            if item_failed:
                failed.append(f"line_{ordinal}:reasoning:failed")
            continue
        if item.get("type") != "mcp_tool_call":
            raise ValueError(f"Codex trace line {ordinal} item type is unknown")
        arguments = item.get("arguments")
        safe_arguments = arguments if isinstance(arguments, dict) else {}
        status = str(item.get("status") or "unknown")
        result = item.get("result")
        structured = result.get("structured_content") if isinstance(result, dict) else None
        response = structured if isinstance(structured, dict) else {}
        failed_call = (
            item_failed or status != "completed" or item.get("error") is not None
        )
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
    if not turn_terminal:
        raise ValueError("Codex trace has no closed turn terminal")
    if agent_message_count != 1 or not final_response.strip():
        raise ValueError("Codex trace must have exactly one non-empty final agent message")
    return CodexToolTrace(
        events=tuple(events),
        raw_events=tuple(raw_events),
        failed_calls=tuple(failed),
        unrelated_mcp_call_count=len(unrelated_events),
        unrelated_mcp_calls=tuple(unrelated_events),
        final_response=final_response,
        turn_completed=turn_completed,
        turn_started_at=turn_started_at,
        turn_terminal_at=turn_terminal_at,
        turn_terminal=turn_terminal,
        run_id=run_id,
        case_id=case_id,
        model=model,
        config_sha256=config_sha256,
        arm=arm,
    )


def _reject_duplicate_json_keys(
    pairs: Sequence[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key:{key}")
        result[key] = value
    return result


def _event_timestamp(row: Mapping[str, object], ordinal: int) -> str | None:
    value = row.get("timestamp")
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"Codex trace line {ordinal} timestamp is invalid")
    _parse_utc_timestamp(value)
    return value


def _parse_utc_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("timestamp is not ISO-8601") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("timestamp must be UTC")
    return parsed


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _write_new_bytes(path: Path, payload: bytes) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def record_acceptance_preregistration(
    preregistration: bytes, *, ledger_path: Path
) -> bytes:
    """Atomically record a preregistration before any campaign dispatch."""

    registered = validate_acceptance_preregistration_bytes(preregistration)
    receipt = canonical_json(
        {
            "schema_version": ACCEPTANCE_PREREGISTRATION_LEDGER_SCHEMA,
            "producer": "quant_hub.knowledge_mcp.evaluation/prereg-ledger-v1",
            "run_id": registered["run_id"],
            "registered_at": _utc_now(),
            "preregistration_bytes": len(preregistration),
            "preregistration_sha256": hashlib.sha256(preregistration).hexdigest(),
        }
    ).encode("utf-8")
    _write_new_bytes(ledger_path, receipt)
    return receipt


def _load_preregistration_ledger(
    ledger_path: Path, preregistration: bytes
) -> Mapping[str, object]:
    try:
        payload = Path(ledger_path).read_bytes()
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("acceptance preregistration ledger is invalid") from error
    registered = validate_acceptance_preregistration_bytes(preregistration)
    fields = {
        "schema_version", "producer", "run_id", "registered_at",
        "preregistration_bytes", "preregistration_sha256",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema_version") != ACCEPTANCE_PREREGISTRATION_LEDGER_SCHEMA
        or value.get("producer")
        != "quant_hub.knowledge_mcp.evaluation/prereg-ledger-v1"
        or value.get("run_id") != registered["run_id"]
        or value.get("preregistration_bytes") != len(preregistration)
        or value.get("preregistration_sha256")
        != hashlib.sha256(preregistration).hexdigest()
        or not isinstance(value.get("registered_at"), str)
        or canonical_json(value).encode("utf-8") != payload
    ):
        raise ValueError("acceptance preregistration ledger differs")
    _parse_utc_timestamp(value["registered_at"])
    return value


def score_response_markers(
    response: str,
    *,
    markers: Mapping[str, Sequence[str]],
) -> MarkerScoreReport:
    """Non-authoritative deterministic component scorer."""

    if not isinstance(response, str) or set(markers) != set(QUALITY_DIMENSIONS):
        raise ValueError("response markers must cover every quality dimension")
    normalized = _normalize_marker(response)
    marker_bytes = _marker_definition_bytes(markers)
    closed = json.loads(marker_bytes)
    scores: dict[str, float] = {}
    for dimension in QUALITY_DIMENSIONS:
        expected = tuple(closed[dimension])
        scores[dimension] = sum(value in normalized for value in expected) / len(
            expected
        )
    return MarkerScoreReport(
        authority="NON_AUTHORITATIVE_COMPONENT",
        scores=tuple((dimension, scores[dimension]) for dimension in QUALITY_DIMENSIONS),
    )


@dataclass(frozen=True, slots=True)
class MarkerScoreReport:
    authority: str
    scores: tuple[tuple[str, float], ...]

    def as_dict(self) -> dict[str, float]:
        return dict(self.scores)


def _normalize_marker(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


_CITATION_TUPLE_FIELDS = {
    "object_id", "document_version_id", "source_sha256", "span_id",
    "byte_start", "byte_end", "citation_id",
}


def _citation_tuple(value: Mapping[str, object]) -> tuple[object, ...]:
    return tuple(
        value[name]
        for name in (
            "object_id", "document_version_id", "source_sha256", "span_id",
            "byte_start", "byte_end", "citation_id",
        )
    )


def _valid_citation_tuple(value: object) -> bool:
    return bool(
        isinstance(value, dict)
        and set(value) == _CITATION_TUPLE_FIELDS
        and all(
            isinstance(value[name], str) and value[name]
            for name in (
                "object_id", "document_version_id", "span_id", "citation_id"
            )
        )
        and _is_sha256(value["source_sha256"])
        and type(value["byte_start"]) is int
        and type(value["byte_end"]) is int
        and 0 <= value["byte_start"] < value["byte_end"]
    )


def _parse_structured_response(
    response: str,
) -> dict[str, list[dict[str, object]]]:
    try:
        value = json.loads(response, object_pairs_hook=_reject_duplicate_json_keys)
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError("final response is not structured canonical JSON") from error
    fields = {"schema_version", "decision", "conditions", "limitations"}
    claim_fields = {"claim", "citations"}
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema_version") != STRUCTURED_ACCEPTANCE_RESPONSE_SCHEMA
        or canonical_json(value) != response
    ):
        raise ValueError("final response is not a closed structured response")
    result: dict[str, list[dict[str, object]]] = {}
    for section in ("decision", "conditions", "limitations"):
        rows = value[section]
        if not isinstance(rows, list) or not rows:
            raise ValueError("structured response sections must be non-empty")
        closed: list[dict[str, object]] = []
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != claim_fields
                or not isinstance(row["claim"], str)
                or not row["claim"].strip()
                or not isinstance(row["citations"], list)
                or not row["citations"]
                or any(not _valid_citation_tuple(item) for item in row["citations"])
                or len({canonical_json(item) for item in row["citations"]})
                != len(row["citations"])
            ):
                raise ValueError("structured response claim is invalid")
            closed.append(row)
        result[section] = closed
    return result


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
    authority: str = "NON_AUTHORITATIVE_COMPONENT"


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
    successful_gets: list[tuple[str, set[tuple[object, ...]]]] = []
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
                continue
            response_object_id = event.response.get("object_id")
            citations = event.response.get("source_citations")
            if response_object_id != object_id or not isinstance(citations, list) or not citations:
                findings.append(f"get_provenance_missing:line_{event.ordinal}")
                continue
            citation_tuples: set[tuple[object, ...]] = set()
            for citation in citations:
                if not isinstance(citation, dict) or citation.get("object_id") != object_id:
                    continue
                citation_ids = citation.get("citation_ids")
                if not isinstance(citation_ids, list):
                    continue
                for citation_id in citation_ids:
                    candidate = {
                        "object_id": object_id,
                        "document_version_id": citation.get("document_version_id"),
                        "source_sha256": citation.get("source_sha256"),
                        "span_id": citation.get("span_id"),
                        "byte_start": citation.get("byte_start"),
                        "byte_end": citation.get("byte_end"),
                        "citation_id": citation_id,
                    }
                    if _valid_citation_tuple(candidate):
                        citation_tuples.add(_citation_tuple(candidate))
            if not citation_tuples:
                findings.append(f"get_provenance_missing:line_{event.ordinal}")
                continue
            successful_gets.append((object_id, citation_tuples))
    if should_call and successful_gets:
        try:
            structured = _parse_structured_response(trace.final_response)
        except ValueError:
            findings.append("final_response_not_structured")
        else:
            cited = {
                _citation_tuple(citation)
                for section in structured.values()
                for claim in section
                for citation in claim["citations"]
            }
            allowed = set().union(*(values for _, values in successful_gets))
            if not cited <= allowed:
                findings.append("final_response_contains_unreturned_citation")
            for object_id, returned in successful_gets:
                if not cited & returned:
                    findings.append(
                        f"final_response_not_linked_to_prior_get:{object_id}"
                    )
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
    all_values: list[tuple[str, str]] = []
    for dimension in QUALITY_DIMENSIONS:
        raw_values = markers[dimension]
        if not isinstance(raw_values, (list, tuple)):
            raise ValueError(
                "marker definitions must be non-empty unique list/tuple strings"
            )
        values = tuple(raw_values)
        normalized = tuple(
            _normalize_marker(value) if isinstance(value, str) else ""
            for value in values
        )
        if (
            not values
            or any(not isinstance(value, str) or not value.strip() for value in values)
            or any(not value for value in normalized)
            or len(set(normalized)) != len(normalized)
        ):
            raise ValueError(
                "marker definitions must be non-empty unique list/tuple strings"
            )
        closed[dimension] = list(normalized)
        all_values.extend((dimension, value) for value in normalized)
    for index, (dimension, value) in enumerate(all_values):
        for other_dimension, other in all_values[index + 1 :]:
            if value in other or other in value:
                raise ValueError(
                    "normalized marker definitions must be globally unique and non-overlapping:"
                    f"{dimension}:{other_dimension}"
                )
    return canonical_json(closed).encode("utf-8")


def build_acceptance_preregistration(
    *,
    suite_id: str,
    authority_identity: AuthorityIdentity,
    server_name: str,
    model: str,
    config_bytes: bytes,
    run_id: str,
    preregistered_at: str,
    cases: Sequence[AcceptanceCaseDefinition],
    marker_definitions: Mapping[str, Sequence[str]],
    minimum_net_gain: float = 0.05,
) -> bytes:
    """Build deterministic future-suite evidence without storing prompt text."""

    if (
        not isinstance(suite_id, str)
        or not suite_id
        or not cases
        or not isinstance(authority_identity, AuthorityIdentity)
        or not isinstance(server_name, str)
        or not server_name
        or not isinstance(model, str)
        or not model
        or not isinstance(config_bytes, bytes)
        or not config_bytes
        or len(config_bytes) > MAX_ACCEPTANCE_CONFIG_BYTES
        or not isinstance(run_id, str)
        or not run_id
        or not isinstance(preregistered_at, str)
        or isinstance(minimum_net_gain, bool)
        or not isinstance(minimum_net_gain, (int, float))
        or not 0 < minimum_net_gain <= 1
        or len(cases) > MAX_ACCEPTANCE_CASES
    ):
        raise ValueError("acceptance preregistration header is invalid")
    identity_value = authority_identity.to_dict()
    if (
        not identity_value["release_id"]
        or not identity_value["snapshot_id"]
        or not _is_sha256(identity_value["manifest_sha256"])
    ):
        raise ValueError("acceptance preregistration authority identity is invalid")
    _parse_utc_timestamp(preregistered_at)
    marker_bytes = _marker_definition_bytes(marker_definitions)
    if len(marker_bytes) > MAX_ACCEPTANCE_MARKER_BYTES:
        raise ValueError("acceptance marker definition budget is exceeded")
    rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for case in cases:
        if (
            not case.case_id
            or case.case_id in seen
            or not isinstance(case.prompt_bytes, bytes)
            or not case.prompt_bytes
            or len(case.prompt_bytes) > MAX_ACCEPTANCE_PROMPT_BYTES
            or type(case.should_call) is not bool
            or type(case.maximum_target_calls) is not int
            or case.maximum_target_calls < (1 if case.should_call else 0)
            or case.maximum_target_calls > MAX_TARGET_CALLS_PER_CASE
            or any(name not in READ_TOOLS for name in case.required_sequence)
            or (case.should_call and not case.required_sequence)
            or (
                case.should_call
                and not _is_subsequence(
                    ("search_quant_knowledge", "get_quant_knowledge"),
                    case.required_sequence,
                )
            )
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
    if sum(row["maximum_target_calls"] for row in rows) > MAX_TARGET_CALLS_PER_CAMPAIGN:
        raise ValueError("acceptance preregistration campaign budget is too large")
    value = {
        "schema_version": ACCEPTANCE_PREREGISTRATION_SCHEMA,
        "suite_id": suite_id,
        "authority_identity": authority_identity.to_dict(),
        "server_name": server_name,
        "model": model,
        "config_bytes": len(config_bytes),
        "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "run_id": run_id,
        "preregistered_at": preregistered_at,
        "marker_definition_bytes_base64": base64.b64encode(marker_bytes).decode("ascii"),
        "marker_definition_sha256": hashlib.sha256(marker_bytes).hexdigest(),
        "minimum_net_gain_each_dimension": minimum_net_gain,
        "cases": rows,
    }
    return canonical_json(value).encode("utf-8")


def validate_acceptance_preregistration_bytes(payload: bytes) -> Mapping[str, object]:
    """Validate canonical bytes and every closed future-suite binding field."""

    if (
        not isinstance(payload, bytes)
        or not payload
        or len(payload) > 2 * 1024 * 1024
    ):
        raise ValueError("acceptance preregistration bytes are invalid")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("acceptance preregistration is invalid UTF-8 JSON") from error
    expected_fields = {
        "schema_version",
        "suite_id",
        "authority_identity",
        "server_name",
        "model",
        "config_bytes",
        "config_sha256",
        "run_id",
        "preregistered_at",
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
        if len(marker_bytes) > MAX_ACCEPTANCE_MARKER_BYTES:
            raise ValueError("acceptance marker definition budget is exceeded")
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
        or not 0 < gain <= 1
        or not isinstance(value["suite_id"], str)
        or not value["suite_id"]
        or not isinstance(value["authority_identity"], dict)
        or set(value["authority_identity"]) != {
            "release_id", "manifest_sha256", "snapshot_id"
        }
        or not isinstance(value["server_name"], str)
        or not value["server_name"]
        or not isinstance(value["model"], str)
        or not value["model"]
        or type(value["config_bytes"]) is not int
        or value["config_bytes"] < 1
        or value["config_bytes"] > MAX_ACCEPTANCE_CONFIG_BYTES
        or not isinstance(value["config_sha256"], str)
        or not _is_sha256(value["config_sha256"])
        or not isinstance(value["run_id"], str)
        or not value["run_id"]
        or not isinstance(value["preregistered_at"], str)
        or not isinstance(value["cases"], list)
        or not value["cases"]
        or len(value["cases"]) > MAX_ACCEPTANCE_CASES
    ):
        raise ValueError("acceptance preregistration header values are invalid")
    try:
        identity = AuthorityIdentity(**value["authority_identity"])
        _parse_utc_timestamp(value["preregistered_at"])
    except (TypeError, ValueError) as error:
        raise ValueError("acceptance preregistration identity/time is invalid") from error
    if (
        not identity.release_id
        or not identity.snapshot_id
        or not _is_sha256(identity.manifest_sha256)
    ):
        raise ValueError("acceptance preregistration identity/time is invalid")
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
            or case["prompt_bytes"] > MAX_ACCEPTANCE_PROMPT_BYTES
            or not isinstance(case["prompt_sha256"], str)
            or len(case["prompt_sha256"]) != 64
            or any(character not in "0123456789abcdef" for character in case["prompt_sha256"])
            or type(should_call) is not bool
            or not isinstance(required, list)
            or any(name not in READ_TOOLS for name in required)
            or type(maximum) is not int
            or maximum < (1 if should_call else 0)
            or maximum > MAX_TARGET_CALLS_PER_CASE
            or (should_call and not required)
            or (
                should_call
                and not _is_subsequence(
                    ("search_quant_knowledge", "get_quant_knowledge"), required
                )
            )
            or (not should_call and (required or maximum != 0))
        ):
            raise ValueError("acceptance preregistration case values are invalid")
        seen.add(case_id)
    if sum(case["maximum_target_calls"] for case in value["cases"]) > MAX_TARGET_CALLS_PER_CAMPAIGN:
        raise ValueError("acceptance preregistration campaign budget is too large")
    return value


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


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


@dataclass(frozen=True, slots=True)
class PreregisteredAcceptanceCase:
    """One paired execution bound to a canonical preregistration case."""

    case_id: str
    prompt_bytes: bytes
    assisted_trace_bytes: bytes
    no_mcp_trace_bytes: bytes
    assisted_dispatch_intent: bytes = b""
    assisted_dispatch_completion: bytes = b""
    no_mcp_dispatch_intent: bytes = b""
    no_mcp_dispatch_completion: bytes = b""
    expected_identity: AuthorityIdentity | None = None


@dataclass(frozen=True, slots=True)
class IntegratedAcceptanceCaseReport:
    case_id: str
    assisted_trace_sha256: str
    no_mcp_trace_sha256: str
    assisted_trace_status: str
    no_mcp_trace_status: str
    assisted_dispatched_at: str
    assisted_completed_at: str
    no_mcp_dispatched_at: str
    no_mcp_completed_at: str
    assisted_quality: tuple[tuple[str, float], ...]
    no_mcp_quality: tuple[tuple[str, float], ...]
    quality_gains: tuple[tuple[str, float], ...]
    findings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IntegratedAcceptanceReport:
    status: str
    preregistration_sha256: str
    case_count: int
    should_call_count: int
    should_not_call_count: int
    case_reports: tuple[IntegratedAcceptanceCaseReport, ...]
    findings: tuple[str, ...]
    authority: str
    campaign_receipt: bytes


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
    del cases, minimum_net_gain
    raise ValueError(
        "unbound tool-choice events and caller-supplied quality floats are disabled; "
        "use evaluate_preregistered_acceptance"
    )


def _markers_from_preregistration(value: Mapping[str, object]) -> dict[str, list[str]]:
    try:
        marker_bytes = base64.b64decode(
            str(value["marker_definition_bytes_base64"]), validate=True
        )
        markers = json.loads(marker_bytes.decode("utf-8", errors="strict"))
    except (ValueError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("acceptance marker definition bytes are invalid") from error
    # The preregistration validator already closes this shape.  Re-run the
    # canonical helper here so this integrated path cannot be invoked with a
    # hand-built Mapping that bypassed byte validation.
    if _marker_definition_bytes(markers) != marker_bytes:
        raise ValueError("acceptance marker definition normalization drifted")
    return {dimension: list(markers[dimension]) for dimension in QUALITY_DIMENSIONS}


def _fake_dispatch_paths(
    ledger_root: Path, *, run_id: str, case_id: str, arm: str
) -> tuple[Path, Path]:
    key = canonical_json({"run_id": run_id, "case_id": case_id, "arm": arm})
    name = hashlib.sha256(key.encode("utf-8")).hexdigest()
    root = Path(ledger_root)
    return root / f"{name}.intent.json", root / f"{name}.complete.json"


def _validate_fake_dispatch(
    *,
    intent_payload: bytes,
    completion_payload: bytes,
    dispatch_ledger_root: Path,
    preregistration_ledger_value: Mapping[str, object],
    registered: Mapping[str, object],
    case_id: str,
    arm: str,
    prompt_bytes: bytes,
    config_bytes: bytes,
    trace_bytes: bytes,
) -> dict[str, str]:
    intent_path, completion_path = _fake_dispatch_paths(
        dispatch_ledger_root,
        run_id=str(registered["run_id"]),
        case_id=case_id,
        arm=arm,
    )
    try:
        if intent_path.read_bytes() != intent_payload:
            raise ValueError("fake dispatch intent ledger bytes differ")
        if completion_path.read_bytes() != completion_payload:
            raise ValueError("fake dispatch completion ledger bytes differ")
        intent = json.loads(
            intent_payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
        completion = json.loads(
            completion_payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("fake dispatch ledger is invalid") from error
    intent_fields = {
        "schema_version", "record_type", "runner", "run_id", "case_id",
        "arm", "dispatched_at", "preregistration_ledger_sha256",
        "prompt_sha256", "config_sha256",
    }
    completion_fields = {
        "schema_version", "record_type", "runner", "run_id", "case_id",
        "arm", "dispatched_at", "completed_at", "intent_sha256",
        "trace_bytes", "trace_sha256",
    }
    common = {
        "schema_version": ACCEPTANCE_FAKE_DISPATCH_SCHEMA,
        "runner": "FAKE_ONLY_REAL_CODEX_DISABLED",
        "run_id": registered["run_id"],
        "case_id": case_id,
        "arm": arm,
    }
    if (
        not isinstance(intent, dict)
        or set(intent) != intent_fields
        or not isinstance(completion, dict)
        or set(completion) != completion_fields
        or canonical_json(intent).encode("utf-8") != intent_payload
        or canonical_json(completion).encode("utf-8") != completion_payload
        or any(intent.get(name) != value for name, value in common.items())
        or any(completion.get(name) != value for name, value in common.items())
        or intent.get("record_type") != "INTENT"
        or completion.get("record_type") != "COMPLETE"
        or intent.get("prompt_sha256") != hashlib.sha256(prompt_bytes).hexdigest()
        or intent.get("config_sha256") != hashlib.sha256(config_bytes).hexdigest()
        or intent.get("preregistration_ledger_sha256")
        != hashlib.sha256(
            canonical_json(dict(preregistration_ledger_value)).encode("utf-8")
        ).hexdigest()
        or completion.get("intent_sha256") != hashlib.sha256(intent_payload).hexdigest()
        or completion.get("trace_bytes") != len(trace_bytes)
        or completion.get("trace_sha256") != hashlib.sha256(trace_bytes).hexdigest()
        or completion.get("dispatched_at") != intent.get("dispatched_at")
        or not isinstance(intent.get("dispatched_at"), str)
        or not isinstance(completion.get("completed_at"), str)
    ):
        raise ValueError("fake dispatch evidence binding is invalid")
    registered_at = _parse_utc_timestamp(
        str(preregistration_ledger_value["registered_at"])
    )
    dispatched_at = _parse_utc_timestamp(intent["dispatched_at"])
    completed_at = _parse_utc_timestamp(completion["completed_at"])
    if not registered_at < dispatched_at <= completed_at:
        raise ValueError("fake dispatch did not follow preregistration")
    return {
        "dispatched_at": intent["dispatched_at"],
        "completed_at": completion["completed_at"],
    }


def evaluate_preregistered_acceptance(
    preregistration: bytes,
    cases: Sequence[PreregisteredAcceptanceCase],
    *,
    preregistration_ledger: Path,
    dispatch_ledger_root: Path,
    config_bytes: bytes,
) -> IntegratedAcceptanceReport:
    """Issue the only final MCP/no-MCP acceptance verdict.

    The gate binds canonical preregistration bytes, exact prompt bytes, immutable
    raw Codex JSONL bytes, call budgets, failures/unrelated calls, search→get
    provenance, response identities and marker-derived paired quality.  It
    deliberately has no caller-supplied trace-event or quality-float input.
    """

    registered = validate_acceptance_preregistration_bytes(preregistration)
    ledger_value = _load_preregistration_ledger(
        preregistration_ledger, preregistration
    )
    if (
        not isinstance(config_bytes, bytes)
        or len(config_bytes) != registered["config_bytes"]
        or hashlib.sha256(config_bytes).hexdigest() != registered["config_sha256"]
    ):
        raise ValueError("acceptance config bytes differ from preregistration")
    expected_identity = AuthorityIdentity(**registered["authority_identity"])
    server_name = str(registered["server_name"])
    markers = _markers_from_preregistration(registered)
    definitions = tuple(registered["cases"])
    if not cases or len(cases) != len(definitions):
        raise ValueError("acceptance result cases do not match preregistration")
    case_by_id: dict[str, PreregisteredAcceptanceCase] = {}
    for case in cases:
        if not case.case_id or case.case_id in case_by_id:
            raise ValueError("acceptance result case IDs must be non-empty and unique")
        case_by_id[case.case_id] = case
    registered_ids = tuple(str(row["case_id"]) for row in definitions)
    if set(case_by_id) != set(registered_ids):
        raise ValueError("acceptance result case IDs do not match preregistration")
    total_trace_bytes = sum(
        len(case.assisted_trace_bytes) + len(case.no_mcp_trace_bytes)
        for case in cases
        if isinstance(case.assisted_trace_bytes, bytes)
        and isinstance(case.no_mcp_trace_bytes, bytes)
    )
    if total_trace_bytes > MAX_ACCEPTANCE_CAMPAIGN_TRACE_BYTES:
        raise ValueError("acceptance campaign trace byte budget is exceeded")

    findings: list[str] = []
    reports: list[IntegratedAcceptanceCaseReport] = []
    should_call_count = should_not_call_count = 0
    minimum_gain = float(registered["minimum_net_gain_each_dimension"])
    for definition in definitions:
        case_finding_start = len(findings)
        case_id = str(definition["case_id"])
        case = case_by_id[case_id]
        if (
            not isinstance(case.prompt_bytes, bytes)
            or len(case.prompt_bytes) != definition["prompt_bytes"]
            or hashlib.sha256(case.prompt_bytes).hexdigest()
            != definition["prompt_sha256"]
        ):
            findings.append(f"{case_id}:prompt_bytes_mismatch")
        should_call = bool(definition["should_call"])
        if should_call:
            should_call_count += 1
        else:
            should_not_call_count += 1
            if case.expected_identity is not None:
                findings.append(f"{case_id}:unexpected_identity_for_no_call_case")
        if not isinstance(case.assisted_trace_bytes, bytes) or not isinstance(
            case.no_mcp_trace_bytes, bytes
        ):
            raise ValueError("acceptance cases require immutable raw trace bytes")
        assisted_trace_sha256 = hashlib.sha256(case.assisted_trace_bytes).hexdigest()
        no_mcp_trace_sha256 = hashlib.sha256(case.no_mcp_trace_bytes).hexdigest()
        assisted_dispatch = _validate_fake_dispatch(
            intent_payload=case.assisted_dispatch_intent,
            completion_payload=case.assisted_dispatch_completion,
            dispatch_ledger_root=dispatch_ledger_root,
            preregistration_ledger_value=ledger_value,
            registered=registered,
            case_id=case_id,
            arm="assisted",
            prompt_bytes=case.prompt_bytes,
            config_bytes=config_bytes,
            trace_bytes=case.assisted_trace_bytes,
        )
        no_mcp_dispatch = _validate_fake_dispatch(
            intent_payload=case.no_mcp_dispatch_intent,
            completion_payload=case.no_mcp_dispatch_completion,
            dispatch_ledger_root=dispatch_ledger_root,
            preregistration_ledger_value=ledger_value,
            registered=registered,
            case_id=case_id,
            arm="no_mcp",
            prompt_bytes=case.prompt_bytes,
            config_bytes=config_bytes,
            trace_bytes=case.no_mcp_trace_bytes,
        )
        assisted_trace = load_codex_tool_trace_bytes(
            case.assisted_trace_bytes, server_name=server_name
        )
        no_mcp_trace = load_codex_tool_trace_bytes(
            case.no_mcp_trace_bytes, server_name=server_name
        )
        expected_bindings = {
            "run_id": registered["run_id"],
            "case_id": case_id,
            "model": registered["model"],
            "config_sha256": registered["config_sha256"],
        }
        for arm_name, trace in (("assisted", assisted_trace), ("no_mcp", no_mcp_trace)):
            actual = {
                "run_id": trace.run_id,
                "case_id": trace.case_id,
                "model": trace.model,
                "config_sha256": trace.config_sha256,
            }
            if actual != expected_bindings or trace.arm != arm_name:
                findings.append(f"{case_id}:{arm_name}:run_binding_mismatch")
        if case.expected_identity is not None and case.expected_identity != expected_identity:
            findings.append(f"{case_id}:caller_identity_differs_from_preregistration")
        assisted_gate = evaluate_codex_trace(
            assisted_trace,
            should_call=should_call,
            maximum_target_calls=int(definition["maximum_target_calls"]),
            required_sequence=tuple(definition["required_sequence"]),
            expected_identity=expected_identity if should_call else None,
        )
        control_gate = evaluate_codex_trace(
            no_mcp_trace,
            should_call=False,
            maximum_target_calls=0,
        )
        findings.extend(
            f"{case_id}:assisted:{finding}" for finding in assisted_gate.findings
        )
        findings.extend(
            f"{case_id}:no_mcp:{finding}" for finding in control_gate.findings
        )
        assisted_quality: dict[str, float] = {}
        no_mcp_quality: dict[str, float] = {}
        quality_gains: dict[str, float] = {}
        if should_call:
            try:
                structured = _parse_structured_response(
                    assisted_trace.final_response
                )
            except ValueError:
                structured = {"decision": [], "conditions": [], "limitations": []}
            assisted_quality = {
                "grounded_decision": score_response_markers(
                    " ".join(str(row["claim"]) for row in structured["decision"]),
                    markers=markers,
                ).as_dict()["grounded_decision"],
                "condition_limitation_recognition": score_response_markers(
                    " ".join(
                        str(row["claim"])
                        for section in ("conditions", "limitations")
                        for row in structured[section]
                    ),
                    markers=markers,
                ).as_dict()["condition_limitation_recognition"],
                "citation_correctness": (
                    1.0
                    if structured["decision"]
                    and not any(
                        finding.startswith("get_provenance_missing")
                        or finding.startswith("final_response_")
                        for finding in assisted_gate.findings
                    )
                    else 0.0
                ),
            }
            no_mcp_quality = score_response_markers(
                no_mcp_trace.final_response,
                markers=markers,
            ).as_dict()
            no_mcp_quality["citation_correctness"] = 0.0
            quality_gains = {
                dimension: assisted_quality[dimension] - no_mcp_quality[dimension]
                for dimension in QUALITY_DIMENSIONS
            }
            for dimension in QUALITY_DIMENSIONS:
                if quality_gains[dimension] < minimum_gain:
                    findings.append(
                        f"{case_id}:quality_gain_below_preregistered_minimum:{dimension}"
                    )
        reports.append(
            IntegratedAcceptanceCaseReport(
                case_id=case_id,
                assisted_trace_sha256=assisted_trace_sha256,
                no_mcp_trace_sha256=no_mcp_trace_sha256,
                assisted_trace_status=assisted_gate.status,
                no_mcp_trace_status=control_gate.status,
                assisted_dispatched_at=assisted_dispatch["dispatched_at"],
                assisted_completed_at=assisted_dispatch["completed_at"],
                no_mcp_dispatched_at=no_mcp_dispatch["dispatched_at"],
                no_mcp_completed_at=no_mcp_dispatch["completed_at"],
                assisted_quality=tuple(
                    (dimension, assisted_quality[dimension])
                    for dimension in QUALITY_DIMENSIONS
                    if dimension in assisted_quality
                ),
                no_mcp_quality=tuple(
                    (dimension, no_mcp_quality[dimension])
                    for dimension in QUALITY_DIMENSIONS
                    if dimension in no_mcp_quality
                ),
                quality_gains=tuple(
                    (dimension, quality_gains[dimension])
                    for dimension in QUALITY_DIMENSIONS
                    if dimension in quality_gains
                ),
                findings=tuple(findings[case_finding_start:]),
            )
        )
    if should_call_count == 0 or should_not_call_count == 0:
        findings.append("suite:positive_and_negative_cases_required")
    campaign_value = {
        "schema_version": ACCEPTANCE_CAMPAIGN_RECEIPT_SCHEMA,
        "producer": "quant_hub.knowledge_mcp.evaluation/v3-raw-replay",
        "authority": "AUTHORITATIVE_INTEGRATED_GATE",
        "preregistration": {
            "bytes": len(preregistration),
            "sha256": hashlib.sha256(preregistration).hexdigest(),
            "preregistered_at": registered["preregistered_at"],
            "ledger_registered_at": ledger_value["registered_at"],
        },
        "run_id": registered["run_id"],
        "server_name": registered["server_name"],
        "model": registered["model"],
        "config_sha256": registered["config_sha256"],
        "cases": [
            {
                "case_id": report.case_id,
                "assisted_trace_sha256": report.assisted_trace_sha256,
                "no_mcp_trace_sha256": report.no_mcp_trace_sha256,
                "assisted_dispatch": {
                    "dispatched_at": report.assisted_dispatched_at,
                    "completed_at": report.assisted_completed_at,
                },
                "no_mcp_dispatch": {
                    "dispatched_at": report.no_mcp_dispatched_at,
                    "completed_at": report.no_mcp_completed_at,
                },
                "assisted_trace_status": report.assisted_trace_status,
                "no_mcp_trace_status": report.no_mcp_trace_status,
                "assisted_quality": dict(report.assisted_quality),
                "no_mcp_quality": dict(report.no_mcp_quality),
                "quality_gains": dict(report.quality_gains),
                "findings": list(report.findings),
            }
            for report in reports
        ],
        "status": "PASS" if not findings else "FAIL",
        "findings": list(findings),
    }
    campaign_receipt = canonical_json(campaign_value).encode("utf-8")
    return IntegratedAcceptanceReport(
        status="PASS" if not findings else "FAIL",
        preregistration_sha256=hashlib.sha256(preregistration).hexdigest(),
        case_count=len(reports),
        should_call_count=should_call_count,
        should_not_call_count=should_not_call_count,
        case_reports=tuple(reports),
        findings=tuple(findings),
        authority="AUTHORITATIVE_INTEGRATED_GATE",
        campaign_receipt=campaign_receipt,
    )


def _campaign_trace_timing(payload: bytes, server_name: str) -> dict[str, str | None]:
    trace = load_codex_tool_trace_bytes(payload, server_name=server_name)
    return {
        "started_at": trace.turn_started_at,
        "terminal_at": trace.turn_terminal_at,
        "terminal": trace.turn_terminal,
    }


def validate_acceptance_campaign_receipt_bytes(
    payload: bytes,
    *,
    preregistration: bytes,
    cases: Sequence[PreregisteredAcceptanceCase],
    preregistration_ledger: Path,
    dispatch_ledger_root: Path,
    config_bytes: bytes,
) -> Mapping[str, object]:
    """Replay exact prompts/config/raw traces and compare the canonical receipt."""

    if not isinstance(payload, bytes) or not payload:
        raise ValueError("acceptance campaign receipt bytes are invalid")
    replay = evaluate_preregistered_acceptance(
        preregistration,
        cases,
        preregistration_ledger=preregistration_ledger,
        dispatch_ledger_root=dispatch_ledger_root,
        config_bytes=config_bytes,
    )
    if payload != replay.campaign_receipt:
        raise ValueError("acceptance campaign receipt differs from raw replay")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError("acceptance campaign receipt is invalid JSON") from error
    return value


__all__ = [
    "ACCEPTANCE_CAMPAIGN_RECEIPT_SCHEMA",
    "ACCEPTANCE_FAKE_DISPATCH_SCHEMA",
    "ACCEPTANCE_PREREGISTRATION_SCHEMA",
    "ACCEPTANCE_PREREGISTRATION_LEDGER_SCHEMA",
    "AcceptanceCaseDefinition",
    "CODEX_TRACE_MAX_BYTES",
    "CodexTraceGateReport",
    "CodexToolTrace",
    "IntegratedAcceptanceCaseReport",
    "IntegratedAcceptanceReport",
    "MAX_ACCEPTANCE_CAMPAIGN_TRACE_BYTES",
    "MAX_ACCEPTANCE_CASES",
    "MAX_ACCEPTANCE_CONFIG_BYTES",
    "MAX_ACCEPTANCE_MARKER_BYTES",
    "MAX_ACCEPTANCE_PROMPT_BYTES",
    "MAX_TARGET_CALLS_PER_CAMPAIGN",
    "MAX_TARGET_CALLS_PER_CASE",
    "MarkerScoreReport",
    "PreregisteredAcceptanceCase",
    "QUALITY_DIMENSIONS",
    "STRUCTURED_ACCEPTANCE_RESPONSE_SCHEMA",
    "ToolChoiceCase",
    "ToolChoiceReport",
    "ToolTraceEvent",
    "build_acceptance_preregistration",
    "evaluate_codex_trace",
    "evaluate_preregistered_acceptance",
    "evaluate_tool_choice",
    "load_codex_tool_trace",
    "load_codex_tool_trace_bytes",
    "record_acceptance_preregistration",
    "score_response_markers",
    "validate_acceptance_preregistration_bytes",
    "validate_acceptance_campaign_receipt_bytes",
]
