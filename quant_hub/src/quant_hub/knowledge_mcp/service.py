"""Current-sensitive read-only tools shared by stdio and deterministic tests."""

from __future__ import annotations

import base64
from dataclasses import dataclass
import heapq
import hashlib
import hmac
import json
import re
import secrets
from typing import Any, Mapping

from quant_hub.knowledge.contracts import canonical_json
from quant_hub.knowledge.retrieval import ArtifactKnowledgeIndex, TaskContext

from .mirror import (
    AuthorityIdentity,
    AuthorityProbe,
    AuthorityUnavailable,
    MirrorError,
    MirrorSnapshot,
    MirrorStore,
)


SERVICE_SCHEMA = "qrh-knowledge-mcp-response/v2"
CONTINUATION_SCHEMA = "qrh-mcp-continuation/v2-session-mac"
MAX_QUERY_CHARS = 500
MAX_ID_CHARS = 200
MAX_CURSOR_CHARS = 4_096
MAX_TASK_CONTEXT_BYTES = 16 * 1024
MAX_TASK_CONTEXT_DEPTH = 32
MAX_SEARCH_WINDOW = 100
_TASK_CONTEXT_FACETS = frozenset(
    {"market", "frequency", "data", "objective", "assumption"}
)
_TOOL_ARGUMENT_FIELDS = {
    "search_quant_knowledge": frozenset(
        {
            "query",
            "task_context",
            "limit",
            "budget_chars",
            "detail",
            "cursor",
            "allow_stale",
            "include_history",
            "include_conflicts",
        }
    ),
    "get_quant_knowledge": frozenset(
        {
            "object_id",
            "include_history",
            "include_relations",
            "budget_chars",
            "allow_stale",
        }
    ),
    "list_knowledge_updates": frozenset(
        {
            "from_snapshot_id",
            "allow_stale",
            "limit",
            "budget_chars",
            "cursor",
        }
    ),
}
_TOOL_REQUIRED_FIELDS = {
    "search_quant_knowledge": frozenset({"query"}),
    "get_quant_knowledge": frozenset({"object_id"}),
    "list_knowledge_updates": frozenset({"from_snapshot_id"}),
}


def _closed_json_depth(value: object, *, depth: int = 1) -> int:
    if depth > MAX_TASK_CONTEXT_DEPTH:
        raise ValueError("task_context exceeds the supported depth")
    if value is None or type(value) in {bool, int, float, str}:
        try:
            canonical_json(value)
        except (TypeError, ValueError) as error:
            raise ValueError("task_context must contain canonical JSON values") from error
        return depth
    if type(value) is list:
        return max(
            (depth, *(_closed_json_depth(member, depth=depth + 1) for member in value))
        )
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ValueError("task_context keys must be strings")
        return max(
            (depth, *(_closed_json_depth(member, depth=depth + 1) for member in value.values()))
        )
    raise ValueError("task_context must contain canonical JSON values")


def _validate_task_context(value: object) -> None:
    if type(value) is not dict:
        raise ValueError("task_context must be an object")
    if not set(value).issubset(_TASK_CONTEXT_FACETS):
        raise ValueError("task_context fields are not closed")
    _closed_json_depth(value)
    if len(canonical_json(value).encode("utf-8")) > MAX_TASK_CONTEXT_BYTES:
        raise ValueError("task_context exceeds the supported size")
    for facet, member in value.items():
        values = [member] if isinstance(member, str) else member
        if type(values) is not list or any(type(item) is not str for item in values):
            raise ValueError(f"task_context.{facet} must be a string or list of strings")


def validate_tool_arguments(tool: str, arguments: Mapping[str, object]) -> None:
    """Enforce the advertised closed MCP schemas at every runtime boundary."""

    if type(arguments) is not dict or tool not in _TOOL_ARGUMENT_FIELDS:
        raise ValueError("tool arguments are invalid")
    fields = set(arguments)
    if not _TOOL_REQUIRED_FIELDS[tool].issubset(fields):
        raise ValueError("required tool arguments are missing")
    if not fields.issubset(_TOOL_ARGUMENT_FIELDS[tool]):
        raise ValueError("tool argument fields are not closed")

    cursor = arguments.get("cursor")
    if cursor is not None and (
        type(cursor) is not str or len(cursor) > MAX_CURSOR_CHARS
    ):
        raise ValueError("cursor must be a string of at most 4096 characters or null")
    for flag in (
        "allow_stale",
        "include_history",
        "include_conflicts",
        "include_relations",
    ):
        if flag in arguments and type(arguments[flag]) is not bool:
            raise ValueError(f"{flag} must be a boolean")
    if "budget_chars" in arguments and (
        type(arguments["budget_chars"]) is not int
        or not 500 <= arguments["budget_chars"] <= 50_000
    ):
        raise ValueError("budget_chars is outside the supported range")

    if tool == "search_quant_knowledge":
        query = arguments["query"]
        if (
            type(query) is not str
            or not query.strip()
            or len(query) > MAX_QUERY_CHARS
        ):
            raise ValueError("query must contain 1 to 500 characters")
        if "task_context" in arguments:
            _validate_task_context(arguments["task_context"])
        if "limit" in arguments and (
            type(arguments["limit"]) is not int
            or not 1 <= arguments["limit"] <= 20
        ):
            raise ValueError("limit is outside the supported range")
        if "detail" in arguments and arguments["detail"] not in {
            "compact",
            "evidence",
        }:
            raise ValueError("detail must be compact or evidence")
    elif tool == "get_quant_knowledge":
        object_id = arguments["object_id"]
        if (
            type(object_id) is not str
            or not object_id
            or len(object_id) > MAX_ID_CHARS
        ):
            raise ValueError("object_id must contain 1 to 200 characters")
    else:
        snapshot_id = arguments["from_snapshot_id"]
        if (
            type(snapshot_id) is not str
            or not snapshot_id
            or len(snapshot_id) > MAX_ID_CHARS
        ):
            raise ValueError("from_snapshot_id must contain 1 to 200 characters")
        if "limit" in arguments and (
            type(arguments["limit"]) is not int
            or not 1 <= arguments["limit"] <= 200
        ):
            raise ValueError("limit is outside the supported range")


def _identity(value: AuthorityIdentity | None) -> dict[str, str] | None:
    return value.to_dict() if value is not None else None


def _context_values(
    context: Mapping[str, object] | None, facet: str
) -> set[str]:
    if not context or facet not in context:
        return set()
    value = context[facet]
    values = (value,) if isinstance(value, str) else value
    if not isinstance(values, (list, tuple, set)):
        raise ValueError(f"task_context.{facet} must be a string or list")
    return {
        re.sub(r"\s+", " ", str(item).casefold()).strip()
        for item in values
        if str(item).strip()
    }


@dataclass(frozen=True, slots=True)
class Resolution:
    availability: str
    mirror: MirrorSnapshot | None
    local_identity: AuthorityIdentity | None
    observed_identity: AuthorityIdentity | None
    verified_at: str | None
    last_verified_at: str | None
    reason: str | None
    changed_from: AuthorityIdentity | None = None


class KnowledgeMCPService:
    """Three non-overlapping read tools with one freshness decision boundary."""

    def __init__(
        self,
        *,
        store: MirrorStore,
        authority: AuthorityProbe,
        artifact_release_root,
    ) -> None:
        self.store = store
        self.authority = authority
        self.artifact_release_root = artifact_release_root
        self._session_identity: AuthorityIdentity | None = None
        self._pending_transition: tuple[AuthorityIdentity, AuthorityIdentity] | None = None
        self._last_verified_at: str | None = None
        self._search_index_identity: AuthorityIdentity | None = None
        self._search_index: ArtifactKnowledgeIndex | None = None
        # ``get`` expands a result selected by ``search``; it is not a second
        # unscoped lookup surface.  Retain the exact matched locator only for
        # this stdio session and clear it whenever the snapshot changes.
        self._search_provenance_identity: AuthorityIdentity | None = None
        self._search_provenance: dict[str, dict[str, object]] = {}
        self._cursor_key = secrets.token_bytes(32)

    def _use_provenance_identity(self, identity: AuthorityIdentity) -> None:
        if self._search_provenance_identity != identity:
            self._search_provenance_identity = identity
            self._search_provenance.clear()

    def _index_for(self, mirror: MirrorSnapshot) -> ArtifactKnowledgeIndex:
        if self._search_index_identity != mirror.identity:
            if self._search_index is not None:
                self._search_index.close()
            self._search_index = ArtifactKnowledgeIndex(mirror.artifact)
            self._search_index_identity = mirror.identity
        return self._search_index

    def close(self) -> None:
        if self._search_index is not None:
            self._search_index.close()
            self._search_index = None
            self._search_index_identity = None
        self._search_provenance_identity = None
        self._search_provenance.clear()

    def __del__(self) -> None:
        self.close()

    def startup_probe(self) -> dict[str, Any]:
        """Probe/sync once at server initialization without claiming availability."""

        return self._base(self._resolve(allow_stale=False))

    def _resolve(self, *, allow_stale: bool) -> Resolution:
        try:
            local, durable_pending = self.store.current_and_pending()
        except (MirrorError, KeyError, TypeError, ValueError, OSError):
            self._pending_transition = None
            return Resolution(
                availability="unavailable",
                mirror=None,
                local_identity=None,
                observed_identity=None,
                verified_at=None,
                last_verified_at=self._last_verified_at,
                reason="mirror_identity_or_transition_corrupt",
            )
        self._pending_transition = (
            (durable_pending.from_identity, durable_pending.to_identity)
            if durable_pending is not None
            else None
        )
        local_identity = local.identity if local else None
        try:
            observation = self.authority.probe()
        except AuthorityUnavailable:
            return Resolution(
                availability="stale" if allow_stale and local else "unavailable",
                mirror=local if allow_stale else None,
                local_identity=local_identity,
                observed_identity=None,
                verified_at=None,
                last_verified_at=self._last_verified_at or (local.synced_at if local else None),
                reason="authority_unreachable_or_unverifiable",
            )
        observed = observation.identity
        if local_identity != observed or (
            durable_pending is not None
            and local_identity == durable_pending.from_identity
        ):
            try:
                local = self.store.sync_from(observed, self.artifact_release_root)
                local_identity = local.identity
                _current, durable_pending = self.store.current_and_pending()
            except (MirrorError, KeyError, TypeError, ValueError, OSError):
                return Resolution(
                    availability="stale" if allow_stale and local else "unavailable",
                    mirror=local if allow_stale else None,
                    local_identity=local_identity,
                    observed_identity=observed,
                    verified_at=observation.verified_at,
                    last_verified_at=observation.verified_at,
                    reason="mirror_missing_lagging_or_sync_failed",
                )
        self._last_verified_at = observation.verified_at
        changed_from = (
            durable_pending.from_identity if durable_pending is not None else None
        )
        self._pending_transition = (
            (durable_pending.from_identity, durable_pending.to_identity)
            if durable_pending is not None
            else None
        )
        if self._session_identity is None:
            self._session_identity = observed
        elif self._session_identity != observed:
            self._session_identity = observed
        self._use_provenance_identity(observed)
        return Resolution(
            availability="fresh",
            mirror=local,
            local_identity=local_identity,
            observed_identity=observed,
            verified_at=observation.verified_at,
            last_verified_at=observation.verified_at,
            reason=None,
            changed_from=changed_from,
        )

    def _base(self, resolution: Resolution) -> dict[str, Any]:
        identity = resolution.mirror.identity if resolution.mirror else None
        pending = self._pending_transition
        return {
            "schema_version": SERVICE_SCHEMA,
            "availability": resolution.availability,
            "identity": _identity(identity),
            "local_identity": _identity(resolution.local_identity),
            "observed_identity": _identity(resolution.observed_identity),
            "authority_verified_at": resolution.verified_at,
            "last_authority_verified_at": resolution.last_verified_at,
            "mirror_synced_at": resolution.mirror.synced_at if resolution.mirror else None,
            "reason": resolution.reason,
            "transition_pending": pending is not None,
            "pending_from_identity": _identity(pending[0]) if pending else None,
            "pending_to_identity": _identity(pending[1]) if pending else None,
            "source_is_untrusted_data": True,
        }

    def _blocked(self, resolution: Resolution) -> dict[str, Any] | None:
        if resolution.mirror is None:
            return {**self._base(resolution), "results": [], "truncated": False}
        if self._pending_transition is None:
            return None
        old, new = self._pending_transition
        return {
            **self._base(resolution),
            "status": "snapshot_refresh_required",
            "results": [],
            "truncated": False,
            "requires": ["list_knowledge_updates", "search_quant_knowledge", "get_quant_knowledge"],
            "changed_from": old.to_dict(),
            "changed_to": new.to_dict(),
        }

    def _decode_cursor(self, cursor: str | None) -> Mapping[str, Any] | None:
        if cursor is None:
            return None
        if type(cursor) is not str or len(cursor) > MAX_CURSOR_CHARS:
            raise ValueError("continuation exceeds the supported size")
        try:
            padded = cursor + ("=" * (-len(cursor) % 4))
            value = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("continuation is malformed") from error
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema_version",
                "identity",
                "tool",
                "position",
                "request_hash",
                "mac",
            }
            or value.get("schema_version") != CONTINUATION_SCHEMA
            or not isinstance(value.get("identity"), dict)
            or set(value["identity"])
            != {"release_id", "manifest_sha256", "snapshot_id"}
            or any(
                not isinstance(value["identity"].get(field), str)
                or not value["identity"][field]
                for field in ("release_id", "manifest_sha256", "snapshot_id")
            )
            or not isinstance(value.get("tool"), str)
            or not isinstance(value.get("request_hash"), str)
            or not isinstance(value.get("mac"), str)
            or re.fullmatch(r"[0-9a-f]{64}", value["mac"]) is None
        ):
            raise ValueError("continuation schema is invalid")
        unsigned = {key: member for key, member in value.items() if key != "mac"}
        expected_mac = hmac.new(
            self._cursor_key,
            canonical_json(unsigned).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(value["mac"], expected_mac):
            raise ValueError("continuation authenticity is invalid")
        return value

    def _cursor(
        self,
        *,
        identity: AuthorityIdentity,
        tool: str,
        position: object,
        request_hash: str,
    ) -> str:
        unsigned = {
            "schema_version": CONTINUATION_SCHEMA,
            "identity": identity.to_dict(),
            "tool": tool,
            "position": position,
            "request_hash": request_hash,
        }
        value = {
            **unsigned,
            "mac": hmac.new(
                self._cursor_key,
                canonical_json(unsigned).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest(),
        }
        return base64.urlsafe_b64encode(canonical_json(value).encode()).decode().rstrip("=")

    def _cursor_offset(
        self,
        cursor: str | None,
        *,
        identity: AuthorityIdentity,
        tool: str,
        request_hash: str,
        maximum: int,
    ) -> int:
        value = self._decode_cursor(cursor)
        if value is None:
            return 0
        if (
            value.get("identity") != identity.to_dict()
            or value.get("tool") != tool
            or value.get("request_hash") != request_hash
        ):
            raise ValueError("continuation_invalidated_by_snapshot_or_request")
        offset = value.get("position")
        if type(offset) is not int or not 0 <= offset <= maximum:
            raise ValueError("continuation offset is invalid")
        return offset

    def _cursor_update_key(
        self,
        cursor: str | None,
        *,
        identity: AuthorityIdentity,
        tool: str,
        request_hash: str,
    ) -> tuple[str, str, str] | None:
        value = self._decode_cursor(cursor)
        if value is None:
            return None
        if (
            value.get("identity") != identity.to_dict()
            or value.get("tool") != tool
            or value.get("request_hash") != request_hash
        ):
            raise ValueError("continuation_invalidated_by_snapshot_or_request")
        position = value.get("position")
        if (
            not isinstance(position, list)
            or len(position) != 3
            or any(type(member) is not str for member in position)
        ):
            raise ValueError("continuation position is invalid")
        return tuple(position)

    def search_quant_knowledge(
        self,
        *,
        query: str,
        task_context: Mapping[str, object] | None = None,
        limit: int = 8,
        budget_chars: int = 8_000,
        detail: str = "compact",
        cursor: str | None = None,
        allow_stale: bool = False,
        include_history: bool = False,
        include_conflicts: bool = False,
    ) -> dict[str, Any]:
        arguments: dict[str, object] = {
            "query": query,
            "limit": limit,
            "budget_chars": budget_chars,
            "detail": detail,
            "allow_stale": allow_stale,
            "include_history": include_history,
            "include_conflicts": include_conflicts,
        }
        if task_context is not None:
            arguments["task_context"] = task_context
        if cursor is not None:
            arguments["cursor"] = cursor
        validate_tool_arguments("search_quant_knowledge", arguments)
        resolution = self._resolve(allow_stale=allow_stale)
        blocked = self._blocked(resolution)
        if blocked is not None:
            return blocked
        assert resolution.mirror is not None
        artifact = resolution.mirror.artifact
        identity = resolution.mirror.identity
        context = TaskContext(
            **{
                facet: tuple(sorted(_context_values(task_context, facet)))
                for facet in (
                    "market",
                    "frequency",
                    "data",
                    "objective",
                    "assumption",
                )
            }
        )
        request_hash = hashlib.sha256(
            canonical_json(
                {
                    "query": query,
                    "task_context": task_context or {},
                    "detail": detail,
                    "include_history": include_history,
                    "include_conflicts": include_conflicts,
                }
            ).encode()
        ).hexdigest()
        try:
            record_count = len(artifact["retrieval"]["records"])
            search_ceiling = min(record_count, MAX_SEARCH_WINDOW)
            offset = self._cursor_offset(
                cursor,
                identity=identity,
                tool="search_quant_knowledge",
                request_hash=request_hash,
                maximum=max(0, search_ceiling - 1),
            )
        except ValueError as error:
            return {
                **self._base(resolution),
                "status": "continuation_invalid",
                "reason": str(error),
                "results": [],
                "truncated": False,
                "requires": ["list_knowledge_updates", "search_quant_knowledge"],
            }
        requested_limit = max(1, min(search_ceiling, offset + limit + 1))
        shared = self._index_for(resolution.mirror).search(
            query,
            context=context,
            limit=requested_limit,
            include_history=include_history,
            include_conflicts=include_conflicts,
        )
        page_cards = shared.cards[offset : offset + limit + 1]
        needed_object_ids = {
            card.evidence_id
            for card in page_cards
            if card.source_kind != "chunk"
        }
        remaining_object_ids = set(needed_object_ids)
        knowledge_by_id: dict[str, Mapping[str, Any]] = {}
        for row in artifact["knowledge"]:
            object_id = str(row["knowledge_item_id"])
            if object_id in remaining_object_ids:
                knowledge_by_id[object_id] = row
                remaining_object_ids.remove(object_id)
                if not remaining_object_ids:
                    break
        has_citation_proofs = (
            artifact.get("schema_version") == "qrh-mcp-search-artifact/v3"
        )
        needed_source_material: set[tuple[str, str]] = set()
        for card in page_cards:
            knowledge = knowledge_by_id.get(card.evidence_id)
            if knowledge is None:
                needed_source_material.add(
                    (str(card.document_version_id), str(card.locator.span_id))
                )
                continue
            raw_citations = knowledge.get("source_citations")
            raw_locators = (
                [member["source_locator"] for member in raw_citations]
                if isinstance(raw_citations, list)
                else knowledge.get("source_locators", [])
            )
            for locator in raw_locators:
                if isinstance(locator, Mapping):
                    needed_source_material.add(
                        (
                            str(card.document_version_id),
                            str(locator.get("span_id") or ""),
                        )
                    )
        remaining_source_material = set(needed_source_material)
        source_material_by_key: dict[tuple[str, str], Mapping[str, Any]] = {}
        for row in artifact.get("citation_source_material", []):
            if not isinstance(row, Mapping):
                continue
            material_key = (
                str(row["document_version_id"]),
                str(row["span_id"]),
            )
            if material_key in remaining_source_material:
                source_material_by_key[material_key] = row
                remaining_source_material.remove(material_key)
                if not remaining_source_material:
                    break

        def service_source_citations(
            *,
            card: Any,
            knowledge: Mapping[str, Any] | None,
            mapping_status: str,
        ) -> list[dict[str, object]]:
            raw_members = (
                knowledge["source_citations"]
                if knowledge is not None and "source_citations" in knowledge
                else [
                    {
                        "source_locator": locator,
                        "citation_ids": (
                            list(card.citation_ids)
                            if len(knowledge["source_locators"]) == 1
                            else []
                        ),
                    }
                    for locator in knowledge["source_locators"]
                ]
                if knowledge is not None
                else [
                    {
                        "source_locator": {
                            "document_id": card.document_id,
                            "document_version_id": card.document_version_id,
                            "span_id": card.locator.span_id,
                            "span_ids": list(card.covered_span_ids),
                            "source_sha256": card.locator.source_sha256,
                            "line_start": card.locator.line_start,
                            "line_end": card.locator.line_end,
                            "byte_start": card.locator.byte_start,
                            "byte_end": card.locator.byte_end,
                        },
                        "citation_ids": list(card.citation_ids),
                    }
                ]
            )
            result: list[dict[str, object]] = []
            for member in raw_members:
                locator = member["source_locator"]
                projected: dict[str, object] = {
                    "document_id": card.document_id,
                    "document_version_id": card.document_version_id,
                    **json.loads(canonical_json(locator)),
                    "citation_ids": list(member["citation_ids"]),
                    "citation_mapping_status": mapping_status,
                }
                if has_citation_proofs:
                    material = source_material_by_key.get(
                        (
                            str(card.document_version_id),
                            str(locator["span_id"]),
                        )
                    )
                    projected["citation_attributions"] = json.loads(
                        canonical_json(member.get("citation_attributions", []))
                    )
                    projected["source_material_identity"] = (
                        {
                            **{
                                key: material[key]
                                for key in (
                                    "document_version_id",
                                    "source_sha256",
                                    "span_id",
                                    "kind",
                                    "byte_start",
                                    "byte_end",
                                    "source_text_sha256",
                                )
                            },
                            "attributes_sha256": hashlib.sha256(
                                canonical_json(material["attributes"]).encode("utf-8")
                            ).hexdigest(),
                        }
                        if material is not None
                        else None
                    )
                result.append(projected)
            return result

        snippet_limit = 1_600 if detail == "evidence" else 420
        ordered: list[dict[str, Any]] = []
        source_citations_by_object_id: dict[str, list[dict[str, object]]] = {}
        for card in page_cards:
            knowledge = knowledge_by_id.get(card.evidence_id)
            legacy_multi_binding = bool(
                knowledge is not None
                and "source_citations" not in knowledge
                and len(knowledge.get("source_locators", [])) > 1
            )
            mapping_status = (
                "unavailable_legacy_v1"
                if legacy_multi_binding
                else "exact_per_locator"
            )
            source_citations = service_source_citations(
                card=card,
                knowledge=knowledge,
                mapping_status=mapping_status,
            )
            source_citations_by_object_id[card.evidence_id] = source_citations
            ordered_row: dict[str, Any] = {
                "object_id": card.evidence_id,
                "object_kind": (
                    "evidence_chunk"
                    if card.source_kind == "chunk"
                    else card.knowledge_kind or "accepted_knowledge"
                ),
                "canonical_key": card.canonical_key,
                "document_id": card.document_id,
                "document_version_id": card.document_version_id,
                "research_id": card.research_id,
                "title": card.title,
                "heading_path": list(card.heading_path),
                "snippet": card.text[:snippet_limit],
                "source_locator": {
                    "document_id": card.document_id,
                    "document_version_id": card.document_version_id,
                    "span_id": card.locator.span_id,
                    "span_ids": list(card.covered_span_ids),
                    "source_sha256": card.locator.source_sha256,
                    "line_start": card.locator.line_start,
                    "line_end": card.locator.line_end,
                    "byte_start": card.locator.byte_start,
                    "byte_end": card.locator.byte_end,
                },
                "citation_ids": (
                    [] if legacy_multi_binding else list(card.citation_ids)
                ),
                "citation_mapping_status": mapping_status,
                "fact_status": card.fact_status,
                "knowledge_enrichment": card.knowledge_enrichment,
                "applicability": card.applicability or "not_assessed",
                "applicability_matches": list(card.applicability_matches),
                "limitations": list(card.limitations),
                "failures": list(card.failures),
                "conflicts": list(card.applicability_conflicts),
                "generation": knowledge.get("generation") if knowledge else None,
                "match_reasons": list(card.hit_reasons),
                "score": card.score,
                "rank": card.rank,
                "historical": card.active_status != "active",
                "active_status": card.active_status,
            }
            if has_citation_proofs:
                ordered_row["source_citations"] = source_citations
            ordered.append(ordered_row)
        selected: list[dict[str, Any]] = []
        used = 0
        index = 0
        while index < len(ordered) and len(selected) < limit:
            row_size = len(canonical_json(ordered[index]))
            if selected and used + row_size > budget_chars:
                break
            selected.append(ordered[index])
            used += row_size
            index += 1
        truncated = index < len(ordered)
        self._use_provenance_identity(identity)
        # A new search establishes a new closed expansion set.  Do not let
        # recommendations from an earlier task context accumulate across the
        # lifetime of a long-running stdio process.
        self._search_provenance.clear()
        recommended = selected[:3]
        for row in recommended:
            self._search_provenance[str(row["object_id"])] = {
                "source_citations": json.loads(
                    canonical_json(
                        source_citations_by_object_id[str(row["object_id"])]
                    )
                ),
            }
        recommended_ids = [str(row["object_id"]) for row in recommended]
        return {
            **self._base(resolution),
            "status": "ok" if selected else "no_answer",
            "query": query,
            "task_context": task_context or {},
            "index_version": shared.index_version,
            "total_candidates": shared.total_candidates,
            "no_answer_reason": shared.no_answer_reason if not selected else None,
            "results": selected,
            "truncated": truncated,
            "continuation": self._cursor(
                identity=identity,
                tool="search_quant_knowledge",
                position=offset + index,
                request_hash=request_hash,
            )
            if truncated
            else None,
            "deduplication": "shared_canonical_evidence_span_contract",
            "next_action": {
                "tool": "get_quant_knowledge" if selected else None,
                "recommended_object_ids": recommended_ids,
                "maximum_unique_gets": len(recommended_ids),
                "repeat_search_only_if_task_context_or_snapshot_changes": True,
                "citation_rule": (
                    "cite only canonical source_citations returned by get; "
                    "never invent citation_ids"
                ),
            },
        }

    def get_quant_knowledge(
        self,
        *,
        object_id: str,
        include_history: bool = False,
        include_relations: bool = False,
        budget_chars: int = 12_000,
        allow_stale: bool = False,
    ) -> dict[str, Any]:
        validate_tool_arguments(
            "get_quant_knowledge",
            {
                "object_id": object_id,
                "include_history": include_history,
                "include_relations": include_relations,
                "budget_chars": budget_chars,
                "allow_stale": allow_stale,
            },
        )
        resolution = self._resolve(allow_stale=allow_stale)
        blocked = self._blocked(resolution)
        if blocked is not None:
            return blocked
        assert resolution.mirror is not None
        identity = resolution.mirror.identity
        self._use_provenance_identity(identity)
        search_provenance = self._search_provenance.get(object_id)
        if search_provenance is None:
            return {
                **self._base(resolution),
                "status": "search_provenance_required",
                "results": [],
                "requires": ["search_quant_knowledge", "get_quant_knowledge"],
                "reason": "object_id_was_not_returned_by_search_in_this_snapshot_session",
            }
        searched_citations = search_provenance["source_citations"]
        assert isinstance(searched_citations, list) and searched_citations
        artifact = resolution.mirror.artifact
        matches: list[dict[str, Any]] = []
        for collection, id_key, kind in (
            (artifact["documents"], "document_id", "document"),
            (artifact["versions"], "version_id", "document_version"),
            (artifact["chunks"], "chunk_id", "evidence_chunk"),
            (artifact["knowledge"], "knowledge_item_id", "accepted_knowledge"),
        ):
            for row in collection:
                if row.get(id_key) == object_id:
                    matches.append({"object_kind": kind, **row})
        if not matches:
            return {**self._base(resolution), "status": "not_found", "results": []}
        if not include_history:
            matches = [
                row
                for row in matches
                if row["object_kind"] not in {"document_version", "evidence_chunk"}
                or row.get("is_current", True)
                or any(
                    version.get("version_id") == row.get("document_version_id")
                    and version.get("is_current")
                    for version in artifact["versions"]
                )
            ]
        if not matches:
            return {
                **self._base(resolution),
                "status": "historical_requires_include_history",
                "results": [],
            }
        payload = canonical_json(matches)
        truncated = len(payload) > budget_chars
        if truncated:
            matches = [{**matches[0], "text": str(matches[0].get("text") or "")[:budget_chars]}]
        relation_rows: list[dict[str, object]] = []
        if include_relations:
            relation_rows = [
                {
                    "knowledge_item_id": row.get("knowledge_item_id"),
                    "relation": row.get("relation"),
                    "source_locator": row.get("source_locator"),
                }
                for row in artifact["knowledge"]
                if row.get("relation")
                and (
                    row.get("knowledge_item_id") == object_id
                    or (
                        isinstance(row.get("relation"), Mapping)
                        and row["relation"].get("target_id") == object_id
                    )
                )
            ]
        versions = {
            str(row["version_id"]): row for row in artifact["versions"]
        }
        source_citations: list[dict[str, object]] = []
        for member in searched_citations:
            assert isinstance(member, Mapping)
            version = versions.get(str(member["document_version_id"]))
            if version is None:
                return {
                    **self._base(resolution),
                    "status": "mirror_identity_or_membership_invalid",
                    "results": [],
                }
            source_citations.append(
                ({
                    "object_id": object_id,
                    "logical_path": version["logical_path"],
                    "document_id": member["document_id"],
                    "document_version_id": member["document_version_id"],
                    "source_sha256": member["source_sha256"],
                    "span_id": member["span_id"],
                    "byte_start": member["byte_start"],
                    "byte_end": member["byte_end"],
                    "citation_ids": list(member["citation_ids"]),
                    "citation_mapping_status": member["citation_mapping_status"],
                } | (
                    {
                        "citation_attributions": json.loads(
                            canonical_json(member["citation_attributions"])
                        ),
                        "source_material_identity": json.loads(
                            canonical_json(member["source_material_identity"])
                        )
                        if member["source_material_identity"] is not None
                        else None,
                    }
                    if "citation_attributions" in member
                    else {}
                ))
            )
        return {
            **self._base(resolution),
            "status": "ok",
            "results": matches,
            "include_relations": include_relations,
            "relations": relation_rows if include_relations else None,
            "truncated": truncated,
            "source_is_untrusted_data": True,
            "source_citations": source_citations,
            "next_action": {
                "compose_from_expanded_evidence": True,
                "repeat_search_only_if_task_context_or_snapshot_changes": True,
                "citation_rule": (
                    "include logical_path, document_version_id, source_sha256, "
                    "span_id and byte range from source_citations; never invent citation_ids"
                ),
            },
        }

    def list_knowledge_updates(
        self,
        *,
        from_snapshot_id: str,
        allow_stale: bool = False,
        limit: int = 50,
        budget_chars: int = 12_000,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        arguments: dict[str, object] = {
            "from_snapshot_id": from_snapshot_id,
            "allow_stale": allow_stale,
            "limit": limit,
            "budget_chars": budget_chars,
        }
        if cursor is not None:
            arguments["cursor"] = cursor
        validate_tool_arguments("list_knowledge_updates", arguments)
        resolution = self._resolve(allow_stale=allow_stale)
        if resolution.mirror is None:
            return {**self._base(resolution), "status": "unavailable", "updates": []}
        if (
            self._pending_transition is not None
            and resolution.availability != "fresh"
        ):
            old_identity, new_identity = self._pending_transition
            return {
                **self._base(resolution),
                "status": "snapshot_refresh_unavailable",
                "updates": [],
                "refresh_acknowledged": False,
                "changed_from": old_identity.to_dict(),
                "changed_to": new_identity.to_dict(),
            }
        current = resolution.mirror
        request_hash = hashlib.sha256(
            canonical_json({"from_snapshot_id": from_snapshot_id}).encode()
        ).hexdigest()
        try:
            after_key = self._cursor_update_key(
                cursor,
                identity=current.identity,
                tool="list_knowledge_updates",
                request_hash=request_hash,
            )
        except ValueError as error:
            return {
                **self._base(resolution),
                "status": "continuation_invalid",
                "reason": str(error),
                "updates": [],
                "truncated": False,
                "requires": ["list_knowledge_updates"],
            }
        previous = self.store.find_snapshot(from_snapshot_id)
        if previous is None:
            if self._pending_transition is not None:
                old_identity, new_identity = self._pending_transition
                if (
                    old_identity.snapshot_id == from_snapshot_id
                    and new_identity == current.identity
                ):
                    # The caller acknowledged the transition; no retained
                    # baseline exists to enumerate, so search/get may restart.
                    self.store.acknowledge_transition(old_identity, new_identity)
                    self._pending_transition = None
            return {
                **self._base(resolution),
                "status": "baseline_unavailable",
                "updates": [],
                "requires": ["search_quant_knowledge", "get_quant_knowledge"],
            }
        def update_key(row: Mapping[str, object]) -> tuple[str, str, str]:
            return (
                str(row.get("document_id") or ""),
                str(row.get("knowledge_item_id") or ""),
                str(row.get("change") or ""),
            )

        def merge_members(
            old_rows: list[Mapping[str, Any]],
            new_rows: list[Mapping[str, Any]],
            identity_key: str,
        ):
            old_index = 0
            new_index = 0
            while old_index < len(old_rows) or new_index < len(new_rows):
                old = old_rows[old_index] if old_index < len(old_rows) else None
                new = new_rows[new_index] if new_index < len(new_rows) else None
                old_id = str(old[identity_key]) if old is not None else None
                new_id = str(new[identity_key]) if new is not None else None
                if new_id is None or old_id is not None and old_id < new_id:
                    yield old, None
                    old_index += 1
                elif old_id is None or new_id < old_id:
                    yield None, new
                    new_index += 1
                else:
                    yield old, new
                    old_index += 1
                    new_index += 1

        def iter_updates():
            for old, new in merge_members(
                previous.artifact["documents"],
                current.artifact["documents"],
                "document_id",
            ):
                document_id = str(
                    (old if old is not None else new)["document_id"]
                )
                if old is None:
                    yield {"change": "added", "document_id": document_id, "to": new}
                elif new is None:
                    yield {"change": "removed", "document_id": document_id, "from": old}
                elif (
                    old.get("active_version_id") != new.get("active_version_id")
                    or old.get("status") != new.get("status")
                    or old.get("replacement_document_id")
                    != new.get("replacement_document_id")
                ):
                    yield {
                        "change": "replaced_or_status_changed",
                        "document_id": document_id,
                        "from_version_id": old.get("active_version_id"),
                        "to_version_id": new.get("active_version_id"),
                        "from_status": old.get("status"),
                        "to_status": new.get("status"),
                        "replacement_document_id": new.get(
                            "replacement_document_id"
                        ),
                    }
            for old_version, new_version in merge_members(
                previous.artifact["versions"],
                current.artifact["versions"],
                "version_id",
            ):
                if (
                    old_version is not None
                    and new_version is not None
                    and old_version.get("is_current") is True
                    and new_version.get("is_current") is True
                    and old_version.get("document_id")
                    == new_version.get("document_id")
                    and old_version.get("knowledge_enrichment")
                    != new_version.get("knowledge_enrichment")
                ):
                    yield {
                        "change": "knowledge_enrichment_changed",
                        "document_id": new_version.get("document_id"),
                        "document_version_id": new_version.get("version_id"),
                        "from_status": old_version.get("knowledge_enrichment"),
                        "to_status": new_version.get("knowledge_enrichment"),
                    }
            for old, new in merge_members(
                previous.artifact["knowledge"],
                current.artifact["knowledge"],
                "knowledge_item_id",
            ):
                knowledge_id = str(
                    (old if old is not None else new)["knowledge_item_id"]
                )
                if old is None:
                    yield {
                        "change": "knowledge_added",
                        "knowledge_item_id": knowledge_id,
                        "document_id": new.get("document_id") if new else None,
                        "fact_status": new.get("fact_status") if new else None,
                    }
                elif new is None:
                    yield {
                        "change": "knowledge_removed_or_superseded",
                        "knowledge_item_id": knowledge_id,
                        "document_id": old.get("document_id"),
                    }

        update_summary: dict[str, int] = {}
        update_count = 0
        eligible_count = 0

        def counted_page_candidates():
            nonlocal update_count, eligible_count
            for row in iter_updates():
                update_count += 1
                change = str(row.get("change") or "unknown")
                update_summary[change] = update_summary.get(change, 0) + 1
                if after_key is None or update_key(row) > after_key:
                    eligible_count += 1
                    yield row

        # Count/summary cover the complete immutable diff.  Keyset pagination
        # retains only one bounded look-ahead page, so a valid deep page never
        # allocates in proportion to its position and a forged position is
        # impossible without this service instance's MAC key.
        page = heapq.nsmallest(
            limit + 1,
            counted_page_candidates(),
            key=update_key,
        )
        selected: list[dict[str, Any]] = []
        used = 0
        index = 0
        while index < len(page) and len(selected) < limit:
            row_size = len(canonical_json(page[index]))
            if selected and used + row_size > budget_chars:
                break
            selected.append(page[index])
            used += row_size
            index += 1
        truncated = index < eligible_count
        refresh_acknowledged = False
        if self._pending_transition is not None:
            old_identity, new_identity = self._pending_transition
            if (
                old_identity.snapshot_id == from_snapshot_id
                and new_identity == current.identity
            ):
                # A verified summary plus bounded sample acknowledges the
                # identity transition. Exhaustive pagination remains an
                # optional audit operation and must not block search/get.
                self.store.acknowledge_transition(old_identity, new_identity)
                self._pending_transition = None
                refresh_acknowledged = True
        return {
            **self._base(resolution),
            "status": "ok",
            "from_snapshot_id": from_snapshot_id,
            "to_snapshot_id": current.identity.snapshot_id,
            "update_count": update_count,
            "update_summary": update_summary,
            "updates": selected,
            "truncated": truncated,
            "refresh_acknowledged": refresh_acknowledged,
            "continuation": self._cursor(
                identity=current.identity,
                tool="list_knowledge_updates",
                position=list(update_key(selected[-1])),
                request_hash=request_hash,
            )
            if truncated and selected
            else None,
            "requires": ["search_quant_knowledge", "get_quant_knowledge"],
        }


__all__ = [
    "KnowledgeMCPService",
    "Resolution",
    "SERVICE_SCHEMA",
    "validate_tool_arguments",
]
