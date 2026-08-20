from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sqlite3
from typing import Any

from quant_hub.config import Settings
from quant_hub.platform.db import immediate_transaction, utc_now
from quant_hub.platform.workflow import canonical_json

from .contracts import CitationOccurrenceInput, FetchAttemptInput, StrongIdentifierInput
from .database import evidence_connection, initialize_evidence_database
from .ids import stable_evidence_id


class EvidenceConflict(RuntimeError):
    pass


class EvidenceNotFound(KeyError):
    pass


@dataclass(frozen=True, slots=True)
class PaperIdentity:
    paper_id: str
    canonical_urn: str
    created: bool


@dataclass(frozen=True, slots=True)
class FetchAttemptRecord:
    fetch_attempt_id: str
    result_status: str
    created: bool


def _material(row: sqlite3.Row, names: tuple[str, ...]) -> tuple[Any, ...]:
    return tuple(row[name] for name in names)


def _json(value: object) -> str:
    return canonical_json(value)


class EvidenceRepository:
    """Evidence 的事务边界；所有事实写入均显式保存来源。"""

    def __init__(self, settings: Settings):
        self.settings = settings

    def initialize(self) -> list[int]:
        return initialize_evidence_database(self.settings)

    def put_clue(
        self,
        *,
        source_candidate_id: str,
        entity_kind: str,
        domain_category: str | None,
        raw_claim: dict[str, object],
        provenance_urn: str,
        resolution_status: str,
    ) -> tuple[str, bool]:
        clue_id = stable_evidence_id("clue", "archive-ledger/v1", source_candidate_id)
        expected = (
            source_candidate_id,
            entity_kind,
            domain_category,
            _json(raw_claim),
            provenance_urn,
            resolution_status,
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT * FROM paper_clue WHERE clue_id=?", (clue_id,)
            ).fetchone()
            if row is not None:
                actual = _material(
                    row,
                    (
                        "source_candidate_id",
                        "entity_kind",
                        "domain_category",
                        "raw_claim_json",
                        "provenance_urn",
                        "resolution_status",
                    ),
                )
                if actual != expected:
                    raise EvidenceConflict("stable clue ID is bound to different material")
                return clue_id, False
            connection.execute(
                """
                INSERT INTO paper_clue(
                    clue_id,source_candidate_id,entity_kind,domain_category,raw_claim_json,
                    provenance_urn,resolution_status,created_at
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (clue_id, *expected, utc_now()),
            )
        return clue_id, True

    def put_candidate(
        self,
        *,
        source_candidate_id: str,
        candidate_kind: str,
        title_claim: str | None,
        publication_year: int | None,
        resolution_status: str,
        provenance_urn: str,
    ) -> tuple[str, bool]:
        candidate_id = stable_evidence_id(
            "pcand", "archive-resolution/v1", source_candidate_id, provenance_urn
        )
        expected = (
            candidate_kind,
            title_claim,
            publication_year,
            resolution_status,
            provenance_urn,
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT * FROM paper_candidate WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            if row is not None:
                if _material(
                    row,
                    (
                        "candidate_kind",
                        "title_claim",
                        "publication_year",
                        "resolution_status",
                        "provenance_urn",
                    ),
                ) != expected:
                    raise EvidenceConflict("stable paper candidate conflicts")
                return candidate_id, False
            connection.execute(
                """
                INSERT INTO paper_candidate(
                    candidate_id,candidate_kind,title_claim,publication_year,
                    resolution_status,provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (candidate_id, *expected, utc_now()),
            )
        return candidate_id, True

    def link_clue_candidate(
        self,
        clue_id: str,
        candidate_id: str,
        *,
        link_kind: str,
        evidence: dict[str, object],
    ) -> bool:
        evidence_json = _json(evidence)
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                """
                SELECT evidence_json FROM paper_clue_candidate
                WHERE clue_id=? AND candidate_id=? AND link_kind=?
                """,
                (clue_id, candidate_id, link_kind),
            ).fetchone()
            if row is not None:
                if row["evidence_json"] != evidence_json:
                    raise EvidenceConflict("clue/candidate link evidence conflicts")
                return False
            connection.execute(
                """
                INSERT INTO paper_clue_candidate(
                    clue_id,candidate_id,link_kind,evidence_json,linked_at
                ) VALUES(?,?,?,?,?)
                """,
                (clue_id, candidate_id, link_kind, evidence_json, utc_now()),
            )
        return True

    def create_paper(self, identity_key: str, *, provenance_urn: str) -> PaperIdentity:
        paper_id = stable_evidence_id("paper", "canonical-paper/v1", identity_key)
        canonical_urn = f"qrh:evidence:paper:{paper_id}"
        event_id = stable_evidence_id("idevt", "paper-created/v1", paper_id)
        payload_json = _json({"identity_key": identity_key, "paper_urn": canonical_urn})
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT canonical_urn,creation_event_id FROM paper WHERE paper_id=?",
                (paper_id,),
            ).fetchone()
            if row is not None:
                if (row["canonical_urn"], row["creation_event_id"]) != (
                    canonical_urn,
                    event_id,
                ):
                    raise EvidenceConflict("canonical paper identity conflicts")
                return PaperIdentity(paper_id, canonical_urn, False)
            now = utc_now()
            connection.execute(
                """
                INSERT INTO paper_identity_event(
                    identity_event_id,event_kind,from_paper_id,to_paper_id,scheme,
                    normalized_value,provenance_urn,payload_json,occurred_at
                ) VALUES(?,'paper_created',NULL,?,NULL,NULL,?,?,?)
                """,
                (event_id, paper_id, provenance_urn, payload_json, now),
            )
            connection.execute(
                "INSERT INTO paper(paper_id,canonical_urn,creation_event_id,created_at) VALUES(?,?,?,?)",
                (paper_id, canonical_urn, event_id, now),
            )
        return PaperIdentity(paper_id, canonical_urn, True)

    def assert_metadata(
        self,
        *,
        paper_id: str | None,
        candidate_id: str | None,
        field_name: str,
        value: object,
        assertion_status: str,
        source_kind: str,
        provenance_urn: str,
    ) -> tuple[str, bool]:
        value_json = _json(value)
        assertion_id = stable_evidence_id(
            "massert",
            paper_id or "",
            candidate_id or "",
            field_name,
            value_json,
            provenance_urn,
        )
        expected = (
            paper_id,
            candidate_id,
            field_name,
            value_json,
            assertion_status,
            source_kind,
            provenance_urn,
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT * FROM metadata_assertion WHERE assertion_id=?", (assertion_id,)
            ).fetchone()
            if row is not None:
                if _material(
                    row,
                    (
                        "paper_id",
                        "candidate_id",
                        "field_name",
                        "value_json",
                        "assertion_status",
                        "source_kind",
                        "provenance_urn",
                    ),
                ) != expected:
                    raise EvidenceConflict("metadata assertion conflicts")
                return assertion_id, False
            connection.execute(
                """
                INSERT INTO metadata_assertion(
                    assertion_id,paper_id,candidate_id,field_name,value_json,
                    assertion_status,source_kind,provenance_urn,asserted_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (assertion_id, *expected, utc_now()),
            )
        return assertion_id, True

    def select_metadata(
        self,
        *,
        paper_id: str,
        field_name: str,
        assertion_id: str,
        provenance_urn: str,
    ) -> tuple[str, bool]:
        selection_id = stable_evidence_id(
            "msel", paper_id, field_name, assertion_id, provenance_urn
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            assertion = connection.execute(
                """
                SELECT paper_id,field_name,assertion_status
                FROM metadata_assertion WHERE assertion_id=?
                """,
                (assertion_id,),
            ).fetchone()
            if assertion is None or (
                assertion["paper_id"], assertion["field_name"], assertion["assertion_status"]
            ) != (paper_id, field_name, "verified"):
                raise EvidenceConflict("canonical metadata requires a matching verified assertion")
            existing = connection.execute(
                "SELECT * FROM canonical_metadata_selection WHERE selection_id=?",
                (selection_id,),
            ).fetchone()
            if existing is not None:
                expected = (paper_id, field_name, assertion_id, provenance_urn)
                if _material(
                    existing,
                    ("paper_id", "field_name", "assertion_id", "provenance_urn"),
                ) != expected:
                    raise EvidenceConflict("canonical metadata selection conflicts")
                return selection_id, False
            predecessor = connection.execute(
                """
                SELECT selection_id FROM canonical_metadata_selection
                WHERE paper_id=? AND field_name=?
                ORDER BY selected_at DESC,selection_id DESC LIMIT 1
                """,
                (paper_id, field_name),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO canonical_metadata_selection(
                    selection_id,paper_id,field_name,assertion_id,
                    supersedes_selection_id,provenance_urn,selected_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    selection_id,
                    paper_id,
                    field_name,
                    assertion_id,
                    str(predecessor["selection_id"]) if predecessor else None,
                    provenance_urn,
                    utc_now(),
                ),
            )
        return selection_id, True

    def put_bibliography_projection(
        self,
        *,
        paper_id: str,
        title: str,
        publication_date: str | None,
        authors: list[dict[str, object]],
        institutions: list[str],
        categories: list[str],
        core_conclusions: list[dict[str, str]],
        external_links: list[dict[str, str]],
        provenance_urn: str,
    ) -> None:
        """保存规范作者/机构事实，并重建可替换的目录投影。"""

        now = utc_now()
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            if connection.execute(
                "SELECT 1 FROM paper WHERE paper_id=?", (paper_id,)
            ).fetchone() is None:
                raise EvidenceNotFound("canonical paper does not exist")

            for category_key in categories:
                category_id = stable_evidence_id("cat", category_key.casefold())
                row = connection.execute(
                    "SELECT category_key,display_name FROM paper_category WHERE category_id=?",
                    (category_id,),
                ).fetchone()
                expected_category = (category_key.casefold(), category_key)
                if row is None:
                    connection.execute(
                        "INSERT INTO paper_category(category_id,category_key,display_name) VALUES(?,?,?)",
                        (category_id, *expected_category),
                    )
                elif tuple(row) != expected_category:
                    raise EvidenceConflict("paper category identity conflicts")
                connection.execute(
                    """
                    INSERT INTO paper_category_assignment(
                        paper_id,category_id,provenance_urn,assigned_at
                    ) VALUES(?,?,?,?) ON CONFLICT DO NOTHING
                    """,
                    (paper_id, category_id, provenance_urn, now),
                )

            for order, author in enumerate(authors, start=1):
                name = str(author["name"])
                person_id = stable_evidence_id(
                    "person", name.casefold(), provenance_urn
                )
                connection.execute(
                    """
                    INSERT INTO person(person_id,display_name,orcid,provenance_urn)
                    VALUES(?,?,NULL,?) ON CONFLICT(person_id) DO NOTHING
                    """,
                    (person_id, name, provenance_urn),
                )
                person = connection.execute(
                    "SELECT display_name,provenance_urn FROM person WHERE person_id=?",
                    (person_id,),
                ).fetchone()
                if person is None or tuple(person) != (name, provenance_urn):
                    raise EvidenceConflict("person identity conflicts")
                existing_authorship = connection.execute(
                    "SELECT person_id,role,provenance_urn FROM paper_authorship WHERE paper_id=? AND author_order=?",
                    (paper_id, order),
                ).fetchone()
                if existing_authorship is None:
                    connection.execute(
                        """
                        INSERT INTO paper_authorship(
                            paper_id,person_id,author_order,role,provenance_urn
                        ) VALUES(?,?,?,'author',?)
                        """,
                        (paper_id, person_id, order, provenance_urn),
                    )
                elif tuple(existing_authorship) != (person_id, "author", provenance_urn):
                    raise EvidenceConflict("paper authorship conflicts")
                for organization_name in author.get("affiliations", []):
                    organization_name = str(organization_name)
                    organization_id = stable_evidence_id(
                        "org", organization_name.casefold(), provenance_urn
                    )
                    connection.execute(
                        """
                        INSERT INTO organization(
                            organization_id,display_name,ror_id,provenance_urn
                        ) VALUES(?,?,NULL,?) ON CONFLICT(organization_id) DO NOTHING
                        """,
                        (organization_id, organization_name, provenance_urn),
                    )
                    affiliation_id = stable_evidence_id(
                        "aff", paper_id, person_id, organization_id, provenance_urn
                    )
                    connection.execute(
                        """
                        INSERT INTO person_affiliation_assertion(
                            affiliation_id,paper_id,person_id,organization_id,
                            provenance_urn,assertion_status,asserted_at
                        ) VALUES(?,?,?,?,?,'verified',?) ON CONFLICT(affiliation_id) DO NOTHING
                        """,
                        (
                            affiliation_id,
                            paper_id,
                            person_id,
                            organization_id,
                            provenance_urn,
                            now,
                        ),
                    )

            for link in external_links:
                link_id = stable_evidence_id(
                    "link", paper_id, link["kind"], link["url"], provenance_urn
                )
                connection.execute(
                    """
                    INSERT INTO paper_external_link(
                        external_link_id,paper_id,candidate_id,link_kind,url,
                        verification_status,provenance_urn,asserted_at
                    ) VALUES(?,?,NULL,?,?,?, ?,?)
                    ON CONFLICT(external_link_id) DO NOTHING
                    """,
                    (
                        link_id,
                        paper_id,
                        link["kind"],
                        link["url"],
                        link.get("verification_status", "verified"),
                        provenance_urn,
                        now,
                    ),
                )

            for conclusion in core_conclusions:
                conclusion_id = stable_evidence_id(
                    "conclusion",
                    paper_id,
                    conclusion["text"],
                    conclusion["provenance_urn"],
                )
                connection.execute(
                    """
                    INSERT INTO paper_core_conclusion(
                        conclusion_id,paper_id,conclusion_text,fact_status,
                        provenance_urn,created_at
                    ) VALUES(?,?,?,?,?,?) ON CONFLICT(conclusion_id) DO NOTHING
                    """,
                    (
                        conclusion_id,
                        paper_id,
                        conclusion["text"],
                        conclusion.get("fact_status", "source_claim"),
                        conclusion["provenance_urn"],
                        now,
                    ),
                )

            resources = [
                {
                    "resource_id": str(row["resource_id"]),
                    "url": f"/api/v1/evidence/resources/{row['resource_id']}",
                    "sha256": str(row["content_sha256"]),
                    "bytes": int(row["bytes"]),
                }
                for row in connection.execute(
                    """
                    SELECT resource_id,content_sha256,bytes
                    FROM paper_resource WHERE paper_id=? AND verification_status='verified'
                    ORDER BY resource_id
                    """,
                    (paper_id,),
                )
            ]
            projected = (
                title,
                publication_date,
                _json(authors),
                _json(sorted(set(institutions))),
                _json(sorted(set(categories))),
                _json(core_conclusions),
                _json(external_links),
                _json(resources),
                "verified",
            )
            row = connection.execute(
                "SELECT * FROM paper_catalog_projection WHERE paper_id=?",
                (paper_id,),
            ).fetchone()
            fields = (
                "title",
                "publication_date",
                "authors_json",
                "institutions_json",
                "categories_json",
                "core_conclusions_json",
                "external_links_json",
                "local_resources_json",
                "verification_status",
            )
            if row is None:
                connection.execute(
                    """
                    INSERT INTO paper_catalog_projection(
                        paper_id,title,publication_date,authors_json,institutions_json,
                        categories_json,core_conclusions_json,external_links_json,
                        local_resources_json,verification_status,projection_revision,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,1,?)
                    """,
                    (paper_id, *projected, now),
                )
            elif _material(row, fields) != projected:
                connection.execute(
                    """
                    UPDATE paper_catalog_projection
                    SET title=?,publication_date=?,authors_json=?,institutions_json=?,
                        categories_json=?,core_conclusions_json=?,external_links_json=?,
                        local_resources_json=?,verification_status=?,
                        projection_revision=projection_revision+1,updated_at=?
                    WHERE paper_id=?
                    """,
                    (*projected, now, paper_id),
                )

    def assert_and_assign_identifier(
        self,
        paper_id: str,
        identifier: StrongIdentifierInput,
        *,
        candidate_id: str | None = None,
        allow_reassignment: bool = False,
    ) -> tuple[str, bool]:
        normalized = identifier.normalized_value
        assertion_id = stable_evidence_id(
            "iassert",
            paper_id,
            identifier.scheme,
            normalized,
            identifier.provenance_urn,
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            assertion = connection.execute(
                "SELECT * FROM paper_identifier_assertion WHERE identifier_assertion_id=?",
                (assertion_id,),
            ).fetchone()
            assertion_expected = (
                paper_id,
                candidate_id,
                identifier.scheme,
                identifier.raw_value,
                normalized,
                identifier.assertion_status,
                identifier.provenance_urn,
            )
            if assertion is None:
                connection.execute(
                    """
                    INSERT INTO paper_identifier_assertion(
                        identifier_assertion_id,paper_id,candidate_id,scheme,raw_value,
                        normalized_value,assertion_status,provenance_urn,asserted_at
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (assertion_id, *assertion_expected, utc_now()),
                )
            elif _material(
                assertion,
                (
                    "paper_id",
                    "candidate_id",
                    "scheme",
                    "raw_value",
                    "normalized_value",
                    "assertion_status",
                    "provenance_urn",
                ),
            ) != assertion_expected:
                raise EvidenceConflict("identifier assertion conflicts")

            current = connection.execute(
                """
                SELECT paper_id,source_event_id,revision
                FROM identifier_assignment_projection
                WHERE scheme=? AND normalized_value=?
                """,
                (identifier.scheme, normalized),
            ).fetchone()
            if current is not None and current["paper_id"] == paper_id:
                return assertion_id, False
            if identifier.assertion_status != "verified":
                raise EvidenceConflict("only externally verified identifiers may be assigned")
            if current is not None and not allow_reassignment:
                raise EvidenceConflict("strong identifier is already assigned to another paper")

            now = utc_now()
            if current is None:
                event_kind = "identifier_assigned"
                from_paper_id = None
                revision = 1
            else:
                event_kind = "identifier_reassigned"
                from_paper_id = str(current["paper_id"])
                revision = int(current["revision"]) + 1
            event_id = stable_evidence_id(
                "idevt",
                event_kind,
                identifier.scheme,
                normalized,
                paper_id,
                str(revision),
            )
            connection.execute(
                """
                INSERT INTO paper_identity_event(
                    identity_event_id,event_kind,from_paper_id,to_paper_id,scheme,
                    normalized_value,provenance_urn,payload_json,occurred_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    event_kind,
                    from_paper_id,
                    paper_id,
                    identifier.scheme,
                    normalized,
                    identifier.provenance_urn,
                    _json({"identifier_assertion_id": assertion_id}),
                    now,
                ),
            )
            if current is None:
                connection.execute(
                    """
                    INSERT INTO identifier_assignment_projection(
                        scheme,normalized_value,paper_id,source_event_id,revision,updated_at
                    ) VALUES(?,?,?,?,1,?)
                    """,
                    (identifier.scheme, normalized, paper_id, event_id, now),
                )
            else:
                connection.execute(
                    """
                    UPDATE identifier_assignment_projection
                    SET paper_id=?,source_event_id=?,revision=?,updated_at=?
                    WHERE scheme=? AND normalized_value=?
                    """,
                    (
                        paper_id,
                        event_id,
                        revision,
                        now,
                        identifier.scheme,
                        normalized,
                    ),
                )
        return assertion_id, True

    def add_citation(
        self, occurrence: CitationOccurrenceInput, source_bytes: bytes | None = None
    ) -> tuple[str, bool]:
        if occurrence.locator_kind == "utf8_bytes":
            if source_bytes is None:
                raise ValueError("UTF-8 citation import requires source bytes")
            occurrence.verify_source_bytes(source_bytes)
        canonical_reason = {
            "valid": "exact UTF-8 source object and half-open byte span verified",
            "source_only": "source ledger locator retained without a raw UTF-8 byte claim",
            "unresolved": "source locator could not be independently verified",
        }[occurrence.locator_status]
        canonical_expected = (
            occurrence.document_sha256,
            occurrence.locator_kind,
            _json(occurrence.locator),
            occurrence.line_start,
            occurrence.line_end,
            occurrence.byte_start,
            occurrence.byte_end,
            occurrence.raw_marker_text,
            occurrence.raw_marker_sha256,
            occurrence.context_text,
            occurrence.context_sha256,
            occurrence.occurrence_kind,
            occurrence.locator_status,
            canonical_reason,
        )
        canonical_fields = (
            "document_sha256",
            "locator_kind",
            "locator_json",
            "line_start",
            "line_end",
            "byte_start",
            "byte_end",
            "raw_marker_text",
            "raw_marker_sha256",
            "context_text",
            "context_sha256",
            "occurrence_kind",
            "locator_status",
            "status_reason",
        )
        entry_expected = (
            occurrence.citation_id,
            occurrence.clue_id,
            occurrence.research_urn,
            occurrence.archive_release_urn,
            occurrence.document_version_urn,
            occurrence.source_object_urn,
            occurrence.source_path,
            occurrence.canonical_path,
            occurrence.locator_claim,
            occurrence.raw_occurrence_type,
            occurrence.candidate_link_method,
            occurrence.evidence_strength,
            occurrence.identifier_claim,
            occurrence.resolution_status,
            occurrence.status_reason,
            _json(occurrence.ledger_payload),
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT * FROM citation_occurrence WHERE citation_id=?",
                (occurrence.citation_id,),
            ).fetchone()
            if row is not None:
                if _material(row, canonical_fields) != canonical_expected:
                    raise EvidenceConflict("stable citation ID conflicts with source material")
            else:
                connection.execute(
                    """
                    INSERT INTO citation_occurrence(
                        citation_id,document_sha256,locator_kind,locator_json,line_start,line_end,
                        byte_start,byte_end,raw_marker_text,raw_marker_sha256,context_text,
                        context_sha256,occurrence_kind,locator_status,status_reason,created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (occurrence.citation_id, *canonical_expected, utc_now()),
                )
            entry = connection.execute(
                "SELECT * FROM citation_ledger_entry WHERE ledger_entry_id=?",
                (occurrence.legacy_occurrence_id,),
            ).fetchone()
            entry_fields = (
                "citation_id",
                "clue_id",
                "research_urn",
                "archive_release_urn",
                "document_version_urn",
                "source_object_urn",
                "source_path",
                "canonical_path",
                "locator_claim",
                "occurrence_type",
                "candidate_link_method",
                "evidence_strength",
                "identifier_claim",
                "entry_status",
                "entry_reason",
                "raw_payload_json",
            )
            if entry is not None:
                if _material(entry, entry_fields) != entry_expected:
                    raise EvidenceConflict("legacy citation ledger entry conflicts")
                return occurrence.citation_id, False
            connection.execute(
                """
                INSERT INTO citation_ledger_entry(
                    ledger_entry_id,citation_id,clue_id,research_urn,archive_release_urn,
                    document_version_urn,source_object_urn,source_path,canonical_path,
                    locator_claim,occurrence_type,candidate_link_method,evidence_strength,
                    identifier_claim,entry_status,entry_reason,raw_payload_json,imported_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (occurrence.legacy_occurrence_id, *entry_expected, utc_now()),
            )
        return occurrence.citation_id, True

    def bind_citation(
        self,
        ledger_entry_id: str,
        *,
        paper_id: str | None,
        binding_status: str,
        rationale: str,
        provenance_urn: str,
    ) -> tuple[str, bool]:
        binding_id = stable_evidence_id(
            "bind", ledger_entry_id, paper_id or "", binding_status, provenance_urn
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            binding = connection.execute(
                "SELECT * FROM citation_binding WHERE binding_id=?", (binding_id,)
            ).fetchone()
            expected = (ledger_entry_id, paper_id, binding_status, rationale, provenance_urn)
            if binding is None:
                connection.execute(
                    """
                    INSERT INTO citation_binding(
                        binding_id,ledger_entry_id,paper_id,binding_status,rationale,
                        provenance_urn,created_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (binding_id, *expected, utc_now()),
                )
            elif _material(
                binding,
                ("ledger_entry_id", "paper_id", "binding_status", "rationale", "provenance_urn"),
            ) != expected:
                raise EvidenceConflict("citation binding conflicts")

            current = connection.execute(
                "SELECT * FROM citation_binding_projection WHERE ledger_entry_id=?",
                (ledger_entry_id,),
            ).fetchone()
            if current is not None and current["binding_id"] == binding_id:
                return binding_id, False
            now = utc_now()
            if current is None:
                event_kind = "binding_created"
                supersedes = None
                revision = 1
            else:
                event_kind = "binding_revised"
                supersedes = str(current["source_event_id"])
                revision = int(current["revision"]) + 1
            event_id = stable_evidence_id(
                "bevt", ledger_entry_id, binding_id, str(revision)
            )
            connection.execute(
                """
                INSERT INTO citation_binding_event(
                    binding_event_id,ledger_entry_id,binding_id,event_kind,
                    supersedes_event_id,provenance_urn,occurred_at
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    event_id,
                    ledger_entry_id,
                    binding_id,
                    event_kind,
                    supersedes,
                    provenance_urn,
                    now,
                ),
            )
            if current is None:
                connection.execute(
                    """
                    INSERT INTO citation_binding_projection(
                        ledger_entry_id,binding_id,source_event_id,revision,updated_at
                    ) VALUES(?,?,?,?,?)
                    """,
                    (ledger_entry_id, binding_id, event_id, revision, now),
                )
            else:
                connection.execute(
                    """
                    UPDATE citation_binding_projection
                    SET binding_id=?,source_event_id=?,revision=?,updated_at=?
                    WHERE ledger_entry_id=?
                    """,
                    (binding_id, event_id, revision, now, ledger_entry_id),
                )
        return binding_id, True

    def record_fetch_attempt(
        self,
        attempt: FetchAttemptInput,
        *,
        paper_id: str | None,
        candidate_id: str | None,
        attempt_key: str,
        subject_urn: str | None = None,
    ) -> FetchAttemptRecord:
        attempt_id = stable_evidence_id("fetch", "fetch-attempt/v1", attempt_key)
        resolved_subject_urn = subject_urn or (
            f"qrh:evidence:paper:{paper_id}"
            if paper_id is not None
            else (
                f"qrh:evidence:candidate:{candidate_id}"
                if candidate_id is not None
                else f"qrh:evidence:network-attempt:{attempt_id}"
            )
        )
        expected = (
            attempt_key,
            resolved_subject_urn,
            paper_id,
            candidate_id,
            attempt.requested_url,
            _json(list(attempt.redirect_chain)),
            attempt.final_url,
            attempt.http_status,
            attempt.response_mime,
            attempt.response_bytes,
            attempt.response_sha256,
            attempt.request_identity_hash,
            attempt.rights_status,
            attempt.legal_basis,
            attempt.result_status,
            attempt.error_class,
            attempt.error_detail,
        )
        fields = (
            "source_request_id",
            "subject_urn",
            "paper_id",
            "candidate_id",
            "requested_url",
            "redirect_chain_json",
            "final_url",
            "http_status",
            "response_mime",
            "response_bytes",
            "response_sha256",
            "request_identity_hash",
            "rights_status",
            "legal_basis",
            "result_status",
            "error_class",
            "error_detail",
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT * FROM fetch_attempt WHERE fetch_attempt_id=?", (attempt_id,)
            ).fetchone()
            if row is not None:
                if _material(row, fields) != expected:
                    raise EvidenceConflict("fetch attempt key conflicts with immutable audit data")
                return FetchAttemptRecord(attempt_id, attempt.result_status, False)
            connection.execute(
                """
                INSERT INTO fetch_attempt(
                    fetch_attempt_id,source_request_id,subject_urn,paper_id,candidate_id,
                    requested_url,redirect_chain_json,
                    final_url,http_status,response_mime,response_bytes,response_sha256,
                    request_identity_hash,rights_status,legal_basis,result_status,error_class,
                    error_detail,attempted_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (attempt_id, *expected, utc_now()),
            )
        return FetchAttemptRecord(attempt_id, attempt.result_status, True)

    def register_resource(
        self,
        *,
        paper_id: str | None,
        candidate_id: str | None = None,
        fetch_attempt_id: str,
        content_sha256: str,
        size: int,
        relative_path: str,
        rights_status: str,
        media_type: str = "application/pdf",
    ) -> tuple[str, bool]:
        resource_id = stable_evidence_id("res", "paper-resource/v1", content_sha256)
        expected = (
            paper_id,
            candidate_id,
            fetch_attempt_id,
            "paper_pdf",
            media_type,
            content_sha256,
            size,
            relative_path,
            rights_status,
            "verified",
        )
        fields = (
            "paper_id",
            "candidate_id",
            "fetch_attempt_id",
            "resource_kind",
            "media_type",
            "content_sha256",
            "bytes",
            "relative_path",
            "rights_status",
            "verification_status",
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT * FROM paper_resource WHERE resource_id=?", (resource_id,)
            ).fetchone()
            if row is not None:
                if _material(row, fields) != expected:
                    raise EvidenceConflict("content-addressed paper resource conflicts")
                return resource_id, False
            fetch = connection.execute(
                "SELECT * FROM fetch_attempt WHERE fetch_attempt_id=?",
                (fetch_attempt_id,),
            ).fetchone()
            if fetch is None or (
                fetch["paper_id"],
                fetch["candidate_id"],
                fetch["result_status"],
                fetch["response_mime"],
                fetch["response_bytes"],
                fetch["response_sha256"],
            ) != (paper_id, candidate_id, "succeeded", media_type, size, content_sha256):
                raise EvidenceConflict("resource does not match its successful fetch audit")
            connection.execute(
                """
                INSERT INTO paper_resource(
                    resource_id,paper_id,candidate_id,fetch_attempt_id,resource_kind,media_type,
                    content_sha256,bytes,relative_path,rights_status,
                    verification_status,acquired_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (resource_id, *expected, utc_now()),
            )
        return resource_id, True

    def refresh_catalog_resources(self, paper_id: str) -> bool:
        """仅刷新目录中的已核验本地资源，不改写其他论文事实字段。"""

        with evidence_connection(self.settings) as connection, immediate_transaction(
            connection
        ):
            catalog = connection.execute(
                "SELECT local_resources_json FROM paper_catalog_projection WHERE paper_id=?",
                (paper_id,),
            ).fetchone()
            if catalog is None:
                raise EvidenceNotFound("canonical paper catalog does not exist")
            resources = [
                {
                    "resource_id": str(row["resource_id"]),
                    "url": f"/api/v1/evidence/resources/{row['resource_id']}",
                    "sha256": str(row["content_sha256"]),
                    "bytes": int(row["bytes"]),
                }
                for row in connection.execute(
                    """
                    SELECT resource_id,content_sha256,bytes
                    FROM paper_resource
                    WHERE paper_id=? AND verification_status='verified'
                    UNION
                    SELECT resource.resource_id,resource.content_sha256,resource.bytes
                    FROM evidence_canonical_resource_attachment AS attachment
                    JOIN paper_resource AS resource USING(resource_id)
                    WHERE attachment.paper_id=?
                      AND resource.verification_status='verified'
                    ORDER BY resource_id
                    """,
                    (paper_id, paper_id),
                )
            ]
            projected = _json(resources)
            if str(catalog["local_resources_json"]) == projected:
                return False
            connection.execute(
                """
                UPDATE paper_catalog_projection
                SET local_resources_json=?,projection_revision=projection_revision+1,
                    updated_at=?
                WHERE paper_id=?
                """,
                (projected, utc_now(), paper_id),
            )
        return True

    def add_research_relation(
        self,
        *,
        research_urn: str,
        document_version_urn: str,
        ledger_entry_id: str,
        citation_id: str,
        paper_id: str,
        relation_kind: str,
        provenance_urn: str,
    ) -> tuple[str, bool]:
        relation_id = stable_evidence_id(
            "relation", ledger_entry_id, paper_id, relation_kind
        )
        expected = (
            research_urn,
            document_version_urn,
            ledger_entry_id,
            citation_id,
            paper_id,
            relation_kind,
            provenance_urn,
        )
        fields = (
            "research_urn",
            "document_version_urn",
            "ledger_entry_id",
            "citation_id",
            "paper_id",
            "relation_kind",
            "provenance_urn",
        )
        with evidence_connection(self.settings) as connection, immediate_transaction(connection):
            row = connection.execute(
                "SELECT * FROM research_paper_relation WHERE relation_id=?",
                (relation_id,),
            ).fetchone()
            if row is not None:
                if _material(row, fields) != expected:
                    raise EvidenceConflict("research/paper relation conflicts")
                return relation_id, False
            connection.execute(
                """
                INSERT INTO research_paper_relation(
                    relation_id,research_urn,document_version_urn,ledger_entry_id,
                    citation_id,paper_id,relation_kind,provenance_urn,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (relation_id, *expected, utc_now()),
            )
        return relation_id, True

    def counts(self) -> dict[str, int]:
        tables = (
            "paper_clue",
            "paper_candidate",
            "paper",
            "citation_occurrence",
            "citation_ledger_entry",
            "citation_binding",
            "fetch_attempt",
            "paper_resource",
            "research_paper_relation",
            "evidence_method_origin_candidate_derivation",
            "evidence_canonicalization_receipt",
            "evidence_canonical_resource_attachment",
            "evidence_associated_method_relation",
            "evidence_fulltext_conclusion_support",
            "evidence_canonicalization_event",
            "evidence_canonicalization_state",
        )
        with evidence_connection(self.settings) as connection:
            return {
                table: int(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0])
                for table in tables
            }

    def snapshot_hash(self) -> str:
        """为确定性导出计算与运行时间无关的逻辑快照。"""

        queries = {
            "import_receipts": "SELECT import_receipt_id,package_schema_version,input_manifest_hash,artifact_manifest_hash,candidate_count,ledger_entry_count,unlinked_entry_count,external_candidate_count,resource_count,validation_status,report_json FROM evidence_import_receipt ORDER BY import_receipt_id",
            "clues": "SELECT clue_id,source_candidate_id,entity_kind,raw_claim_json,resolution_status FROM paper_clue ORDER BY clue_id",
            "papers": "SELECT paper_id,canonical_urn FROM paper ORDER BY paper_id",
            "identifiers": "SELECT scheme,normalized_value,paper_id,revision FROM identifier_assignment_projection ORDER BY scheme,normalized_value",
            "metadata_assertions": "SELECT assertion_id,paper_id,candidate_id,field_name,value_json,assertion_status,source_kind,provenance_urn FROM metadata_assertion ORDER BY assertion_id",
            "metadata_selections": "SELECT selection_id,paper_id,field_name,assertion_id,supersedes_selection_id,provenance_urn FROM canonical_metadata_selection ORDER BY selection_id",
            "categories": "SELECT category_id,category_key,display_name FROM paper_category ORDER BY category_id",
            "category_assignments": "SELECT paper_id,category_id,provenance_urn FROM paper_category_assignment ORDER BY paper_id,category_id,provenance_urn",
            "category_assertions": "SELECT category_assertion_id,paper_id,source_system,source_categories_json,primary_source_category,mapping_policy_version,assertion_status,provenance_urn FROM paper_category_assertion ORDER BY category_assertion_id",
            "category_assignment_details": "SELECT paper_id,category_id,provenance_urn,is_primary,category_assertion_id FROM paper_category_assignment_detail ORDER BY paper_id,category_id,provenance_urn",
            "people": "SELECT person_id,display_name,orcid,provenance_urn FROM person ORDER BY person_id",
            "organizations": "SELECT organization_id,display_name,ror_id,provenance_urn FROM organization ORDER BY organization_id",
            "authorships": "SELECT paper_id,person_id,author_order,role,provenance_urn FROM paper_authorship ORDER BY paper_id,author_order",
            "affiliations": "SELECT affiliation_id,paper_id,person_id,organization_id,provenance_urn,assertion_status FROM person_affiliation_assertion ORDER BY affiliation_id",
            "external_links": "SELECT external_link_id,paper_id,candidate_id,link_kind,url,verification_status,provenance_urn FROM paper_external_link ORDER BY external_link_id",
            "analyses": "SELECT analysis_id,paper_id,analysis_kind,analysis_text,fact_status,provenance_urn FROM paper_analysis ORDER BY analysis_id",
            "core_conclusions": "SELECT conclusion_id,paper_id,conclusion_text,fact_status,provenance_urn FROM paper_core_conclusion ORDER BY conclusion_id",
            "core_conclusion_evidence": "SELECT conclusion_id,excerpt_id,claim_scope,verification_status,provenance_urn FROM paper_core_conclusion_evidence ORDER BY conclusion_id",
            "institution_resolutions": "SELECT institution_resolution_id,paper_id,resolution_status,institutions_json,reason_code,reason_text,checked_source_fields_json,provenance_urn FROM paper_institution_resolution ORDER BY institution_resolution_id",
            "excerpts": "SELECT excerpt_id,paper_id,resource_id,excerpt_text,locator_json,excerpt_sha256,provenance_urn FROM evidence_excerpt ORDER BY excerpt_id",
            "reading_tasks": "SELECT reading_task_id,paper_id,resource_id,abstract_excerpt_id,input_snapshot_hash,objective_text,required_outputs_json,provenance_urn FROM paper_reading_task ORDER BY reading_task_id",
            "reading_runs": "SELECT reading_run_id,reading_task_id,attempt_number,idempotency_key,worker_kind,input_snapshot_hash,result_status,analysis_payload_json,failure_json,provenance_urn FROM paper_reading_run ORDER BY reading_run_id",
            "reading_conclusion_bindings": "SELECT reading_run_id,conclusion_id,provenance_urn FROM paper_reading_conclusion_binding ORDER BY reading_run_id,conclusion_id",
            "citations": "SELECT citation_id,document_sha256,locator_kind,locator_json,byte_start,byte_end,raw_marker_sha256,locator_status FROM citation_occurrence ORDER BY citation_id",
            "citation_ledger": "SELECT ledger_entry_id,citation_id,clue_id,research_urn,document_version_urn,source_path,locator_claim,entry_status FROM citation_ledger_entry ORDER BY ledger_entry_id",
            "bindings": "SELECT ledger_entry_id,binding_id,revision FROM citation_binding_projection ORDER BY ledger_entry_id",
            "external_identity_candidates": "SELECT external_candidate_id,candidate_id,provider,provider_rank,provider_score,provider_record_json,selection_status,identity_decision,provenance_urn FROM external_identity_candidate ORDER BY external_candidate_id",
            "external_assertions": "SELECT external_assertion_id,candidate_id,assertion_kind,field_name,value_json,verification_status,selection_status,provenance_urn FROM external_assertion ORDER BY external_assertion_id",
            "resources": "SELECT resource_id,paper_id,candidate_id,content_sha256,bytes,relative_path,rights_status FROM paper_resource ORDER BY resource_id",
            "fetch_attempts": "SELECT fetch_attempt_id,source_request_id,subject_urn,paper_id,candidate_id,requested_url,final_url,http_status,response_mime,response_bytes,response_sha256,rights_status,legal_basis,result_status,error_class,error_detail FROM fetch_attempt ORDER BY fetch_attempt_id",
            "research_relations": "SELECT relation_id,research_urn,document_version_urn,ledger_entry_id,citation_id,paper_id,relation_kind,provenance_urn FROM research_paper_relation ORDER BY relation_id",
            "catalog_projection": "SELECT paper_id,title,publication_date,authors_json,institutions_json,categories_json,core_conclusions_json,external_links_json,local_resources_json,verification_status,projection_revision FROM paper_catalog_projection ORDER BY paper_id",
            "resolution_cases": "SELECT resolution_case_id,candidate_id,input_snapshot_hash,input_claim_json,policy_version,provenance_urn FROM evidence_resolution_case ORDER BY resolution_case_id",
            "resolution_events": "SELECT resolution_event_id,resolution_case_id,idempotency_key,event_kind,from_state,to_state,reason_code,reason_detail,evidence_refs_json FROM evidence_resolution_event ORDER BY resolution_event_id",
            "resolution_states": "SELECT resolution_case_id,state,revision,source_event_id FROM evidence_resolution_state ORDER BY resolution_case_id",
            "provider_requests": "SELECT provider_request_id,resolution_case_id,provider,operation,request_method,request_url,request_headers_json,query_context_json,request_fingerprint,provenance_urn FROM evidence_provider_request ORDER BY provider_request_id",
            "provider_attempts": "SELECT provider_attempt_id,provider_request_id,attempt_number,idempotency_key,result_status,final_url,redirect_chain_json,http_status,response_mime,response_bytes,response_sha256,response_headers_json,request_identity_hash,error_class,error_detail,provenance_urn FROM evidence_provider_attempt ORDER BY provider_attempt_id",
            "provider_observations": "SELECT provider_observation_id,provider_attempt_id,provider,provider_record_id,provider_rank,provider_score,record_json,record_sha256,metadata_json,normalized_identifiers_json,match_basis,identity_effect,canonicalization_status,rationale,provenance_urn FROM evidence_provider_observation ORDER BY provider_observation_id",
            "resource_offers": "SELECT resource_offer_id,provider_observation_id,provider,resource_kind,source_kind,url,media_type,rights_hint,license_evidence_json,canonicalization_effect,provenance_urn FROM evidence_resource_offer ORDER BY resource_offer_id",
            "identity_decisions": "SELECT identity_decision_id,resolution_case_id,provider_observation_id,decision_kind,identifier_scheme,normalized_identifier,authority_kind,policy_version,rationale,evidence_refs_json,canonicalization_effect,idempotency_key,provenance_urn FROM evidence_identity_decision ORDER BY identity_decision_id",
            "rights_assessments": "SELECT rights_assessment_id,resource_offer_id,decision,rights_status,authority_kind,policy_version,legal_basis,evidence_json,supersedes_assessment_id,idempotency_key,provenance_urn FROM evidence_rights_assessment ORDER BY rights_assessment_id",
            "acquisition_cases": "SELECT acquisition_case_id,resource_offer_id,rights_assessment_id,input_snapshot_hash,provenance_urn FROM evidence_acquisition_case ORDER BY acquisition_case_id",
            "acquisition_events": "SELECT acquisition_event_id,acquisition_case_id,idempotency_key,event_kind,from_state,to_state,fetch_attempt_id,resource_id,reason_code,reason_detail,evidence_refs_json FROM evidence_acquisition_event ORDER BY acquisition_event_id",
            "acquisition_states": "SELECT acquisition_case_id,state,revision,source_event_id FROM evidence_acquisition_state ORDER BY acquisition_case_id",
            "method_origin_candidate_derivations": "SELECT derivation_id,original_source_candidate_id,derived_source_candidate_id,derived_candidate_id,identifier_scheme,normalized_identifier,rationale,provenance_urn FROM evidence_method_origin_candidate_derivation ORDER BY derivation_id",
            "canonicalization_receipts": "SELECT canonicalization_receipt_id,manifest_schema_version,manifest_sha256,item_key,item_material_sha256,idempotency_key,treatment,source_candidate_id,paper_source_candidate_id,resolution_case_id,identity_decision_id,paper_id,resource_mode,result_material_sha256,provenance_urn FROM evidence_canonicalization_receipt ORDER BY canonicalization_receipt_id",
            "canonical_resource_attachments": "SELECT resource_attachment_id,canonicalization_receipt_id,resolution_case_id,paper_id,resource_id,provenance_urn FROM evidence_canonical_resource_attachment ORDER BY resource_attachment_id",
            "associated_method_relations": "SELECT associated_relation_id,canonicalization_receipt_id,source_candidate_id,ledger_entry_id,citation_id,paper_id,association_kind,rationale,provenance_urn FROM evidence_associated_method_relation ORDER BY associated_relation_id",
            "fulltext_conclusion_support": "SELECT conclusion_id,resource_id,page_number,page_text_sha256,support_text_sha256,locator_json,verification_status,provenance_urn FROM evidence_fulltext_conclusion_support ORDER BY conclusion_id",
            "canonicalization_events": "SELECT canonicalization_event_id,canonicalization_receipt_id,event_sequence,event_kind,entity_urn,payload_json,payload_sha256 FROM evidence_canonicalization_event ORDER BY canonicalization_receipt_id,event_sequence",
            "canonicalization_states": "SELECT canonicalization_receipt_id,state,revision,source_event_id FROM evidence_canonicalization_state ORDER BY canonicalization_receipt_id",
        }
        payload: dict[str, list[list[object]]] = {}
        with evidence_connection(self.settings) as connection:
            for key, query in queries.items():
                payload[key] = [list(row) for row in connection.execute(query).fetchall()]
        return hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()
