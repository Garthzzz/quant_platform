"""Read-only projection of canonical Evidence citations into knowledge snapshots.

The Evidence database remains an independent authority.  This module never
initialises or migrates it: a projection is built through SQLite's immutable,
read-only URI mode and is then bound to one deterministic BaseSnapshot.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import hashlib
from pathlib import Path
import re
import sqlite3
import stat
from typing import Any, Mapping, Sequence
import unicodedata

from quant_hub.evidence.ids import citation_id_for_marker, validate_citation_id
from quant_hub.presentation.citation_overlays import (
    CitationOverlayError,
    CitationOverlayRegistry,
    citation_overlay_manifest_path,
    select_non_overlapping_citations,
)
from quant_hub.platform.migrations import MigrationError, migrate_up

from .contracts import BaseSnapshot, canonical_json, content_hash


CITATION_PROJECTION_SCHEMA = "qrh-evidence-citation-projection/v1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_TABLE_SCHEMA = {
    "citation_occurrence": (
        ("citation_id", "TEXT", 1, 1),
        ("document_sha256", "TEXT", 1, 0),
        ("locator_kind", "TEXT", 1, 0),
        ("locator_json", "TEXT", 1, 0),
        ("line_start", "INTEGER", 1, 0),
        ("line_end", "INTEGER", 1, 0),
        ("byte_start", "INTEGER", 0, 0),
        ("byte_end", "INTEGER", 0, 0),
        ("raw_marker_text", "TEXT", 1, 0),
        ("raw_marker_sha256", "TEXT", 1, 0),
        ("context_text", "TEXT", 1, 0),
        ("context_sha256", "TEXT", 1, 0),
        ("occurrence_kind", "TEXT", 1, 0),
        ("locator_status", "TEXT", 1, 0),
        ("status_reason", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "citation_ledger_entry": (
        ("ledger_entry_id", "TEXT", 1, 1),
        ("citation_id", "TEXT", 1, 0),
        ("clue_id", "TEXT", 0, 0),
        ("research_urn", "TEXT", 1, 0),
        ("archive_release_urn", "TEXT", 1, 0),
        ("document_version_urn", "TEXT", 1, 0),
        ("source_object_urn", "TEXT", 1, 0),
        ("source_path", "TEXT", 1, 0),
        ("canonical_path", "TEXT", 1, 0),
        ("locator_claim", "TEXT", 1, 0),
        ("occurrence_type", "TEXT", 1, 0),
        ("candidate_link_method", "TEXT", 1, 0),
        ("evidence_strength", "TEXT", 1, 0),
        ("identifier_claim", "TEXT", 1, 0),
        ("entry_status", "TEXT", 1, 0),
        ("entry_reason", "TEXT", 1, 0),
        ("raw_payload_json", "TEXT", 1, 0),
        ("imported_at", "TEXT", 1, 0),
    ),
    "citation_binding": (
        ("binding_id", "TEXT", 1, 1),
        ("ledger_entry_id", "TEXT", 1, 0),
        ("paper_id", "TEXT", 0, 0),
        ("binding_status", "TEXT", 1, 0),
        ("rationale", "TEXT", 1, 0),
        ("provenance_urn", "TEXT", 1, 0),
        ("created_at", "TEXT", 1, 0),
    ),
    "citation_binding_event": (
        ("binding_event_id", "TEXT", 1, 1),
        ("ledger_entry_id", "TEXT", 1, 0),
        ("binding_id", "TEXT", 1, 0),
        ("event_kind", "TEXT", 1, 0),
        ("supersedes_event_id", "TEXT", 0, 0),
        ("provenance_urn", "TEXT", 1, 0),
        ("occurred_at", "TEXT", 1, 0),
    ),
    "citation_binding_projection": (
        ("ledger_entry_id", "TEXT", 1, 1),
        ("binding_id", "TEXT", 1, 0),
        ("source_event_id", "TEXT", 1, 0),
        ("revision", "INTEGER", 1, 0),
        ("updated_at", "TEXT", 1, 0),
    ),
    "schema_migration": (
        ("version", "INTEGER", 0, 1),
        ("name", "TEXT", 1, 0),
        ("up_sha256", "TEXT", 1, 0),
        ("down_sha256", "TEXT", 1, 0),
        ("applied_at", "TEXT", 1, 0),
    ),
}
_REQUIRED_FOREIGN_KEYS = {
    "citation_occurrence": (),
    "citation_ledger_entry": (
        ("citation_occurrence", "citation_id", "citation_id", "NO ACTION", "RESTRICT", "NONE"),
        ("paper_clue", "clue_id", "clue_id", "NO ACTION", "RESTRICT", "NONE"),
    ),
    "citation_binding": (
        ("citation_ledger_entry", "ledger_entry_id", "ledger_entry_id", "NO ACTION", "RESTRICT", "NONE"),
        ("paper", "paper_id", "paper_id", "NO ACTION", "RESTRICT", "NONE"),
    ),
    "citation_binding_event": (
        ("citation_binding", "binding_id", "binding_id", "NO ACTION", "RESTRICT", "NONE"),
        (
            "citation_binding_event",
            "supersedes_event_id",
            "binding_event_id",
            "NO ACTION",
            "RESTRICT",
            "NONE",
        ),
        ("citation_ledger_entry", "ledger_entry_id", "ledger_entry_id", "NO ACTION", "RESTRICT", "NONE"),
    ),
    "citation_binding_projection": (
        ("citation_binding", "binding_id", "binding_id", "NO ACTION", "RESTRICT", "NONE"),
        ("citation_binding_event", "source_event_id", "binding_event_id", "NO ACTION", "RESTRICT", "NONE"),
        ("citation_ledger_entry", "ledger_entry_id", "ledger_entry_id", "NO ACTION", "RESTRICT", "NONE"),
    ),
    "schema_migration": (),
}
_MARKDOWN_GAP_DELIMITERS = frozenset("_*~+=<>\\/|#")


class CitationProjectionError(RuntimeError):
    """The configured Evidence sidecar cannot safely authorize citations."""


@dataclass(frozen=True, slots=True)
class ProjectedCitation:
    citation_id: str
    source_sha256: str
    containing_span_ids: tuple[str, ...]
    line_start: int
    line_end: int
    byte_start: int
    byte_end: int
    raw_marker_text: str
    raw_marker_sha256: str
    occurrence_kind: str
    resolution_state: str
    authority_kind: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CitationAttribution:
    citation_id: str
    relation: str
    anchor_byte_end: int
    gap_text: str
    gap_sha256: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CitationProjection:
    schema_version: str
    base_snapshot_id: str
    evidence_database_sha256: str
    evidence_migration_authority_sha256: str
    reviewed_overlay_manifest_sha256: str
    active_source_membership: dict[str, str]
    occurrences: tuple[ProjectedCitation, ...]
    rejected_overlap_count: int
    membership_sha256: str
    _source_objects: Mapping[str, bytes] = field(repr=False, compare=False)
    _block_ranges: Mapping[str, Mapping[str, tuple[int, int]]] = field(
        repr=False, compare=False
    )

    def for_version(self, version_id: str) -> tuple[ProjectedCitation, ...]:
        source_sha256 = self.active_source_membership.get(version_id)
        if source_sha256 is None:
            return ()
        return tuple(
            row for row in self.occurrences if row.source_sha256 == source_sha256
        )

    def source_bytes(self, version_id: str) -> bytes:
        source_sha256 = self.active_source_membership.get(version_id)
        if source_sha256 is None or source_sha256 not in self._source_objects:
            raise CitationProjectionError("citation projection source object is unavailable")
        return self._source_objects[source_sha256]

    def identity_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "base_snapshot_id": self.base_snapshot_id,
            "evidence_database_sha256": self.evidence_database_sha256,
            "evidence_migration_authority_sha256": (
                self.evidence_migration_authority_sha256
            ),
            "reviewed_overlay_manifest_sha256": self.reviewed_overlay_manifest_sha256,
            "active_source_membership": dict(sorted(self.active_source_membership.items())),
            "occurrence_count": len(self.occurrences),
            "rejected_overlap_count": self.rejected_overlap_count,
            "membership_sha256": self.membership_sha256,
        }


def _authority_file_state(
    path: Path, *, authority_name: str
) -> tuple[int, int, str]:
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise CitationProjectionError(
                f"{authority_name} must be a regular, non-hard-linked file"
            )
        value = path.read_bytes()
    except OSError as error:
        raise CitationProjectionError(f"{authority_name} is unavailable") from error
    return info.st_size, info.st_mtime_ns, hashlib.sha256(value).hexdigest()


def _assert_no_journal_artifacts(path: Path) -> None:
    for suffix in ("-wal", "-shm", "-journal"):
        if path.with_name(path.name + suffix).exists():
            raise CitationProjectionError(
                "immutable Evidence sidecar must not depend on SQLite journal artifacts"
            )


def _migration_authority(
    root: Path,
) -> tuple[tuple[tuple[int, str, str, str], ...], str, str]:
    try:
        root_info = root.lstat()
    except OSError as error:
        raise CitationProjectionError(
            "Evidence migration authority is unavailable"
        ) from error
    if not stat.S_ISDIR(root_info.st_mode):
        raise CitationProjectionError(
            "Evidence migration authority must be a regular directory"
        )
    expected_migrations: list[tuple[int, str, str, str]] = []
    identity_rows: list[tuple[str, str]] = []
    state_rows: list[tuple[str, int, int, str]] = []
    try:
        paths = sorted(root.iterdir(), key=lambda item: item.name)
    except OSError as error:
        raise CitationProjectionError(
            "Evidence migration authority is unavailable"
        ) from error
    if not paths or any(not path.name.endswith((".up.sql", ".down.sql")) for path in paths):
        raise CitationProjectionError("Evidence migration authority is not closed")
    for path in paths:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise CitationProjectionError(
                "Evidence migration must be a regular, non-hard-linked file"
            )
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        identity_rows.append((path.name, digest))
        state_rows.append((path.name, info.st_size, info.st_mtime_ns, digest))
    by_name = dict(identity_rows)
    for up_name, up_hash in identity_rows:
        match = re.fullmatch(r"([0-9]{4})_([a-z0-9_]+)\.up\.sql", up_name)
        if match is None:
            continue
        down_name = up_name.replace(".up.sql", ".down.sql")
        down_hash = by_name.get(down_name)
        if down_hash is None:
            raise CitationProjectionError("Evidence migration identity is incomplete")
        expected_migrations.append(
            (int(match.group(1)), match.group(2), up_hash, down_hash)
        )
    if len(identity_rows) != 2 * len(expected_migrations):
        raise CitationProjectionError("Evidence migration identity is not closed")
    content_identity = content_hash(
        "qrh-evidence-migration-authority/v1", identity_rows
    )
    state_identity = content_hash(
        "qrh-evidence-migration-authority-state/v1", state_rows
    )
    return tuple(expected_migrations), content_identity, state_identity


def _validate_table_schema(
    connection: sqlite3.Connection,
    expected_migrations: Sequence[tuple[int, str, str, str]],
) -> None:
    table_list = {
        str(row[1]): row for row in connection.execute("PRAGMA table_list").fetchall()
    }
    for table_name, expected_schema in _REQUIRED_TABLE_SCHEMA.items():
        rows = connection.execute(f"PRAGMA table_xinfo('{table_name}')").fetchall()
        actual_schema = tuple(
            (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
            for row in rows
        )
        if actual_schema != expected_schema:
            raise CitationProjectionError("Evidence citation schema is not closed")
        if any(int(row[6]) != 0 for row in rows):
            raise CitationProjectionError("Evidence citation schema contains hidden columns")
        table = table_list.get(table_name)
        if table is None or int(table[5]) != 1:
            raise CitationProjectionError("Evidence citation authority table is not STRICT")
        actual_foreign_keys = tuple(
            sorted(
                (
                    str(row[2]),
                    str(row[3]),
                    str(row[4]),
                    str(row[5]),
                    str(row[6]),
                    str(row[7]),
                )
                for row in connection.execute(
                    f"PRAGMA foreign_key_list('{table_name}')"
                ).fetchall()
            )
        )
        if actual_foreign_keys != _REQUIRED_FOREIGN_KEYS[table_name]:
            raise CitationProjectionError(
                "Evidence citation schema foreign keys are not closed"
            )

    actual_migrations = [
        (int(row[0]), str(row[1]), str(row[2]), str(row[3]))
        for row in connection.execute(
            "SELECT version,name,up_sha256,down_sha256 FROM schema_migration ORDER BY version"
        ).fetchall()
    ]
    if not expected_migrations or actual_migrations != list(expected_migrations):
        raise CitationProjectionError("Evidence migration identity is not canonical")


def _canonical_schema_rows(
    migration_root: Path,
) -> tuple[tuple[str, str, str, str], ...]:
    canonical = sqlite3.connect(":memory:")
    canonical.row_factory = sqlite3.Row
    try:
        canonical.execute("PRAGMA foreign_keys=ON")
        migrate_up(canonical, migration_root)
        return tuple(
            (
                str(row["type"]),
                str(row["name"]),
                str(row["tbl_name"]),
                str(row["sql"]),
            )
            for row in canonical.execute(
                """
                SELECT type,name,tbl_name,sql
                FROM sqlite_schema
                WHERE sql IS NOT NULL
                ORDER BY type,name,tbl_name
                """
            ).fetchall()
        )
    except (MigrationError, sqlite3.Error) as error:
        raise CitationProjectionError(
            "canonical Evidence schema cannot be reconstructed"
        ) from error
    finally:
        canonical.close()


def _validate_canonical_schema(
    connection: sqlite3.Connection,
    migration_root: Path,
) -> None:
    expected = _canonical_schema_rows(migration_root)
    actual = tuple(
        (
            str(row["type"]),
            str(row["name"]),
            str(row["tbl_name"]),
            str(row["sql"]),
        )
        for row in connection.execute(
            """
            SELECT type,name,tbl_name,sql
            FROM sqlite_schema
            WHERE sql IS NOT NULL
            ORDER BY type,name,tbl_name
            """
        ).fetchall()
    )
    if not expected or actual != expected:
        raise CitationProjectionError(
            "Evidence authority schema differs from sealed migrations"
        )


def _containing_span_ids(
    snapshot: BaseSnapshot, version_id: str, byte_start: int, byte_end: int
) -> tuple[str, ...]:
    matches = {
        block.source_span.span_id
        for block in snapshot.ir_documents[version_id].blocks
        if block.source_span.byte_start <= byte_start
        and byte_end <= block.source_span.byte_end
    }
    return tuple(sorted(matches))


def _select_non_overlapping(
    occurrences: Sequence[ProjectedCitation],
) -> tuple[tuple[ProjectedCitation, ...], int]:
    """Use the presentation layer's deterministic shortest-valid-span rule."""
    by_source: dict[str, list[ProjectedCitation]] = {}
    for row in occurrences:
        by_source.setdefault(row.source_sha256, []).append(row)
    selected: list[ProjectedCitation] = []
    for source_sha256 in sorted(by_source):
        selected.extend(select_non_overlapping_citations(by_source[source_sha256]))
    rejected = len(occurrences) - len(selected)
    return (
        tuple(
            sorted(
                selected,
                key=lambda row: (
                    row.source_sha256,
                    row.byte_start,
                    row.byte_end,
                    row.citation_id,
                ),
            )
        ),
        rejected,
    )


def build_citation_projection(
    snapshot: BaseSnapshot,
    evidence_database: Path,
    source_objects: Mapping[str, bytes],
    *,
    overlay_manifest_path: Path | None = None,
    evidence_migration_root: Path | None = None,
) -> CitationProjection:
    """Project active, exact citation occurrences without mutating authority."""

    database_input = Path(evidence_database)
    before = _authority_file_state(
        database_input, authority_name="Evidence sidecar"
    )
    database = database_input.resolve(strict=True)
    _assert_no_journal_artifacts(database)
    migration_root = Path(
        evidence_migration_root
        or Path(__file__).resolve().parents[3] / "migrations" / "research_papers"
    )
    (
        expected_migrations,
        migration_content_identity,
        migration_state_before,
    ) = _migration_authority(migration_root)
    active_source_membership = {
        version_id: snapshot.versions[version_id].source_sha256
        for version_id in sorted(snapshot.active_membership.values())
    }
    verified_sources: dict[str, bytes] = {}
    for source_sha256 in sorted(set(active_source_membership.values())):
        value = source_objects.get(source_sha256)
        if type(value) is not bytes or hashlib.sha256(value).hexdigest() != source_sha256:
            raise CitationProjectionError(
                "citation projection source object differs from active source identity"
            )
        verified_sources[source_sha256] = value

    try:
        connection = sqlite3.connect(
            database.as_uri() + "?mode=ro&immutable=1",
            uri=True,
            timeout=1.0,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA query_only=ON")
            if int(connection.execute("PRAGMA query_only").fetchone()[0]) != 1:
                raise CitationProjectionError("Evidence sidecar query_only was not enforced")
            _validate_table_schema(connection, expected_migrations)
            _validate_canonical_schema(connection, migration_root)
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise CitationProjectionError("Evidence sidecar integrity check failed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise CitationProjectionError("Evidence sidecar foreign keys are invalid")
            rows = connection.execute(
                """
                SELECT citation_id,document_sha256,locator_kind,locator_json,
                       line_start,line_end,byte_start,byte_end,raw_marker_text,
                       raw_marker_sha256,context_text,context_sha256,
                       occurrence_kind,locator_status,status_reason,created_at
                FROM citation_occurrence
                WHERE locator_kind='utf8_bytes' AND locator_status='valid'
                ORDER BY document_sha256,byte_start,byte_end,citation_id
                """
            ).fetchall()
            binding_rows = connection.execute(
                """
                SELECT ledger.citation_id,
                       CASE WHEN event.binding_event_id IS NOT NULL
                            THEN binding.binding_status END AS binding_status
                FROM citation_ledger_entry AS ledger
                LEFT JOIN citation_binding_projection AS projection
                  USING(ledger_entry_id)
                LEFT JOIN citation_binding AS binding
                  ON binding.binding_id=projection.binding_id
                 AND binding.ledger_entry_id=ledger.ledger_entry_id
                LEFT JOIN citation_binding_event AS event
                  ON event.binding_event_id=projection.source_event_id
                 AND event.binding_id=binding.binding_id
                 AND event.ledger_entry_id=ledger.ledger_entry_id
                ORDER BY ledger.citation_id,ledger.ledger_entry_id
                """
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as error:
        raise CitationProjectionError("Evidence sidecar read failed") from error

    source_to_versions: dict[str, list[str]] = {}
    for version_id, source_sha256 in active_source_membership.items():
        source_to_versions.setdefault(source_sha256, []).append(version_id)
    projected: list[ProjectedCitation] = []
    statuses_by_citation: dict[str, list[str]] = {}
    for row in binding_rows:
        statuses_by_citation.setdefault(str(row["citation_id"]), []).append(
            str(row["binding_status"] or "unresolved")
        )
    for row in rows:
        source_sha256 = str(row["document_sha256"])
        version_ids = source_to_versions.get(source_sha256)
        if not version_ids:
            continue
        citation_id = str(row["citation_id"])
        statuses = statuses_by_citation.get(citation_id, [])
        if "conflicted" in statuses or "resolved" not in statuses:
            continue
        raw_marker_text = row["raw_marker_text"]
        raw_marker_sha256 = str(row["raw_marker_sha256"])
        byte_start = row["byte_start"]
        byte_end = row["byte_end"]
        line_start = row["line_start"]
        line_end = row["line_end"]
        if (
            not _SHA256.fullmatch(source_sha256)
            or not isinstance(raw_marker_text, str)
            or type(byte_start) is not int
            or type(byte_end) is not int
            or type(line_start) is not int
            or type(line_end) is not int
            or not 1 <= line_start <= line_end
        ):
            raise CitationProjectionError("Evidence citation row types are invalid")
        try:
            validate_citation_id(citation_id)
        except ValueError as error:
            raise CitationProjectionError("Evidence citation ID is not canonical") from error
        source_bytes = verified_sources[source_sha256]
        marker_bytes = raw_marker_text.encode("utf-8")
        context_text = row["context_text"]
        context_sha256 = str(row["context_sha256"])
        source_lines = source_bytes.decode("utf-8").splitlines()
        try:
            prefix_text = source_bytes[:byte_start].decode("utf-8")
        except UnicodeDecodeError as error:
            raise CitationProjectionError(
                "Evidence citation marker is not UTF-8 aligned"
            ) from error
        actual_line_start = prefix_text.count("\n") + 1
        actual_line_end = actual_line_start + raw_marker_text.count("\n")
        if (
            not 0 <= byte_start < byte_end <= len(source_bytes)
            or hashlib.sha256(marker_bytes).hexdigest() != raw_marker_sha256
            or source_bytes[byte_start:byte_end] != marker_bytes
            or citation_id
            != citation_id_for_marker(source_sha256, byte_start, byte_end, marker_bytes)
            or not isinstance(context_text, str)
            or hashlib.sha256(context_text.encode("utf-8")).hexdigest()
            != context_sha256
            or line_end > len(source_lines)
            or line_start != actual_line_start
            or line_end != actual_line_end
            or source_lines[line_start - 1] != context_text
        ):
            raise CitationProjectionError(
                "Evidence citation marker identity differs from active source bytes"
            )
        containing = {
            span_id
            for version_id in version_ids
            for span_id in _containing_span_ids(
                snapshot, version_id, byte_start, byte_end
            )
        }
        if not containing:
            raise CitationProjectionError(
                "Evidence citation marker is outside compiled source blocks"
            )
        projected.append(
            ProjectedCitation(
                citation_id=citation_id,
                source_sha256=source_sha256,
                containing_span_ids=tuple(sorted(containing)),
                line_start=line_start,
                line_end=line_end,
                byte_start=byte_start,
                byte_end=byte_end,
                raw_marker_text=raw_marker_text,
                raw_marker_sha256=raw_marker_sha256,
                occurrence_kind=str(row["occurrence_kind"]),
                resolution_state="valid",
                authority_kind="evidence_binding",
            )
        )

    manifest_input = Path(
        overlay_manifest_path or citation_overlay_manifest_path()
    )
    manifest_before = _authority_file_state(
        manifest_input, authority_name="reviewed citation overlay"
    )
    manifest_path = manifest_input.resolve(strict=True)
    overlay_manifest_sha256 = manifest_before[2]
    source_paths = {
        source_sha256: snapshot.versions[version_ids[0]].logical_path
        for source_sha256, version_ids in source_to_versions.items()
    }
    try:
        overlay_registry = CitationOverlayRegistry(
            None,
            manifest_path=manifest_path,
            source_objects=verified_sources,
            source_paths=source_paths,
        )
        for source_sha256, version_ids in sorted(source_to_versions.items()):
            for overlay in overlay_registry.for_document(source_sha256):
                containing = {
                    span_id
                    for version_id in version_ids
                    for span_id in _containing_span_ids(
                        snapshot,
                        version_id,
                        overlay.byte_start,
                        overlay.byte_end,
                    )
                }
                if not containing:
                    raise CitationOverlayError(
                        "reviewed citation marker is outside compiled source blocks"
                    )
                marker_bytes = overlay.marker.encode("utf-8")
                projected.append(
                    ProjectedCitation(
                        citation_id=overlay.citation_id,
                        source_sha256=source_sha256,
                        containing_span_ids=tuple(sorted(containing)),
                        line_start=overlay.line_number,
                        line_end=overlay.line_number,
                        byte_start=overlay.byte_start,
                        byte_end=overlay.byte_end,
                        raw_marker_text=overlay.marker,
                        raw_marker_sha256=hashlib.sha256(marker_bytes).hexdigest(),
                        occurrence_kind="reviewed_projection",
                        resolution_state="valid",
                        authority_kind="reviewed_overlay",
                    )
                )
    except CitationOverlayError as error:
        raise CitationProjectionError("reviewed citation overlay is invalid") from error

    deduplicated: dict[str, ProjectedCitation] = {}
    for row in projected:
        previous = deduplicated.get(row.citation_id)
        if previous is not None and (
            previous.source_sha256,
            previous.byte_start,
            previous.byte_end,
            previous.raw_marker_sha256,
        ) != (
            row.source_sha256,
            row.byte_start,
            row.byte_end,
            row.raw_marker_sha256,
        ):
            raise CitationProjectionError("citation authorities disagree on canonical identity")
        if previous is None or row.authority_kind == "reviewed_overlay":
            deduplicated[row.citation_id] = row
    selected, rejected_overlap_count = _select_non_overlapping(
        tuple(deduplicated.values())
    )
    membership_material = {
        "schema_version": CITATION_PROJECTION_SCHEMA,
        "base_snapshot_id": snapshot.snapshot_id,
        "evidence_database_sha256": before[2],
        "evidence_migration_authority_sha256": migration_content_identity,
        "reviewed_overlay_manifest_sha256": overlay_manifest_sha256,
        "active_source_membership": dict(sorted(active_source_membership.items())),
        "occurrences": [row.to_dict() for row in selected],
        "rejected_overlap_count": rejected_overlap_count,
    }
    projection = CitationProjection(
        schema_version=CITATION_PROJECTION_SCHEMA,
        base_snapshot_id=snapshot.snapshot_id,
        evidence_database_sha256=before[2],
        evidence_migration_authority_sha256=migration_content_identity,
        reviewed_overlay_manifest_sha256=overlay_manifest_sha256,
        active_source_membership=active_source_membership,
        occurrences=selected,
        rejected_overlap_count=rejected_overlap_count,
        membership_sha256=content_hash(
            CITATION_PROJECTION_SCHEMA, membership_material
        ),
        _source_objects=verified_sources,
        _block_ranges={
            version_id: {
                block.source_span.span_id: (
                    block.source_span.byte_start,
                    block.source_span.byte_end,
                )
                for block in snapshot.ir_documents[version_id].blocks
            }
            for version_id in active_source_membership
        },
    )
    after = _authority_file_state(
        database_input, authority_name="Evidence sidecar"
    )
    manifest_after = _authority_file_state(
        manifest_input, authority_name="reviewed citation overlay"
    )
    _, migration_content_after, migration_state_after = _migration_authority(
        migration_root
    )
    _assert_no_journal_artifacts(database)
    if (
        before != after
        or manifest_before != manifest_after
        or migration_content_identity != migration_content_after
        or migration_state_before != migration_state_after
    ):
        raise CitationProjectionError(
            "citation authorities changed during immutable projection"
        )
    return projection


def citation_ids_for_chunk(
    projection: CitationProjection, version_id: str, chunk: Any
) -> tuple[str, ...]:
    return tuple(
        row.citation_id
        for row in projection.for_version(version_id)
        if chunk.byte_start <= row.byte_start
        and row.byte_end <= chunk.byte_end
    )


def citation_ids_for_binding(
    projection: CitationProjection,
    version_id: str,
    binding: Any,
) -> tuple[str, ...]:
    """Authorize citation markers covered by, or punctuationally adjacent to, one binding."""

    return tuple(
        row.citation_id
        for row in citation_attributions_for_binding(projection, version_id, binding)
    )


def is_valid_citation_gap(gap_bytes: bytes) -> bool:
    if len(gap_bytes) > 24:
        return False
    try:
        gap = gap_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return all(
        character.isspace()
        or unicodedata.category(character).startswith("P")
        or character in _MARKDOWN_GAP_DELIMITERS
        for character in gap
    )


def citation_attributions_for_binding(
    projection: CitationProjection,
    version_id: str,
    binding: Any,
) -> tuple[CitationAttribution, ...]:
    """Return minimal, source-derived proof for every projected attribution."""

    source = projection.source_bytes(version_id)
    binding_start = int(binding.byte_start)
    binding_end = int(binding.byte_end)
    if not 0 <= binding_start < binding_end <= len(source):
        raise CitationProjectionError("knowledge evidence binding escapes source bytes")
    quote = getattr(binding, "quote", None)
    quote_sha256 = getattr(binding, "quote_sha256", None)
    located = source[binding_start:binding_end]
    try:
        located_text = located.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CitationProjectionError(
            "knowledge evidence binding is not UTF-8 aligned"
        ) from error
    if (
        not isinstance(quote, str)
        or not isinstance(quote_sha256, str)
        or located_text != quote
        or hashlib.sha256(located).hexdigest() != quote_sha256
    ):
        raise CitationProjectionError(
            "knowledge evidence binding differs from active source bytes"
        )
    block_range = projection._block_ranges.get(version_id, {}).get(
        str(binding.span_id)
    )
    if (
        block_range is None
        or not block_range[0] <= binding_start
        or not binding_end <= block_range[1]
    ):
        raise CitationProjectionError(
            "knowledge evidence binding escapes its compiled source block"
        )
    attributions: list[CitationAttribution] = []
    adjacency_cursor = binding_end
    for row in projection.for_version(version_id):
        if str(binding.span_id) not in row.containing_span_ids:
            continue
        contained = binding_start <= row.byte_start and row.byte_end <= binding_end
        gap_bytes: bytes | None = None
        if adjacency_cursor <= row.byte_start:
            candidate_gap = source[adjacency_cursor:row.byte_start]
            if is_valid_citation_gap(candidate_gap):
                gap_bytes = candidate_gap
        if contained:
            attributions.append(
                CitationAttribution(
                    citation_id=row.citation_id,
                    relation="contained",
                    anchor_byte_end=binding_end,
                    gap_text="",
                    gap_sha256=hashlib.sha256(b"").hexdigest(),
                )
            )
        elif gap_bytes is not None:
            attributions.append(
                CitationAttribution(
                    citation_id=row.citation_id,
                    relation="adjacent",
                    anchor_byte_end=adjacency_cursor,
                    gap_text=gap_bytes.decode("utf-8"),
                    gap_sha256=hashlib.sha256(gap_bytes).hexdigest(),
                )
            )
        elif row.byte_start >= adjacency_cursor:
            break
        if contained or gap_bytes is not None:
            adjacency_cursor = max(adjacency_cursor, row.byte_end)
    return tuple(sorted(attributions, key=lambda row: row.citation_id))


__all__ = [
    "CITATION_PROJECTION_SCHEMA",
    "CitationProjection",
    "CitationProjectionError",
    "CitationAttribution",
    "ProjectedCitation",
    "build_citation_projection",
    "citation_ids_for_binding",
    "citation_attributions_for_binding",
    "citation_ids_for_chunk",
    "is_valid_citation_gap",
]
